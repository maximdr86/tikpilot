"""
Аутентификация администраторов и работа с сессиями.

Сессия — подписанная cookie (itsdangerous), внутри лежит id пользователя
и его имя. Отдельная таблица сессий не нужна: подпись невозможно подделать
без SECRET_KEY, а срок жизни проверяется по метке времени.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import settings
from .crypto import verify_password
from .database import execute_changes, query_one

_serializer = URLSafeTimedSerializer(settings.secret_key, salt="tikpilot-session")


# ------------------------------------------------------------------ проверки
def authenticate(username: str, password: str) -> dict[str, Any] | None:
    """Проверить пару логин/пароль. Возвращает данные пользователя либо None."""
    row = query_one(
        "SELECT id, username, password_hash, is_active FROM users WHERE username = ?",
        (username.strip(),),
    )
    if row is None or not row["is_active"]:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return {"id": row["id"], "username": row["username"]}


def session_epoch(user_id: int) -> int:
    """Текущее поколение сессий пользователя."""
    row = query_one("SELECT session_epoch FROM users WHERE id = ?", (user_id,))
    return int(row["session_epoch"] or 0) if row else 0


def end_sessions(user_id: int) -> None:
    """
    Завершить все входы пользователя, кроме будущих.

    Сессия это подписанная cookie: сервер её не хранит и отозвать поштучно
    не может. Поэтому у каждого есть номер поколения, он лежит внутри
    cookie и сверяется на каждом запросе. Сдвинули номер — все выданные
    ранее cookie разом перестали подходить.

    Зовётся при смене пароля. Смена пароля, после которой чужой вход
    продолжает работать, защищает ровно ни от чего.
    """
    execute_changes(
        "UPDATE users SET session_epoch = COALESCE(session_epoch, 0) + 1 WHERE id = ?",
        (user_id,))


def make_session_token(user: dict[str, Any], remember: bool = False) -> str:
    """
    Сформировать значение сессионной cookie.

    Признак «запомнить» лежит внутри подписанного значения, а не отдельной
    cookie: иначе его хватило бы стереть в браузере, чтобы получить сессию
    другой длины, а подписанное значение подделать нельзя.
    """
    return _serializer.dumps({
        "uid": user["id"],
        "username": user["username"],
        "epoch": session_epoch(user["id"]),
        "remember": bool(remember),
    })


def read_session(request: Request) -> dict[str, Any] | None:
    """Прочитать и проверить сессию из cookie запроса."""
    raw = request.cookies.get(settings.session_cookie)
    if not raw:
        return None
    try:
        # Читаем по длинной мерке, а решаем по той, что записана в самой
        # cookie: обычная сессия живёт часы, отмеченная «запомнить» - недели
        data, issued = _serializer.loads(
            raw, max_age=settings.session_remember_age, return_timestamp=True)
    except (BadSignature, SignatureExpired):
        return None

    limit = (settings.session_remember_age if data.get("remember")
             else settings.session_max_age)
    if (datetime.now(timezone.utc) - issued).total_seconds() > limit:
        return None
    # Убеждаемся, что пользователь всё ещё существует и не заблокирован
    row = query_one(
        "SELECT id, username, is_active, session_epoch FROM users WHERE id = ?",
        (data.get("uid"),))
    if row is None or not row["is_active"]:
        return None

    # Поколение сессий. Старые cookie, выписанные до смены пароля,
    # сюда не проходят: у них внутри прежний номер
    if int(data.get("epoch", 0)) != int(row["session_epoch"] or 0):
        return None

    # Права читаются на каждый запрос намеренно. Класть их в cookie нельзя:
    # тогда отнятое право продолжало бы действовать до конца сессии.
    from .permissions import load

    return {"id": row["id"], "username": row["username"], **load(row["id"])}


def set_session_cookie(response, token: str, remember: bool = False) -> None:
    """Проставить сессионную cookie на ответ."""
    response.set_cookie(
        settings.session_cookie,
        token,
        max_age=(settings.session_remember_age if remember
                 else settings.session_max_age),
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        path="/",
    )


def clear_session_cookie(response) -> None:
    """Удалить сессионную cookie (выход из системы)."""
    response.delete_cookie(settings.session_cookie, path="/")


# --------------------------------------------------------------- зависимости
def current_user(request: Request) -> dict[str, Any]:
    """
    FastAPI-зависимость: требует авторизации.

    Для обычных запросов — редирект на /login, для HTMX/API — код 401.
    """
    user = read_session(request)
    if user is None:
        if request.headers.get("HX-Request") or request.url.path.startswith("/api/"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Требуется вход")
        raise RedirectException(f"/login?next={request.url.path}")
    return user


class RedirectException(Exception):
    """Внутреннее исключение — перехватывается обработчиком в main.py."""

    def __init__(self, url: str) -> None:
        self.url = url
        super().__init__(url)


async def redirect_exception_handler(_request: Request, exc: RedirectException):
    """Превращает RedirectException в обычный HTTP-редирект."""
    return RedirectResponse(exc.url, status_code=status.HTTP_303_SEE_OTHER)


def client_ip(request: Request) -> str:
    """IP клиента с учётом обратного прокси."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else ""


class Forbidden(Exception):
    """Не хватает прав. Перехватывается обработчиком в main.py."""

    def __init__(self, detail: str = "Недостаточно прав") -> None:
        self.detail = detail
        super().__init__(detail)


def require(permission: str):
    """
    Зависимость FastAPI: пускать только с указанным правом.

    Использование:  user=Depends(require("backups.download"))

    Проверка именно на сервере. Спрятанная в шаблоне кнопка это удобство,
    а не защита: адрес страницы можно набрать руками, а запрос отправить
    curl-ом.
    """
    from .permissions import has

    def dependency(request: Request) -> dict[str, Any]:
        user = current_user(request)
        if not has(user, permission):
            raise Forbidden()
        return user

    return dependency
