"""
Аутентификация администраторов и работа с сессиями.

Сессия — подписанная cookie (itsdangerous), внутри лежит id пользователя
и его имя. Отдельная таблица сессий не нужна: подпись невозможно подделать
без SECRET_KEY, а срок жизни проверяется по метке времени.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException, Request, status
from fastapi.responses import RedirectResponse
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import settings
from .crypto import verify_password
from .database import query_one

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


def make_session_token(user: dict[str, Any]) -> str:
    """Сформировать значение сессионной cookie."""
    return _serializer.dumps({"uid": user["id"], "username": user["username"]})


def read_session(request: Request) -> dict[str, Any] | None:
    """Прочитать и проверить сессию из cookie запроса."""
    raw = request.cookies.get(settings.session_cookie)
    if not raw:
        return None
    try:
        data = _serializer.loads(raw, max_age=settings.session_max_age)
    except (BadSignature, SignatureExpired):
        return None
    # Убеждаемся, что пользователь всё ещё существует и не заблокирован
    row = query_one("SELECT id, username, is_active FROM users WHERE id = ?", (data.get("uid"),))
    if row is None or not row["is_active"]:
        return None

    # Права читаются на каждый запрос намеренно. Класть их в cookie нельзя:
    # тогда отнятое право продолжало бы действовать до конца сессии.
    from .permissions import load

    return {"id": row["id"], "username": row["username"], **load(row["id"])}


def set_session_cookie(response, token: str) -> None:
    """Проставить сессионную cookie на ответ."""
    response.set_cookie(
        settings.session_cookie,
        token,
        max_age=settings.session_max_age,
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
