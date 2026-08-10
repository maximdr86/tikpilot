"""
Публичный лист состояния группы.

Ссылка вида `/status/<токен>` открывается без входа: её дают подрядчикам,
дежурной смене, кому угодно. Поэтому страница отдаёт ровно один вид сведений
и ничего сверх него: имя точки, в сети она или нет, и с какого момента.

Чего здесь нет намеренно:

* **адресов.** Список внутренних IP это карта сети, а она не нужна человеку,
  который смотрит, работает точка или нет;
* **версий RouterOS.** Знание, что на площадке стоит устаревшая прошивка,
  полезно ровно тому, кто собирается ей воспользоваться;
* **текстов ошибок.** «Неверный логин или пароль» рассказывает о внутренностях
  системы больше, чем стоит показывать наружу;
* **всего парка.** Ссылка привязана к одной группе. Нужны две группы — будут
  две разные ссылки, и отозвать их можно по отдельности.

Токен случайный и достаточно длинный, чтобы его нельзя было подобрать. Если
ссылка ушла не туда, её отзывают одним нажатием, и старый адрес перестаёт
работать сразу.
"""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import Response

from .. import i18n, publicviews
from ..database import execute, query, query_one, utcnow
from .deps import resolve_lang, templates

router = APIRouter()

#: Длина токена в байтах. 24 байта это 32 символа в base64: подобрать
#: перебором нереально, а скопировать в переписку всё ещё удобно.
TOKEN_BYTES = 24


def new_token() -> str:
    """Создать токен для публичной ссылки."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def public_url(request: Request, token: str) -> str:
    """
    Полный адрес публичной страницы: его копируют и отправляют.

    Если задан `PUBLIC_BASE_URL`, берём его. Сам по себе сервер знает только
    адрес, по которому к нему пришли, а панель обычно открывают изнутри по
    локальному `10.x:8080`. Такую ссылку подрядчику отправлять бесполезно,
    и понять это можно лишь после того, как он ответит «не открывается».
    """
    from ..config import settings

    base = settings.public_base_url or str(request.base_url).rstrip("/")
    return base + "/status/" + token


#: Cookie, по которой открытие отличается от автообновления страницы.
VISIT_COOKIE = "tp_seen"

#: Сколько живёт эта отметка. Полсуток: вкладка, открытая на весь рабочий
#: день, считается одним обращением, а завтрашний заход — уже новым.
VISIT_TTL = 12 * 3600


#: Cookie языка публичной страницы. Отдельная от панельной и живёт только
#: на `/status`: подрядчик, переключивший страницу на русский, не должен
#: заодно менять язык панели администратору, открывшему ту же ссылку.
PUBLIC_LANG_COOKIE = "tp_status_lang"


def public_lang(request: Request, chosen: str = "") -> str:
    """
    Язык публичной страницы.

    Порядок: выбор в адресе (`?lang=ru`) → cookie этой страницы → язык
    браузера → `DEFAULT_LANG`. Язык браузера здесь учитывается, в отличие
    от панели: ссылку открывает человек со стороны, и заголовок
    Accept-Language это единственное, что о нём известно.
    """
    if chosen:
        return i18n.normalize_lang(chosen)

    saved = request.cookies.get(PUBLIC_LANG_COOKIE)
    if saved:
        return i18n.normalize_lang(saved)

    guess = i18n.browser_lang(request.headers.get("accept-language"))
    return guess or resolve_lang(None)


#: Окно, за которое считается простой на публичной странице. Сутки это
#: та единица, которой пользуются в разговоре: «за сегодня лежала дважды».
DOWNTIME_HOURS = 24


def _with_downtime(group_id: int, devices: list[Any]) -> list[dict[str, Any]]:
    """
    Добавить к точкам простой за сутки.

    Считается тем же кодом, что и на странице мониторинга, поэтому цифры
    на публичной ссылке и в панели совпадают. Расхождение здесь было бы
    хуже отсутствия цифры вовсе: подрядчик и администратор смотрели бы
    на разные числа и спорили, чьё верно.
    """
    from .. import monitor

    stats = {
        row["id"]: row
        for row in monitor.availability(DOWNTIME_HOURS, (" AND d.group_id = ?", [group_id]))
    }
    result = []
    for device in devices:
        found = stats.get(device["id"], {})
        result.append({
            **dict(device),
            "down_seconds": int(found.get("down_seconds") or 0),
            "outages": int(found.get("outages") or 0),
        })
    return result


def _count_visit(request: Request, group_id: int) -> bool:
    """
    Учесть обращение к публичной странице. Возвращает True, если это новое.

    Считаем именно обращения людей, а не запросы. Страница сама обновляется
    раз в минуту, поэтому одна забытая открытой вкладка дала бы полторы
    тысячи «посещений» в сутки, и счётчик перестал бы что-либо значить.
    Отличаем по короткоживущей cookie.
    """
    if request.cookies.get(f"{VISIT_COOKIE}_{group_id}"):
        return False

    day = utcnow()[:10]
    execute(
        "INSERT INTO public_visits (group_id, day, hits) VALUES (?,?,1) "
        "ON CONFLICT(group_id, day) DO UPDATE SET hits = hits + 1",
        (group_id, day),
    )
    execute("UPDATE groups SET public_last_seen = ? WHERE id = ?", (utcnow(), group_id))
    return True


@router.get("/status/{token}")
async def public_status(request: Request, token: str, lang: str = ""):
    """
    Лист состояния группы для тех, у кого есть ссылка.

    Несуществующий токен и отключённая ссылка отвечают одинаково: страницей
    «не найдено». Разница в ответах подсказала бы перебирающему, что он на
    верном пути.
    """
    chosen = public_lang(request, lang)

    group = None
    if len(token) >= 16:
        group = query_one(
            "SELECT id, name, color FROM groups WHERE public_token = ? AND public_token <> ''",
            (token,),
        )

    if group is None:
        publicviews.record(request, None, token)
        return templates.TemplateResponse(
            request,
            "public_missing.html",
            {"lang": chosen},
            status_code=404,
            headers=_headers(),
        )

    devices = query(
        "SELECT id, name, status, status_changed_at, last_seen FROM devices "
        "WHERE group_id = ? AND enabled = 1 "
        "ORDER BY CASE status WHEN 'offline' THEN 0 WHEN 'unknown' THEN 1 ELSE 2 END, "
        "name COLLATE NOCASE",
        (group["id"],),
    )

    counts = {"online": 0, "offline": 0, "unknown": 0}
    for device in devices:
        counts[device["status"] if device["status"] in counts else "unknown"] += 1

    rows = _with_downtime(group["id"], devices)
    fresh_visit = _count_visit(request, group["id"])
    session = publicviews.record(request, group)

    response = templates.TemplateResponse(
        request,
        "public_status.html",
        {
            "lang": chosen,
            "languages": i18n.available_languages(),
            "group": group,
            "devices": rows,
            "counts": counts,
            "total": len(rows),
            "downtime_hours": DOWNTIME_HOURS,
            "downtime_total": sum(r["down_seconds"] for r in rows),
            "downtime_points": sum(1 for r in rows if r["down_seconds"]),
        },
        headers=_headers(),
    )
    if lang:
        # Выбор языка запоминаем, чтобы следующий заход по той же ссылке
        # открылся сразу как надо
        response.set_cookie(PUBLIC_LANG_COOKIE, chosen, max_age=365 * 24 * 3600,
                            path="/status", httponly=True, samesite="lax")
    if fresh_visit:
        # Отметка только для счётчика: ничего о человеке она не хранит
        response.set_cookie(
            f"{VISIT_COOKIE}_{group['id']}", "1",
            max_age=VISIT_TTL, path="/status", httponly=True, samesite="lax",
        )
    if session:
        # Случайная метка сеанса. Без неё вкладка, открытая на весь день,
        # выглядела бы в журнале как полторы тысячи разных посетителей
        response.set_cookie(
            publicviews.SESSION_COOKIE, session,
            max_age=publicviews.SESSION_TTL, path="/status",
            httponly=True, samesite="lax",
        )
    return response


def _headers() -> dict[str, str]:
    """
    Заголовки публичной страницы.

    Поисковикам её индексировать незачем: ссылка секретная ровно до тех пор,
    пока не попала в выдачу. Кэширование тоже выключено, иначе прокси может
    отдать вчерашнее состояние сети как сегодняшнее, а это хуже, чем ничего.
    """
    return {
        "X-Robots-Tag": "noindex, nofollow, noarchive",
        "Cache-Control": "no-store, max-age=0",
        "Referrer-Policy": "no-referrer",
    }
