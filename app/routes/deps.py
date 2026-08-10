"""
Общие зависимости роутов: шаблоны, фильтры Jinja2 и вспомогательные функции.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context
from markupsafe import Markup, escape

from .. import i18n
from ..config import BASE_DIR
from ..database import query_one

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

# Расширение само оборачивает русский текст шаблонов вызовами `_()`.
# Подключать нужно до первой компиляции — то есть прямо здесь.
templates.env.add_extension(i18n.TranslateExtension)
i18n.load_catalogs()


# ------------------------------------------------------------------ фильтры
def dt_local(value: str | None) -> str:
    """UTC-строка из БД → локальное время в удобочитаемом виде."""
    if not value:
        return "—"
    try:
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return str(value)
    return dt.astimezone().strftime("%d.%m.%Y %H:%M:%S")


@pass_context
def dt_short(ctx: Any, value: str | None) -> str:
    """То же, но короче — для колонки «последняя проверка»."""
    if not value:
        return "—"
    try:
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return str(value)
    local = dt.astimezone()
    lang = ctx.get("lang", i18n.SOURCE_LANG)
    if local.date() == datetime.now().astimezone().date():
        return i18n.translate("сегодня %(p0)s", lang, p0=local.strftime("%H:%M"))
    return local.strftime("%d.%m %H:%M")


def log_time(value: str | None) -> str:
    """
    Время строки журнала: часы, минуты и секунды.

    Секунды здесь не педантизм: в журнале роутера события идут пачками
    внутри одной минуты, и без секунд не понять их порядок. Дата
    добавляется только для строк не сегодняшних, иначе она занимает
    место в каждой строке ради одного и того же числа.

    Формат совпадает с тем, что рисует браузер для новых строк: иначе
    лента выглядит склеенной из двух разных журналов, что и происходило.
    """
    if not value:
        return ""
    try:
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return str(value)
    local = dt.astimezone()
    if local.date() == datetime.now().astimezone().date():
        return local.strftime("%H:%M:%S")
    return local.strftime("%d.%m %H:%M:%S")


@pass_context
def human_size(ctx: Any, value: Any) -> str:
    """Байты → КиБ/МиБ."""
    try:
        num = float(value)
    except (TypeError, ValueError):
        return "—"
    lang = ctx.get("lang", i18n.SOURCE_LANG)
    for unit in ("Б", "КиБ", "МиБ", "ГиБ"):
        if num < 1024:
            return f"{num:.1f} {i18n.translate(unit, lang)}"
        num /= 1024
    return f"{num:.1f} {i18n.translate('ТиБ', lang)}"


@pass_context
def since(ctx: Any, value: str | None) -> str:
    """Сколько времени прошло с момента в БД: «5 мин», «2 ч 13 мин», «3 дн 4 ч»."""
    if not value:
        return "—"
    try:
        moment = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return "—"
    seconds = int((datetime.now(timezone.utc) - moment).total_seconds())
    return _duration(seconds, ctx.get("lang", i18n.SOURCE_LANG))


def _duration(seconds: Any, lang: str = i18n.SOURCE_LANG) -> str:
    """
    Секунды → человекочитаемая длительность.

    Сокращения единиц переводятся отдельными строками: в английском это
    «d», «h», «min», «s», и склеивать их с числом на стороне шаблона нельзя.
    """
    try:
        total = max(0, int(seconds))
    except (TypeError, ValueError):
        return "—"

    def unit(text: str) -> str:
        return i18n.translate(text, lang)

    minutes, sec = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return f"{days} {unit('дн')} {hours} {unit('ч')}"
    if hours:
        return f"{hours} {unit('ч')} {minutes} {unit('мин')}"
    if minutes:
        return f"{minutes} {unit('мин')}"
    return f"{sec} {unit('с')}"


@pass_context
def duration(ctx: Any, seconds: Any) -> str:
    """Фильтр длительности — язык берётся из контекста страницы."""
    return _duration(seconds, ctx.get("lang", i18n.SOURCE_LANG))


def sort_version(value: Any) -> int:
    """
    Числовой ключ сортировки для версии RouterOS.

    Как текст версии сортируются неправильно: «7.9» оказывается больше «7.21».
    Превращаем в одно число: 7.21.5 → 7·10⁶ + 21·10³ + 5.
    """
    from ..mikrotik import parse_version

    parts = (parse_version(value) + (0, 0, 0))[:3]
    return parts[0] * 1_000_000 + parts[1] * 1_000 + parts[2]


def uptime_seconds(value: Any) -> int:
    """
    Uptime RouterOS («3w2d10:15:42») → секунды, чтобы сортировка была осмысленной.
    """
    text = str(value or "").strip()
    if not text:
        return 0

    total = 0
    units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
    for number, unit in re.findall(r"(\d+)([wdhms])", text):
        total += int(number) * units[unit]

    # Хвост вида «10:15:42» — часы, минуты, секунды
    clock = re.search(r"(\d+):(\d+):(\d+)$", text)
    if clock:
        h, m, s = (int(g) for g in clock.groups())
        total += h * 3600 + m * 60 + s
    return total


def status_rank(value: Any) -> int:
    """Порядок статусов при сортировке: сначала проблемные."""
    return {"offline": 0, "unknown": 1, "online": 2}.get(str(value or ""), 3)


@pass_context
def plural(ctx: Any, count: Any, one: str, few: str, many: str) -> str:
    """
    Выбрать форму слова по числу: 1 измерение, 2 измерения, 5 измерений.

    Без этого в интерфейсе появляется «3 устройств» и «1 замеров» —
    мелочь, но бросается в глаза на каждой странице. Язык берётся из
    контекста страницы: в английском форм две, а не три.
    """
    return i18n.plural(count, (one, few, many), ctx.get("lang", i18n.SOURCE_LANG))


@pass_context
def gettext(ctx: Any, msgid: str, **params: Any) -> Any:
    """
    Перевод строки шаблона. Вызовы расставляет `i18n.TranslateExtension`,
    руками писать `_()` в шаблонах не нужно.

    Фраза может содержать теги оформления — `<code>`, `<strong>` и подобные
    попадают внутрь ключа целиком, иначе перевести её нельзя. Такой результат
    отдаётся как готовая разметка, поэтому подставляемые значения (имена
    устройств, адреса) экранируются вручную: имя вида `<script>` не должно
    превращаться в исполняемый код.
    """
    lang = ctx.get("lang", i18n.SOURCE_LANG)
    if "<" in msgid:
        safe = {key: escape(value) for key, value in params.items()}
        return Markup(i18n.translate(msgid, lang, **safe))
    return i18n.translate(msgid, lang, **params)


@pass_context
def translate_value(ctx: Any, value: Any) -> str:
    """
    Фильтр `| t` — для строк, пришедших из Python: названий действий,
    сообщений об ошибках, результатов задач.

    Автоматическая пометка их не видит: в шаблоне это выражение, а не текст.
    Сообщения об ошибках вдобавок хранятся в базе по-русски, и перевод при
    показе — единственный способ, при котором старые записи в истории тоже
    становятся читаемыми на другом языке.
    """
    if not isinstance(value, str) or not value:
        return value
    return i18n.translate_text(value, ctx.get("lang", i18n.SOURCE_LANG))


@pass_context
def can(ctx: Any, permission: str) -> bool:
    """
    Проверка права прямо в шаблоне: `{% if can("devices.edit") %}`.

    Нужна только чтобы не показывать заведомо недоступные кнопки. Настоящая
    проверка стоит на сервере в самом роуте.
    """
    from .. import permissions

    return permissions.has(ctx.get("user"), permission)


templates.env.globals["can"] = can
templates.env.globals["_"] = gettext
templates.env.filters["t"] = translate_value
templates.env.filters["plural"] = plural
templates.env.filters["sort_version"] = sort_version
templates.env.filters["uptime_seconds"] = uptime_seconds
templates.env.filters["status_rank"] = status_rank
templates.env.filters["dt"] = dt_local
templates.env.filters["dt_short"] = dt_short
templates.env.filters["log_time"] = log_time
templates.env.filters["size"] = human_size
templates.env.filters["since"] = since
templates.env.filters["duration"] = duration


# ------------------------------------------------------------------- язык
LANG_COOKIE = "tikpilot_lang"


def resolve_lang(request: Request | None, user: dict[str, Any] | None = None) -> str:
    """
    Определить язык страницы.

    Порядок: сохранённый выбор администратора → cookie (нужна на странице
    входа, где пользователя ещё нет) → `DEFAULT_LANG` из .env.

    Язык браузера намеренно не учитывается: панель обычно открывают
    в браузере с системным языком, который к предпочтениям в работе
    отношения не имеет.
    """
    if user and user.get("id"):
        row = query_one("SELECT lang FROM users WHERE id = ?", (user["id"],))
        if row and row["lang"]:
            return i18n.normalize_lang(row["lang"])

    if request is not None:
        cookie = request.cookies.get(LANG_COOKIE)
        if cookie:
            return i18n.normalize_lang(cookie)

    from ..config import settings

    return i18n.normalize_lang(settings.default_lang)


# --------------------------------------------------------------- контекст
def base_context(
    user: dict[str, Any],
    request: Request | None = None,
    **extra: Any,
) -> dict[str, Any]:
    """Контекст, общий для всех страниц (шапка, счётчики, активный раздел)."""
    from .. import __version__
    from ..config import settings

    lang = resolve_lang(request, user)
    running = query_one("SELECT COUNT(*) AS c FROM jobs WHERE status IN ('pending','running')")
    from .. import permissions

    where, scope_params = permissions.scope_sql(user)
    offline = query_one(
        f"SELECT COUNT(*) AS c FROM devices d WHERE enabled=1 AND status='offline'{where}",
        tuple(scope_params),
    )
    ctx: dict[str, Any] = {
        "user": user,
        "running_jobs": running["c"] if running else 0,
        "offline_count": offline["c"] if offline else 0,
        "app_version": __version__,
        "monitor_on": settings.monitor_enabled,
        "ui_refresh_interval": settings.ui_refresh_interval,
        "lang": lang,
        "languages": i18n.available_languages(),
        "js_i18n": i18n.js_catalog(lang),
        "active": "",
    }
    ctx.update(extra)
    return ctx


def render(name: str, request: Request, user: dict[str, Any],
           status_code: int = 200, **extra: Any):
    """Короткая обёртка над TemplateResponse."""
    return templates.TemplateResponse(
        request, name, base_context(user, request, **extra), status_code=status_code
    )


def render_partial(name: str, request: Request, user: dict[str, Any] | None = None, **extra: Any):
    """
    Отрисовать фрагмент страницы (кусок таблицы, карту, ленту событий).

    Полный контекст фрагменту не нужен, но язык нужен обязательно: иначе
    страница будет английской, а подгруженные в неё строки — русскими.
    """
    ctx: dict[str, Any] = {"lang": resolve_lang(request, user)}
    ctx.update(extra)
    return templates.TemplateResponse(request, name, ctx)


def form_bool(value: Any) -> int:
    """Значение чекбокса из формы → 0/1."""
    return 1 if str(value).strip().lower() in ("1", "true", "yes", "on", "да") else 0


#: Сколько строк на странице. Полсотни это примерно один экран на ноутбуке
#: и заведомо меньше, чем парк устройств: страница не должна расти вместе
#: с историей.
PAGE_SIZE = 50


def pager(request: Request, total: int, page: int, per_page: int = PAGE_SIZE) -> dict[str, Any]:
    """
    Разбивка длинного списка на страницы.

    Возвращает всё, что нужно и запросу, и шаблону: смещение для SQL,
    номера страниц для ссылок и остальные параметры адреса.

    Параметры фильтров переносятся на соседние страницы как есть. Иначе
    переход на вторую страницу сбрасывал бы поиск, и человек попадал бы
    не туда, куда шёл.

    Номер страницы приходит из адреса, поэтому загоняется в границы:
    «page=99999» должно показать последнюю страницу, а не пустоту.
    """
    from urllib.parse import urlencode

    per_page = max(1, per_page)
    pages = max(1, -(-total // per_page))     # деление с округлением вверх
    page = min(max(1, page), pages)

    rest = [(key, value) for key, value in request.query_params.multi_items()
            if key != "page"]
    base = urlencode(rest)

    # Показываем края и окно вокруг текущей страницы, между ними пропуск.
    # Полсотни номеров подряд не помогают никому.
    numbers: list[int | None] = []
    for number in range(1, pages + 1):
        if number <= 2 or number > pages - 2 or abs(number - page) <= 2:
            numbers.append(number)
        elif numbers and numbers[-1] is not None:
            numbers.append(None)

    return {
        "page": page,
        "pages": pages,
        "total": total,
        "per_page": per_page,
        "offset": (page - 1) * per_page,
        "base": (base + "&") if base else "",
        "numbers": numbers,
        "first": (page - 1) * per_page + 1 if total else 0,
        "last": min(page * per_page, total),
    }
