"""
Кто открывает публичные листы состояния.

Счётчик обращений отвечал на вопрос «сколько», но не на вопрос, который
задают на самом деле: «ссылка разошлась дальше, чем я рассчитывал?».
Ответ на него это адрес, устройство и время, а не число.

Что здесь записывается и почему именно это:

* **адрес,** потому что по нему видно чужой это офис или свой;
* **устройство и браузер** из заголовка User-Agent, потому что три захода
  с одного адреса с трёх разных телефонов это три человека;
* **начало и последняя активность,** потому что страница обновляет себя
  раз в минуту, и по этому следу видно, кто смотрит прямо сейчас;
* **откуда пришли,** потому что непустой Referer означает, что ссылку
  где-то выложили, а не переслали в личном сообщении;
* **заходы по неверному токену,** потому что десяток таких с одного
  адреса это перебор, и узнать о нём лучше сразу.

Чего здесь нет: попыток опознать человека надёжнее, чем позволяют эти
данные. Отпечатков браузера, скрытых пикселей, сторонних счётчиков.
Ссылка публичная, и следить за тем, кто её открыл, панель может ровно
в тех пределах, в которых это видно из обычного журнала веб-сервера.

Опознание сеанса сделано случайной меткой в cookie. Без неё вкладка,
забытая открытой на сутки, выглядела бы как полторы тысячи посещений,
а метка не несёт в себе ничего: это случайные байты, по которым сходятся
строки одного и того же сеанса.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from .database import execute, query, query_one, utcnow

#: Cookie со случайной меткой сеанса. Живёт на `/status`, чтобы не уезжать
#: вместе с запросами к панели.
SESSION_COOKIE = "tp_view"

#: Сколько живёт метка. Месяц: следующий заход того же человека по той же
#: ссылке видно как продолжение истории, а не как нового посетителя.
SESSION_TTL = 30 * 24 * 3600

#: Пауза, после которой заход считается новым. Полчаса это обычный перерыв
#: между «посмотрел утром» и «посмотрел после обеда».
SESSION_GAP = 30 * 60

#: Насколько свежей должна быть последняя активность, чтобы считать, что
#: страница открыта прямо сейчас. Страница обновляет себя раз в минуту,
#: три минуты дают запас на плохую связь в тайге.
ONLINE_SECONDS = 180

#: Попытки по неверному токену с одного адреса склеиваются в одну строку,
#: если идут подряд. Иначе перебор забьёт журнал за минуту.
FAIL_MERGE_SECONDS = 300

#: Максимальная длина того, что приходит от клиента. Заголовки не ограничены
#: ничем, и класть их в базу как есть значит однажды получить мегабайт.
MAX_AGENT = 400
MAX_REFERER = 300


# --------------------------------------------------------------- User-Agent
#: Роботы, которые ходят по ссылке сами. Первым делом это предпросмотр
#: в мессенджерах: стоит отправить ссылку в чат, и она открывается ещё
#: до того, как её увидел человек. Без отдельной пометки такой заход
#: выглядел бы как «подрядчик уже смотрит».
_BOTS = (
    ("telegrambot", "Telegram"),
    ("whatsapp", "WhatsApp"),
    ("viber", "Viber"),
    ("facebookexternalhit", "Facebook"),
    ("vkshare", "ВКонтакте"),
    ("twitterbot", "Twitter"),
    ("discordbot", "Discord"),
    ("slackbot", "Slack"),
    ("skypeuripreview", "Skype"),
    ("bingbot", "Bing"),
    ("googlebot", "Google"),
    ("yandexbot", "Яндекс"),
    ("duckduckbot", "DuckDuckGo"),
    ("curl", "curl"),
    ("wget", "wget"),
    ("python-requests", "python"),
    ("go-http-client", "Go"),
    ("okhttp", "okhttp"),
    ("headlesschrome", "Chrome без окна"),
)

#: Браузеры: что искать, как назвать, откуда брать версию. Порядок важен:
#: Edge и Яндекс представляются ещё и как Chrome, Chrome представляется
#: как Safari, и первым должен проверяться самый редкий из совпадающих.
#:
#: Версия берётся по своему же слову, а не первым попавшимся числом:
#: у Яндекс Браузера в строке стоит и Chrome/137, и YaBrowser/25, причём
#: чужая версия идёт раньше собственной.
_BROWSERS = (
    ("YaBrowser", "Яндекс Браузер", "YaBrowser"),
    ("Edg", "Edge", "Edg"),
    ("OPR", "Opera", "OPR"),
    ("Opera", "Opera", "Opera"),
    ("Firefox", "Firefox", "Firefox"),
    ("Chrome", "Chrome", "Chrome"),
    ("Safari", "Safari", "Version"),
)

_SYSTEMS = (
    ("Android", "Android"),
    ("iPhone", "iPhone"),
    ("iPad", "iPad"),
    ("Windows NT 10", "Windows"),
    ("Windows", "Windows"),
    ("Mac OS X", "macOS"),
    ("Linux", "Linux"),
)


def describe_agent(agent: str) -> tuple[str, int]:
    """
    User-Agent в читаемое «Chrome, Android». Возвращает ещё и признак робота.

    Разбор нарочно грубый. Точный разбор User-Agent невозможен в принципе,
    браузеры двадцать лет представляются друг другом, и библиотека ради
    этого в проект не приедет. Задача здесь скромная: отличить телефон от
    компьютера и человека от предпросмотра ссылки.
    """
    text = (agent or "").strip()
    if not text:
        return "", 0

    low = text.lower()
    for needle, name in _BOTS:
        if needle in low:
            return name, 1

    found_browser = next(((name, token) for needle, name, token in _BROWSERS
                          if needle in text), ("", ""))
    browser, token = found_browser
    system = next((name for needle, name in _SYSTEMS if needle in text), "")

    version = ""
    if browser:
        found = re.search(token + r"[A-Za-z]*/(\d+)", text)
        if found:
            version = " " + found.group(1)

    parts = [p for p in (browser + version if browser else "", system) if p]
    return ", ".join(parts), 0


# ------------------------------------------------------------------- запись
def _fresh(moment: Any, seconds: int) -> bool:
    """Была ли отметка времени не позже, чем `seconds` назад."""
    try:
        stamp = datetime.strptime(str(moment), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return False
    return datetime.now(timezone.utc) - stamp < timedelta(seconds=seconds)


def record(request: Any, group: Any = None, token: str = "") -> str:
    """
    Записать обращение к публичной странице. Возвращает метку сеанса.

    Метку роут кладёт в cookie. Возвращать её, а не ставить самому, нужно
    потому, что ответ формируется позже: страница и заголовки собираются
    в роуте, и лезть в них отсюда значило бы размазать одну задачу по двум
    местам.
    """
    from .auth import client_ip

    ip = client_ip(request)
    agent = (request.headers.get("user-agent") or "")[:MAX_AGENT]
    referer = (request.headers.get("referer") or "")[:MAX_REFERER]
    device, bot = describe_agent(agent)
    lang = (request.headers.get("accept-language") or "")[:40]
    now = utcnow()

    if group is None:
        _record_miss(ip, agent, device, bot, token, now)
        return ""

    group_id = int(group["id"])
    session = str(request.cookies.get(SESSION_COOKIE) or "")[:40]

    if session:
        row = query_one(
            "SELECT id, last_at FROM public_views "
            "WHERE session = ? AND group_id = ? AND ok = 1 ORDER BY id DESC LIMIT 1",
            (session, group_id),
        )
        if row and _fresh(row["last_at"], SESSION_GAP):
            # Продолжение того же сеанса: адрес и устройство перезаписываем,
            # человек мог за это время уйти с вайфая в мобильный интернет
            execute(
                "UPDATE public_views SET last_at = ?, hits = hits + 1, ip = ?, "
                "agent = ?, device = ? WHERE id = ?",
                (now, ip, agent, device, row["id"]),
            )
            return session

    session = session or secrets.token_urlsafe(9)
    execute(
        "INSERT INTO public_views (group_id, group_name, session, ok, bot, ip, agent,"
        " device, referer, lang, started_at, last_at, hits)"
        " VALUES (?,?,?,1,?,?,?,?,?,?,?,?,1)",
        (group_id, str(group["name"]), session, bot, ip, agent, device,
         referer, lang, now, now),
    )
    return session


def _record_miss(ip: str, agent: str, device: str, bot: int,
                 token: str, now: str) -> None:
    """
    Заход по несуществующей ссылке.

    Сам токен не хранится: он либо чужой действующий (и тогда это
    полноценный секрет в нашей базе), либо мусор. Хвоста достаточно,
    чтобы отличить опечатку в одном символе от перебора.
    """
    tail = ("..." + token[-6:]) if len(token) > 6 else token
    row = query_one(
        "SELECT id, last_at FROM public_views WHERE ok = 0 AND ip = ? "
        "ORDER BY id DESC LIMIT 1", (ip,),
    )
    if row and _fresh(row["last_at"], FAIL_MERGE_SECONDS):
        execute(
            "UPDATE public_views SET last_at = ?, hits = hits + 1, token_tail = ? WHERE id = ?",
            (now, tail, row["id"]),
        )
        return

    execute(
        "INSERT INTO public_views (group_id, group_name, session, ok, bot, ip, agent,"
        " device, referer, lang, token_tail, started_at, last_at, hits)"
        " VALUES (NULL,'','',0,?,?,?,?,'','',?,?,?,1)",
        (bot, ip, agent, device, tail, now, now),
    )


# ------------------------------------------------------------------- чтение
def watching(group_id: int | None = None) -> list[dict[str, Any]]:
    """Сеансы, активные прямо сейчас."""
    where = " AND group_id = ?" if group_id else ""
    params: tuple[Any, ...] = (group_id,) if group_id else ()
    rows = query(
        "SELECT * FROM public_views WHERE ok = 1 AND bot = 0 "
        f"AND last_at > datetime('now', ?){where} ORDER BY last_at DESC",
        (f"-{ONLINE_SECONDS} seconds", *params),
    )
    return [dict(row) for row in rows]


def watching_count() -> dict[int, int]:
    """Сколько человек смотрит каждую группу прямо сейчас."""
    rows = query(
        "SELECT group_id, COUNT(*) AS c FROM public_views "
        "WHERE ok = 1 AND bot = 0 AND last_at > datetime('now', ?) GROUP BY group_id",
        (f"-{ONLINE_SECONDS} seconds",),
    )
    return {int(row["group_id"]): int(row["c"]) for row in rows}


def prune(days: int) -> int:
    """Удалить старые записи. Возвращает число удалённых."""
    if days <= 0:
        return 0
    before = query_one("SELECT COUNT(*) AS c FROM public_views")
    execute("DELETE FROM public_views WHERE last_at < datetime('now', ?)",
            (f"-{days} days",))
    after = query_one("SELECT COUNT(*) AS c FROM public_views")
    return int(before["c"]) - int(after["c"]) if before and after else 0
