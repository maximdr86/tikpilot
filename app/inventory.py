"""
Паспорт устройства: порты, сервисы, соседи, датчики.

Зачем это отдельно от клиентов и метрик
---------------------------------------

Клиенты отвечают на вопрос «кто подключён», метрики на «как себя чувствует».
Здесь третий вопрос, который задают не реже: «как эта коробка устроена
прямо сейчас». Какие порты живые и на какой скорости, где висит питание
по PoE, какие мосты и VLAN настроены, кто стоит рядом в сети и какие
сервисы на роутере открыты.

Самое ценное тут не порты, а сервисы. Одна забытая точка с включённым
telnet или ftp это дыра, и найти её глазами в парке из полусотни коробок
невозможно: надо зайти в каждую. Панель спрашивает `/ip/service` вместе
со всем остальным, и вопрос закрывается одним взглядом.

Как читается
------------

Каждая таблица читается отдельно и независимо, как у клиентов. На коробке
без PoE нет полей питания, на коробке без сенсоров нет `/system/health`,
на RouterOS 6 половина полей называется иначе. Отсутствие любой таблицы
не повод остаться совсем без данных.

Про `/system/health` стоит сказать отдельно, потому что это ровно тот
случай, на котором мы уже обжигались с `bsd-syslog`. В RouterOS 7 команда
возвращает **строки** вида `name=temperature value=57`, а в шестой это
была одна запись с полями `temperature`, `voltage`. Разбираются обе формы,
и обе проверены тестом: заглушка умеет притворяться и той, и другой.

Данные складываются в базу и показываются оттуда. Карточка обязана
открываться мгновенно и работать, когда точка лежит: «что там было
настроено» чаще всего спрашивают как раз про упавшую точку.
"""

from __future__ import annotations

from typing import Any, Iterable

from .database import get_conn, query, query_one, utcnow, write_lock
from .mikrotik import DeviceError

#: Сервисы, включённость которых сама по себе плохая новость. Не «запрещено»,
#: а «объяснитесь»: telnet и ftp передают пароль открытым текстом, www без
#: ssl тоже, а api и winbox наружу открывают ровно то, чем управляют.
RISKY_SERVICES = {"telnet", "ftp", "www", "api"}

#: Порядок, в котором сервисы показываются. RouterOS отдаёт их вразнобой,
#: а взгляд ищет знакомое место.
SERVICE_ORDER = ("ftp", "ssh", "telnet", "www", "www-ssl", "api", "api-ssl", "winbox")

#: Пороги скоростей для цвета плитки порта. Значения в мегабитах.
SPEED_STEPS = ((10000, "10g"), (2500, "25g"), (1000, "1g"), (100, "100m"), (10, "10m"))

#: Виды интерфейсов, которые показываются плитками. Всё остальное уходит
#: в список: мост и VLAN не имеют ни скорости, ни разъёма.
PHYSICAL_KINDS = ("ether", "sfp", "wlan", "wifi")


# ------------------------------------------------------------------ разбор
def is_yes(value: Any) -> bool:
    """librouteros отдаёт настоящий bool, старые ответы приходят строкой."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "yes", "1")


def speed_mbit(value: Any) -> int:
    """«1Gbps», «100Mbps», «2.5Gbps» в мегабиты. Ноль, если не разобрали."""
    text = str(value or "").strip().lower().replace(" ", "")
    if not text:
        return 0
    try:
        if text.endswith("gbps"):
            return int(float(text[:-4]) * 1000)
        if text.endswith("mbps"):
            return int(float(text[:-4]))
        return int(float(text))
    except ValueError:
        return 0


def speed_class(mbit: int) -> str:
    """Класс скорости для цвета плитки."""
    for limit, name in SPEED_STEPS:
        if mbit >= limit:
            return name
    return ""


def parse_health(rows: Iterable[dict[str, Any]]) -> dict[str, str]:
    """
    Показания датчиков из обеих форм ответа RouterOS.

    Седьмая версия отдаёт по строке на датчик (`name`/`value`), шестая одну
    запись со всеми полями сразу. Обе формы живые: в парке встречаются
    и те, и другие коробки.
    """
    found: dict[str, str] = {}
    for row in rows:
        name = str(row.get("name", "")).strip().lower()
        if name and "value" in row:
            found[name] = str(row.get("value", "")).strip()
            continue
        for key, value in row.items():
            key = str(key).strip().lower()
            if key in ("temperature", "cpu-temperature", "board-temperature1",
                       "voltage", "current", "power-consumption", "fan1-speed",
                       "fan2-speed", "psu1-voltage", "psu2-voltage"):
                found[key] = str(value).strip()
    return found


def temperature_of(health: dict[str, str]) -> str:
    """Температура: у разных плат она называется по-разному."""
    for key in ("temperature", "cpu-temperature", "board-temperature1",
                "board-temperature"):
        if health.get(key):
            return health[key]
    return ""


def voltage_of(health: dict[str, str]) -> str:
    """Напряжение питания, если плата его измеряет."""
    for key in ("voltage", "psu1-voltage", "psu2-voltage"):
        if health.get(key):
            return health[key]
    return ""


def merge_ports(interfaces: Iterable[dict[str, Any]],
                ethernet: Iterable[dict[str, Any]] = (),
                poe: Iterable[dict[str, Any]] = (),
                monitor: Iterable[dict[str, Any]] = (),
                vlans: Iterable[dict[str, Any]] = (),
                poe_live: Iterable[dict[str, Any]] = ()) -> list[dict[str, Any]]:
    """
    Свести список интерфейсов с их железными свойствами.

    `/interface` знает имя, тип и состояние, `/interface/ethernet` знает
    разъём, PoE живёт отдельной таблицей. Ключ везде имя.

    Скорость приходится спрашивать отдельно, через `monitor`. В `print`
    поле `speed` это **настройка** («какую скорость разрешено согласовать»),
    а на части плат его нет вовсе, и на hAP ac lite все порты выглядели
    погасшими при живом линке. Договорённая скорость есть только в monitor.

    По той же причине отдельными таблицами приходят VLAN и питание:

    * тег и родительский интерфейс лежат в `/interface/vlan`, а не в общем
      списке интерфейсов. Сверка с парком показала, что `vlan-id` не приходит
      в `/interface/print` **ни на одной из сорока семи коробок**, и подпись
      VLAN была пустой всегда;
    * `poe-out-status` это живое состояние, оно в `/interface/ethernet/poe/monitor`.
      В `print` лежат только настройки, и отметка «питание подано» не
      появлялась ни разу.
    """
    speed_by_name: dict[str, dict[str, Any]] = {}
    for row in ethernet:
        speed_by_name[str(row.get("name", ""))] = row

    live_by_name: dict[str, dict[str, Any]] = {}
    for row in monitor:
        name = str(row.get("name", "") or "")
        if name:
            live_by_name[name] = row

    poe_by_name: dict[str, dict[str, Any]] = {}
    for row in poe:
        poe_by_name[str(row.get("name", ""))] = row

    poe_live_by_name: dict[str, dict[str, Any]] = {}
    for row in poe_live:
        name = str(row.get("name", "") or "")
        if name:
            poe_live_by_name[name] = row

    vlan_by_name: dict[str, dict[str, Any]] = {}
    for row in vlans:
        name = str(row.get("name", "") or "")
        if name:
            vlan_by_name[name] = row

    result: list[dict[str, Any]] = []
    for row in interfaces:
        name = str(row.get("name", ""))
        if not name:
            continue
        kind = str(row.get("type", "")).lower()
        extra = speed_by_name.get(name, {})
        live = live_by_name.get(name, {})
        power = poe_by_name.get(name, {})
        power_live = poe_live_by_name.get(name, {})

        running = is_yes(row.get("running"))
        disabled = is_yes(row.get("disabled"))
        if live:
            # monitor знает правду о линке лучше, чем флаг running.
            # Кроме `unknown`: по документации это «карта не умеет
            # сообщать состояние линка», а не «линка нет». Считать её
            # погасшей значит затереть флаг `running`, который в этом
            # случае как раз единственный источник
            status = str(live.get("status", "") or "").lower()
            if status and status != "unknown":
                running = status in ("link-ok", "ok")
        # Скорость показывает только работающий порт: у погашенного
        # RouterOS оставляет прошлое значение, и плитка врёт
        rate = speed_mbit(live.get("rate") or extra.get("rate")) if running else 0

        result.append({
            "name": name,
            "kind": kind,
            "physical": any(kind.startswith(p) for p in PHYSICAL_KINDS),
            "running": 1 if running else 0,
            "disabled": 1 if disabled else 0,
            "speed": rate,
            # Живой порт без известной скорости это «работает», а не
            # «нет линка»: серая плитка на рабочем порту врёт человеку
            # ровно в том месте, ради которого он открыл карточку
            "speed_class": speed_class(rate) or ("up" if running else ""),
            "comment": str(row.get("comment", "") or "")[:120],
            "mac": str(row.get("mac-address", "") or ""),
            "poe": str(power.get("poe-out", "") or ""),
            "poe_status": str(power_live.get("poe-out-status", "")
                              or power.get("poe-out-status", "") or ""),
            "detail": _detail(row, kind, vlan_by_name.get(name, {})),
        })

    # Порядок как в Winbox: сначала физические, потом всё остальное
    result.sort(key=lambda r: (not r["physical"], r["name"]))
    return result


## Состояния PoE, как их называет сама RouterOS. Список из документации
## MikroTik («PoE-Out»), а не из головы. Разделитель у MikroTik гуляет:
## `short-circuit` через дефис, а `power_reset` и `controller_error`
## через подчёркивание, поэтому сравниваем по приведённому виду.
POE_FAULTS = (
    "short-circuit",      # замыкание в кабеле или устройство не держит PoE
    "overload",           # превышен предел порта, питание снято
    "voltage-too-low",    # напряжения не хватает, устройство не поднимется
    "voltage-too-high",   # на порт подали больше, чем устройство ждёт
    "current-too-low",    # устройство берёт меньше 10 мА, скорее всего умерло
    "voltage-on-poe-in",  # на порт пришло чужое питание либо сгорела обвязка
    "controller-error",   # контроллер питания не отвечает
)
POE_BUSY = ("power-reset", "controller-init", "controller-upgrade")


def poe_state(status: str) -> str:
    """
    Свести `poe-out-status` к тому, что решает человек, открывший карточку.

    Возвращает `on`, `fault`, `busy`, `idle` или пусто. Раньше карточка
    красила отметку только у `powered-on`, а всё остальное выглядело
    одинаково: порт с замыканием было не отличить от порта, в который
    просто ничего не воткнуто. Для магазина это разница между «камеры нет
    в проекте» и «камера умерла, и никто не знает».
    """
    text = str(status or "").strip().lower().replace("_", "-")
    if not text:
        return ""
    if text.startswith("powered"):
        return "on"
    if text in POE_FAULTS:
        return "fault"
    if text in POE_BUSY:
        return "busy"
    return "idle"


def _detail(row: dict[str, Any], kind: str,
            vlan: dict[str, Any] | None = None) -> str:
    """
    Короткое пояснение для нефизического интерфейса.

    Для VLAN сведения берутся из его собственной таблицы: в общем списке
    интерфейсов ни тега, ни родителя нет. Запись из общего списка осталась
    запасным источником на случай версий, где поля всё-таки приходят.
    """
    if kind == "vlan":
        source = vlan or row
        tag = source.get("vlan-id") or source.get("vlan_id") or ""
        parent = source.get("interface") or ""
        return " · ".join(str(p) for p in (f"VLAN {tag}" if tag else "", parent) if p)
    if kind == "bridge":
        return ""
    return str(row.get("comment", "") or "")


def parse_services(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Сервисы роутера с пометкой опасных.

    В RouterOS 7.21 `/ip/service` отдаёт не только настроенные сервисы,
    но и динамические записи: поднятый dhcp-клиент, resolver, ppp,
    wireguard, а вдобавок **установленные соединения** к самому роутеру.
    Соединение отличается от сервиса тем, что у него заполнены remote
    и local: это не «порт открыт», а «кто-то сейчас подключён».

    Разделять их обязательно, и вот почему. Панель сама сидит на api,
    поэтому в списке всегда есть соединение `api` без ограничения по
    адресам, и без отсева оно каждый раз попадало бы в опасные. Настроенный
    api при этом может быть закрыт списком сетей, то есть предупреждение
    было бы ложным. Ложная тревога хуже отсутствия тревоги: человек
    перестаёт смотреть на предупреждения вообще, и настоящий telnet
    проезжает мимо глаз.
    """
    order = {name: i for i, name in enumerate(SERVICE_ORDER)}
    found: dict[tuple[str, str], dict[str, Any]] = {}

    for row in rows:
        name = str(row.get("name", "")).strip()
        if not name:
            continue

        # Живое соединение к роутеру, а не открытый порт
        if str(row.get("remote", "") or "").strip():
            continue

        dynamic = is_yes(row.get("dynamic"))
        enabled = not is_yes(row.get("disabled")) and not is_yes(row.get("invalid"))
        address = str(row.get("address", "") or "")
        item = {
            "name": name,
            "port": str(row.get("port", "") or ""),
            "enabled": 1 if enabled else 0,
            "dynamic": 1 if dynamic else 0,
            "address": address,
            # Ограничение по адресам меняет дело: telnet, открытый только
            # для своей сети, это не то же самое, что telnet для всех.
            # Динамические записи не судим: их поднимает сам RouterOS
            # под свои нужды, и «выключить» их через /ip/service нельзя
            "risky": 1 if (enabled and not dynamic and name in RISKY_SERVICES
                           and not address) else 0,
        }

        # Один и тот же сервис приходит дважды: настроенный и динамический.
        # Оставляем настроенный, он и есть ответ на вопрос «что открыто»
        key = (name, item["port"])
        old = found.get(key)
        if old is None or (old["dynamic"] and not dynamic):
            found[key] = item

    result = list(found.values())
    result.sort(key=lambda r: (r["dynamic"], order.get(r["name"], 99), r["name"]))
    return result


def parse_scripts(scripts: Iterable[dict[str, Any]] = (),
                  schedulers: Iterable[dict[str, Any]] = ()) -> list[dict[str, Any]]:
    """
    Скрипты и расписания устройства в одном списке.

    Вместе, потому что порознь они не имеют смысла: скрипт без расписания
    обычно никогда не запускается, а расписание без скрипта это одинокая
    строка команд. В карточке их и читают парой.
    """
    result: list[dict[str, Any]] = []

    for row in scripts:
        name = str(row.get("name", "")).strip()
        if not name:
            continue
        result.append({
            "kind": "script",
            "name": name,
            "comment": str(row.get("comment", "") or "")[:200],
            "detail": str(row.get("policy", "") or ""),
            "runs": str(row.get("run-count", "") or ""),
            "last_run": str(row.get("last-started", "") or ""),
            "disabled": 1 if is_yes(row.get("invalid")) else 0,
        })

    for row in schedulers:
        name = str(row.get("name", "")).strip()
        if not name:
            continue
        result.append({
            "kind": "scheduler",
            "name": name,
            "comment": str(row.get("comment", "") or "")[:200],
            "detail": " · ".join(part for part in (
                str(row.get("interval", "") or ""),
                str(row.get("on-event", "") or "")[:80],
            ) if part),
            "runs": str(row.get("run-count", "") or ""),
            "last_run": str(row.get("next-run", "") or ""),
            "disabled": 1 if is_yes(row.get("disabled")) else 0,
        })

    result.sort(key=lambda r: (r["kind"], r["name"].lower()))
    return result


def parse_neighbors(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Соседи из таблицы обнаружения."""
    found = []
    for row in rows:
        identity = str(row.get("identity", "") or "").strip()
        address = str(row.get("address", "") or row.get("address4", "")
                      or row.get("address6", "") or "").strip()
        if not identity and not address:
            continue
        found.append({
            "identity": identity,
            "address": address,
            "mac": str(row.get("mac-address", "") or ""),
            "interface": str(row.get("interface", "") or ""),
            "platform": str(row.get("platform", "") or ""),
            "board": str(row.get("board", "") or ""),
            "version": str(row.get("version", "") or ""),
        })
    found.sort(key=lambda r: (r["identity"].lower(), r["address"]))
    return found


# ------------------------------------------------------------------ чтение
def monitor_ports(mt: Any, ethernet: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Спросить у портов договорённую скорость.

    Одним вызовом на все порты сразу, а не по вызову на порт: на полусотне
    точек разница между одним обменом и восемью заметна, а на тайговом
    канале заметна вдвойне.

    Команда требует список номеров, поэтому передаём имена: `.id` меняются
    между перезагрузками, а имена нет. Если версия команду не понимает,
    остаёмся без скоростей, но с остальным паспортом.
    """
    names = [str(row.get("name", "")) for row in ethernet if row.get("name")]
    if not names:
        return []
    try:
        rows = list(mt.cmd("/interface/ethernet/monitor",
                           **{"numbers": ",".join(names), "once": ""}))
    except Exception:  # noqa: BLE001 — нет команды, значит нет скоростей
        # Но если оборвалась связь, а не команда не понята, продолжать
        # обход нельзя: ответы поедут со сдвигом на одну команду
        if not getattr(mt, "alive", True):
            raise
        return []

    # Часть версий не возвращает имя в ответе, зато порядок совпадает
    # с переданным списком
    for index, row in enumerate(rows):
        if not row.get("name") and index < len(names):
            row["name"] = names[index]
    return rows


def monitor_poe(mt: Any, poe: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Спросить у портов с питанием, подано ли оно сейчас.

    Отдельная команда по той же причине, что и со скоростью: в `print`
    лежат настройки (`poe-out`, приоритет, перезапуск по пингу), а живое
    состояние только в `monitor`. Сверка с парком показала, что
    `poe-out-status` не приходит в `print` ни на одной коробке, и отметка
    «питание подано» в карточке не появлялась ни разу.

    Спрашиваем одним вызовом на все порты с питанием, а не по вызову
    на порт: на полусотне точек разница заметна.
    """
    names = [str(row.get("name", "")) for row in poe if row.get("name")]
    if not names:
        return []
    try:
        rows = list(mt.cmd("/interface/ethernet/poe/monitor",
                           **{"numbers": ",".join(names), "once": ""}))
    except Exception:  # noqa: BLE001 — нет команды, значит нет состояния
        # Как и у скоростей: оборванная связь это не «нет команды»,
        # и продолжать обход нельзя, иначе ответы поедут со сдвигом
        if not getattr(mt, "alive", True):
            raise
        return []

    for index, row in enumerate(rows):
        if not row.get("name") and index < len(names):
            row["name"] = names[index]
    return rows


def collect(mt: Any) -> dict[str, Any]:
    """
    Прочитать паспорт устройства в уже открытой сессии.

    Каждая команда обёрнута отдельно: на коробке без PoE нет таблицы
    питания, на коробке без сенсоров нет health, а на RouterOS 6 нет
    части команд вовсе. Одна пустая таблица не должна оставлять карточку
    без всех остальных.
    """
    def safe(command: str) -> list[dict[str, Any]]:
        """
        Спросить таблицу, пережив её отсутствие, но не обрыв связи.

        Разница принципиальная, и она стоила испорченного паспорта.
        «Нет такой таблицы» это ответ роутера: соединение живо, следующая
        команда получит свой ответ. Таймаут и сетевая ошибка это ответ,
        который остался недочитанным в сокете, и дальше каждая команда
        читает хвост предыдущей: расписания приезжают с именами портов,
        интерфейсы с именами скриптов. Мусор при этом выглядит как
        нормальные данные, поэтому молчать нельзя, надо прекращать обход.
        """
        try:
            return list(mt.cmd(command))
        except DeviceError:
            if not getattr(mt, "alive", True):
                raise
            return []
        except Exception:  # noqa: BLE001 — нет такой таблицы, значит нет
            return []

    health = parse_health(safe("/system/health/print"))
    ethernet = safe("/interface/ethernet/print")
    poe = safe("/interface/ethernet/poe/print")
    return {
        "scripts": parse_scripts(safe("/system/script/print"),
                                 safe("/system/scheduler/print")),
        "ports": merge_ports(
            safe("/interface/print"),
            ethernet,
            poe,
            monitor_ports(mt, ethernet),
            # Тег и родитель VLAN лежат в своей таблице, в общем списке
            # интерфейсов их нет ни на одной коробке парка
            safe("/interface/vlan/print"),
            # Живое состояние питания: подано или нет. В `print` только
            # настройки, поэтому отметка не появлялась никогда
            monitor_poe(mt, poe),
        ),
        "services": parse_services(safe("/ip/service/print")),
        "neighbors": parse_neighbors(safe("/ip/neighbor/print")),
        "temperature": temperature_of(health),
        "voltage": voltage_of(health),
        "health": health,
    }


# ---------------------------------------------------------------- хранение
def save(device_id: int, data: dict[str, Any]) -> None:
    """
    Записать паспорт, заменив прежний.

    Именно заменив, а не дополнив, в отличие от клиентов. У клиента ценна
    история («когда эту камеру видели последний раз»), а у порта нет:
    список интерфейсов это снимок настроек, и вчерашний VLAN, удалённый
    сегодня, в карточке только путает.
    """
    now = utcnow()
    with write_lock:
        conn = get_conn()
        conn.execute("BEGIN")
        try:
            for table in ("device_ports", "device_services", "device_neighbors",
                          "device_scripts"):
                conn.execute(f"DELETE FROM {table} WHERE device_id = ?", (device_id,))

            conn.executemany(
                "INSERT INTO device_ports (device_id, name, kind, physical, running,"
                " disabled, speed, speed_class, poe, poe_status, mac, comment, detail,"
                " updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(device_id, p["name"], p["kind"], p["physical"], p["running"],
                  p["disabled"], p["speed"], p["speed_class"], p["poe"],
                  p["poe_status"], p["mac"], p["comment"], p["detail"], now)
                 for p in data.get("ports", [])],
            )
            conn.executemany(
                "INSERT INTO device_services (device_id, name, port, enabled, address,"
                " risky, dynamic, updated_at) VALUES (?,?,?,?,?,?,?,?)",
                [(device_id, s["name"], s["port"], s["enabled"], s["address"],
                  s["risky"], s.get("dynamic", 0), now)
                 for s in data.get("services", [])],
            )
            conn.executemany(
                "INSERT INTO device_neighbors (device_id, identity, address, mac,"
                " interface, platform, board, version, updated_at)"
                " VALUES (?,?,?,?,?,?,?,?,?)",
                [(device_id, n["identity"], n["address"], n["mac"], n["interface"],
                  n["platform"], n["board"], n["version"], now)
                 for n in data.get("neighbors", [])],
            )
            conn.executemany(
                "INSERT INTO device_scripts (device_id, kind, name, comment, detail,"
                " runs, last_run, disabled, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                [(device_id, s["kind"], s["name"], s["comment"], s["detail"],
                  s["runs"], s["last_run"], s["disabled"], now)
                 for s in data.get("scripts", [])],
            )
            conn.execute(
                "UPDATE devices SET temperature = ?, voltage = ?, inventory_at = ?"
                " WHERE id = ?",
                (data.get("temperature", ""), data.get("voltage", ""), now, device_id),
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise


def forget(device_id: int) -> None:
    """
    Забыть паспорт точки. На устройстве при этом ничего не меняется.

    Нужно ровно для одного случая, зато настоящего: в снимке оказалась
    ерунда, а точка на связь не выходит, и заменить снимок нечем. Пока
    такой снимок лежит в базе, он попадает и в карточку, и в сводку
    «Что стоит на точках», где выглядит как настоящие расписания.

    Прежде эту кнопку заменял бы следующий удачный обход, но на точке
    с тайговым каналом он может не случиться неделю.
    """
    with write_lock:
        conn = get_conn()
        conn.execute("BEGIN")
        try:
            for table in ("device_ports", "device_services", "device_neighbors",
                          "device_scripts"):
                conn.execute(f"DELETE FROM {table} WHERE device_id = ?", (device_id,))
            conn.execute(
                "UPDATE devices SET temperature = '', voltage = '', inventory_at = ''"
                " WHERE id = ?", (device_id,))
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise


#: Порты, при которых номер в адресе браузера не нужен
_DEFAULT_WEB_PORTS = {"http": "80", "https": "443"}


def webfig_url(host: str, services: Iterable[dict[str, Any]]) -> str:
    """
    Адрес WebFig на самой точке, либо пустая строка, если веб выключен.

    Порт не угадывается, а берётся из паспорта: там записано, включён ли
    `www`, на каком он порту и есть ли `www-ssl`. Гадать нельзя, потому
    что перенести веб с восьмидесятого порта это первое, что делают на
    точке, смотрящей наружу, а кнопка, ведущая в никуда, хуже её
    отсутствия.

    При включённых обоих сервисах выбирается `https`: раз шифрованный
    вход настроен, отправлять человека по открытому незачем.

    Ссылка ведёт с машины человека, а не с сервера панели. Дойдёт она
    или нет, отсюда не проверить: у панели туннель есть, а у ноутбука
    может и не быть. Поэтому кнопка ничего не обещает, а просто ведёт.
    """
    host = str(host or "").strip()
    if not host:
        return ""
    # IPv6 в адресе браузера пишется в скобках, иначе двоеточия адреса
    # и порта неразличимы
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    enabled = {str(s.get("name") or ""): s for s in services
               if int(s.get("enabled") or 0)}
    for name, scheme in (("www-ssl", "https"), ("www", "http")):
        service = enabled.get(name)
        if service is None:
            continue
        port = str(service.get("port") or "").strip()
        tail = "" if port in ("", _DEFAULT_WEB_PORTS[scheme]) else f":{port}"
        return f"{scheme}://{host}{tail}/webfig/"
    return ""


def load(device_id: int) -> dict[str, Any]:
    """Паспорт устройства из базы, готовый для карточки."""
    ports = [dict(r) for r in query(
        "SELECT * FROM device_ports WHERE device_id = ? ORDER BY physical DESC, name",
        (device_id,))]
    services = [dict(r) for r in query(
        "SELECT * FROM device_services WHERE device_id = ? ORDER BY id", (device_id,))]
    neighbors = [dict(r) for r in query(
        "SELECT * FROM device_neighbors WHERE device_id = ? ORDER BY identity, address",
        (device_id,))]
    scripts = [dict(r) for r in query(
        "SELECT * FROM device_scripts WHERE device_id = ? ORDER BY kind, name",
        (device_id,))]

    known = _known_neighbors(neighbors)
    for row in neighbors:
        row["known_id"] = known.get(row["address"]) or known.get(row["identity"].lower())

    return {
        "ports": [p for p in ports if p["physical"]],
        "logical": [p for p in ports if not p["physical"]],
        # Настроенные и динамические показываются порознь: первые это
        # решения человека, вторые побочный продукт работы роутера, и
        # смешивать их значит утопить восемь важных строк в двух десятках
        "services": [s for s in services if not s["dynamic"]],
        "dynamic": [s for s in services if s["dynamic"]],
        "risky": [s for s in services if s["risky"]],
        "neighbors": neighbors,
        "scripts": scripts,
        "has_data": bool(ports or services or neighbors or scripts),
        # Адрес веб-интерфейса самой точки. Считается по всем сервисам,
        # а не по отфильтрованным выше: www среди динамических не бывает,
        # но зависеть от этого незачем
        "webfig": webfig_url(
            (query_one("SELECT host FROM devices WHERE id = ?", (device_id,)) or
             {"host": ""})["host"],
            services),
    }


def _known_neighbors(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    """
    Сопоставить соседей с точками самой панели.

    Сосед, который есть в панели, должен быть ссылкой: «рядом стоит
    DC-CORE01» полезнее, чем «рядом стоит 10.0.1.1». Ищем и по адресу,
    и по identity: адрес соседа бывает туннельным, а имя роутер называет
    своё собственное.
    """
    addresses = {str(r.get("address") or "") for r in rows if r.get("address")}
    names = {str(r.get("identity") or "").lower() for r in rows if r.get("identity")}
    if not addresses and not names:
        return {}

    found: dict[str, int] = {}
    for row in query("SELECT id, host, name, identity FROM devices WHERE enabled = 1"):
        if row["host"] in addresses:
            found[row["host"]] = row["id"]
        for label in (row["name"], row["identity"]):
            if label and str(label).lower() in names:
                found[str(label).lower()] = row["id"]
    return found


def risky_fleet(scope: tuple[str, list[Any]] = ("", [])) -> list[dict[str, Any]]:
    """
    Опасные сервисы по всему парку.

    Ради этого всё и затевалось: «где до сих пор включён telnet» это
    вопрос ко всему парку сразу, а не к карточке одной точки.
    """
    rows = query(
        "SELECT s.name, s.port, d.id AS device_id, d.name AS device_name "
        "FROM device_services s JOIN devices d ON d.id = s.device_id "
        f"WHERE s.risky = 1 AND d.enabled = 1{scope[0]} "
        "ORDER BY s.name, d.name COLLATE NOCASE",
        tuple(scope[1]),
    )
    return [dict(r) for r in rows]


# Отдельной уборки за удалённым устройством здесь нет намеренно: у всех
# трёх таблиц внешний ключ с ON DELETE CASCADE, а PRAGMA foreign_keys в базе
# включена. Дублировать это кодом значит однажды получить два разных ответа
# на вопрос, что происходит при удалении точки.
