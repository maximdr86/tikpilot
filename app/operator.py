"""
Оператор связи площадки: кто даёт точке интернет.

Зачем
-----

Когда точка падает, первый вопрос не «что с роутером», а «чей канал».
Полсотни точек на четырёх операторах, и по журналу видно только адрес.
Ответ есть у самой точки, надо просто его прочитать.

Откуда берётся
--------------

Два источника, в таком порядке:

1. **Модем.** `/interface/lte/monitor` отдаёт код сети (MCC/MNC) и, на
   части прошивок, готовое имя. Код точнее имени: имя модем берёт из
   прошивки и пишет как придётся, от «MTS RUS» до «MTS-RUS», а код
   `25001` это всегда МТС. Поэтому имя берём по коду, а строку от
   модема оставляем запасным вариантом.

2. **Реестр адресов.** Там, где модема нет, спрашиваем RDAP о публичном
   адресе точки. Это единственное место во всей панели, которое ходит
   в интернет, поэтому оно выключено по умолчанию и включается
   `OPERATOR_LOOKUP=1`. Серые адреса не спрашиваем вовсе: за NAT
   оператора реестр знает провайдера самого NAT, а не точки.

Поставленное руками сильнее найденного: человек, подписавший точку
«Мегафон, договор 512», знает больше, чем модем.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import urllib.request
from typing import Any

from .config import BASE_DIR, settings
from .database import execute_changes, query, query_one, utcnow

log = logging.getLogger("tikpilot.operator")

#: Источник сведений. Ручной сильнее всех, дальше по точности.
MANUAL = "manual"
LTE = "lte"
WHOIS = "whois"

#: Коды сетей российских операторов: MCC 250 и соседи. Список короткий
#: намеренно: он покрывает то, что реально встречается в парке, а всё
#: остальное показывается кодом, и это честнее выдуманного имени.
NETWORKS = {
    "25001": "МТС",
    "25002": "МегаФон",
    "25003": "НСС",
    "25004": "Сибчеллендж",
    "25005": "ЕТК",
    "25007": "СМАРТС",
    "25009": "Скайлинк",
    "25011": "Yota",
    "25012": "Байкалвестком",
    "25013": "Кубань GSM",
    "25016": "НТК",
    "25017": "Утел",
    "25019": "Инфотел",
    "25020": "Tele2",
    "25028": "Вояж",
    "25035": "МОТИВ",
    "25039": "Ростелеком",
    "25050": "Ростелеком",
    "25062": "Тинькофф Мобайл",
    "25099": "Билайн",
    "40101": "Beeline KZ",
    "43701": "Beeline KG",
}

#: Соответствие «кусок строки реестра -> имя и цвет» лежит рядом файлом.
#: В коде его держать нельзя: операторы переименовываются, покупают друг
#: друга и заводят новые сети, а править ради этого исходник и выпускать
#: версию неразумно. Файл читается при старте и правится руками.
OPERATORS_PATH = BASE_DIR / "app" / "operators.json"

#: Свои соответствия. Регионального провайдера в общий список не впишешь,
#: а обновление панели затрёт правку в `operators.json`. Поэтому имена,
#: заданные на месте, лежат отдельно в данных и проверяются первыми.
LOCAL_PATH = settings.data_dir / "operators.local.json"

#: Цвета меток, которые понимает оформление.
COLORS = ("slate", "blue", "green", "amber", "red", "violet", "cyan", "pink")

_registry: list[tuple[str, str, str]] | None = None


def _read(path: Any) -> list[tuple[str, str, str]]:
    """Прочитать один файл соответствий. Нет файла - нет и соответствий."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, ValueError):
        log.warning("Не удалось прочитать %s, имена операторов останутся как в реестре", path)
        return []
    rows = []
    for row in data.get("operators", []) if isinstance(data, dict) else []:
        try:
            rows.append((str(row[0]).upper(), str(row[1]),
                         str(row[2]) if len(row) > 2 else ""))
        except (TypeError, IndexError, KeyError):
            continue
    return rows


def load_registry() -> list[tuple[str, str, str]]:
    """
    Соответствия «строка реестра -> имя»: сначала свои, потом общие.

    Порядок важен: побеждает первое совпавшее правило, и правило,
    заданное на месте, должно перебивать поставляемое с панелью.
    """
    global _registry

    if _registry is None:
        _registry = _read(LOCAL_PATH) + _read(OPERATORS_PATH)
    return _registry


def forget_registry() -> None:
    """Забыть прочитанные соответствия. Нужно тестам и странице настроек."""
    global _registry
    _registry = None


def save_local(needle: str, name: str, color: str = "slate") -> None:
    """
    Запомнить своё имя для строки реестра.

    Пустое имя удаляет правило: так исправляется опечатка, а строка
    возвращается к виду из реестра.
    """
    needle = str(needle or "").strip().upper()
    name = str(name or "").strip()[:60]
    if not needle:
        return
    if color not in COLORS:
        color = "slate"

    rows = [row for row in _read(LOCAL_PATH) if row[0] != needle]
    if name:
        rows.insert(0, (needle, name, color))
    LOCAL_PATH.write_text(
        json.dumps({
            "_note": "Свои имена операторов. Файл создан панелью,"
                     " обновление его не трогает.",
            "operators": [list(row) for row in rows],
        }, ensure_ascii=False, indent=2),
        encoding="utf-8")
    forget_registry()


def unknown_names() -> list[dict[str, Any]]:
    """
    Строки реестра, для которых имени пока нет, и сколько точек за ними.

    Это и есть список работы на странице настроек: назвал один раз,
    и все точки этого провайдера подписаны по-человечески.
    """
    found = []
    for row in query("SELECT operator AS name, COUNT(*) AS devices FROM devices"
                     " WHERE operator <> '' AND operator_source IN ('whois', 'lte')"
                     " GROUP BY operator ORDER BY COUNT(*) DESC, operator"):
        if not color_of(str(row["name"])):
            found.append({"name": str(row["name"]), "devices": int(row["devices"])})
    return found


def color_of(name: str) -> str:
    """
    Цвет метки оператора. Пусто, если оператор незнакомый.

    Цвет, а не логотип: логотипы операторов это чужие товарные знаки,
    и класть их в репозиторий под MIT нельзя. Цветная метка узнаётся
    в списке ничуть не хуже, а прав ни на что не требует.
    """
    for _needle, title, color in load_registry():
        if title == name:
            return color
    return ""


def name_by_code(code: Any) -> str:
    """
    Имя оператора по коду сети.

    Код приходит в разном виде: «25001», «250 01», «MTS 25001». Пробелы
    и дефисы между цифрами убираем, потом берём первую группу из пяти
    или шести цифр. Именно так, а не «все цифры подряд»: в строке вроде
    «LTE 4G 25001» иначе получилось бы «42500».
    """
    text = re.sub(r"[\s\-]+", "", str(code or ""))
    digits = re.search(r"\d{5,6}", text)
    if not digits:
        return ""
    return NETWORKS.get(digits.group(0)[:5], "")


def from_lte(rows: Any) -> dict[str, str]:
    """
    Разобрать ответ `/interface/lte/monitor`.

    Возвращает словарь с именем оператора, кодом сети, технологией
    и уровнем сигнала. Пустой словарь означает «модема нет или он
    не зарегистрирован», и это не ошибка: у половины парка проводной
    канал.
    """
    for row in rows or ():
        status = str(row.get("status") or row.get("registration-status") or "").lower()
        if status and "registered" not in status and "connected" not in status:
            continue

        code = str(row.get("current-operator") or row.get("operator") or "").strip()
        reported = str(row.get("current-operator-name") or row.get("provider") or "").strip()
        name = name_by_code(code) or reported
        if not name:
            continue

        return {
            "name": name,
            "code": re.sub(r"\D", "", code)[:6],
            "technology": str(row.get("access-technology") or "").strip(),
            "signal": str(row.get("rsrp") or row.get("rssi") or "").strip(),
        }
    return {}


def is_public(address: Any) -> bool:
    """
    Публичный ли адрес.

    Серый адрес спрашивать в реестре бессмысленно: за NAT оператора
    ответом будет владелец этого NAT, то есть чаще всего сам оператор
    магистрали, а не тот, кто даёт канал точке.
    """
    text = str(address or "").split("/")[0].strip()
    if not text:
        return False
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_multicast or ip.is_reserved
                # 100.64.0.0/10: адреса CGNAT, у мобильных операторов
                # почти всегда именно они
                or ip in ipaddress.ip_network("100.64.0.0/10"))


def registry_name(text: str) -> str:
    """
    Узнаваемое имя оператора из строки реестра, иначе строка как есть.

    «Как есть» это осознанный выбор: `RU-XYZ-NET` читать неприятно, но
    выдуманное имя хуже непонятного. Незнакомую строку видно, и её можно
    добавить в `operators.json` одной строкой.
    """
    upper = str(text or "").upper()
    for needle, name, _color in load_registry():
        if needle in upper:
            return name
    return str(text or "").strip()[:60]


#: Ответы реестра на процесс. Соседние точки часто сидят в одной сети
#: оператора, и спрашивать про каждую отдельно незачем: ключ это /24.
_cache: dict[str, str] = {}


def _network_key(address: str) -> str:
    """Ключ кэша: сеть /24. Соседние адреса принадлежат одному владельцу."""
    parts = str(address).split("/")[0].split(".")
    return ".".join(parts[:3]) if len(parts) == 4 else str(address)


def _from_rdap(data: dict) -> str:
    """
    Вытащить владельца из ответа RDAP, как он там записан.

    Возвращается именно строка реестра, без перевода в человеческое имя:
    её сохраняют рядом с именем, чтобы уточнённое соответствие можно
    было применить потом, не опрашивая парк заново.

    Сначала имя самой сети (`name`): у операторов оно говорящее,
    вроде `MTS-NET` или `MEGAFON-RU`. Если его нет, идём в список
    организаций и берём имя оттуда: там оно записано человеческим
    языком, но длиннее и с юридической формой.
    """
    netname = str(data.get("name") or "")
    if netname and color_of(registry_name(netname)):
        return netname

    # Таблица соответствий русская, и за границей она пуста. Зато сам
    # реестр знает владельца по имени: `DTAG-DIAL18` ничего не говорит,
    # а «Deutsche Telekom AG» рядом в той же записи говорит всё.
    # Поэтому незнакомый netname уступает имени организации.
    for entity in data.get("entities") or ():
        vcard = entity.get("vcardArray") or []
        if len(vcard) < 2:
            continue
        for field in vcard[1]:
            if len(field) >= 4 and field[0] == "fn" and field[3]:
                org = str(field[3]).strip()
                # Реестры прячут частных лиц за заглушками, и подписывать
                # ими точку незачем: netname хотя бы что-то значит
                if org and not org.lower().startswith(("private", "not disclosed",
                                                       "redacted", "unknown")):
                    return org[:120]

    return netname or str(data.get("handle") or "")[:120]


def lookup_ip(address: str, timeout: float = 6.0) -> str:
    """
    Спросить реестр, чей это адрес.

    RDAP, а не whois: обычный JSON вместо текста, у которого в каждом
    реестре свой формат. Ходим через `rdap.org`: он сам перенаправляет
    в нужный реестр, и не приходится гадать, RIPE это, ARIN или APNIC.

    Ответы кэшируются по сети /24: полсотни точек одного оператора
    сидят в соседних адресах, и спрашивать про каждую отдельно значит
    молотить чужой сервис без всякой пользы.

    Ошибки глотаем молча: сведения об операторе приятны, но не
    настолько, чтобы падать из-за них или задерживать опрос парка.
    """
    if not is_public(address):
        return ""

    plain = str(address).split("/")[0]
    key = _network_key(plain)
    if key in _cache:
        return _cache[key]

    name = ""
    for url in ("https://rdap.org/ip/%s" % plain,
                "https://rdap.db.ripe.net/ip/%s" % plain):
        try:
            request = urllib.request.Request(
                url, headers={"Accept": "application/rdap+json",
                              "User-Agent": "tikpilot"})
            with urllib.request.urlopen(request, timeout=timeout) as answer:
                data = json.loads(answer.read().decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001 — сеть, разбор, что угодно
            log.debug("RDAP не ответил про %s (%s): %s", plain, url, exc)
            continue
        name = _from_rdap(data)
        if name:
            break

    _cache[key] = name
    return name


def forget_cache() -> None:
    """Забыть ответы реестра. Нужно тестам и при смене настроек."""
    _cache.clear()


def save(device_id: int, name: str, source: str, detail: str = "",
         raw: str = "") -> None:
    """
    Записать оператора, не затирая поставленное руками.

    Человек, подписавший точку «Мегафон, договор 512», знает больше
    модема, и следующий опрос не должен стирать эту строку.
    """
    if not name:
        return
    row = query_one("SELECT operator, operator_source FROM devices WHERE id = ?",
                    (device_id,))
    if row is None:
        return
    if str(row["operator_source"] or "") == MANUAL and str(row["operator"] or "").strip():
        return

    execute_changes(
        "UPDATE devices SET operator = ?, operator_source = ?, operator_detail = ?,"
        " operator_raw = ?, operator_at = ? WHERE id = ?",
        (name[:60], source, detail[:120], raw[:120], utcnow(), device_id),
    )


def _safe(mt: Any, command: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Спросить таблицу, пережив её отсутствие."""
    rows, _error = _probe(mt, command, **kwargs)
    return rows


def _probe(mt: Any, command: str, **kwargs: Any) -> tuple[list[dict[str, Any]], str]:
    """
    То же самое, но с текстом ошибки.

    Молчаливое «не получилось» стоило разбирательства: на точке с живым
    модемом панель писала «модема нет», хотя на самом деле команда
    вернула отказ. Причину надо показывать, а не глотать.
    """
    try:
        return list(mt.cmd(command, **kwargs)), ""
    except Exception as exc:  # noqa: BLE001 — нет таблицы, нет прав, что угодно
        return [], str(exc)[:120]


def from_modem(mt: Any) -> tuple[dict[str, str], str]:
    """
    Спросить модем, если он есть.

    Возвращает `(сведения, пояснение)`. Пояснение пустое, когда модема
    действительно нет, и содержит ответ роутера, когда модем есть,
    а спросить его не вышло: без этого «нет модема» врёт.

    Интерфейсы перечисляем и спрашиваем по имени, а не по номеру:
    номер зависит от порядка в списке, а `numbers=0` на коробке без
    модема означает «первый попавшийся интерфейс», то есть промах.
    """
    rows, error = _probe(mt, "/interface/lte/print")
    if error:
        return {}, f"модем не опрошен: {error}"
    if not rows:
        return {}, ""

    notes: list[str] = []
    for row in rows:
        name = str(row.get("name") or row.get("default-name") or "").strip()
        if not name:
            continue

        # Часть прошивок отдаёт оператора прямо в списке интерфейсов,
        # и тогда отдельный опрос не нужен вовсе
        found = from_lte([row])
        if found.get("name"):
            return found, ""

        answer, fail = _probe(mt, "/interface/lte/monitor",
                              **{"numbers": name, "once": ""})
        if fail:
            notes.append(f"{name}: {fail}")
            continue
        found = from_lte(answer)
        if found.get("name"):
            return found, ""

        # Модем есть и ответил, но оператора не назвал: чаще всего он
        # не зарегистрирован в сети, и это стоит сказать прямо
        status = ""
        for item in answer:
            status = str(item.get("status")
                         or item.get("registration-status") or "").strip()
            if status:
                break
        notes.append(f"{name}: {status or 'оператор не назван'}")

    return {}, ("модем есть, но оператора не сказал · " + " · ".join(notes)
                if notes else "")


def public_address(mt: Any) -> str:
    """
    Публичный адрес точки, каким его видно снаружи.

    Три источника, по убыванию надёжности:

    1. `/ip/cloud` — служба MikroTik уже знает внешний адрес роутера,
       если она включена. Ничего не стоит и работает за любым NAT.
    2. Адрес на самом интерфейсе — годится там, где провайдер выдаёт
       белый адрес напрямую.
    3. Адрес, который панель видит у SSTP-подключения точки к серверу,
       здесь недоступен: он есть на сервере, а не на роутере.

    За NAT оператора первые два молчат, и это нормально: тогда оператор
    остаётся неизвестным, пока его не впишут руками.
    """
    for row in _safe(mt, "/ip/cloud/print"):
        address = str(row.get("public-address") or "").strip()
        if is_public(address):
            return address

    for row in _safe(mt, "/ip/address/print"):
        address = str(row.get("address") or "")
        if is_public(address):
            return address.split("/")[0]

    return ""


def remember_miss(device_id: int, note: str) -> None:
    """
    Запомнить, что оператора узнать не вышло, и почему.

    Нужно для двух вещей: не спрашивать снова каждый полный опрос
    и показать человеку причину вместо молчаливого прочерка.
    """
    row = query_one("SELECT operator, operator_source FROM devices WHERE id = ?",
                    (device_id,))
    if row is None or str(row["operator"] or "").strip():
        return
    execute_changes(
        "UPDATE devices SET operator_source = 'none', operator_detail = ?,"
        " operator_at = ? WHERE id = ?",
        (str(note or "")[:120], utcnow(), device_id),
    )


def rename_known() -> int:
    """
    Привести уже сохранённых операторов к человеческим именам.

    Соответствия пополняются, а в базе лежат строки, найденные раньше:
    `RU-MTU-20060821` так и останется, пока точку не опросят снова, а это
    сутки. Проход при старте применяет свежий список сразу ко всему парку.

    Вписанное руками не трогаем: это не строка реестра, а решение
    человека, и приводить его к «правильному» виду не наше дело.
    """
    changed = 0
    for row in query("SELECT id, operator, operator_raw FROM devices"
                     " WHERE operator <> '' AND operator_source IN ('whois', 'lte')"):
        # Строка реестра важнее уже показанного имени: соответствие могли
        # уточнить (не «Дансер», а «Данцер»), и от готового имени обратно
        # к строке не вернуться. Записи, снятые старой версией, её ещё
        # не имеют, для них остаётся то, что видно
        pretty = registry_name(str(row["operator_raw"] or row["operator"]))
        if pretty and pretty != row["operator"]:
            execute_changes("UPDATE devices SET operator = ? WHERE id = ?",
                            (pretty, row["id"]))
            changed += 1
    return changed


def collect(mt: Any, device: dict[str, Any]) -> tuple[str, str]:
    """
    Определить оператора точки в уже открытой сессии.

    Возвращает `(имя, пояснение)`. Пустое имя это не ошибка, а ответ
    «узнать неоткуда», и пояснение говорит почему. Молчать здесь нельзя:
    пустая колонка без объяснения выглядит как сломанная возможность,
    и именно так она и выглядела.
    """
    modem, modem_note = from_modem(mt)
    if modem.get("name"):
        detail = " · ".join(part for part in (modem.get("technology"),
                                              modem.get("signal")) if part)
        save(device["id"], modem["name"], LTE, detail)
        return modem["name"], detail

    address = public_address(mt)
    if not address:
        # Пояснение от модема важнее общего: если он есть и молчит,
        # «нет модема» это неправда, и человек будет искать не там
        if modem_note:
            return "", modem_note
        return "", "нет модема, публичный адрес точки не виден (NAT провайдера)"

    if not settings.operator_lookup:
        return "", (f"публичный адрес {address}, осталось разрешить запрос "
                    "в реестр: OPERATOR_LOOKUP=1 в .env и перезапуск")

    raw = lookup_ip(address)
    if raw:
        name = registry_name(raw)
        save(device["id"], name, WHOIS, address, raw)
        return name, address

    return "", f"реестр не ответил про {address}"
