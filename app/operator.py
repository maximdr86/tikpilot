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

from .config import settings
from .database import execute_changes, query_one, utcnow

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

#: Как называются в реестре крупные операторы. Netname у них говорящий,
#: но с суффиксами вроде «-NET» и «-RU», поэтому ищем вхождение.
REGISTRY_NAMES = (
    ("MTS", "МТС"),
    ("MEGAFON", "МегаФон"),
    ("MF-", "МегаФон"),
    ("BEELINE", "Билайн"),
    ("VIMPELCOM", "Билайн"),
    ("TELE2", "Tele2"),
    ("T2-", "Tele2"),
    ("YOTA", "Yota"),
    ("SCARTEL", "Yota"),
    ("ROSTELECOM", "Ростелеком"),
    ("RTCOMM", "Ростелеком"),
    ("TTK", "ТрансТелеКом"),
    ("ER-TELECOM", "Дом.ru"),
    ("MOTIV", "МОТИВ"),
)


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
    """Узнаваемое имя оператора из строки реестра, иначе строка как есть."""
    upper = str(text or "").upper()
    for needle, name in REGISTRY_NAMES:
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
    Вытащить имя владельца из ответа RDAP.

    Сначала имя самой сети (`name`): у операторов оно говорящее,
    вроде `MTS-NET` или `MEGAFON-RU`. Если его нет, идём в список
    организаций и берём имя оттуда: там оно записано человеческим
    языком, но длиннее и с юридической формой.
    """
    if data.get("name"):
        return registry_name(str(data["name"]))

    for entity in data.get("entities") or ():
        vcard = entity.get("vcardArray") or []
        if len(vcard) < 2:
            continue
        for field in vcard[1]:
            if len(field) >= 4 and field[0] == "fn" and field[3]:
                return registry_name(str(field[3]))

    if data.get("handle"):
        return registry_name(str(data["handle"]))
    return ""


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


def save(device_id: int, name: str, source: str, detail: str = "") -> None:
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
        " operator_at = ? WHERE id = ?",
        (name[:60], source, detail[:120], utcnow(), device_id),
    )


def _safe(mt: Any, command: str, **kwargs: Any) -> list[dict[str, Any]]:
    """Спросить таблицу, пережив её отсутствие."""
    try:
        return list(mt.cmd(command, **kwargs))
    except Exception:  # noqa: BLE001 — нет модема, нет и таблицы
        return []


def from_modem(mt: Any) -> dict[str, str]:
    """
    Спросить модем, если он есть.

    Интерфейсы перечисляем и спрашиваем по имени, а не по номеру:
    номер зависит от порядка в списке, а `numbers=0` на коробке без
    модема означает «первый попавшийся интерфейс», то есть промах.
    """
    for row in _safe(mt, "/interface/lte/print"):
        name = str(row.get("name") or row.get("default-name") or "").strip()
        if not name:
            continue
        found = from_lte(_safe(mt, "/interface/lte/monitor",
                               **{"numbers": name, "once": ""}))
        if found.get("name"):
            return found
        # Часть прошивок отдаёт оператора прямо в списке интерфейсов
        found = from_lte([row])
        if found.get("name"):
            return found
    return {}


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


def collect(mt: Any, device: dict[str, Any]) -> tuple[str, str]:
    """
    Определить оператора точки в уже открытой сессии.

    Возвращает `(имя, пояснение)`. Пустое имя это не ошибка, а ответ
    «узнать неоткуда», и пояснение говорит почему. Молчать здесь нельзя:
    пустая колонка без объяснения выглядит как сломанная возможность,
    и именно так она и выглядела.
    """
    modem = from_modem(mt)
    if modem.get("name"):
        detail = " · ".join(part for part in (modem.get("technology"),
                                              modem.get("signal")) if part)
        save(device["id"], modem["name"], LTE, detail)
        return modem["name"], detail

    address = public_address(mt)
    if not address:
        return "", "нет модема, публичный адрес точки не виден (NAT провайдера)"

    if not settings.operator_lookup:
        return "", (f"публичный адрес {address}, осталось разрешить запрос "
                    "в реестр: OPERATOR_LOOKUP=1 в .env и перезапуск")

    name = lookup_ip(address)
    if name:
        save(device["id"], name, WHOIS, address)
        return name, address

    return "", f"реестр не ответил про {address}"
