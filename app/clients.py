"""
Клиенты за роутерами: что подключено к площадке и куда воткнуто.

Панель управляет роутерами, но вопрос на площадке обычно звучит иначе:
«в какой порт воткнут этот телевизор», «какой адрес у кассы», «когда эта
камера последний раз была в сети». Ответ есть на самом роутере, надо лишь
собрать его в одном месте.

Источники, потому что поодиночке каждый неполон
-----------------------------------------------

* `/ip/dhcp-server/lease` — имя, адрес, MAC. Лучший источник, но видит
  только тех, кому адрес выдал сам роутер;
* `/ip/arp` — MAC, адрес, интерфейс. Ловит тех, у кого адрес прописан
  руками: как раз кассы, камеры и принтеры, то есть половина площадки;
* `/interface/bridge/host` — MAC и **физический порт**. Единственный,
  кто отвечает на «куда воткнут», потому что в мосту все интерфейсы
  выглядят одним;
* `/interface/wireless/registration-table` и `/interface/wifi/...` —
  кто подключён по воздуху, с каким сигналом и к какой сети.

Комментарий, если он проставлен на роутере, забирается вместе с остальным:
администратор уже назвал эту железку один раз, и заставлять его называть
её второй раз в панели незачем.

Данные сливаются по MAC: он есть во всех источниках и не меняется. Адрес
и имя меняются, порт меняется, MAC остаётся.

Что в список не попадает
------------------------

* **сам роутер.** В таблице моста его собственные интерфейсы помечены
  `local=yes`. Без отсева в списке клиентов оказывается роутер, к которому
  этот список и относится;
* **шлюз провайдера.** Модем или маршрутизатор на стороне оператора виден
  в ARP на WAN-интерфейсе, но клиентом площадки не является. Отличаем его
  по адресу шлюза в маршруте по умолчанию, а не по имени интерфейса: имя
  бывает любым, а маршрут говорит правду;
* **чужая сеть за аплинком.** Точка доступа, включённая в общую сеть, учит
  каждый MAC, чей кадр прошёл через её аплинк, и вдобавок заводит записи
  ARP на соседей по этой же сети: на такой железке в списке оказывался
  весь широковещательный домен, полторы сотни чужих устройств.

  Аплинк вычисляется по шлюзу: адрес из маршрута по умолчанию -> MAC
  из ARP -> порт, на котором этот MAC выучен мостом. И если аплинк
  найден, клиентом площадки считается только тот, кто это доказал:
  получил адрес у самого роутера, подключился по воздуху или выучен
  мостом на порту, отличном от аплинка. Всё остальное пришло снаружи.

Разбор отделён от чтения: `merge()` принимает готовые списки и ничего не
знает ни про сеть, ни про базу, поэтому проверяется тестами на выдуманных
ответах роутера, без единого устройства.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

#: Вид подключения. Третьего не дано: клиент либо по кабелю, либо по воздуху.
WIRED = "wired"
WIRELESS = "wireless"


def normalize_mac(value: Any) -> str:
    """
    MAC к единому виду `aa:bb:cc:dd:ee:ff`.

    RouterOS отдаёт их заглавными и с двоеточиями, но в разных таблицах
    попадаются варианты с дефисами. Приводим всё к одному, иначе один
    и тот же клиент разойдётся на несколько строк.
    """
    text = re.sub(r"[^0-9a-fA-F]", "", str(value or "")).lower()
    if len(text) != 12:
        return ""
    return ":".join(text[i:i + 2] for i in range(0, 12, 2))


def vendor_of(mac: str) -> str:
    """
    Производитель по MAC.

    Сам поиск живёт в `vendors`: там и встроенный короткий список,
    и скачанные реестры IEEE с блоками разной длины.
    """
    from . import vendors

    normalized = normalize_mac(mac)
    if not normalized:
        return ""

    # Локально назначенный адрес: второй бит первого байта. Такие MAC
    # придумывает сам телефон ради приватности, и искать вендора
    # бессмысленно - его там нет.
    try:
        first = int(normalized[:2], 16)
    except ValueError:
        return ""
    if first & 0b10:
        return "случайный MAC"

    return vendors.lookup(normalized)


def is_yes(value: Any) -> bool:
    """
    Флаг RouterOS в bool.

    librouteros приводит `true`/`false` к настоящим True и False ещё при
    разборе ответа, поэтому сравнение со строкой было бы всегда ложным.
    """
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "yes", "1")


def host_port(host: dict[str, Any]) -> str:
    """
    Порт из записи таблицы моста.

    В RouterOS 7 поле называется `on-interface`, в шестёрке называлось
    `interface`. Читаем оба: панель работает с обеими версиями, и брать
    что-то одно означало бы на половине парка показывать пустоту.
    """
    for key in ("on-interface", "interface"):
        value = str(host.get(key) or "").strip()
        if value:
            return value
    return ""


def default_gateways(routes: Iterable[dict[str, Any]]) -> set[str]:
    """
    Адреса шлюзов из маршрутов по умолчанию.

    По ним отсеивается оборудование провайдера: оно видно в ARP, но
    клиентом площадки не является и в списке только мешает.
    """
    found = set()
    for route in routes:
        if str(route.get("dst-address") or "") not in ("0.0.0.0/0", "::/0"):
            continue
        if is_yes(route.get("disabled")):
            continue
        for gateway in str(route.get("gateway") or "").split(","):
            gateway = gateway.strip()
            # Шлюзом бывает и имя интерфейса: такие пропускаем, отсев
            # идёт по адресам
            if gateway and gateway[0].isdigit():
                found.add(gateway)
    return found


def uplink_ports(arp: Iterable[dict[str, Any]] = (),
                 hosts: Iterable[dict[str, Any]] = (),
                 routes: Iterable[dict[str, Any]] = ()) -> set[str]:
    """
    Порты моста, за которыми находится вышестоящая сеть.

    Ход рассуждения тот же, каким пользуется человек: шлюз по умолчанию
    стоит не на площадке, значит порт, на котором мост выучил его MAC,
    смотрит наружу. Всё, что мост услышал с этого порта, пришло из чужой
    сети, а не с площадки.

    Пусто, если шлюза нет или его MAC мосту неизвестен: тогда отсеивать
    нечего и лучше показать лишнее, чем спрятать нужное.
    """
    gateways = default_gateways(routes)
    if not gateways:
        return set()

    upstream_macs = {
        normalize_mac(entry.get("mac-address"))
        for entry in arp
        if str(entry.get("address") or "").strip() in gateways
    }
    upstream_macs.discard("")
    if not upstream_macs:
        return set()

    ports = set()
    for host in hosts:
        if normalize_mac(host.get("mac-address")) in upstream_macs:
            port = host_port(host)
            if port:
                ports.add(port)
    return ports


def merge(leases: Iterable[dict[str, Any]] = (), arp: Iterable[dict[str, Any]] = (),
          hosts: Iterable[dict[str, Any]] = (), wireless: Iterable[dict[str, Any]] = (),
          routes: Iterable[dict[str, Any]] = ()) -> list[dict[str, Any]]:
    """
    Слить таблицы роутера в список клиентов.

    Правила простые и намеренно предсказуемые:

    * ключ — MAC, записи без разбираемого MAC отбрасываются;
    * имя берётся из аренды DHCP, другого источника имени нет;
    * комментарий из аренды, а если его там нет — из ARP;
    * адрес из аренды, а если её нет — из ARP;
    * порт из таблицы моста или из таблицы регистрации, если клиент
      подключён по воздуху. Интерфейс из ARP портом не считается: там
      будет имя моста, а «bridge» это не ответ на вопрос «куда воткнут»;
    * вид подключения беспроводной, если MAC нашёлся в таблице
      регистрации, и проводной во всех остальных случаях.
    """
    # Списки читаются дважды: сначала для поиска аплинка, потом по делу.
    # Генератор второго прохода не переживёт
    arp = list(arp)
    hosts = list(hosts)
    routes = list(routes)
    uplink = uplink_ports(arp, hosts, routes)

    found: dict[str, dict[str, Any]] = {}

    def slot(mac: str) -> dict[str, Any]:
        return found.setdefault(mac, {
            "mac": mac, "hostname": "", "comment": "", "ip": "", "port": "",
            "interface": "", "vlan": "", "source": "", "dynamic": True,
            "link": WIRED, "ssid": "", "signal": "",
        })

    for lease in leases:
        mac = normalize_mac(lease.get("mac-address"))
        if not mac:
            continue
        row = slot(mac)
        row["hostname"] = str(lease.get("host-name") or "").strip()
        # Комментарий с аренды: его пишет администратор руками, поэтому
        # он точнее имени, которое устройство сообщает о себе само
        row["comment"] = str(lease.get("comment") or "").strip()
        row["ip"] = str(lease.get("address") or "").strip()
        row["interface"] = str(lease.get("server") or "").strip()
        # Статическая аренда означает, что адрес закреплён за клиентом
        # намеренно: это касса или камера, а не чей-то телефон
        row["dynamic"] = is_yes(lease.get("dynamic", "true"))
        row["source"] = "dhcp"

    upstream = default_gateways(routes)
    for entry in arp:
        mac = normalize_mac(entry.get("mac-address"))
        address = str(entry.get("address") or "").strip()
        if not mac:
            continue
        # Оборудование провайдера пропускаем, но только если больше о нём
        # ничего не известно: свой роутер с таким же адресом в аренде
        # остался бы в списке справедливо
        if address in upstream and mac not in found:
            continue
        row = slot(mac)
        if not row["ip"]:
            row["ip"] = address
        if not row["interface"]:
            row["interface"] = str(entry.get("interface") or "").strip()
        if not row["comment"]:
            row["comment"] = str(entry.get("comment") or "").strip()
        row["source"] = row["source"] or "arp"

    for host in hosts:
        mac = normalize_mac(host.get("mac-address"))
        if not mac:
            continue
        # Собственные интерфейсы роутера в списке клиентов не нужны:
        # это тот самый роутер, к которому список и относится
        if is_yes(host.get("local")):
            found.pop(mac, None)
            continue
        row = slot(mac)
        port = host_port(host)
        if port:
            row["port"] = port
            if port in uplink:
                row["upstream"] = True
        if host.get("vid"):
            row["vlan"] = str(host.get("vid"))
        row["source"] = row["source"] or "bridge"

    for entry in wireless:
        mac = normalize_mac(entry.get("mac-address"))
        if not mac:
            continue
        row = slot(mac)
        row["link"] = WIRELESS
        # Порт беспроводного клиента это интерфейс, через который он
        # подключён: в таблице моста у него будет то же самое
        port = str(entry.get("interface") or "").strip()
        if port:
            row["port"] = port
        row["ssid"] = str(entry.get("ssid") or "").strip()
        row["signal"] = str(
            entry.get("signal-strength") or entry.get("signal") or ""
        ).strip()
        row["source"] = row["source"] or "wireless"

    for row in found.values():
        row["vendor"] = vendor_of(row["mac"])
        # Интерфейс из ARP портом не считается: «bridge» и «lte1» на вопрос
        # «куда воткнут кабель» не отвечают
        if not row["port"] and row["link"] == WIRELESS:
            row["port"] = row["interface"]

    result = []
    for row in found.values():
        row.pop("upstream", None)
        if uplink and not _is_local(row, uplink):
            continue
        result.append(row)

    return sorted(result, key=lambda r: r["mac"])


def _is_local(row: dict[str, Any], uplink: set[str]) -> bool:
    """
    Клиент ли это площадки, когда известно, где у роутера аплинк.

    Доказательств ровно три: адрес выдал сам роутер, клиент подключён
    по воздуху, или мост выучил его на порту, который наружу не смотрит.
    Записи ARP доказательством не считаются: точка доступа заводит их
    на соседей по чужой сети точно так же, как на своих.
    """
    if row.get("source") == "dhcp":
        return True
    if row.get("link") == WIRELESS:
        return True
    port = str(row.get("port") or "")
    return bool(port) and port not in uplink


def collect(mt: Any) -> list[dict[str, Any]]:
    """
    Прочитать клиентов с устройства в уже открытой сессии.

    Каждая таблица читается отдельно и независимо: на роутере без моста
    нет `/interface/bridge/host`, на роутере без DHCP нет аренд, а из двух
    беспроводных пакетов RouterOS обычно установлен ровно один. Отсутствие
    любой таблицы не повод остаться вообще без данных.
    """
    def safe(command: str) -> list[dict[str, Any]]:
        try:
            return list(mt.cmd(command))
        except Exception:  # noqa: BLE001 — нет такой таблицы, значит нет
            return []

    # Старый пакет wireless и новый wifi: имена команд разные, наличие
    # зависит от версии и модели, поэтому спрашиваем оба
    air = safe("/interface/wireless/registration-table/print")
    air += safe("/interface/wifi/registration-table/print")

    return merge(
        leases=safe("/ip/dhcp-server/lease/print"),
        arp=safe("/ip/arp/print"),
        hosts=safe("/interface/bridge/host/print"),
        wireless=air,
        routes=safe("/ip/route/print"),
    )


# ------------------------------------------------------------------ хранение
def save(device_id: int, rows: Iterable[dict[str, Any]]) -> int:
    """
    Записать собранных клиентов. Возвращает их число.

    Записи не удаляются, а обновляются: пропавший клиент остаётся в базе
    со старым `last_seen`, и это главное, ради чего всё затевалось. Вопрос
    «когда эту камеру видели последний раз» без истории не имеет ответа.

    Своя подпись (`label`) не трогается: её задаёт человек, а мы приносим
    только то, что сказал роутер.
    """
    from .database import execute, utcnow

    now = utcnow()
    saved = 0
    for row in rows:
        if not row.get("mac"):
            continue
        execute(
            "INSERT INTO clients (device_id, mac, hostname, comment, ip, port,"
            " interface, vlan, vendor, dynamic, source, link, ssid, signal,"
            " first_seen, last_seen)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            " ON CONFLICT(device_id, mac) DO UPDATE SET"
            "   hostname = excluded.hostname,"
            "   comment = excluded.comment,"
            "   ip = excluded.ip,"
            "   port = excluded.port,"
            "   interface = excluded.interface,"
            "   vlan = excluded.vlan,"
            "   vendor = excluded.vendor,"
            "   dynamic = excluded.dynamic,"
            "   source = excluded.source,"
            "   link = excluded.link,"
            "   ssid = excluded.ssid,"
            "   signal = excluded.signal,"
            "   last_seen = excluded.last_seen",
            (
                device_id, row["mac"], row.get("hostname", ""),
                row.get("comment", ""), row.get("ip", ""),
                row.get("port", ""), row.get("interface", ""), row.get("vlan", ""),
                row.get("vendor", ""), 1 if row.get("dynamic", True) else 0,
                row.get("source", ""), row.get("link", WIRED),
                row.get("ssid", ""), row.get("signal", ""), now, now,
            ),
        )
        saved += 1
    return saved


def prune(days: int) -> int:
    """
    Забыть клиентов, которых давно не видели.

    Своими подписями помеченные не трогаем: раз человек дал строке имя,
    значит она ему зачем-то нужна, и стирать её молча неправильно.
    """
    from .database import execute_changes

    if days <= 0:
        return 0
    return execute_changes(
        "DELETE FROM clients WHERE label = '' AND last_seen < datetime('now', ?)",
        (f"-{days} days",),
    )
