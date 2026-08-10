"""
Site-to-site WireGuard: расчёты, ключи и сборка конфигураций.

Схема «звезда»: один роутер это **хаб**, к нему подключаются **споуки**.
На хабе для каждого споука заводится пир и маршруты к его подсетям, споук
получает готовый скрипт со своей стороной связи.

Здесь только чистые вычисления: криптография, разбор подсетей и сборка
текста конфигураций. Всё, что ходит на роутер, лежит в `app/routes/wireguard.py`,
поэтому эту часть можно проверить тестами без единого устройства.

Почему `allowed-address` мало и нужны маршруты
----------------------------------------------

В RouterOS `allowed-address` у пира работает как cryptokey routing: он решает,
какому пиру шифровать пакет, но **в таблицу маршрутизации ничего не добавляет**.
Пакет должен сначала попасть в WireGuard-интерфейс по обычному маршруту.
Поэтому на хабе к подсетям каждого споука создаётся `/ip route` через
интерфейс туннеля, а в скрипте споука делается зеркальное отражение
к подсетям хаба. Забыть об этом — классическая причина «туннель поднялся,
а сети не видят друг друга».
"""

from __future__ import annotations

import base64
import ipaddress
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

#: Метка, которой помечаются все созданные объекты: пиры, маршруты, правила.
#: Совпадает с меткой отдельной панели, из которой выросла эта возможность,
#: поэтому уже настроенные линки подхватываются как свои.
TAG = "wgpanel:"


# ------------------------------------------------------------------- ключи
def generate_keypair() -> tuple[str, str]:
    """
    Пара ключей WireGuard: (приватный, публичный) в base64.

    WireGuard использует X25519. Библиотека уже стоит ради шифрования паролей
    устройств, поэтому никаких новых зависимостей и, что важнее, никакой
    загрузки крипто-библиотеки из интернета в браузере пользователя.
    """
    private = X25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return (
        base64.b64encode(private_bytes).decode(),
        base64.b64encode(public_bytes).decode(),
    )


def generate_psk() -> str:
    """Предварительный общий ключ: 32 случайных байта в base64."""
    return base64.b64encode(secrets.token_bytes(32)).decode()


# ------------------------------------------------------------------ подсети
def parse_cidr(value: str) -> tuple[str, int] | None:
    """«10.20.0.1/24» → («10.20.0.1», 24). Без маски считаем /32."""
    text = str(value or "").strip()
    if not text:
        return None
    address, _, prefix = text.partition("/")
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return None
    try:
        return address, int(prefix) if prefix else 32
    except ValueError:
        return None


def network_of(value: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Сеть, которой принадлежит адрес с маской."""
    try:
        return ipaddress.ip_network(str(value or "").strip(), strict=False)
    except ValueError:
        return None


def overlaps(first: str, second: str) -> bool:
    """Пересекаются ли две подсети."""
    left, right = network_of(first), network_of(second)
    if left is None or right is None:
        return False
    return left.overlaps(right)


#: Единицы длительности RouterOS: «1w2d3h4m5s».
_DURATION_UNITS = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
_DURATION_PART = re.compile(r"(\d+)\s*([wdhms])", re.I)


def duration_seconds(value: Any) -> int | None:
    """
    Длительность RouterOS в секунды. None, если её нет вовсе.

    Нужна для сортировки по рукопожатию: как текст «45s» больше «1m30s»,
    и колонка, отсортированная по возрасту связи, показывает ерунду.
    """
    text = str(value or "").strip()
    if not text:
        return None
    total = 0
    found = False
    for amount, unit in _DURATION_PART.findall(text):
        total += int(amount) * _DURATION_UNITS[unit.lower()]
        found = True
    return total if found else None


def address_sort_key(value: str) -> int:
    """
    Адрес в число для сортировки. Строкой «10.8.0.9» идёт после «10.8.0.10».
    """
    parsed = parse_cidr(value)
    if not parsed:
        return -1
    try:
        return int(ipaddress.ip_address(parsed[0]))
    except ValueError:
        return -1


def is_on(value: Any) -> bool:
    """
    Флаг RouterOS в обычный bool.

    Сравнивать со строкой «true» напрямую нельзя: librouteros приводит
    yes/no и true/false к настоящим True и False ещё при разборе ответа,
    и проверка `value == "true"` тихо становится всегда ложной. Ошибка из
    разряда незаметных: выключенный адрес просто попадает в списки как
    рабочий.
    """
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("true", "yes", "1")


def split_list(value: str) -> list[str]:
    """Строка «10.0.0.0/24, 10.0.1.0/24» → список без пустых элементов."""
    return [
        part.strip()
        for part in str(value or "").replace(";", ",").split(",")
        if part.strip()
    ]


def next_free_tunnel_ip(tunnel_address: str, taken: Iterable[str]) -> str | None:
    """
    Первый свободный адрес в туннельной подсети хаба.

    `tunnel_address` — адрес самого хаба с маской, например «10.20.0.1/24».
    `taken` — уже занятые адреса (из allowed-address существующих пиров).

    Возвращает None, если подсеть кончилась или задана как /32: из одного
    адреса раздавать нечего, и об этом лучше сказать прямо.
    """
    parsed = parse_cidr(tunnel_address)
    if not parsed:
        return None
    hub_ip, prefix = parsed
    if prefix >= 31:
        return None

    network = network_of(f"{hub_ip}/{prefix}")
    if network is None:
        return None

    # allowed-address приходит одной строкой вида
    # «10.8.0.5/32,192.168.55.0/24», поэтому каждый элемент сначала
    # разбирается на части. Без этого разбор всей строки целиком просто
    # не удавался, занятые адреса не находились и панель предлагала
    # второй адрес подсети, уже давно выданный.
    busy = {hub_ip}
    for item in taken:
        for part in split_list(item):
            found = parse_cidr(part)
            if not found:
                continue
            address, size = found
            # Интересуют только адреса внутри туннеля: LAN дальней стороны
            # к раздаче туннельных адресов отношения не имеет
            if size == 32 and network.overlaps(network_of(f"{address}/32")):
                busy.add(address)

    for host in network.hosts():
        if str(host) not in busy:
            return str(host)
    return None


# ------------------------------------------------------------------- линки
@dataclass
class Link:
    """Один споук: то, что нужно знать и хабу, и для сборки его конфигурации."""

    name: str
    tunnel_ip: str                       # адрес споука в туннеле, без маски
    remote_subnets: list[str] = field(default_factory=list)   # LAN споука
    keepalive: int = 25
    psk: str | None = None
    private_key: str | None = None       # только сразу после создания
    public_key: str = ""


@dataclass
class Hub:
    """Настройки стороны хаба, общие для всех линков."""

    interface: str
    public_key: str
    listen_port: int = 13231
    tunnel_address: str = ""             # с маской: 10.20.0.1/24
    public_host: str = ""                # внешний адрес, который увидят споуки
    lan_subnets: list[str] = field(default_factory=list)

    @property
    def tunnel_prefix(self) -> int:
        parsed = parse_cidr(self.tunnel_address)
        return parsed[1] if parsed else 24

    @property
    def tunnel_network(self) -> str:
        network = network_of(self.tunnel_address)
        return str(network) if network else ""

    @property
    def tunnel_ip(self) -> str:
        """Адрес хаба в туннеле без маски: он же шлюз для маршрутов споука."""
        parsed = parse_cidr(self.tunnel_address)
        return parsed[0] if parsed else ""


def allowed_for_spoke(hub: Hub) -> list[str]:
    """
    Что споук должен пускать в туннель: сеть туннеля и LAN-подсети хаба.

    Пустой список означал бы, что споук не знает, ради чего туннель, поэтому
    вызывающая сторона в таком случае подставляет 0.0.0.0/0.
    """
    allowed = []
    if hub.tunnel_network:
        allowed.append(hub.tunnel_network)
    allowed += [s for s in hub.lan_subnets if s not in allowed]
    return allowed


def peer_allowed_address(link: Link) -> str:
    """`allowed-address` пира на хабе: туннельный адрес споука и его LAN."""
    return ",".join([f"{link.tunnel_ip}/32", *link.remote_subnets])


def build_spoke_script(hub: Hub, link: Link, interface: str = "wg-hub") -> str:
    """
    Готовый `.rsc` для роутера-споука.

    Скрипт делает всё, что нужно дальней стороне: интерфейс, адрес в туннеле,
    пир на хаб, маршруты к подсетям хаба и правила firewall. Импортируется
    целиком, править ничего не требуется.

    Если приватного ключа нет (перевыпуск скрипта для существующего линка),
    в текст попадает явное предупреждение вместо тихой подстановки пустого
    значения: человек должен понять, почему скрипт не заработает как есть.
    """
    endpoint = hub.public_host.strip()
    allowed = ",".join(allowed_for_spoke(hub)) or "0.0.0.0/0"
    private = link.private_key or "ВСТАВЬТЕ_ПРИВАТНЫЙ_КЛЮЧ_СПОУКА"

    lines = [
        f"# WireGuard: связь с хабом, линк «{link.name}»",
        "# Выполнить на РОУТЕРЕ-СПОУКЕ (RouterOS v7).",
        "",
        "/interface/wireguard",
        f'add name={interface} private-key="{private}"',
        "",
        "/ip/address",
        f"add address={link.tunnel_ip}/{hub.tunnel_prefix} interface={interface}",
        "",
        "/interface/wireguard/peers",
    ]

    peer = (
        f'add interface={interface} public-key="{hub.public_key}"'
        f" endpoint-address={endpoint} endpoint-port={hub.listen_port}"
        f" allowed-address={allowed}"
        f" persistent-keepalive={link.keepalive}"
    )
    if link.psk:
        peer += f' preshared-key="{link.psk}"'
    peer += ' comment="hub"'
    lines.append(peer)
    lines.append("")

    if hub.lan_subnets:
        # Шлюзом ставится адрес хаба в туннеле, а не имя интерфейса.
        # Через интерфейс RouterOS приходится самому догадываться, какому
        # пиру отдать пакет, и на интерфейсе с несколькими пирами это
        # работает непредсказуемо. Адрес шлюза убирает всякую догадку.
        gateway = hub.tunnel_ip or interface
        lines.append("/ip/route")
        for subnet in hub.lan_subnets:
            lines.append(f'add dst-address={subnet} gateway={gateway} comment="{TAG}hub"')
        lines.append("")

    lines += [
        "/ip/firewall/filter",
        f'add chain=forward action=accept in-interface={interface}'
        f' comment="{TAG}link" place-before=0',
        f'add chain=forward action=accept out-interface={interface}'
        f' comment="{TAG}link" place-before=0',
    ]

    if not link.private_key:
        lines += [
            "",
            "# ВНИМАНИЕ: приватный ключ споука на хабе не хранится намеренно.",
            "# Это шаблон: подставьте настоящий ключ или пересоздайте линк.",
        ]

    return "\n".join(lines) + "\n"


def qr_svg(text: str, border: int = 2) -> str:
    """
    QR-код конфигурации в виде готового SVG.

    Собирается на сервере и вставляется в страницу как есть. Отдельной
    картинки нет намеренно: в конфигурации лежит приватный ключ споука,
    и превращать его в адрес, который останется в журнале веб-сервера
    и в истории браузера, не стоит.

    Рисуем по матрице сами, а не сохранялкой библиотеки: так в страницу
    попадает чистый SVG без XML-заголовка. Цвета жёстко чёрный на белом
    и в тёмной теме тоже: телефон читает код камерой, а не глазами, и
    поля вокруг ему нужны настоящие белые, иначе он его просто не найдёт.

    Если библиотека не установлена, возвращается пустая строка: раздел
    обязан работать и без QR, это удобство, а не часть настройки.
    """
    if not text:
        return ""
    try:
        import segno
    except ImportError:
        return ""

    try:
        matrix = segno.make(text, error="m").matrix
    except Exception:  # noqa: BLE001 — QR это удобство, падать из-за него нельзя
        return ""

    size = len(matrix)
    parts = []
    for y, row in enumerate(matrix):
        x = 0
        while x < size:
            if not row[x]:
                x += 1
                continue
            run = x
            while run < size and row[run]:
                run += 1
            parts.append(f"M{x + border} {y + border}h{run - x}v1h-{run - x}z")
            x = run

    full = size + border * 2
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {full} {full}" '
        f'role="img" aria-label="QR" shape-rendering="crispEdges">'
        f'<rect width="{full}" height="{full}" fill="#ffffff"/>'
        f'<path fill="#000000" d="{"".join(parts)}"/></svg>'
    )


def build_wg_quick_config(hub: Hub, link: Link, dns: str = "") -> str:
    """
    Тот же линк в формате обычного клиента WireGuard.

    Нужен, когда дальняя сторона не MikroTik: ноутбук, телефон, сервер.
    Формат тот же, что понимает `wg-quick` и мобильные приложения.
    """
    allowed = ", ".join(allowed_for_spoke(hub)) or "0.0.0.0/0"
    lines = [
        "[Interface]",
        f"PrivateKey = {link.private_key or 'ВСТАВЬТЕ_ПРИВАТНЫЙ_КЛЮЧ'}",
        f"Address = {link.tunnel_ip}/{hub.tunnel_prefix}",
    ]
    if dns:
        lines.append(f"DNS = {dns}")
    lines += [
        "",
        "[Peer]",
        f"PublicKey = {hub.public_key}",
    ]
    if link.psk:
        lines.append(f"PresharedKey = {link.psk}")
    lines += [
        f"AllowedIPs = {allowed}",
        f"Endpoint = {hub.public_host}:{hub.listen_port}",
        f"PersistentKeepalive = {link.keepalive}",
    ]
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------- проверки
def validate_link(hub: Hub, link: Link, hub_networks: Iterable[str],
                  existing_names: Iterable[str]) -> list[str]:
    """
    Проверить будущий линк и вернуть список проблем понятным текстом.

    Отдельная функция, потому что почти все ошибки в site-to-site это ошибки
    ввода, а не связи: подсеть без маски, повтор имени, туннель /32, чужая
    сеть в списке удалённых. Ловить их до записи на роутер дешевле, чем
    разбираться потом, почему сети не видят друг друга.
    """
    problems = []

    if not link.name:
        problems.append("Не указано имя линка")
    if link.name in set(existing_names):
        problems.append(f"Линк с именем «{link.name}» уже есть")

    if not parse_cidr(f"{link.tunnel_ip}/32"):
        problems.append("Туннельный адрес споука указан неверно")

    if not hub.public_key:
        problems.append("У интерфейса хаба нет публичного ключа")
    if not hub.public_host.strip():
        problems.append(
            "Не задан публичный адрес хаба: споуку некуда подключаться"
        )

    parsed = parse_cidr(hub.tunnel_address)
    if not parsed:
        problems.append("Не задан туннельный адрес хаба")
    elif parsed[1] >= 31:
        problems.append(
            "Туннельный адрес хаба задан как /32: из одного адреса нельзя "
            "выдать адрес споуку. Укажите подсеть, например 10.20.0.1/24"
        )

    for subnet in link.remote_subnets:
        if "/" not in subnet:
            problems.append(f"Подсеть {subnet} без маски: укажите, например {subnet}/24")
            continue
        if network_of(subnet) is None:
            problems.append(f"Подсеть {subnet} разобрать не удалось")
            continue
        # Частая ошибка: сюда вписывают сети самого хаба. Тогда хаб начинает
        # маршрутизировать собственную сеть в туннель и теряет её.
        for own in hub_networks:
            if overlaps(own, subnet):
                problems.append(
                    f"Подсеть {subnet} это сеть самого хаба. Здесь указывают "
                    f"сети ДАЛЬНЕЙ стороны"
                )
                break

    return problems
