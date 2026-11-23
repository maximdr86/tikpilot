"""
Ограничение доступа к панели по сетям.

Задача одна: публичный лист состояния должен открываться откуда угодно,
а сама панель — только из доверенных сетей. Иначе, пробросив порт наружу
ради ссылки для подрядчиков, вы заодно выставляете туда форму входа
в систему управления парком.

Настраивается переменной `ADMIN_NETWORKS` в `.env`:

    ADMIN_NETWORKS=10.0.0.0/8,192.168.0.0/16

Пустое значение означает «не ограничивать» — так работает установка
по умолчанию, и обновление программы ни у кого ничего не отнимает.

Про заголовок X-Forwarded-For
-----------------------------

За обратным прокси настоящий адрес клиента приходит в заголовке, и его
может подделать кто угодно. Поэтому заголовку доверяем, только если сам
запрос пришёл от прокси, перечисленного в `TRUSTED_PROXIES`. Без этой
оговорки проверка не стоила бы ничего: достаточно было бы отправить
`X-Forwarded-For: 10.0.0.1` и попасть внутрь.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Iterable

log = logging.getLogger("tikpilot.access")

#: Что открыто всем, независимо от настройки. Публичный лист состояния и
#: файлы оформления к нему: без стилей страница выглядит сломанной.
#:
#: `/healthz` здесь потому, что спрашивающий обычно не человек: установщик
#: сразу после запуска, systemd, монитор контейнера, внешняя проверка.
#: Все они приходят с адреса, которого нет в списке доверенных сетей,
#: и получали бы 403 от живой и здоровой панели. Ответ пустой настолько,
#: насколько это возможно: слово «ok» и ничего о том, что внутри.
PUBLIC_PREFIXES = ("/status/", "/static/", "/favicon.ico", "/healthz")


def parse_networks(raw: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """
    Разобрать список сетей из настройки.

    Понимает и сети, и одиночные адреса: `10.0.0.0/8` и `10.0.0.5` одинаково
    допустимы. Неразборчивое значение пропускается с записью в журнал:
    опечатка в одной сети не должна отключать проверку целиком.
    """
    networks = []
    for item in str(raw or "").replace(";", ",").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            log.error("Непонятная запись в списке сетей: %r", item)
    return networks


def is_public_path(path: str) -> bool:
    """Открыт ли адрес всем без ограничений."""
    return path.startswith(PUBLIC_PREFIXES)


def _canonical_ip(value: str) -> str:
    """Normalize literal IP addresses, including IPv4-mapped IPv6."""
    if "%" in value:
        return ""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return str(address.ipv4_mapped)
    return str(address)


def real_client_ip(peer: str, forwarded: str | list[str], trusted_proxies: Iterable) -> str:
    """Resolve the first untrusted hop; an invalid forwarded chain has no identity."""
    trusted_proxies = tuple(trusted_proxies)
    peer = _canonical_ip(peer) or peer
    if not _in_networks(peer, trusted_proxies):
        return peer
    # A missing header also permits direct local access. A trusted proxy must
    # always supply it; the application cannot distinguish the two cases.
    if forwarded == "" or forwarded == []:
        return peer
    headers = [forwarded] if isinstance(forwarded, str) else forwarded
    chain = [_canonical_ip(part.strip()) for header in headers for part in header.split(",")]
    if not chain or any(not address for address in chain):
        return ""
    for address in reversed(chain):
        if not _in_networks(address, trusted_proxies):
            return address
    return ""


def request_client_ip(request, trusted_proxies: Iterable) -> str:
    """Use the transport peer and all X-Forwarded-For header fields."""
    peer = request.client.host if request.client else ""
    return real_client_ip(peer, request.headers.getlist("x-forwarded-for"), trusted_proxies)


def allowed(peer: str, forwarded: str | list[str], networks: Iterable, trusted_proxies: Iterable) -> bool:
    """Разрешён ли доступ к панели с этого адреса."""
    if not networks:
        return True
    return _in_networks(real_client_ip(peer, forwarded, trusted_proxies), networks)


class TrustedProxyScheme:
    """Apply only a trusted proxy's protocol, without changing the ASGI peer."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            from starlette.requests import HTTPConnection
            from .config import settings

            connection = HTTPConnection(scope)
            peer = connection.client.host if connection.client else ""
            forwarded = connection.headers.getlist("x-forwarded-for")
            proto = connection.headers.getlist("x-forwarded-proto")
            if (_in_networks(peer, settings.trusted_proxies) and forwarded
                    and real_client_ip(peer, forwarded, settings.trusted_proxies)
                    and len(proto) == 1 and proto[0].strip().lower() in ("http", "https")):
                scheme = proto[0].strip().lower()
                scope = dict(scope)
                scope["scheme"] = ({"http": "ws", "https": "wss"}[scheme]
                                   if scope["type"] == "websocket" else scheme)
        await self.app(scope, receive, send)


def _in_networks(address: str, networks: Iterable) -> bool:
    """Входит ли адрес хотя бы в одну из сетей."""
    if not address:
        return False
    try:
        ip = ipaddress.ip_address(_canonical_ip(address))
    except ValueError:
        # Не адрес вовсе. При включённой проверке это отказ: пропускать
        # непонятное значение опаснее, чем отклонить.
        return False
    return any(ip in network for network in networks)
