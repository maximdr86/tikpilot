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


def real_client_ip(peer: str, forwarded: str, trusted_proxies: Iterable) -> str:
    """
    Определить адрес клиента.

    `peer` — тот, кто реально установил соединение. Если это доверенный
    прокси, берём последний адрес из `X-Forwarded-For`: он ближе всего
    к нам и подделать его сложнее всего. Иначе заголовок игнорируем.
    """
    if not forwarded or not _in_networks(peer, trusted_proxies):
        return peer

    chain = [part.strip() for part in forwarded.split(",") if part.strip()]
    return chain[-1] if chain else peer


def allowed(peer: str, forwarded: str, networks: Iterable, trusted_proxies: Iterable) -> bool:
    """Разрешён ли доступ к панели с этого адреса."""
    if not networks:
        return True
    return _in_networks(real_client_ip(peer, forwarded, trusted_proxies), networks)


def _in_networks(address: str, networks: Iterable) -> bool:
    """Входит ли адрес хотя бы в одну из сетей."""
    if not address:
        return False
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        # Не адрес вовсе. При включённой проверке это отказ: пропускать
        # непонятное значение опаснее, чем отклонить.
        return False
    return any(ip in network for network in networks)
