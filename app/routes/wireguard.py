"""
Раздел WireGuard: связи «роутер-роутер» через хаб.

Работа идёт по обычному RouterOS API в уже открытой сессии устройства.
Отдельного пользователя, включённого `www-ssl`, сертификата и прокси
не требуется: всё это нужно было только браузеру, который ходил на роутер
напрямую.

Каждый созданный объект помечается комментарием `wgpanel:<имя линка>`.
Удаление линка трогает только помеченное, остальная конфигурация роутера
остаётся как была.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .. import permissions, wireguard as wg
from ..auth import Forbidden, client_ip, require
from ..database import execute, log_audit, query, query_one, utcnow
from .deps import render

router = APIRouter()


# --------------------------------------------------------------- хранилище
def _hub_settings(device_id: int) -> dict[str, Any]:
    """Настройки хаба из базы. Их нет в роутере: это наши договорённости."""
    row = query_one("SELECT * FROM wg_hubs WHERE device_id = ?", (device_id,))
    if row is None:
        return {"device_id": device_id, "interface": "", "public_host": "",
                "lan_subnets": "", "listen_port": 13231}
    return dict(row)


def _save_hub(device_id: int, **fields: Any) -> None:
    """Записать настройки хаба, создав запись при необходимости."""
    if query_one("SELECT device_id FROM wg_hubs WHERE device_id = ?", (device_id,)) is None:
        execute("INSERT INTO wg_hubs (device_id, updated_at) VALUES (?,?)",
                (device_id, utcnow()))
    for name, value in fields.items():
        execute(f"UPDATE wg_hubs SET {name} = ? WHERE device_id = ?", (value, device_id))
    execute("UPDATE wg_hubs SET updated_at = ? WHERE device_id = ?", (utcnow(), device_id))


# ------------------------------------------------------------- связь с хабом
def _device(device_id: int, user: dict[str, Any]) -> dict[str, Any]:
    """Устройство хаба с проверкой области видимости."""
    if not permissions.can_touch(user, [device_id]):
        raise Forbidden()
    row = query_one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if row is None:
        raise Forbidden("Устройство не найдено")
    return dict(row)


def _read_state(device: dict[str, Any]) -> dict[str, Any]:
    """
    Прочитать с хаба всё, что нужно разделу за один заход.

    Один вызов вместо четырёх запросов с браузера: страница открывается
    одним обращением к роутеру, а не пятью подряд.
    """
    from ..sessions import pool

    with pool.borrow(device) as mt:
        return {
            "interfaces": mt.cmd("/interface/wireguard/print"),
            "peers": mt.cmd("/interface/wireguard/peers/print"),
            "addresses": mt.cmd("/ip/address/print"),
            "routes": mt.cmd("/ip/route/print"),
            "firewall": mt.cmd("/ip/firewall/filter/print"),
        }


def _pick_interface(state: dict[str, Any], settings: dict[str, Any]) -> str:
    """
    Интерфейс хаба: сохранённый, а если его нет — первый найденный на роутере.

    Без этого раздел при первом открытии выглядел бы пустым: пока интерфейс
    не выбран и не сохранён, панели не с чего читать ни туннельный адрес,
    ни пиры, хотя на роутере всё это уже есть. Догадаться, что нужно сначала
    нажать «Сохранить», человеку неоткуда.
    """
    names = [str(i.get("name") or "") for i in state["interfaces"] if i.get("name")]
    saved = str(settings.get("interface") or "").strip()
    if saved in names:
        return saved
    return names[0] if names else saved


def _peers_of(state: dict[str, Any], interface: str) -> list[dict[str, Any]]:
    """Пиры выбранного интерфейса. Чужие туннели того же роутера не наше дело."""
    return [p for p in state["peers"]
            if not interface or p.get("interface") == interface]


def _tunnel_address(state: dict[str, Any], interface: str) -> str:
    """Адрес хаба в туннеле. Живёт на роутере, поэтому читаем, а не храним."""
    for address in state["addresses"]:
        if address.get("interface") == interface and not wg.is_on(address.get("disabled")):
            return str(address.get("address") or "")
    return ""


def _hub_from(state: dict[str, Any], settings: dict[str, Any], device: dict[str, Any]) -> wg.Hub:
    """Собрать описание хаба из ответа роутера и наших настроек."""
    interface = _pick_interface(state, settings)
    found = next((i for i in state["interfaces"] if i.get("name") == interface), {})
    tunnel = _tunnel_address(state, interface)

    return wg.Hub(
        interface=interface,
        public_key=found.get("public-key", ""),
        listen_port=int(found.get("listen-port") or settings.get("listen_port") or 13231),
        tunnel_address=tunnel,
        # Публичный адрес по умолчанию берём из карточки устройства: чаще
        # всего хаб доступен по тому же адресу, по которому им и управляют.
        public_host=(settings.get("public_host") or device.get("host") or ""),
        lan_subnets=wg.split_list(settings.get("lan_subnets", "")),
    )


def _link_name(peer: dict[str, Any]) -> str:
    """Имя линка из комментария пира. Чужие пиры остаются без имени."""
    comment = str(peer.get("comment") or "")
    return comment[len(wg.TAG):] if comment.startswith(wg.TAG) else ""


#: Возраст рукопожатия, которого не было. Сортировка ставит такие строки
#: в конец, а не в начало: «связи нет» это не «связь самая свежая».
NO_HANDSHAKE = 10 ** 9


def _links(peers: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Пиры хаба в виде, пригодном для таблицы.

    Кроме показываемых значений считаются ключи сортировки. Как текст
    «45s» больше «1m30s», а «9 GB» меньше «10 MB», поэтому колонки
    рукопожатия, трафика и адреса сортируются по числам, а не по надписи.
    """
    result = []
    for peer in peers:
        name = _link_name(peer)
        allowed = wg.split_list(peer.get("allowed-address", ""))
        tunnel = next((a for a in allowed if a.endswith("/32")), "")
        handshake = str(peer.get("last-handshake") or "")
        age = wg.duration_seconds(handshake)
        result.append({
            "name": name or "(не наш пир)",
            "ours": bool(name),
            "public_key": peer.get("public-key", ""),
            "tunnel_ip": tunnel.split("/")[0],
            "tunnel_key": wg.address_sort_key(tunnel),
            "subnets": [a for a in allowed if not a.endswith("/32")],
            "endpoint": peer.get("current-endpoint-address", ""),
            "handshake": handshake,
            "handshake_key": NO_HANDSHAKE if age is None else age,
            "rx": peer.get("rx", "0"),
            "tx": peer.get("tx", "0"),
            "traffic_key": _to_int(peer.get("rx")) + _to_int(peer.get("tx")),
            "id": peer.get(".id", ""),
        })
    # По умолчанию сверху те, с кем связь свежее: если что-то отвалилось,
    # это видно внизу списка, а не приходится искать глазами
    result.sort(key=lambda r: (not r["ours"], r["handshake_key"], r["name"].lower()))
    return result


def _to_int(value: Any) -> int:
    """Счётчик трафика в число. RouterOS отдаёт их строками."""
    try:
        return int(str(value or "0").strip() or 0)
    except ValueError:
        return 0


def _hub_networks(state: dict[str, Any], interface: str) -> list[str]:
    """
    Собственные сети хаба, определённые по адресам на его интерфейсах.

    Именно этот список подставляется в поле «LAN-подсети хаба», поэтому
    отсюда выброшено всё, что в него попадать не должно: сам туннель,
    выключенные адреса и одиночные `/32`, которые сетью не являются.
    Повторы убираются, порядок сохраняется — так список читается как
    перечень площадок, а не как выгрузка из роутера.
    """
    nets: list[str] = []
    for address in state["addresses"]:
        if address.get("interface") == interface or wg.is_on(address.get("disabled")):
            continue
        value = str(address.get("address") or "")
        parsed = wg.parse_cidr(value)
        if not parsed or parsed[1] >= 32:
            continue
        network = wg.network_of(value)
        if network and str(network) not in nets:
            nets.append(str(network))
    return nets


# ---------------------------------------------------------------- страница
@router.get("/wireguard")
async def wireguard_page(request: Request, device_id: int = 0,
                         user=Depends(require("wireguard.manage"))):
    """Раздел WireGuard: выбор хаба, линки, маршруты, настройки."""
    where, params = permissions.scope_sql(user)
    devices = query(
        f"SELECT d.id, d.name, d.host FROM devices d WHERE enabled = 1{where} "
        "ORDER BY d.name COLLATE NOCASE",
        tuple(params),
    )

    # Хаб по умолчанию — тот, что настраивали в прошлый раз
    if not device_id:
        last = query_one(
            "SELECT device_id FROM wg_hubs ORDER BY updated_at DESC LIMIT 1")
        device_id = last["device_id"] if last else 0

    context: dict[str, Any] = {
        "devices": devices, "hub_id": device_id, "error": None,
        "state": None, "hub": None, "links": [], "routes": [],
        "settings": {}, "hub_networks": [],
    }

    if device_id:
        device = _device(device_id, user)
        settings = _hub_settings(device_id)
        try:
            state = _read_state(device)
        except Exception as exc:  # noqa: BLE001 — показываем причину человеку
            context["error"] = str(exc)
        else:
            hub = _hub_from(state, settings, device)
            peers = _peers_of(state, hub.interface)
            detected = _hub_networks(state, hub.interface)
            context.update({
                "state": state,
                "hub": hub,
                "settings": settings,
                "links": _links(peers),
                "routes": [r for r in state["routes"]
                           if str(r.get("comment") or "").startswith(wg.TAG)],
                # Маршруты, созданные через имя интерфейса: их стоит перевести
                # на туннельные адреса, иначе с несколькими пирами роутер
                # отдаёт пакеты не тому
                "legacy_routes": sum(
                    1 for r in state["routes"]
                    if str(r.get("comment") or "").startswith(wg.TAG)
                    and r.get("gateway") == hub.interface
                ),
                "hub_networks": detected,
                # Поле LAN заполняем сохранённым, а при его отсутствии тем,
                # что нашлось на роутере: человеку остаётся вычеркнуть лишнее
                # и нажать «Сохранить», а не собирать список руками.
                "lan_value": settings.get("lan_subnets") or ", ".join(detected),
                "lan_guessed": not settings.get("lan_subnets") and bool(detected),
                "suggested_ip": wg.next_free_tunnel_ip(
                    hub.tunnel_address,
                    [p.get("allowed-address", "") for p in peers],
                ) or "",
                "firewall_ready": _firewall_ready(state, hub),
            })

    return render("wireguard.html", request, user, active="wireguard", **context)


def _firewall_ready(state: dict[str, Any], hub: wg.Hub) -> bool:
    """Есть ли уже правила, пропускающие туннель."""
    comments = {str(r.get("comment") or "") for r in state["firewall"]}
    needed = {f"{wg.TAG}fwd-in:{hub.interface}", f"{wg.TAG}fwd-out:{hub.interface}"}
    return needed <= comments


# ------------------------------------------------------------- настройки хаба
@router.post("/api/wg/hub")
async def save_hub(request: Request, user=Depends(require("wireguard.manage"))):
    """Сохранить настройки хаба: интерфейс, публичный адрес, LAN-подсети."""
    payload = await request.json()
    device_id = int(payload.get("device_id") or 0)
    device = _device(device_id, user)

    _save_hub(
        device_id,
        interface=str(payload.get("interface") or "").strip(),
        public_host=str(payload.get("public_host") or "").strip(),
        lan_subnets=",".join(wg.split_list(payload.get("lan_subnets", ""))),
        listen_port=int(payload.get("listen_port") or 13231),
    )
    log_audit(user["username"], "Настроен хаб WireGuard", device["name"],
              ip=client_ip(request))
    return {"ok": True}


@router.post("/api/wg/tunnel-address")
def set_tunnel_address(request: Request, payload: dict = Body(default={}),
                       user=Depends(require("wireguard.manage"))):
    """
    Задать туннельный адрес хаба.

    Живёт на роутере, а не у нас: это обычный `/ip/address` на интерфейсе.
    Существующий адрес меняем, а не добавляем второй, иначе на интерфейсе
    окажется два адреса и маршрутизация станет непредсказуемой.
    """
    from ..sessions import pool

    device = _device(int(payload.get("device_id") or 0), user)
    interface = str(payload.get("interface") or "").strip()
    address = str(payload.get("address") or "").strip()

    if not wg.parse_cidr(address):
        return JSONResponse({"error": "Адрес указан неверно"}, status_code=400)

    with pool.borrow(device) as mt:
        existing = [a for a in mt.cmd("/ip/address/print")
                    if a.get("interface") == interface]
        if existing:
            mt.cmd("/ip/address/set", **{".id": existing[0][".id"], "address": address})
        else:
            mt.cmd("/ip/address/add", **{"address": address, "interface": interface})

    log_audit(user["username"], "Туннельный адрес хаба", device["name"], address,
              ip=client_ip(request))
    return {"ok": True}


@router.post("/api/wg/firewall")
def apply_firewall(request: Request, payload: dict = Body(default={}),
                   user=Depends(require("wireguard.manage"))):
    """
    Добавить правила, пропускающие туннель.

    Правила ставятся ПЕРЕД первым drop или reject в цепочке: добавленные
    в конец списка после запрещающего правила они бы просто не сработали,
    и человек долго искал бы, почему «правило есть, а трафика нет».
    """
    from ..sessions import pool

    device = _device(int(payload.get("device_id") or 0), user)
    interface = str(payload.get("interface") or "").strip()
    port = str(payload.get("listen_port") or "").strip()

    added = 0
    with pool.borrow(device) as mt:
        wanted = [
            (f"{wg.TAG}listen:{interface}",
             {"chain": "input", "protocol": "udp", "dst-port": port} if port else None),
            (f"{wg.TAG}fwd-in:{interface}",
             {"chain": "forward", "in-interface": interface}),
            (f"{wg.TAG}fwd-out:{interface}",
             {"chain": "forward", "out-interface": interface}),
        ]
        for comment, props in wanted:
            if props is None:
                continue
            rules = mt.cmd("/ip/firewall/filter/print")
            if any(str(r.get("comment") or "") == comment for r in rules):
                continue

            body = {"action": "accept", "comment": comment, **props}
            blocker = next(
                (r for r in rules
                 if r.get("chain") == props["chain"]
                 and r.get("action") in ("drop", "reject")),
                None,
            )
            if blocker:
                body["place-before"] = blocker[".id"]
            mt.cmd("/ip/firewall/filter/add", **body)
            added += 1

    log_audit(user["username"], "Правила firewall для WireGuard", device["name"],
              f"добавлено: {added}", ip=client_ip(request))
    return {"ok": True, "added": added}


# ------------------------------------------------------------------- линки
@router.post("/api/wg/links")
def create_link(request: Request, payload: dict = Body(default={}),
                user=Depends(require("wireguard.manage"))):
    """
    Создать линк: пир и маршруты на хабе, скрипт для споука.

    Приватный ключ споука возвращается один раз в ответе и нигде не
    сохраняется. Хранить его означало бы, что утечка базы это утечка всех
    туннелей сразу, а пользы почти нет: линк проще пересоздать.
    """
    from ..sessions import pool

    device = _device(int(payload.get("device_id") or 0), user)
    settings = _hub_settings(device["id"])
    state = _read_state(device)
    hub = _hub_from(state, settings, device)
    peers = _peers_of(state, hub.interface)

    link = wg.Link(
        name=str(payload.get("name") or "").strip(),
        tunnel_ip=str(payload.get("tunnel_ip") or "").strip(),
        remote_subnets=wg.split_list(payload.get("subnets", "")),
        keepalive=int(payload.get("keepalive") or 25),
    )

    problems = wg.validate_link(
        hub, link,
        _hub_networks(state, hub.interface),
        [_link_name(p) for p in peers],
    )
    if problems:
        return JSONResponse({"error": "; ".join(problems)}, status_code=400)

    private, public = wg.generate_keypair()
    link.private_key, link.public_key = private, public
    if payload.get("psk"):
        link.psk = wg.generate_psk()

    body = {
        "interface": hub.interface,
        "public-key": public,
        "allowed-address": wg.peer_allowed_address(link),
        "comment": wg.TAG + link.name,
    }
    if link.psk:
        body["preshared-key"] = link.psk

    with pool.borrow(device) as mt:
        mt.cmd("/interface/wireguard/peers/add", **body)
        # Маршруты обязательны: allowed-address сам в таблицу ничего не пишет.
        # Шлюз это туннельный адрес споука, а не имя интерфейса: когда на
        # интерфейсе несколько пиров, маршрут через интерфейс не говорит
        # роутеру, какому из них отдать пакет.
        for subnet in link.remote_subnets:
            mt.cmd("/ip/route/add", **{
                "dst-address": subnet,
                "gateway": link.tunnel_ip,
                "comment": wg.TAG + link.name,
            })

    log_audit(user["username"], "Создан линк WireGuard", link.name,
              ", ".join(link.remote_subnets), ip=client_ip(request))

    config = wg.build_wg_quick_config(hub, link)
    return {
        "ok": True,
        "name": link.name,
        "script": wg.build_spoke_script(hub, link),
        "config": config,
        # QR только здесь: он нужен, чтобы внести конфигурацию в телефон,
        # а без приватного ключа вносить нечего
        "qr": wg.qr_svg(config),
    }


@router.post("/api/wg/links/delete")
def delete_link(request: Request, payload: dict = Body(default={}),
                user=Depends(require("wireguard.manage"))):
    """Удалить линк: пир и маршруты с его меткой. Чужое не трогаем."""
    from ..sessions import pool

    device = _device(int(payload.get("device_id") or 0), user)
    name = str(payload.get("name") or "").strip()
    if not name:
        return JSONResponse({"error": "Не указан линк"}, status_code=400)

    comment = wg.TAG + name
    removed = {"peers": 0, "routes": 0}
    with pool.borrow(device) as mt:
        for peer in mt.cmd("/interface/wireguard/peers/print"):
            if str(peer.get("comment") or "") == comment:
                mt.cmd("/interface/wireguard/peers/remove", **{".id": peer[".id"]})
                removed["peers"] += 1
        for route in mt.cmd("/ip/route/print"):
            if str(route.get("comment") or "") == comment:
                mt.cmd("/ip/route/remove", **{".id": route[".id"]})
                removed["routes"] += 1

    log_audit(user["username"], "Удалён линк WireGuard", name,
              f"пиров: {removed['peers']}, маршрутов: {removed['routes']}",
              ip=client_ip(request))
    return {"ok": True, **removed}


@router.post("/api/wg/links/script")
async def link_script(request: Request, user=Depends(require("wireguard.manage"))):
    """
    Перевыпустить скрипт для существующего линка.

    Без приватного ключа: его у нас нет и не должно быть. Скрипт остаётся
    шаблоном, о чём в нём же и написано.
    """
    payload = await request.json()
    device = _device(int(payload.get("device_id") or 0), user)
    settings = _hub_settings(device["id"])
    state = _read_state(device)
    hub = _hub_from(state, settings, device)

    name = str(payload.get("name") or "").strip()
    peer = next((p for p in _peers_of(state, hub.interface)
                 if _link_name(p) == name), None)
    if peer is None:
        return JSONResponse({"error": "Линк не найден"}, status_code=404)

    allowed = wg.split_list(peer.get("allowed-address", ""))
    tunnel = next((a for a in allowed if a.endswith("/32")), "/")
    link = wg.Link(
        name=name,
        tunnel_ip=tunnel.split("/")[0],
        remote_subnets=[a for a in allowed if not a.endswith("/32")],
        public_key=peer.get("public-key", ""),
    )
    return {
        "ok": True,
        "name": name,
        "script": wg.build_spoke_script(hub, link),
        "config": wg.build_wg_quick_config(hub, link),
        # Ключа нет, значит и в QR попадёт нерабочая конфигурация:
        # честнее не показывать его вовсе
        "qr": "",
    }


@router.post("/api/wg/links/apply")
async def apply_to_spoke(request: Request, user=Depends(require("wireguard.manage"))):
    """
    Применить скрипт на дальней стороне, если она есть в списке устройств.

    Отдельным действием и только по явной кнопке. Ошибка в подсетях может
    отрезать удалённую точку, поэтому перед выполнением снимается бэкап:
    вернуться будет к чему.
    """
    from ..actions import get_action
    from .. import worker

    payload = await request.json()
    spoke_id = int(payload.get("spoke_id") or 0)
    script = str(payload.get("script") or "")
    if not script.strip():
        return JSONResponse({"error": "Пустой скрипт"}, status_code=400)
    if not permissions.can_touch(user, [spoke_id]):
        raise Forbidden()
    if not permissions.can_run(user, "run_source"):
        raise Forbidden("Нет права выполнять код скрипта")

    spoke = query_one("SELECT name FROM devices WHERE id = ?", (spoke_id,))
    if spoke is None:
        return JSONResponse({"error": "Устройство не найдено"}, status_code=404)

    get_action("run_source")  # проверяем, что действие на месте
    job_id = worker.create_job(
        "run_source", [spoke_id],
        {"source": script, "keep_name": "", "wait_seconds": 120},
        user["username"],
    )
    log_audit(user["username"], "Применён конфиг WireGuard", spoke["name"],
              ip=client_ip(request))
    return {"ok": True, "job_id": job_id}


# ----------------------------------------------------------------- маршруты
@router.post("/api/wg/routes")
def add_route(request: Request, payload: dict = Body(default={}),
              user=Depends(require("wireguard.manage"))):
    """
    Добавить маршрут в туннель вручную.

    Шлюзом указывается туннельный адрес нужного споука, например 10.8.0.43.
    Имя интерфейса тоже принимается, но выбирается редко и осознанно:
    на интерфейсе с несколькими пирами такой маршрут работает не так,
    как ожидается.
    """
    from ..sessions import pool

    device = _device(int(payload.get("device_id") or 0), user)
    subnet = str(payload.get("subnet") or "").strip()
    gateway = str(payload.get("gateway") or "").strip()
    label = str(payload.get("label") or "manual").strip() or "manual"

    if wg.network_of(subnet) is None:
        return JSONResponse({"error": "Подсеть указана неверно"}, status_code=400)
    if not gateway:
        return JSONResponse(
            {"error": "Укажите шлюз: туннельный адрес споука, например 10.8.0.43"},
            status_code=400,
        )

    with pool.borrow(device) as mt:
        mt.cmd("/ip/route/add", **{
            "dst-address": subnet, "gateway": gateway, "comment": wg.TAG + label,
        })
    log_audit(user["username"], "Добавлен маршрут WireGuard", subnet, ip=client_ip(request))
    return {"ok": True}


@router.post("/api/wg/routes/fix-gateways")
def fix_route_gateways(request: Request, payload: dict = Body(default={}),
                       user=Depends(require("wireguard.manage"))):
    """
    Перевести маршруты панели с интерфейса на туннельные адреса споуков.

    Раньше маршруты создавались через имя интерфейса. На интерфейсе с одним
    пиром это работает, а с несколькими роутеру приходится самому решать,
    кому отдать пакет, и решение это не то, которого ждёшь. Здесь маршрут
    находит свой пир по общей метке и получает его адрес в туннеле.

    Трогаются только маршруты с меткой панели и только те, у которых шлюз
    сейчас неверный. Чужие маршруты и уже правильные не затрагиваются.
    """
    from ..sessions import pool

    device = _device(int(payload.get("device_id") or 0), user)
    settings = _hub_settings(device["id"])
    state = _read_state(device)
    hub = _hub_from(state, settings, device)

    # Имя линка → его туннельный адрес
    addresses: dict[str, str] = {}
    for peer in _peers_of(state, hub.interface):
        name = _link_name(peer)
        tunnel = next((a for a in wg.split_list(peer.get("allowed-address", ""))
                       if a.endswith("/32")), "")
        if name and tunnel:
            addresses[name] = tunnel.split("/")[0]

    fixed = 0
    with pool.borrow(device) as mt:
        for route in mt.cmd("/ip/route/print"):
            comment = str(route.get("comment") or "")
            if not comment.startswith(wg.TAG):
                continue
            wanted = addresses.get(comment[len(wg.TAG):])
            if not wanted or route.get("gateway") == wanted:
                continue
            mt.cmd("/ip/route/set", **{".id": route[".id"], "gateway": wanted})
            fixed += 1

    log_audit(user["username"], "Маршруты WireGuard переведены на шлюзы",
              device["name"], f"исправлено: {fixed}", ip=client_ip(request))
    return {"ok": True, "fixed": fixed}


@router.post("/api/wg/routes/delete")
def delete_route(request: Request, payload: dict = Body(default={}),
                 user=Depends(require("wireguard.manage"))):
    """Удалить маршрут по идентификатору. Только помеченные нашей меткой."""
    from ..sessions import pool

    device = _device(int(payload.get("device_id") or 0), user)
    route_id = str(payload.get("id") or "")

    with pool.borrow(device) as mt:
        found = next((r for r in mt.cmd("/ip/route/print") if r.get(".id") == route_id), None)
        if found is None:
            return JSONResponse({"error": "Маршрут не найден"}, status_code=404)
        if not str(found.get("comment") or "").startswith(wg.TAG):
            # Чужие маршруты не наше дело: удалить чей-то рабочий маршрут
            # намного хуже, чем не удалить свой
            raise Forbidden("Этот маршрут создан не панелью")
        mt.cmd("/ip/route/remove", **{".id": route_id})

    log_audit(user["username"], "Удалён маршрут WireGuard",
              found.get("dst-address", ""), ip=client_ip(request))
    return {"ok": True}
