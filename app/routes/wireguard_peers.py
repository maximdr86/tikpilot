"""Gestione dei peer client WireGuard, indipendente dai link site-to-site."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import JSONResponse

from .. import i18n, permissions, wireguard as wg, wireguard_clients as clients
from ..auth import Forbidden, client_ip, require
from ..database import execute, log_audit, query, query_one, utcnow
from .deps import render, resolve_lang

router = APIRouter()
PERMISSION = "wireguard.peers.manage"


def _device(device_id: int, user: dict[str, Any]) -> dict[str, Any]:
    if not permissions.can_touch(user, [device_id]):
        raise Forbidden()
    row = query_one("SELECT * FROM devices WHERE id = ? AND enabled = 1", (device_id,))
    if row is None:
        raise Forbidden("Dispositivo non trovato o disabilitato")
    return dict(row)


def _devices(user: dict[str, Any]) -> list[dict[str, Any]]:
    scope, params = permissions.scope_sql(user)
    return [dict(row) for row in query(
        "SELECT DISTINCT d.id,d.name,d.host FROM devices d "
        "JOIN device_ports p ON p.device_id=d.id "
        "WHERE d.enabled=1 AND lower(p.kind) IN ('wireguard','wg') "
        "AND p.running=1 AND p.disabled=0" + scope +
        " ORDER BY d.name COLLATE NOCASE",
        tuple(params),
    )]


def _managed_devices_by_ip(user: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Index visible fleet devices by canonical literal host IP."""
    scope, params = permissions.scope_sql(user)
    rows = query(
        "SELECT d.id,d.name,d.host FROM devices d WHERE 1=1" + scope
        + " ORDER BY d.name COLLATE NOCASE,d.id",
        tuple(params),
    )
    by_ip: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        address = clients.normalize_ip(row["host"])
        if address:
            by_ip.setdefault(address, []).append({
                "id": int(row["id"]), "name": str(row["name"]),
            })
    return by_ip


def _remembered_selection(user_id: int) -> tuple[int | None, str]:
    row = query_one(
        "SELECT device_id,interface_name FROM wg_peer_user_preferences WHERE user_id=?",
        (user_id,),
    )
    if not row:
        return None, ""
    device_id = int(row["device_id"]) if row["device_id"] is not None else None
    return device_id, str(row["interface_name"] or "")


def _remember_selection(user_id: int, device_id: int | None,
                        interface: str = "") -> None:
    execute(
        "INSERT INTO wg_peer_user_preferences "
        "(user_id,device_id,interface_name,updated_at) VALUES (?,?,?,?) "
        "ON CONFLICT(user_id) DO UPDATE SET device_id=excluded.device_id,"
        "interface_name=excluded.interface_name,updated_at=excluded.updated_at",
        (user_id, device_id, interface, utcnow()),
    )


def _read_state(mt: Any) -> dict[str, list[dict[str, Any]]]:
    return {
        "interfaces": list(mt.cmd("/interface/wireguard/print")),
        "peers": list(mt.cmd("/interface/wireguard/peers/print")),
        "addresses": list(mt.cmd("/ip/address/print")),
    }


def _active_interfaces(state: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    return [row for row in state["interfaces"] if clients.is_active_interface(row)]


def _interface(state: dict[str, list[dict[str, Any]]], name: str) -> dict[str, Any] | None:
    return next((row for row in _active_interfaces(state) if row.get("name") == name), None)


def _peer_settings(device_id: int, interface: str) -> dict[str, Any]:
    row = query_one(
        "SELECT public_endpoint,dnat_base,dnat_multiplier FROM wg_peer_settings "
        "WHERE device_id=? AND interface=?",
        (device_id, interface),
    )
    return dict(row) if row else {
        "public_endpoint": "", "dnat_base": None, "dnat_multiplier": None,
    }


def _configured_interface(device_id: int,
                          active: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Prefer an active interface with saved peer settings to a bare first interface."""
    active_names = {str(row.get("name") or "") for row in active}
    if not active_names:
        return None
    settings = query(
        "SELECT interface FROM wg_peer_settings WHERE device_id=? AND "
        "(trim(public_endpoint)<>'' OR (dnat_base IS NOT NULL AND dnat_multiplier IS NOT NULL)) "
        "ORDER BY CASE WHEN dnat_base IS NOT NULL AND dnat_multiplier IS NOT NULL "
        "THEN 0 ELSE 1 END,updated_at DESC,interface",
        (device_id,),
    )
    configured = next((str(row["interface"]) for row in settings
                       if str(row["interface"]) in active_names), "")
    return next((row for row in active if row.get("name") == configured), None)


def _optional_int(value: Any, minimum: int, maximum: int) -> int | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError("Некорректное значение DNAT.")
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("Некорректное значение DNAT.") from exc
    if not minimum <= number <= maximum:
        raise ValueError("Значение DNAT вне допустимого диапазона.")
    return number


def _error(request: Request, user: dict[str, Any], message: str,
           status_code: int) -> JSONResponse:
    return JSONResponse(
        {"error": i18n.translate_text(message, resolve_lang(request, user))},
        status_code=status_code,
    )


def _hub(device: dict[str, Any], state: dict[str, list[dict[str, Any]]],
         interface: dict[str, Any]) -> tuple[wg.Hub, list[str], bool]:
    address = clients.tunnel_address(state["addresses"], str(interface.get("name") or ""))
    network = wg.network_of(address)
    legacy = query_one(
        "SELECT interface,public_host,lan_subnets FROM wg_hubs WHERE device_id=?",
        (device["id"],),
    )
    peer_settings = _peer_settings(int(device["id"]), str(interface.get("name") or ""))
    listen_port = int(interface.get("listen-port") or 0)
    endpoint_value = str(peer_settings["public_endpoint"] or "").strip()
    endpoint_fallback = not bool(endpoint_value)
    if endpoint_value:
        resolved = clients.resolve_public_endpoint(endpoint_value, listen_port)
        public_host, port_text = resolved.rsplit(":", 1)
        public_host = public_host.strip("[]")
        listen_port = int(port_text)
    elif (legacy and legacy["interface"] == interface.get("name")
          and str(legacy["public_host"] or "").strip()):
        public_host = str(legacy["public_host"]).strip()
    else:
        public_host = str(device.get("host") or "").strip()
        endpoint_fallback = True

    lan_subnets = wg.split_list(legacy["lan_subnets"] if legacy else "")
    allowed_ips = ([str(network)] if network else [])
    for subnet in lan_subnets:
        parsed = wg.network_of(subnet)
        if parsed and str(parsed) not in allowed_ips:
            allowed_ips.append(str(parsed))

    hub = wg.Hub(
        interface=str(interface.get("name") or ""),
        public_key=str(interface.get("public-key") or ""),
        listen_port=listen_port,
        tunnel_address=address,
        public_host=public_host,
        lan_subnets=[item for item in allowed_ips[1:]],
    )
    return hub, allowed_ips, endpoint_fallback


def _peer_row(peer: dict[str, Any], dnat_base: int | None = None,
              dnat_multiplier: int | None = None,
              managed_devices_by_ip: dict[str, list[dict[str, Any]]] | None = None
              ) -> dict[str, Any]:
    """Project only display fields; RouterOS keys and PSKs never go to the list UI."""
    allowed = wg.split_list(peer.get("allowed-address", ""))
    disabled = wg.is_on(peer.get("disabled"))
    handshake = str(peer.get("last-handshake") or "")
    connected = clients.is_connected(handshake, disabled)
    assigned_ip = clients.peer_ip(peer)
    row = {
        "id": str(peer.get(".id") or ""),
        "interface": str(peer.get("interface") or ""),
        "name": str(peer.get("name") or ""),
        "ip": assigned_ip,
        "allowed_address": allowed,
        "endpoint": str(peer.get("current-endpoint-address") or ""),
        "handshake": handshake if connected else "",
        "rx": str(peer.get("rx") or "0"),
        "tx": str(peer.get("tx") or "0"),
        "disabled": disabled,
        "connected": connected,
        "connection_status": "disabled" if disabled else "connected" if connected else "disconnected",
        "managed_devices": (managed_devices_by_ip or {}).get(
            clients.normalize_ip(assigned_ip), []),
    }
    if dnat_base is not None and dnat_multiplier is not None:
        row["dnat_port"] = clients.dnat_port(row["ip"], dnat_base, dnat_multiplier)
    return row


def _find_peer(peers: list[dict[str, Any]], peer_id: str,
               interface: str) -> dict[str, Any] | None:
    return next((peer for peer in peers
                 if str(peer.get(".id") or "") == peer_id
                 and peer.get("interface") == interface), None)


def _config_payload(name: str, client_ip: str, private_key: str,
                    hub: wg.Hub, allowed_ips: list[str],
                    preshared_key: str = "") -> dict[str, str]:
    if not hub.tunnel_address or not hub.public_key or not hub.public_host or not hub.listen_port:
        raise ValueError("Недоступны endpoint, публичный ключ, порт или адрес туннеля сервера.")
    peer_prefix = 128 if ":" in client_ip else 32
    endpoint = clients.endpoint(hub.public_host, hub.listen_port)
    if not endpoint:
        raise ValueError("Некорректный endpoint роутера.")
    lines = [
        "[Interface]",
        f"PrivateKey = {private_key}",
        f"Address = {client_ip}/{peer_prefix}",
        "",
        "[Peer]",
        f"PublicKey = {hub.public_key}",
    ]
    if preshared_key:
        lines.append(f"PresharedKey = {preshared_key}")
    lines += [
        f"Endpoint = {endpoint}",
        f"AllowedIPs = {', '.join(allowed_ips)}",
        "PersistentKeepalive = 25",
    ]
    config = "\n".join(lines) + "\n"
    server_ip, prefix = wg.parse_cidr(hub.tunnel_address)
    script = clients.build_routeros_script(
        client_ip=client_ip, prefix=prefix, server_ip=server_ip,
        private_key=private_key,
        server_public_key=hub.public_key, server_endpoint=endpoint,
        allowed_ips=allowed_ips, preshared_key=preshared_key,
    )
    return {
        "config": config,
        "script": script,
        "qr": wg.qr_svg(config),
        "conf_file": wg.config_filename(name),
        "rsc_file": wg.config_filename(name, ".rsc"),
    }


@router.get("/wireguard/peers")
def peer_clients_page(request: Request, device_id: int = 0, interface: str = "",
                      user=Depends(require(PERMISSION))):
    devices = _devices(user)
    available_device_ids = {int(device["id"]) for device in devices}
    remembered_device_id, remembered_interface = _remembered_selection(int(user["id"]))
    if "device_id" not in request.query_params:
        if remembered_device_id in available_device_ids:
            device_id = remembered_device_id
            if "interface" not in request.query_params:
                interface = remembered_interface
        elif remembered_device_id is not None:
            _remember_selection(int(user["id"]), None)
    elif device_id == 0:
        _remember_selection(int(user["id"]), None)
    elif device_id in available_device_ids:
        if not interface and remembered_device_id == device_id:
            interface = remembered_interface
        _remember_selection(int(user["id"]), device_id, interface)

    context: dict[str, Any] = {
        "devices": devices, "device_id": device_id, "interface": interface,
        "interfaces": [], "peers": [], "error": "", "selected_device": None,
        "hub": None, "allowed_ips": [], "endpoint_fallback": False,
        "peer_settings": {"public_endpoint": "", "dnat_base": None,
                          "dnat_multiplier": None},
        "show_dnat_column": False,
        "managed_devices_by_ip": _managed_devices_by_ip(user),
        "can_add_device": permissions.has(user, "devices.edit"),
    }
    if device_id:
        device = _device(device_id, user)
        context["selected_device"] = device
        from ..sessions import pool

        try:
            with pool.borrow(device) as mt:
                state = _read_state(mt)
        except Exception as exc:  # noqa: BLE001 — render an actionable device error
            context["error"] = str(exc)
        else:
            active = _active_interfaces(state)
            context["interfaces"] = active
            selected = _interface(state, interface) if interface else None
            if selected is None and not request.query_params.get("interface"):
                selected = _configured_interface(device_id, active)
                selected = selected or (active[0] if active else None)
            if not active:
                context["error"] = "Il router non ha interfacce WireGuard attive"
            elif selected is None:
                context["error"] = "L'interfaccia selezionata non è attiva"
            else:
                context["interface"] = selected["name"]
                if device_id in available_device_ids:
                    _remember_selection(int(user["id"]), device_id,
                                        str(selected.get("name") or ""))
                peer_settings = _peer_settings(device_id, selected["name"])
                context["peer_settings"] = peer_settings
                context["show_dnat_column"] = (
                    peer_settings["dnat_base"] is not None
                    and peer_settings["dnat_multiplier"] is not None
                )
                (context["hub"], context["allowed_ips"],
                 context["endpoint_fallback"]) = _hub(device, state, selected)
                context["peers"] = [
                    _peer_row(peer, peer_settings["dnat_base"],
                              peer_settings["dnat_multiplier"],
                              context["managed_devices_by_ip"])
                    for peer in state["peers"]
                    if peer.get("interface") == selected["name"]
                ]
    return render("wireguard_peers.html", request, user,
                  active="wireguard-peers", **context)


@router.get("/api/wg/peers")
def peer_clients_snapshot(request: Request, device_id: int, interface: str,
                          user=Depends(require(PERMISSION))):
    device = _device(device_id, user)
    from ..sessions import pool

    with pool.borrow(device) as mt:
        state = _read_state(mt)
    selected = _interface(state, interface)
    if selected is None:
        return _error(request, user, "Интерфейс WireGuard не активен.", 400)
    peer_settings = _peer_settings(device_id, interface)
    managed_devices_by_ip = _managed_devices_by_ip(user)
    return JSONResponse(
        {"peers": [_peer_row(peer, peer_settings["dnat_base"],
                              peer_settings["dnat_multiplier"], managed_devices_by_ip)
                   for peer in state["peers"] if peer.get("interface") == interface]},
        headers={"Cache-Control": "no-store"},
    )


@router.post("/api/wg/peers/settings")
def save_peer_settings(request: Request, payload: dict = Body(default={}),
                       user=Depends(require(PERMISSION))):
    device = _device(int(payload.get("device_id") or 0), user)
    interface_name = str(payload.get("interface") or "").strip()
    if not interface_name:
        return _error(request, user, "Интерфейс WireGuard обязателен.", 400)

    setting_fields = {"public_endpoint", "dnat_base", "dnat_multiplier"}
    if not setting_fields.intersection(payload):
        return _error(request, user, "Нет параметров для обновления.", 400)
    current = _peer_settings(int(device["id"]), interface_name)
    public_endpoint = str(current["public_endpoint"] or "").strip()
    if "public_endpoint" in payload:
        raw_endpoint = payload["public_endpoint"]
        if raw_endpoint is not None and not isinstance(raw_endpoint, str):
            return _error(request, user, "Некорректный публичный endpoint.", 400)
        public_endpoint = str(raw_endpoint or "").strip()
    if len(public_endpoint) > 300:
        return _error(request, user, "Публичный endpoint слишком длинный.", 400)
    try:
        dnat_base = (
            _optional_int(payload.get("dnat_base"), 1, 65535)
            if "dnat_base" in payload else current["dnat_base"]
        )
        dnat_multiplier = (
            _optional_int(payload.get("dnat_multiplier"), 256, 65535)
            if "dnat_multiplier" in payload else current["dnat_multiplier"]
        )
    except ValueError as exc:
        return _error(request, user, str(exc), 400)

    from ..sessions import pool

    with pool.borrow(device) as mt:
        state = _read_state(mt)
        selected = _interface(state, interface_name)
        if selected is None:
            return _error(request, user, "Интерфейс WireGuard не активен.", 400)
        if public_endpoint:
            try:
                clients.resolve_public_endpoint(
                    public_endpoint, int(selected.get("listen-port") or 0),
                )
            except ValueError as exc:
                return _error(request, user, str(exc), 400)

    now = utcnow()
    if not public_endpoint and dnat_base is None and dnat_multiplier is None:
        execute(
            "DELETE FROM wg_peer_settings WHERE device_id=? AND interface=?",
            (device["id"], interface_name),
        )
    else:
        execute(
            "INSERT INTO wg_peer_settings "
            "(device_id,interface,public_endpoint,dnat_base,dnat_multiplier,updated_at) "
            "VALUES (?,?,?,?,?,?) ON CONFLICT(device_id,interface) DO UPDATE SET "
            "public_endpoint=excluded.public_endpoint,dnat_base=excluded.dnat_base,"
            "dnat_multiplier=excluded.dnat_multiplier,updated_at=excluded.updated_at",
            (device["id"], interface_name, public_endpoint, dnat_base,
             dnat_multiplier, now),
        )
    log_audit(user["username"], "Aggiornate impostazioni peer WireGuard",
              device["name"], interface_name, ip=client_ip(request))
    return JSONResponse({"settings": {
        "public_endpoint": public_endpoint,
        "dnat_base": dnat_base,
        "dnat_multiplier": dnat_multiplier,
    }})


@router.post("/api/wg/peers/create")
def create_peer_client(request: Request, payload: dict = Body(default={}),
                       user=Depends(require(PERMISSION))):
    device = _device(int(payload.get("device_id") or 0), user)
    interface_name = str(payload.get("interface") or "").strip()
    name = str(payload.get("name") or "").strip()
    if not name or len(name) > 128:
        return _error(request, user, "Имя обязательно; максимум 128 символов.", 400)

    from ..sessions import pool

    with pool.borrow(device) as mt:
        state = _read_state(mt)
        interface = _interface(state, interface_name)
        if interface is None:
            return _error(request, user, "Интерфейс WireGuard не активен.", 400)
        hub, allowed_ips, _ = _hub(device, state, interface)
        peers = [p for p in state["peers"] if p.get("interface") == interface_name]
        if any(str(p.get("name") or "").casefold() == name.casefold() for p in peers):
            return _error(request, user, "Peer с таким именем уже существует.", 409)
        if not hub.tunnel_address:
            return _error(request, user, "У интерфейса нет корректного туннельного адреса.", 400)
        taken_addresses = [p.get("allowed-address", "") for p in peers]
        taken_addresses.extend(clients.interface_host_addresses(state["addresses"], interface_name))
        assigned_ip = wg.next_free_tunnel_ip(
            hub.tunnel_address,
            taken_addresses,
        )
        if not assigned_ip:
            return _error(request, user, "В подсети WireGuard нет свободных IP-адресов.", 409)
        private, public = wg.generate_keypair()
        # Verifica prerequisiti prima della mutazione: non lasciare un peer
        # creato quando non è possibile consegnare una configurazione valida.
        try:
            exports = _config_payload(name, assigned_ip, private, hub, allowed_ips)
        except (ValueError, TypeError) as exc:
            return _error(request, user, str(exc), 400)
        mt.cmd("/interface/wireguard/peers/add", **{
            "interface": interface_name,
            "name": name,
            "public-key": public,
            "allowed-address": f"{assigned_ip}/32" if ":" not in assigned_ip else f"{assigned_ip}/128",
        })

    log_audit(user["username"], "Creato peer client WireGuard", name,
              f"{device['name']} · {interface_name} · {assigned_ip}", ip=client_ip(request))
    return JSONResponse({"peer": {"name": name, "ip": assigned_ip, **exports}},
                        headers={"Cache-Control": "no-store"})


@router.post("/api/wg/peers/rename")
def rename_peer_client(request: Request, payload: dict = Body(default={}),
                       user=Depends(require(PERMISSION))):
    device = _device(int(payload.get("device_id") or 0), user)
    interface = str(payload.get("interface") or "").strip()
    peer_id = str(payload.get("id") or "").strip()
    name = str(payload.get("name") or "").strip()
    if not name or len(name) > 128:
        return _error(request, user, "Имя обязательно; максимум 128 символов.", 400)
    from ..sessions import pool

    with pool.borrow(device) as mt:
        state = _read_state(mt)
        if _interface(state, interface) is None:
            return _error(request, user, "Интерфейс WireGuard не активен.", 400)
        peer = _find_peer(state["peers"], peer_id, interface)
        if peer is None:
            return _error(request, user, "Peer не найден.", 404)
        if any(str(row.get("name") or "").casefold() == name.casefold()
               and str(row.get(".id") or "") != peer_id
               for row in state["peers"] if row.get("interface") == interface):
            return _error(request, user, "Peer с таким именем уже существует.", 409)
        mt.cmd("/interface/wireguard/peers/set", **{".id": peer_id, "name": name})
    log_audit(user["username"], "Rinominato peer client WireGuard", name,
              f"{device['name']} · {interface}", ip=client_ip(request))
    return {"ok": True, "name": name}


@router.post("/api/wg/peers/toggle")
def toggle_peer_client(request: Request, payload: dict = Body(default={}),
                       user=Depends(require(PERMISSION))):
    device = _device(int(payload.get("device_id") or 0), user)
    interface = str(payload.get("interface") or "").strip()
    peer_id = str(payload.get("id") or "").strip()
    if not isinstance(payload.get("disabled"), bool):
        return _error(request, user, "Некорректное значение disabled.", 400)
    from ..sessions import pool

    with pool.borrow(device) as mt:
        state = _read_state(mt)
        if _interface(state, interface) is None:
            return _error(request, user, "Интерфейс WireGuard не активен.", 400)
        if _find_peer(state["peers"], peer_id, interface) is None:
            return _error(request, user, "Peer не найден.", 404)
        mt.cmd("/interface/wireguard/peers/set", **{
            ".id": peer_id, "disabled": "yes" if payload["disabled"] else "no",
        })
    action = "Disabilitato" if payload["disabled"] else "Riattivato"
    log_audit(user["username"], f"{action} peer client WireGuard", peer_id,
              f"{device['name']} · {interface}", ip=client_ip(request))
    return {"ok": True, "disabled": payload["disabled"]}


@router.post("/api/wg/peers/delete")
def delete_peer_client(request: Request, payload: dict = Body(default={}),
                       user=Depends(require(PERMISSION))):
    device = _device(int(payload.get("device_id") or 0), user)
    interface = str(payload.get("interface") or "").strip()
    peer_id = str(payload.get("id") or "").strip()
    from ..sessions import pool

    with pool.borrow(device) as mt:
        state = _read_state(mt)
        if _interface(state, interface) is None:
            return _error(request, user, "Интерфейс WireGuard не активен.", 400)
        peer = _find_peer(state["peers"], peer_id, interface)
        if peer is None:
            return _error(request, user, "Peer не найден.", 404)
        name = str(peer.get("name") or peer_id)
        mt.cmd("/interface/wireguard/peers/remove", **{".id": peer_id})
    log_audit(user["username"], "Eliminato peer client WireGuard", name,
              f"{device['name']} · {interface}", ip=client_ip(request))
    return {"ok": True}


@router.post("/api/wg/peers/regenerate")
def regenerate_peer_client(request: Request, payload: dict = Body(default={}),
                           user=Depends(require(PERMISSION))):
    device = _device(int(payload.get("device_id") or 0), user)
    interface_name = str(payload.get("interface") or "").strip()
    peer_id = str(payload.get("id") or "").strip()
    from ..sessions import pool

    with pool.borrow(device) as mt:
        state = _read_state(mt)
        interface = _interface(state, interface_name)
        if interface is None:
            return _error(request, user, "Интерфейс WireGuard не активен.", 400)
        peer = _find_peer(state["peers"], peer_id, interface_name)
        if peer is None:
            return _error(request, user, "Peer не найден.", 404)
        assigned_ip = clients.peer_ip(peer)
        if not assigned_ip:
            return _error(request, user, "У peer не назначен IP-адрес хоста.", 400)
        hub, allowed_ips, _ = _hub(device, state, interface)
        private, public = wg.generate_keypair()
        try:
            exports = _config_payload(
                str(peer.get("name") or "peer"), assigned_ip, private, hub, allowed_ips,
                str(peer.get("preshared-key") or ""),
            )
        except (ValueError, TypeError) as exc:
            return _error(request, user, str(exc), 400)
        mt.cmd("/interface/wireguard/peers/set", **{".id": peer_id, "public-key": public})

    name = str(peer.get("name") or peer_id)
    log_audit(user["username"], "Rigenerata chiave peer client WireGuard", name,
              f"{device['name']} · {interface_name}", ip=client_ip(request))
    return JSONResponse({"peer": {"name": name, "ip": assigned_ip, **exports}},
                        headers={"Cache-Control": "no-store"})
