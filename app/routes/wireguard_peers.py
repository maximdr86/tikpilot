"""Gestione dei peer client WireGuard, indipendente dai link site-to-site."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import JSONResponse

from .. import permissions, wireguard as wg, wireguard_clients as clients
from ..auth import Forbidden, client_ip, require
from ..database import log_audit, query, query_one
from .deps import render

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


def _hub(device: dict[str, Any], state: dict[str, list[dict[str, Any]]],
         interface: dict[str, Any]) -> tuple[wg.Hub, list[str], bool]:
    address = clients.tunnel_address(state["addresses"], str(interface.get("name") or ""))
    network = wg.network_of(address)
    settings = query_one("SELECT public_host,lan_subnets FROM wg_hubs WHERE device_id=?",
                         (device["id"],))
    saved_host = str(settings["public_host"] if settings else "").strip()
    public_host = saved_host or str(device.get("host") or "").strip()
    lan_subnets = wg.split_list(settings["lan_subnets"] if settings else "")
    allowed_ips = ([str(network)] if network else [])
    for subnet in lan_subnets:
        parsed = wg.network_of(subnet)
        if parsed and str(parsed) not in allowed_ips:
            allowed_ips.append(str(parsed))

    hub = wg.Hub(
        interface=str(interface.get("name") or ""),
        public_key=str(interface.get("public-key") or ""),
        listen_port=int(interface.get("listen-port") or 0),
        tunnel_address=address,
        public_host=public_host,
        lan_subnets=[item for item in allowed_ips[1:]],
    )
    return hub, allowed_ips, not bool(saved_host)


def _peer_row(peer: dict[str, Any]) -> dict[str, Any]:
    """Project only display fields; RouterOS keys and PSKs never go to the list UI."""
    allowed = wg.split_list(peer.get("allowed-address", ""))
    disabled = wg.is_on(peer.get("disabled"))
    handshake = str(peer.get("last-handshake") or "")
    connected = clients.is_connected(handshake, disabled)
    return {
        "id": str(peer.get(".id") or ""),
        "interface": str(peer.get("interface") or ""),
        "name": str(peer.get("name") or ""),
        "ip": clients.peer_ip(peer),
        "allowed_address": allowed,
        "endpoint": str(peer.get("current-endpoint-address") or ""),
        "handshake": handshake if connected else "",
        "rx": str(peer.get("rx") or "0"),
        "tx": str(peer.get("tx") or "0"),
        "disabled": disabled,
        "connected": connected,
        "connection_status": "disabled" if disabled else "connected" if connected else "disconnected",
    }


def _find_peer(peers: list[dict[str, Any]], peer_id: str,
               interface: str) -> dict[str, Any] | None:
    return next((peer for peer in peers
                 if str(peer.get(".id") or "") == peer_id
                 and peer.get("interface") == interface), None)


def _config_payload(name: str, client_ip: str, private_key: str,
                    hub: wg.Hub, allowed_ips: list[str],
                    preshared_key: str = "") -> dict[str, str]:
    if not hub.tunnel_address or not hub.public_key or not hub.public_host or not hub.listen_port:
        raise ValueError("Endpoint, chiave pubblica o indirizzo del server WireGuard non disponibili")
    peer_prefix = 128 if ":" in client_ip else 32
    endpoint = clients.endpoint(hub.public_host, hub.listen_port)
    if not endpoint:
        raise ValueError("Endpoint del router non valido")
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
    context: dict[str, Any] = {
        "devices": devices, "device_id": device_id, "interface": interface,
        "interfaces": [], "peers": [], "error": "", "selected_device": None,
        "hub": None, "allowed_ips": [], "endpoint_fallback": False,
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
            selected = _interface(state, interface) if interface else (active[0] if active else None)
            if not active:
                context["error"] = "Il router non ha interfacce WireGuard attive"
            elif selected is None:
                context["error"] = "L'interfaccia selezionata non è attiva"
            else:
                context["interface"] = selected["name"]
                (context["hub"], context["allowed_ips"],
                 context["endpoint_fallback"]) = _hub(device, state, selected)
                context["peers"] = [
                    _peer_row(peer) for peer in state["peers"]
                    if peer.get("interface") == selected["name"]
                ]
    return render("wireguard_peers.html", request, user,
                  active="wireguard-peers", **context)


@router.get("/api/wg/peers")
def peer_clients_snapshot(device_id: int, interface: str,
                          user=Depends(require(PERMISSION))):
    device = _device(device_id, user)
    from ..sessions import pool

    with pool.borrow(device) as mt:
        state = _read_state(mt)
    selected = _interface(state, interface)
    if selected is None:
        return JSONResponse({"error": "Interfaccia WireGuard non attiva"}, status_code=400)
    return JSONResponse(
        {"peers": [_peer_row(peer) for peer in state["peers"]
                   if peer.get("interface") == interface]},
        headers={"Cache-Control": "no-store"},
    )


@router.post("/api/wg/peers/create")
def create_peer_client(request: Request, payload: dict = Body(default={}),
                       user=Depends(require(PERMISSION))):
    device = _device(int(payload.get("device_id") or 0), user)
    interface_name = str(payload.get("interface") or "").strip()
    name = str(payload.get("name") or "").strip()
    if not name or len(name) > 128:
        return JSONResponse({"error": "Il nome è obbligatorio e non può superare 128 caratteri"},
                            status_code=400)

    from ..sessions import pool

    with pool.borrow(device) as mt:
        state = _read_state(mt)
        interface = _interface(state, interface_name)
        if interface is None:
            return JSONResponse({"error": "Interfaccia WireGuard non attiva"}, status_code=400)
        hub, allowed_ips, _ = _hub(device, state, interface)
        peers = [p for p in state["peers"] if p.get("interface") == interface_name]
        if any(str(p.get("name") or "").casefold() == name.casefold() for p in peers):
            return JSONResponse({"error": "Esiste già un peer con questo nome"}, status_code=409)
        if not hub.tunnel_address:
            return JSONResponse({"error": "L'interfaccia non ha un indirizzo tunnel valido"},
                                status_code=400)
        taken_addresses = [p.get("allowed-address", "") for p in peers]
        taken_addresses.extend(clients.interface_host_addresses(state["addresses"], interface_name))
        assigned_ip = wg.next_free_tunnel_ip(
            hub.tunnel_address,
            taken_addresses,
        )
        if not assigned_ip:
            return JSONResponse({"error": "Non ci sono IP liberi nella subnet WireGuard"},
                                status_code=409)
        private, public = wg.generate_keypair()
        # Verifica prerequisiti prima della mutazione: non lasciare un peer
        # creato quando non è possibile consegnare una configurazione valida.
        try:
            exports = _config_payload(name, assigned_ip, private, hub, allowed_ips)
        except (ValueError, TypeError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
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
        return JSONResponse({"error": "Il nome è obbligatorio e non può superare 128 caratteri"},
                            status_code=400)
    from ..sessions import pool

    with pool.borrow(device) as mt:
        state = _read_state(mt)
        if _interface(state, interface) is None:
            return JSONResponse({"error": "Interfaccia WireGuard non attiva"}, status_code=400)
        peer = _find_peer(state["peers"], peer_id, interface)
        if peer is None:
            return JSONResponse({"error": "Peer non trovato"}, status_code=404)
        if any(str(row.get("name") or "").casefold() == name.casefold()
               and str(row.get(".id") or "") != peer_id
               for row in state["peers"] if row.get("interface") == interface):
            return JSONResponse({"error": "Esiste già un peer con questo nome"}, status_code=409)
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
        return JSONResponse({"error": "Stato disabled non valido"}, status_code=400)
    from ..sessions import pool

    with pool.borrow(device) as mt:
        state = _read_state(mt)
        if _interface(state, interface) is None:
            return JSONResponse({"error": "Interfaccia WireGuard non attiva"}, status_code=400)
        if _find_peer(state["peers"], peer_id, interface) is None:
            return JSONResponse({"error": "Peer non trovato"}, status_code=404)
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
            return JSONResponse({"error": "Interfaccia WireGuard non attiva"}, status_code=400)
        peer = _find_peer(state["peers"], peer_id, interface)
        if peer is None:
            return JSONResponse({"error": "Peer non trovato"}, status_code=404)
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
            return JSONResponse({"error": "Interfaccia WireGuard non attiva"}, status_code=400)
        peer = _find_peer(state["peers"], peer_id, interface_name)
        if peer is None:
            return JSONResponse({"error": "Peer non trovato"}, status_code=404)
        assigned_ip = clients.peer_ip(peer)
        if not assigned_ip:
            return JSONResponse({"error": "Il peer non ha un IP host assegnato"}, status_code=400)
        hub, allowed_ips, _ = _hub(device, state, interface)
        private, public = wg.generate_keypair()
        try:
            exports = _config_payload(
                str(peer.get("name") or "peer"), assigned_ip, private, hub, allowed_ips,
                str(peer.get("preshared-key") or ""),
            )
        except (ValueError, TypeError) as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        mt.cmd("/interface/wireguard/peers/set", **{".id": peer_id, "public-key": public})

    name = str(peer.get("name") or peer_id)
    log_audit(user["username"], "Rigenerata chiave peer client WireGuard", name,
              f"{device['name']} · {interface_name}", ip=client_ip(request))
    return JSONResponse({"peer": {"name": name, "ip": assigned_ip, **exports}},
                        headers={"Cache-Control": "no-store"})
