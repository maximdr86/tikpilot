"""Calcoli ed export per peer WireGuard client, separati dai link site-to-site."""

from __future__ import annotations

import hashlib
import ipaddress
import re

from . import wireguard as wg

HANDSHAKE_TIMEOUT_SECONDS = 300


def is_active_interface(interface: dict) -> bool:
    """Un'interfaccia è selezionabile se RouterOS la marca running e non disabilitata."""
    return wg.is_on(interface.get("running")) and not wg.is_on(interface.get("disabled"))


def tunnel_address(addresses: list[dict], interface: str) -> str:
    """Primo indirizzo CIDR abilitato assegnato all'interfaccia WireGuard."""
    for row in addresses:
        if row.get("interface") != interface or wg.is_on(row.get("disabled")):
            continue
        value = str(row.get("address") or "").strip()
        parsed = wg.parse_cidr(value)
        if parsed and parsed[1] < 32:
            return value
    return ""


def interface_host_addresses(addresses: list[dict], interface: str) -> list[str]:
    """Host reservations for every enabled address already bound to the interface."""
    reserved = []
    for row in addresses:
        if row.get("interface") != interface or wg.is_on(row.get("disabled")):
            continue
        parsed = wg.parse_cidr(str(row.get("address") or ""))
        if parsed:
            ip, _prefix = parsed
            reserved.append(f"{ip}/{'128' if ':' in ip else '32'}")
    return reserved


def peer_ip(peer: dict) -> str:
    """Estrae l'indirizzo host /32 o /128 assegnato al peer."""
    for value in wg.split_list(peer.get("allowed-address", "")):
        parsed = wg.parse_cidr(value)
        if parsed and parsed[1] in (32, 128):
            return parsed[0]
    return ""


def is_connected(handshake: str, disabled: bool = False) -> bool:
    """A recent handshake, not the enabled flag, marks a client as connected."""
    age = wg.duration_seconds(handshake)
    return not disabled and age is not None and age <= HANDSHAKE_TIMEOUT_SECONDS


def endpoint(host: str, port: int) -> str:
    """Formatta l'endpoint WireGuard, mettendo tra parentesi gli IPv6."""
    value = str(host or "").strip()
    try:
        port = int(port)
    except (TypeError, ValueError):
        return ""
    if not value or not 1 <= port <= 65535 or any(char in value for char in "\r\n\t /\\"):
        return ""
    value = value.strip("[]")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if len(value) > 253 or not re.fullmatch(
            r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
            r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*",
            value,
        ):
            return ""
        return f"{value}:{port}"
    if address.version == 6:
        return f"[{address}]:{port}"
    return f"{address}:{port}"


def routeros_quote(value: str) -> str:
    """Quote una stringa per gli attributi testuali dello script RouterOS."""
    escaped = str(value).replace("\\", "\\\\").replace('"', '\\"')
    escaped = escaped.replace("\r", " ").replace("\n", " ")
    return f'"{escaped}"'


def client_interface_name(address: str) -> str:
    """Nome RouterOS corto e deterministico, senza incorporare il nome del peer."""
    parsed = ipaddress.ip_address(address)
    if parsed.version == 4:
        return f"wg-{str(parsed).replace('.', '-')}"
    suffix = hashlib.sha256(str(parsed).encode()).hexdigest()[:8]
    return f"wg6-{suffix}"


def build_routeros_script(*, client_ip: str, prefix: int, server_ip: str,
                          private_key: str, server_public_key: str,
                          server_endpoint: str, allowed_ips: list[str],
                          preshared_key: str = "") -> str:
    """Create a minimal client setup and mark the server IP as MANAGEMENT."""
    if not private_key or not server_public_key or not server_endpoint or not allowed_ips:
        raise ValueError("Dati WireGuard insufficienti per generare lo script")
    if not 0 <= int(prefix) <= 128:
        raise ValueError("Prefisso tunnel non valido")
    try:
        server_address = ipaddress.ip_address(server_ip)
    except ValueError as exc:
        raise ValueError("Indirizzo tunnel del server non valido") from exc
    try:
        client_address = ipaddress.ip_address(client_ip)
    except ValueError as exc:
        raise ValueError("Indirizzo client non valido") from exc
    if client_address.version != server_address.version:
        raise ValueError("Indirizzo client e server devono usare la stessa famiglia IP")

    interface = client_interface_name(client_ip)
    address = routeros_quote(f"{client_ip}/{prefix}")
    address_command = f"add address={address} interface={routeros_quote(interface)}"
    if client_address.version == 4:
        network = ipaddress.ip_network(f"{client_address}/{int(prefix)}", strict=False).network_address
        address_command = (
            f"add address={address} network={routeros_quote(str(network))} "
            f"interface={routeros_quote(interface)}"
        )
    private = routeros_quote(private_key)
    public = routeros_quote(server_public_key)
    endpoint_host, endpoint_port = server_endpoint.rsplit(":", 1)
    endpoint_host = endpoint_host.strip("[]")
    allowed = routeros_quote(",".join(allowed_ips))
    peer_command = (
        f"add interface={routeros_quote(interface)} public-key={public} "
        f"endpoint-address={routeros_quote(endpoint_host)} endpoint-port={int(endpoint_port)} "
        f"allowed-address={allowed} persistent-keepalive=25s"
    )
    if preshared_key:
        peer_command += f" preshared-key={routeros_quote(preshared_key)}"

    lines = [
        "/interface/wireguard",
        f"add name={routeros_quote(interface)} private-key={private}",
        "",
        "/ipv6/address" if ":" in client_ip else "/ip/address",
        address_command,
        "",
        "/interface/wireguard/peers",
        peer_command,
        "",
        "/ipv6/firewall/address-list" if server_address.version == 6 else "/ip/firewall/address-list",
        f"add address={server_address.compressed} list=MANAGEMENT",
    ]
    return "\n".join(lines) + "\n"
