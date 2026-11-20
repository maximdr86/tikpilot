"""Minimal Winbox 4 address-book export."""

from __future__ import annotations

import struct
from typing import Any, Iterable


def _text(field: bytes, value: str) -> bytes:
    encoded = value.encode("utf-8")
    if len(encoded) > 255:
        raise ValueError("Winbox: значение поля превышает 255 байт UTF-8")
    return field + bytes([len(encoded)]) + encoded


def export_cdb(devices: Iterable[dict[str, Any]]) -> bytes:
    """Serialize the subset of CDB verified against Winbox 4."""
    result = bytearray(bytes.fromhex("0df01dc0"))
    for index, device in enumerate(devices, start=1):
        identity = (bytes([9, index]) if index <= 255
                    else bytes([8]) + struct.pack("<I", index))
        name = str(device["name"])
        record = bytearray(b"M2")
        record += bytes.fromhex("050000000700000109000008ffffffff0100fe") + identity
        for field, value in (
            ("08000021", ""),
            ("04000021", name),
            ("03000021", str(device.get("password") or "")),
            ("02000021", str(device["username"])),
            ("01000021", str(device["host"])),
            ("06000021", "<own>"),
            ("0900fe21", name),
        ):
            record += _text(bytes.fromhex(field), value)
        result += struct.pack("<I", len(record)) + record
    return bytes(result)
