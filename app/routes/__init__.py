"""HTTP-роуты приложения, разбитые по разделам интерфейса."""

from . import (  # noqa: F401
    auth_routes, backups, devices, groups, jobs, pages, wireguard_peers,
)

__all__ = ["auth_routes", "backups", "devices", "groups", "jobs", "pages",
           "wireguard_peers"]
