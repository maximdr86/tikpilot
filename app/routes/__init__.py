"""HTTP-роуты приложения, разбитые по разделам интерфейса."""

from . import auth_routes, backups, devices, groups, jobs, pages  # noqa: F401

__all__ = ["auth_routes", "backups", "devices", "groups", "jobs", "pages"]
