"""
Место на диске самой панели.

Зачем
-----

Панель следит за полусотней роутеров и однажды не уследила за собой:
диск сервера кончился, SQLite перестала писать, приём журнала встал,
а сводка в Телеграм ушла шестьдесят раз подряд, потому что отметку
об отправке тоже некуда было записать. Место при этом кончалось не
внезапно, его хватило бы предупредить за неделю.

Здесь ровно то, чего тогда не хватило: сколько свободно, что занимает
место и много ли это.

Как считается
-------------

Свободное место берётся у файловой системы, где лежит база: именно
её отказ и роняет панель. Размер папок считается обходом файлов,
поэтому ответ кэшируется на несколько минут: на дашборде он нужен
при каждом обновлении страницы, а меняется раз в сутки.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from pathlib import Path
from typing import Any

from .config import settings

log = logging.getLogger("tikpilot.disk")

#: Насколько долго держим посчитанные размеры папок. Обход каталога
#: с бэкапами полусотни точек стоит заметно дороже, чем statvfs,
#: а меняется он раз в сутки.
CACHE_SECONDS = 300

_sizes: dict[str, Any] = {"at": 0.0, "data": 0, "backups": 0, "db": 0}


def free_space() -> dict[str, int]:
    """Сколько всего, занято и свободно на диске с базой, в байтах."""
    try:
        total, used, free = shutil.disk_usage(settings.data_dir)
    except OSError as exc:  # noqa: BLE001 - без места лучше молчать, чем падать
        log.warning("Не удалось узнать свободное место: %s", exc)
        return {"total": 0, "used": 0, "free": 0}
    return {"total": total, "used": used, "free": free}


def percent_free() -> float:
    """Свободно процентов. Ноль, если спросить не удалось."""
    space = free_space()
    if not space["total"]:
        return 0.0
    return round(space["free"] * 100 / space["total"], 1)


def low() -> bool:
    """Мало ли места по нынешней настройке."""
    limit = settings.disk_min_free_percent
    if limit <= 0:
        return False
    space = free_space()
    if not space["total"]:
        return False
    return space["free"] * 100 / space["total"] < limit


def _folder_size(path: Path) -> int:
    """Сколько занимает папка со всем содержимым."""
    total = 0
    for root, _dirs, files in os.walk(path, onerror=lambda exc: None):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                continue
    return total


def sizes() -> dict[str, int]:
    """
    Что занимает место у панели: база, бэкапы, данные целиком.

    Ответ кэшируется: страница дашборда обновляется каждые пятнадцать
    секунд, а размеры так часто не меняются.
    """
    now = time.monotonic()
    if now - float(_sizes["at"]) < CACHE_SECONDS:
        return {"data": _sizes["data"], "backups": _sizes["backups"], "db": _sizes["db"]}

    db = 0
    for suffix in ("", "-wal", "-shm"):
        try:
            db += os.path.getsize(str(settings.db_path) + suffix)
        except OSError:
            continue

    _sizes.update({
        "at": now,
        "db": db,
        "backups": _folder_size(settings.backup_dir),
        "data": _folder_size(settings.data_dir),
    })
    return {"data": _sizes["data"], "backups": _sizes["backups"], "db": _sizes["db"]}


def forget() -> None:
    """Сбросить кэш размеров. Нужно тестам и ночной уборке."""
    _sizes["at"] = 0.0


def report() -> str:
    """Строка для журнала: сколько занято и сколько осталось."""
    space = free_space()
    parts = sizes()
    return (
        "Диск панели: свободно %s из %s (%.1f%%), база %s, бэкапы %s"
        % (human(space["free"]), human(space["total"]), percent_free(),
           human(parts["db"]), human(parts["backups"]))
    )


def human(size: int | float | None) -> str:
    """Байты в человеческий вид: 4,2 ГиБ."""
    value = float(size or 0)
    for unit in ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ"):
        if value < 1024 or unit == "ТиБ":
            if unit == "Б":
                return f"{int(value)} {unit}"
            return f"{value:.1f}".replace(".", ",") + f" {unit}"
        value /= 1024
    return f"{value:.1f} ТиБ"
