"""
Страховка при изменении конфигурации: откат, который сделает сам роутер.

Проверено на живом парке в августе 2026: задача заводится, срабатывает
один раз, снимок восстанавливается, точка возвращается.

Зачем
-----

Опечатка в правиле файрвола на точке за триста километров по зимнику стоит
поездки. Панель тут помочь не может: связь уже потеряна, и любая её попытка
«исправить обратно» упирается в то же самое отсутствие связи.

Поэтому решение переносится на само устройство. Перед изменением на роутере
заводится отложенная задача: через N минут восстановить снимок, снятый
секунду назад. Если после изменения связь есть и человек подтвердил, задача
снимается и ничего не происходит. Если связи нет, роутер через N минут сам
вернётся к прежней конфигурации и перезагрузится.

Ключевое свойство: страховка работает без участия панели. Упал сервер,
пропал интернет у офиса, администратор закрыл ноутбук и уехал, точка всё
равно вернётся.

Почему бинарный снимок, а не обратные команды
---------------------------------------------

Обратную команду к произвольной строке вычислить нельзя. `add` можно
отменить, а `set` без знания прежнего значения нет, и это ещё простой
случай. Снимок отменяет всё сразу, ценой перезагрузки. Перезагрузка на
удалённой точке неприятна, но она несопоставима с поездкой туда.

Почему `interval`, а не время старта
------------------------------------

Отложенную задачу можно поставить на «в 15:42». Но часы на роутере бывают
сбиты, а после потери связи ещё и не синхронизируются: NTP тоже ходит через
упавший канал. Интервал считается от момента создания задачи самим
устройством и от часов не зависит вовсе.

Что здесь намеренно не делается
-------------------------------

Проверка «а работает ли точка на самом деле» остаётся за человеком. Панель
умеет убедиться, что устройство отвечает, и не более того: правило, которое
закрыло кассам доступ к серверу, роутер обслуживать не мешает. Поэтому режим
подтверждения руками есть и он основной.
"""

from __future__ import annotations

import logging
from typing import Any

from .database import execute, execute_changes, log_audit, query, query_one, utcnow

log = logging.getLogger("tikpilot.rollback")

#: Имя задачи и снимка на устройстве. Одно на все точки: две страховки
#: одновременно это состояние, в котором никто не разберётся, и вторая
#: попытка должна натыкаться на первую, а не заводить соседнюю.
SCHEDULER_NAME = "tikpilot-rollback"
BACKUP_NAME = "tikpilot-rollback"

#: Границы срока. Меньше двух минут не хватит даже дойти до точки глазами,
#: больше часа означает, что страховка забыта.
MIN_MINUTES, MAX_MINUTES, DEFAULT_MINUTES = 2, 60, 10


class RollbackError(Exception):
    """Страховку не удалось взвести. Текст показывается человеку как есть."""


def _script(minutes: int) -> str:
    """
    Что выполнит роутер, если его не остановить.

    Сначала снимает саму задачу, потом восстанавливает снимок. Порядок
    важен: `backup load` перезагружает устройство, и всё, что написано
    после него, не выполнится никогда. Оставшаяся задача после
    перезагрузки сработала бы снова, и точка попала бы в петлю.
    """
    return (
        "/system scheduler remove [find name=\"%s\"]; "
        "/system backup load name=%s password=\"\""
    ) % (SCHEDULER_NAME, BACKUP_NAME)


def arm(mt: Any, device: dict[str, Any], minutes: int, username: str,
        note: str = "") -> dict[str, Any]:
    """
    Снять снимок и завести на устройстве отложенный откат.

    Возвращает запись страховки. Если что-то из этого не получилось,
    поднимаем ошибку и **не** даём применить изменение: смысл страховки
    в том, что без неё изменение не идёт.
    """
    minutes = max(MIN_MINUTES, min(MAX_MINUTES, int(minutes or DEFAULT_MINUTES)))
    device_id = int(device["id"])

    # Прежняя страховка на этой точке снимается: две одновременно это
    # состояние, в котором не разберётся никто
    disarm_device(mt, device_id, quiet=True)

    try:
        mt.cmd("/system/backup/save", **{"name": BACKUP_NAME, "dont-encrypt": "yes"})
    except Exception as exc:  # noqa: BLE001 — текст уйдёт человеку
        raise RollbackError(f"Не удалось снять снимок для отката: {exc}") from exc

    try:
        mt.cmd("/system/scheduler/add", **{
            "name": SCHEDULER_NAME,
            "interval": "00:%02d:00" % minutes if minutes < 60 else "01:00:00",
            "on-event": _script(minutes),
            "comment": "Tikpilot: откат, если изменение не подтвердят",
            "policy": "read,write,policy,reboot,test",
        })
    except Exception as exc:  # noqa: BLE001
        raise RollbackError(f"Не удалось завести отложенный откат: {exc}") from exc

    now = utcnow()
    execute(
        "INSERT INTO rollbacks (device_id, device_name, username, note, minutes,"
        " state, created_at, expires_at) VALUES (?,?,?,?,?,'armed',?,"
        " datetime(?, ?))",
        (device_id, str(device.get("name") or ""), username, note[:200], minutes,
         now, now, f"+{minutes} minutes"),
    )
    log_audit(username, "Взведена страховка", str(device.get("name") or ""),
              f"откат через {minutes} мин", "")
    return current(device_id) or {}


def disarm_device(mt: Any, device_id: int, quiet: bool = False) -> bool:
    """
    Снять задачу и убрать снимок с устройства.

    Снимок удаляется тоже: это полный слепок конфигурации, включая пароли
    подключений, и оставлять его лежать в файлах роутера незачем.
    """
    removed = False
    try:
        for row in mt.cmd("/system/scheduler/print"):
            if str(row.get("name", "")) == SCHEDULER_NAME:
                mt.cmd("/system/scheduler/remove", **{".id": row[".id"]})
                removed = True
    except Exception as exc:  # noqa: BLE001
        if not quiet:
            raise RollbackError(f"Не удалось снять отложенный откат: {exc}") from exc
        return False

    try:
        for row in mt.cmd("/file/print"):
            if str(row.get("name", "")).startswith(BACKUP_NAME):
                mt.cmd("/file/remove", **{".id": row[".id"]})
    except Exception:  # noqa: BLE001 — файл не критичен, задача важнее
        pass
    return removed


def confirm(mt: Any, device_id: int, username: str, how: str = "руками") -> bool:
    """Подтвердить изменение: снять страховку с устройства и из базы."""
    row = current(device_id)
    if row is None:
        return False

    disarm_device(mt, device_id)
    execute("UPDATE rollbacks SET state = 'confirmed', closed_at = ? WHERE id = ?",
            (utcnow(), row["id"]))
    log_audit(username, "Изменение подтверждено", str(row["device_name"]), how, "")
    return True


def rollback_now(mt: Any, device_id: int, username: str) -> bool:
    """
    Откатить немедленно, не дожидаясь срока.

    Нужно, когда человек уже видит, что стало хуже, и ждать десять минут
    бессмысленно. Устройство перезагрузится.
    """
    row = current(device_id)
    if row is None:
        return False

    try:
        mt.cmd("/system/scheduler/remove", **{
            ".id": _scheduler_id(mt) or SCHEDULER_NAME})
    except Exception:  # noqa: BLE001 — задача могла уже сработать
        pass
    try:
        mt.cmd("/system/backup/load", **{"name": BACKUP_NAME, "password": ""})
    except Exception as exc:  # noqa: BLE001
        # Команда рвёт соединение: устройство уходит в перезагрузку, и
        # ошибка здесь обычно означает как раз успех
        log.debug("Откат %s: %s", row["device_name"], exc)

    execute("UPDATE rollbacks SET state = 'rolled-back', closed_at = ? WHERE id = ?",
            (utcnow(), row["id"]))
    log_audit(username, "Откат выполнен вручную", str(row["device_name"]),
              "устройство перезагружается", "")
    return True


def _scheduler_id(mt: Any) -> str | None:
    for row in mt.cmd("/system/scheduler/print"):
        if str(row.get("name", "")) == SCHEDULER_NAME:
            return str(row[".id"])
    return None


# ------------------------------------------------------------------ чтение
def current(device_id: int) -> dict[str, Any] | None:
    """Взведённая страховка этой точки, если она есть."""
    row = query_one(
        "SELECT * FROM rollbacks WHERE device_id = ? AND state = 'armed' "
        "ORDER BY id DESC LIMIT 1", (device_id,))
    return dict(row) if row else None


def armed(scope: tuple[str, list[Any]] = ("", [])) -> list[dict[str, Any]]:
    """Все взведённые страховки: их видно на дашборде, пока они не сняты."""
    rows = query(
        "SELECT r.*, d.host FROM rollbacks r LEFT JOIN devices d ON d.id = r.device_id "
        f"WHERE r.state = 'armed'{scope[0]} ORDER BY r.expires_at",
        tuple(scope[1]),
    )
    return [dict(row) for row in rows]


def confirm_all(username: str, scope: tuple[str, list[Any]] = ("", [])) -> dict[str, int]:
    """
    Снять все взведённые страховки разом.

    Без этой кнопки возможность была ловушкой: взвести на полсотни точек
    можно одним нажатием, а снимать пришлось бы по одной карточке за
    десять минут. Так и вышло на живом парке: человек отправил безобидный
    пинг, чтобы посмотреть, как работает страховка, и весь парк
    перезагрузился, потому что подтвердить сорок девять точек вручную
    физически невозможно.

    Точки обходятся параллельно: по очереди на плохих каналах это минуты,
    а именно минут в этот момент и нет.
    """
    from concurrent.futures import ThreadPoolExecutor

    from .database import query_one
    from .sessions import pool

    items = armed(scope)
    if not items:
        return {"total": 0, "done": 0, "failed": 0}

    def one(item: dict[str, Any]) -> bool:
        device = query_one("SELECT * FROM devices WHERE id = ?", (item["device_id"],))
        if device is None:
            return False
        try:
            with pool.borrow(dict(device)) as mt:
                return confirm(mt, int(item["device_id"]), username, "подтверждено разом")
        except Exception:  # noqa: BLE001 — одна точка не должна ломать обход
            return False

    done = 0
    with ThreadPoolExecutor(max_workers=min(8, len(items)),
                            thread_name_prefix="confirm") as executor:
        for ok in executor.map(one, items):
            done += 1 if ok else 0

    log_audit(username, "Подтверждены все изменения",
              f"точек: {len(items)}", f"снято: {done}", "")
    return {"total": len(items), "done": done, "failed": len(items) - done}


def sweep() -> int:
    """
    Пометить просроченные страховки.

    Просроченная означает «роутер уже откатился сам»: задача на устройстве
    сработала, конфигурация вернулась, точка перезагрузилась. Панель об
    этом узнать не может, поэтому просто закрывает запись по времени
    и оставляет след в журнале.
    """
    rows = query(
        "SELECT * FROM rollbacks WHERE state = 'armed' AND expires_at < ?",
        (utcnow(),),
    )
    for row in rows:
        # Формулировка осторожная намеренно: панель не видит отката, она
        # знает только, что срок вышел. Утверждать «устройство откатилось»
        # значит выдавать расчёт за наблюдение
        log_audit("система", "Срок страховки вышел", str(row["device_name"]),
                  "подтверждения не было, устройство должно было откатиться само", "")
    if rows:
        execute_changes(
            "UPDATE rollbacks SET state = 'expired', closed_at = ? "
            "WHERE state = 'armed' AND expires_at < ?", (utcnow(), utcnow()))
    return len(rows)
