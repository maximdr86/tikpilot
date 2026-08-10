"""
Фоновый исполнитель массовых задач.

Устройство очереди максимально простое и не требует Redis/Celery:

  * задача и её элементы кладутся в SQLite (таблицы jobs и job_items);
  * один поток-диспетчер раз в секунду забирает задачи со статусом pending;
  * элементы задачи раскладываются по ThreadPoolExecutor (MAX_WORKERS потоков);
  * прогресс пишется в БД, интерфейс опрашивает его через HTMX.

Плюс такого подхода: задачи переживают перезагрузку страницы, видны всем
администраторам и не теряются при завершении HTTP-запроса.
"""

from __future__ import annotations

import json
import logging
import threading
import time  # noqa: F401 — используется для пауз между пачками
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from . import monitor, schedules, sessions
from .actions import get_action
from .config import settings
from .database import (
    cleanup_old_jobs,
    execute,
    execute_changes,
    execute_many,
    log_audit,
    query,
    query_one,
    save_device_info,
    save_device_update,
    utcnow,
)
from .mikrotik import DeviceError, MikroTik

log = logging.getLogger("tikpilot.worker")

# Событие «появилась новая задача» — чтобы не ждать следующего тика опроса
_wakeup = threading.Event()
_stop = threading.Event()
_threads: list[threading.Thread] = []


# --------------------------------------------------------------- API воркера
def notify() -> None:
    """Разбудить диспетчер сразу после постановки задачи."""
    _wakeup.set()


def start() -> None:
    """Запустить фоновые потоки (вызывается на старте FastAPI)."""
    if _threads:
        return
    _stop.clear()
    dispatcher = threading.Thread(target=_dispatch_loop, name="job-dispatcher", daemon=True)
    dispatcher.start()
    _threads.append(dispatcher)
    housekeeper = threading.Thread(target=_housekeeping_loop, name="housekeeper", daemon=True)
    housekeeper.start()
    _threads.append(housekeeper)
    planner = threading.Thread(target=_schedule_loop, name="backup-schedules", daemon=True)
    planner.start()
    _threads.append(planner)
    guard = threading.Thread(target=_rollback_loop, name="rollback-guard", daemon=True)
    guard.start()
    _threads.append(guard)
    log.info("Фоновый воркер запущен (потоков: %s)", settings.max_workers)


def stop() -> None:
    """Остановить фоновые потоки (вызывается при завершении приложения)."""
    _stop.set()
    _wakeup.set()
    for thread in _threads:
        thread.join(timeout=3)
    _threads.clear()


# ------------------------------------------------------------ создание задачи
def create_job(
    action_name: str,
    device_ids: list[int],
    params: dict[str, Any],
    username: str,
    scheduled_at: str | None = None,
    schedule_id: int | None = None,
) -> int:
    """
    Поставить массовую задачу в очередь.

    Возвращает id задачи; фактическое выполнение начнётся в фоне.
    """
    action = get_action(action_name)
    if not device_ids:
        raise ValueError("Не выбрано ни одного устройства")

    placeholders = ",".join("?" * len(device_ids))
    devices = query(
        f"SELECT id, name, host FROM devices WHERE id IN ({placeholders}) AND enabled = 1 "
        "ORDER BY name COLLATE NOCASE",
        device_ids,
    )
    if not devices:
        raise ValueError("Выбранные устройства не найдены или отключены")

    job_id = execute(
        "INSERT INTO jobs (action, action_label, params_json, username, status, total, "
        "scheduled_at, schedule_id, created_at) VALUES (?,?,?,?,'pending',?,?,?,?)",
        (
            action.name,
            action.label,
            json.dumps(params, ensure_ascii=False),
            username,
            len(devices),
            scheduled_at,
            schedule_id,
            utcnow(),
        ),
    )
    # Одним пакетом — при задаче на сотни устройств это заметно быстрее
    execute_many(
        "INSERT INTO job_items (job_id, device_id, device_name, device_host, status) "
        "VALUES (?,?,?,?, 'pending')",
        [(job_id, d["id"], d["name"], d["host"]) for d in devices],
    )
    notify()
    return job_id


def cancel_job(job_id: int) -> None:
    """
    Отменить задачу.

    Идущая задача только помечается: устройства, которые уже в работе,
    доводятся до конца, прерывать их на середине опаснее, чем дождаться.
    Остальные пропускаются.

    Задача, которая ещё не начиналась, закрывается сразу. Раньше она тоже
    только помечалась и оставалась в очереди до своего часа: человек жал
    «отменить», видел «отмена запрошена», а задача, поставленная на 02:00,
    так и висела в списке до двух ночи.

    Условие `status='pending'` в самом запросе не случайно: между проверкой
    и записью диспетчер успевает взять задачу в работу, и тогда закрывать
    её как неначатую уже нельзя. База решает это за нас одним действием.
    """
    execute(
        "UPDATE jobs SET cancel_flag = 1 WHERE id = ? AND status IN ('pending','running')",
        (job_id,),
    )

    closed = execute_changes(
        "UPDATE jobs SET status='cancelled', finished_at=? WHERE id=? AND status='pending'",
        (utcnow(), job_id),
    )
    if closed:
        # Устройства этой задачи так и не начинали трогать
        execute(
            "UPDATE job_items SET status='skipped', result='Задача отменена', "
            "finished_at=? WHERE job_id=? AND status='pending'",
            (utcnow(), job_id),
        )
        execute("UPDATE jobs SET done = total WHERE id = ?", (job_id,))


# ------------------------------------------------------------------- циклы
def _dispatch_loop() -> None:
    """Главный цикл: ищет задачи в очереди и выполняет их по одной."""
    while not _stop.is_set():
        try:
            # Отложенные задачи ждут своего времени: обновлять парк удобнее
            # ночью, когда точки не работают с посетителями.
            row = query_one(
                "SELECT id FROM jobs WHERE status = 'pending' "
                "AND (scheduled_at IS NULL OR scheduled_at <= datetime('now')) "
                "ORDER BY id LIMIT 1"
            )
            if row is None:
                _wakeup.wait(timeout=2.0)
                _wakeup.clear()
                continue
            _run_job(int(row["id"]))
        except Exception:  # noqa: BLE001 — диспетчер не должен умирать
            log.exception("Ошибка диспетчера задач")
            time.sleep(2)


def _housekeeping_loop() -> None:
    """Раз в час подчищаем старую историю."""
    while not _stop.is_set():
        try:
            cleanup_old_jobs()
        except Exception:  # noqa: BLE001
            log.exception("Ошибка очистки истории")
        _stop.wait(timeout=3600)


def _rollback_loop() -> None:
    """
    Раз в минуту закрываем просроченные страховки.

    Панель не может увидеть, что роутер откатился: связи с ним в этот
    момент как раз нет. Но она знает срок, а значит может честно записать
    «подтверждения не было» вместо того, чтобы вечно показывать страховку
    взведённой.
    """
    from . import rollback

    while not _stop.is_set():
        try:
            rollback.sweep()
        except Exception:  # noqa: BLE001
            log.exception("Ошибка обхода страховок")
        _stop.wait(timeout=60)


def _schedule_loop() -> None:
    """
    Раз в полминуты смотрим, не наступило ли время какого-нибудь правила.

    Отдельный поток, а не проверка внутри диспетчера: диспетчер во время
    массового обновления парка занят часами, и расписание, привязанное
    к нему, в такие сутки просто не сработало бы.
    """
    while not _stop.is_set():
        try:
            run_due_schedules()
        except Exception:  # noqa: BLE001 — расписание не должно ронять поток
            log.exception("Ошибка расписания бэкапов")
        _stop.wait(timeout=30)


def run_due_schedules(now: Any = None) -> list[int]:
    """
    Запустить все правила, чьё время пришло. Возвращает их номера.

    Время следующего запуска пересчитывается сразу, до самой работы:
    если панель перезапустят посреди снятия бэкапов, правило не пойдёт
    по второму кругу.
    """
    started = []
    for row in query("SELECT * FROM backup_schedules WHERE enabled = 1"):
        if row["next_run_at"] is None:
            # Время ещё не рассчитано (правило только что создано вручную
            # в базе или обновилась программа) — считаем и ждём следующего раза
            execute(
                "UPDATE backup_schedules SET next_run_at = ? WHERE id = ?",
                (schedules.next_run(row["at_time"], schedules.parse_days(row["days"])), row["id"]),
            )
            continue

        if not schedules.is_due(row["next_run_at"], now):
            continue

        execute(
            "UPDATE backup_schedules SET next_run_at = ?, last_run_at = ? WHERE id = ?",
            (
                schedules.next_run(row["at_time"], schedules.parse_days(row["days"])),
                utcnow(),
                row["id"],
            ),
        )
        _run_schedule(dict(row))
        started.append(int(row["id"]))
    return started


def _run_schedule(rule: dict[str, Any]) -> None:
    """Отработать одно правило: архив панели или задача бэкапа устройств."""
    from . import panelbackup

    name = rule.get("name") or f"правило {rule['id']}"

    if rule["target"] == schedules.TARGET_PANEL:
        try:
            path = panelbackup.build()
            removed = panelbackup.prune(int(rule["keep"] or 0))
            result = "архив %s, удалено старых: %d" % (path.name, removed)
        except Exception as exc:  # noqa: BLE001 — причину показываем в интерфейсе
            result = f"ошибка: {exc}"
        _schedule_result(rule["id"], result)
        log_audit("расписание", "Архив панели по расписанию", name, result)
        return

    where, params = "", []
    if rule["target"] == schedules.TARGET_GROUP and rule["group_id"]:
        where, params = " AND group_id = ?", [rule["group_id"]]

    devices = query(f"SELECT id FROM devices WHERE enabled = 1{where}", tuple(params))
    if not devices:
        _schedule_result(rule["id"], "устройств нет")
        return

    try:
        job_id = create_job(
            "backup",
            [int(d["id"]) for d in devices],
            {
                "do_binary": "1" if rule["do_binary"] else "",
                "do_export": "1" if rule["do_export"] else "",
                # Пароли в текстовый export по расписанию не кладём: такой
                # файл лежит на диске месяцами, и решение о нём должно
                # приниматься осознанно, руками
                "show_sensitive": "",
            },
            "расписание",
            schedule_id=int(rule["id"]),
        )
    except ValueError as exc:
        _schedule_result(rule["id"], f"ошибка: {exc}")
        return

    _schedule_result(rule["id"], "задача %d, устройств: %d" % (job_id, len(devices)))
    log_audit("расписание", "Бэкап по расписанию", name, f"задача {job_id}")


def prune_backups(device_ids: list[int], keep: int) -> int:
    """
    Оставить только `keep` последних бэкапов на устройство и вид.

    Считаем по видам отдельно: у бинарного бэкапа и текстового export
    разное назначение, и «последние 14 файлов» вперемешку означало бы
    семь копий каждого вида в удачном случае и ни одного export в плохом.

    Файл удаляется вместе с записью. Запись без файла хуже, чем нет
    записи вовсе: человек увидит копию в списке, понадеется на неё
    и обнаружит пустоту, когда будет поздно.
    """
    if keep <= 0 or not device_ids:
        return 0

    removed = 0
    marks = ",".join("?" * len(device_ids))
    rows = query(
        f"SELECT id, device_id, kind, filename FROM backups "
        f"WHERE device_id IN ({marks}) ORDER BY device_id, kind, id DESC",
        tuple(device_ids),
    )

    seen: dict[tuple[Any, Any], int] = {}
    for row in rows:
        key = (row["device_id"], row["kind"])
        seen[key] = seen.get(key, 0) + 1
        if seen[key] <= keep:
            continue

        path = (settings.backup_dir / row["filename"]).resolve()
        if str(path).startswith(str(settings.backup_dir.resolve())):
            path.unlink(missing_ok=True)
        execute("DELETE FROM backups WHERE id = ?", (row["id"],))
        removed += 1

    return removed


def _schedule_result(schedule_id: int, text: str) -> None:
    """Запомнить итог последнего запуска правила — он виден в интерфейсе."""
    execute("UPDATE backup_schedules SET last_result = ? WHERE id = ?", (text, schedule_id))


def _run_job(job_id: int) -> None:
    """Выполнить одну задачу целиком: разложить устройства по пулу потоков."""
    job = query_one("SELECT * FROM jobs WHERE id = ?", (job_id,))
    if job is None:
        return

    execute("UPDATE jobs SET status='running', started_at=? WHERE id=?", (utcnow(), job_id))
    log.info("Задача %s «%s»: начата, устройств %s (запустил %s)",
             job_id, job["action_label"], job["total"], job["username"])

    try:
        action = get_action(job["action"])
    except ValueError as exc:
        execute(
            "UPDATE jobs SET status='done', finished_at=? WHERE id=?",
            (utcnow(), job_id),
        )
        execute(
            "UPDATE job_items SET status='error', result=? WHERE job_id=?",
            (str(exc), job_id),
        )
        return

    params = json.loads(job["params_json"] or "{}")
    params["_job_id"] = job_id
    # Кто запустил: нужно действиям, которые сами пишут в журнал от его имени
    params["_username"] = job["username"] or ""

    items = query("SELECT * FROM job_items WHERE job_id = ? ORDER BY id", (job_id,))

    # Пачки: любое действие может объявить параметры batch_size и batch_pause.
    # Это удобно для опасных операций — обновления, перезагрузки: устройства
    # обрабатываются группами с паузой, и есть время остановиться.
    batch_size = _as_int(params.get("batch_size"), 0)
    batch_pause = _as_int(params.get("batch_pause"), 0)
    batches = (
        [items[i:i + batch_size] for i in range(0, len(items), batch_size)]
        if batch_size > 0 else [items]
    )

    for index, batch in enumerate(batches):
        workers = max(1, min(settings.max_workers, len(batch)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="tikpilot") as pool:
            list(pool.map(lambda item: _run_item(job_id, action, dict(item), params), batch))

        # Пауза перед следующей пачкой — прерывается, если задачу отменили
        is_last = index == len(batches) - 1
        if batch_pause > 0 and not is_last and not _is_cancelled(job_id):
            log.info("Задача %s: пачка %s/%s готова, пауза %s с",
                     job_id, index + 1, len(batches), batch_pause)
            for _ in range(batch_pause):
                if _stop.is_set() or _is_cancelled(job_id):
                    break
                time.sleep(1)

    cancelled = query_one("SELECT cancel_flag FROM jobs WHERE id = ?", (job_id,))
    final_status = "cancelled" if cancelled and cancelled["cancel_flag"] else "done"
    totals = query_one(
        "SELECT ok_count, fail_count FROM jobs WHERE id = ?", (job_id,)) or {}
    log.info("Задача %s «%s»: %s, успешно %s, с ошибкой %s",
             job_id, job["action_label"],
             "отменена" if final_status == "cancelled" else "завершена",
             totals["ok_count"], totals["fail_count"])
    execute(
        "UPDATE jobs SET status=?, finished_at=? WHERE id=?",
        (final_status, utcnow(), job_id),
    )

    # Чистим лишние копии сразу после снятия новых, а не по расписанию
    # отдельно: так на диске никогда не оказывается больше файлов, чем
    # человек разрешил хранить
    if job["schedule_id"]:
        rule = query_one(
            "SELECT keep FROM backup_schedules WHERE id = ?", (job["schedule_id"],))
        if rule:
            removed = prune_backups(
                [int(i["device_id"]) for i in items if i["device_id"]], int(rule["keep"] or 0))
            if removed:
                log.info("Расписание %s: удалено старых копий %d", job["schedule_id"], removed)


def _is_cancelled(job_id: int) -> bool:
    """Запрошена ли отмена задачи."""
    row = query_one("SELECT cancel_flag FROM jobs WHERE id = ?", (job_id,))
    return bool(row and row["cancel_flag"])


def _as_int(value: Any, default: int) -> int:
    """Мягкое приведение параметра задачи к целому числу."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _run_item(job_id: int, action, item: dict[str, Any], params: dict[str, Any]) -> None:
    """Обработать одно устройство в рамках задачи."""
    item_id = item["id"]

    # Проверяем флаг отмены перед началом работы
    if _is_cancelled(job_id):
        execute(
            "UPDATE job_items SET status='skipped', result='Задача отменена', finished_at=? WHERE id=?",
            (utcnow(), item_id),
        )
        _bump(job_id, ok=False, skipped=True)
        return

    device = query_one("SELECT * FROM devices WHERE id = ?", (item["device_id"],))
    if device is None:
        _finish_item(job_id, item_id, "error", "Устройство удалено из базы")
        return

    device = dict(device)
    group = query_one("SELECT name FROM groups WHERE id = ?", (device.get("group_id"),))
    device["group_name"] = group["name"] if group else ""

    execute("UPDATE job_items SET status='running', started_at=? WHERE id=?", (utcnow(), item_id))

    status_text = "ok"
    connected = False
    try:
        # Работаем в постоянной сессии из пула: если монитор уже держит
        # соединение с этим устройством, повторный вход не потребуется.
        with sessions.pool.borrow(device) as mt:
            connected = True
            # Любое успешное подключение — повод освежить кэш состояния.
            # Информацию кладём в device, чтобы действия не опрашивали её повторно.
            device["_info"] = _refresh_device_cache(device["id"], mt)
            result = action.handler(mt, device, params)
    except DeviceError as exc:
        status_text = "error"
        result = str(exc)
        # Оффлайн ставим только если не удалось подключиться;
        # ошибка самого действия не означает недоступность устройства.
        if not connected:
            _mark_offline(device["id"], result)
    except AttributeError as exc:
        # Такое бывает, только если модули программы не согласованы между собой:
        # сервер запущен из старой папки либо не перезапущен после обновления.
        log.error("Несогласованный код при работе с %s: %s", device["host"], exc)
        status_text = "error"
        result = (
            f"Программа запущена в несогласованном состоянии ({exc}). "
            "Остановите сервер и запустите заново из актуальной папки: "
            "путь показан в разделе «Настройки → О программе»."
        )
    except Exception as exc:  # noqa: BLE001 — непредвиденная ошибка не должна ронять задачу
        log.exception("Необработанная ошибка на устройстве %s", device["host"])
        status_text = "error"
        result = f"Внутренняя ошибка: {exc}"
        if not connected:
            _mark_offline(device["id"], result)

    # Перезагрузившее устройство соединение переиспользовать нельзя
    if getattr(action, "disrupts_connection", False):
        sessions.pool.drop(device["id"])

    # Действие могло узнать что-то новое об устройстве (например, доступную
    # версию RouterOS) — переносим это в базу.
    if device.get("_update"):
        _save_update_info(device["id"], device["_update"])
    if connected and device.get("_info"):
        _save_system_info(device["id"], device["_info"])

    _finish_item(job_id, item_id, status_text, result)


def _finish_item(job_id: int, item_id: int, status_text: str, result: str) -> None:
    """Записать результат по устройству и подвинуть счётчики задачи."""
    # Одна строка на устройство: ради неё живая консоль и нужна. Ошибку
    # показываем громче, чем успех, потому что искать будут именно её.
    item = query_one("SELECT device_name FROM job_items WHERE id = ?", (item_id,))
    name = item["device_name"] if item else "?"
    if status_text == "ok":
        log.info("%s: готово%s", name, f": {result}" if result else "")
    else:
        log.warning("%s: ошибка, %s", name, result or "без описания")

    execute(
        "UPDATE job_items SET status=?, result=?, finished_at=? WHERE id=?",
        (status_text, (result or "")[:8000], utcnow(), item_id),
    )
    _bump(job_id, ok=(status_text == "ok"))


def _bump(job_id: int, ok: bool, skipped: bool = False) -> None:
    """Инкрементировать счётчики прогресса задачи."""
    if skipped:
        execute("UPDATE jobs SET done = done + 1 WHERE id = ?", (job_id,))
    elif ok:
        execute("UPDATE jobs SET done = done + 1, ok_count = ok_count + 1 WHERE id = ?", (job_id,))
    else:
        execute("UPDATE jobs SET done = done + 1, fail_count = fail_count + 1 WHERE id = ?", (job_id,))


# --------------------------------------------------------- кэш состояния
def _refresh_device_cache(device_id: int, mt: MikroTik) -> dict[str, str]:
    """Обновить в БД версию/uptime/модель после успешного подключения."""
    try:
        info = mt.system_info()
    except DeviceError:
        info = {}
    _save_system_info(device_id, info)
    return info


def _save_system_info(device_id: int, info: dict[str, str]) -> None:
    """Записать сведения с устройства и отметить его доступным."""
    save_device_info(device_id, info)
    _set_status(device_id, alive=True)


def _save_update_info(device_id: int, update: dict[str, str]) -> None:
    """Записать результат проверки обновлений RouterOS."""
    save_device_update(device_id, update)


def _mark_offline(device_id: int, error: str) -> None:
    """
    Пометить устройство недоступным.

    Задача выполняет полноценное подключение, поэтому её неудача — достоверный
    признак недоступности: выдержку в несколько промахов здесь не применяем.
    """
    _set_status(device_id, alive=False, error=error, threshold=1)


def _set_status(device_id: int, alive: bool, error: str = "", threshold: int | None = None) -> None:
    """Обновить статус через общую с монитором логику (и записать событие)."""
    row = query_one(
        "SELECT id, name, host, status, fail_streak, status_changed_at "
        "FROM devices WHERE id = ?",
        (device_id,),
    )
    if row is not None:
        monitor.apply_result(dict(row), alive=alive, error=error, threshold=threshold)
