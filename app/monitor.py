"""
Фоновый мониторинг доступности устройств.

Проверки идут через **постоянные API-сессии** (см. sessions.py): вход в систему
выполняется один раз на устройство, дальше используется уже открытое
соединение. Это важно сразу по двум причинам:

* авторизация пишется в журнал RouterOS, и логин раз в минуту на полусотне
  точек вымыл бы оттуда всё остальное;
* поток коротких TCP-подключений заставляет слабые устройства ругаться
  «possible SYN flooding on tcp port 8728».

Два вида проверок:

* **Быстрая (по умолчанию раз в 60 с)** — дешёвая команда в открытой сессии.
* **Полная (раз в 15 минут)** — чтение версии, uptime, загрузки CPU и памяти
  в той же сессии.

Устройство признаётся недоступным не с первого промаха, а после нескольких
подряд (MONITOR_FAIL_THRESHOLD). На нестабильных туннелях это избавляет от
мигания статусов.

Обратно в «онлайн» — сразу с первого успешного ответа: статус обязан
отражать действительность.

Дребезг гасится в истории, а не в статусе. Пропадание короче
MONITOR_MIN_OUTAGE записывается как моргание: оно не идёт в простой и не
попадает в ленту событий, но видно в списке моргающих точек. Иначе на
плохом канале цифра простоя за сутки складывается из секундных провалов,
а история забивается сотнями строк.

Каждая смена статуса пишется в таблицу status_events: видно, когда точка
упала, сколько лежала и когда вернулась.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import settings
from .crypto import decrypt
from .database import execute, query, query_one, save_device_info, utcnow
from .mikrotik import DeviceError, MikroTik
from .sessions import pool

log = logging.getLogger("tikpilot.monitor")

# Сколько неудачных проверок подряд считать доказательством, что цель
# просто не отвечает на ICMP, а не что канал плохой
MUTE_AFTER_FAILURES = 3

_stop = threading.Event()
_thread: threading.Thread | None = None

# Сведения о работе монитора — показываются в настройках
state: dict[str, Any] = {
    "enabled": False,
    "last_cycle": None,      # время последнего цикла (UTC, строка)
    "last_full_cycle": None,
    "last_duration": 0.0,    # сколько занял последний цикл, секунд
    "checked": 0,            # сколько устройств проверено в последнем цикле
    "skipped": 0,            # пропущено (заняты задачей)
    "sessions": 0,           # открытых постоянных сессий
    "logins": 0,             # всего входов в систему с момента запуска
    "interval": settings.monitor_interval,
    "full_interval": settings.monitor_full_interval,
}


# ------------------------------------------------------------------ запуск
def start() -> None:
    """Запустить фоновый монитор (вызывается на старте приложения)."""
    global _thread

    # Флаг сбрасываем в любом случае: иначе после stop() он остаётся взведённым
    # и мешает ручным вызовам run_cycle().
    _stop.clear()

    if not settings.monitor_enabled:
        log.info("Мониторинг отключён (MONITOR_ENABLED=0)")
        return
    if _thread is not None:
        return

    state["enabled"] = True
    _thread = threading.Thread(target=_loop, name="monitor", daemon=True)
    _thread.start()
    log.info(
        "Мониторинг запущен: проба каждые %s с, полный опрос каждые %s с, "
        "порог недоступности %s промаха(ов)",
        settings.monitor_interval,
        settings.monitor_full_interval,
        settings.monitor_fail_threshold,
    )


def stop() -> None:
    """Остановить монитор и закрыть все постоянные сессии."""
    global _thread

    _stop.set()
    if _thread is not None:
        _thread.join(timeout=5)
        _thread = None
    state["enabled"] = False
    pool.close_all()


# -------------------------------------------------------------------- цикл
def _loop() -> None:
    """Главный цикл: чередует быстрые пробы и полные опросы."""
    last_full = 0.0
    # Небольшая задержка на старте — даём приложению подняться
    if _stop.wait(timeout=5):
        return

    while not _stop.is_set():
        started = time.monotonic()
        full = (started - last_full) >= settings.monitor_full_interval
        try:
            run_cycle(full=full, stop_event=_stop)
            if full:
                last_full = started
        except Exception:  # noqa: BLE001 — монитор не должен умирать
            log.exception("Ошибка цикла мониторинга")

        # Спим остаток интервала: если цикл занял много времени, следующий
        # начнётся сразу, но не чаще, чем раз в пять секунд.
        elapsed = time.monotonic() - started
        _stop.wait(timeout=max(5.0, settings.monitor_interval - elapsed))


def run_cycle(full: bool = False, stop_event: threading.Event | None = None) -> dict[str, int]:
    """
    Один проход по всем активным устройствам.

    Вынесено отдельно от цикла, чтобы можно было вызвать вручную — из тестов
    или по кнопке «проверить сейчас».

    :param full: полный опрос по API вместо быстрой пробы порта.
    :param stop_event: если задан, проход прервётся при его срабатывании.
        Передаётся только фоновым циклом: ручной вызов должен отработать
        целиком независимо от того, запущен ли монитор.
    """
    started = time.monotonic()

    devices = [dict(d) for d in query(
        "SELECT id, name, host, api_port, ftp_port, use_ssl, username, password_enc, "
        "status, fail_streak, status_changed_at FROM devices WHERE enabled = 1"
    )]

    # Устройства, которые прямо сейчас обрабатывает массовая задача, не трогаем:
    # они могут быть в перезагрузке, и промах там ожидаем.
    busy = {
        row["device_id"]
        for row in query("SELECT DISTINCT device_id FROM job_items WHERE status = 'running'")
    }
    # Занятые задачей устройства пропускаем: задача работает в той же сессии,
    # а промах во время перезагрузки был бы ложным.
    targets = [d for d in devices if d["id"] not in busy]

    if targets:
        # Разносим проверки во времени, чтобы не бить по всем точкам разом
        spacing = min(0.3, settings.monitor_interval * 0.5 / len(targets))
        workers = max(1, min(settings.monitor_workers, len(targets)))

        # Имя executor, а не pool: pool — это пул постоянных API-сессий
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="monitor") as executor:
            futures = []
            for device in targets:
                if stop_event is not None and stop_event.is_set():
                    break
                futures.append(executor.submit(_check_device, device, full))
                if spacing:
                    time.sleep(spacing)
            wait(futures)

    state["last_cycle"] = utcnow()
    state["last_duration"] = round(time.monotonic() - started, 1)
    # Строка на каждый проход: в живой консоли по ней видно, что панель
    # работает, а не молчит из-за зависшего потока
    offline = query_one(
        "SELECT COUNT(*) AS c FROM devices WHERE enabled = 1 AND status = 'offline'")
    log.info(
        "%s: устройств %d, недоступно %d, за %s с",
        "полный опрос" if full else "проверка",
        len(targets), offline["c"] if offline else 0,
        round(time.monotonic() - started, 1),
    )
    state["checked"] = len(targets)
    state["skipped"] = len(busy)
    state["sessions"] = pool.size()
    state["logins"] = pool.logins
    if full:
        state["last_full_cycle"] = state["last_cycle"]

    return {"checked": len(targets), "skipped": len(busy)}


# ------------------------------------------------------------- проверки
def _check_device(device: dict[str, Any], full: bool) -> None:
    """Проверить одно устройство и обновить его статус."""
    try:
        alive, error = _full_poll(device) if full else _quick_check(device)
        if alive is None:
            # Сессия занята массовой задачей — статус не трогаем
            return
        apply_result(device, alive, error)
    except Exception:  # noqa: BLE001 — сбой на одном устройстве не ломает цикл
        log.exception("Ошибка проверки устройства %s", device.get("host"))


def _quick_check(device: dict[str, Any]) -> tuple[bool, str]:
    """Быстрая проверка живости выбранным способом."""
    if settings.monitor_probe_method == "tcp":
        return _tcp_probe(device)
    return pool.check(device)


def _tcp_probe(device: dict[str, Any]) -> tuple[bool, str]:
    """
    Запасной способ: просто открыть и закрыть порт API.

    По умолчанию не используется. На слабых устройствах поток таких коротких
    подключений вызывает предупреждения «possible SYN flooding on tcp port 8728»,
    поэтому включать стоит только там, где держать сессию нельзя
    (MONITOR_PROBE_METHOD=tcp).
    """
    host, port = device["host"], int(device["api_port"] or 8728)
    try:
        with socket.create_connection((host, port), timeout=settings.monitor_probe_timeout):
            return True, ""
    except socket.timeout:
        return False, "Таймаут подключения"
    except ConnectionRefusedError:
        return False, "Соединение отклонено (API-сервис выключен или другой порт?)"
    except socket.gaierror:
        return False, "Не удалось разрешить имя хоста"
    except OSError as exc:
        return False, f"Хост недоступен ({exc.strerror or exc})"


def _collect_clients(device: dict[str, Any]) -> None:
    """
    Прочитать клиентов площадки в той же сессии, что и всё остальное.

    Отдельного подключения не создаётся: три команды в уже открытом
    соединении. На слабом канале это дешевле, чем кажется, а вопрос
    «куда воткнут этот кабель» возникает регулярно.
    """
    from . import clients as client_list

    try:
        with pool.borrow(device) as mt:
            rows = client_list.collect(mt)
    except DeviceError as exc:
        log.debug("Клиенты не прочитаны для %s: %s", device.get("host"), exc)
        return

    if rows:
        client_list.save(device["id"], rows)
        log.info("%s: клиентов %d", device.get("name"), len(rows))


def _collect_inventory(device: dict[str, Any]) -> None:
    """
    Прочитать паспорт точки: порты, сервисы, соседей, датчики.

    В той же сессии и только в полном опросе. Это четыре команды поверх
    уже открытого соединения, а быстрая проверка доступности должна
    оставаться быстрой: на тайговом канале лишний обмен в каждом
    минутном цикле обходится дороже, чем свежесть этих сведений стоит.
    """
    from . import inventory

    try:
        with pool.borrow(device) as mt:
            data = inventory.collect(mt)
    except DeviceError as exc:
        log.debug("Паспорт не прочитан для %s: %s", device.get("host"), exc)
        return

    if data.get("ports") or data.get("services"):
        inventory.save(device["id"], data)


def _collect_metrics(device: dict[str, Any], info: dict[str, str]) -> None:
    """Сохранить точку временного ряда: загрузка CPU и свободная память."""
    cpu = info.get("cpu_load")
    free = info.get("free_memory_bytes") or ""
    try:
        cpu_value = float(str(cpu).strip()) if str(cpu).strip() else None
    except ValueError:
        cpu_value = None
    try:
        free_value = int(str(free).strip()) if str(free).strip() else None
    except ValueError:
        free_value = None

    if cpu_value is None and free_value is None:
        return
    execute(
        "INSERT INTO device_metrics (device_id, ts, cpu_load, free_memory) VALUES (?,?,?,?)",
        (device["id"], utcnow(), cpu_value, free_value),
    )


def _latency_targets(device: dict[str, Any]) -> list[tuple[str, str]]:
    """
    Список целей пинга для устройства: пары (адрес, подпись).

    Свои цели устройства перекрывают общие. Шлюз добавляется автоматически,
    если он определён и включён соответствующий параметр.
    """
    own = [t.strip() for t in str(device.get("latency_targets") or "").split(",") if t.strip()]
    targets = [_split_target(t) for t in (own or settings.latency_targets)]

    if settings.latency_ping_gateway:
        gateway = str(device.get("gateway") or "").strip()
        if gateway and all(gateway != t for t, _ in targets):
            targets.insert(0, (gateway, "шлюз"))
    return targets


def _split_target(value: str) -> tuple[str, str]:
    """
    Разобрать запись цели «адрес=подпись».

    Подпись необязательна, но с ней таблица читается куда лучше:
    «10.0.0.1 (хаб)» понятнее, чем голый адрес.
    """
    address, _, label = str(value).partition("=")
    return address.strip(), label.strip()


def _target_is_mute(device_id: int, target: str) -> bool:
    """
    Стоит ли перестать пинговать эту цель.

    Многие провайдеры блокируют ICMP к своему шлюзу. Такая цель показывает
    ровно 100% потерь всегда — это не деградация канала, а просто молчащий
    адрес. Толку от него нет, а в таблице он забивает собой настоящие проблемы.

    Правило: если подряд идут одни неудачи и **ни разу** за всю историю ответа
    не было — пропускаем. Раз в час пробуем снова: вдруг ICMP включили.
    """
    row = query_one(
        "SELECT COUNT(*) AS total, "
        "       SUM(CASE WHEN received > 0 THEN 1 ELSE 0 END) AS answered, "
        "       MAX(ts) AS last_ts "
        "FROM latency_samples WHERE device_id = ? AND target = ?",
        (device_id, target),
    )
    if row is None or not row["total"]:
        return False
    if row["answered"]:
        return False                       # цель отвечала — продолжаем следить
    if row["total"] < MUTE_AFTER_FAILURES:
        return False                       # ещё не убедились

    # Раз в час даём цели шанс: вдруг ICMP разрешили
    last = _parse_ts(row["last_ts"])
    if last is None:
        return False
    return (datetime.now(timezone.utc) - last) < timedelta(hours=1)


def _check_latency(device: dict[str, Any], mt: MikroTik) -> None:
    """Пропинговать цели с устройства и записать результат."""
    # Шлюз узнаём один раз и запоминаем — маршрут меняется редко
    if settings.latency_ping_gateway and not str(device.get("gateway") or "").strip():
        gateway = mt.default_gateway()
        if gateway:
            device["gateway"] = gateway
            execute("UPDATE devices SET gateway = ? WHERE id = ?", (gateway, device["id"]))

    now = utcnow()
    for target, label in _latency_targets(device):
        # Молчащие цели не пингуем без конца — см. пояснение в _target_is_mute
        if _target_is_mute(device["id"], target):
            continue
        try:
            result = mt.ping(target, count=settings.latency_count)
            execute(
                "INSERT INTO latency_samples (device_id, target, label, ts, sent, received, "
                "loss, rtt_min, rtt_avg, rtt_max) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (device["id"], target, label, now, result["sent"], result["received"],
                 result["loss"], result["rtt_min"], result["rtt_avg"], result["rtt_max"]),
            )
        except DeviceError as exc:
            execute(
                "INSERT INTO latency_samples (device_id, target, label, ts, error) "
                "VALUES (?,?,?,?,?)",
                (device["id"], target, label, now, str(exc)[:300]),
            )


def _full_poll(device: dict[str, Any]) -> tuple[bool, str]:
    """Полный опрос с обновлением версии, uptime и прочего — в той же сессии."""
    if settings.monitor_probe_method == "tcp":
        # Режим без постоянных сессий: подключаемся разово
        try:
            with MikroTik(device, decrypt(device["password_enc"])) as mt:
                info = mt.system_info()
        except DeviceError as exc:
            return False, str(exc)
        save_device_info(device["id"], info)
        return True, ""

    alive, error, info = pool.poll(device)
    if alive and info:
        save_device_info(device["id"], info)
        _collect_metrics(device, info)
        if settings.clients_enabled:
            _collect_clients(device)
        if settings.inventory_enabled:
            _collect_inventory(device)
        if settings.latency_enabled:
            try:
                with pool.borrow(device) as mt:
                    _check_latency(device, mt)
            except DeviceError as exc:
                log.debug("Проверка задержки не удалась для %s: %s", device.get("host"), exc)
    return alive, error


# ------------------------------------------------------------- применение
def apply_result(device: dict[str, Any], alive: bool, error: str = "",
                 threshold: int | None = None) -> None:
    """
    Обновить статус устройства с учётом выдержки на падении.

    Падение засчитывается после нескольких промахов подряд, возврат — с
    первого же успешного ответа. Используется и монитором, и воркером задач,
    поэтому публичная.

    Выдержки на подъёме здесь намеренно нет. Она была, и оказалась вредной:
    достаточно одного промаха в канале с потерями, чтобы счётчик удачных
    проверок обнулился, и точка, доступная девять минут из десяти, висела
    «офлайн» бессрочно. Панель, которая врёт про доступность, хуже шумной
    истории.

    Дребезг гасится не здесь, а в истории: короткие пропадания записываются
    как моргание и не идут в простой (см. MONITOR_MIN_OUTAGE).

    :param threshold: сколько промахов подряд нужно для «оффлайн».
        Воркер передаёт 1: он делает полноценное подключение, и если оно не
        удалось — это уже достоверный факт, а не подозрение.
    """
    if threshold is None:
        threshold = settings.monitor_fail_threshold

    previous = device.get("status") or "unknown"
    now = utcnow()

    if alive:
        new_status, streak = "online", 0
    else:
        streak = int(device.get("fail_streak") or 0) + 1
        # До достижения порога сохраняем прежний статус — точка «под подозрением»
        new_status = "offline" if streak >= threshold else previous

    changed = new_status != previous

    if alive:
        execute(
            "UPDATE devices SET status='online', fail_streak=0, last_seen=?, last_check=?, "
            "last_error='', status_changed_at=COALESCE(?, status_changed_at), updated_at=? "
            "WHERE id=?",
            (now, now, now if changed else None, now, device["id"]),
        )
    else:
        execute(
            "UPDATE devices SET status=?, fail_streak=?, last_check=?, last_error=?, "
            "status_changed_at=COALESCE(?, status_changed_at), updated_at=? WHERE id=?",
            (new_status, streak, now, error[:500], now if changed else None, now, device["id"]),
        )

    if changed:
        _record_event(device, new_status, error)


def _record_event(device: dict[str, Any], status: str, reason: str) -> None:
    """
    Записать смену статуса в историю и в лог сервера.

    Короткое пропадание помечается как моргание: и запись о падении, и
    запись о возврате получают признак `short`. Такие пары не идут ни
    в простой, ни в ленту событий, но остаются в базе и считаются в списке
    моргающих точек.

    Так решается задача, ради которой всё затевалось: цифра простоя за сутки
    перестаёт складываться из секундных провалов, а история не забивается
    сотнями строк. При этом статус остаётся честным: точка на связи —
    значит на связи.
    """
    downtime = None
    if status == "online":
        downtime = _seconds_since(device.get("status_changed_at"))

    limit = max(0, settings.monitor_min_outage)
    short = bool(limit and status == "online" and downtime is not None and downtime < limit)

    execute(
        "INSERT INTO status_events (device_id, device_name, device_host, status, reason, "
        "downtime, short, ts) VALUES (?,?,?,?,?,?,?,?)",
        (device["id"], device["name"], device["host"], status, reason[:500],
         downtime, 1 if short else 0, utcnow()),
    )

    if short:
        # Помечаем и парное падение: поодиночке они бессмысленны, а искать
        # пару при каждом расчёте простоя дороже, чем поставить признак один раз
        execute(
            "UPDATE status_events SET short = 1 WHERE id = ("
            "  SELECT id FROM status_events WHERE device_id = ? AND status = 'offline' "
            "  ORDER BY id DESC LIMIT 1)",
            (device["id"],),
        )
        log.info("Моргание: %s (%s), %s", device["name"], device["host"],
                 _human_duration(downtime))
        return

    if status == "offline":
        log.warning("Устройство недоступно: %s (%s), причина: %s", device["name"], device["host"], reason)
    else:
        extra = f", лежало {_human_duration(downtime)}" if downtime else ""
        log.info("Устройство вернулось: %s (%s)%s", device["name"], device["host"], extra)


def _seconds_since(value: str | None) -> int | None:
    """Сколько секунд прошло с момента, записанного в БД."""
    if not value:
        return None
    try:
        moment = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None
    return max(0, int((datetime.now(timezone.utc) - moment).total_seconds()))


def _human_duration(seconds: int | None) -> str:
    """Секунды → «5 мин», «2 ч 13 мин», «3 дн 4 ч»."""
    if not seconds:
        return "—"
    minutes, sec = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    if days:
        return f"{days} дн {hours} ч"
    if hours:
        return f"{hours} ч {minutes} мин"
    if minutes:
        return f"{minutes} мин"
    return f"{sec} с"


#: Область видимости пользователя: кусок SQL и его параметры.
#: Пустая пара означает «виден весь парк» — так работают фоновые вызовы.
Scope = tuple[str, list[Any]]
NO_SCOPE: Scope = ("", [])

def recent_events(limit: int = 20, scope: Scope = NO_SCOPE) -> list[Any]:
    """Последние смены статуса — для дашборда."""
    where, params = scope
    if where:
        # События хранят device_id, поэтому фильтруем подзапросом по устройствам
        return query(
            "SELECT * FROM status_events WHERE short = 0 AND device_id IN "
            f"(SELECT d.id FROM devices d WHERE 1=1{where}) "
            "ORDER BY id DESC LIMIT ?",
            (*params, limit),
        )
    return query(
        "SELECT * FROM status_events WHERE short = 0 ORDER BY id DESC LIMIT ?", (limit,))


def device_events(device_id: int, limit: int = 20) -> list[Any]:
    """История доступности одного устройства."""
    return query(
        "SELECT * FROM status_events WHERE device_id = ? ORDER BY id DESC LIMIT ?",
        (device_id, limit),
    )


def availability(hours: int = 24, scope: Scope = NO_SCOPE) -> list[dict[str, Any]]:
    """
    Доступность каждого устройства за последние `hours` часов.

    Считается по журналу событий: складываем все промежутки, когда устройство
    было недоступно, и делим на длину окна.

    Тонкости, которые приходится учитывать:

    * событие «поднялось» несёт длительность простоя (downtime), но простой
      мог начаться ещё до начала окна — тогда обрезаем его по границе;
    * если точка лежит прямо сейчас, незакрытый простой считаем до текущего
      момента;
    * если событий не было вовсе, точка всё окно провела в текущем статусе.
    """
    window = max(1, hours) * 3600
    now = datetime.now(timezone.utc)
    since = now - timedelta(seconds=window)
    since_text = since.strftime("%Y-%m-%d %H:%M:%S")

    devices = query(
        "SELECT d.id, d.name, d.host, d.status, d.status_changed_at, "
        "g.name AS group_name, g.color AS group_color "
        "FROM devices d LEFT JOIN groups g ON g.id = d.group_id "
        f"WHERE d.enabled = 1{scope[0]} ORDER BY d.name COLLATE NOCASE",
        tuple(scope[1]),
    )
    # Моргания в расчёт не берём: они для того и помечены, чтобы цифра
    # простоя не складывалась из секундных провалов
    events = query(
        "SELECT device_id, status, downtime, ts FROM status_events "
        "WHERE ts >= ? AND short = 0 ORDER BY id",
        (since_text,),
    )
    flaps = {
        row["device_id"]: row["c"]
        for row in query(
            "SELECT device_id, COUNT(*) AS c FROM status_events "
            "WHERE ts >= ? AND short = 1 AND status = 'online' GROUP BY device_id",
            (since_text,),
        )
    }

    by_device: dict[int, list[Any]] = {}
    for event in events:
        by_device.setdefault(event["device_id"], []).append(event)

    result: list[dict[str, Any]] = []
    for device in devices:
        rows = by_device.get(device["id"], [])
        down_seconds = 0
        outages = 0

        for event in rows:
            if event["status"] != "online":
                outages += 1
                continue
            # Подъём: прибавляем простой, обрезав его по границе окна
            downtime = int(event["downtime"] or 0)
            moment = _parse_ts(event["ts"])
            if moment is not None:
                started = moment - timedelta(seconds=downtime)
                if started < since:
                    downtime = max(0, int((moment - since).total_seconds()))
            down_seconds += downtime

        # Незакрытый простой: точка лежит прямо сейчас
        if device["status"] == "offline":
            changed = _parse_ts(device["status_changed_at"]) or since
            down_seconds += max(0, int((now - max(changed, since)).total_seconds()))
            if not rows:
                outages = 1

        down_seconds = min(down_seconds, window)
        percent = round(100.0 * (window - down_seconds) / window, 2)

        result.append({
            "id": device["id"],
            "name": device["name"],
            "host": device["host"],
            "status": device["status"],
            "group_name": device["group_name"],
            "group_color": device["group_color"],
            "uptime_percent": percent,
            "down_seconds": down_seconds,
            "outages": outages,
            "flaps": flaps.get(device["id"], 0),
        })

    return result


def outage_intervals(hours: int = 24, scope: Scope = NO_SCOPE) -> list[dict[str, Any]]:
    """
    Промежутки недоступности за окно, по одному на каждое падение.

    `availability()` отвечает на вопрос «сколько всего», а отчёту нужно
    «когда именно»: с провайдером разговаривают датами, а не суммами.
    Источник тот же самый журнал, поэтому суммы сходятся.

    Начало простоя нигде не хранится: событие «поднялось» несёт его
    длительность, и начало получается вычитанием. Простой, начавшийся
    до окна, обрезается по его границе и помечается `trimmed`, иначе
    в отчёте за сутки появилась бы дата недельной давности.

    Моргания (`short = 1`) не берём: они и помечены для того, чтобы не
    попадать в отчёты.
    """
    window = max(1, hours) * 3600
    now = datetime.now(timezone.utc)
    since = now - timedelta(seconds=window)
    since_text = since.strftime("%Y-%m-%d %H:%M:%S")

    devices = {
        row["id"]: row
        for row in query(
            "SELECT d.id, d.name, d.host, d.status, d.status_changed_at, "
            "g.name AS group_name FROM devices d LEFT JOIN groups g ON g.id = d.group_id "
            f"WHERE d.enabled = 1{scope[0]}",
            tuple(scope[1]),
        )
    }
    events = query(
        "SELECT device_id, status, downtime, ts FROM status_events "
        "WHERE ts >= ? AND short = 0 AND status = 'online' ORDER BY id",
        (since_text,),
    )

    result: list[dict[str, Any]] = []

    def add(device: Any, start: datetime, end: datetime, ongoing: bool, trimmed: bool) -> None:
        seconds = int((end - start).total_seconds())
        if seconds <= 0:
            return
        result.append({
            "device_id": device["id"],
            "name": device["name"],
            "host": device["host"],
            "group_name": device["group_name"],
            "start": start,
            "end": end,
            "seconds": seconds,
            "ongoing": ongoing,
            "trimmed": trimmed,
        })

    for event in events:
        device = devices.get(event["device_id"])
        downtime = int(event["downtime"] or 0)
        moment = _parse_ts(event["ts"])
        if device is None or moment is None or downtime <= 0:
            continue
        started = moment - timedelta(seconds=downtime)
        add(device, max(started, since), moment, False, started < since)

    for device in devices.values():
        if device["status"] != "offline":
            continue
        changed = _parse_ts(device["status_changed_at"]) or since
        add(device, max(changed, since), now, True, changed < since)

    result.sort(key=lambda row: row["start"], reverse=True)
    return result


def availability_buckets(hours: int = 24,
                         scope: Scope = NO_SCOPE) -> list[dict[str, Any]]:
    """
    Доступность всего парка по отрезкам окна: сутки по часам, остальное по дням.

    Считается как доля «устройство-секунд» в сети от всех возможных. Одна
    точка, лежавшая весь день, при парке в пятьдесят штук даёт 98 процентов
    за день, и это честно: столбик показывает масштаб, а не число точек.

    Границы отрезков берутся по местному времени, а не по UTC: отчёт читает
    человек, и «пятое августа» для него начинается в его полночь.
    """
    window = max(1, hours) * 3600
    now = datetime.now(timezone.utc)
    since = now - timedelta(seconds=window)

    total = query_one(
        f"SELECT COUNT(*) AS c FROM devices d WHERE d.enabled = 1{scope[0]}",
        tuple(scope[1]),
    )
    devices = int(total["c"]) if total else 0
    if not devices:
        return []

    step = 3600 if hours <= 24 else 86400
    local_now = now.astimezone()
    if step == 86400:
        edge = local_now.replace(hour=0, minute=0, second=0, microsecond=0)
    else:
        edge = local_now.replace(minute=0, second=0, microsecond=0)

    edges: list[datetime] = []
    while edge > since:
        edges.append(edge)
        edge = edge - timedelta(seconds=step)
    edges.append(edge)
    edges.reverse()

    intervals = outage_intervals(hours, scope)
    buckets: list[dict[str, Any]] = []

    for index, start in enumerate(edges):
        end = edges[index + 1] if index + 1 < len(edges) else local_now
        start = max(start, since.astimezone())
        if end <= start:
            continue
        seconds = (end - start).total_seconds()
        down = 0.0
        for row in intervals:
            overlap = (min(row["end"], end) - max(row["start"], start)).total_seconds()
            if overlap > 0:
                down += overlap
        capacity = seconds * devices
        percent = round(100.0 * max(0.0, capacity - down) / capacity, 3) if capacity else 100.0
        buckets.append({
            "start": start,
            "end": end,
            "label": start.strftime("%H:%M" if step == 3600 else "%d.%m"),
            "percent": percent,
            "down_seconds": int(down),
        })

    return buckets


def _parse_ts(value: Any) -> datetime | None:
    """Строка времени из БД → datetime с зоной UTC."""
    if not value:
        return None
    try:
        return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def summary(scope: Scope = NO_SCOPE) -> dict[str, Any]:
    """Сводка по парку для страницы мониторинга."""
    row = query_one(
        "SELECT COUNT(*) AS total, "
        "SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END) AS online, "
        "SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) AS offline, "
        "SUM(CASE WHEN status='unknown' THEN 1 ELSE 0 END) AS unknown, "
        "SUM(CASE WHEN fail_streak > 0 AND status='online' THEN 1 ELSE 0 END) AS shaky "
        f"FROM devices d WHERE enabled = 1{scope[0]}",
        tuple(scope[1]),
    )
    data = dict(row) if row else {}
    events_24h = query_one(
        "SELECT COUNT(*) AS c FROM status_events WHERE ts > datetime('now', '-24 hours')"
        + (" AND device_id IN (SELECT d.id FROM devices d WHERE 1=1%s)" % scope[0] if scope[0] else ""),
        tuple(scope[1]),
    )
    data["events_24h"] = events_24h["c"] if events_24h else 0
    return data


def status_map(scope: Scope = NO_SCOPE) -> list[dict[str, Any]]:
    """
    Все устройства, сгруппированные по группам — для «карты» статусов.

    Порядок внутри группы: сначала проблемные, чтобы они не терялись.
    """
    devices = query(
        "SELECT d.id, d.name, d.host, d.status, d.fail_streak, d.status_changed_at, "
        "d.ros_version, d.last_error, g.name AS group_name, g.color AS group_color "
        "FROM devices d LEFT JOIN groups g ON g.id = d.group_id "
        f"WHERE d.enabled = 1{scope[0]}",
        tuple(scope[1]),
    )
    order = {"offline": 0, "unknown": 1, "online": 2}
    groups: dict[str, dict[str, Any]] = {}
    for device in devices:
        key = device["group_name"] or "Без группы"
        group = groups.setdefault(key, {
            "name": key,
            "color": device["group_color"] or "slate",
            "devices": [],
            "online": 0,
            "offline": 0,
        })
        group["devices"].append(dict(device))
        if device["status"] == "online":
            group["online"] += 1
        elif device["status"] == "offline":
            group["offline"] += 1

    for group in groups.values():
        group["devices"].sort(
            key=lambda d: (order.get(d["status"], 3), (d["name"] or "").lower())
        )

    # Группы с проблемами — наверх
    return sorted(groups.values(), key=lambda g: (-g["offline"], g["name"].lower()))


def latency_history(device_id: int, hours: int = 24) -> dict[str, list[Any]]:
    """
    Замеры задержки по каждой цели за период — для графиков.

    Цели, убранные из настроек, не показываем: иначе после смены списка
    на графике ещё сутки болтались бы старые линии.
    """
    device = query_one("SELECT id, latency_targets, gateway FROM devices WHERE id = ?", (device_id,))
    active = {t for t, _ in _latency_targets(dict(device))} if device else set()

    rows = query(
        "SELECT target, label, ts, loss, rtt_avg FROM latency_samples "
        "WHERE device_id = ? AND ts > datetime('now', ?) ORDER BY ts",
        (device_id, f"-{max(1, hours)} hours"),
    )
    by_target: dict[str, list[Any]] = {}
    for row in rows:
        if row["target"] not in active:
            continue
        key = f"{row['target']}" + (f" ({row['label']})" if row["label"] else "")
        by_target.setdefault(key, []).append(row)
    return by_target


def metrics_history(device_id: int, hours: int = 24) -> list[Any]:
    """Временной ряд загрузки CPU и свободной памяти."""
    return query(
        "SELECT ts, cpu_load, free_memory FROM device_metrics "
        "WHERE device_id = ? AND ts > datetime('now', ?) ORDER BY ts",
        (device_id, f"-{max(1, hours)} hours"),
    )


def latency_summary(hours: int = 24, scope: Scope = NO_SCOPE) -> dict[str, list[Any]]:
    """
    Сводка по задержке для страницы мониторинга.

    Результат разделён на две части, и это важно:

    * ``problems`` — цели, которые отвечают, но с потерями или высокой
      задержкой. Здесь настоящая деградация канала.
    * ``mute`` — цели, которые не ответили **ни разу**. Это не проблема сети,
      а просто адрес, не отвечающий на ICMP (обычное дело для шлюзов
      провайдеров). Смешивать их с первыми нельзя: сплошные 100% потерь
      заслоняют собой реальные неполадки.
    """
    rows = query(
        "SELECT s.device_id, d.name AS device_name, d.host, s.target, s.label, "
        "       COUNT(*) AS samples, "
        "       SUM(CASE WHEN s.received > 0 THEN 1 ELSE 0 END) AS answered, "
        "       ROUND(AVG(s.rtt_avg), 1) AS rtt, "
        "       ROUND(MAX(s.rtt_avg), 1) AS rtt_max, "
        "       ROUND(AVG(s.loss), 1) AS loss "
        "FROM latency_samples s JOIN devices d ON d.id = s.device_id "
        f"WHERE s.ts > datetime('now', ?) AND s.error = ''{scope[0]} "
        "GROUP BY s.device_id, s.target",
        (f"-{max(1, hours)} hours", *scope[1]),
    )

    # Замеры по целям, которых в настройках больше нет, показывать незачем.
    # Иначе после смены LATENCY_TARGETS или отключения пинга шлюзов старые
    # записи висели бы в таблице до конца периода — выглядит так, будто
    # настройка не сработала.
    active = _configured_targets()
    result: list[dict[str, Any]] = []
    for row in rows:
        key = (row["device_id"], row["target"])
        if key not in active:
            continue
        item = dict(row)
        item["label"] = active[key]      # подпись из настроек, а не из старых замеров
        result.append(item)

    problems = [r for r in result if r["answered"]]
    mute = [r for r in result if not r["answered"]]

    # Показываем все точки, а не «худшие N»: таблица сортируется кликом,
    # и отрезать половину парка без предупреждения — только путать.
    problems.sort(key=lambda r: (-(r["loss"] or 0), -(r["rtt"] or 0)))
    mute.sort(key=lambda r: (r["device_name"] or "").lower())
    return {"problems": problems, "mute": mute}


def _configured_targets() -> dict[tuple[int, str], str]:
    """
    Цели, которые опрашиваются согласно текущим настройкам: (устройство, адрес) → подпись.

    Нужны, чтобы отсеять из отчётов замеры по целям, которые уже убрали
    из конфигурации, и показать актуальную подпись. Подпись берём отсюда,
    а не из самих замеров: старые записи могли быть сделаны, когда подписи
    ещё не было, и один и тот же адрес выглядел бы в таблице по-разному.
    """
    result: dict[tuple[int, str], str] = {}
    for device in query(
        "SELECT id, latency_targets, gateway FROM devices WHERE enabled = 1"
    ):
        for target, label in _latency_targets(dict(device)):
            result[(device["id"], target)] = label
    return result


def device_timeline(device_id: int, limit: int = 60) -> list[dict[str, Any]]:
    """
    Единая хронология по устройству.

    Смены статуса, выполненные операции и снятые бэкапы в одной ленте:
    так сразу видно, например, что падения начались после обновления.
    """
    entries: list[dict[str, Any]] = []

    for row in query(
        "SELECT status, reason, downtime, ts FROM status_events WHERE device_id = ? "
        "ORDER BY id DESC LIMIT ?", (device_id, limit)
    ):
        entries.append({
            "ts": row["ts"],
            "kind": "status",
            "status": row["status"],
            "title": "Устройство поднялось" if row["status"] == "online" else "Устройство недоступно",
            "details": row["reason"] or "",
            "downtime": row["downtime"],
        })

    for row in query(
        "SELECT ji.status, ji.result, ji.finished_at, j.action_label, j.username "
        "FROM job_items ji JOIN jobs j ON j.id = ji.job_id "
        "WHERE ji.device_id = ? AND ji.finished_at IS NOT NULL "
        "ORDER BY ji.id DESC LIMIT ?", (device_id, limit)
    ):
        entries.append({
            "ts": row["finished_at"],
            "kind": "job",
            "status": row["status"],
            "title": row["action_label"],
            "details": row["result"] or "",
            "who": row["username"],
        })

    for row in query(
        "SELECT kind, filename, size, created_at FROM backups WHERE device_id = ? "
        "ORDER BY id DESC LIMIT ?", (device_id, limit)
    ):
        entries.append({
            "ts": row["created_at"],
            "kind": "backup",
            "status": "ok",
            "title": "Снят бэкап" + (" (бинарный)" if row["kind"] == "binary" else " (export)"),
            "details": str(row["filename"]).split("/")[-1],
        })

    entries.sort(key=lambda e: str(e["ts"] or ""), reverse=True)
    return entries[:limit]


def flapping_devices(hours: int = 24, min_events: int = 4,
                     scope: Scope = NO_SCOPE) -> list[Any]:
    """
    Точки, которые чаще других меняли статус за последние сутки.

    Помогает отличить «канал моргает» от «оборудование умерло».
    """
    return query(
        "SELECT device_id, device_name, device_host, COUNT(*) AS events, "
        "SUM(short) AS flaps "
        "FROM status_events WHERE ts > datetime('now', ?) "
        + (f"AND device_id IN (SELECT d.id FROM devices d WHERE 1=1{scope[0]}) " if scope[0] else "")
        + "GROUP BY device_id HAVING events >= ? ORDER BY events DESC LIMIT 10",
        (f"-{hours} hours", *scope[1], min_events),
    )
