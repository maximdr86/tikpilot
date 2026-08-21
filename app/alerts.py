"""
Пороги: правила вида «если стало плохо дольше стольких минут».

Зачем
-----

Панель и так показывает всё, но смотреть на неё круглосуточно некому.
Пороги переворачивают задачу: не человек ищет проблему в таблицах,
а панель отмечает то, что вышло за оговорённые рамки.

Заметить полезно не только падение. Забитый диск это причина, по которой
не встаёт обновление, и узнать о ней в момент обновления поздно. Точка,
которая неделю живёт на девяноста процентах CPU, до аварии ещё не дошла,
но дойдёт.

Как устроено
------------

Правило это метрика, сравнение, значение и **время удержания**. Последнее
здесь главное. Мгновенный всплеск загрузки при ночном бэкапе не событие,
а вот полчаса на том же уровне уже событие. Пока условие держится меньше
оговорённого, правило молчит.

У каждого правила есть область: весь парк, группа или одна точка. Так
можно требовать от кассового сервера одного, а от роутера в столовой
другого, не заводя полсотни одинаковых правил.

Состояние живёт в `alert_state`, по строке на пару «правило и точка»:
когда условие стало верным, сработало ли уже и какое значение было. Из
смены состояния рождается запись в `alert_events` - это и лента на
странице, и то, что потом уходит в уведомления.

Чего тут нет
------------

Здесь ничего не отправляют. Правила только считают и записывают событие,
а доставкой занимается отдельный слой. Разделение не ради красоты:
пороги должны работать и у того, кто вообще не хочет уведомлений,
а хочет открыть страницу и увидеть список.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, NamedTuple

from .config import settings
from .database import execute, execute_changes, query, query_one, utcnow

log = logging.getLogger("tikpilot.alerts")


class Metric(NamedTuple):
    """Что умеем мерить и как это читать."""

    key: str
    label: str
    unit: str
    #: Куда смотрит правило по смыслу: «выше порога плохо» или «ниже».
    #: Это только подсказка в форме, сравнение всё равно задаёт человек.
    natural: str
    #: Значение для устройства. None означает «сейчас сказать нечего»:
    #: точка молчит, замеров не было, датчика на плате нет. Такое
    #: состояние не считается ни срабатыванием, ни выздоровлением.
    read: Callable[[dict[str, Any]], float | None]


def _float(value: Any) -> float | None:
    try:
        text = str(value).strip().replace(",", ".")
        return float(text) if text else None
    except (TypeError, ValueError):
        return None


def _offline_minutes(device: dict[str, Any]) -> float | None:
    """Сколько минут точка не отвечает. Для доступной это ноль."""
    if str(device.get("status") or "") != "offline":
        return 0.0
    since = _parse(device.get("status_changed_at"))
    if since is None:
        return None
    return max(0.0, (datetime.now(timezone.utc) - since).total_seconds() / 60)


def _latest_metric(device_id: int, column: str) -> float | None:
    row = query_one(
        f"SELECT {column} AS v FROM device_metrics WHERE device_id = ?"
        " ORDER BY ts DESC LIMIT 1",
        (device_id,),
    )
    return _float(row["v"]) if row else None


def _latest_latency(device_id: int, column: str) -> float | None:
    """
    Задержка и потери по последнему замеру, худшая из целей.

    Худшая, а не средняя: если до хаба всё хорошо, а до шлюза провайдера
    двадцать процентов потерь, важно второе.
    """
    row = query_one(
        f"SELECT MAX({column}) AS v FROM latency_samples WHERE device_id = ?"
        " AND ts >= datetime('now', '-2 hours')",
        (device_id,),
    )
    return _float(row["v"]) if row else None


def _latest_traffic(device_id: int, column: str) -> float | None:
    """Скорость по последнему замеру, мегабиты в секунду, худший интерфейс."""
    row = query_one(
        f"SELECT MAX({column}) AS v FROM traffic_samples WHERE device_id = ?"
        " AND ts >= datetime('now', '-2 hours')",
        (device_id,),
    )
    value = _float(row["v"]) if row else None
    return value / 1_000_000 if value is not None else None


def _backup_age_hours(device: dict[str, Any]) -> float | None:
    """
    Сколько часов прошло с последнего успешного бэкапа.

    Точка, у которой бэкапов не было никогда, возвращает None, а не
    бесконечность: правило «бэкап старше суток» о ней ничего не знает,
    а вот пустой список бэкапов виден и без порогов.
    """
    row = query_one(
        "SELECT MAX(created_at) AS ts FROM backups WHERE device_id = ?",
        (device["id"],),
    )
    when = _parse(row["ts"]) if row else None
    if when is None:
        return None
    return (datetime.now(timezone.utc) - when).total_seconds() / 3600


METRICS: tuple[Metric, ...] = (
    Metric("offline", "Точка не отвечает", "мин", "above", _offline_minutes),
    Metric("cpu", "Загрузка CPU", "%", "above",
           lambda d: _latest_metric(int(d["id"]), "cpu_load")),
    Metric("free_memory", "Свободная память", "МиБ", "below",
           lambda d: (lambda v: v / 1048576 if v is not None else None)(
               _latest_metric(int(d["id"]), "free_memory"))),
    Metric("temperature", "Температура", "°C", "above",
           lambda d: _float(d.get("temperature"))),
    Metric("loss", "Потери пакетов", "%", "above",
           lambda d: _latest_latency(int(d["id"]), "loss")),
    Metric("rtt", "Задержка", "мс", "above",
           lambda d: _latest_latency(int(d["id"]), "rtt_avg")),
    Metric("rx", "Приём на интерфейсе", "Мбит/с", "above",
           lambda d: _latest_traffic(int(d["id"]), "rx_bps")),
    Metric("tx", "Передача на интерфейсе", "Мбит/с", "above",
           lambda d: _latest_traffic(int(d["id"]), "tx_bps")),
    Metric("backup_age", "Возраст последнего бэкапа", "ч", "above", _backup_age_hours),
)

BY_KEY = {m.key: m for m in METRICS}

#: Место на диске самой панели. В список правил не входит намеренно:
#: это не свойство точки, и правило «весь парк» размножило бы одно
#: событие на полсотни одинаковых. Проверка своя, ниже, а здесь запись
#: нужна только чтобы событие красиво называлось и считалось в процентах.
PANEL_DISK = Metric("panel_disk", "Свободно на диске панели", "%", "below",
                    lambda device: None)
BY_KEY[PANEL_DISK.key] = PANEL_DISK


def _parse(value: Any) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value)).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


# -------------------------------------------------------------------- правила
def rules(only_enabled: bool = False) -> list[dict[str, Any]]:
    """Все правила, свежие сверху."""
    sql = "SELECT * FROM alert_rules"
    if only_enabled:
        sql += " WHERE enabled = 1"
    sql += " ORDER BY id"
    return [dict(row) for row in query(sql)]


def save_rule(data: dict[str, Any], username: str = "") -> int:
    """
    Создать или изменить правило. Возвращает его номер.

    Проверка значений живёт здесь, а не в форме: правило можно завести
    и не из браузера, а негодный порог хуже отсутствующего.
    """
    metric = str(data.get("metric") or "")
    # Именно METRICS, а не BY_KEY: в последнем есть ещё диск самой панели,
    # и правило по нему завести нельзя - он не свойство точки
    if metric not in {item.key for item in METRICS}:
        raise ValueError("Неизвестная метрика")

    comparison = "below" if str(data.get("comparison")) == "below" else "above"
    value = _float(data.get("value"))
    if value is None:
        raise ValueError("Нужно пороговое значение")

    hold = max(0, min(1440, int(_float(data.get("hold_minutes")) or 0)))
    scope_kind = str(data.get("scope_kind") or "all")
    if scope_kind not in ("all", "group", "device"):
        scope_kind = "all"
    scope_id = int(_float(data.get("scope_id")) or 0) if scope_kind != "all" else 0

    name = str(data.get("name") or "").strip() or _default_name(metric, comparison, value)
    enabled = 0 if str(data.get("enabled") or "1") in ("0", "false", "no") else 1
    rule_id = int(_float(data.get("id")) or 0)
    now = utcnow()

    if rule_id:
        execute_changes(
            "UPDATE alert_rules SET name = ?, metric = ?, comparison = ?, value = ?,"
            " hold_minutes = ?, scope_kind = ?, scope_id = ?, enabled = ?, updated_at = ?"
            " WHERE id = ?",
            (name, metric, comparison, value, hold, scope_kind, scope_id, enabled,
             now, rule_id),
        )
        # Условие изменилось, прежнее состояние о нём ничего не говорит
        execute_changes("DELETE FROM alert_state WHERE rule_id = ?", (rule_id,))
        return rule_id

    execute(
        "INSERT INTO alert_rules (name, metric, comparison, value, hold_minutes,"
        " scope_kind, scope_id, enabled, created_at, updated_at, created_by)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        (name, metric, comparison, value, hold, scope_kind, scope_id, enabled,
         now, now, username),
    )
    row = query_one("SELECT id FROM alert_rules ORDER BY id DESC LIMIT 1")
    return int(row["id"]) if row else 0


def _default_name(metric: str, comparison: str, value: float) -> str:
    """Имя по умолчанию: «Загрузка CPU выше 80 %»."""
    m = BY_KEY[metric]
    sign = "выше" if comparison == "above" else "ниже"
    number = f"{value:g}"
    return f"{m.label} {sign} {number} {m.unit}".strip()


def delete_rule(rule_id: int) -> None:
    """Убрать правило вместе с его состоянием. События остаются в ленте."""
    execute_changes("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
    execute_changes("DELETE FROM alert_state WHERE rule_id = ?", (rule_id,))


def toggle_rule(rule_id: int, on: bool) -> None:
    """Включить или выключить правило, не удаляя его."""
    execute_changes("UPDATE alert_rules SET enabled = ? WHERE id = ?",
                    (1 if on else 0, rule_id))
    if not on:
        execute_changes("DELETE FROM alert_state WHERE rule_id = ?", (rule_id,))


# ------------------------------------------------------------------ вычисление
def devices_for(rule: dict[str, Any]) -> list[dict[str, Any]]:
    """Точки, к которым применимо правило. Выключенные не считаются."""
    sql = "SELECT * FROM devices WHERE enabled = 1"
    params: list[Any] = []
    if rule["scope_kind"] == "group":
        sql += " AND group_id = ?"
        params.append(rule["scope_id"])
    elif rule["scope_kind"] == "device":
        sql += " AND id = ?"
        params.append(rule["scope_id"])
    return [dict(row) for row in query(sql, params)]


def breached(rule: dict[str, Any], value: float | None) -> bool:
    """Вышло ли значение за порог. None это не нарушение и не норма."""
    if value is None:
        return False
    if rule["comparison"] == "below":
        return value < float(rule["value"])
    return value > float(rule["value"])


def evaluate() -> dict[str, int]:
    """
    Пройти по всем включённым правилам и обновить состояние.

    Возвращает счётчики сработавших и погасших: их видно в журнале, и по
    ним же удобно проверять, что вычисление вообще идёт.
    """
    fired = resolved = 0
    now = utcnow()

    for rule in rules(only_enabled=True):
        metric = BY_KEY.get(str(rule["metric"]))
        if metric is None:
            continue

        for device in devices_for(rule):
            try:
                value = metric.read(device)
            except Exception as exc:  # noqa: BLE001 - одна метрика не роняет остальные
                log.debug("Метрика %s не прочиталась для %s: %s",
                          metric.key, device.get("name"), exc)
                continue

            state = query_one(
                "SELECT * FROM alert_state WHERE rule_id = ? AND device_id = ?",
                (rule["id"], device["id"]),
            )
            over = breached(rule, value)

            if not over:
                if state and state["firing"]:
                    _event(rule, device, "resolved", value, now, state)
                    resolved += 1
                if state:
                    execute_changes(
                        "DELETE FROM alert_state WHERE rule_id = ? AND device_id = ?",
                        (rule["id"], device["id"]),
                    )
                continue

            if state is None:
                execute(
                    "INSERT INTO alert_state (rule_id, device_id, since, firing,"
                    " last_value, updated_at) VALUES (?,?,?,?,?,?)",
                    (rule["id"], device["id"], now, 0, value, now),
                )
                state = query_one(
                    "SELECT * FROM alert_state WHERE rule_id = ? AND device_id = ?",
                    (rule["id"], device["id"]),
                )

            execute_changes(
                "UPDATE alert_state SET last_value = ?, updated_at = ?"
                " WHERE rule_id = ? AND device_id = ?",
                (value, now, rule["id"], device["id"]),
            )

            if state["firing"]:
                continue

            since = _parse(state["since"]) or datetime.now(timezone.utc)
            held = (datetime.now(timezone.utc) - since).total_seconds() / 60
            if held + 0.001 >= float(rule["hold_minutes"] or 0):
                execute_changes(
                    "UPDATE alert_state SET firing = 1, fired_at = ?"
                    " WHERE rule_id = ? AND device_id = ?",
                    (now, rule["id"], device["id"]),
                )
                _event(rule, device, "fired", value, now, state)
                fired += 1

    if fired or resolved:
        log.info("Пороги: сработало %d, погасло %d", fired, resolved)
    return {"fired": fired, "resolved": resolved}


def check_panel_disk() -> str:
    """
    Посмотреть, не кончается ли место на диске панели.

    Возвращает, что случилось: «fired», «resolved» или пусто.

    Почему отдельно от правил. Пороги описывают точки, а это про сам
    сервер: правило с областью «весь парк» породило бы полсотни
    одинаковых событий об одном и том же диске. Событие поэтому пишется
    без устройства, а дальше живёт как все: попадает в ленту, уходит
    в сводку, слушается тихих часов и паузы.

    Ради чего всё: кончившееся место останавливает панель целиком.
    SQLite перестаёт писать, приём журнала встаёт, отметки об отправке
    не сохраняются. Место при этом кончается неделями, и предупредить
    о нём можно заранее.
    """
    from . import disk

    if settings.disk_min_free_percent <= 0:
        return ""

    space = disk.free_space()
    if not space["total"]:
        return ""

    percent = round(space["free"] * 100 / space["total"], 1)
    low = percent < settings.disk_min_free_percent

    row = query_one(
        "SELECT kind FROM alert_events WHERE metric = ? ORDER BY id DESC LIMIT 1",
        (PANEL_DISK.key,))
    was_firing = bool(row and str(row["kind"]) == "fired")
    if low == was_firing:
        return ""

    now = utcnow()
    execute(
        "INSERT INTO alert_events (rule_id, rule_name, device_id, device_name,"
        " metric, kind, value, ts, started_at, sent) VALUES (?,?,?,?,?,?,?,?,?,0)",
        (None, "Место на диске", None, "Панель", PANEL_DISK.key,
         "fired" if low else "resolved", percent, now, now),
    )
    if low:
        log.warning("Мало места на диске панели: свободно %.1f%%", percent)
    else:
        log.info("Место на диске панели вернулось в норму: свободно %.1f%%", percent)
    return "fired" if low else "resolved"


def _event(rule: dict[str, Any], device: dict[str, Any], kind: str,
           value: float | None, now: str, state: Any = None) -> None:
    """Записать смену состояния. Отсюда потом берутся уведомления."""
    execute(
        "INSERT INTO alert_events (rule_id, rule_name, device_id, device_name,"
        " metric, kind, value, ts, started_at, sent) VALUES (?,?,?,?,?,?,?,?,?,0)",
        (rule["id"], rule["name"], device["id"], device["name"],
         rule["metric"], kind, value, now, _began(rule, device, state, kind)),
    )


def _began(rule: dict[str, Any], device: dict[str, Any], state: Any, kind: str) -> str:
    """
    Когда началось то, о чём событие.

    Не то же самое, что время срабатывания. Правило «не отвечает
    полчаса» загорается в 12:47, а точка упала в 12:17, и в сводке
    человеку нужно второе: по нему он поймёт, попадает ли простой
    в рабочее время и что в этот момент происходило.

    Для недоступности точное время падения знает сама точка:
    `status_changed_at` ставится в момент смены состояния, до всяких
    порогов. Остальные метрики такой отметки не имеют, для них началом
    считается момент, когда условие стало верным.

    У выздоровления начало берётся от парного срабатывания: к этому
    времени точка уже поднялась, и спрашивать её бесполезно.
    """
    if kind != "fired":
        row = query_one(
            "SELECT started_at FROM alert_events WHERE rule_id IS ? AND device_id IS ?"
            " AND kind = 'fired' ORDER BY id DESC LIMIT 1",
            (rule["id"], device["id"]),
        )
        if row and row["started_at"]:
            return str(row["started_at"])

    if str(rule["metric"]) == "offline" and kind == "fired":
        when = str(device.get("status_changed_at") or "")
        if when:
            return when

    if state is not None and state["since"]:
        return str(state["since"])
    return utcnow()


# --------------------------------------------------------------------- чтение
def active() -> list[dict[str, Any]]:
    """Что горит прямо сейчас: правило, точка, значение и с какого времени."""
    return [dict(row) for row in query(
        "SELECT s.*, r.name AS rule_name, r.metric, r.comparison, r.value AS threshold,"
        " d.name AS device_name FROM alert_state s"
        " JOIN alert_rules r ON r.id = s.rule_id"
        " JOIN devices d ON d.id = s.device_id"
        " WHERE s.firing = 1 ORDER BY s.fired_at DESC"
    )]


def pending() -> list[dict[str, Any]]:
    """
    Условие уже верно, но выдержка ещё не вышла.

    Показывать это стоит: человек, увидевший «держится три минуты из
    десяти», понимает, что панель следит, а не проспала.
    """
    return [dict(row) for row in query(
        "SELECT s.*, r.name AS rule_name, r.hold_minutes, d.name AS device_name"
        " FROM alert_state s JOIN alert_rules r ON r.id = s.rule_id"
        " JOIN devices d ON d.id = s.device_id"
        " WHERE s.firing = 0 ORDER BY s.since"
    )]


def events(limit: int = 100) -> list[dict[str, Any]]:
    """Лента срабатываний, свежие сверху."""
    return [dict(row) for row in query(
        "SELECT * FROM alert_events ORDER BY id DESC LIMIT ?", (limit,))]


def unsent(limit: int = 200) -> list[dict[str, Any]]:
    """События, которые ещё никуда не отправляли. Нужно доставке."""
    return [dict(row) for row in query(
        "SELECT * FROM alert_events WHERE sent = 0 ORDER BY id LIMIT ?", (limit,))]


def mark_sent(ids: list[int]) -> None:
    """Отметить события отправленными."""
    if not ids:
        return
    marks = ",".join("?" for _ in ids)
    execute_changes(f"UPDATE alert_events SET sent = 1 WHERE id IN ({marks})", ids)


def format_value(metric_key: Any, value: Any, lang: str = "ru") -> str:
    """
    Значение с единицей, в читаемом виде.

    Минуты недоступности отдельно: «1705.41» это правда, но человек
    читает «1 д 4 ч», а не пересчитывает в уме почти двое суток.
    """
    from . import i18n

    if value is None:
        return "—"
    metric = BY_KEY.get(str(metric_key))
    number = float(value)

    if metric is not None and metric.key == "offline":
        minutes = int(number)
        days, rest = divmod(minutes, 1440)
        hours, mins = divmod(rest, 60)
        parts = []
        if days:
            parts.append(f"{days} " + i18n.translate_text("д", lang))
        if hours:
            parts.append(f"{hours} " + i18n.translate_text("ч", lang))
        if mins or not parts:
            parts.append(f"{mins} " + i18n.translate_text("мин", lang))
        return " ".join(parts)

    unit = i18n.translate_text(metric.unit, lang) if metric else ""
    return f"{number:g} {unit}".strip()


def clock(value: Any) -> str:
    """
    Время события по часам сервера: «13:02», а для несегодняшнего
    «16.08 23:40».

    Дата в каждой строке съедала бы место ради одного и того же числа,
    но сводка приходит и после тихих часов, и после недоступности
    Телеграма, поэтому у вчерашних событий она обязана быть.
    """
    moment = _parse(value)
    if moment is None:
        return ""
    local = moment.astimezone()
    if local.date() == datetime.now().astimezone().date():
        return local.strftime("%H:%M")
    return local.strftime("%d.%m %H:%M")


def lasted(event: dict[str, Any], lang: str = "ru") -> str:
    """
    Сколько длилось событие: от начала до возвращения в норму.

    Пусто у срабатывания: оно ещё идёт, и длительность у него будет
    только когда закончится.
    """
    if str(event.get("kind")) == "fired":
        return ""
    began, moment = _parse(event.get("started_at")), _parse(event.get("ts"))
    if began is None or moment is None:
        return ""
    return format_value("offline", max(0, int((moment - began).total_seconds() // 60)),
                        lang)


def describe(event: dict[str, Any], lang: str = "ru") -> str:
    """
    Человеческая строка события со временем.

    Время здесь обязательно. Сообщение приходит сводкой и может
    задержаться на тихие часы, поэтому «точка не отвечает» без часов
    непонятно: то ли это случилось только что, то ли в четыре утра.

    У выздоровления вместо значения стоят обе отметки и длительность:
    «0 мин» после подъёма это правда, но правда бесполезная, а вот
    «с 12:17 до 13:02, 45 мин» отвечает на всё сразу.
    """
    from . import i18n

    metric = BY_KEY.get(str(event.get("metric")))
    label = i18n.translate_text(metric.label, lang) if metric else str(event.get("metric"))
    name = str(event.get("device_name") or "")
    began, moment = _parse(event.get("started_at")), _parse(event.get("ts"))

    if str(event.get("kind")) != "fired":
        line = f"{name}: {label}".strip()
        if began and moment:
            minutes = max(0, int((moment - began).total_seconds() // 60))
            return line + ", " + i18n.translate(
                "с %(p0)s до %(p1)s, %(p2)s", lang, p0=clock(began), p1=clock(moment),
                p2=format_value("offline", minutes, lang))
        if moment:
            return line + ", " + i18n.translate("в %(p0)s", lang, p0=clock(moment))
        return line

    value = format_value(event.get("metric"), event.get("value"), lang)
    line = f"{name}: {label} {value}".strip()
    if began:
        return line + ", " + i18n.translate("с %(p0)s", lang, p0=clock(began))
    return line
