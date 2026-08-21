"""
Ходовые настройки: те, что правятся из панели, а не из `.env`.

Зачем
-----

Поменять интервал опроса или срок хранения логов проще всего тогда, когда
ты уже смотришь на панель и видишь, что тебе не нравится. Вместо этого
приходилось идти на сервер, править `.env` и перезапускать службу, а
в Docker ещё и вспоминать, где этот файл лежит внутри контейнера.

Здесь собраны только те настройки, которые можно менять на ходу и которые
меняют реже, чем хотелось бы, именно из-за неудобства. Всё остальное
остаётся в `.env` намеренно:

* **ключи и пути** (`SECRET_KEY`, `FERNET_KEY`, `DATA_DIR`, `HOST`, `PORT`)
  нужны раньше, чем появляется база, из которой их можно было бы прочитать;
* **периметр** (`ADMIN_NETWORKS`, `TRUSTED_PROXIES`, `COOKIE_SECURE`)
  не должен меняться из самой панели: если в неё кто-то вошёл, он не должен
  иметь возможности раздвинуть её границы;
* **порты syslog** требуют пересоздания сокета, то есть всё равно
  перезапуска.

Как устроено
------------

Значение из `.env` (или умолчание в коде) остаётся отправной точкой, оно
запоминается при старте. Сохранённое в панели кладётся в таблицу
`panel_settings` и накладывается поверх при запуске и сразу после
сохранения. Поэтому изменение действует немедленно: и монитор, и уборка
старых записей читают `settings.*` каждый раз, а не запоминают значение.

Сброс возвращает то, что написано в `.env`: строка из таблицы удаляется,
и панель снова слушается файла.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, NamedTuple

from .config import settings

log = logging.getLogger("tikpilot.prefs")


class Field(NamedTuple):
    """Одна настройка: где живёт, как выглядит и что в ней допустимо."""

    key: str                    # имя в `.env` и в таблице
    attr: str                   # имя поля в объекте настроек
    kind: str                   # int | bool | list | text
    group: str                  # раздел формы
    label: str
    hint: str
    low: int = 0                # границы для чисел
    high: int = 0


FIELDS: tuple[Field, ...] = (
    Field("MONITOR_INTERVAL", "monitor_interval", "int", "Мониторинг",
          "Проверка доступности, секунд",
          "Как часто панель стучится к каждой точке. Реже значит меньше"
          " нагрузки на слабый канал, чаще значит быстрее видно падение.",
          10, 3600),
    Field("MONITOR_FULL_INTERVAL", "monitor_full_interval", "int", "Мониторинг",
          "Полный опрос, секунд",
          "Как часто, кроме проверки связи, забираются версия, аптайм,"
          " клиенты и остальной паспорт точки.",
          60, 86400),
    Field("MONITOR_FAIL_THRESHOLD", "monitor_fail_threshold", "int", "Мониторинг",
          "Промахов подряд до статуса «офлайн»",
          "Защита от дребезга: одна потерянная проба на плохом канале"
          " не должна превращаться в падение площадки.",
          1, 10),
    Field("MONITOR_MIN_OUTAGE", "monitor_min_outage", "int", "Мониторинг",
          "Не считать падением короче, секунд",
          "Такие провалы не попадут в отчёты и в историю. 0 значит"
          " записывать все.",
          0, 86400),
    Field("MONITOR_SESSION_TIMEOUT", "monitor_session_timeout", "int", "Мониторинг",
          "Ждать ответа от точки, секунд",
          "Столько панель ждёт подключения и ответа по API. На канале"
          " с большой задержкой и потерями восьми секунд бывает мало,"
          " и живая точка выглядит упавшей.",
          2, 120),
    Field("ICMP_CHECK_ENABLED", "icmp_check_enabled", "bool", "Мониторинг",
          "Пинговать точку, если API не ответил",
          "Второе мнение: статус остаётся про API, но становится видно,"
          " жив ли сам роутер. Пинг делается только для неответивших,"
          " то есть в обычный день не делается вовсе."),

    Field("LATENCY_ENABLED", "latency_enabled", "bool", "Задержка и потери",
          "Мерить задержку и потери",
          "Пинг запускается на самой точке, панель только забирает итог."),
    Field("LATENCY_INTERVAL", "latency_interval", "int", "Задержка и потери",
          "Как часто мерить, секунд",
          "Каждое измерение это команда на роутере, поэтому чаще"
          " нескольких минут смысла нет.",
          60, 86400),
    Field("LATENCY_TARGETS", "latency_targets", "list", "Задержка и потери",
          "Цели пинга",
          "Через запятую. Шлюз точки добавляется сам, если это не выключено"
          " отдельно в `.env`."),

    Field("TRAFFIC_ENABLED", "traffic_enabled", "bool", "Трафик",
          "Считать скорость на интерфейсах",
          "Счётчики снимаются вместе с полным опросом, отдельных подключений"
          " к роутеру не появляется."),
    Field("TRAFFIC_ALL_INTERFACES", "traffic_all_interfaces", "bool", "Трафик",
          "Следить за всеми интерфейсами",
          "Обычно достаточно аплинка и того, что отмечено в карточке точки."
          " На коробке с тремя десятками VLAN это тридцать рядов вместо одного."),

    Field("NOTIFY_ENABLED", "notify_enabled", "bool", "Уведомления",
          "Отправлять уведомления",
          "Пока выключено, панель наружу не ходит и события просто копятся"
          " на странице порогов."),
    Field("NOTIFY_DIGEST_MINUTES", "notify_digest_minutes", "int", "Уведомления",
          "Сводка не чаще чем раз в, минут",
          "Всё накопившееся уходит одним сообщением. На парке с дребезжащими"
          " каналами это единственный режим, который читают через месяц.",
          1, 1440),
    Field("NOTIFY_QUIET_FROM", "notify_quiet_from", "int", "Уведомления",
          "Тихие часы с",
          "По времени сервера. Ночью события копятся и уходят утром.",
          0, 23),
    Field("NOTIFY_QUIET_TO", "notify_quiet_to", "int", "Уведомления",
          "Тихие часы до",
          "Совпадающие границы означают, что тихих часов нет.",
          0, 23),
    Field("NOTIFY_COOLDOWN_MINUTES", "notify_cooldown_minutes", "int", "Уведомления",
          "Не повторять одно и то же чаще чем раз в, минут",
          "Считается по паре «правило и точка». Дребезжащая точка не должна"
          " заслонять собой всё остальное.",
          0, 1440),
    Field("NOTIFY_RESOLVED", "notify_resolved", "bool", "Уведомления",
          "Сообщать о возвращении в норму",
          "Иначе непонятно, закончилось ли то, о чём написали час назад."),

    Field("HEARTBEAT_URL", "heartbeat_url", "text", "Уведомления",
          "Адрес сигнала живости",
          "Панель раз в несколько минут дёргает этот адрес. Смысл в обратном:"
          " если сигнал перестал приходить, значит умерла сама панель или"
          " сервер, и сказать вам об этом она уже не сможет. Подходит любой"
          " сторож, который умеет ждать запрос: healthchecks.io, свой скрипт,"
          " задача в кроне на другой машине. Пусто значит выключено."),
    Field("HEARTBEAT_MINUTES", "heartbeat_minutes", "int", "Уведомления",
          "Как часто подавать сигнал, минут",
          "Сторож должен ждать заметно дольше этого срока, иначе он будет"
          " срабатывать на каждую перезагрузку панели.",
          1, 1440),

    Field("OPERATOR_LOOKUP", "operator_lookup", "bool", "Операторы",
          "Спрашивать оператора в реестре адресов",
          "Единственное место, где панель ходит в интернет: запрос RDAP"
          " о публичном адресе точки. Модем опрашивается в любом случае."),

    Field("UI_REFRESH_INTERVAL", "ui_refresh_interval", "int", "Интерфейс",
          "Обновление страниц, секунд",
          "Как часто открытая страница подтягивает свежие данные."
          " На дашборде и в списке устройств это заметнее всего.",
          5, 600),

    Field("SYSLOG_RETENTION_DAYS", "syslog_retention_days", "int", "Сроки хранения",
          "Логи с устройств, дней",
          "Старше этого срока строки удаляются при ночной уборке.",
          1, 3650),
    Field("METRICS_RETENTION_DAYS", "metrics_retention_days", "int", "Сроки хранения",
          "Задержка и потери, дней",
          "На парке в полсотни точек это самая объёмная таблица в базе.",
          1, 3650),
    Field("CLIENT_RETENTION_DAYS", "client_retention_days", "int", "Сроки хранения",
          "Пропавшие клиенты, дней",
          "Клиент, которого столько не видели, забывается. Подписанные"
          " руками не трогаются никогда.",
          1, 3650),
    Field("JOB_RETENTION_DAYS", "job_retention_days", "int", "Сроки хранения",
          "Задачи, дней",
          "История массовых действий вместе с результатами по устройствам.",
          1, 3650),

    Field("DISK_MIN_FREE_PERCENT", "disk_min_free_percent", "int", "Сроки хранения",
          "Предупреждать, когда свободно меньше, %",
          "Свободное место на диске, где лежит база. Кончилось место -"
          " панель перестаёт писать вовсе: ни журнала с устройств,"
          " ни истории, ни отметок об отправке. Ноль выключает проверку.",
          0, 90),
)

BY_KEY = {field.key: field for field in FIELDS}

#: Значения из `.env` и умолчания кода: то, к чему возвращает сброс.
#: Снимаются один раз, до первого наложения сохранённого.
_baseline: dict[str, Any] = {}


def baseline() -> dict[str, Any]:
    """Запомнить исходные значения. Повторный вызов ничего не меняет."""
    if not _baseline:
        for field in FIELDS:
            _baseline[field.key] = getattr(settings, field.attr)
    return _baseline


def parse(field: Field, raw: Any) -> Any:
    """
    Строку из формы или из базы в значение нужного вида.

    Негодное значение это не повод падать: возвращаем исходное из `.env`,
    а разбираться с ним будет тот, кто его вписал.
    """
    text = str(raw if raw is not None else "").strip()
    if field.kind == "bool":
        return text.lower() in ("1", "true", "yes", "on", "да")
    if field.kind == "list":
        return [part.strip() for part in text.split(",") if part.strip()]
    if field.kind == "text":
        return text
    try:
        number = int(text)
    except ValueError:
        return baseline()[field.key]
    if field.low or field.high:
        number = max(field.low, min(field.high, number))
    return number


def to_text(field: Field, value: Any) -> str:
    """Значение в строку для хранения и для формы."""
    if field.kind == "bool":
        return "1" if value else "0"
    if field.kind == "list":
        return ", ".join(str(part) for part in value or ())
    return str(value or "") if field.kind == "text" else str(value)


def stored() -> dict[str, str]:
    """Что сохранено в панели. Пусто, если таблицы ещё нет."""
    import sqlite3

    from .database import query

    try:
        rows = query("SELECT key, value FROM panel_settings")
    except sqlite3.Error:
        return {}
    return {str(row["key"]): str(row["value"]) for row in rows}


def apply() -> int:
    """
    Наложить сохранённое в панели поверх значений из `.env`.

    Вызывается при старте и после каждого сохранения. Возвращает число
    настроек, отличающихся от файла.
    """
    baseline()
    saved = stored()
    changed = 0
    for field in FIELDS:
        if field.key in saved:
            setattr(settings, field.attr, parse(field, saved[field.key]))
            changed += 1
        else:
            setattr(settings, field.attr, _baseline[field.key])

    # Монитор показывает свои интервалы в настройках: пусть показывает
    # те, по которым работает
    from . import monitor

    monitor.state["interval"] = settings.monitor_interval
    monitor.state["full_interval"] = settings.monitor_full_interval
    return changed


def save(values: dict[str, Any], username: str = "") -> list[str]:
    """
    Сохранить настройки из формы. Возвращает имена изменившихся.

    Значение, совпавшее с тем, что в `.env`, не хранится: панель не должна
    накапливать записи, которые ничего не меняют, а человек не должен
    гадать, почему правка файла перестала действовать.
    """
    from .database import execute, execute_changes, log_audit, utcnow

    baseline()
    saved = stored()
    touched = []
    now = utcnow()

    for field in FIELDS:
        if field.key not in values:
            continue
        value = parse(field, values[field.key])
        text = to_text(field, value)
        was = saved.get(field.key, to_text(field, _baseline[field.key]))
        if text == was:
            continue

        if value == _baseline[field.key]:
            execute_changes("DELETE FROM panel_settings WHERE key = ?", (field.key,))
        else:
            execute(
                "INSERT INTO panel_settings (key, value, updated_at, updated_by)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
                " updated_at = excluded.updated_at, updated_by = excluded.updated_by",
                (field.key, text, now, username),
            )
        touched.append(field.key)
        if username:
            log_audit(username, "Изменена настройка", field.key, f"{was} -> {text}")

    apply()
    return touched


def reset(username: str = "") -> int:
    """Забыть сохранённое и вернуться к тому, что написано в `.env`."""
    from .database import execute_changes, log_audit

    removed = execute_changes("DELETE FROM panel_settings")
    if removed and username:
        log_audit(username, "Настройки сброшены к .env", "", f"снято: {removed}")
    apply()
    return removed


def form(only: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    """
    Поля для страницы настроек, по разделам и с текущими значениями.

    `only` оставляет перечисленные разделы: настройки разложены по
    вкладкам, и на вкладке «Сбор данных» полям про уведомления делать
    нечего. Порядок разделов сохраняется тот же, что в `FIELDS`.
    """
    baseline()
    saved = stored()
    groups: dict[str, dict[str, Any]] = {}
    for field in FIELDS:
        if only is not None and field.group not in only:
            continue
        block = groups.setdefault(field.group, {"name": field.group, "fields": []})
        block["fields"].append({
            "key": field.key,
            "kind": field.kind,
            "label": field.label,
            "hint": field.hint,
            "value": to_text(field, getattr(settings, field.attr)),
            "checked": bool(getattr(settings, field.attr)) if field.kind == "bool" else False,
            "default": to_text(field, _baseline[field.key]),
            "from_env": field.key not in saved,
            "low": field.low,
            "high": field.high,
        })
    return list(groups.values())
