"""
Слой доступа к SQLite.

Используется «голый» sqlite3 без ORM — схема маленькая, а зависимостей
и накладных расходов так значительно меньше. Соединение создаётся
отдельно для каждого потока (воркер работает в пуле потоков).

Включён режим WAL: он позволяет читать данные во время записи,
что важно при опросе прогресса массовых задач из веб-интерфейса.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from .config import settings

_local = threading.local()

# Отдельный логгер: по имени источника в консоли видно, что это действие
# человека, а не работа панели
_audit_log = logging.getLogger("tikpilot.audit")

# Глобальная блокировка на запись: SQLite допускает лишь одного писателя,
# а воркер обновляет прогресс из десятка потоков одновременно.
write_lock = threading.RLock()


# --------------------------------------------------------------------- utils
def utcnow() -> str:
    """Текущее время UTC в виде строки ISO-8601 (в БД храним только так)."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def get_conn() -> sqlite3.Connection:
    """Вернуть соединение SQLite, привязанное к текущему потоку."""
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(
            settings.db_path,
            timeout=30,
            check_same_thread=False,
            isolation_level=None,  # автокоммит; транзакции открываем вручную
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=30000")
        # Своя функция приведения к нижнему регистру. Встроенная в SQLite
        # знает только латиницу, поэтому поиск «магазин» не находил
        # «Магазин», и это било по каждому русскому имени в парке.
        conn.create_function(
            "lower_ru", 1,
            lambda value: value.lower() if isinstance(value, str) else value,
            deterministic=True)
        _local.conn = conn
    return conn


def query(sql: str, params: Sequence[Any] = ()) -> list[sqlite3.Row]:
    """Выполнить SELECT и вернуть список строк."""
    return get_conn().execute(sql, params).fetchall()


def query_one(sql: str, params: Sequence[Any] = ()) -> sqlite3.Row | None:
    """Выполнить SELECT и вернуть первую строку либо None."""
    return get_conn().execute(sql, params).fetchone()


def execute(sql: str, params: Sequence[Any] = ()) -> int:
    """Выполнить INSERT/UPDATE/DELETE. Возвращает lastrowid."""
    with write_lock:
        cur = get_conn().execute(sql, params)
        return cur.lastrowid


def execute_changes(sql: str, params: Sequence[Any] = ()) -> int:
    """
    Выполнить UPDATE/DELETE и вернуть число затронутых строк.

    Нужно там, где запрос сам решает, применяться ему или нет: например
    «отменить задачу, если она ещё не началась». Ответ базы это надёжнее,
    чем прочитать состояние, подумать и записать: между чтением и записью
    успевает вклиниться фоновый поток.
    """
    with write_lock:
        cur = get_conn().execute(sql, params)
        return cur.rowcount


def execute_many(sql: str, seq: Iterable[Sequence[Any]]) -> None:
    """Пакетное выполнение запроса (используется при создании задач)."""
    with write_lock:
        get_conn().executemany(sql, seq)


# -------------------------------------------------------------------- схема
SCHEMA = """
-- Администраторы веб-интерфейса
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_active     INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT NOT NULL,
    lang          TEXT NOT NULL DEFAULT '',
    -- Права: список ключей через запятую, «full» означает полный доступ
    permissions   TEXT NOT NULL DEFAULT 'full',
    -- 1 — виден весь парк, 0 — только выбранные группы и устройства
    scope_all     INTEGER NOT NULL DEFAULT 1,
    -- Номер поколения сессий. Растёт при каждой смене пароля, и старые
    -- cookie после этого перестают действовать: сессия у нас подписанная
    -- и по себе бессрочная, иначе смена пароля не выгоняла бы того, кто
    -- уже вошёл, а ради этого её обычно и делают.
    session_epoch INTEGER NOT NULL DEFAULT 0
);

-- Настройки хаба WireGuard. Сами линки живут на роутере: он источник
-- правды. Здесь только то, чего роутер о себе не знает — какой интерфейс
-- считать хабом, по какому адресу он доступен снаружи и какие его LAN
-- должны видеть споуки.
CREATE TABLE IF NOT EXISTS wg_hubs (
    device_id   INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    interface   TEXT NOT NULL DEFAULT '',
    public_host TEXT NOT NULL DEFAULT '',
    lan_subnets TEXT NOT NULL DEFAULT '',
    listen_port INTEGER NOT NULL DEFAULT 13231,
    updated_at  TEXT NOT NULL
);

-- Обращения к публичной ссылке, по одной строке на группу и день.
-- Хранить каждое открытие отдельно незачем: нужен не журнал посещений,
-- а ответ на вопрос «этой ссылкой вообще пользуются и не выросло ли вдруг».
CREATE TABLE IF NOT EXISTS public_visits (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    day      TEXT NOT NULL,             -- YYYY-MM-DD по UTC
    hits     INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (group_id, day)
);

-- Библиотека команд: то, что человек однажды написал и хочет повторять.
-- Без неё длинные скрипты живут в переписке и в буфере обмена, а через
-- месяц никто не помнит, какая версия раскатана.
CREATE TABLE IF NOT EXISTS snippets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL,
    note       TEXT NOT NULL DEFAULT '',
    body       TEXT NOT NULL,
    -- Имя скрипта или расписания, которое эта запись создаёт на устройстве.
    -- По нему панель считает, где она раскатана: сверяется с тем, что
    -- реально лежит на точках, а не с нашими намерениями
    marker     TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Скрипты и расписания, найденные на устройстве. Часть паспорта:
-- собирается тем же обходом и так же заменяется целиком.
CREATE TABLE IF NOT EXISTS device_scripts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL DEFAULT 'script',   -- script | scheduler
    name       TEXT NOT NULL,
    comment    TEXT NOT NULL DEFAULT '',
    detail     TEXT NOT NULL DEFAULT '',   -- политики или интервал запуска
    runs       TEXT NOT NULL DEFAULT '',   -- сколько раз запускался
    last_run   TEXT NOT NULL DEFAULT '',
    disabled   INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_dscripts_device ON device_scripts(device_id);
CREATE INDEX IF NOT EXISTS idx_dscripts_name ON device_scripts(name);

-- Страховка при изменении конфигурации.
-- Строка живёт, пока изменение не подтвердили или пока не вышел срок.
-- Сам откат делает роутер своей отложенной задачей, здесь только учёт:
-- что взведено, кем, до какого времени и чем кончилось.
CREATE TABLE IF NOT EXISTS rollbacks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    device_name TEXT NOT NULL DEFAULT '',
    username    TEXT NOT NULL DEFAULT '',
    note        TEXT NOT NULL DEFAULT '',   -- что именно меняли
    minutes     INTEGER NOT NULL DEFAULT 10,
    -- armed | confirmed | rolled-back | expired
    state       TEXT NOT NULL DEFAULT 'armed',
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    closed_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_rollbacks_state ON rollbacks(state, expires_at);

-- Паспорт устройства: порты, сервисы и соседи.
-- Заменяется целиком при каждом сборе, истории здесь нет намеренно:
-- список интерфейсов это снимок настроек, и вчерашний VLAN, удалённый
-- сегодня, в карточке только путает.
CREATE TABLE IF NOT EXISTS device_ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT '',   -- ether, sfp, bridge, vlan, bond
    physical    INTEGER NOT NULL DEFAULT 0, -- есть разъём: показывается плиткой
    running     INTEGER NOT NULL DEFAULT 0,
    disabled    INTEGER NOT NULL DEFAULT 0,
    speed       INTEGER NOT NULL DEFAULT 0, -- мегабиты, 0 если порт погашен
    speed_class TEXT NOT NULL DEFAULT '',
    poe         TEXT NOT NULL DEFAULT '',   -- auto-on, off, forced-on
    poe_status  TEXT NOT NULL DEFAULT '',
    mac         TEXT NOT NULL DEFAULT '',
    comment     TEXT NOT NULL DEFAULT '',
    detail      TEXT NOT NULL DEFAULT '',   -- «VLAN 100 · bridge-main»
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ports_device ON device_ports(device_id);

CREATE TABLE IF NOT EXISTS device_services (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    port       TEXT NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 0,
    address    TEXT NOT NULL DEFAULT '',   -- ограничение по сетям, если задано
    risky      INTEGER NOT NULL DEFAULT 0, -- включён, опасен и открыт всем
    -- Динамическую запись поднял сам RouterOS (resolver, dhcp-клиент,
    -- wireguard). Выключить её через /ip/service нельзя, и судить её
    -- как настроенный сервис бессмысленно
    dynamic    INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_services_device ON device_services(device_id);
CREATE INDEX IF NOT EXISTS idx_services_risky ON device_services(risky);

CREATE TABLE IF NOT EXISTS device_neighbors (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    identity   TEXT NOT NULL DEFAULT '',
    address    TEXT NOT NULL DEFAULT '',
    mac        TEXT NOT NULL DEFAULT '',
    interface  TEXT NOT NULL DEFAULT '',
    platform   TEXT NOT NULL DEFAULT '',
    board      TEXT NOT NULL DEFAULT '',
    version    TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_neighbors_device ON device_neighbors(device_id);

-- Ходовые настройки, изменённые из панели. Здесь только то, что
-- отличается от `.env`: совпавшее с файлом не хранится, чтобы правка
-- файла не переставала действовать молча.
CREATE TABLE IF NOT EXISTS panel_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL DEFAULT ''
);

-- Приглашения администраторов: одноразовая ссылка со сроком.
-- Использованные и просроченные остаются в таблице: «кто кого позвал»
-- это часть истории, а не мусор.
CREATE TABLE IF NOT EXISTS invites (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token      TEXT NOT NULL UNIQUE,
    note       TEXT NOT NULL DEFAULT '',   -- для кого выписано
    created_by TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at    TEXT,                       -- NULL, пока не воспользовались
    used_by    TEXT NOT NULL DEFAULT '',   -- какой логин себе завели
    used_ip    TEXT NOT NULL DEFAULT '',
    revoked    INTEGER NOT NULL DEFAULT 0
);

-- Заходы по публичным ссылкам: по строке на сеанс.
-- Счётчик public_visits отвечает «сколько», эта таблица «кто и когда»:
-- адрес, устройство, начало и последняя активность. Строка с ok = 0 это
-- заход по несуществующему токену, у неё нет группы.
CREATE TABLE IF NOT EXISTS public_views (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id   INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    -- Имя группы копией: ссылку могли отозвать, а группу удалить,
    -- и тогда история заходов превратилась бы в список безымянных строк
    group_name TEXT NOT NULL DEFAULT '',
    session    TEXT NOT NULL DEFAULT '',   -- случайная метка сеанса из cookie
    ok         INTEGER NOT NULL DEFAULT 1, -- 0 — ссылка не найдена
    bot        INTEGER NOT NULL DEFAULT 0, -- предпросмотр в мессенджере и роботы
    ip         TEXT NOT NULL DEFAULT '',
    agent      TEXT NOT NULL DEFAULT '',   -- User-Agent целиком
    device     TEXT NOT NULL DEFAULT '',   -- он же коротко: «Chrome, Android»
    referer    TEXT NOT NULL DEFAULT '',
    lang       TEXT NOT NULL DEFAULT '',
    token_tail TEXT NOT NULL DEFAULT '',   -- хвост неверного токена
    started_at TEXT NOT NULL,
    last_at    TEXT NOT NULL,
    hits       INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_views_last ON public_views(last_at);
CREATE INDEX IF NOT EXISTS idx_views_session ON public_views(session, group_id);

-- Область видимости: какие группы доступны пользователю
CREATE TABLE IF NOT EXISTS user_groups (
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, group_id)
);

-- ... и какие отдельные устройства сверх групп
CREATE TABLE IF NOT EXISTS user_devices (
    user_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, device_id)
);

-- Группы устройств (Core, Access, CPE, Регион-1 ...)
CREATE TABLE IF NOT EXISTS groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE,
    comment    TEXT NOT NULL DEFAULT '',
    color      TEXT NOT NULL DEFAULT 'slate',
    created_at TEXT NOT NULL,
    -- Токен публичной страницы состояния. Пусто — ссылки нет.
    public_token TEXT NOT NULL DEFAULT '',
    -- Когда ссылку открывали последний раз (UTC)
    public_last_seen TEXT
);

-- Устройства MikroTik
CREATE TABLE IF NOT EXISTS devices (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    host          TEXT NOT NULL,
    api_port      INTEGER NOT NULL DEFAULT 8728,
    ftp_port      INTEGER NOT NULL DEFAULT 21,
    ssh_port      INTEGER NOT NULL DEFAULT 22,
    use_ssl       INTEGER NOT NULL DEFAULT 0,
    username      TEXT NOT NULL,
    password_enc  TEXT NOT NULL DEFAULT '',
    group_id      INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    comment       TEXT NOT NULL DEFAULT '',
    enabled       INTEGER NOT NULL DEFAULT 1,
    -- Кэш последнего опроса
    status        TEXT NOT NULL DEFAULT 'unknown',   -- online | offline | unknown
    ros_version   TEXT NOT NULL DEFAULT '',
    board_name    TEXT NOT NULL DEFAULT '',
    identity      TEXT NOT NULL DEFAULT '',
    uptime        TEXT NOT NULL DEFAULT '',
    cpu_load      TEXT NOT NULL DEFAULT '',
    free_memory   TEXT NOT NULL DEFAULT '',
    architecture  TEXT NOT NULL DEFAULT '',   -- arm, mipsbe, tile, x86 ...
    latest_version TEXT NOT NULL DEFAULT '',  -- доступная версия по данным MikroTik
    update_status TEXT NOT NULL DEFAULT '',   -- ответ check-for-updates
    update_channel TEXT NOT NULL DEFAULT '',  -- long-term / stable / testing
    -- Мониторинг доступности
    fail_streak   INTEGER NOT NULL DEFAULT 0, -- промахов подряд (выдержка перед «оффлайн»)
    latency_targets TEXT NOT NULL DEFAULT '',  -- свои цели пинга, через запятую
    gateway       TEXT NOT NULL DEFAULT '',    -- шлюз по умолчанию, определяется сам
    last_seen     TEXT,                       -- когда устройство отвечало в последний раз
    status_changed_at TEXT,                   -- когда статус сменился
    last_check    TEXT,
    last_error    TEXT NOT NULL DEFAULT '',
    -- Датчики с последнего сбора паспорта. Строкой: у разных плат это
    -- «57», «57.5» и «not-supported», а сравнивать их между собой незачем
    temperature   TEXT NOT NULL DEFAULT '',
    voltage       TEXT NOT NULL DEFAULT '',
    inventory_at  TEXT,                     -- когда собирали порты и сервисы
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
,
    -- Оператор связи площадки: кто даёт этой точке канал
    operator      TEXT NOT NULL DEFAULT '',
    operator_source TEXT NOT NULL DEFAULT '',   -- lte | whois | manual
    operator_detail TEXT NOT NULL DEFAULT '',   -- технология и сигнал либо адрес
    operator_raw  TEXT NOT NULL DEFAULT '',    -- что ответил реестр, до перевода в имя
    operator_at   TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_group  ON devices(group_id);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);

-- Массовая задача (одна кнопка «Перезагрузить группу» = одна запись)
CREATE TABLE IF NOT EXISTS jobs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    action       TEXT NOT NULL,
    action_label TEXT NOT NULL DEFAULT '',
    params_json  TEXT NOT NULL DEFAULT '{}',
    username     TEXT NOT NULL DEFAULT '',
    status       TEXT NOT NULL DEFAULT 'pending',   -- pending|running|done|cancelled
    total        INTEGER NOT NULL DEFAULT 0,
    done         INTEGER NOT NULL DEFAULT 0,
    ok_count     INTEGER NOT NULL DEFAULT 0,
    fail_count   INTEGER NOT NULL DEFAULT 0,
    cancel_flag  INTEGER NOT NULL DEFAULT 0,
    scheduled_at TEXT,                          -- отложенный запуск (UTC)
    created_at   TEXT NOT NULL,
    started_at   TEXT,
    finished_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);

-- Результат задачи по каждому отдельному устройству
CREATE TABLE IF NOT EXISTS job_items (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id      INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    device_id   INTEGER,
    device_name TEXT NOT NULL DEFAULT '',
    device_host TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending',   -- pending|running|ok|error|skipped
    result      TEXT NOT NULL DEFAULT '',
    started_at  TEXT,
    finished_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_job_items_job ON job_items(job_id);

-- Журнал действий администраторов (вход, правка устройств, запуск задач)
CREATE TABLE IF NOT EXISTS audit_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    username TEXT NOT NULL DEFAULT '',
    action   TEXT NOT NULL,
    target   TEXT NOT NULL DEFAULT '',
    details  TEXT NOT NULL DEFAULT '',
    ip       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);

-- История падений и подъёмов устройств (заполняет монитор)
CREATE TABLE IF NOT EXISTS status_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER,
    device_name TEXT NOT NULL DEFAULT '',
    device_host TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL,          -- online | offline
    reason      TEXT NOT NULL DEFAULT '',
    downtime    INTEGER,                -- сколько секунд лежало (заполняется при подъёме)
    ts          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_status_events_ts ON status_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_status_events_device ON status_events(device_id);

-- Временной ряд состояния устройства (CPU, память)
CREATE TABLE IF NOT EXISTS device_metrics (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL,
    ts          TEXT NOT NULL,
    cpu_load    REAL,
    free_memory INTEGER,
    UNIQUE(device_id, ts) ON CONFLICT REPLACE
);
CREATE INDEX IF NOT EXISTS idx_device_metrics ON device_metrics(device_id, ts);

-- Чаты, куда уходят уведомления. Токен бота лежит зашифрованным тем же
-- ключом, что и пароли роутеров, и обратно в интерфейс не отдаётся.
CREATE TABLE IF NOT EXISTS notify_channels (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    -- Всегда telegram. Колонка осталась от версии, где был ещё вебхук:
    -- удалять её ради чистоты значит переписывать таблицу на боевой базе
    kind       TEXT NOT NULL DEFAULT 'telegram',
    address    TEXT NOT NULL,               -- идентификатор чата
    secret_enc TEXT NOT NULL DEFAULT '',    -- токен бота, зашифрован
    enabled    INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Попытки отправки: без них молчащий канал не отладить
CREATE TABLE IF NOT EXISTS notify_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_id INTEGER,
    kind       TEXT NOT NULL DEFAULT '',
    ok         INTEGER NOT NULL DEFAULT 0,
    error      TEXT NOT NULL DEFAULT '',
    ts         TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_notify_log_ts ON notify_log(ts DESC);

-- Пороги: правило, его состояние по каждой точке и лента срабатываний
CREATE TABLE IF NOT EXISTS alert_rules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL,
    metric       TEXT NOT NULL,             -- ключ из alerts.METRICS
    comparison   TEXT NOT NULL DEFAULT 'above',  -- above | below
    value        REAL NOT NULL,
    hold_minutes INTEGER NOT NULL DEFAULT 0,     -- сколько держаться до срабатывания
    scope_kind   TEXT NOT NULL DEFAULT 'all',    -- all | group | device
    scope_id     INTEGER NOT NULL DEFAULT 0,
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL,
    created_by   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS alert_state (
    rule_id    INTEGER NOT NULL,
    device_id  INTEGER NOT NULL,
    since      TEXT NOT NULL,        -- когда условие стало верным
    firing     INTEGER NOT NULL DEFAULT 0,
    fired_at   TEXT,
    last_value REAL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (rule_id, device_id)
);

CREATE TABLE IF NOT EXISTS alert_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id     INTEGER,
    rule_name   TEXT NOT NULL DEFAULT '',
    device_id   INTEGER,
    device_name TEXT NOT NULL DEFAULT '',
    metric      TEXT NOT NULL DEFAULT '',
    kind        TEXT NOT NULL,        -- fired | resolved
    value       REAL,
    ts          TEXT NOT NULL,
    -- Когда началось то, о чём событие: время падения, а не время
    -- срабатывания правила. Их разделяет выдержка, и в сводке нужно первое
    started_at  TEXT,
    -- Ушло ли событие в уведомление. Доставка отдельная и может быть
    -- выключена: тогда флаг просто остаётся нулём и никому не мешает
    sent        INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_alert_events_ts ON alert_events(ts DESC);
CREATE INDEX IF NOT EXISTS idx_alert_events_sent ON alert_events(sent);

-- Скорость на интерфейсах: посчитана из разницы счётчиков между обходами
CREATE TABLE IF NOT EXISTS traffic_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL,
    interface   TEXT NOT NULL,
    ts          TEXT NOT NULL,
    rx_bps      INTEGER NOT NULL DEFAULT 0,
    tx_bps      INTEGER NOT NULL DEFAULT 0,
    span        INTEGER NOT NULL DEFAULT 0   -- секунд между снятиями счётчиков
);
CREATE INDEX IF NOT EXISTS idx_traffic ON traffic_samples(device_id, interface, ts);

-- Последние снятые счётчики: точка отсчёта для следующего обхода.
-- Хранится по одной строке на интерфейс, история тут не нужна.
CREATE TABLE IF NOT EXISTS traffic_counters (
    device_id   INTEGER NOT NULL,
    interface   TEXT NOT NULL,
    ts          TEXT NOT NULL,
    rx_bytes    INTEGER NOT NULL,
    tx_bytes    INTEGER NOT NULL,
    PRIMARY KEY (device_id, interface)
);

-- За какими интерфейсами следить помимо аплинка. Отдельно от паспорта:
-- паспорт при каждом обходе переписывается, а выбор человека остаётся.
CREATE TABLE IF NOT EXISTS traffic_watch (
    device_id   INTEGER NOT NULL,
    interface   TEXT NOT NULL,
    PRIMARY KEY (device_id, interface)
);

-- Результаты проверок задержки: устройство пингует цель и сообщает итог
CREATE TABLE IF NOT EXISTS latency_samples (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL,
    target      TEXT NOT NULL,
    label       TEXT NOT NULL DEFAULT '',   -- «шлюз» или пусто
    ts          TEXT NOT NULL,
    sent        INTEGER NOT NULL DEFAULT 0,
    received    INTEGER NOT NULL DEFAULT 0,
    loss        REAL,                        -- потери, проценты
    rtt_min     REAL,
    rtt_avg     REAL,
    rtt_max     REAL,
    error       TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_latency ON latency_samples(device_id, target, ts);

-- Файлы бэкапов, скачанные с устройств
CREATE TABLE IF NOT EXISTS backups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER,
    device_name TEXT NOT NULL DEFAULT '',
    job_id      INTEGER,
    kind        TEXT NOT NULL,          -- binary | export
    filename    TEXT NOT NULL,
    size        INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_backups_device ON backups(device_id);

-- Клиенты за роутерами: что подключено к площадке и куда воткнуто.
-- Ключ — пара «устройство и MAC»: один и тот же ноутбук на двух точках
-- это две записи, и это правильно, потому что порт у них разный.
CREATE TABLE IF NOT EXISTS clients (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id   INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    mac         TEXT NOT NULL,
    hostname    TEXT NOT NULL DEFAULT '',   -- имя из аренды DHCP
    comment     TEXT NOT NULL DEFAULT '',   -- комментарий, проставленный на роутере
    label       TEXT NOT NULL DEFAULT '',   -- своя подпись, её задаёт человек
    ip          TEXT NOT NULL DEFAULT '',
    port        TEXT NOT NULL DEFAULT '',   -- физический порт из таблицы моста
    link        TEXT NOT NULL DEFAULT 'wired',  -- wired | wireless
    ssid        TEXT NOT NULL DEFAULT '',   -- сеть, если подключён по воздуху
    signal      TEXT NOT NULL DEFAULT '',   -- уровень сигнала, дБм
    interface   TEXT NOT NULL DEFAULT '',
    vlan        TEXT NOT NULL DEFAULT '',
    vendor      TEXT NOT NULL DEFAULT '',
    dynamic     INTEGER NOT NULL DEFAULT 1, -- 0 — адрес закреплён за клиентом
    source      TEXT NOT NULL DEFAULT '',   -- dhcp | arp | bridge
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    UNIQUE (device_id, mac)
);
CREATE INDEX IF NOT EXISTS idx_clients_device ON clients(device_id);
CREATE INDEX IF NOT EXISTS idx_clients_mac ON clients(mac);

-- Системный журнал, принятый с роутеров по syslog.
-- Строка привязана к устройству панели по адресу источника: из журнала
-- сразу видно, чья это площадка, и можно уйти в её карточку.
CREATE TABLE IF NOT EXISTS syslog (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT NOT NULL,              -- когда приняли, UTC
    device_id     INTEGER REFERENCES devices(id) ON DELETE SET NULL,
    device_name   TEXT NOT NULL DEFAULT '',   -- имя на момент приёма
    source        TEXT NOT NULL DEFAULT '',   -- адрес, с которого пришло
    host          TEXT NOT NULL DEFAULT '',   -- как назвал себя отправитель
    topics        TEXT NOT NULL DEFAULT '',   -- темы RouterOS: system,info
    severity      INTEGER NOT NULL DEFAULT 6,
    severity_name TEXT NOT NULL DEFAULT 'info',
    facility      INTEGER NOT NULL DEFAULT 1,
    stamp         TEXT NOT NULL DEFAULT '',   -- отметка времени отправителя, как есть
    message       TEXT NOT NULL DEFAULT '',
    -- Исходная строка целиком, как пришла. Разбор форматов дело гадательное:
    -- если поля разобрались неверно, восстановить содержимое можно только
    -- отсюда. Место того стоит.
    raw           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_syslog_ts ON syslog(id DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_device ON syslog(device_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_syslog_severity ON syslog(severity, id DESC);

-- Адреса, с которых разрешено принимать журнал сверх адресов устройств.
-- Заводятся человеком по кнопке: роутер часто отправляет с туннельного
-- адреса, а панель знает его по адресу управления, и молча принимать
-- что попало нельзя.
CREATE TABLE IF NOT EXISTS syslog_sources (
    address    TEXT PRIMARY KEY,
    device_id  INTEGER REFERENCES devices(id) ON DELETE CASCADE,
    note       TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);

-- Отпечатки ключей SSH: доверие при первом подключении.
-- Принимать любой ключ молча нельзя, это открытая дверь для подмены,
-- а заполнять список отпечатков руками на полсотни точек никто не станет.
CREATE TABLE IF NOT EXISTS ssh_hosts (
    device_id   INTEGER PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    first_seen  TEXT NOT NULL
);

-- Правила подсветки строк журнала. Побеждает первое подошедшее,
-- порядок задаёт человек полем position.
CREATE TABLE IF NOT EXISTS syslog_rules (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern    TEXT NOT NULL,
    is_regex   INTEGER NOT NULL DEFAULT 0,
    color      TEXT NOT NULL DEFAULT 'warn',
    note       TEXT NOT NULL DEFAULT '',
    enabled    INTEGER NOT NULL DEFAULT 1,
    position   INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    -- Что делать со строкой: color (подсветить), hide (не показывать,
    -- но хранить), drop (не сохранять вовсе)
    action     TEXT NOT NULL DEFAULT 'color',
    -- Правило, предложенное самой панелью. Отличается от заведённого
    -- человеком: удалённое такое правило не должно возвращаться при
    -- следующем запуске
    builtin    TEXT NOT NULL DEFAULT ''
);

-- Встроенные правила, которые панель предлагала. Здесь только их ключи:
-- по ним видно, что правило уже предлагалось, и удалять его человек может
-- насовсем.
CREATE TABLE IF NOT EXISTS syslog_builtin (
    key       TEXT PRIMARY KEY,
    added_at  TEXT NOT NULL
);

-- Расписание бэкапов: что снимать, когда и сколько копий хранить
CREATE TABLE IF NOT EXISTS backup_schedules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL DEFAULT '',
    target       TEXT NOT NULL DEFAULT 'all',   -- all | group | panel
    group_id     INTEGER,                       -- заполнено только для target='group'
    at_time      TEXT NOT NULL DEFAULT '03:00', -- местное время сервера
    days         TEXT NOT NULL DEFAULT '',      -- «1,3,5», пусто — ежедневно
    keep         INTEGER NOT NULL DEFAULT 14,   -- сколько последних копий оставлять
    do_binary    INTEGER NOT NULL DEFAULT 1,
    do_export    INTEGER NOT NULL DEFAULT 1,
    enabled      INTEGER NOT NULL DEFAULT 1,
    next_run_at  TEXT,                          -- UTC
    last_run_at  TEXT,                          -- UTC
    last_result  TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL
);
"""


# Колонки, добавленные уже после первых версий программы.
# Проверяются при каждом старте, чтобы существующая база обновлялась сама.
MIGRATIONS: dict[str, list[tuple[str, str]]] = {
    "devices": [
        ("architecture", "TEXT NOT NULL DEFAULT ''"),
        ("latest_version", "TEXT NOT NULL DEFAULT ''"),
        ("update_status", "TEXT NOT NULL DEFAULT ''"),
        ("update_channel", "TEXT NOT NULL DEFAULT ''"),
        ("fail_streak", "INTEGER NOT NULL DEFAULT 0"),
        ("last_seen", "TEXT"),
        ("status_changed_at", "TEXT"),
        # Свои цели пинга для этой точки, через запятую (пусто — общие настройки)
        ("latency_targets", "TEXT NOT NULL DEFAULT ''"),
        ("gateway", "TEXT NOT NULL DEFAULT ''"),
        # Порт SSH: нужен только терминалу, у RouterOS по умолчанию 22
        ("ssh_port", "INTEGER NOT NULL DEFAULT 22"),
        # Показания датчиков с последнего сбора паспорта. Строкой, а не
        # числом: у разных плат это «57», «57.5» и «not-supported».
        ("temperature", "TEXT NOT NULL DEFAULT ''"),
        ("voltage", "TEXT NOT NULL DEFAULT ''"),
        ("inventory_at", "TEXT"),
        # Оператор связи площадки: имя, откуда узнали (lte|whois|manual),
        # подробности (технология и сигнал либо адрес) и когда узнали
        ("operator", "TEXT NOT NULL DEFAULT ''"),
        ("operator_source", "TEXT NOT NULL DEFAULT ''"),
        ("operator_detail", "TEXT NOT NULL DEFAULT ''"),
        ("operator_raw", "TEXT NOT NULL DEFAULT ''"),
        ("operator_at", "TEXT"),
        # Интерфейс, через который у точки уходит маршрут по умолчанию.
        # Определяется сам и запоминается: спрашивать маршруты каждый
        # обход ради имени, которое меняется раз в год, незачем.
        ("uplink_interface", "TEXT NOT NULL DEFAULT ''"),
    ],
    "syslog": [
        # Исходная строка целиком: страховка на случай, если разбор ошибся
        ("raw", "TEXT NOT NULL DEFAULT ''"),
    ],
    "clients": [
        # Комментарий с роутера: аренда DHCP или запись ARP
        ("comment", "TEXT NOT NULL DEFAULT ''"),
        # Вид подключения и сведения о беспроводном
        ("link", "TEXT NOT NULL DEFAULT 'wired'"),
        ("ssid", "TEXT NOT NULL DEFAULT ''"),
        ("signal", "TEXT NOT NULL DEFAULT ''"),
    ],
    "status_events": [
        # Короткое пропадание: не идёт в простой и в ленту событий
        ("short", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "device_services": [
        ("dynamic", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "syslog_rules": [
        # Правило может не только красить, но и прятать строку или
        # отбрасывать её на приёме. Старые правила остаются красящими.
        ("action", "TEXT NOT NULL DEFAULT 'color'"),
        ("builtin", "TEXT NOT NULL DEFAULT ''"),
    ],
    "jobs": [
        # Отложенный запуск: задача ждёт указанного времени (UTC)
        ("scheduled_at", "TEXT"),
        # Правило расписания, породившее задачу. По нему после её окончания
        # чистятся лишние копии.
        ("schedule_id", "INTEGER"),
    ],
    "groups": [
        # Публичная ссылка на лист состояния. Пусто — ссылки нет.
        ("public_token", "TEXT NOT NULL DEFAULT ''"),
        # Когда ссылку открывали последний раз (UTC)
        ("public_last_seen", "TEXT"),
        # Показывать ли оператора связи на публичном листе. По умолчанию
        # нет: лист задуман как «имя точки и состояние», и всё, что
        # добавляется сверх этого, добавляется осознанно и по одной группе
        ("public_show_operator", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "alert_events": [
        # Когда всё началось. Не то же самое, что время события: правило
        # с выдержкой срабатывает через полчаса после падения, а человеку
        # в сводке нужно время падения, а не время срабатывания.
        ("started_at", "TEXT"),
    ],
    "users": [
        # Выбранный язык интерфейса. Пусто — берётся DEFAULT_LANG из .env.
        ("lang", "TEXT NOT NULL DEFAULT ''"),
        # Права. Значение по умолчанию намеренно полное: до появления этой
        # колонки все учётные записи были администраторами, и обновление
        # программы не должно внезапно отнимать доступ.
        ("permissions", "TEXT NOT NULL DEFAULT 'full'"),
        ("scope_all", "INTEGER NOT NULL DEFAULT 1"),
        # Поколение сессий: растёт при смене пароля, старые cookie после
        # этого не подходят. Ноль у всех существующих — это правильно,
        # ровно такое же значение кладётся в свежие cookie
        ("session_epoch", "INTEGER NOT NULL DEFAULT 0"),
    ],
}


def _migrate() -> None:
    """Добавить недостающие колонки в уже существующую базу."""
    conn = get_conn()
    for table, columns in MIGRATIONS.items():
        existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
        if not existing:
            # Таблицы нет вовсе — дополнять нечего. Обычно её создаст SCHEMA.
            continue
        for name, definition in columns:
            if name not in existing:
                with write_lock:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {definition}")


def init_db() -> None:
    """Создать схему и учётную запись администратора при первом запуске."""
    conn = get_conn()
    with write_lock:
        conn.executescript(SCHEMA)
    _migrate()

    # Администратор по умолчанию — только если пользователей ещё нет
    if query_one("SELECT id FROM users LIMIT 1") is None:
        from .crypto import hash_password

        execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)",
            (settings.admin_username, hash_password(settings.admin_password), utcnow()),
        )

    # Задачи, «зависшие» после аварийной остановки процесса, помечаем завершёнными
    execute(
        "UPDATE jobs SET status='done', finished_at=? WHERE status='running'",
        (utcnow(),),
    )
    execute(
        "UPDATE job_items SET status='error', result='Прервано при перезапуске сервиса', "
        "finished_at=? WHERE status IN ('running')",
        (utcnow(),),
    )


# ------------------------------------------------- кэш состояния устройства
def save_device_info(device_id: int, info: dict[str, Any]) -> None:
    """
    Записать сведения, полученные с устройства при успешном подключении.

    Используется и воркером задач, и фоновым монитором, поэтому живёт здесь,
    а не в одном из них.
    """
    now = utcnow()
    execute(
        "UPDATE devices SET ros_version=?, board_name=?, identity=?, uptime=?, "
        "cpu_load=?, free_memory=?, architecture=?, last_check=?, last_seen=?, "
        "last_error='', fail_streak=0, updated_at=? WHERE id=?",
        (
            info.get("ros_version", ""),
            info.get("board_name", ""),
            info.get("identity", ""),
            info.get("uptime", ""),
            info.get("cpu_load", ""),
            info.get("free_memory", ""),
            info.get("architecture", ""),
            now,
            now,
            now,
            device_id,
        ),
    )


def save_device_update(device_id: int, update: dict[str, Any]) -> None:
    """Записать результат проверки обновлений RouterOS."""
    execute(
        "UPDATE devices SET latest_version=?, update_status=?, update_channel=?, updated_at=? "
        "WHERE id=?",
        (
            update.get("latest_version", ""),
            update.get("update_status", ""),
            update.get("update_channel", ""),
            utcnow(),
            device_id,
        ),
    )


def log_audit(username: str, action: str, target: str = "", details: str = "", ip: str = "") -> None:
    """
    Записать событие в журнал действий.

    Заодно строка уходит в лог, а значит и в живую консоль. Иначе консоль
    показывала бы, что делает панель, но не что делают в панели: вход,
    правка карточки, выдача прав и отзыв публичной ссылки проходили бы мимо.

    Подробности в консоли обрезаем: в них попадают параметры задач целиком,
    и лента превратилась бы в простыню.
    """
    execute(
        "INSERT INTO audit_log (ts, username, action, target, details, ip) VALUES (?,?,?,?,?,?)",
        (utcnow(), username, action, target, details[:4000], ip),
    )

    line = f"{username}: {action}"
    if target:
        line += f" · {target}"
    if details:
        line += f" ({details[:120]})"
    if ip:
        line += f" [{ip}]"
    # Неудачный вход это предупреждение: его ищут глазами среди прочего
    if "еудачн" in action:
        _audit_log.warning(line)
    else:
        _audit_log.info(line)


def forget_device_traces(device_ids: Sequence[int]) -> None:
    """
    Убрать следы удалённых точек из таблиц без внешнего ключа.

    Паспорт, клиенты и прочее уходят каскадом: у них есть
    `REFERENCES devices(id) ON DELETE CASCADE`. У порогов и трафика его
    нет, и добавить задним числом нельзя: SQLite не умеет
    `ALTER TABLE ADD CONSTRAINT`, а переписывать боевую таблицу ради
    этого дороже, чем убрать строки руками.

    Пока их не убирали, удалённая точка продолжала гореть в счётчике
    меню: список на странице соединяется с устройствами и её не
    показывал, а счётчик считал строки состояния и видел.

    Лента срабатываний не трогается: это история, и в ней имя точки
    записано отдельным полем.
    """
    if not device_ids:
        return
    marks = ",".join("?" for _ in device_ids)
    params = list(device_ids)
    for table in ("alert_state", "traffic_watch", "traffic_counters",
                  "traffic_samples"):
        execute(f"DELETE FROM {table} WHERE device_id IN ({marks})", params)

    # Приёмник журнала держит соответствие «адрес - точка» в памяти
    # и обновляет его раз в минуту. Без этого он ещё минуту привязывал бы
    # приходящие строки к удалённой точке, и каждая такая строка ломала
    # запись целой пачки по внешнему ключу.
    try:
        from . import syslog

        syslog._sources.refresh(force=True)
    except Exception:  # noqa: BLE001 - удаление важнее кэша приёмника
        pass


def cleanup_orphan_rows() -> int:
    """
    Подчистить строки, оставшиеся от точек, которых уже нет.

    Страховка на случай, если удаление прошло мимо `forget_device_traces`:
    например точку убрали прямо в базе или при переносе со старой версии.
    """
    removed = 0
    for table in ("alert_state", "traffic_watch", "traffic_counters",
                  "traffic_samples"):
        removed += execute_changes(
            f"DELETE FROM {table} WHERE device_id NOT IN (SELECT id FROM devices)")
    return removed


def cleanup_old_jobs() -> None:
    """Удалить историю задач старше JOB_RETENTION_DAYS (0 — не удалять)."""
    days = settings.job_retention_days
    if days <= 0:
        return
    execute(
        "DELETE FROM jobs WHERE finished_at IS NOT NULL "
        "AND finished_at < datetime('now', ?)",
        (f"-{days} days",),
    )
    execute("DELETE FROM audit_log WHERE ts < datetime('now', ?)", (f"-{days} days",))

    metric_days = settings.metrics_retention_days
    if metric_days > 0:
        for table in ("device_metrics", "latency_samples", "traffic_samples"):
            execute(f"DELETE FROM {table} WHERE ts < datetime('now', ?)", (f"-{metric_days} days",))

    client_days = settings.client_retention_days
    if client_days > 0:
        execute(
            "DELETE FROM clients WHERE label = '' AND last_seen < datetime('now', ?)",
            (f"-{client_days} days",),
        )

    orphans = cleanup_orphan_rows()
    if orphans:
        _audit_log.info("Убрано строк от удалённых устройств: %s", orphans)

    event_days = settings.monitor_event_retention_days
    if event_days > 0:
        execute(
            "DELETE FROM status_events WHERE ts < datetime('now', ?)",
            (f"-{event_days} days",),
        )
        # Лента порогов живёт по тем же правилам, что и события статуса:
        # это соседние строки об одном и том же парке
        execute(
            "DELETE FROM alert_events WHERE ts < datetime('now', ?)",
            (f"-{event_days} days",),
        )

    # Журнал устройств. Ограничений два: срок и потолок по числу строк.
    # Второй нужен потому, что одна взбесившаяся точка за ночь пишет
    # миллион строк об одной и той же ошибке, и срок тут не спасёт.
    syslog_days = settings.syslog_retention_days
    if syslog_days > 0:
        execute("DELETE FROM syslog WHERE ts < datetime('now', ?)",
                (f"-{syslog_days} days",))
    if settings.syslog_max_rows > 0:
        row = query_one("SELECT COUNT(*) AS c FROM syslog")
        extra = (row["c"] if row else 0) - settings.syslog_max_rows
        if extra > 0:
            execute("DELETE FROM syslog WHERE id IN "
                    "(SELECT id FROM syslog ORDER BY id LIMIT ?)", (extra,))

    # Счётчик обращений к публичным ссылкам. Данных здесь мало (строка на
    # группу в день), но и смысла в прошлогодних цифрах никакого.
    execute("DELETE FROM public_visits WHERE day < date('now','-90 day')")

    # Заходы по публичным ссылкам. Тут уже адреса и устройства, то есть
    # сведения о людях: хранить их дольше, чем нужно для ответа на вопрос
    # «кому разошлась ссылка», незачем.
    view_days = settings.public_view_retention_days
    if view_days > 0:
        execute("DELETE FROM public_views WHERE last_at < datetime('now', ?)",
                (f"-{view_days} days",))

    # Приглашения. Полгода это запас на вопрос «откуда у нас этот человек»,
    # дальше запись отвечает уже на вопрос, который никто не задаёт.
    execute("DELETE FROM invites WHERE created_at < datetime('now','-180 day')")
