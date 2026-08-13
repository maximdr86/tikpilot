"""
Конфигурация приложения.

Все параметры читаются из переменных окружения (или из файла .env).
Значения по умолчанию подобраны так, чтобы приложение запускалось
"из коробки" без единой настройки.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from dotenv import load_dotenv

# Корень проекта (каталог, где лежит requirements.txt)
BASE_DIR = Path(__file__).resolve().parent.parent

# Подхватываем .env, если он есть рядом с проектом
load_dotenv(BASE_DIR / ".env")


def _int_env(name: str, default: int) -> int:
    """Прочитать целочисленную переменную окружения с запасным значением."""
    try:
        return int(os.getenv(name, "") or default)
    except ValueError:
        return default


class Settings:
    """Набор настроек приложения (создаётся один раз при импорте)."""

    def __init__(self) -> None:
        # --- Каталоги -------------------------------------------------------
        self.data_dir: Path = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data"))).resolve()
        self.backup_dir: Path = self.data_dir / "backups"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        self.db_path: Path = self.data_dir / "tikpilot.db"
        self._adopt_legacy_database()

        # --- Ключи ----------------------------------------------------------
        self.secret_key: str = os.getenv("SECRET_KEY") or self._persisted_secret()
        self.fernet_key: str = os.getenv("FERNET_KEY") or self._persisted_fernet()

        # --- Учётка администратора по умолчанию ------------------------------
        self.admin_username: str = os.getenv("ADMIN_USERNAME", "admin")
        self.admin_password: str = os.getenv("ADMIN_PASSWORD", "admin")

        # --- Язык интерфейса -------------------------------------------------
        # По умолчанию английский: проект публичный, а русский включается
        # одной строкой в .env.
        self.default_lang: str = os.getenv("DEFAULT_LANG", "en").strip().lower() or "en"

        # --- Доступ к панели --------------------------------------------------
        # Сети, из которых открывается сама панель. Пусто — без ограничений.
        # Публичный лист состояния /status/ доступен всегда: в этом весь смысл.
        self.admin_networks_raw: str = os.getenv("ADMIN_NETWORKS", "")
        # Прокси, чьему заголовку X-Forwarded-For можно верить. Без этого
        # списка заголовок игнорируется: подделать его может кто угодно.
        self.trusted_proxies_raw: str = os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1")
        # Адрес, по которому панель видна снаружи. Нужен только для того,
        # чтобы публичная ссылка получалась пригодной к отправке. Сама панель
        # знает лишь адрес, по которому к ней пришли, а это обычно локальный
        # 10.x:8080, который подрядчику ничего не даст.
        # Пример: PUBLIC_BASE_URL=http://vpn.example.com:6060
        self.public_base_url: str = os.getenv("PUBLIC_BASE_URL", "").strip().rstrip("/")
        # Адрес самой панели, для ссылок, которые ведут внутрь: приглашение
        # администратору. Это не то же самое, что PUBLIC_BASE_URL: тот адрес
        # выставлен наружу ради листа состояния, а страница регистрации
        # открывается только из доверенной сети (ADMIN_NETWORKS), и внешний
        # адрес в такой ссылке скорее собьёт с толку.
        #
        # Пусто (по умолчанию) означает «тот адрес, по которому вы сейчас
        # смотрите панель»: он заведомо рабочий, раз вы по нему пришли.
        # Пример: PANEL_BASE_URL=http://10.10.0.5:6060
        self.panel_base_url: str = os.getenv("PANEL_BASE_URL", "").strip().rstrip("/")

        # Спрашивать ли реестр адресов (RDAP) об операторе тех точек, где
        # нет LTE-модема. Единственное место, которое ходит в интернет,
        # поэтому по умолчанию выключено: панель должна работать в сети
        # без выхода наружу. Оператор с модема читается всегда, он бесплатный.
        self.operator_lookup: bool = os.getenv("OPERATOR_LOOKUP", "0").strip() in ("1", "true", "yes", "on")

        # --- Отчёты -----------------------------------------------------------
        # Название организации в шапке отчёта по доступности. Пусто — шапка
        # будет только с названием отчёта. Отдельная настройка, а не поле
        # в базе: меняется раз в жизни, а в .env её видно рядом с остальным.
        # Пример: REPORT_TITLE=ООО «Ромашка», отдел ИТ
        self.report_title: str = os.getenv("REPORT_TITLE", "").strip()

        # Сколько дней хранить заходы по публичным ссылкам. Там адреса
        # и устройства людей, поэтому срок короче, чем у счётчика обращений.
        self.public_view_retention_days: int = _int_env("PUBLIC_VIEW_DAYS", 90)

        # --- Сеть -----------------------------------------------------------
        self.host: str = os.getenv("HOST", "0.0.0.0")
        self.port: int = _int_env("PORT", 8080)

        # --- Работа с устройствами ------------------------------------------
        self.max_workers: int = _int_env("MAX_WORKERS", 12)
        self.api_timeout: int = _int_env("API_TIMEOUT", 10)
        self.ftp_timeout: int = _int_env("FTP_TIMEOUT", 30)

        # Ожидание устройства после перезагрузки (обновление RouterOS)
        self.reboot_initial_delay: int = _int_env("REBOOT_INITIAL_DELAY", 20)
        self.reboot_probe_interval: int = _int_env("REBOOT_PROBE_INTERVAL", 10)
        # Как часто спрашивать устройство о ходе загрузки пакетов обновления
        self.update_poll_interval: int = _int_env("UPDATE_POLL_INTERVAL", 10)

        # --- Фоновый мониторинг доступности ----------------------------------
        self.monitor_enabled: bool = os.getenv("MONITOR_ENABLED", "1") not in ("0", "false", "no")
        # Как проверять доступность:
        #   session — постоянная API-сессия (по умолчанию). Вход в систему
        #             происходит один раз, дальше дешёвая команда в открытом
        #             соединении: ни записей в журнале, ни новых подключений.
        #   tcp     — открыть и закрыть порт API. Оставлено на случай, когда
        #             держать сессии нельзя; на слабых устройствах вызывает
        #             предупреждения «possible SYN flooding».
        self.monitor_probe_method: str = os.getenv("MONITOR_PROBE_METHOD", "session").strip().lower()
        self.monitor_interval: int = _int_env("MONITOR_INTERVAL", 60)
        self.monitor_probe_timeout: int = _int_env("MONITOR_PROBE_TIMEOUT", 3)
        # Таймаут постоянных сессий мониторинга
        self.monitor_session_timeout: int = _int_env("MONITOR_SESSION_TIMEOUT", 8)
        # Полный опрос с версией, uptime и CPU — реже, требует авторизации
        self.monitor_full_interval: int = _int_env("MONITOR_FULL_INTERVAL", 900)
        # Сколько промахов подряд нужно, чтобы признать устройство недоступным.
        # Защищает от мигания на нестабильных туннелях.
        self.monitor_fail_threshold: int = _int_env("MONITOR_FAIL_THRESHOLD", 3)
        # Пропадание короче этого (в секундах) считается морганием: оно не
        # идёт в простой и не попадает в ленту событий, но видно в списке
        # моргающих точек. 0 — записывать всё подряд, как раньше.
        #
        # Гасит дребезг там, где он мешает, не трогая статус: точка на связи
        # должна показываться на связи, даже если связь плохая.
        self.monitor_min_outage: int = _int_env("MONITOR_MIN_OUTAGE", 0)
        self.monitor_workers: int = _int_env("MONITOR_WORKERS", 0) or self.max_workers
        # Собирать ли клиентов за роутерами (аренды DHCP, ARP, таблица моста).
        # Читается в той же сессии полного опроса, новых подключений не создаёт.
        self.clients_enabled: bool = os.getenv("CLIENTS_ENABLED", "1") not in ("0", "false", "no")
        # Собирать ли паспорт точки: порты и их скорость, PoE, мосты и VLAN,
        # включённые сервисы, соседей, показания датчиков. Четыре команды
        # в той же сессии полного опроса. Выключается, если канал совсем плох:
        # карточка тогда покажет только то, что успели собрать раньше.
        self.inventory_enabled: bool = os.getenv("INVENTORY_ENABLED", "1") not in ("0", "false", "no")
        # Сколько дней помнить клиента, которого больше не видно.
        # Строки со своей подписью не удаляются никогда.
        self.client_retention_days: int = _int_env("CLIENT_RETENTION_DAYS", 30)
        # Сколько дней хранить историю падений и подъёмов
        self.monitor_event_retention_days: int = _int_env("MONITOR_EVENT_RETENTION_DAYS", 30)
        # Как часто интерфейс сам перечитывает таблицу устройств, секунд
        self.ui_refresh_interval: int = _int_env("UI_REFRESH_INTERVAL", 15)

        # --- Проверки задержки -----------------------------------------------
        # Устройство само пингует заданные адреса и сообщает задержку и потери.
        # Это показывает деградацию канала ДО того, как точка отвалится.
        self.latency_enabled: bool = os.getenv("LATENCY_ENABLED", "1") not in ("0", "false", "no")
        # Общие цели для всего парка, через запятую.
        # Можно подписывать: «10.0.0.1=хаб» — подпись видна в интерфейсе.
        self.latency_targets: list[str] = [
            t.strip() for t in os.getenv("LATENCY_TARGETS", "8.8.8.8").split(",") if t.strip()
        ]
        # Пинговать ли шлюз по умолчанию каждой точки (определяется автоматически)
        self.latency_ping_gateway: bool = os.getenv("LATENCY_PING_GATEWAY", "1") not in ("0", "false", "no")
        self.latency_count: int = _int_env("LATENCY_COUNT", 5)
        # Проверки идут вместе с полным опросом, но не чаще этого интервала
        self.latency_interval: int = _int_env("LATENCY_INTERVAL", 900)
        # Сколько дней хранить временные ряды
        self.metrics_retention_days: int = _int_env("METRICS_RETENTION_DAYS", 14)

        # --- Терминал ---------------------------------------------------------
        # Полная командная строка RouterOS по SSH. Самая опасная возможность
        # панели, поэтому её можно выключить целиком, не полагаясь на права.
        self.terminal_enabled: bool = os.getenv("TERMINAL_ENABLED", "1") not in ("0", "false", "no")
        # Сколько минут держать сессию без единого нажатия
        self.terminal_idle_minutes: int = _int_env("TERMINAL_IDLE_MINUTES", 15)

        # --- Приём системного журнала с роутеров ------------------------------
        # Панель слушает syslog и складывает строки рядом со всем остальным:
        # падение точки, её конфигурация и то, что она писала в журнал, видны
        # в одном месте, а не в трёх разных программах.
        self.syslog_enabled: bool = os.getenv("SYSLOG_ENABLED", "1") not in ("0", "false", "no")
        # Порт по умолчанию высокий: 514 требует особых прав, а служба ходит
        # под обычным пользователем. Установщик умеет выдать право на 514,
        # если оно понадобится.
        self.syslog_udp_port: int = _int_env("SYSLOG_UDP_PORT", 5514)
        self.syslog_tcp_port: int = _int_env("SYSLOG_TCP_PORT", 5514)
        self.syslog_bind: str = os.getenv("SYSLOG_BIND", "0.0.0.0")
        # Откуда принимаем строки помимо адресов заведённых устройств.
        # Пусто значит «только от заведённых»: syslog не подписан, и открытый
        # для всех приёмник это приглашение забить диск.
        self.syslog_networks: list[str] = [
            n.strip() for n in os.getenv("SYSLOG_NETWORKS", "").split(",") if n.strip()
        ]
        self.syslog_retention_days: int = _int_env("SYSLOG_RETENTION_DAYS", 30)
        # Потолок по числу строк: спасает диск, когда одна точка за ночь пишет
        # миллион строк об одной и той же ошибке
        self.syslog_max_rows: int = _int_env("SYSLOG_MAX_ROWS", 2_000_000)

        # --- Сессии и хранение истории ---------------------------------------
        self.session_max_age: int = _int_env("SESSION_MAX_AGE", 12 * 3600)
        self.session_cookie: str = "tikpilot_session"
        self.job_retention_days: int = _int_env("JOB_RETENTION_DAYS", 90)

        # --- Защита входа ------------------------------------------------
        # Сколько промахов подряд с одного адреса допустимо, прежде чем
        # включится пауза. 0 — не ограничивать.
        self.login_max_attempts: int = _int_env("LOGIN_MAX_ATTEMPTS", 5)
        # Длина первой паузы в секундах. Каждое следующее превышение
        # удваивает её, но не больше часа.
        self.login_block_seconds: int = _int_env("LOGIN_BLOCK_SECONDS", 60)

        # Ставить ли на cookie флаг Secure (включите при работе за HTTPS)
        self.cookie_secure: bool = os.getenv("COOKIE_SECURE", "0") in ("1", "true", "yes")

        from .netguard import parse_networks

        self.admin_networks = parse_networks(self.admin_networks_raw)
        self.trusted_proxies = parse_networks(self.trusted_proxies_raw)

    # --------------------------------------------------------------- миграция
    def _adopt_legacy_database(self) -> None:
        """
        Подхватить базу от прежнего имени проекта.

        Проект назывался ROSmanager, база лежала в `rosmanager.db`. Молча
        создать рядом пустую новую базу было бы худшим из возможных поведений:
        человек обновился и увидел пустой список устройств, решив, что всё
        потеряно. Поэтому старый файл переименовывается в новый, вместе со
        служебными файлами SQLite.
        """
        legacy = self.data_dir / "rosmanager.db"
        if self.db_path.exists() or not legacy.exists():
            return

        import logging

        for suffix in ("", "-wal", "-shm"):
            source = legacy.with_name(legacy.name + suffix)
            if source.exists():
                source.rename(self.db_path.with_name(self.db_path.name + suffix))

        logging.getLogger("tikpilot").info(
            "База от прежнего имени проекта перенесена: %s -> %s",
            legacy.name, self.db_path.name,
        )

    # ------------------------------------------------------------------ ключи
    def _persisted_secret(self) -> str:
        """Ключ подписи cookie: читаем из файла либо генерируем и сохраняем."""
        path = self.data_dir / "secret.key"
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
        value = secrets.token_urlsafe(48)
        path.write_text(value, encoding="utf-8")
        _chmod_600(path)
        return value

    def _persisted_fernet(self) -> str:
        """Ключ шифрования паролей устройств: читаем из файла либо генерируем."""
        from cryptography.fernet import Fernet  # локальный импорт — ускоряет старт

        path = self.data_dir / "fernet.key"
        if path.exists():
            return path.read_text(encoding="utf-8").strip()
        value = Fernet.generate_key().decode()
        path.write_text(value, encoding="utf-8")
        _chmod_600(path)
        return value


def _chmod_600(path: Path) -> None:
    """Ограничить права на файл ключа (в Windows молча игнорируется)."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


settings = Settings()
