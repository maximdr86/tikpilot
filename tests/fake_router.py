"""
Заглушка устройства MikroTik для автотестов.

Реализует протокол RouterOS API поверх обычного TCP-сокета и минимальный
FTP-сервер, чтобы можно было проверить весь путь целиком:
подключение → команда → создание бэкапа → скачивание файла.

Запускается прямо в процессе теста, никакого реального роутера не нужно.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Any

import librouteros.protocol as _proto


class _Codec:
    """
    Кодек слов RouterOS API — переиспользуем реализацию из librouteros.

    В librouteros 3.4.1 это классы Encoder/Decoder, в 3.4.3+ — функции модуля.
    Поддерживаем оба варианта, чтобы тесты не зависели от версии библиотеки.
    """

    encoding = "utf-8"

    def __init__(self) -> None:
        if hasattr(_proto, "encode_sentence"):           # librouteros >= 3.4.2
            self.encodeSentence = lambda *words: _proto.encode_sentence(*words, encoding=self.encoding)
            self.determineLength = _proto.determine_length
            self.decodeLength = _proto.decode_length
        else:                                            # librouteros 3.4.1 и старше
            codec = type("_C", (_proto.Encoder, _proto.Decoder), {"encoding": self.encoding})()
            self.encodeSentence = codec.encodeSentence
            self.determineLength = codec.determineLength
            self.decodeLength = codec.decodeLength


class FakeRouter:
    """
    Простейшая эмуляция RouterOS API.

    Поддерживает: /login, /system/resource/print, /system/identity/print,
    /system/script/{print,add,set,run,remove}, /file/{print,remove},
    /system/backup/save, /export, /system/reboot, /system/identity/set.
    """

    def __init__(self, username: str = "admin", password: str = "test", host: str = "127.0.0.1") -> None:
        self.username = username
        self.password = password
        self.host = host
        self.codec = _Codec()

        # Состояние «устройства»
        # Пусто по умолчанию: тесты загрузки скриптов считают записи,
        # и «подарок» от заглушки ломал бы их счёт. Кому нужен готовый
        # скрипт на устройстве, тот кладёт его сам.
        self.scripts: list[dict[str, Any]] = []
        # Настройка отправки журнала: получатели и правила
        self.log_actions: list[dict[str, str]] = []
        self.log_rules: list[dict[str, str]] = []
        self.files: list[dict[str, str]] = []
        self.identity = "MikroTik"
        self.rebooted = False
        #: Отложенные задачи устройства. На них держится страховка отката.
        self.schedulers: list[dict[str, Any]] = []
        self.restored = False           # выполняли ли backup load
        self.executed: list[str] = []   # журнал вызванных команд — для проверок в тестах
        self.connections = 0            # принято TCP-подключений (важно для теста сессий)
        self.logins = 0                 # успешных входов в систему
        self.script_run_seconds = 0.0   # сколько «выполняется» скрипт

        # --- проверка канала ---
        # --- WireGuard ---
        # Хранится как на настоящем устройстве: списки записей со своими .id.
        self.wg_interfaces: list[dict[str, str]] = [{
            ".id": "*10", "name": "wg-hub", "listen-port": "13231",
            "public-key": "HUBPUBLICKEY0000000000000000000000000000000=",
            "running": "true",
        }]
        self.wg_peers: list[dict[str, str]] = []
        # Клиенты площадки: аренды DHCP, ARP и таблица моста.
        # Один и тот же ноутбук намеренно встречается в разных таблицах:
        # на этом проверяется слияние по MAC.
        self.dhcp_leases: list[dict[str, str]] = [
            {".id": "*1", "address": "192.168.88.10", "mac-address": "BC:24:11:F0:70:DB",
             "host-name": "касса-1", "server": "dhcp1", "dynamic": "false",
             "comment": "касса у входа"},
            {".id": "*2", "address": "192.168.88.11", "mac-address": "B0:FC:0D:F3:56:8F",
             "host-name": "echo", "server": "dhcp1", "dynamic": "true"},
        ]
        self.arp_entries: list[dict[str, str]] = [
            {".id": "*1", "address": "192.168.88.10", "mac-address": "BC:24:11:F0:70:DB",
             "interface": "bridge"},
            # Камера с прописанным руками адресом: в арендах её нет
            {".id": "*2", "address": "192.168.88.50", "mac-address": "C0:56:E3:11:22:33",
             "interface": "bridge", "comment": "камера склад"},
            # Оборудование провайдера на WAN: клиентом площадки не является
            {".id": "*3", "address": "10.0.0.254", "mac-address": "10:E8:40:18:73:0F",
             "interface": "lte1"},
        ]
        self.bridge_hosts: list[dict[str, str]] = [
            # В RouterOS 7 порт называется on-interface, в шестёрке был interface
            {".id": "*1", "mac-address": "BC:24:11:F0:70:DB", "on-interface": "ether3",
             "vid": "10"},
            {".id": "*2", "mac-address": "C0:56:E3:11:22:33", "on-interface": "ether5"},
            {".id": "*3", "mac-address": "B0:FC:0D:F3:56:8F", "on-interface": "wlan1"},
            # Собственный интерфейс роутера: клиентом не является
            {".id": "*4", "mac-address": "CC:2D:E0:F2:4C:F3", "on-interface": "bridge",
             "local": "true"},
        ]
        # Подключённые по воздуху. Старый пакет wireless и новый wifi
        # отдают одно и то же разными командами.
        self.wireless_registrations: list[dict[str, str]] = [
            {".id": "*1", "mac-address": "B0:FC:0D:F3:56:8F", "interface": "wlan1",
             "ssid": "Magazin", "signal-strength": "-64"},
        ]
        self.ip_addresses: list[dict[str, str]] = [
            {".id": "*1", "address": "10.0.0.1/24", "interface": "ether1"},
        ]
        # --- паспорт устройства: порты, сервисы, соседи, датчики ---
        # librouteros превращает true/false в настоящие bool, поэтому здесь
        # они такие же: разбор обязан это учитывать.
        self.interfaces: list[dict[str, Any]] = [
            {".id": "*1", "name": "ether1", "type": "ether", "running": True,
             "disabled": False, "mac-address": "CC:2D:E0:F2:4C:F0", "comment": "uplink"},
            {".id": "*2", "name": "ether2", "type": "ether", "running": True,
             "disabled": False, "mac-address": "CC:2D:E0:F2:4C:F1"},
            {".id": "*3", "name": "ether3", "type": "ether", "running": False,
             "disabled": False, "mac-address": "CC:2D:E0:F2:4C:F2"},
            {".id": "*4", "name": "bridge", "type": "bridge", "running": True,
             "disabled": False},
            {".id": "*5", "name": "vlan-100", "type": "vlan", "running": True,
             "disabled": False, "vlan-id": "100", "interface": "bridge"},
        ]
        # В print скорости нет: там только настройка «что разрешено
        # согласовать», а на части плат нет и её. Договорённая скорость
        # живёт в monitor, как на настоящем hAP ac lite.
        self.ethernet: list[dict[str, Any]] = [
            {".id": "*1", "name": "ether1", "speed": "1Gbps", "full-duplex": True},
            {".id": "*2", "name": "ether2", "speed": "1Gbps", "full-duplex": True},
            {".id": "*3", "name": "ether3", "speed": "1Gbps"},
        ]
        self.ethernet_monitor: list[dict[str, Any]] = [
            {"name": "ether1", "status": "link-ok", "rate": "1Gbps"},
            {"name": "ether2", "status": "link-ok", "rate": "100Mbps"},
            {"name": "ether3", "status": "no-link"},
        ]
        self.poe: list[dict[str, Any]] = [
            {".id": "*2", "name": "ether2", "poe-out": "auto-on",
             "poe-out-status": "powered-on"},
        ]
        # В RouterOS 7.21 /ip/service отдаёт три разных вида записей сразу:
        # настроенные сервисы, динамические (их поднимает сам роутер)
        # и живые соединения к роутеру, у которых заполнены remote и local.
        # Панель обязана их различать, иначе собственное подключение
        # панели по api выглядит как открытый настежь порт.
        self.services: list[dict[str, Any]] = [
            {".id": "*0", "name": "telnet", "port": "23", "disabled": False, "address": ""},
            {".id": "*1", "name": "ftp", "port": "21", "disabled": True, "address": ""},
            {".id": "*2", "name": "www", "port": "80", "disabled": False,
             "address": "10.0.0.0/8"},
            {".id": "*3", "name": "ssh", "port": "22", "disabled": False, "address": ""},
            # Настроенный api закрыт списком сетей
            {".id": "*4", "name": "api", "port": "8728", "disabled": False,
             "address": "192.168.88.0/24,10.10.1.0/24"},
            # Соединение самой панели: адресов доступа у него нет по природе
            {".id": "*5", "name": "api", "port": "8728", "dynamic": True,
             "remote": "10.10.0.5:36027", "local": "192.168.88.1"},
            # Динамика, которую роутер поднял сам
            {".id": "*6", "name": "resolver", "port": "53", "dynamic": True},
            {".id": "*7", "name": "dhcpclient", "port": "68", "dynamic": True},
        ]
        self.neighbors: list[dict[str, Any]] = [
            {".id": "*1", "identity": "AP-Sklad", "address": "192.168.88.20",
             "mac-address": "48:8F:5A:11:22:33", "interface": "ether2",
             "platform": "MikroTik", "board": "cAP ac", "version": "7.14.3"},
        ]
        #: Показания датчиков. Форма ответа зависит от версии RouterOS,
        #: и это не мелочь: в семёрке health отдаёт строки name/value,
        #: в шестёрке одну запись с полями.
        self.health_rows: list[dict[str, Any]] = [
            {".id": "*0", "name": "temperature", "value": "57", "type": "C"},
            {".id": "*1", "name": "voltage", "value": "24.1", "type": "V"},
        ]
        self.health_legacy = False      # True = отвечать как RouterOS 6
        self.ip_routes: list[dict[str, str]] = [
            {".id": "*1", "dst-address": "0.0.0.0/0", "gateway": "10.0.0.254", "disabled": "false"},
        ]
        self.firewall: list[dict[str, str]] = [
            {".id": "*100", "chain": "input", "action": "drop", "comment": "drop all"},
            {".id": "*101", "chain": "forward", "action": "drop", "comment": "drop all"},
        ]

        self.ping_rtt_ms = 12           # какую задержку «показывает» устройство
        self.ping_lost = 0              # сколько пакетов из пачки теряется
        self.gateway = "10.0.0.254"     # шлюз по умолчанию
        self.pinged: list[str] = []     # что пинговали — для проверок в тестах
        self._next_id = 1

        # --- обновления RouterOS ---
        self.version = "7.14.3"
        self.channel = "stable"
        # Какую версию «видит» устройство в выбранном канале.
        # None означает, что обновлений нет.
        self.latest_version: str | None = None
        self.install_count = 0
        self.download_count = 0
        self.downloaded = False
        self.download_seconds = 0.0      # сколько «качаются» пакеты
        self.download_fails = False
        self.download_error = False
        self._download_done_at = 0.0
        self.free_space = 128 * 1024 * 1024
        # Задержка между командой reboot и реальным пропаданием связи
        self.reboot_delay = 0.0
        # Сколько секунд после /system/package/update/install устройство
        # «недоступно» (эмуляция перезагрузки)
        self.reboot_seconds = 0.0
        self._unavailable_until = 0.0
        self._unavailable_from = 0.0

        # --- RouterBOOT ---
        self.routerboard = True
        self.current_firmware = "7.14.3"
        self.upgrade_firmware = "7.14.3"

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, 0))
        self.server.listen(16)
        self.port: int = self.server.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    # ------------------------------------------------------------- запуск
    def start(self) -> "FakeRouter":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self.server.close()
        except OSError:
            pass

    def __enter__(self) -> "FakeRouter":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    # ------------------------------------------------------------ приём
    def _accept_loop(self) -> None:
        """
        Приём подключений.

        Во время «перезагрузки» слушающий сокет закрывается совсем — так же,
        как у настоящего выключенного устройства. Раньше заглушка продолжала
        принимать соединения и тут же их закрывать, из-за чего простая проверка
        доступности порта считала перезагружающееся устройство живым.
        """
        self.server.settimeout(0.2)
        while not self._stop.is_set():
            now = time.monotonic()
            if self._unavailable_from <= now < self._unavailable_until:
                self._close_listener()
                # Ждём окончания «перезагрузки» и снова открываем порт
                while not self._stop.is_set() and time.monotonic() < self._unavailable_until:
                    time.sleep(0.05)
                if self._stop.is_set():
                    return
                self._open_listener()
                continue

            try:
                conn, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                continue

            self.connections += 1
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _close_listener(self) -> None:
        """Закрыть слушающий сокет (устройство «ушло в перезагрузку»)."""
        try:
            self.server.close()
        except OSError:
            pass

    def _open_listener(self) -> None:
        """Снова открыть порт на том же номере («устройство поднялось»)."""
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((self.host, self.port))
        self.server.listen(16)
        self.server.settimeout(0.2)

    def _serve(self, conn: socket.socket) -> None:
        try:
            while not self._stop.is_set():
                sentence = self._read_sentence(conn)
                if not sentence:
                    return
                cmd, attrs = sentence[0], self._parse(sentence[1:])
                self.executed.append(cmd)
                try:
                    rows = self._handle(cmd, attrs)
                except _Trap as trap:
                    self._send(conn, "!trap", {"message": str(trap)})
                    self._send(conn, "!done", {})
                    continue
                for row in rows:
                    self._send(conn, "!re", row)
                self._send(conn, "!done", {})
        except (OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    # ------------------------------------------------------------- логика
    #: Что понимает /system logging action в этой версии RouterOS.
    #: Список закрытый намеренно: настоящий роутер отвечает «unknown
    #: parameter» на всё лишнее, и заглушка, принимающая что угодно,
    #: пропустит ровно ту ошибку, ради которой её и писали.
    LOGGING_ACTION_PARAMS = {
        ".id", "name", "target", "remote", "remote-port", "remote-protocol",
        "src-address", "syslog-facility", "syslog-severity", "syslog-time-format",
        "disk-file-name", "disk-lines-per-file", "disk-file-count",
        "memory-lines", "memory-stop-on-full", "email-to", "email-start-tls",
    }
    #: Появилось в седьмой версии вместо флага bsd-syslog из шестой
    LOGGING_ACTION_PARAMS_V7 = {"remote-log-format"}
    LOGGING_ACTION_PARAMS_V6 = {"bsd-syslog"}

    def _check_logging_params(self, attrs: dict[str, str]) -> None:
        """Отклонить параметры, которых эта версия RouterOS не знает."""
        allowed = set(self.LOGGING_ACTION_PARAMS)
        if self.version.startswith("6"):
            allowed |= self.LOGGING_ACTION_PARAMS_V6
        else:
            allowed |= self.LOGGING_ACTION_PARAMS_V7
        for key in attrs:
            if key not in allowed:
                raise _Trap("unknown parameter %s" % key)

    def _handle(self, cmd: str, attrs: dict[str, str]) -> list[dict[str, Any]]:
        if cmd == "/login":
            if attrs.get("name") != self.username or attrs.get("password") != self.password:
                raise _Trap("invalid user name or password (6)")
            # На реальном устройстве каждый вход попадает в /log — считаем их
            self.logins += 1
            return []

        if cmd == "/system/resource/print":
            return [{
                "version": f"{self.version} ({self.channel})",
                "uptime": "3w2d10:15:42",
                "board-name": "CCR2004-1G-12S+2XS",
                "architecture-name": "arm64",
                "cpu-load": "7",
                "free-memory": "1073741824",
                "free-hdd-space": str(self.free_space),
            }]

        # ----------------------------------------------------- обновления
        if cmd == "/system/package/update/set":
            self.channel = attrs.get("channel", self.channel)
            return []

        if cmd == "/system/package/update/check-for-updates":
            return []

        if cmd == "/system/package/update/print":
            latest = self.latest_version or self.version
            if self.downloaded:
                status = "Downloaded, please reboot for changes to take effect!"
            elif self._download_done_at and time.monotonic() < self._download_done_at:
                status = "Downloading..."
            elif self._download_done_at:
                # Загрузка «докачалась»
                self.downloaded = True
                self._download_done_at = 0.0
                status = "Downloaded, please reboot for changes to take effect!"
            elif latest != self.version:
                status = "New version is available"
            else:
                status = "System is already up to date"
            return [{
                "channel": self.channel,
                "installed-version": self.version,
                "latest-version": latest,
                "status": status,
            }]

        if cmd == "/system/package/update/download":
            if self.download_fails:
                self.downloaded = False
                self._download_done_at = 0.0
                self.download_error = True
                return []
            # Загрузка идёт download_seconds и НЕ перезагружает устройство
            self._download_done_at = time.monotonic() + self.download_seconds
            self.downloaded = self.download_seconds <= 0
            self.download_count += 1
            return []

        if cmd == "/system/package/update/install":
            # Старый путь: скачивает и сразу перезагружает. Больше не используется,
            # но оставлен, чтобы тест мог убедиться, что его не вызывают.
            self.install_count += 1
            if self.latest_version and self.latest_version != self.version:
                self.version = self.latest_version
            self._go_offline()
            return []

        if cmd == "/system/routerboard/print":
            if not self.routerboard:
                raise _Trap("no such command prefix")
            return [{
                "routerboard": "true",
                "current-firmware": self.current_firmware,
                "upgrade-firmware": self.upgrade_firmware,
            }]

        if cmd == "/system/routerboard/upgrade":
            self.current_firmware = self.upgrade_firmware
            return []

        if cmd == "/system/identity/print":
            return [{"name": self.identity}]

        if cmd == "/system/identity/set":
            self.identity = attrs.get("name", self.identity)
            return []

        # --------------------------------------------- отправка журнала
        if cmd == "/system/logging/action/print":
            return list(self.log_actions)

        if cmd == "/system/logging/action/add":
            self._check_logging_params(attrs)
            item = {k: v for k, v in attrs.items()}
            item[".id"] = "*%X" % (len(self.log_actions) + 1)
            self.log_actions.append(item)
            return []

        if cmd == "/system/logging/action/set":
            self._check_logging_params(attrs)
            for item in self.log_actions:
                if item[".id"] == attrs.get(".id"):
                    item.update({k: v for k, v in attrs.items() if k != ".id"})
            return []

        if cmd == "/system/logging/print":
            return list(self.log_rules)

        if cmd == "/system/logging/add":
            item = {k: v for k, v in attrs.items()}
            item[".id"] = "*%X" % (len(self.log_rules) + 1)
            self.log_rules.append(item)
            return []

        if cmd == "/system/logging/remove":
            if not any(r[".id"] == attrs.get(".id") for r in self.log_rules):
                raise _Trap("no such item")
            self.log_rules = [r for r in self.log_rules if r[".id"] != attrs.get(".id")]
            return []

        if cmd == "/system/logging/action/remove":
            target = attrs.get(".id")
            if not any(a[".id"] == target for a in self.log_actions):
                raise _Trap("no such item")
            # Как настоящий: пока на получателя ссылается правило, удалить нельзя
            names = {a["name"] for a in self.log_actions if a[".id"] == target}
            if any(str(r.get("action") or "") in names for r in self.log_rules):
                raise _Trap("action is in use")
            self.log_actions = [a for a in self.log_actions if a[".id"] != target]
            return []

        if cmd == "/system/reboot":
            self.rebooted = True
            # Скачанное обновление применяется именно при перезагрузке
            if self.downloaded and self.latest_version:
                self.version = self.latest_version
                self.downloaded = False
                self.install_count += 1
            self._go_offline()
            return []

        # ------------------------------------------------------- скрипты
        if cmd == "/system/script/print":
            return list(self.scripts)

        if cmd == "/system/script/add":
            script = {".id": self._id(), "name": attrs.get("name", ""),
                      "source": attrs.get("source", ""), "policy": attrs.get("policy", "")}
            self.scripts.append(script)
            return []

        if cmd == "/system/script/set":
            for script in self.scripts:
                if script[".id"] == attrs.get(".id"):
                    script.update({k: v for k, v in attrs.items() if k != ".id"})
                    return []
            raise _Trap("no such item")

        if cmd == "/system/script/run":
            if not any(s[".id"] == attrs.get(".id") for s in self.scripts):
                raise _Trap("no such item")
            # RouterOS не отвечает, пока скрипт не отработает — эмулируем задержку
            if self.script_run_seconds:
                time.sleep(self.script_run_seconds)
            return []

        if cmd == "/system/script/remove":
            self.scripts = [s for s in self.scripts if s[".id"] != attrs.get(".id")]
            return []

        # --------------------------------------------------------- файлы
        if cmd == "/file/print":
            return list(self.files)

        if cmd == "/file/remove":
            self.files = [f for f in self.files if f[".id"] != attrs.get(".id")]
            return []

        # ------------------------------------------- отложенные задачи
        if cmd == "/system/script/print":
            return list(self.scripts)

        if cmd == "/system/scheduler/print":
            return list(self.schedulers)

        if cmd == "/system/scheduler/add":
            self.schedulers.append({".id": self._new_id(), **attrs})
            return []

        if cmd == "/system/scheduler/remove":
            self.schedulers = [s for s in self.schedulers
                               if s[".id"] != attrs.get(".id")]
            return []

        if cmd == "/system/backup/load":
            # Настоящий роутер уходит в перезагрузку и обрывает соединение
            self.restored = True
            self.rebooted = True
            return []

        if cmd == "/system/backup/save":
            self.files.append({".id": self._id(), "name": attrs.get("name", "backup") + ".backup",
                               "size": "65536", "type": "backup"})
            return []

        if cmd == "/export":
            if "show-sensitive" in attrs:
                raise _Trap("unknown parameter show-sensitive")  # как на части версий ROS
            self.files.append({".id": self._id(), "name": attrs.get("file", "export") + ".rsc",
                               "size": "4096", "type": "script"})
            return []

        # ------------------------------------------------ проверка канала
        if cmd == "/ping":
            count = int(attrs.get("count", "1") or 1)
            address = attrs.get("address", "")
            lost = min(self.ping_lost, count)
            replied = count - lost
            rows: list[dict[str, Any]] = []
            for seq in range(count):
                if seq < replied:
                    rows.append({"seq": str(seq), "host": address, "size": "56",
                                 "ttl": "64", "time": f"{self.ping_rtt_ms}ms"})
                else:
                    rows.append({"seq": str(seq), "host": address, "status": "timeout"})
            # Последняя строка несёт итог, как на настоящем устройстве
            rows[-1].update({
                "sent": str(count),
                "received": str(replied),
                "packet-loss": str(int(100 * lost / count)) if count else "0",
                "min-rtt": f"{self.ping_rtt_ms}ms",
                "avg-rtt": f"{self.ping_rtt_ms}ms",
                "max-rtt": f"{self.ping_rtt_ms + 2}ms",
            })
            self.pinged.append(address)
            return rows

        if cmd == "/ip/route/print":
            rows = list(self.ip_routes)
            if not any(r.get("gateway") == "wg1" for r in rows):
                rows.append({".id": "*900", "dst-address": "10.0.0.0/8",
                             "gateway": "wg1", "disabled": "false"})
            for row in rows:
                if row.get("dst-address") == "0.0.0.0/0":
                    row["gateway"] = self.gateway
            return rows

        if cmd == "/ip/address/print":
            return list(self.ip_addresses)

        if cmd == "/ip/dhcp-server/lease/print":
            return list(self.dhcp_leases)

        if cmd == "/ip/arp/print":
            return list(self.arp_entries)

        if cmd == "/interface/bridge/host/print":
            return list(self.bridge_hosts)

        # ------------------------------------------------ паспорт устройства
        if cmd == "/interface/print":
            return list(self.interfaces)

        if cmd == "/interface/ethernet/print":
            return list(self.ethernet)

        if cmd == "/interface/ethernet/monitor":
            if "numbers" not in attrs:
                raise _Trap("no such item")
            wanted = [n for n in str(attrs["numbers"]).split(",") if n]
            return [row for row in self.ethernet_monitor if row["name"] in wanted]

        if cmd == "/interface/ethernet/poe/print":
            if not self.poe:
                # Коробка без PoE отвечает так же, как настоящая
                raise _Trap("no such command prefix")
            return list(self.poe)

        if cmd == "/ip/service/print":
            return list(self.services)

        if cmd == "/ip/neighbor/print":
            return list(self.neighbors)

        if cmd == "/system/health/print":
            if self.health_legacy:
                # RouterOS 6: одна запись со всеми полями сразу
                return [{".id": "*0", "temperature": "42", "voltage": "24.0"}]
            return list(self.health_rows)

        if cmd == "/interface/wireless/registration-table/print":
            return list(self.wireless_registrations)

        if cmd == "/interface/wifi/registration-table/print":
            # Нового пакета wifi на этом «устройстве» нет: так же ведёт
            # себя настоящий роутер со старым wireless
            raise _Trap("no such command prefix")

        # ---------------------------------------------------- WireGuard
        if cmd == "/interface/wireguard/print":
            return list(self.wg_interfaces)

        if cmd == "/interface/wireguard/peers/print":
            return list(self.wg_peers)

        if cmd == "/interface/wireguard/peers/add":
            peer = {".id": self._new_id(), **attrs}
            # Настоящий роутер отдаёт счётчики даже у молчащего пира
            peer.setdefault("rx", "0")
            peer.setdefault("tx", "0")
            self.wg_peers.append(peer)
            return []

        if cmd == "/interface/wireguard/peers/remove":
            self.wg_peers = [p for p in self.wg_peers if p[".id"] != attrs.get(".id")]
            return []

        if cmd == "/ip/address/add":
            self.ip_addresses.append({".id": self._new_id(), **attrs})
            return []

        if cmd == "/ip/address/set":
            for row in self.ip_addresses:
                if row[".id"] == attrs.get(".id"):
                    row.update({k: v for k, v in attrs.items() if k != ".id"})
            return []

        if cmd == "/ip/route/add":
            self.ip_routes.append({".id": self._new_id(), **attrs})
            return []

        if cmd == "/ip/route/set":
            for row in self.ip_routes:
                if row[".id"] == attrs.get(".id"):
                    row.update({k: v for k, v in attrs.items() if k != ".id"})
            return []

        if cmd == "/ip/route/remove":
            self.ip_routes = [r for r in self.ip_routes if r[".id"] != attrs.get(".id")]
            return []

        if cmd == "/ip/firewall/filter/print":
            return list(self.firewall)

        if cmd == "/ip/firewall/filter/add":
            rule = {".id": self._new_id(), **attrs}
            before = rule.pop("place-before", None)
            if before:
                index = next((i for i, r in enumerate(self.firewall)
                              if r[".id"] == before), len(self.firewall))
                self.firewall.insert(index, rule)
            else:
                self.firewall.append(rule)
            return []

        if cmd == "/ip/firewall/filter/remove":
            self.firewall = [r for r in self.firewall if r[".id"] != attrs.get(".id")]
            return []

        raise _Trap(f"no such command prefix ({cmd})")

    # ------------------------------------------------------------ утилиты
    def _new_id(self) -> str:
        """Очередной .id, как их выдаёт RouterOS."""
        self._next_id += 1
        return f"*{self._next_id:x}"

    def _go_offline(self) -> None:
        """
        Сделать устройство недоступным на reboot_seconds секунд.

        reboot_delay эмулирует запаздывание: RouterOS не всегда пропадает
        со связи мгновенно после команды.
        """
        if self.reboot_seconds > 0:
            start = time.monotonic() + self.reboot_delay
            self._unavailable_until = start + self.reboot_seconds
            if self.reboot_delay > 0:
                self._unavailable_from = start

    def _id(self) -> str:
        value = f"*{self._next_id:X}"
        self._next_id += 1
        return value

    @staticmethod
    def _parse(words: tuple[str, ...]) -> dict[str, str]:
        """Разобрать слова вида «=ключ=значение» в словарь."""
        result: dict[str, str] = {}
        for word in words:
            if word.startswith("="):
                key, _, value = word[1:].partition("=")
                result[key] = value
        return result

    def _read_sentence(self, conn: socket.socket) -> tuple[str, ...]:
        words: list[str] = []
        while True:
            word = self._read_word(conn)
            if word == "":
                return tuple(words)
            words.append(word)

    def _read_word(self, conn: socket.socket) -> str:
        first = self._recv(conn, 1)
        if not first:
            raise OSError("соединение закрыто")
        if first == b"\x00":
            return ""
        extra = self.codec.determineLength(first)
        raw = first + self._recv(conn, extra)
        length = self.codec.decodeLength(raw)
        return self._recv(conn, length).decode("utf-8", "ignore")

    @staticmethod
    def _recv(conn: socket.socket, count: int) -> bytes:
        buf = b""
        while len(buf) < count:
            chunk = conn.recv(count - len(buf))
            if not chunk:
                raise OSError("соединение закрыто")
            buf += chunk
        return buf

    def _send(self, conn: socket.socket, reply: str, attrs: dict[str, Any]) -> None:
        words = [reply] + [f"={k}={v}" for k, v in attrs.items()]
        conn.sendall(self.codec.encodeSentence(*words))


class _Trap(Exception):
    """Ошибка уровня RouterOS (отправляется клиенту как !trap)."""


class FakeFtp:
    """
    Минимальный FTP-сервер (только чтение) для проверки скачивания бэкапов.

    Реализовано ровно столько, сколько использует ftplib: USER/PASS, TYPE,
    PASV и RETR. Содержимое файлов задаётся словарём `files`.
    """

    def __init__(self, files: dict[str, bytes], username: str = "tikpilot",
                 password: str = "s3cret", host: str = "127.0.0.1") -> None:
        self.files = files
        self.username = username
        self.password = password
        self.host = host

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((host, 0))
        self.server.listen(8)
        self.port: int = self.server.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    def start(self) -> "FakeFtp":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        try:
            self.server.close()
        except OSError:
            pass

    def __enter__(self) -> "FakeFtp":
        return self.start()

    def __exit__(self, *_exc) -> None:
        self.stop()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn: socket.socket) -> None:
        data_sock: socket.socket | None = None
        try:
            reader = conn.makefile("rb")
            conn.sendall(b"220 FakeRouterOS FTP\r\n")
            while True:
                line = reader.readline()
                if not line:
                    return
                parts = line.decode("utf-8", "ignore").strip().split(" ", 1)
                cmd = parts[0].upper()
                arg = parts[1] if len(parts) > 1 else ""

                if cmd == "USER":
                    conn.sendall(b"331 need password\r\n")
                elif cmd == "PASS":
                    ok = arg == self.password
                    conn.sendall(b"230 logged in\r\n" if ok else b"530 login incorrect\r\n")
                elif cmd in ("TYPE", "MODE", "STRU", "OPTS", "NOOP"):
                    conn.sendall(b"200 ok\r\n")
                elif cmd == "PASV":
                    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    data_sock.bind((self.host, 0))
                    data_sock.listen(1)
                    port = data_sock.getsockname()[1]
                    host_part = self.host.replace(".", ",")
                    conn.sendall(
                        f"227 Entering Passive Mode ({host_part},{port >> 8},{port & 0xFF})\r\n".encode()
                    )
                elif cmd == "RETR":
                    payload = self.files.get(arg)
                    if payload is None or data_sock is None:
                        conn.sendall(b"550 no such file\r\n")
                        continue
                    conn.sendall(b"150 opening data connection\r\n")
                    channel, _ = data_sock.accept()
                    channel.sendall(payload)
                    channel.close()
                    data_sock.close()
                    data_sock = None
                    conn.sendall(b"226 transfer complete\r\n")
                elif cmd == "QUIT":
                    conn.sendall(b"221 bye\r\n")
                    return
                else:
                    conn.sendall(b"502 not implemented\r\n")
        except OSError:
            pass
        finally:
            for sock in (data_sock, conn):
                try:
                    if sock:
                        sock.close()
                except OSError:
                    pass
