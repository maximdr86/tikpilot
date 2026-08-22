"""
Тонкая обёртка над RouterOS API (librouteros) + загрузка файлов по FTP.

Здесь сосредоточена вся «сетевая» логика общения с устройством:
подключение, чтение системной информации, выполнение команд,
загрузка/выгрузка скриптов и скачивание бэкапов.

Все методы бросают DeviceError с понятным русским текстом —
воркер просто записывает его в результат задачи.
"""

from __future__ import annotations

import re
import socket
import ssl
import time
from contextlib import contextmanager
from ftplib import FTP, all_errors as FTP_ERRORS
from pathlib import Path
from typing import Any, Iterable

from librouteros import connect
from librouteros.exceptions import LibRouterosError, MultiTrapError, TrapError

from .config import settings


class DeviceError(Exception):
    """Любая ошибка взаимодействия с устройством (с человекочитаемым текстом)."""


def _friendly(exc: Exception) -> str:
    """Перевести типовые сетевые исключения в понятное сообщение."""
    if isinstance(exc, socket.timeout):
        return "Таймаут подключения"
    if isinstance(exc, ConnectionRefusedError):
        return "Соединение отклонено (API-сервис выключен или другой порт?)"
    if isinstance(exc, ConnectionResetError):
        # Самый частый случай на живом парке, и по голому «Errno 104»
        # его не опознать. RouterOS принимает соединение и обрывает его
        # сразу же, если адрес источника не входит в список у службы.
        # Порт при этом снаружи выглядит открытым: проверка вида
        # `nc -vz` доходит только до рукопожатия и рапортует об успехе.
        #
        # Особенно любит вылезать при переключении на резервный канал:
        # путь другой, адрес источника другой, а список остался прежним.
        return ("Роутер разорвал соединение сразу после подключения. "
                "Обычно это список адресов у службы: проверьте "
                "/ip service print detail, разрешён ли адрес панели")
    if isinstance(exc, socket.gaierror):
        return "Не удалось разрешить имя хоста"
    if isinstance(exc, OSError) and getattr(exc, "errno", None) in (113, 101, 111):
        return "Хост недоступен"
    if isinstance(exc, LibRouterosError):
        text = str(exc)
        lowered = text.lower()
        # Типовые ответы RouterOS переводим на русский
        if "invalid user name or password" in lowered or "cannot log in" in lowered:
            return "Неверный логин или пароль"
        if "not logged in" in lowered:
            return "Сессия не авторизована (проверьте политику api у пользователя)"
        if "no permissions" in lowered or "not enough permissions" in lowered:
            return f"Недостаточно прав у пользователя: {text}"
        if isinstance(exc, (TrapError, MultiTrapError)):
            return f"RouterOS отклонил команду: {text}"
        return f"Ошибка API: {text}"
    return f"{type(exc).__name__}: {exc}"


class MikroTik:
    """
    Подключение к одному устройству.

    Используется как контекстный менеджер:

        with MikroTik(device) as mt:
            info = mt.system_info()
    """

    def __init__(self, device: dict[str, Any], password: str, timeout: int | None = None) -> None:
        self.device = device
        self.host: str = device["host"]
        self.port: int = int(device.get("api_port") or 8728)
        self.ftp_port: int = int(device.get("ftp_port") or 21)
        self.username: str = device["username"]
        self.password: str = password
        self.use_ssl: bool = bool(device.get("use_ssl"))
        self.timeout: int = timeout or settings.api_timeout
        self.api = None
        # Признак работоспособности соединения. Сбрасывается, когда ошибка
        # связана с сетью, а не с отказом RouterOS выполнить команду.
        # По нему пул сессий решает, можно ли переиспользовать соединение.
        self.alive: bool = False

    # ------------------------------------------------------------- жизненный цикл
    def __enter__(self) -> "MikroTik":
        self.open()
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def open(self) -> None:
        """Установить соединение и авторизоваться."""
        # RouterOS принимает только ASCII в логине и пароле. Проверяем заранее,
        # иначе librouteros падает с непонятным UnicodeEncodeError.
        for value, label in ((self.username, "Логин"), (self.password, "Пароль")):
            if not value.isascii():
                raise DeviceError(
                    f"{label} содержит не-ASCII символы, RouterOS такие не принимает. "
                    "Используйте латиницу, цифры и знаки пунктуации."
                )

        kwargs: dict[str, Any] = {"port": self.port, "timeout": self.timeout}
        if self.use_ssl:
            # api-ssl: сертификаты MikroTik по умолчанию самоподписанные,
            # поэтому проверку отключаем, шифрование канала при этом работает.
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_ciphers("ADH:@SECLEVEL=0")
            kwargs["ssl_wrapper"] = ctx.wrap_socket
        try:
            self.api = connect(
                host=self.host,
                username=self.username,
                password=self.password,
                # librouteros по умолчанию кодирует команды в ASCII, а RouterOS
                # понимает UTF-8. Без этого любое русское слово в комментарии
                # или имени скрипта роняло команду с UnicodeEncodeError.
                encoding="utf-8",
                **kwargs,
            )
        except Exception as exc:  # noqa: BLE001 — хотим единый понятный текст
            self.alive = False
            raise DeviceError(_friendly(exc)) from exc
        self.alive = True

    def close(self) -> None:
        """Закрыть соединение, не поднимая исключений."""
        try:
            if self.api is not None:
                self.api.close()
        except Exception:  # noqa: BLE001
            pass
        finally:
            self.api = None
            self.alive = False

    # ------------------------------------------------------------- таймауты
    def set_timeout(self, seconds: int) -> None:
        """
        Сменить таймаут уже открытого соединения.

        Недостаточно поменять поле объекта: значение задано на самом сокете
        в момент подключения, поэтому меняем и его.
        """
        self.timeout = seconds
        try:
            self.api.protocol.transport.sock.settimeout(seconds)  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass

    @contextmanager
    def extended_timeout(self, seconds: int):
        """
        Временно увеличить таймаут — для команд, которые заведомо долгие.

        Главный пример: /system/script/run не возвращает управление, пока скрипт
        не отработает. Бэкап или выгрузка конфигурации могут занять минуты,
        и обычных 10 секунд там категорически не хватает.
        """
        previous = self.timeout
        self.set_timeout(max(seconds, previous))
        try:
            yield
        finally:
            self.set_timeout(previous)

    # --------------------------------------------------------------- примитивы
    def cmd(self, command: str, **kwargs: Any) -> list[dict[str, Any]]:
        """
        Выполнить команду API и вернуть список словарей-ответов.

        Пример: mt.cmd('/ip/address/print')
                mt.cmd('/system/script/run', **{'.id': '*1'})
        """
        try:
            return list(self.api(command, **kwargs))
        except (TrapError, MultiTrapError) as exc:
            # RouterOS отказался выполнять команду — само соединение при этом живо.
            #
            # MultiTrapError здесь не для красоты: это тот же отказ, только
            # роутер прислал две ловушки вместо одной, а в librouteros этот
            # класс наследуется не от TrapError, а от ProtocolError. Пока его
            # не ловили отдельно, обычное «no such command or directory» на
            # коробке без датчиков считалось сетевым сбоем: сессия объявлялась
            # мёртвой и переоткрывалась, а с версии 1.49 ещё и обрывала обход
            # паспорта целиком.
            raise DeviceError(_friendly(exc)) from exc
        except socket.timeout as exc:
            # Подключение было в порядке — не дождались ответа на саму команду.
            # Важно не называть это «таймаутом подключения»: причина другая.
            self.alive = False
            raise DeviceError(
                f"Устройство не ответило на команду {command} за {self.timeout} с. "
                "Сама команда, скорее всего, продолжает выполняться на устройстве."
            ) from exc
        except Exception as exc:  # noqa: BLE001
            # Сетевая ошибка: соединение больше использовать нельзя
            self.alive = False
            raise DeviceError(_friendly(exc)) from exc

    def cmd_fire_and_forget(self, command: str, **kwargs: Any) -> None:
        """
        Выполнить команду, после которой устройство может разорвать соединение
        (например, /system/reboot). Разрыв здесь — ожидаемое поведение.
        """
        try:
            list(self.api(command, **kwargs))
        except (TrapError, MultiTrapError) as exc:
            raise DeviceError(_friendly(exc)) from exc
        except Exception:  # noqa: BLE001 — обрыв связи считаем успехом
            self.alive = False

    # ------------------------------------------------------------ информация
    def system_info(self) -> dict[str, str]:
        """Собрать базовую информацию: версия, uptime, модель, загрузка."""
        info: dict[str, str] = {}
        res = self.cmd("/system/resource/print")
        if res:
            r = res[0]
            info["ros_version"] = str(r.get("version", ""))
            info["uptime"] = str(r.get("uptime", ""))
            info["board_name"] = str(r.get("board-name", ""))
            info["cpu_load"] = str(r.get("cpu-load", ""))
            info["free_memory"] = _human_bytes(r.get("free-memory"))
            info["architecture"] = str(r.get("architecture-name", ""))
            info["free_space"] = _human_bytes(r.get("free-hdd-space"))
            info["free_space_bytes"] = str(r.get("free-hdd-space", "") or "")
            info["free_memory_bytes"] = str(r.get("free-memory", "") or "")
            # Всего памяти на плате. Без этого числа свободные 11 МиБ
            # не значат ничего: на hAP lite с его 32 МиБ это треть,
            # а на CCR с гигабайтом это повод ехать
            info["total_memory_bytes"] = str(r.get("total-memory", "") or "")
        try:
            ident = self.cmd("/system/identity/print")
            if ident:
                info["identity"] = str(ident[0].get("name", ""))
        except DeviceError:
            info["identity"] = ""
        return info

    # ------------------------------------------------------- обновления ROS
    def update_info(self, set_channel: str = "", wait: int = 25) -> dict[str, str]:
        """
        Узнать у устройства, есть ли обновление RouterOS.

        Устройство само обращается к серверам MikroTik, поэтому ответ приходит
        не сразу — опрашиваем /system/package/update/print, пока статус не
        перестанет быть «finding out latest version...».

        :param set_channel: если задан — сначала переключить канал обновлений.
        :returns: словарь с ключами channel, installed-version, latest-version, status.
        """
        if set_channel:
            self.cmd("/system/package/update/set", **{"channel": set_channel})

        try:
            self.cmd("/system/package/update/check-for-updates")
        except DeviceError:
            # На некоторых версиях команда отвечает трапом, но проверку всё же запускает
            pass

        row: dict[str, Any] = {}
        deadline = time.monotonic() + max(wait, 1)
        while time.monotonic() < deadline:
            rows = self.cmd("/system/package/update/print")
            if rows:
                row = rows[0]
                status = str(row.get("status", "")).lower()
                if status and "finding out" not in status and "checking" not in status:
                    break
            time.sleep(1.5)

        return {k: str(v) for k, v in row.items()}

    def download_update(self, timeout: int = 1800, poll_interval: int | None = None) -> str:
        """
        Скачать обновление на устройство, **не перезагружая его**.

        Ключевой момент для медленных каналов. Команда install скачивает пакеты
        и сразу уходит в перезагрузку, поэтому момент ухода непредсказуем:
        на тонком канале загрузка идёт минутами. Здесь загрузка отделена от
        установки — устройство всё это время остаётся на связи, а если что-то
        пойдёт не так, оно просто продолжит работать на старой версии.

        Возвращает итоговый статус, сообщённый устройством.

        :raises DeviceError: при ошибке загрузки или если она не завершилась
            за отведённое время.
        """
        if poll_interval is None:
            poll_interval = settings.update_poll_interval

        self.cmd("/system/package/update/download")

        deadline = time.monotonic() + max(timeout, poll_interval)
        last_status = ""
        while time.monotonic() < deadline:
            rows = self.cmd("/system/package/update/print")
            last_status = str(rows[0].get("status", "")) if rows else ""
            lowered = last_status.lower()

            if "error" in lowered or "fail" in lowered:
                raise DeviceError(_download_error(last_status))
            # RouterOS сообщает об успехе фразой вида
            # «Downloaded, please reboot for changes to take effect!»
            if "reboot" in lowered or "downloaded" in lowered:
                return last_status
            time.sleep(poll_interval)

        raise DeviceError(
            f"Обновление не докачалось за {timeout} с (последний статус: "
            f"{last_status or 'нет ответа'}). Устройство работает на прежней версии, "
            "попробуйте увеличить время загрузки или обновить эту точку отдельно."
        )

    # ------------------------------------------------------- проверка канала
    def ping(self, address: str, count: int = 5, timeout: int | None = None) -> dict[str, Any]:
        """
        Пропинговать адрес **с самого устройства**.

        Это принципиально: пинг с сервера покажет только состояние канала до
        точки, а пинг с точки — состояние её собственного канала наружу.
        Именно так видно, что канал деградирует, ещё до того как точка отвалится.

        Возвращает словарь: sent, received, loss (проценты), rtt_min/avg/max (мс).

        RouterOS не отвечает, пока не отправит все пакеты, поэтому на время
        команды таймаут увеличивается.
        """
        wait = timeout or (count + 8)
        with self.extended_timeout(wait):
            rows = self.cmd("/ping", **{"address": address, "count": str(count)})

        result: dict[str, Any] = {
            "sent": 0, "received": 0, "loss": None,
            "rtt_min": None, "rtt_avg": None, "rtt_max": None,
        }
        if not rows:
            return result

        # В последней строке RouterOS присылает итог; если его нет — считаем сами
        summary = rows[-1]
        result["sent"] = _to_int(summary.get("sent"), len(rows))
        result["received"] = _to_int(summary.get("received"), _count_replies(rows))
        result["rtt_min"] = _parse_rtt(summary.get("min-rtt"))
        result["rtt_avg"] = _parse_rtt(summary.get("avg-rtt"))
        result["rtt_max"] = _parse_rtt(summary.get("max-rtt"))

        if summary.get("packet-loss") is not None:
            result["loss"] = _to_float(summary.get("packet-loss"))
        elif result["sent"]:
            result["loss"] = round(100.0 * (result["sent"] - result["received"]) / result["sent"], 1)

        # На части версий итога нет — берём времена из отдельных ответов
        if result["rtt_avg"] is None:
            times = [t for t in (_parse_rtt(r.get("time")) for r in rows) if t is not None]
            if times:
                result["rtt_min"] = min(times)
                result["rtt_avg"] = round(sum(times) / len(times), 2)
                result["rtt_max"] = max(times)

        return result

    def default_gateway(self) -> str:
        """
        Найти шлюз по умолчанию — его полезно пинговать на каждой точке.

        Берётся **активный** маршрут 0.0.0.0/0 с наименьшей метрикой: на точках
        с резервным каналом маршрутов несколько, и запасной обычно неактивен.

        Если шлюз задан именем интерфейса (частый случай для туннелей),
        возвращается пустая строка — пинговать имя интерфейса бессмысленно.
        """
        try:
            routes = self.cmd("/ip/route/print")
        except DeviceError:
            return ""

        candidates: list[tuple[int, str]] = []
        for row in routes:
            if str(row.get("dst-address", "")) != "0.0.0.0/0":
                continue
            if str(row.get("disabled", "false")).lower() == "true":
                continue
            # Неактивный маршрут трафик не несёт — его шлюз ни о чём не говорит
            if str(row.get("active", "true")).lower() == "false":
                continue

            gateway = str(row.get("gateway", "")).split(",")[0].strip()
            # Годится только адрес, не имя интерфейса
            if not gateway or not re.fullmatch(r"[0-9.]+|[0-9a-fA-F:]+", gateway):
                continue
            candidates.append((_to_int(row.get("distance"), 1), gateway))

        if not candidates:
            return ""
        candidates.sort(key=lambda item: item[0])
        return candidates[0][1]

    def routerboard_info(self) -> dict[str, str]:
        """Сведения о загрузчике RouterBOOT (текущая и доступная версии)."""
        rows = self.cmd("/system/routerboard/print")
        return {k: str(v) for k, v in rows[0].items()} if rows else {}

    def port_open(self, timeout: int = 3) -> bool:
        """Отвечает ли порт API. Используется для отслеживания перезагрузки."""
        try:
            with socket.create_connection((self.host, self.port), timeout=timeout):
                return True
        except OSError:
            return False

    def wait_until_down(self, timeout: int = 240, probe_interval: int | None = None) -> int:
        """
        Дождаться, пока устройство действительно уйдёт в перезагрузку.

        Без этого шага легко обмануться: на медленном канале RouterOS сначала
        минутами качает пакеты и всё это время исправно отвечает. Если сразу
        начать ждать «возврата», устройство ответит ещё до перезагрузки, и
        обновление будет ошибочно объявлено неудачным.

        Возвращает, сколько секунд прошло до пропадания связи.

        :raises DeviceError: если устройство так и не ушло в перезагрузку.
        """
        if probe_interval is None:
            probe_interval = max(1, settings.reboot_probe_interval // 2)

        self.close()
        started = time.monotonic()
        deadline = started + timeout
        while time.monotonic() < deadline:
            if not self.port_open(timeout=3):
                return int(time.monotonic() - started)
            time.sleep(probe_interval)

        raise DeviceError(
            f"Устройство не ушло в перезагрузку за {timeout} с: "
            "команда перезагрузки не сработала либо она отложена самим RouterOS"
        )

    def wait_until_back(self, timeout: int = 420, probe_interval: int | None = None,
                        initial_delay: int | None = None) -> int:
        """
        Дождаться, пока устройство перезагрузится и снова начнёт отвечать.

        Соединение закрывается, затем выполняются короткие попытки подключения.
        Возвращает, сколько секунд заняло ожидание.

        Паузы настраиваются переменными REBOOT_INITIAL_DELAY и
        REBOOT_PROBE_INTERVAL — значения по умолчанию подобраны под реальное
        железо, где перезагрузка занимает больше минуты.

        :raises DeviceError: если устройство не вернулось за отведённое время.
        """
        if probe_interval is None:
            probe_interval = settings.reboot_probe_interval
        if initial_delay is None:
            initial_delay = settings.reboot_initial_delay

        self.close()
        started = time.monotonic()
        time.sleep(initial_delay)          # даём устройству реально уйти в ребут

        # На время ожидания используем короткий таймаут, чтобы чаще пробовать
        original_timeout, self.timeout = self.timeout, min(self.timeout, 5)
        last_error = "нет ответа"
        try:
            deadline = started + timeout
            while time.monotonic() < deadline:
                try:
                    self.open()
                    return int(time.monotonic() - started)
                except DeviceError as exc:
                    last_error = str(exc)
                    time.sleep(probe_interval)
        finally:
            self.timeout = original_timeout

        raise DeviceError(
            f"Устройство не вернулось после перезагрузки за {timeout} с "
            f"(последняя ошибка: {last_error}). Мониторинг продолжит следить за ним: "
            "если точка поднимется позже, это будет видно в истории её доступности."
        )

    # -------------------------------------------------------------- скрипты
    def list_scripts(self) -> list[dict[str, Any]]:
        """Список скриптов на устройстве."""
        return self.cmd("/system/script/print")

    def find_script_id(self, name: str) -> str | None:
        """Найти .id скрипта по имени."""
        for row in self.list_scripts():
            if row.get("name") == name:
                return str(row.get(".id"))
        return None

    def run_script_by_name(self, name: str, wait_seconds: int = 120) -> str:
        """
        Запустить существующий на устройстве скрипт по имени.

        RouterOS не возвращает управление, пока скрипт не отработает, поэтому
        на время выполнения таймаут поднимается до wait_seconds.
        """
        script_id = self.find_script_id(name)
        if script_id is None:
            raise DeviceError(f"Скрипт «{name}» на устройстве не найден")
        with self.extended_timeout(wait_seconds):
            self.cmd("/system/script/run", **{".id": script_id})
        return f"Скрипт «{name}» выполнен"

    def remove_named(self, name: str, kind: str = "script") -> int:
        """
        Удалить с устройства скрипты или расписания с указанным именем.

        Возвращает количество удалённых записей. Ноль это не ошибка:
        удаление запускается сразу на группе точек, и на части из них
        записи может не быть. Отдельная жалоба на каждую такую точку
        только мешала бы увидеть настоящие сбои.

        Имён-дубликатов RouterOS не запрещает, поэтому удаляем все
        совпадения, а не первое.
        """
        path = "/system/scheduler" if kind == "scheduler" else "/system/script"
        rows = self.cmd(f"{path}/print")
        ids = [str(row.get(".id")) for row in rows if row.get("name") == name]
        for item_id in ids:
            self.cmd(f"{path}/remove", **{".id": item_id})
        return len(ids)

    def upload_script(self, name: str, source: str, policy: str = "read,write,policy,test,ftp,reboot") -> str:
        """
        Создать (или перезаписать) скрипт на устройстве.

        Если скрипт с таким именем уже есть — обновляется его тело.
        """
        existing = self.find_script_id(name)
        if existing:
            self.cmd("/system/script/set", **{".id": existing, "source": source, "policy": policy})
            return f"Скрипт «{name}» обновлён"
        self.cmd("/system/script/add", **{"name": name, "source": source, "policy": policy})
        return f"Скрипт «{name}» загружен"

    def run_source(self, source: str, keep_name: str | None = None,
                   wait_seconds: int = 120) -> str:
        """
        Выполнить произвольный код скрипта.

        RouterOS API не умеет «выполнить строку», поэтому создаётся временный
        скрипт, запускается и (если не просили сохранить) удаляется.
        """
        name = keep_name or f"tikpilot-tmp-{_rand_suffix()}"
        temporary = keep_name is None
        self.upload_script(name, source)
        try:
            script_id = self.find_script_id(name)
            with self.extended_timeout(wait_seconds):
                self.cmd("/system/script/run", **{".id": script_id})
        finally:
            if temporary:
                try:
                    sid = self.find_script_id(name)
                    if sid:
                        self.cmd("/system/script/remove", **{".id": sid})
                except DeviceError:
                    pass
        return "Скрипт выполнен"

    # --------------------------------------------------------------- файлы
    def list_files(self) -> list[dict[str, Any]]:
        """Список файлов на устройстве."""
        return self.cmd("/file/print")

    def remove_file(self, filename: str) -> None:
        """Удалить файл с устройства (ошибки игнорируются)."""
        try:
            for row in self.cmd("/file/print"):
                if row.get("name") == filename:
                    self.cmd("/file/remove", **{".id": str(row.get(".id"))})
                    return
        except DeviceError:
            pass

    # ------------------------------------------------------- тест скорости
    def bandwidth_server(self) -> dict[str, Any]:
        """
        Настройки встроенного сервера btest: включён ли он и требует ли пароль.

        Нужно, чтобы вернуть цель в прежнее состояние. Сервер по умолчанию
        включён не на всех платах и не во всех версиях, а оставлять его
        включённым после измерения нельзя: это открытая дверь, через
        которую любой, кто знает логин, может занять канал целиком.
        """
        rows = self.cmd("/tool/bandwidth-server/print")
        return dict(rows[0]) if rows else {}

    def set_bandwidth_server(self, enabled: bool, authenticate: bool = True) -> None:
        """Включить или выключить сервер btest."""
        self.cmd(
            "/tool/bandwidth-server/set",
            **{
                "enabled": "yes" if enabled else "no",
                "authenticate": "yes" if authenticate else "no",
            },
        )

    def bandwidth_test(self, address: str, duration: int = 10,
                       direction: str = "receive", user: str = "",
                       password: str = "", protocol: str = "tcp",
                       limit_mbps: int = 0) -> dict[str, Any]:
        """
        Померить скорость **с этого устройства** до указанного адреса.

        Смысл тот же, что у пинга с точки: канал до площадки со стороны
        сервера и канал самой площадки это разные вещи, и полосу надо
        мерить оттуда, где она нужна.

        Направление `receive` означает «цель шлёт, мы принимаем», то есть
        скорость загрузки на точку. Это самое частое: жалуются обычно на
        то, что на кассе долго открывается страница.

        Возвращает словарь: rx, tx (биты в секунду, средние за тест),
        lost, duration, status. Значений может не быть вовсе, если
        RouterOS оборвал тест на первой же секунде.
        """
        seconds = max(1, min(60, int(duration)))
        params: dict[str, str] = {
            "address": address,
            "duration": f"{seconds}s",
            "direction": direction,
            "protocol": protocol,
        }
        if user:
            params["user"] = user
            params["password"] = password
        if limit_mbps:
            # Ограничение ставится на обе стороны: какая из них шлёт,
            # зависит от направления, а лишний параметр RouterOS не смущает
            rate = str(int(limit_mbps) * 1_000_000)
            params["local-tx-speed"] = rate
            params["remote-tx-speed"] = rate

        # Команда возвращает управление только когда тест закончился,
        # плюс запас на установление соединения и на ответ
        with self.extended_timeout(seconds + 20):
            rows = self.cmd("/tool/bandwidth-test", **params)

        if not rows:
            return {"rx": None, "tx": None, "lost": None,
                    "duration": seconds, "status": ""}

        # Промежуточные строки RouterOS шлёт каждую секунду, итог в последней.
        # Берём последнюю со статусом «done», иначе просто последнюю: тест
        # мог оборваться, и тогда честнее показать, что успели намерить
        final = rows[-1]
        for row in reversed(rows):
            if "done" in str(row.get("status") or ""):
                final = row
                break

        return {
            "rx": _to_float(final.get("rx-total-average")),
            "tx": _to_float(final.get("tx-total-average")),
            "lost": _to_int(final.get("lost-packets"), 0),
            "duration": final.get("duration") or f"{seconds}s",
            "status": str(final.get("status") or ""),
        }

    def download_via_ftp(self, remote_name: str, local_path: Path) -> int:
        """
        Скачать файл с устройства по FTP (встроенный FTP-сервер RouterOS).

        Возвращает размер полученного файла в байтах.
        """
        try:
            ftp = FTP()
            ftp.connect(self.host, self.ftp_port, timeout=settings.ftp_timeout)
            ftp.login(self.username, self.password)
            ftp.set_pasv(True)
            local_path.parent.mkdir(parents=True, exist_ok=True)
            with local_path.open("wb") as fh:
                ftp.retrbinary(f"RETR {remote_name}", fh.write)
            try:
                ftp.quit()
            except Exception:  # noqa: BLE001
                ftp.close()
        except FTP_ERRORS as exc:
            raise DeviceError(f"FTP: не удалось скачать {remote_name} ({exc})") from exc
        except OSError as exc:
            raise DeviceError(f"FTP: {_friendly(exc)}") from exc
        return local_path.stat().st_size


# ------------------------------------------------------------------ помощники
def _human_bytes(value: Any) -> str:
    """Байты → человекочитаемый вид (MiB/GiB)."""
    try:
        num = float(value)
    except (TypeError, ValueError):
        return ""
    for unit in ("Б", "КиБ", "МиБ", "ГиБ"):
        if num < 1024:
            return f"{num:.1f} {unit}"
        num /= 1024
    return f"{num:.1f} ТиБ"


def _rand_suffix(length: int = 8) -> str:
    """Случайный суффикс для имён временных объектов."""
    import secrets

    return secrets.token_hex(length // 2)


def _download_error(status: str) -> str:
    """
    Превратить ответ RouterOS об ошибке загрузки в полезное сообщение.

    Отдельно разбираем нехватку места: на устройствах с 16 МиБ флеш-памяти
    (hAP lite, hAP ac lite и подобные) свободного места после установки
    RouterOS остаётся меньше двух мегабайт, и пакет туда попросту не влезает.
    Точные цифры знает только само устройство — они уже есть в его ответе,
    остаётся добавить, что с этим делать.
    """
    text = f"Загрузка обновления не удалась: {status}"
    lowered = status.lower()
    if "space" in lowered or "disk" in lowered:
        text += (
            ". Не хватает места во флеш-памяти. Удалите с устройства лишние файлы "
            "(старые .npk и бэкапы в /file), либо обновляйте отдельными пакетами "
            "из набора Extra packages, либо через netinstall."
        )
    return text


# ------------------------------------------------------------ разбор ответов
def _parse_rtt(value: Any) -> float | None:
    """
    Время из ответа RouterOS → миллисекунды.

    Форматы бывают разные: «1ms», «1ms500us», «980us», «12s».
    """
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None

    # Просто число — считаем миллисекундами
    try:
        return round(float(text), 2)
    except ValueError:
        pass

    units = {"us": 0.001, "ms": 1.0, "s": 1000.0, "m": 60000.0}
    total = 0.0
    found = False
    for number, unit in re.findall(r"(\d+(?:\.\d+)?)(us|ms|s|m)", text):
        total += float(number) * units[unit]
        found = True
    return round(total, 2) if found else None


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _to_float(value: Any) -> float | None:
    try:
        return round(float(str(value).strip().rstrip("%")), 1)
    except (TypeError, ValueError):
        return None


def _count_replies(rows: list[dict[str, Any]]) -> int:
    """Сколько ответов реально пришло (у неудачных пакетов нет времени)."""
    return sum(1 for r in rows if r.get("time") and not str(r.get("status", "")).strip())


# --------------------------------------------------------------- версии ROS
def parse_version(value: Any) -> tuple[int, ...]:
    """
    Разобрать версию RouterOS в кортеж чисел для сравнения.

        «7.23.1 (stable)» → (7, 23, 1)
        «7.21.5»          → (7, 21, 5)
        «7.24beta3»       → (7, 24)

    Пометка канала в скобках и буквенные суффиксы отбрасываются.
    Пустая строка даёт пустой кортеж — такие версии считаем неизвестными.
    """
    text = re.sub(r"\s*\(.*?\)\s*", "", str(value or "")).strip()
    parts: list[int] = []
    for chunk in text.split("."):
        match = re.match(r"(\d+)", chunk)
        if match is None:
            break
        parts.append(int(match.group(1)))
    return tuple(parts)


def compare_versions(left: Any, right: Any) -> int | None:
    """
    Сравнить две версии RouterOS.

    Возвращает −1, 0 или 1; None — если хотя бы одну версию разобрать не удалось.
    Именно из-за этого нельзя сравнивать версии как строки: «7.9» больше «7.21»
    по алфавиту, но меньше по смыслу.
    """
    a, b = parse_version(left), parse_version(right)
    if not a or not b:
        return None
    # Дополняем нулями, чтобы 7.23 и 7.23.0 считались равными
    length = max(len(a), len(b))
    a += (0,) * (length - len(a))
    b += (0,) * (length - len(b))
    return (a > b) - (a < b)


def is_newer(candidate: Any, current: Any) -> bool:
    """Правда ли, что candidate новее, чем current."""
    return compare_versions(candidate, current) == 1


SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_filename(value: str) -> str:
    """Привести произвольную строку к безопасному имени файла."""
    cleaned = SAFE_FILENAME_RE.sub("_", value).strip("._-")
    return cleaned or "device"


def flatten_rows(rows: Iterable[dict[str, Any]], limit: int = 40) -> str:
    """
    Превратить ответ API в читаемый текст для показа в результатах задачи.

    Длинные ответы обрезаются, чтобы история задач не разрасталась.
    """
    rows = list(rows)
    out: list[str] = []
    for row in rows[:limit]:
        parts = [f"{k}={v}" for k, v in row.items() if not k.startswith("!")]
        out.append("; ".join(parts))
    if len(rows) > limit:
        out.append(f"... ещё {len(rows) - limit} строк(и)")
    return "\n".join(out) if out else "(пустой ответ)"
