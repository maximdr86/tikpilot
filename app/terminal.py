"""
Терминал до роутера по SSH.

Зачем не по API
---------------

Панель разговаривает с устройствами по API, и это правильно почти для всего.
Но у API свой синтаксис: в командной строке пишут
`/ip address print where interface=ether1`, а по API это другой вызов
с другими параметрами. Команда, скопированная с форума или из своей же
шпаргалки, по API не работает. Плюс там нет ни дополнения по табу,
ни `?`, ни команд, которые пишут вывод бесконечно.

Поэтому терминал именно по SSH: это та же строка, что в Winbox, со всеми
её удобствами.

Чем это опасно
--------------

Это самая опасная возможность панели, и относиться к ней надо соответственно.
Вся остальная механика построена на подтверждениях: массовое действие
показывает список устройств, опасное требует согласия, перезагрузка сорока
точек не случается одним кликом. В терминале достаточно опечатки.

Отсюда три решения:

* отдельное право `terminal.use`, в набор по умолчанию оно не входит;
* всё набранное пишется в журнал действий, строкой на команду;
* ключ хоста запоминается при первом подключении и сверяется при следующих.

Про ключ хоста
--------------

Принимать любой ключ молча нельзя: это открытая дверь для подмены. Но и
требовать заранее заполненный список отпечатков на полсотни точек значит
похоронить возможность. Поэтому доверие при первом подключении: ключ
запоминается, а при смене подключение отклоняется с внятным текстом.
Смена ключа бывает и законной (перезалили устройство), тогда отпечаток
убирается кнопкой.
"""

from __future__ import annotations

import logging
import re
import socket
import threading
import time
from typing import Any, Callable

from .config import settings
from .crypto import decrypt
from .database import execute, log_audit, query_one, utcnow

log = logging.getLogger("tikpilot.terminal")

#: Сколько ждать соединения, приветствия и авторизации.
#:
#: Десяти секунд не хватало. RouterOS на слабой плате делает обмен
#: ключами долго, а на канале с задержкой в двести миллисекунд и
#: потерями рукопожатие не укладывается и подавно. Paramiko в этом
#: случае бросает `No existing session` - сообщение, по которому
#: невозможно догадаться, что дело во времени.
CONNECT_TIMEOUT = 10


def _timeout() -> int:
    """Сколько ждать. Настройка живёт в панели, умолчание здесь."""
    return max(5, int(getattr(settings, "ssh_timeout", 0) or CONNECT_TIMEOUT))


def _explain(exc: Exception) -> str:
    """
    Человеческий текст вместо загадок библиотеки.

    `No existing session` означает, что соединение установилось, а
    рукопожатие SSH не доехало: роутер не успел прислать приветствие
    или обменяться ключами. На парке это самая частая причина неудачи
    массовой команды, и она лечится временем ожидания, а не поездкой.
    """
    text = str(exc).strip()
    lowered = text.lower()
    if "no existing session" in lowered or "banner" in lowered or not text:
        return (
            "роутер не завершил рукопожатие SSH за %d с. Так бывает на слабой"
            " плате и на канале с потерями, особенно когда команда идёт"
            " на весь парк сразу. Увеличьте ожидание в настройках"
            " или запускайте группами поменьше" % _timeout()
        )
    return text

#: Размер окна по умолчанию, пока браузер не сообщил свой.
DEFAULT_COLS, DEFAULT_ROWS = 120, 30

#: Управляющие символы, которые не должны попасть в журнал действий:
#: в набранной строке остаются возвраты каретки и последовательности
#: от стрелок, а в истории нужна команда, а не то, как её печатали.
_CONTROL = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|[\x00-\x08\x0b-\x1f\x7f]")


class TerminalError(Exception):
    """Не удалось открыть терминал. Текст показывается человеку как есть."""


def fingerprint_of(key: Any) -> str:
    """Отпечаток ключа хоста в привычном виде: тип и base64 от sha256."""
    import base64
    import hashlib

    digest = hashlib.sha256(key.asbytes()).digest()
    return "%s SHA256:%s" % (
        key.get_name(), base64.b64encode(digest).decode().rstrip("="))


def known_fingerprint(device_id: int) -> str:
    """Запомненный отпечаток ключа устройства, если он есть."""
    row = query_one("SELECT fingerprint FROM ssh_hosts WHERE device_id = ?", (device_id,))
    return row["fingerprint"] if row else ""


def remember_fingerprint(device_id: int, fingerprint: str) -> None:
    """Запомнить отпечаток при первом подключении."""
    execute(
        "INSERT INTO ssh_hosts (device_id, fingerprint, first_seen) VALUES (?,?,?) "
        "ON CONFLICT(device_id) DO UPDATE SET fingerprint = excluded.fingerprint",
        (device_id, fingerprint, utcnow()),
    )


def forget_fingerprint(device_id: int) -> int:
    """Забыть отпечаток: устройство перезалили, ключ сменился законно."""
    from .database import execute_changes

    return execute_changes("DELETE FROM ssh_hosts WHERE device_id = ?", (device_id,))


def connect(device: dict[str, Any]) -> Any:
    """
    Подключиться к устройству по SSH и вернуть готовый клиент paramiko.

    Общая для терминала и для команд по SSH: доверие ключу при первом
    подключении, отказ при его смене и один и тот же понятный текст
    ошибки. Две копии этой логики разошлись бы через месяц, и первой
    разошлась бы как раз проверка ключа.
    """
    import paramiko

    device_id = int(device["id"])
    host = str(device["host"])
    port = int(device.get("ssh_port") or 22)

    known = known_fingerprint(device_id)
    seen: dict[str, str] = {}

    class _Policy(paramiko.MissingHostKeyPolicy):
        """Доверие при первом подключении, отказ при смене ключа."""

        def missing_host_key(self, client, hostname, key):  # noqa: ANN001
            seen["fingerprint"] = fingerprint_of(key)
            if known and seen["fingerprint"] != known:
                raise TerminalError(
                    "Ключ устройства изменился. Так выглядит и подмена, "
                    "и обычная перезаливка роутера. Если устройство "
                    "переустанавливали, забудьте прежний ключ в его "
                    "карточке и подключитесь заново."
                )

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(_Policy())
    wait = _timeout()

    # Одна повторная попытка. Сорванное рукопожатие это почти всегда
    # случайность канала, и со второго раза оно проходит; гонять человека
    # обратно в список за галочками ради этого незачем.
    last: Exception | None = None
    for attempt in (1, 2):
        try:
            client.connect(
                hostname=host,
                port=port,
                username=str(device["username"]),
                password=decrypt(device["password_enc"]),
                timeout=wait,
                auth_timeout=wait,
                banner_timeout=wait,
                allow_agent=False,
                look_for_keys=False,
            )
            last = None
            break
        except TerminalError:
            raise
        except paramiko.AuthenticationException as exc:
            raise TerminalError(
                "Устройство не приняло логин или пароль. Для входа по SSH "
                "у пользователя RouterOS должна быть политика «ssh»: панели "
                "хватает «api», а терминалу нет."
            ) from exc
        except (paramiko.SSHException, socket.error, OSError) as exc:
            last = exc
            log.debug("SSH к %s не удался (попытка %s): %s", host, attempt, exc)
            if attempt == 1:
                time.sleep(1.0)

    if last is not None:
        raise TerminalError("Не удалось подключиться по SSH: %s" % _explain(last)) from last

    if seen.get("fingerprint") and not known:
        remember_fingerprint(device_id, seen["fingerprint"])
    return client


class Session:
    """
    Одна сессия терминала: соединение SSH и канал с псевдотерминалом.

    Чтение идёт в отдельном потоке. Держать его в цикле событий нельзя:
    чтение из сокета блокирующее, и на время ожидания замерла бы вся панель.
    Тот же урок, что и с опросом устройств.
    """

    def __init__(self, device: dict[str, Any], username: str,
                 cols: int = DEFAULT_COLS, rows: int = DEFAULT_ROWS) -> None:
        self.device = device
        self.username = username
        self.cols, self.rows = cols, rows
        self.client: Any = None
        self.channel: Any = None
        self._typed = ""
        self._lock = threading.Lock()

    # ------------------------------------------------------------ соединение
    def open(self) -> None:
        """Подключиться и запросить псевдотерминал."""
        host = str(self.device["host"])
        port = int(self.device.get("ssh_port") or 22)

        self.client = connect(self.device)
        self.channel = self.client.invoke_shell(
            term="vt100", width=self.cols, height=self.rows)
        self.channel.settimeout(0.0)

        log_audit(self.username, "Открыт терминал", str(self.device["name"]),
                  f"{host}:{port}", "")

    def close(self) -> None:
        """Закрыть канал и соединение. Вызывается всегда, в том числе на ошибке."""
        with self._lock:
            for item in (self.channel, self.client):
                try:
                    if item is not None:
                        item.close()
                except Exception:  # noqa: BLE001 — закрытие не должно падать
                    pass
            self.channel = self.client = None

    # ---------------------------------------------------------------- обмен
    def send(self, data: str) -> None:
        """Отправить нажатия на устройство и запомнить набранное для журнала."""
        if not self.channel:
            return
        self._remember(data)
        self.channel.send(data)

    def resize(self, cols: int, rows: int) -> None:
        """Сообщить устройству новый размер окна."""
        self.cols, self.rows = max(20, cols), max(5, rows)
        if self.channel:
            self.channel.resize_pty(width=self.cols, height=self.rows)

    def pump(self, on_data: Callable[[str], None], stop: threading.Event) -> None:
        """
        Читать вывод устройства, пока не закроют.

        Работает в своём потоке: recv блокирующий, и в цикле событий
        он остановил бы всю панель.
        """
        import paramiko

        while not stop.is_set() and self.channel is not None:
            try:
                if self.channel.recv_ready():
                    chunk = self.channel.recv(8192)
                    if not chunk:
                        break
                    on_data(chunk.decode("utf-8", "replace"))
                elif self.channel.exit_status_ready():
                    break
                else:
                    stop.wait(0.03)
            except paramiko.SSHException:
                break
            except OSError:
                break

    # --------------------------------------------------------------- журнал
    def _remember(self, data: str) -> None:
        """
        Накопить набранное и записать команду по нажатию ввода.

        Пишется то, что человек набрал, а не то, что в итоге выполнилось:
        после дополнения по табу устройство достраивает строку само, и
        со стороны панели этого не видно. Для вопроса «кто это сделал»
        набранного достаточно, а обещать большего нечестно.
        """
        for char in data:
            if char in ("\r", "\n"):
                line = _CONTROL.sub("", self._typed).strip()
                self._typed = ""
                if line:
                    log_audit(self.username, "Команда в терминале",
                              str(self.device["name"]), line[:500], "")
            elif char in ("\x7f", "\x08"):
                self._typed = self._typed[:-1]
            else:
                self._typed += char

        # Строка без ввода тоже не должна расти без предела
        if len(self._typed) > 2000:
            self._typed = self._typed[-500:]
