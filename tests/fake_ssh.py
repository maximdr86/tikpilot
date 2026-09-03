"""
Заглушка SSH-сервера для проверки терминала.

Зачем настоящий сервер, а не мок
--------------------------------

Тот же довод, что и с заглушкой RouterOS: мок принял бы любую ошибку
в рукопожатии, в запросе псевдотерминала и в кодировках. Здесь работает
настоящий paramiko со стороны сервера, поэтому проверяется то же, что
произойдёт с живым роутером: обмен ключами, авторизация, канал, pty.

Сервер отвечает как командная строка RouterOS: печатает приглашение,
повторяет введённое эхом и выдаёт ответ на пару известных команд.
Полностью изображать RouterOS незачем, терминал прозрачен и содержимого
не разбирает.
"""

from __future__ import annotations

import socket
import threading
import time
from typing import Any

import paramiko

#: Ключ хоста генерируется один раз на прогон: две тысячи бит это секунда
#: процессорного времени, и платить её в каждом тесте незачем.
_HOST_KEY: Any = None


def host_key() -> Any:
    """Ключ хоста заглушки. Один на все тесты, если не попросили другой."""
    global _HOST_KEY
    if _HOST_KEY is None:
        _HOST_KEY = paramiko.RSAKey.generate(2048)
    return _HOST_KEY


class _Server(paramiko.ServerInterface):
    """Минимальный сервер: пароль, сессия, псевдотерминал."""

    def __init__(self, username: str, password: str,
                 authorized: Any = None) -> None:
        self.username, self.password = username, password
        #: Публичная часть ключа, которую сервер согласен принять. Пусто —
        #: значит вход по ключу не настроен, как на роутере без импорта
        self.authorized = authorized
        self.shell = threading.Event()
        self.exec_requested = threading.Event()
        self.executed: list[str] = []
        self.size: tuple[int, int] = (0, 0)

    def check_auth_password(self, username: str, password: str) -> int:
        if username == self.username and password == self.password:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: Any) -> int:
        """
        Принять ключ, если он тот самый.

        Сравниваются байты публичной части, а не отпечаток: отпечаток
        считается по-разному в разных версиях, и тест начал бы падать
        от смены библиотеки, а не от ошибки в панели.
        """
        if self.authorized is None or username != self.username:
            return paramiko.AUTH_FAILED
        if key.asbytes() == self.authorized.asbytes():
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "publickey,password" if self.authorized is not None else "password"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_pty_request(self, channel, term, width, height,  # noqa: ANN001
                                  pixelwidth, pixelheight, modes) -> bool:
        self.size = (width, height)
        return True

    def check_channel_shell_request(self, channel) -> bool:  # noqa: ANN001
        self.shell.set()
        return True

    def check_channel_exec_request(self, channel, command) -> bool:  # noqa: ANN001
        """
        Одиночная команда без псевдотерминала.

        Так работают массовые действия: соединение, команда, ответ,
        разрыв. Настоящий RouterOS это умеет, и заглушка обязана уметь
        тоже, иначе проверять нечего.
        """
        self.executed.append(command.decode("utf-8", "replace")
                             if isinstance(command, bytes) else str(command))
        self.exec_requested.set()
        return True

    def check_channel_window_change_request(self, channel, width, height,  # noqa: ANN001
                                            pixelwidth, pixelheight) -> bool:
        self.size = (width, height)
        return True


class FakeSSH:
    """
    SSH-сервер на случайном порту.

    Живёт в своём потоке и принимает одно соединение за раз: терминалу
    больше и не нужно, а простота здесь дороже общности.
    """

    PROMPT = "[admin@MikroTik] > "

    def __init__(self, username: str = "tikpilot", password: str = "s3cret",
                 key: Any = None, authorized: Any = None) -> None:
        self.username, self.password = username, password
        self.key = key or host_key()
        #: Публичная часть ключа, которую сервер примет. Аналог того, что
        #: на роутере лежит в `/user ssh-keys`
        self.authorized = authorized
        self.received: list[str] = []
        #: Команды, пришедшие без псевдотерминала (массовые действия)
        self.commands: list[str] = []
        self.server: _Server | None = None

        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]

        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True,
                                        name="fake-ssh")
        self._thread.start()

    # ------------------------------------------------------------------ жизнь
    def _serve(self) -> None:
        self._sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn: socket.socket) -> None:
        """
        Одно соединение. Каналов в нём может быть много.

        Терминал открывает один канал с псевдотерминалом и живёт в нём,
        а массовое действие открывает по каналу на команду в том же
        соединении. Обрабатывать только первый канал значит проверить
        ровно одну команду из списка, то есть не проверить ничего.
        """
        transport = paramiko.Transport(conn)
        transport.add_server_key(self.key)
        server = _Server(self.username, self.password, self.authorized)
        self.server = server
        try:
            transport.start_server(server=server)
            while not self._stop.is_set():
                channel = transport.accept(5)
                if channel is None:
                    if not transport.is_active():
                        break
                    continue
                threading.Thread(target=self._channel, args=(server, channel),
                                 daemon=True).start()
        except Exception:  # noqa: BLE001 — заглушка не должна ронять тесты
            pass
        finally:
            try:
                transport.close()
            except Exception:  # noqa: BLE001
                pass

    def _channel(self, server: "_Server", channel: Any) -> None:
        """Обслужить один канал: либо команду, либо интерактивную оболочку."""
        try:
            # Клиент просит либо оболочку, либо команду. Ждём, что придёт
            for _ in range(100):
                if server.shell.is_set() or server.exec_requested.is_set():
                    break
                time.sleep(0.05)

            if server.exec_requested.is_set():
                command = server.executed[-1] if server.executed else ""
                self.commands.append(command)
                server.exec_requested.clear()
                channel.send(self._answer(command))
                channel.send_exit_status(0)
                channel.close()
                return

            channel.send(self.PROMPT)

            typed = ""
            while not self._stop.is_set():
                data = channel.recv(1024)
                if not data:
                    break
                text = data.decode("utf-8", "replace")
                self.received.append(text)
                # Эхо, как настоящий терминал: без него в окне пусто
                channel.send(text)
                typed += text
                if "\r" in typed or "\n" in typed:
                    line = typed.strip()
                    typed = ""
                    channel.send("\r\n" + self._answer(line) + self.PROMPT)
        except Exception:  # noqa: BLE001 — заглушка не должна ронять тесты
            pass

    def _answer(self, line: str) -> str:
        """Ответ на команду. Знакомых ровно столько, сколько нужно тестам."""
        # Отказ проверяется первым: кривая команда может начинаться с той же
        # знакомой строки, что и правильная, и порядок здесь важен так же,
        # как на настоящем устройстве.
        #
        # Настоящий RouterOS на кривую команду отвечает текстом, а код
        # возврата при этом бывает нулевым. Панель обязана смотреть в текст.
        if "ошибка" in line or "bad-command" in line:
            return "expected end of command (line 1 column 5)\r\n"
        if line.startswith("/system/identity/print") or line.startswith("/system identity"):
            return "  name: MikroTik\r\n"
        if line:
            return "выполнено: %s\r\n" % line
        return ""

    def stop(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass
