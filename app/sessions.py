"""
Пул постоянных API-сессий для мониторинга.

Зачем это нужно
---------------
Первая версия монитора проверяла доступность так: открыть TCP-соединение
с портом API и сразу закрыть. Выяснилось, что на слабых устройствах
(hAP ac lite и подобных) очередь приёма мала, и поток таких оборванных
подключений заставляет RouterOS ругаться:

    possible SYN flooding on tcp port 8728

Кроме того, авторизация на устройстве пишется в его журнал. Если логиниться
раз в минуту на полусотне точек, внутренний лог MikroTik вымывается за минуты.

Решение: держать соединение открытым. Вход в систему происходит **один раз**,
дальше проверка — это дешёвая команда в уже установленной сессии. Команды
RouterOS в журнал не пишет, новых TCP-подключений не возникает.

Повторный вход случается только когда соединение действительно оборвалось:
после перезагрузки устройства или обрыва канала.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from contextlib import contextmanager
from typing import Any

from .config import settings
from .crypto import decrypt
from .mikrotik import DeviceError, MikroTik

log = logging.getLogger("tikpilot.sessions")

# Команда для проверки живости: возвращает одну строку и ничего не меняет.
PING_COMMAND = "/system/identity/print"


class SessionPool:
    """
    Набор открытых API-сессий, по одной на устройство.

    Потокобезопасен: на каждое устройство свой замок, поэтому две проверки
    одного и того же устройства не столкнутся в одном сокете.
    """

    def __init__(self) -> None:
        self._sessions: dict[int, MikroTik] = {}
        self._locks: dict[int, threading.Lock] = {}
        self._auth_backoff: dict[int, float] = {}
        self._guard = threading.Lock()
        self.logins = 0            # сколько раз пришлось авторизоваться (для диагностики)

    # ------------------------------------------------------------- служебное
    def _lock_for(self, device_id: int) -> threading.Lock:
        with self._guard:
            return self._locks.setdefault(device_id, threading.Lock())

    def size(self) -> int:
        """Сколько сессий сейчас открыто."""
        with self._guard:
            return len(self._sessions)

    def drop(self, device_id: int) -> None:
        """
        Закрыть сессию устройства.

        Вызывается, когда устройство изменили или отдали массовой задаче:
        соединение всё равно станет невалидным.
        """
        with self._guard:
            session = self._sessions.pop(device_id, None)
            self._auth_backoff.pop(device_id, None)
        if session is not None:
            session.close()

    def close_all(self) -> None:
        """Закрыть все сессии (при остановке приложения)."""
        with self._guard:
            sessions = list(self._sessions.values())
            self._sessions.clear()
            self._auth_backoff.clear()
        for session in sessions:
            session.close()
        if sessions:
            log.info("Закрыто сессий: %s", len(sessions))

    # -------------------------------------------------------------- проверки
    def check(self, device: dict[str, Any]) -> tuple[bool | None, str]:
        """
        Быстрая проверка живости через уже открытую сессию.

        Новое подключение создаётся, только если сессии нет или она умерла.

        Возвращает None вместо True/False, если сессия сейчас занята массовой
        задачей: тогда статус устройства не трогаем — промах был бы ложным.
        """
        lock = self._lock_for(device["id"])
        if not lock.acquire(timeout=settings.monitor_session_timeout):
            return None, "Сессия занята задачей"
        try:
            session = self._sessions.get(device["id"])
            if session is not None:
                try:
                    session.cmd(PING_COMMAND)
                    return True, ""
                except DeviceError:
                    # Соединение оборвалось — уберём и попробуем открыть заново
                    self._forget(device["id"])

            try:
                self._connect(device)
                return True, ""
            except DeviceError as exc:
                return False, str(exc)
        finally:
            lock.release()

    def poll(self, device: dict[str, Any]) -> tuple[bool | None, str, dict[str, str]]:
        """
        Полный опрос: версия, uptime, загрузка, архитектура.

        Использует ту же постоянную сессию, что и быстрая проверка.
        """
        lock = self._lock_for(device["id"])
        if not lock.acquire(timeout=settings.monitor_session_timeout):
            return None, "Сессия занята задачей", {}
        try:
            session = self._sessions.get(device["id"])
            if session is not None:
                try:
                    return True, "", session.system_info()
                except DeviceError:
                    self._forget(device["id"])

            try:
                session = self._connect(device)
                return True, "", session.system_info()
            except DeviceError as exc:
                return False, str(exc), {}
        finally:
            lock.release()

    # --------------------------------------------------------- аренда сессии
    @contextmanager
    def borrow(self, device: dict[str, Any]):
        """
        Отдать сессию массовой задаче во временное пользование.

        Благодаря этому выполнение действия на устройстве не требует нового
        входа в систему: задача работает в том же соединении, что и монитор.
        Именно это убирает всплеск записей «user ... logged in» при каждом
        массовом действии.

        На время работы устройство заблокировано для монитора — он в это время
        его всё равно пропускает.

        После выхода соединение остаётся в пуле, если оно исправно. Порванное
        (например, устройство ушло в перезагрузку) убирается автоматически.
        """
        device_id = device["id"]
        lock = self._lock_for(device_id)
        lock.acquire()
        session = None
        try:
            session = self._sessions.get(device_id)
            if session is None or not session.alive:
                if session is not None:
                    self._forget(device_id)
                session = self._connect(device)

            # Мониторингу хватает короткого таймаута, а задачам — нет:
            # /export и /system/backup/save на большой конфигурации отвечают
            # заметно дольше. На время работы задачи таймаут поднимаем.
            session.set_timeout(settings.api_timeout)
            yield session
        finally:
            if session is not None:
                if session.alive:
                    session.set_timeout(settings.monitor_session_timeout)
                else:
                    # Соединение не пережило выполненную команду
                    self._forget(device_id)
            lock.release()

    # ------------------------------------------------------------ соединение
    def _connect(self, device: dict[str, Any]) -> MikroTik:
        """
        Открыть новую сессию. Именно здесь происходит единственный вход в систему.

        При неверных учётных данных включается отступ: незачем раз в минуту
        плодить в журнале устройства неудачные попытки входа.
        """
        device_id = device["id"]

        until = self._auth_backoff.get(device_id, 0.0)
        if until > time.monotonic():
            raise DeviceError(
                "Неверный логин или пароль, повторная попытка отложена. "
                "Исправьте учётные данные в карточке устройства."
            )

        session = MikroTik(device, decrypt(device["password_enc"]),
                           timeout=settings.monitor_session_timeout)
        try:
            session.open()
        except DeviceError as exc:
            text = str(exc)
            if "логин или пароль" in text or "не-ASCII" in text:
                # Пробуем не чаще, чем раз в полный цикл опроса
                self._auth_backoff[device_id] = time.monotonic() + settings.monitor_full_interval
            raise

        _enable_keepalive(session)

        with self._guard:
            self._sessions[device_id] = session
            self._auth_backoff.pop(device_id, None)
        self.logins += 1
        # На уровне info, а не debug: вход в систему на устройстве событие
        # редкое и важное. Если эта строка появляется каждую минуту, значит
        # сессия рвётся, и это видно сразу, а не через журнал роутера.
        log.info("Вход в систему: %s (%s)", device.get("name"), device.get("host"))
        return session

    def _forget(self, device_id: int) -> None:
        """Убрать нерабочую сессию из пула (замок устройства уже взят)."""
        with self._guard:
            session = self._sessions.pop(device_id, None)
        if session is not None:
            session.close()


def _enable_keepalive(session: MikroTik) -> None:
    """
    Включить TCP keepalive на сокете сессии.

    Без этого «тихий» обрыв канала (например, упавший туннель) заметен только
    при следующей команде и по таймауту. С keepalive система обнаружит разрыв
    сама и следующая проверка честно сообщит о недоступности.
    """
    try:
        sock = session.api.protocol.transport.sock  # type: ignore[union-attr]
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        # Опции ниже есть не во всех системах — включаем по возможности
        for option, value in (
            ("TCP_KEEPIDLE", 30),
            ("TCP_KEEPINTVL", 10),
            ("TCP_KEEPCNT", 3),
        ):
            if hasattr(socket, option):
                sock.setsockopt(socket.IPPROTO_TCP, getattr(socket, option), value)
    except (AttributeError, OSError):
        pass


# Единый пул на всё приложение
pool = SessionPool()
