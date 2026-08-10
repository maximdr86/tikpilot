"""
Живая консоль: что панель делает прямо сейчас.

Обычный журнал сервера лежит в systemd, и чтобы его посмотреть, нужен
доступ по ssh. Между тем девяносто процентов вопросов к панели звучат
как «она вообще работает?» и «почему эта точка до сих пор не проверена».
Ответ на них есть в журнале, и его достаточно показать.

Как устроено
------------

К логгеру `tikpilot` подключается обработчик, складывающий записи
в кольцевой буфер в памяти. Страница опрашивает его и дорисовывает
появившееся.

Именно память, а не таблица в базе: строк много, живут они минуты,
и писать их на диск ради того, чтобы через час удалить, незачем. При
перезапуске буфер пуст, и это правильно: консоль показывает настоящее,
а не историю. История падений и задач хранится отдельно и по-настоящему.

Про пароли
----------

В журнал они попадать не должны, но полагаться на аккуратность каждой
строчки кода нельзя: достаточно один раз залогировать словарь параметров
целиком. Поэтому значения после `password`, `private-key` и подобных
слов вырезаются здесь, на входе в буфер.
"""

from __future__ import annotations

import logging
import re
import threading
from collections import deque
from datetime import datetime, timezone
from typing import Any

#: Сколько строк держим. Тысячи хватает на несколько минут работы парка
#: в полсотни точек, а больше на экране всё равно не читают.
CAPACITY = 1000

#: Значения этих полей в консоль не попадают ни при каких обстоятельствах.
_SECRET = re.compile(
    r"((?:password|passwd|pass|private-key|preshared-key|secret|token|key)"
    r"\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|\S+)",
    re.I,
)

_lock = threading.Lock()
_buffer: deque[dict[str, Any]] = deque(maxlen=CAPACITY)
_counter = 0

#: Понятные названия источников. Имя логгера человеку ничего не говорит,
#: а «мониторинг» и «задачи» говорят.
SOURCES = {
    "tikpilot.audit": "действия",
    "tikpilot.monitor": "мониторинг",
    "tikpilot.worker": "задачи",
    "tikpilot.sessions": "сессии",
    "tikpilot.mikrotik": "устройства",
    "tikpilot": "панель",
}


def hide_secrets(text: str) -> str:
    """Заменить значения паролей и ключей на звёздочки."""
    return _SECRET.sub(lambda m: m.group(1) + "***", text)


def source_name(logger: str) -> str:
    """Человеческое имя источника записи."""
    return SOURCES.get(logger, logger.replace("tikpilot.", "") or "панель")


def add(level: str, message: str, logger: str = "tikpilot") -> dict[str, Any]:
    """Добавить строку в консоль. Возвращает добавленную запись."""
    global _counter

    with _lock:
        _counter += 1
        row = {
            "id": _counter,
            "ts": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "level": level.lower(),
            "source": source_name(logger),
            "text": hide_secrets(message)[:2000],
        }
        _buffer.append(row)
        return row


def tail(after: int = 0, limit: int = 300, level: str = "",
         needle: str = "") -> list[dict[str, Any]]:
    """
    Записи новее указанной.

    `after` это номер последней уже показанной строки: страница просит
    только то, чего у неё нет, и не перерисовывает экран целиком.
    """
    wanted = str(level or "").lower()
    text = str(needle or "").strip().lower()

    with _lock:
        rows = [r for r in _buffer if r["id"] > after]

    if wanted in ("warning", "error"):
        # «Предупреждения» показывают и ошибки: человек, включивший фильтр,
        # ищет проблемы, а не конкретный уровень
        allowed = {"warning", "error", "critical"} if wanted == "warning" else {"error", "critical"}
        rows = [r for r in rows if r["level"] in allowed]
    if text:
        rows = [r for r in rows if text in r["text"].lower() or text in r["source"].lower()]

    return rows[-limit:]


def last_id() -> int:
    """Номер последней записи: с него страница начинает опрос."""
    with _lock:
        return _buffer[-1]["id"] if _buffer else 0


def clear() -> None:
    """Очистить консоль. На саму работу панели никак не влияет."""
    with _lock:
        _buffer.clear()


class BufferHandler(logging.Handler):
    """
    Обработчик, складывающий записи в кольцевой буфер.

    Ошибку внутри самого обработчика гасим молча: логирование не должно
    ронять то, что оно логирует.
    """

    def emit(self, record: logging.LogRecord) -> None:
        try:
            add(record.levelname, record.getMessage(), record.name)
        except Exception:  # noqa: BLE001
            pass


def install() -> None:
    """Подключить буфер к логгеру приложения (вызывается на старте)."""
    logger = logging.getLogger("tikpilot")
    # Уровень задаём своему логгеру, а не полагаемся на корневой: под
    # pytest и в некоторых окружениях корневой настроен на WARNING, и
    # тогда консоль оказывалась пустой при работающей панели.
    logger.setLevel(logging.INFO)
    if any(isinstance(h, BufferHandler) for h in logger.handlers):
        return
    handler = BufferHandler()
    handler.setLevel(logging.INFO)
    logger.addHandler(handler)
