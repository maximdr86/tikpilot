"""
Защита входа от подбора пароля.

После нескольких промахов подряд адрес получает паузу. Смысл не в том,
чтобы остановить настойчивого злоумышленника — от него защищают длинный
пароль и `ADMIN_NETWORKS`, — а в том, чтобы перебор перестал быть дешёвым.
Без паузы тысяча попыток в секунду ограничена только каналом.

Счёт ведётся по адресу, а не по имени пользователя. По имени было бы
удобнее подбирающему: достаточно чередовать `admin`, `root`, `user`,
и блокировка не наступит никогда. К тому же заблокировать чужое имя
подбором чужих паролей означало бы дать способ не пускать в панель
настоящего администратора.

Всё живёт в памяти и обнуляется при перезапуске. Для задачи «сделать
перебор дорогим» этого достаточно, а таблица в базе означала бы запись
на диск на каждую неудачную попытку, то есть ровно то, чего добивается
тот, кто её устраивает.
"""

from __future__ import annotations

import threading
import time
from collections import defaultdict, deque
from typing import Any

_lock = threading.Lock()
_misses: dict[str, deque[float]] = defaultdict(deque)
_blocked: dict[str, float] = {}


def _clean(address: str, now: float, window: int) -> deque[float]:
    """Убрать промахи старше окна и вернуть оставшиеся."""
    marks = _misses[address]
    while marks and now - marks[0] > window:
        marks.popleft()
    return marks


def wait_seconds(address: str, now: float | None = None) -> int:
    """
    Сколько секунд адресу ещё нельзя пробовать. Ноль — можно.

    Проверяется до сверки пароля: иначе пауза не экономила бы ничего,
    ведь основная цена попытки это как раз проверка хеша.
    """
    from .config import settings

    if settings.login_max_attempts <= 0:
        return 0

    moment = now if now is not None else time.monotonic()
    with _lock:
        until = _blocked.get(address, 0.0)
        return max(0, int(until - moment)) if until > moment else 0


def register_miss(address: str, now: float | None = None) -> int:
    """
    Учесть неудачную попытку. Возвращает длину назначенной паузы.

    Пауза растёт с числом промахов: первые попытки человек делает
    вслепую, набирая пароль не с той раскладкой, и наказывать его
    пятью минутами за это незачем.
    """
    from .config import settings

    if settings.login_max_attempts <= 0:
        return 0

    moment = now if now is not None else time.monotonic()
    window = max(60, settings.login_block_seconds)

    with _lock:
        marks = _clean(address, moment, window)
        marks.append(moment)
        extra = len(marks) - settings.login_max_attempts
        if extra < 0:
            return 0

        # Первое превышение — базовая пауза, каждое следующее вдвое дольше,
        # но не больше часа: дальше это уже не про подбор
        delay = min(3600, settings.login_block_seconds * (2 ** extra))
        _blocked[address] = moment + delay
        return delay


def register_success(address: str) -> None:
    """Удачный вход снимает все счётчики адреса."""
    with _lock:
        _misses.pop(address, None)
        _blocked.pop(address, None)


def state() -> dict[str, Any]:
    """Сведения для страницы настроек: кто сейчас под паузой."""
    now = time.monotonic()
    with _lock:
        return {
            "blocked": {a: int(until - now) for a, until in _blocked.items() if until > now},
            "watched": len(_misses),
        }


def reset() -> None:
    """Полный сброс. Нужен тестам и кнопке «снять блокировки»."""
    with _lock:
        _misses.clear()
        _blocked.clear()
