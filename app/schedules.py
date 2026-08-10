"""
Расписание бэкапов: правила «что, когда и сколько хранить».

Правило описывает три вещи:

* **что снимать.** Группу устройств, весь парк или архив самой панели;
* **когда.** Время суток и дни недели. Пустой список дней означает
  ежедневно;
* **сколько хранить.** Число последних копий на устройство. Лишние
  удаляются сразу после отработки правила, вместе с файлами.

Расчёт времени живёт здесь и не трогает ни базу, ни диск, поэтому его
можно проверить тестами на любую дату, не дожидаясь трёх часов ночи.

Про часовые пояса
-----------------

Человек задаёт время так, как смотрит на часы: «03:00». Хранится оно
тоже строкой «03:00», а в UTC переводится только момент следующего
запуска. Обратный порядок, когда в базу кладут переведённое время,
ломается дважды в год: правило, поставленное на 03:00 летом, зимой
срабатывало бы в 02:00 или в 04:00.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

#: Дни недели: 1 это понедельник, как в ISO. Пусто означает каждый день.
DAY_NAMES = {
    1: "пн", 2: "вт", 3: "ср", 4: "чт", 5: "пт", 6: "сб", 7: "вс",
}

_TIME = re.compile(r"^\s*(\d{1,2})\s*[:.]\s*(\d{1,2})\s*$")


def parse_time(value: Any) -> tuple[int, int] | None:
    """«03:00» → (3, 0). Возвращает None, если время разобрать не удалось."""
    found = _TIME.match(str(value or ""))
    if not found:
        return None
    hour, minute = int(found.group(1)), int(found.group(2))
    if 0 <= hour <= 23 and 0 <= minute <= 59:
        return hour, minute
    return None


def parse_days(value: Any) -> list[int]:
    """
    Строка «1,3,5» в список дней недели. Мусор и повторы отбрасываются.

    Пустой список это «каждый день», и отдельного значения для него нет
    намеренно: одно состояние вместо двух, которые надо не перепутать.

    Список принимается наравне со строкой: из базы дни приходят строкой
    «1,3,5», а из JSON массивом. Раньше массив уезжал в `str()` целиком,
    и от `[1, 3, 5]` выживал ровно один день, средний.
    """
    parts = value if isinstance(value, (list, tuple, set)) else \
        str(value or "").replace(";", ",").split(",")
    days = set()
    for part in (str(p) for p in parts):
        part = part.strip()
        if part.isdigit() and 1 <= int(part) <= 7:
            days.add(int(part))
    return sorted(days)


def dump_days(days: Iterable[int]) -> str:
    """Список дней в строку для базы."""
    return ",".join(str(d) for d in sorted(set(days)) if 1 <= d <= 7)


def describe_days(days: Iterable[int], lang: str = "ru") -> str:
    """Человеческая подпись: «ежедневно» или «пн, ср, пт»."""
    chosen = sorted(set(days))
    if not chosen or len(chosen) == 7:
        return "ежедневно" if lang == "ru" else "daily"
    english = {1: "Mon", 2: "Tue", 3: "Wed", 4: "Thu", 5: "Fri", 6: "Sat", 7: "Sun"}
    names = DAY_NAMES if lang == "ru" else english
    return ", ".join(names[d] for d in chosen)


def next_run(at_time: str, days: Iterable[int], after: datetime | None = None) -> str | None:
    """
    Ближайший момент срабатывания после `after`, строкой UTC для базы.

    `after` берётся в местном времени сервера: правило «03:00» означает
    три часа ночи там, где стоит сервер, а не по Гринвичу.

    Возвращает None, если время задано неверно: правило без времени
    запускать нельзя, и тихо подставлять полночь было бы хуже, чем
    показать, что расписание не настроено.
    """
    parsed = parse_time(at_time)
    if parsed is None:
        return None
    hour, minute = parsed

    moment = (after or datetime.now()).astimezone()
    chosen = sorted(set(int(d) for d in days if 1 <= int(d) <= 7))

    # Максимум восемь шагов: сегодня плюс полная неделя вперёд
    candidate = moment.replace(hour=hour, minute=minute, second=0, microsecond=0)
    for _ in range(8):
        if candidate > moment and (not chosen or candidate.isoweekday() in chosen):
            return candidate.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        candidate += timedelta(days=1)
    return None


def is_due(next_run_at: Any, now: datetime | None = None) -> bool:
    """Пора ли запускать. Пустое значение считается «время не рассчитано»."""
    text = str(next_run_at or "").strip()
    if not text:
        return False
    try:
        planned = datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return planned <= (now or datetime.now(timezone.utc))


#: Что снимает правило. Отдельные значения, а не «группа или null»:
#: по строке в базе сразу видно, о чём речь.
TARGET_ALL = "all"
TARGET_GROUP = "group"
TARGET_PANEL = "panel"

TARGET_LABELS = {
    TARGET_ALL: "Все устройства",
    TARGET_GROUP: "Группа",
    TARGET_PANEL: "Архив панели",
}
