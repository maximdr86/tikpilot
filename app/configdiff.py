"""
Работа с текстовыми экспортами конфигураций: сравнение и поиск.

Две задачи, ради которых бэкапы вообще стоит хранить дольше одного дня:

* **что изменилось.** Сравнение двух копий одной точки отвечает на вопрос
  «конфиг трогали?» и показывает, что именно. После аварии это первое,
  что хочется увидеть;
* **где ещё так же.** Поиск строки по всем точкам сразу: где остался
  старый DNS, на каких площадках есть правило с этим адресом. Иначе это
  обход полусотни роутеров руками.

Работает только с текстовыми экспортами `.rsc`. Бинарный `.backup` это
непрозрачный слепок, и сравнивать в нём нечего.

Про шапку экспорта
------------------

RouterOS кладёт в первую строку дату и версию:

    # aug/06/2026 08:44:00 by RouterOS 7.14.3

Она меняется при каждом снятии, поэтому без отбрасывания таких строк любые
две копии отличались бы всегда, и ответ «изменений нет» не наступал бы
никогда. Именно этот ответ обычно и нужен.
"""

from __future__ import annotations

import difflib
import re
from pathlib import Path
from typing import Any, Iterable

from .config import settings

#: Строка-шапка экспорта: комментарий, начинающийся с даты.
_VOLATILE = re.compile(
    r"^#\s*(?:\w{3}/\d{1,2}/\d{4}|\d{4}-\d{2}-\d{2})[\s\d:]*",
    re.I,
)

#: Больше этого файл не читаем. Экспорт крупного роутера редко превышает
#: сотни килобайт, а десяток мегабайт означает, что что-то пошло не так,
#: и класть это в память незачем.
MAX_BYTES = 8 * 1024 * 1024


def is_volatile(line: str) -> bool:
    """Строка меняется сама по себе и для сравнения бесполезна."""
    return bool(_VOLATILE.match(line.strip()))


def safe_path(filename: Any) -> Path | None:
    """
    Путь к файлу бэкапа с проверкой, что он внутри каталога бэкапов.

    Имя приходит из базы, но подставить туда своё значение может тот, кто
    доберётся до API, поэтому проверяем всегда.
    """
    text = str(filename or "").strip()
    if not text:
        return None
    path = (settings.backup_dir / text).resolve()
    if not str(path).startswith(str(settings.backup_dir.resolve())):
        return None
    return path if path.is_file() else None


def read_lines(filename: Any) -> list[str]:
    """Строки экспорта. Пустой список, если файла нет или он не читается."""
    path = safe_path(filename)
    if path is None or path.stat().st_size > MAX_BYTES:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return text.splitlines()


def meaningful(lines: Iterable[str]) -> list[str]:
    """Строки без шапки: только то, что действительно описывает настройку."""
    return [line for line in lines if not is_volatile(line)]


def compare(old: Iterable[str], new: Iterable[str]) -> dict[str, Any]:
    """
    Сравнить две конфигурации.

    Возвращает список кусков в духе `diff` и счётчики. Показываем именно
    куски с окружением, а не полный текст: в экспорте тысячи строк, и
    изменённые три из них в нём не найти.
    """
    left, right = meaningful(old), meaningful(new)

    rows: list[dict[str, str]] = []
    added = removed = 0
    for line in difflib.unified_diff(left, right, lineterm="", n=3):
        if line.startswith("---") or line.startswith("+++"):
            continue
        if line.startswith("@@"):
            rows.append({"kind": "hunk", "text": line})
        elif line.startswith("+"):
            rows.append({"kind": "add", "text": line[1:]})
            added += 1
        elif line.startswith("-"):
            rows.append({"kind": "del", "text": line[1:]})
            removed += 1
        else:
            rows.append({"kind": "same", "text": line[1:] if line else ""})

    return {
        "rows": rows,
        "added": added,
        "removed": removed,
        "same": not rows,
        "old_lines": len(left),
        "new_lines": len(right),
    }


def numbered(lines: Iterable[str]) -> list[tuple[int, str]]:
    """
    Строки с их настоящими номерами в файле, без шапки экспорта.

    Номер именно из файла, а не порядковый в отфильтрованном списке: по
    нему человек находит место в скачанном `.rsc`, и расхождение в одну
    строку выйдет боком ровно тогда, когда будет некогда разбираться.
    """
    return [(number, line) for number, line in enumerate(lines, start=1)
            if not is_volatile(line)]


def compare_sides(old: Iterable[str], new: Iterable[str],
                  context: int = 3) -> dict[str, Any]:
    """
    Сравнение двумя колонками: слева было, справа стало.

    Так это показывают Winbox, GitHub и любой инструмент, которым человек
    пользовался раньше. Единый список с `@@ -77,8 +77,7 @@` привычен тому,
    кто каждый день живёт в `git diff`, и совершенно нечитаем всем
    остальным: эти числа надо расшифровывать, а они ещё и не отвечают
    ни на один вопрос, который задают, глядя на конфиг.

    Неизменные куски сворачиваются, оставляя по несколько строк вокруг
    правки: в экспорте их тысячи, и три изменённые в них не найти.
    Вместо загадочной строки с решётками пишем словами, сколько пропущено.
    """
    left, right = numbered(old), numbered(new)
    left_text = [text for _, text in left]
    right_text = [text for _, text in right]

    matcher = difflib.SequenceMatcher(None, left_text, right_text, autojunk=False)
    opcodes = matcher.get_opcodes()

    rows: list[dict[str, Any]] = []
    added = removed = 0

    def pair(kind: str, old_index: int | None, new_index: int | None) -> None:
        rows.append({
            "kind": kind,
            "left_no": left[old_index][0] if old_index is not None else None,
            "left": left[old_index][1] if old_index is not None else "",
            "right_no": right[new_index][0] if new_index is not None else None,
            "right": right[new_index][1] if new_index is not None else "",
        })

    for index, (tag, i1, i2, j1, j2) in enumerate(opcodes):
        if tag == "equal":
            size = i2 - i1
            head = context if index > 0 else 0
            tail = context if index < len(opcodes) - 1 else 0
            if size > head + tail + 1:
                for step in range(head):
                    pair("same", i1 + step, j1 + step)
                rows.append({"kind": "skip", "skipped": size - head - tail})
                for step in range(tail, 0, -1):
                    pair("same", i2 - step, j2 - step)
            else:
                for step in range(size):
                    pair("same", i1 + step, j1 + step)
            continue

        # Изменённые куски выравниваем построчно: правка одной строки
        # должна стоять напротив своей пары, а не съезжать вниз
        old_range = list(range(i1, i2))
        new_range = list(range(j1, j2))
        removed += len(old_range)
        added += len(new_range)
        for step in range(max(len(old_range), len(new_range))):
            pair(
                "change" if step < len(old_range) and step < len(new_range)
                else ("del" if step < len(old_range) else "add"),
                old_range[step] if step < len(old_range) else None,
                new_range[step] if step < len(new_range) else None,
            )

    return {
        "rows": rows,
        "added": added,
        "removed": removed,
        "changes": added + removed,
        "same": added == 0 and removed == 0,
        "old_lines": len(left),
        "new_lines": len(right),
    }


def search(needle: str, files: Iterable[dict[str, Any]],
           limit_per_file: int = 20) -> list[dict[str, Any]]:
    """
    Найти строку в экспортах.

    `files` — записи бэкапов с полями `filename` и `device_name`. Поиск
    без учёта регистра: в конфигурации RouterOS одно и то же пишут и так,
    и эдак, а человек ищет то, что помнит.

    Число совпадений на файл ограничено: строка вроде «add» встречается
    в экспорте сотни раз, и вываливать их все означает сделать страницу
    нечитаемой ровно тогда, когда запрос задан неудачно.
    """
    text = str(needle or "").strip().lower()
    if not text:
        return []

    result = []
    for item in files:
        matches = []
        for number, line in enumerate(read_lines(item.get("filename")), start=1):
            if text in line.lower():
                matches.append({"line": number, "text": line.strip()[:300]})
                if len(matches) >= limit_per_file:
                    break
        if matches:
            result.append({
                "device_id": item.get("device_id"),
                "device_name": item.get("device_name") or "",
                "filename": item.get("filename"),
                "created_at": item.get("created_at"),
                "matches": matches,
                "count": len(matches),
            })

    result.sort(key=lambda r: r["device_name"].lower())
    return result
