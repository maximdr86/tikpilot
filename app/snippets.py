"""
Библиотека команд: то, что написали один раз и хотят повторять.

Зачем
-----

Длинный скрипт живёт в переписке, в блокноте и в буфере обмена. Через
месяц его ищут по чату, находят три версии и не помнят, какая раскатана.
Панель, которая умеет выполнять команды на всём парке, обязана уметь их
и хранить.

Как узнаётся, где раскатано
---------------------------

Не по нашим записям о запусках, а по тому, что реально лежит на точках.
Запись библиотеки может объявить **маркер**: имя скрипта или расписания,
которое она создаёт. Панель сверяет его с паспортом устройств, который
собирается обходом.

Разница принципиальная. Журнал запусков говорит «мы отправляли это туда
в среду», а маркер отвечает на настоящий вопрос: «оно там сейчас есть?».
Скрипт могли удалить руками, точку могли перезалить из бэкапа, задача
могла упасть на середине парка. Верить надо устройству.

Маркер угадывается из текста при сохранении, но остаётся полем: угадать
можно не всегда, а человек знает точно.
"""

from __future__ import annotations

import re
from typing import Any

from .database import execute, execute_changes, query, query_one, utcnow

#: Имя скрипта или расписания в команде добавления: `add name=lte-watchdog`.
_NAME = re.compile(r"/system\s+(?:script|scheduler)\s+add\s+[^\n]*?name=([\w.-]+)", re.I)


def guess_marker(body: str) -> str:
    """
    Угадать имена создаваемых записей по тексту.

    Их почти всегда два: скрипт и расписание, которое его запускает,
    и называются они по-разному (`lte-watchdog` и `lte-watchdog-sched`).
    Пока маркер был один, панель считала собственное расписание чужим
    и писала про него «заведено вне панели».

    Несколько имён хранятся в одном поле через запятую: отдельная таблица
    ради двух строк на запись усложнила бы всё, что их читает.
    """
    names: list[str] = []
    for found in _NAME.finditer(str(body or "")):
        name = found.group(1)
        if name not in names:
            names.append(name)
    return ",".join(names)


def markers(value: Any) -> list[str]:
    """
    Маркеры записи списком. Пустые и повторы отсекаются.

    Принимает и строку из базы, и уже разобранный список: функцию зовут
    и снаружи, и изнутри соседних функций, и `str()` от списка превращал
    имена в `['lte-watchdog']` без единой ошибки, молча обнуляя счётчики.
    """
    parts = value if isinstance(value, (list, tuple, set)) else \
        str(value or "").split(",")
    seen: list[str] = []
    for part in parts:
        part = str(part).strip()
        if part and part not in seen:
            seen.append(part)
    return seen


def save(name: str, body: str, note: str = "", marker: str = "",
         username: str = "", snippet_id: int | None = None) -> int:
    """Создать или обновить запись библиотеки."""
    name = str(name or "").strip()[:120]
    body = str(body or "").strip()
    if not name or not body:
        raise ValueError("Нужны название и текст команд")

    marker = ",".join(markers(marker))[:240] or guess_marker(body)
    now = utcnow()

    if snippet_id:
        execute_changes(
            "UPDATE snippets SET name = ?, note = ?, body = ?, marker = ?,"
            " updated_at = ? WHERE id = ?",
            (name, note.strip()[:300], body, marker, now, snippet_id),
        )
        return int(snippet_id)

    return execute(
        "INSERT INTO snippets (name, note, body, marker, created_by, created_at,"
        " updated_at) VALUES (?,?,?,?,?,?,?)",
        (name, note.strip()[:300], body, marker, username, now, now),
    )


def backfill_markers() -> int:
    """
    Дописать записям библиотеки имена, которые появились у них задним числом.

    Маркер стал списком, но в базе у старых записей лежит одно имя, и само
    оно оттуда не размножится: имена вытаскиваются из текста только при
    сохранении. Без этого прохода человек видит ровно то, что видел вчера,
    и справедливо считает, что ничего не поменялось.

    Трогаем только те записи, где всё сохранённое нашлось в тексте: если
    имя правили руками и в командах его нет, значит человек знал, что
    делает, и молча переписывать его нельзя. Возвращает число правок.
    """
    changed = 0
    for row in query("SELECT id, marker, body FROM snippets"):
        stored = markers(row["marker"])
        guessed = markers(guess_marker(str(row["body"] or "")))
        if len(guessed) <= len(stored) or not set(stored) <= set(guessed):
            continue
        execute_changes("UPDATE snippets SET marker = ? WHERE id = ?",
                        (",".join(guessed), row["id"]))
        changed += 1
    return changed


def remove(snippet_id: int) -> dict[str, Any] | None:
    """Удалить запись. Возвращает удалённую, чтобы было что записать в журнал."""
    row = query_one("SELECT * FROM snippets WHERE id = ?", (snippet_id,))
    if not row:
        return None
    execute_changes("DELETE FROM snippets WHERE id = ?", (snippet_id,))
    return dict(row)


def get(snippet_id: int) -> dict[str, Any] | None:
    row = query_one("SELECT * FROM snippets WHERE id = ?", (snippet_id,))
    return dict(row) if row else None


def listing(scope: tuple[str, list[Any]] = ("", [])) -> list[dict[str, Any]]:
    """
    Библиотека вместе с тем, где каждая запись раскатана.

    Счёт идёт по маркеру и по паспорту устройств. Записи без маркера
    показываются без счётчика, и это честнее нуля: «нигде не найдено»
    и «мы не знаем, что искать» разные ответы.
    """
    rows = [dict(r) for r in query("SELECT * FROM snippets ORDER BY name COLLATE NOCASE")]
    for row in rows:
        names = markers(row["marker"])
        row["devices"] = where_deployed(names, scope)
        row["missing"] = missing(names, scope)
    return rows


def where_deployed(marker: Any, scope: tuple[str, list[Any]] = ("", []),
                   kind: str = "") -> list[dict[str, Any]]:
    """
    Точки, на которых лежит хоть одна из записей с этими именами.

    Достаточно одной: запись библиотеки ставит и скрипт, и расписание,
    и если на точке остался только скрипт, «не стоит» это неправда.
    Разбираться, что там половина, человек будет в паспорте точки.

    А вот сводке по парку нужен именно вид: там строки заведены парами
    «имя + вид», и без этого условия строка «net-watchdog, расписание»
    показывала точки, где лежит одноимённый скрипт. Одиннадцать вместо
    одной, и все не те.
    """
    names = markers(marker)
    if not names:
        return []
    holes = ",".join("?" for _ in names)
    kind_sql = " AND s.kind = ?" if kind else ""
    kind_args = (kind,) if kind else ()
    # Строка на точку, а не на найденную запись. Имён теперь несколько,
    # и точка со скриптом и его расписанием давала две строки: DISTINCT
    # их не склеивал, потому что kind разный, и счётчик показывал ровно
    # вдвое больше точек, чем есть в парке.
    #
    # «Выключено» ставим, если выключена хоть одна из записей: расписание
    # в отключке означает, что скрипт не работает, даже если сам он цел.
    rows = query(
        "SELECT d.id, d.name, MAX(s.disabled) AS disabled, "
        "COUNT(DISTINCT s.kind) AS parts FROM device_scripts s "
        "JOIN devices d ON d.id = s.device_id "
        f"WHERE s.name IN ({holes}){kind_sql} AND d.enabled = 1{scope[0]} "
        "GROUP BY d.id, d.name ORDER BY d.name COLLATE NOCASE",
        (*names, *kind_args, *scope[1]),
    )
    return [dict(row) for row in rows]


def fleet(scope: tuple[str, list[Any]] = ("", [])) -> list[dict[str, Any]]:
    """
    Всё, что найдено на устройствах, сгруппированное по имени.

    Здесь видно и то, чего в библиотеке нет: скрипт, заведённый руками
    полгода назад на трёх точках из сорока девяти, это ровно тот случай,
    ради которого раздел и нужен.
    """
    rows = query(
        "SELECT s.name, s.kind, COUNT(DISTINCT s.device_id) AS devices_count, "
        "SUM(s.disabled) AS off FROM device_scripts s "
        "JOIN devices d ON d.id = s.device_id "
        f"WHERE d.enabled = 1{scope[0]} "
        "GROUP BY s.name, s.kind ORDER BY devices_count DESC, s.name COLLATE NOCASE",
        tuple(scope[1]),
    )
    known = {name for r in query("SELECT marker FROM snippets") for name in markers(r["marker"])}
    result = []
    for row in rows:
        item = dict(row)
        item["known"] = item["name"] in known
        # Список точек прямо здесь, а не по отдельному запросу: счётчик
        # без имён заставляет обходить парк руками, ради чего вся сводка
        # и затевалась. Данных немного, десятки строк на весь парк
        item["devices"] = where_deployed(item["name"], scope, str(item["kind"]))
        result.append(item)
    return result


def missing(marker: Any, scope: tuple[str, list[Any]] = ("", [])) -> list[dict[str, Any]]:
    """
    Точки, на которых этого скрипта нет.

    Главный вопрос при раскатке: не «куда поставить», а «где ещё не стоит».
    Считать это глазами по списку из полусотни имён невозможно, а панель
    знает обе стороны.
    """
    names = markers(marker)
    if not names:
        return []
    holes = ",".join("?" for _ in names)
    rows = query(
        "SELECT d.id, d.name FROM devices d WHERE d.enabled = 1"
        f"{scope[0]} AND d.id NOT IN ("
        f"  SELECT device_id FROM device_scripts WHERE name IN ({holes})) "
        "ORDER BY d.name COLLATE NOCASE",
        (*scope[1], *names),
    )
    return [dict(row) for row in rows]
