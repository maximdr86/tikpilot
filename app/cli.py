"""
Команды RouterOS ровно в том виде, в каком их пишут в терминале.

Зачем понадобилось
------------------

Массовое действие «Произвольная команда» умело только синтаксис API:
путь через слэши и параметры отдельными строками. Это не то, что человек
держит в голове и не то, что лежит у него в шпаргалке. Из Winbox, с форума
и из своей же истории команда копируется в консольном виде:

    /ip service
    set api address="192.168.88.0/24,10.10.0.0/24"

и она не работала. Приходилось разбирать её руками на путь и аргументы,
то есть делать за панель работу, ради которой панель и заводили.

Как это делается теперь
-----------------------

Команда уходит на устройство по SSH, и разбирает её сам RouterOS. Это
единственный способ получить настоящий консольный синтаксис: `where`,
`find`, диапазоны, кавычки, скрипты. Переписывать разбор консоли RouterOS
на своей стороне значило бы обещать совместимость, которую невозможно
выполнить, и ломаться на каждой второй команде с форума.

Панель делает ровно две вещи перед отправкой.

**Склеивает перенесённые строки.** Длинное значение консоль переносит
обратным слэшем в конце строки и отступом в начале следующей. Скопированная
команда выглядит рваной, и в таком виде она не выполнится. Обратная склейка
это не украшение: без неё вставленный из Winbox список сетей превращается
в полсотни битых команд.

**Помнит текущее меню.** В консоли `/ip service` это переход в раздел,
а `set api ...` следующей строкой относится уже к нему. По SSH каждая
команда выполняется сама по себе, поэтому путь подставляется к следующим
строкам, и получается то же самое, что человек видел в терминале.

Ни во что другое панель не вмешивается: строка уходит как написана.
"""

from __future__ import annotations

import re
from typing import Any

#: Сколько ждать ответа на одну команду. Секунды хватает на `print`,
#: но не хватает на `/system/backup/save` и на команды с ожиданием,
#: поэтому по умолчанию минута.
DEFAULT_TIMEOUT = 60

#: Ограничение на длину вывода одной команды. Живой `/log print` без
#: фильтра это мегабайты, а в результат задачи их класть некуда.
MAX_OUTPUT = 8000

#: Строки RouterOS, по которым видно, что команда не выполнилась.
#: Код возврата у RouterOS не всегда отличает ошибку от успеха, а текст
#: отличает всегда.
_ERROR_MARKS = (
    "expected end of command",
    "syntax error",
    "no such item",
    "no such command",
    "bad command name",
    "invalid value",
    "unknown parameter",
    "failure:",
    "cannot ",
    "input does not match",
    "ambiguous command name",
)

#: Путь меню: только слова, слэши и дефисы. Ни знака равенства, ни кавычек.
_PATH_ONLY = re.compile(r"^/[A-Za-z0-9/ _-]*$")

#: Слова, после которых строка это уже команда, а не путь. Иначе
#: `/interface print` считался бы переходом в раздел «print», а команда
#: молча пропадала бы.
_VERBS = {
    "print", "set", "add", "remove", "enable", "disable", "unset", "move",
    "edit", "export", "import", "monitor", "reset", "reset-configuration",
    "find", "get", "comment", "scan", "upgrade", "reboot", "shutdown",
    "save", "load", "run", "stop", "start", "clear", "blink", "discover",
    "check-for-updates", "download", "install", "ping", "resolve", "sniff",
    "unhide", "cancel", "retry", "make-supout.rif", "backup", "restore",
}


def brace_depth(text: str, depth: int = 0) -> int:
    """
    Глубина вложенности фигурных скобок с учётом кавычек.

    Скобка внутри строки в кавычках это символ, а не начало блока:
    `on-event="/system script run x"` не открывает ничего, а
    `source={` открывает.
    """
    quoted = False
    escaped = False
    for char in text:
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
        elif char == '"':
            quoted = not quoted
        elif not quoted and char == "{":
            depth += 1
        elif not quoted and char == "}":
            depth = max(0, depth - 1)
    return depth


def unwrap(text: str) -> list[str]:
    """
    Собрать из текста логические команды.

    Две склейки, и обе обязательны.

    **Перенос обратным слэшем.** Консоль RouterOS переносит длинное
    значение слэшем в конце строки и выравнивает продолжение пробелами.
    Отступ продолжения выбрасываем: он часть оформления, а не значения.

    **Блок в фигурных скобках.** Тело скрипта в `source={ ... }` занимает
    десятки строк, и это одна команда, а не десятки. Без учёта скобок
    первая же строка уходила на устройство обрезанной, роутер отвечал
    «expected closing brace», а остальные строки летели следом как
    самостоятельные команды и сыпались одна за другой. Ровно это и
    случилось с watchdog-скриптом на живой точке.
    """
    physical: list[str] = []
    buffer = ""
    for raw in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw.rstrip()
        if buffer:
            # Продолжение перенесённой строки: ведущие пробелы это отступ
            line = buffer + line.lstrip()
            buffer = ""
        if line.endswith("\\"):
            buffer = line[:-1]
            continue
        physical.append(line.strip())
    if buffer.strip():
        physical.append(buffer.strip())

    result: list[str] = []
    block = ""
    depth = 0
    for line in physical:
        if depth <= 0 and (not line or line.startswith("#")):
            # Пустые строки и комментарии выбрасываем только снаружи блока:
            # внутри тела скрипта они часть текста, который уйдёт на роутер
            continue
        block = f"{block}\n{line}" if block else line
        depth = brace_depth(line, depth)
        if depth <= 0:
            result.append(block)
            block, depth = "", 0
    if block:
        # Скобку не закрыли: отдаём как есть, пусть роутер объяснит, что не так
        result.append(block)
    return result


def assemble(lines: list[str]) -> list[str]:
    """
    Собрать готовые команды с учётом текущего меню.

    Строка вида `/ip service` это переход в раздел, и сама по себе
    ничего не делает. Строка `set api ...` после неё относится к разделу.
    По SSH контекста между командами нет, поэтому путь приклеивается
    к каждой следующей строке.
    """
    result: list[str] = []
    path = ""
    path_used = True

    def is_path(line: str) -> bool:
        """Строка это переход в раздел, а не команда."""
        if "\n" in line:
            return False        # многострочный блок это точно команда
        if not (line.startswith("/") and _PATH_ONLY.match(line)):
            return False
        return not any(word in _VERBS for word in line.split())

    def flush() -> None:
        """
        Отправить путь, к которому так и не пришло команды.

        Обычно это опечатка в пути, и ответить на неё должен роутер,
        а не панель: свой список разделов RouterOS знает лучше нас,
        а молча проглоченная строка выглядит как «панель сломалась».
        Порядок при этом сохраняется, иначе отказ приезжал бы в конце
        вывода, после команд, которые шли за ним.
        """
        nonlocal path_used
        if path and not path_used:
            result.append(path)
        path_used = True

    for line in lines:
        if is_path(line):
            flush()
            path, path_used = line.rstrip("/"), False
            continue
        if line == "..":
            flush()
            path, path_used = path.rsplit("/", 1)[0], False
            continue
        if line.startswith("/") or line.startswith(":"):
            flush()
            # Полный путь или скриптовая команда: как написано, так и уйдёт
            result.append(line)
            continue
        result.append(f"{path} {line}".strip() if path else line)
        path_used = True

    flush()
    return result


def parse(text: str) -> list[str]:
    """Текст из формы в список команд, готовых к отправке."""
    return [flatten(command) for command in assemble(unwrap(text))]


def flatten(command: str) -> str:
    """
    Свести многострочную команду в одну строку.

    RouterOS по SSH выполняет ровно одну команду за вызов. Многострочный
    текст он принимает как первую строку и ждёт продолжения с терминала,
    которого в этом режиме нет: соединение молчит до таймаута, а в ответе
    не остаётся вообще ничего. Именно так вёл себя живой роутер, когда
    панель отправляла тело скрипта переносами.

    Внутри тела скрипта перенос строки это разделитель операторов, такой
    же, как точка с запятой. Поэтому строки склеиваются точкой с запятой,
    кроме двух случаев, где она была бы синтаксической ошибкой: сразу
    после открывающей скобки и перед закрывающей.
    """
    if "\n" not in command:
        return command

    result = ""
    for line in (part.strip() for part in command.split("\n")):
        if not line:
            continue
        if not result:
            result = line
            continue
        if result.endswith(("{", ";")) or line.startswith("}"):
            result += " " + line
        else:
            result += "; " + line
    return result


def looks_like_error(output: str) -> bool:
    """Похож ли ответ устройства на отказ."""
    low = output.lower()
    return any(mark in low for mark in _ERROR_MARKS)


def run(client: Any, commands: list[str], timeout: int = DEFAULT_TIMEOUT,
        stop_on_error: bool = True) -> tuple[str, bool]:
    """
    Выполнить команды по одной. Возвращает вывод и признак ошибки.

    По одной, а не всё сразу: иначе непонятно, какая именно строка
    не выполнилась, а при настройке полусотни точек это первый вопрос.

    Остановка на первой ошибке по умолчанию. Продолжать разумно, только
    когда команды независимы; когда вторая опирается на первую, продолжение
    доводит устройство до состояния, которого не хотел никто.
    """
    parts: list[str] = []
    failed = False

    for command in commands:
        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", "replace")
            err = stderr.read().decode("utf-8", "replace")
        except Exception as exc:  # noqa: BLE001 — текст уйдёт человеку как есть
            # У таймаута paramiko текст пустой, и в результате задачи
            # оставалась голая команда без единого слова о том, что
            # случилось. Объяснение важнее точной формулировки библиотеки
            reason = str(exc).strip() or (
                f"устройство не ответило за {timeout} с и не закрыло канал")
            parts.append(f"$ {command}\n{reason}")
            parts.append("Остановлено: команда не выполнилась.")
            failed = True
            break

        answer = (out + err).strip()
        bad = looks_like_error(answer)
        parts.append(f"$ {command}" + (f"\n{answer}" if answer else ""))
        if bad:
            failed = True
            if stop_on_error:
                parts.append("Остановлено: команда не выполнилась.")
                break

    text = "\n".join(parts).strip() or "Команды выполнены, устройство ответило молча."
    if len(text) > MAX_OUTPUT:
        text = text[:MAX_OUTPUT] + "\n... вывод обрезан"
    return text, failed
