"""
Переводы интерфейса.

Устройство слоя намеренно необычное, поэтому объясню зачем.

Обычный путь — обернуть каждую надпись в шаблоне вызовом `_("...")`. В этом
проекте таких надписей около шестисот, и рано или поздно кто-то добавит новую
кнопку, забыв про обёртку: строка молча останется русской. Вместо этого
шаблоны остаются как есть, а расширение Jinja2 `TranslateExtension`
оборачивает русский текст само, на этапе компиляции шаблона. Компиляция
происходит один раз, дальше работает кэш — на скорость отрисовки это не влияет.

Ключом перевода служит сам русский текст. Так делает gettext, и у подхода два
приятных следствия: шаблоны остаются читаемыми, а если перевода нет, надпись
показывается по-русски, а не пустотой или служебным идентификатором.

Подстановки внутри фразы сохраняются: текст
«Проверка каждые {{ n }} с» превращается в ключ «Проверка каждые %(p0)s с».
Переводчик волен переставить подстановку куда угодно — в английском порядок
слов другой.

Добавить язык: положить `app/locales/<код>.json` рядом с `en.json`.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Iterable

from jinja2 import nodes
from jinja2.ext import Extension

from .config import BASE_DIR

log = logging.getLogger(__name__)

LOCALES_DIR = BASE_DIR / "app" / "locales"

#: Язык исходных строк. Для него перевод не нужен по определению.
SOURCE_LANG = "ru"

#: Подписи для переключателя. Ключ — код языка, значение — как он называет сам себя.
LANGUAGE_NAMES = {"ru": "Русский", "en": "English"}

_catalogs: dict[str, dict[str, str]] = {}
_patterns: dict[str, list[tuple[re.Pattern[str], str]]] = {}

#: Ключ в файле перевода со списком шаблонов для строк с переменной частью.
#: Формат: [["^Не ответило за (\\d+) с$", "No answer within \\1 s"], ...]
PATTERNS_KEY = "__patterns__"


# --------------------------------------------------------------- каталоги
def load_catalogs() -> dict[str, dict[str, str]]:
    """Прочитать все файлы переводов. Вызывается один раз при старте."""
    _catalogs.clear()
    _patterns.clear()
    if LOCALES_DIR.is_dir():
        for path in sorted(LOCALES_DIR.glob("*.json")):
            code = path.stem
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                # Битый файл перевода не должен ронять приложение: язык
                # просто останется непереведённым.
                log.error("Не удалось прочитать перевод %s: %s", path.name, exc)
                continue

            _catalogs[code] = {
                k: v for k, v in data.items() if isinstance(v, str) and k != PATTERNS_KEY
            }

            rules: list[tuple[re.Pattern[str], str]] = []
            for entry in data.get(PATTERNS_KEY, []) or []:
                try:
                    rules.append((re.compile(entry[0]), entry[1]))
                except (re.error, IndexError, TypeError) as exc:
                    log.error("Плохое правило в переводе %s: %s", path.name, exc)
            _patterns[code] = rules

            log.info(
                "Загружен перевод %s: %s строк, %s правил",
                code, len(_catalogs[code]), len(rules),
            )
    return _catalogs


def available_languages() -> list[tuple[str, str]]:
    """Языки, доступные в переключателе: [(код, название), ...]."""
    codes = [SOURCE_LANG] + [c for c in sorted(_catalogs) if c != SOURCE_LANG]
    return [(c, LANGUAGE_NAMES.get(c, c.upper())) for c in codes]


def browser_lang(header: Any) -> str | None:
    """
    Язык из заголовка Accept-Language, если он нам знаком.

    В панели язык браузера намеренно не учитывается: её открывают на рабочем
    компьютере, системный язык которого к предпочтениям в работе отношения
    не имеет. Публичная страница другое дело: ссылку открывает человек со
    стороны, о котором не известно ничего, кроме этого заголовка.

    Разбор нарочно простой: коды по порядку, первый знакомый выигрывает.
    Веса `q=` не считаем — браузеры и так перечисляют языки по убыванию.
    """
    known = dict(available_languages())
    for part in str(header or "").split(","):
        code = part.split(";")[0].strip().lower().replace("_", "-").split("-")[0]
        if code in known:
            return code
    return None


def normalize_lang(value: Any) -> str:
    """
    Привести код языка к поддерживаемому.

    Принимаем и «en-US», и «EN» — браузеры и люди пишут по-разному.
    Неизвестный язык молча превращается в язык по умолчанию.
    """
    from .config import settings

    code = str(value or "").strip().lower().replace("_", "-").split("-")[0]
    if code == SOURCE_LANG or code in _catalogs:
        return code
    return settings.default_lang if settings.default_lang in dict(available_languages()) else SOURCE_LANG


# ------------------------------------------------------------- перевод
def translate(msgid: str, lang: str = SOURCE_LANG, **params: Any) -> str:
    """
    Перевести строку и подставить значения.

    Отсутствие перевода — не ошибка: показываем исходный русский текст.
    Полноту каталога проверяет отдельный тест, а не рантайм.
    """
    text = msgid
    if lang != SOURCE_LANG:
        text = _catalogs.get(lang, {}).get(msgid, msgid)

    if params:
        for candidate in (text, _escape_lone_percent(text),
                          msgid, _escape_lone_percent(msgid)):
            try:
                return candidate % params
            except (KeyError, ValueError, TypeError):
                continue
        # Ни один вариант не подставился: показываем исходный текст как есть.
        # Страница с сырым «%(p0)s» уродлива, но живая страница важнее
        log.warning("Плохая подстановка в переводе: %r", msgid)
    return text


def _escape_lone_percent(text: str) -> str:
    """
    Удвоить знаки процента, которые не начинают подстановку.

    Фраза «готово 12 (35%)» это нормальный человеческий текст, и требовать
    от того, кто пишет интерфейс, помнить про %-форматирование, значит
    расставлять мины. Одиночный процент ломал подстановку целиком, и
    вместо строки прогресса на странице задачи висело «%(p0)s из %(p1)s».
    """
    result: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "%":
            following = text[index + 1] if index + 1 < len(text) else ""
            if following in ("(", "%"):
                # Начало подстановки или уже удвоенный процент: не трогаем
                result.append(text[index:index + 2])
                index += 2
                continue
            result.append("%%")
        else:
            result.append(char)
        index += 1
    return "".join(result)


def translate_text(value: str, lang: str = SOURCE_LANG) -> str:
    """
    Перевести строку, пришедшую из Python или из базы.

    Отличается от `translate` тем, что умеет строки с переменной частью:
    «Устройство не ответило на команду /system/script/run за 120 с» —
    имя команды и число подставлены заранее, точного ключа для такой строки
    быть не может. Для них в файле перевода есть список регулярных правил.

    Строки, которых нет ни в каталоге, ни в правилах, возвращаются как есть.
    Для имён устройств, версий RouterOS и прочих данных это ровно то,
    что нужно.
    """
    if lang == SOURCE_LANG or not value:
        return value

    exact = _catalogs.get(lang, {}).get(value)
    if exact is not None:
        return exact

    for rule, replacement in _patterns.get(lang, []):
        match = rule.search(value)
        if not match:
            continue

        # Внутри подставленного куска тоже может быть знакомая строка:
        # «Запуск: Проверить статус» это правило плюс название действия.
        # Без этого шага получалось «Started: Проверить статус».
        result = replacement
        for index, group in enumerate(match.groups(), start=1):
            piece = translate_text(group, lang) if group else (group or "")
            result = result.replace("\\%d" % index, piece)
        return result
    return value


def plural(count: Any, forms: Iterable[str], lang: str = SOURCE_LANG) -> str:
    """
    Выбрать форму слова по числу с учётом языка.

    В русском форм три (1 устройство, 2 устройства, 5 устройств),
    в английском две. Каталог хранит их одной строкой через «|», поэтому
    переводчику не нужно знать про наши внутренние соглашения:
    «устройство|устройства|устройств» → «device|devices».
    """
    forms = list(forms)
    if not forms:
        return ""

    key = "|".join(forms)
    if lang != SOURCE_LANG:
        translated = _catalogs.get(lang, {}).get(key)
        if translated:
            forms = translated.split("|")

    try:
        number = abs(int(count))
    except (TypeError, ValueError):
        return forms[-1]

    if lang == "ru" or len(forms) >= 3:
        if number % 10 == 1 and number % 100 != 11:
            index = 0
        elif 2 <= number % 10 <= 4 and not 12 <= number % 100 <= 14:
            index = 1
        else:
            index = 2
    else:
        # Английский и большинство прочих: единственное и множественное.
        index = 0 if number == 1 else 1

    return forms[min(index, len(forms) - 1)]


# ------------------------------------- автоматическая пометка строк в шаблонах
CYRILLIC = re.compile(r"[Ѐ-ӿ]")

#: Куски шаблона, которые разбираем отдельно. Порядок важен: комментарии и
#: теги Jinja должны опознаваться раньше HTML.
_TOKEN = re.compile(
    r"""
      (?P<comment>\{\#.*?\#\})
    | (?P<stmt>\{%.*?%\})
    | (?P<expr>\{\{.*?\}\})
    | (?P<raw><(?P<rawtag>script|style|pre)\b[^>]*>.*?</(?P=rawtag)\s*>)
    | (?P<tag><[^>]*>)
    """,
    re.S | re.X | re.I,
)

#: Строчные теги оформления. Они не разрывают фразу, а попадают внутрь ключа:
#: «Разделитель (<code>,</code> или <code>;</code>) определяется автоматически»
#: перевести можно, а три обрывка вокруг тегов — уже нет.
_INLINE_TAGS = {
    "a", "b", "strong", "em", "i", "u", "s", "small", "span",
    "code", "kbd", "mark", "sup", "sub", "br", "wbr", "abbr",
}
_TAG_NAME = re.compile(r"</?\s*([a-zA-Z0-9-]+)")

#: Атрибуты, содержимое которых видит пользователь.
_TEXT_ATTRS = ("placeholder", "title", "alt", "value", "label", "aria-label")
_ATTR = re.compile(
    r"""(?P<name>%s)\s*=\s*(?P<quote>["'])(?P<value>.*?)(?P=quote)"""
    % "|".join(_TEXT_ATTRS),
    re.S | re.I,
)


def _quote(text: str) -> str:
    """Строковый литерал для вставки в шаблон."""
    return '"%s"' % text.replace("\\", "\\\\").replace('"', '\\"')


def _build_call(parts: list[tuple[str, str]]) -> tuple[str, str] | None:
    """
    Собрать вызов `_()` из кусочков текста и выражений.

    parts — список пар («text»|«expr», содержимое). Возвращает пару
    (готовый код для шаблона, ключ перевода) либо None, если переводить нечего.
    """
    msgid_parts: list[str] = []
    args: list[str] = []
    for kind, value in parts:
        if kind == "text":
            msgid_parts.append(value)
        else:
            msgid_parts.append("%%(p%d)s" % len(args))
            args.append(value.strip())

    msgid = "".join(msgid_parts)
    # Пробелы и переносы строк внутри фразы схлопываем: в HTML они всё равно
    # равны одному пробелу, а ключ должен быть стабильным при переносе строк.
    msgid = re.sub(r"\s+", " ", msgid).strip()
    if not msgid or not CYRILLIC.search(msgid):
        return None

    call = "_(%s" % _quote(msgid)
    for index, expr in enumerate(args):
        call += ", p%d=(%s)" % (index, expr)
    call += ")"
    return call, msgid


def _wrap_attributes(tag: str, found: set[str]) -> str:
    """Перевести пользовательские атрибуты внутри одного HTML-тега."""

    def replace(match: re.Match[str]) -> str:
        value = match.group("value")
        if not CYRILLIC.search(value) or "{%" in value:
            # Условия внутри атрибута разбирать не беремся — таких мест мало,
            # и они всё равно собираются из уже переведённых кусков.
            return match.group(0)

        parts: list[tuple[str, str]] = []
        position = 0
        for expr in re.finditer(r"\{\{(.*?)\}\}", value, re.S):
            parts.append(("text", value[position:expr.start()]))
            parts.append(("expr", expr.group(1)))
            position = expr.end()
        parts.append(("text", value[position:]))

        built = _build_call(parts)
        if not built:
            return match.group(0)
        call, msgid = built
        found.add(msgid)
        return '%s="{{ %s }}"' % (match.group("name"), call)

    return _ATTR.sub(replace, tag)


def mark_translatable(source: str, found: set[str] | None = None) -> str:
    """
    Обернуть русский текст шаблона вызовами `_()`.

    Выполняется один раз при компиляции шаблона. `found` — необязательное
    множество, куда складываются найденные ключи: этим пользуется тест
    полноты перевода и скрипт выгрузки строк.
    """
    found = found if found is not None else set()
    out: list[str] = []
    run: list[tuple[str, str]] = []  # накопленный текстовый фрагмент

    def flush() -> None:
        """Закрыть текущий фрагмент: перевести его или вернуть как было."""
        if not run:
            return
        raw = "".join(
            value if kind == "text" else "{{%s}}" % value for kind, value in run
        )
        built = _build_call(run)
        if built:
            call, msgid = built
            found.add(msgid)
            # Пробелы по краям сохраняем: они отделяют фразу от соседних тегов.
            lead = raw[: len(raw) - len(raw.lstrip())]
            tail = raw[len(raw.rstrip()):]
            out.append("%s{{ %s }}%s" % (lead, call, tail))
        else:
            out.append(raw)
        run.clear()

    position = 0
    for token in _TOKEN.finditer(source):
        text = source[position:token.start()]
        if text:
            run.append(("text", text))
        position = token.end()

        if token.lastgroup == "expr" or token.group("expr"):
            run.append(("expr", token.group("expr")[2:-2]))
            continue

        chunk = token.group(0)
        if token.group("tag"):
            name = _TAG_NAME.match(chunk)
            inline = name and name.group(1).lower() in _INLINE_TAGS
            # Строчный тег без вставок Jinja оставляем внутри фразы.
            if inline and "{{" not in chunk and "{%" not in chunk:
                run.append(("text", chunk))
                continue
            chunk = _wrap_attributes(chunk, found)

        # Любой другой токен обрывает фразу.
        flush()
        out.append(chunk)

    tail = source[position:]
    if tail:
        run.append(("text", tail))
    flush()
    return "".join(out)


class TranslateExtension(Extension):
    """Подключает автоматическую пометку строк к окружению Jinja2."""

    def preprocess(self, source: str, name: str | None, filename: str | None = None) -> str:
        return mark_translatable(source)

    def parse(self, parser: Any) -> nodes.Node:  # pragma: no cover - не используется
        raise NotImplementedError


#: Строки, зашитые в static/app.js. Браузер берёт их из `window.I18N`,
#: который отдаёт сервер уже переведённым. Список собирается из самого файла,
#: чтобы не разъезжался при правках JS.
_JS_CALL = re.compile(r"T\('([^']*)'\)")


def js_strings() -> list[str]:
    """
    Строки, которые нужно передать в браузер вместе со страницей.

    Ищем и в app.js, и в шаблонах: часть скриптов встроена прямо в страницу,
    например подмена браузерных подсказок о незаполненных полях.
    """
    found: set[str] = set()
    for path in [BASE_DIR / "static" / "app.js", *sorted((BASE_DIR / "templates").rglob("*.html"))]:
        try:
            found.update(_JS_CALL.findall(path.read_text(encoding="utf-8")))
        except OSError:
            continue
    return sorted(found)


def js_catalog(lang: str) -> dict[str, str]:
    """Словарь для `window.I18N`: только то, что реально нужно браузеру."""
    if lang == SOURCE_LANG:
        return {}
    return {text: translate(text, lang) for text in js_strings()}


def template_msgids(templates_dir: Path) -> set[str]:
    """Собрать ключи перевода со всех шаблонов. Нужно тесту и выгрузке строк."""
    found: set[str] = set()
    for path in sorted(templates_dir.rglob("*.html")):
        mark_translatable(path.read_text(encoding="utf-8"), found)
    return found


def missing_translations(lang: str, templates_dir: Path) -> list[str]:
    """Ключи, для которых нет перевода на указанный язык."""
    catalog = _catalogs.get(lang, {})
    return sorted(k for k in template_msgids(templates_dir) if k not in catalog)
