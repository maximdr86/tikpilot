"""
Производитель по MAC-адресу.

Зачем
-----

В списке клиентов половина строк это `no name` и голый MAC. Имя
производителя превращает такую строку в «а, это касса» или «камера
на входе» без похода на площадку.

Откуда берётся
--------------

Два слоя, и они дополняют друг друга:

1. **Встроенная таблица** (`app/vendors.json`) - короткий список частого
   железа. Работает всегда, в том числе на панели без интернета, и
   поставляется вместе с программой;

2. **Реестры IEEE** - настоящая база, откуда берут имена все остальные.
   Панель скачивает её по кнопке в настройках и кладёт рядом с базой
   данных. Найденное там сильнее встроенного: список из репозитория
   стареет вместе с релизом, а скачанный обновляется когда угодно.

Реестров три, и это важно: производителю выделяют блок разной длины.
`MA-L` это привычные 24 бита (первые три байта), `MA-M` - 28 бит,
`MA-S` - 36 бит. Мелкие производители сидят как раз в коротких блоках,
поэтому поиск по одним трём байтам их не находит, а найдя, называет
именем владельца всего блока, то есть чужим. Ищем от длинного к
короткому: сначала 36 бит, потом 28, потом 24.

Чего тут нет
------------

Имя владельца блока это не модель и не тип устройства. `Apple` в строке
означает лишь, что железку выпустила Apple: телефон это, часы или
приставка, MAC не скажет.
"""

from __future__ import annotations

import csv
import gzip
import io
import json
import logging
import re
import urllib.request
from typing import Any, Iterable

from .config import BASE_DIR, settings

log = logging.getLogger("tikpilot.vendors")

#: Короткий список, который едет вместе с программой.
BUNDLED_PATH = BASE_DIR / "app" / "vendors.json"

#: Скачанные реестры. Рядом с базой, а не в коде: обновление панели
#: не должно откатывать базу вендоров к состоянию на день релиза.
LOCAL_PATH = settings.data_dir / "vendors-ieee.tsv.gz"

#: Реестры IEEE и длина префикса в шестнадцатеричных знаках.
#: 6 знаков это 24 бита, 7 - 28 бит, 9 - 36 бит.
SOURCES = (
    ("MA-L", "https://standards-oui.ieee.org/oui/oui.csv", 6),
    ("MA-M", "https://standards-oui.ieee.org/oui28/mam.csv", 7),
    ("MA-S", "https://standards-oui.ieee.org/oui36/oui36.csv", 9),
)

#: Как часто обновлять базу самой, если это разрешено. Реестр меняется
#: медленно: за месяц набирается несколько сотен новых блоков.
REFRESH_DAYS = 30

#: Юридические хвосты, которые в таблице только мешают. Порядок важен:
#: длинные раньше коротких, иначе от «CO.,LTD» останется «CO.,».
SUFFIXES = (
    "corporation", "incorporated", "technologies", "technology",
    "electronics", "international", "industrial", "industries",
    "limited", "company", "holding", "holdings", "systems", "system",
    "networks", "network", "digital", "telecom", "trading", "group",
    "co.,ltd", "co., ltd", "co ltd", "pvt ltd", "pte ltd", "sdn bhd",
    "gmbh", "s.a.s", "s.p.a", "s.r.l", "b.v", "n.v", "a/s", "oy", "ab",
    "inc", "llc", "ltd", "plc", "corp", "co", "kg", "ag", "sa", "srl", "spa",
)

_table: dict[str, str] | None = None


def load() -> dict[str, str]:
    """
    Собрать таблицу префиксов. Скачанное сильнее встроенного.

    Читается один раз: 45 тысяч строк это пара мегабайт в памяти, а
    список клиентов дёргается на каждой странице.
    """
    global _table

    if _table is not None:
        return _table

    table: dict[str, str] = {}
    try:
        table.update(json.loads(BUNDLED_PATH.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        log.warning("Не удалось прочитать %s, останутся только скачанные имена",
                    BUNDLED_PATH)

    table.update(_read_local())
    _table = {key.lower(): value for key, value in table.items()}
    return _table


def forget() -> None:
    """Забыть прочитанную таблицу. Нужно тестам и после обновления."""
    global _table
    _table = None


def _read_local() -> dict[str, str]:
    """Прочитать скачанные реестры. Их отсутствие это обычное дело."""
    found: dict[str, str] = {}
    try:
        with gzip.open(LOCAL_PATH, "rt", encoding="utf-8") as data:
            for line in data:
                if line.startswith("#"):
                    continue
                prefix, _, name = line.rstrip("\n").partition("\t")
                if prefix and name:
                    found[prefix] = name
    except FileNotFoundError:
        return {}
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        # Оборванная закачка оставляет обрезанный файл. Это повод
        # обойтись встроенным списком, а не поводом не открыть страницу
        log.warning("Не удалось прочитать базу вендоров: %s", exc)
        return {}
    return found


def clean_name(value: str) -> str:
    """
    Юридическое имя из реестра в человеческое.

    «Apple, Inc.» это Apple, «TP-LINK TECHNOLOGIES CO.,LTD.» это TP-LINK.
    Хвосты режутся по одному с конца: у некоторых их два подряд.
    Имя, состоящее из одного такого слова, не трогаем, иначе от
    «Systems Ltd» не останется ничего.
    """
    name = re.sub(r"\s+", " ", str(value or "")).strip(" ,.")
    for _ in range(3):
        lowered = name.lower()
        for suffix in SUFFIXES:
            if lowered.endswith(" " + suffix) or lowered.endswith("," + suffix):
                shortened = name[: len(name) - len(suffix)].strip(" ,.")
                if shortened:
                    name = shortened
                    break
        else:
            break
    return name[:40]


def lookup(mac: str) -> str:
    """
    Производитель по MAC. Пусто, если такого блока в реестрах нет.

    Ищем от длинного префикса к короткому: 36 бит, 28, 24. Иначе
    железка из чужого подблока получит имя владельца всего блока.
    """
    digits = re.sub(r"[^0-9a-f]", "", str(mac or "").lower())
    if len(digits) < 6:
        return ""

    table = load()
    for length in (9, 7, 6):
        prefix = digits[:length]
        # В таблице префиксы лежат с двоеточиями для 24 бит (так их
        # писали руками) и без них для остальных
        for key in (prefix, ":".join(prefix[i:i + 2] for i in range(0, len(prefix), 2))):
            name = table.get(key)
            if name:
                return name
    return ""


# ------------------------------------------------------------------ обновление
def _fetch(url: str, timeout: float) -> str:
    """Скачать реестр. Кто зовёт, тот и разбирается с ошибками."""
    request = urllib.request.Request(url, headers={"User-Agent": "tikpilot"})
    with urllib.request.urlopen(request, timeout=timeout) as answer:  # noqa: S310
        return answer.read().decode("utf-8", "replace")


def parse(text: str, length: int) -> dict[str, str]:
    """
    Разобрать CSV реестра IEEE.

    Колонки: `Registry, Assignment, Organization Name, Organization Address`.
    Нас интересуют вторая и третья, остальное лишнее.
    """
    found: dict[str, str] = {}
    for row in csv.DictReader(io.StringIO(text)):
        prefix = re.sub(r"[^0-9A-Fa-f]", "", str(row.get("Assignment") or "")).lower()
        name = clean_name(row.get("Organization Name") or "")
        if len(prefix) == length and name and name.lower() != "private":
            found[prefix] = name
    return found


def update(timeout: float = 60.0) -> int:
    """
    Скачать реестры IEEE и заменить ими скачанное ранее.

    Возвращает число записей. Реестр, который не ответил, пропускаем:
    две трети базы лучше, чем ничего, а неполноту видно по числу.
    """
    collected: dict[str, str] = {}
    for name, url, length in SOURCES:
        try:
            collected.update(parse(_fetch(url, timeout), length))
        except Exception as exc:  # noqa: BLE001 - причину показываем человеку
            log.warning("Реестр %s не скачался: %s", name, exc)

    if not collected:
        raise RuntimeError("ни один реестр IEEE не ответил")

    LOCAL_PATH.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(LOCAL_PATH, "wt", encoding="utf-8") as out:
        out.write("# Реестры IEEE, скачаны панелью. Файл можно удалить:\n")
        out.write("# останется встроенный короткий список.\n")
        for prefix, name in sorted(collected.items()):
            out.write(f"{prefix}\t{name}\n")

    forget()
    return len(collected)


def state() -> dict[str, Any]:
    """Что показать в настройках: сколько знаем и когда скачано."""
    from datetime import datetime, timezone

    downloaded = None
    if LOCAL_PATH.exists():
        downloaded = datetime.fromtimestamp(LOCAL_PATH.stat().st_mtime, timezone.utc)
    return {
        "total": len(load()),
        "bundled": len(load()) - len(_read_local()),
        "downloaded_at": downloaded,
        # Устаревшей считается только скачанная база. Отсутствие файла
        # это не «пора обновиться», а «человек ещё не просил»
        "stale": downloaded is not None
        and (datetime.now(timezone.utc) - downloaded).days >= REFRESH_DAYS,
    }


def refresh_if_stale() -> int:
    """
    Обновить базу, если она старше месяца. Зовётся фоновой уборкой.

    Первое скачивание всегда решает человек: пока файла нет, панель
    наружу не ходит. Это важнее удобства. Панель обещает работать
    в изолированной сети, и запрос в интернет через час после установки,
    которого никто не просил, это нарушение обещания. А если базу один
    раз скачали, поддерживать её свежей уже никого не удивит.

    Тихо возвращает 0, когда обновляться не нужно или не получилось:
    имена производителей приятны, но не настолько, чтобы из-за них
    шуметь в журнале каждую ночь.
    """
    if not settings.vendors_auto_update:
        return 0
    if not LOCAL_PATH.exists() or not state()["stale"]:
        return 0
    try:
        count = update()
    except Exception as exc:  # noqa: BLE001
        log.info("База вендоров не обновилась: %s", exc)
        return 0
    log.info("База вендоров обновлена сама: записей %s", count)
    return count


def known(prefixes: Iterable[str]) -> int:
    """Сколько из перечисленных префиксов панель знает. Нужно тестам."""
    return sum(1 for prefix in prefixes if lookup(prefix))
