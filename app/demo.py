"""
Режим витрины: показать панель, не показав парк.

Зачем
-----

Скриншот для README, ответ на форуме, экран на созвоне: везде видно
названия площадок, внутренние адреса, имена компьютеров за роутерами
и логин администратора. Замазывать это в редакторе долго, а пропустить
одну строку легко, и она уедет в интернет навсегда.

Как устроено
------------

Ответ панели переписывается на выходе, перед отправкой в браузер.
Не запрос, не база: подмена живёт ровно один ответ, и в базе от неё
не остаётся ничего. Поэтому нечего забыть выключить и нечего чинить
потом: снял скриншот, погасил режим, данные на месте.

Подмены устойчивые. Одна и та же точка на всех страницах называется
одинаково, адрес у неё один и тот же, и скриншоты разных разделов
складываются в связную картину, а не в кашу. Устойчивость даёт
не случайность, а порядок: имена сортируются и раздаются по кругу
из готового списка.

Адреса берутся из диапазонов, отведённых под документацию (RFC 5737):
`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`. Их нельзя
встретить в живой сети, поэтому чужой скриншот никого никуда
не приведёт. MAC собираются с локально управляемым битом: такие
адреса не принадлежат ни одному производителю.

Чего режим не делает
--------------------

Он не защита. Тот, кто уже вошёл в панель, видит настоящие данные
в любой момент: достаточно выключить режим. Это удобство для того,
кто снимает экран, а не преграда для того, кто внутри.
"""

from __future__ import annotations

import hashlib
import logging
import re
import sqlite3
from typing import Any

from .database import query
from .mikrotik import safe_filename

log = logging.getLogger("tikpilot.demo")

#: Имя куки. Режим живёт в браузере того, кто его включил: остальные
#: в это время работают с настоящими данными и ничего не замечают.
COOKIE = "tikpilot_demo"

#: На сколько включается. Восьми часов хватает на любую съёмку, а утром
#: режим уже погашен, и панель не встречает чужими именами.
HOURS = 8

#: Вымышленные названия точек. Нейтральные и разные по длине: короткое
#: имя рядом с длинным показывает, как таблица ведёт себя на самом деле.
SITES = (
    "Кафе Ромашка", "Магазин Берёзка", "Склад Северный", "Пекарня на Речной",
    "Столовая Радуга", "Офис Центральный", "Буфет Ясень", "Магазин Уют",
    "Пункт выдачи Клён", "Кафе Тополь", "Склад Южный", "Магазин Огонёк",
    "Столовая Дубрава", "Офис Приморский", "Буфет Ивушка", "Магазин Заря",
    "Пекарня Колосок", "Кафе Лесное", "Склад Восточный", "Магазин Смена",
)

#: То же на английском: скриншоты для README снимаются на нём, и русское
#: «Кафе Ромашка» посреди английской таблицы выглядит случайностью.
SITES_EN = (
    "Cafe Daisy", "Birch Store", "North Depot", "Riverside Bakery",
    "Rainbow Canteen", "Central Office", "Ash Buffet", "Cosy Store",
    "Maple Pickup Point", "Poplar Cafe", "South Depot", "Spark Store",
    "Oakwood Canteen", "Seaside Office", "Willow Buffet", "Dawn Store",
    "Wheatear Bakery", "Forest Cafe", "East Depot", "Relay Store",
)

#: Названия групп. Их мало, и они короткие: в таблице это узкая колонка.
GROUPS = ("Север", "Юг", "Центр", "Запад", "Восток", "Резерв")
GROUPS_EN = ("North", "South", "Centre", "West", "East", "Reserve")

#: Имена администраторов. Роли, а не люди: в журнале действий важно,
#: что действие сделал человек, а не какой именно.
PEOPLE = ("admin", "operator", "monitor", "engineer", "support")

#: Имена устройств за роутером. Обычная касса, принтер и терминал.
CLIENTS = (
    "kassa-1", "kassa-2", "printer-hp", "terminal-sber", "tv-hall",
    "camera-door", "scales-1", "tablet-zal", "nvr-1", "ap-guest",
)

#: Диапазоны из RFC 5737, отведённые под примеры и документацию.
NETS = ("192.0.2", "198.51.100", "203.0.113")

#: Что считать адресом. Версии RouterOS выглядят похоже («7.21.5»),
#: поэтому четыре группы цифр обязательны, а границы проверяются.
IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])")

#: MAC в любом обычном написании.
MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

#: Открытый ключ WireGuard: 43 символа base64 и знак равенства.
KEY_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])")

#: Домены в адресах устройств: у части парка вместо адреса имя.
HOST_RE = re.compile(r"\b[a-z0-9][a-z0-9-]*\.(?:ru|com|net|org|local|sn\.mynetname\.net)\b",
                     re.IGNORECASE)

#: Что подменять нельзя ни при каких совпадениях. Панель называется
#: «Tikpilot», и сервер панели стоит в сети обычным клиентом с таким же
#: именем: попав в словарь клиентом, оно переименовало саму панель в меню
#: и в подвале. Названия программ ничего не выдают, они и должны остаться.
KEEP = frozenset({
    "tikpilot", "mikrotik", "routeros", "winbox", "wireguard", "sstp",
    "webfig", "ubuntu", "docker", "windows", "android",
})

#: Короткие технические сокращения, которые встречаются в самой странице:
#: в именах полей, в разметке, в подписях таблиц. Точка с таким именем
#: подменялась бы вместе с версткой, а сломанная страница выдаёт парк
#: надёжнее, чем несколько букв в названии.
TECH = frozenset({
    "api", "ssh", "ftp", "dns", "dhcp", "ntp", "arp", "vpn", "lte", "wan",
    "lan", "poe", "cpu", "ram", "mac", "vlan", "utc", "url", "svg", "div",
    "css", "img", "get", "post", "put", "rx", "tx", "id", "ip", "ok", "up",
})

#: Слова, из которых состоит сам интерфейс. Подменять их нельзя: точка
#: может называться словом, которое встречается в подписи кнопки, и тогда
#: подмена переписывает не данные, а текст панели. Так «supported by both
#: sides» однажды превратилось в «scamera-door 34orted by both sides».
_vocabulary: frozenset[str] | None = None

#: Готовый словарь подмен и по чему он собран. Парк меняется редко,
#: а страницы дёргаются часто, поэтому словарь собирается один раз
#: и живёт до тех пор, пока не изменится состав парка.
_tables: dict[str, dict[str, str]] = {}
_patterns: dict[str, re.Pattern] = {}
_built_for: tuple = ()


def enabled(request: Any) -> bool:
    """Включён ли режим у того, кто прислал запрос."""
    try:
        return request.cookies.get(COOKIE) == "1"
    except AttributeError:
        return False


def forget() -> None:
    """Забыть словарь подмен. Нужно тестам и после правки парка."""
    global _built_for, _vocabulary
    _tables.clear()
    _patterns.clear()
    _built_for = ()
    _vocabulary = None


def _pick(items: tuple[str, ...], index: int) -> str:
    """
    Взять имя из списка по кругу, добавив номер со второго круга.

    «Кафе Ромашка», а на втором круге «Кафе Ромашка 2». Так имена
    не повторяются даже на парке в полсотни точек, а список остаётся
    коротким и читаемым.
    """
    name = items[index % len(items)]
    circle = index // len(items)
    return name if circle == 0 else f"{name} {circle + 1}"


def _address(index: int) -> str:
    """Вымышленный адрес из документационного диапазона."""
    net = NETS[index // 254 % len(NETS)]
    return f"{net}.{index % 254 + 1}"


def _mac(source: str) -> str:
    """
    Вымышленный MAC, устойчивый для одного и того же настоящего.

    Второй бит первого байта поднят: это локально управляемый адрес,
    он не принадлежит ни одному производителю, и вендор по нему
    не определяется даже случайно.
    """
    digest = hashlib.sha1(source.encode("utf-8", "replace")).hexdigest()
    tail = ":".join(digest[i:i + 2] for i in range(2, 12, 2))
    return f"02:{tail}".upper()


def alias(text: str, lang: str = "ru") -> str:
    """
    Вымышленное имя для строки, которой нет в базе панели.

    Так подписаны связи WireGuard и метки маршрутов: их имена живут
    на роутере, панель их не хранит и подменить по словарю не может.
    Имя выбирается по самой строке, поэтому одна и та же связь
    называется одинаково на всех снимках.
    """
    source = str(text or "").strip()
    if len(source) < 3:
        return source
    pool = SITES_EN if lang == "en" else SITES
    return _pick(pool, _index(source, len(pool) * 3))


def _rows(sql: str) -> list:
    """
    Спросить базу, пережив её отсутствие.

    Подмена это оформление, а не работа панели: если что-то пошло не так,
    страница должна открыться. Пустой словарь оставит на ней настоящие
    имена, и это заметно сразу, в отличие от белого экрана.
    """
    try:
        return query(sql)
    except sqlite3.Error as exc:
        log.warning("Режим витрины: не удалось прочитать данные: %s", exc)
        return []


def _fingerprint() -> tuple:
    """По чему собран словарь: состав парка, групп, людей и клиентов."""
    counts = _rows(
        "SELECT (SELECT COUNT(*) FROM devices) AS d,"
        " (SELECT COUNT(*) FROM groups) AS g,"
        " (SELECT COUNT(*) FROM users) AS u,"
        " (SELECT COUNT(*) FROM clients) AS c,"
        " (SELECT MAX(updated_at) FROM devices) AS t"
    )
    if not counts:
        return ()
    row = counts[0]
    return (row["d"], row["g"], row["u"], row["c"], row["t"])


def vocabulary() -> frozenset[str]:
    """
    Слова, из которых собран сам интерфейс, в нижнем регистре.

    Берутся из каталогов перевода: там лежит всё, что панель пишет
    на страницах, на обоих языках. Ничего заводить руками не нужно,
    и список не устареет вместе с текстами.
    """
    global _vocabulary

    if _vocabulary is None:
        from . import i18n

        words: set[str] = set()
        for lang, catalog in i18n.load_catalogs().items():
            for msgid, text in catalog.items():
                if not isinstance(text, str):
                    continue
                for chunk in re.split(r"[^0-9A-Za-zА-Яа-яЁё]+", f"{msgid} {text}"):
                    if len(chunk) >= 3:
                        words.add(chunk.lower())
        _vocabulary = frozenset(words)
    return _vocabulary


def _add(table: dict[str, str], real: Any, fake: str) -> None:
    """
    Записать подмену, пропустив пустое, опасное и слишком обычное.

    Отдельное слово, которое и так есть в интерфейсе, не подменяется:
    имя точки из одного словарного слова спрячется хуже, чем сломается
    страница.

    Про короткие имена. Раньше отбрасывалось всё короче четырёх символов,
    и на живом парке сквозь витрину проехали «NSK», «URS» и группа «УРС»:
    ровно те названия, которые и надо было спрятать. Причина запрета была
    в другом: короткая строка встречается в разметке где угодно, и замена
    ломала бы страницу. Но с тех пор появились границы слова, а страницу
    ломают не короткие имена вообще, а короткие **строчные латинские**:
    `rx` подменился бы внутри `rx_bps`, потому что подчёркивание границей
    считается.

    Поэтому правило теперь такое: два символа и больше, хотя бы одна
    буква, и для имён короче четырёх ещё и заглавная либо кириллица.
    «NSK» и «УРС» проходят, `rx` и `svg` нет.
    """
    text = str(real or "").strip()
    if len(text) < 2 or text in table or text.lower() in KEEP:
        return
    if text.lower() in TECH:
        return
    # Строка без единой буквы это обычно номер, и подменять его значит
    # переписывать все такие числа на странице, включая счётчики
    # и проценты. Исключение адреса: они как раз из цифр и точек,
    # и прятать их надо в первую очередь
    address = bool(re.fullmatch(r"[0-9a-fA-F.:]{7,}", text)) and ("." in text or ":" in text)
    if not address and not re.search(r"[A-Za-zА-Яа-яЁё]", text):
        return
    if len(text) < 4 and not re.search(r"[A-ZА-ЯЁ]|[а-яёА-ЯЁ]", text):
        return
    if " " not in text and text.lower() in vocabulary():
        return
    table[text] = fake


def build(lang: str = "ru") -> dict[str, str]:
    """Собрать словарь подмен по текущему составу парка."""
    global _built_for

    mark = _fingerprint()
    if mark != _built_for:
        _tables.clear()
        _patterns.clear()
        _built_for = mark
    if lang in _tables:
        return _tables[lang]

    english = lang == "en"
    sites = SITES_EN if english else SITES
    groups = GROUPS_EN if english else GROUPS
    note = "a note about the group" if english else "заметка о группе"
    device_note = "internal note" if english else "служебная заметка"
    guest = "Wi-Fi guest" if english else "Wi-Fi гостевой"
    table: dict[str, str] = {}

    for i, row in enumerate(_rows(
            "SELECT name, comment FROM groups ORDER BY id")):
        _add(table, row["name"], _pick(groups, i))
        _add(table, row["comment"], note)

    for i, row in enumerate(_rows(
            "SELECT name, host, identity, comment, username, gateway"
            " FROM devices ORDER BY id")):
        site = _pick(sites, i)
        _add(table, row["name"], site)
        _add(table, row["host"], _address(i))
        _add(table, row["identity"], f"site-{i + 1:02d}")
        _add(table, row["comment"], device_note)
        _add(table, row["gateway"], _address(i + 500))
        # Имя пользователя API это половина доступа к роутеру, и на
        # экране ему делать нечего. Модель платы, наоборот, остаётся:
        # она у всех одинаковая и как раз показывает, с каким железом
        # панель работает
        _add(table, row["username"], "tikpilot")
        # Имена бэкапов собраны из имени точки: `VAH_Bufet_obshch14_...rsc`
        # выдаёт площадку не хуже самой колонки с именем
        _add(table, safe_filename(str(row["name"])), safe_filename(site))

    for i, row in enumerate(_rows("SELECT username FROM users ORDER BY id")):
        _add(table, row["username"], _pick(PEOPLE, i))

    # Удалённые точки живут дальше в журнале действий и в архиве бэкапов.
    # В самой панели их уже нет, поэтому имена берём оттуда, где остались
    for row in _rows("SELECT DISTINCT device_name FROM backups LIMIT 500"):
        name = str(row["device_name"] or "")
        _add(table, name, alias(name, lang))
        _add(table, safe_filename(name), safe_filename(alias(name, lang)))

    # Люди уходят, а их имена остаются в журнале действий и в задачах.
    # Учётки уже нет, подменить её по таблице пользователей нечем
    for source in ("SELECT DISTINCT username AS name FROM audit_log"
                   " WHERE username <> '' LIMIT 200",
                   "SELECT DISTINCT username AS name FROM jobs"
                   " WHERE username <> '' LIMIT 200",
                   "SELECT DISTINCT device_name AS name FROM syslog LIMIT 200",
                   "SELECT DISTINCT host AS name FROM syslog LIMIT 200"):
        for row in _rows(source):
            name = str(row["name"] or "")
            if "syslog" in source:
                _add(table, name, alias(name, lang))
            else:
                _add(table, name, PEOPLE[_index(name, len(PEOPLE))])

    for row in _rows("SELECT DISTINCT target FROM audit_log"
                     " WHERE target <> '' LIMIT 500"):
        name = str(row["target"] or "")
        # Строки вида «50 устройств» панель составляет сама, и подменять
        # их незачем: они ничего не выдают, а на снимке нужны
        if not name[:1].isdigit():
            _add(table, name, alias(name, lang))

    for i, row in enumerate(_rows(
            "SELECT mac, hostname, comment, label, ip, ssid FROM clients"
            " ORDER BY id LIMIT 3000")):
        name = _pick(CLIENTS, i)
        _add(table, row["mac"], _mac(str(row["mac"])))
        _add(table, row["hostname"], name)
        _add(table, row["comment"], name)
        _add(table, row["label"], name)
        _add(table, row["ip"], _address(i + 100))
        _add(table, row["ssid"], guest)

    _tables[lang] = table
    return table


def mask(text: str, lang: str = "ru") -> str:
    """
    Заменить в готовой странице всё, что показывает настоящий парк.

    Сначала известные строки (их подмены устойчивы и осмысленны),
    потом общее правило для адресов и ключей: в парке всегда найдётся
    адрес, которого нет в базе, вроде шлюза провайдера в логе.
    """
    if not text:
        return text

    table = build(lang)
    if table:
        pattern = _pattern(table, lang)
        text = pattern.sub(lambda m: table.get(m.group(0), m.group(0)), text)

    text = MAC_RE.sub(lambda m: _mac(m.group(0)), text)
    text = IP_RE.sub(_mask_ip, text)
    text = KEY_RE.sub(lambda m: _fake_key(m.group(0)), text)
    text = HOST_RE.sub(lambda m: f"site-{_index(m.group(0), 99) + 1:02d}.example.net", text)
    return text


#: Символы, которые считаются частью слова: подмена не должна срабатывать
#: внутри другого слова. Подчёркивание и дефис в этот список не входят
#: намеренно: имя точки продолжается в имени файла бэкапа ровно через них,
#: и `VAH_Bufet_obshch14_20260812.rsc` иначе осталось бы как есть.
WORDISH = r"0-9A-Za-zА-Яа-яЁё"


def _pattern(table: dict[str, str], lang: str) -> re.Pattern:
    """
    Один шаблон на весь словарь подмен, собранный деревом.

    Раньше здесь стояло перечисление: каждый ключ со своими границами
    слова, через «или». На парке в полсотни точек это двести с лишним
    веток, и движок регулярных выражений примерял их на каждом символе
    страницы. Замер на списке устройств в 240 КБ: **1,3 секунды** на
    страницу. Именно поэтому панель в режиме витрины заметно тормозила.

    Лечится двумя вещами. Первая: границы слова выносятся из каждой
    ветки наружу, один просмотр назад и один вперёд вместо двухсот
    (1,3 с превращаются в 0,1 с). Вторая: ключи складываются в
    префиксное дерево, и общее начало проверяется один раз, а не
    столько раз, сколько ключей с ним начинается (0,1 с превращается
    в 0,009 с). Итого в полтораста раз быстрее.

    Ключи разложены по четырём корзинам, потому что граница нужна не
    всем: имя, начинающееся со скобки, не должно требовать разделителя
    слева. Корзины идут отдельными ветками, внутри каждой дерево, и
    таких веток четыре, а не двести.

    Дерево заодно решает старую задачу: «Магазин» больше не подменяется
    внутри «Магазин Пекарня». Продолжение в дереве жадное, поэтому
    длинный ключ выигрывает у короткого сам собой, без сортировки.
    """
    if lang in _patterns:
        return _patterns[lang]

    buckets: dict[tuple[bool, bool], list[str]] = {}
    for key in table:
        head = bool(re.match(f"[{WORDISH}]", key))
        tail = bool(re.search(f"[{WORDISH}]$", key))
        buckets.setdefault((head, tail), []).append(key)

    parts = []
    for (head, tail), keys in sorted(buckets.items(), reverse=True):
        body = _trie_pattern(_trie(keys))
        if body is None:
            continue
        prefix = f"(?<![{WORDISH}])" if head else ""
        suffix = f"(?![{WORDISH}])" if tail else ""
        parts.append(f"{prefix}(?:{body}){suffix}")

    _patterns[lang] = re.compile("|".join(parts))
    return _patterns[lang]


def _trie(keys: list[str]) -> dict:
    """Сложить строки в дерево по общим началам."""
    root: dict = {}
    for key in keys:
        node = root
        for char in key:
            node = node.setdefault(char, {})
        node[""] = {}
    return root


def _trie_pattern(node: dict) -> str | None:
    """
    Превратить дерево в выражение.

    Ветки с одиночными символами собираются в класс `[абв]`, а конец
    слова превращается в необязательный хвост. Хвост жадный: из двух
    ключей с общим началом выигрывает длинный, а это ровно то, что
    нужно подмене.
    """
    if "" in node and len(node) == 1:
        return None

    alternatives: list[str] = []
    singles: list[str] = []
    for char in sorted(key for key in node if key):
        tail = _trie_pattern(node[char])
        if tail is None:
            singles.append(re.escape(char))
        else:
            alternatives.append(re.escape(char) + tail)

    if singles:
        alternatives.append(singles[0] if len(singles) == 1
                            else "[" + "".join(singles) + "]")

    body = alternatives[0] if len(alternatives) == 1 else "(?:%s)" % "|".join(alternatives)
    return f"(?:{body})?" if "" in node else body


def _bounded(key: str) -> str:
    """
    Правило поиска строки как отдельного слова, а не куска чужого.

    Без этого короткое имя точки находится внутри обычного текста:
    ровно так «supp» из «supported» стало вымышленной кассой.
    """
    body = re.escape(key)
    head = f"(?<![{WORDISH}])" if re.match(f"[{WORDISH}]", key) else ""
    tail = f"(?![{WORDISH}])" if re.search(f"[{WORDISH}]$", key) else ""
    return head + body + tail


def _index(source: str, limit: int) -> int:
    """Устойчивый номер по строке: одинаковый вход даёт одинаковый выход."""
    return int(hashlib.sha1(source.encode("utf-8", "replace")).hexdigest()[:6], 16) % limit


def _mask_ip(match: re.Match) -> str:
    """
    Подменить адрес, оставив служебные как есть.

    `0.0.0.0` и `127.0.0.1` ничего не выдают, зато их подмена сбивает
    с толку: на скриншоте появляется адрес, которого в панели не бывает.
    """
    address = match.group(0)
    if address.startswith(("0.", "127.", "255.")) or address in ("8.8.8.8", "1.1.1.1"):
        return address
    if any(address.startswith(net + ".") for net in NETS):
        return address
    parts = address.split(".")
    if any(not part.isdigit() or int(part) > 255 for part in parts):
        return address
    return _address(_index(address, 700))


def _fake_key(source: str) -> str:
    """Вымышленный ключ WireGuard той же длины: строка узнаётся как ключ."""
    digest = hashlib.sha1(source.encode("utf-8", "replace")).hexdigest()
    body = (digest * 2)[:43]
    return body + "="
