"""
Приём и хранение системного журнала с роутеров.

Зачем это в панели
------------------

Логи с устройств обычно собирает отдельная программа, и получается, что
про падение точки известно в одном месте, про её конфигурацию в другом,
а про то, что она в этот момент писала в журнал, в третьем. Когда точка
одна, это терпимо. Когда их полсотни и они в тайге, разбор аварии
превращается в перекладывание окон.

Здесь журнал лежит рядом со всем остальным: строка из лога сразу привязана
к устройству панели, и с неё можно уйти в его карточку, историю падений
и бэкапы.

Как устроен приём
-----------------

Два слушателя, UDP и TCP, каждый в своём потоке. UDP это классика syslog:
роутер отправляет и забывает, на плохом канале часть строк пропадёт, зато
он никогда не будет ждать. TCP ничего не теряет и переживает потерю связи,
но держит соединение. Пусть работают оба, а точки настраиваются как удобно.

Полученные строки не пишутся в базу поштучно. Роутер, попавший в петлю,
выдаёт тысячи строк в минуту, и отдельная транзакция на каждую убила бы
и SQLite, и диск. Строки складываются в очередь, отдельный поток пишет их
пачками.

Про безопасность
----------------

Syslog никак не подписан: кто дотянулся до порта, тот и пишет в журнал.
Поэтому строки принимаются только с адресов известных панели устройств
либо из сетей, перечисленных в SYSLOG_NETWORKS. Иначе достаточно одного
скучающего человека с интернетом, чтобы забить диск.
"""

from __future__ import annotations

import ipaddress
import logging
import queue
import re
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any

from .config import settings
from .database import execute, execute_changes, get_conn, query, query_one, utcnow, write_lock

log = logging.getLogger("tikpilot.syslog")

#: Имена уровней важности syslog (RFC 5424). Индекс это само значение.
SEVERITIES = ("emerg", "alert", "crit", "error", "warning", "notice", "info", "debug")

#: Русские подписи уровней для интерфейса.
SEVERITY_LABELS = {
    "emerg": "авария",
    "alert": "тревога",
    "crit": "критично",
    "error": "ошибка",
    "warning": "предупреждение",
    "notice": "заметка",
    "info": "сведения",
    "debug": "отладка",
}

#: Сколько строк накапливать до записи и как долго ждать неполную пачку.
BATCH_SIZE = 200
BATCH_SECONDS = 1.0

#: Потолок очереди. Если писать не успеваем, лучше потерять строки, чем
#: память: панель должна пережить взбесившийся роутер, а не упасть вместе с ним.
QUEUE_LIMIT = 20000

_queue: "queue.Queue[dict[str, Any]]" = queue.Queue(maxsize=QUEUE_LIMIT)
_stop = threading.Event()
_threads: list[threading.Thread] = []

#: Что показывать в настройках: работает ли приём и сколько строк прошло.
state: dict[str, Any] = {
    "enabled": False,
    "udp_port": 0,
    "tcp_port": 0,
    "received": 0,     # принято строк с запуска
    "stored": 0,       # записано в базу
    "dropped": 0,      # отброшено: чужой адрес или переполнение очереди
    "ignored": 0,      # отброшено правилом «не сохранять», это не потеря
    "last_at": None,   # время последней принятой строки
    "last_source": "", # и от кого она пришла
    "rejected": {},    # адреса, с которых писать не разрешено, и сколько раз
    "error": "",       # почему приём не поднялся
}

_PRI = re.compile(r"^<(\d{1,3})>")
#: Отметка времени BSD-формата: «Aug  7 10:15:00» либо ISO из RFC 5424.
_BSD_STAMP = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+")
_ISO_STAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+")
#: Темы RouterOS: «system,info», «script,warning» и подобные.
_TOPICS = re.compile(r"^([a-z][a-z0-9-]*(?:,[a-z][a-z0-9-]*)*)\s+")


# ------------------------------------------------------------------- разбор
def parse(raw: str) -> dict[str, Any]:
    """
    Разобрать строку syslog в поля.

    Формат нарочно разбирается мягко: RFC3164 старше многих читателей,
    и каждый производитель понял его по-своему. Всё, что не удалось узнать,
    остаётся в тексте сообщения, а сырая строка сохраняется целиком.
    Потерять содержимое из-за неподошедшего регулярного выражения гораздо
    хуже, чем не заполнить одно поле.
    """
    text = raw.strip("\r\n\x00 ")
    facility, severity = 1, 6      # user.info: разумная замена, если PRI нет

    found = _PRI.match(text)
    if found:
        value = int(found.group(1))
        if value <= 191:
            facility, severity = divmod(value, 8)
            text = text[found.end():]

    stamp = ""
    for pattern in (_ISO_STAMP, _BSD_STAMP):
        found = pattern.match(text)
        if found:
            stamp = found.group(1)
            text = text[found.end():]
            break

    # Имя узла идёт следом за отметкой времени, но только если отметка была:
    # без неё первое слово это обычно уже часть сообщения.
    host = ""
    if stamp:
        parts = text.split(" ", 1)
        if len(parts) == 2 and parts[0] and not parts[0].endswith(":"):
            host, text = parts[0], parts[1]

    # Формат CEF: RouterOS умеет и его, и на многих парках он уже настроен
    # ради стороннего сборщика. Разбираем, чтобы не заставлять человека
    # перенастраивать полсотни точек ради одной панели.
    if "CEF:0|" in text:
        return _parse_cef(text, raw, facility, severity, stamp, host)

    topics = ""
    found = _TOPICS.match(text)
    if found:
        topics = found.group(1)
        text = text[found.end():]

    return {
        "facility": facility,
        "severity": severity,
        "severity_name": SEVERITIES[severity] if severity < len(SEVERITIES) else "info",
        "stamp": stamp,
        "host": host,
        "topics": topics,
        "message": text.strip(),
        "raw": raw.strip("\r\n\x00 "),
    }


#: Важность CEF словом. Числовую шкалу RouterOS не использует, пишет
#: «High», «Medium» и подобное.
_CEF_WEIGHT = {
    "very-high": 2, "very high": 2,
    "high": 3,
    "medium": 4,
    "low": 6,
    "unknown": 6,
}

#: Темы RouterOS сами по себе несут уровень: в «system,error,critical»
#: важность записана словами. Это надёжнее, чем шкала CEF, потому что
#: слова здесь родные для RouterOS, а не пересчитанные им во что-то своё.
_TOPIC_SEVERITY = (
    ("critical", 2), ("error", 3), ("warning", 4), ("info", 6), ("debug", 7),
)


def _cef_severity(topics: str, weight: str, fallback: int) -> int:
    """
    Уровень строки CEF.

    В такой строке нет PRI, поэтому без разбора всё выглядело бы как
    «сведения», и фильтр по важности не работал бы вовсе. Сначала темы,
    в них уровень записан словом самим RouterOS, потом шкала CEF.
    """
    lowered = topics.lower()
    for word, value in _TOPIC_SEVERITY:
        if word in lowered:
            return value
    return _CEF_WEIGHT.get(weight.lower(), fallback)


def _parse_cef(text: str, raw: str, facility: int, severity: int,
               stamp: str, host: str) -> dict[str, Any]:
    """
    Разобрать строку в формате CEF.

    RouterOS умеет отдавать журнал и так, и на многих парках этот формат
    уже настроен ради стороннего сборщика. Заставлять человека
    перенастраивать полсотни точек ради одной панели неправильно.

    Строение: CEF:0|производитель|продукт|версия|код|название|важность|хвост.
    Разложено по живой строке с парка, а не по документации:

        CEF:0|MikroTik|hAP ac lite|7.21.5 (long-term)|10|system,error,critical|
        High|dvchost=office-1 dvc=192.168.88.1 msg=login failure for user operator
        from 10.10.0.199 via winbox app=winbox outcome=failure

    Отсюда видно, что где на самом деле:

    * продукт это модель платы, а не «RouterOS»;
    * код события просто число и смысла для человека не несёт;
    * **темы RouterOS лежат в поле названия**, а не в коде: «system,error,critical»;
    * само сообщение только в хвосте, в `msg=`;
    * важность словом («High»), а не числом, и PRI в такой строке нет вовсе,
      поэтому без разбора важности всё выглядело бы как «сведения».
    """
    head, _, body = text.partition("CEF:0|")
    # Разделитель внутри значений экранируется обратной косой чертой
    parts = re.split(r"(?<!\\)\|", body)
    parts += [""] * (7 - len(parts)) if len(parts) < 7 else []

    name = parts[4].strip() if len(parts) > 4 else ""
    weight = parts[5].strip() if len(parts) > 5 else ""
    tail = parts[6] if len(parts) > 6 else ""

    # Темы лежат в поле названия: «system,error,critical». Проверяем форму,
    # а не полагаемся на позицию: у другой прошивки там может оказаться
    # человекочитаемый заголовок, и записывать его в темы незачем
    topics = name if re.fullmatch(r"[a-z][a-z0-9-]*(?:,[a-z][a-z0-9-]*)*", name) else ""

    # Сообщение только в хвосте. Значение заканчивается там, где начинается
    # следующая пара «ключ=значение»
    message = ""
    found = re.search(r"\bmsg=(.+?)(?=\s+[a-zA-Z][\w.-]*=|$)", tail)
    if found:
        message = found.group(1).strip()
    if not message:
        message = name

    severity = _cef_severity(topics, weight, severity)

    if not host:
        # Имя узла в CEF-строке стоит до самого CEF, как в обычном syslog
        words = head.split()
        if words:
            host = words[-1]

    return {
        "facility": facility,
        "severity": severity,
        "severity_name": SEVERITIES[severity] if severity < len(SEVERITIES) else "info",
        "stamp": stamp,
        "host": host,
        "topics": topics,
        "message": message or text.strip(),
        "raw": raw.strip("\r\n\x00 "),
    }


# ------------------------------------------------------- кто может писать
def _allowed_networks() -> list[Any]:
    """Сети, из которых принимаем строки, из настройки SYSLOG_NETWORKS."""
    result = []
    for item in settings.syslog_networks:
        try:
            result.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            log.warning("SYSLOG_NETWORKS: не разобрать «%s», пропускаю", item)
    return result


class _Sources:
    """
    Кто нам пишет: адрес источника в устройство панели.

    Список устройств меняется редко, а строки приходят часто, поэтому он
    держится в памяти и обновляется раз в минуту. Проверять базу на каждую
    строку значит платить запросом за каждую запись в журнале.
    """

    def __init__(self) -> None:
        self._by_host: dict[str, dict[str, Any]] = {}
        self._by_name: dict[str, dict[str, Any]] = {}
        self._extra: dict[str, dict[str, Any] | None] = {}
        self._at = 0.0
        self._lock = threading.Lock()
        self._networks = _allowed_networks()

    def refresh(self, force: bool = False) -> None:
        with self._lock:
            if not force and time.monotonic() - self._at < 60:
                return
            rows = query("SELECT id, name, host, identity FROM devices")
            self._by_host = {r["host"]: {"id": r["id"], "name": r["name"]} for r in rows}

            # Имя, которым устройство подписывается в журнале. Нужно, чтобы
            # привязать строку к точке, когда она пишет с адреса, отличного
            # от адреса управления: в туннеле это обычное дело.
            self._by_name = {}
            for row in rows:
                for name in (row["identity"], row["name"]):
                    if name:
                        self._by_name.setdefault(
                            str(name).strip().lower(), {"id": row["id"], "name": row["name"]})

            # Адреса, разрешённые человеком по кнопке на странице журнала
            self._extra = {}
            for row in query("SELECT address, device_id FROM syslog_sources"):
                bound = None
                if row["device_id"]:
                    found = query_one("SELECT id, name FROM devices WHERE id = ?",
                                      (row["device_id"],))
                    if found:
                        bound = {"id": found["id"], "name": found["name"]}
                self._extra[row["address"]] = bound

            self._at = time.monotonic()

    def by_name(self, host: str) -> dict[str, Any] | None:
        """
        Устройство по имени, которым отправитель подписал строку.

        Привязка по имени применяется только после того, как адрес уже
        признан разрешённым. Само по себе имя в syslog ничем не заверено,
        и пускать по нему в журнал было бы приглашением подписаться чужой
        точкой.
        """
        self.refresh()
        return self._by_name.get(str(host or "").strip().lower())

    def match(self, address: str) -> tuple[int | None, str, bool]:
        """
        Устройство по адресу и разрешено ли вообще принимать от него.

        Возвращает (device_id, имя, разрешено). Неизвестный адрес из
        разрешённой сети принимается без привязки к устройству: точку могли
        ещё не завести в панели, а её логи уже нужны.
        """
        self.refresh()
        known = self._by_host.get(address)
        if known:
            return known["id"], known["name"], True

        if address in self._extra:
            bound = self._extra[address]
            if bound:
                return bound["id"], bound["name"], True
            return None, "", True

        # Разрешить можно и сеть целиком: при резервном туннеле у каждой
        # точки свой адрес, и заводить их по одному значит полсотни нажатий
        for allowed, bound in self._extra.items():
            if "/" not in allowed:
                continue
            try:
                if ipaddress.ip_address(address) in ipaddress.ip_network(allowed, strict=False):
                    if bound:
                        return bound["id"], bound["name"], True
                    return None, "", True
            except ValueError:
                continue

        if not self._networks:
            # Сети не заданы: принимаем только от заведённых устройств.
            # Это строгий, но честный вариант по умолчанию.
            return None, "", False

        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None, "", False
        for network in self._networks:
            if ip in network:
                return None, "", True
        return None, "", False


_sources = _Sources()


# --------------------------------------------------------------- приёмники
def _accept(raw: str, address: str) -> None:
    """Принять строку от адреса: проверить право писать и поставить в очередь."""
    if not raw.strip():
        return

    device_id, device_name, allowed = _sources.match(address)
    if not allowed:
        state["dropped"] += 1
        # Запоминаем, кого отвергли. Без этого «журнал пустой» превращается
        # в гадание: строки могут не доходить вовсе, а могут приходить
        # с адреса, которого панель не знает. Это разные починки.
        rejected = state["rejected"]
        if address in rejected or len(rejected) < 20:
            item = rejected.get(address) or {"count": 0, "host": ""}
            item["count"] += 1
            # Имя отправителя из самой строки: по нему человек сразу видит,
            # чья это точка, и решение «принимать или нет» становится
            # осмысленным, а не гаданием по адресу
            item["host"] = item["host"] or parse(raw).get("host", "")
            rejected[address] = item
        return

    row = parse(raw)
    if device_id is None:
        # Адрес разрешён, но за устройством не закреплён. Пробуем узнать
        # точку по имени, которым она подписалась: роутер пишет свой
        # identity, и он у нас есть.
        guess = _sources.by_name(row.get("host", ""))
        if guess:
            device_id, device_name = guess["id"], guess["name"]

    # Правило «не сохранять» работает здесь, до очереди и до базы: смысл
    # его в том, чтобы шум не занимал место и не съедал потолок в два
    # миллиона строк. Считаем отброшенное отдельно от потерянного:
    # «выкинули по правилу» и «не справились» это разные новости.
    if match_action(f"{row.get('message', '')} {row.get('topics', '')}") == "drop":
        state["ignored"] += 1
        return

    row["device_id"] = device_id
    row["device_name"] = device_name or row.get("host") or address
    row["source"] = address
    row["ts"] = utcnow()

    state["received"] += 1
    state["last_at"] = row["ts"]
    state["last_source"] = address
    try:
        _queue.put_nowait(row)
    except queue.Full:
        # Очередь переполнена: пишем не успеваем. Терять строки неприятно,
        # но память кончится быстрее, чем роутер угомонится.
        state["dropped"] += 1


def _udp_loop(sock: socket.socket) -> None:
    """Слушать UDP до остановки."""
    sock.settimeout(0.5)
    while not _stop.is_set():
        try:
            data, addr = sock.recvfrom(8192)
        except socket.timeout:
            continue
        except OSError:
            break
        # Один датаграмм это одно сообщение, но некоторые шлют пачкой
        for line in data.decode("utf-8", "replace").splitlines():
            _accept(line, addr[0])
    sock.close()


def _tcp_client(conn: socket.socket, address: str) -> None:
    """
    Одно соединение TCP.

    Границы сообщений в потоке ищутся по переводу строки. Существует ещё
    вариант с длиной в начале (RFC 6587), его тоже понимаем: RouterOS
    умеет оба, а перепутать их значит получить журнал из склеенных строк.
    """
    conn.settimeout(1.0)
    buffer = b""
    while not _stop.is_set():
        try:
            chunk = conn.recv(8192)
        except socket.timeout:
            continue
        except OSError:
            break
        if not chunk:
            break
        buffer += chunk

        while True:
            counted = re.match(rb"^(\d{1,6}) ", buffer)
            if counted:
                length = int(counted.group(1))
                start = counted.end()
                if len(buffer) < start + length:
                    break
                line = buffer[start:start + length]
                buffer = buffer[start + length:]
            elif b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
            else:
                break
            _accept(line.decode("utf-8", "replace"), address)

        if len(buffer) > 65536:      # мусор без переводов строки
            buffer = b""
    conn.close()


def _tcp_loop(sock: socket.socket) -> None:
    """Принимать соединения TCP до остановки."""
    sock.settimeout(0.5)
    while not _stop.is_set():
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        worker = threading.Thread(
            target=_tcp_client, args=(conn, addr[0]),
            name="syslog-tcp-client", daemon=True)
        worker.start()
    sock.close()


# ------------------------------------------------------------------- запись
def _writer_loop() -> None:
    """Писать накопленные строки пачками."""
    batch: list[dict[str, Any]] = []
    deadline = time.monotonic() + BATCH_SECONDS

    while not _stop.is_set() or not _queue.empty():
        timeout = max(0.05, deadline - time.monotonic())
        try:
            batch.append(_queue.get(timeout=timeout))
        except queue.Empty:
            pass

        if batch and (len(batch) >= BATCH_SIZE or time.monotonic() >= deadline):
            save(batch)
            batch = []
            deadline = time.monotonic() + BATCH_SECONDS

    if batch:
        save(batch)


def save(rows: list[dict[str, Any]]) -> int:
    """Записать пачку строк одной транзакцией. Возвращает число записанных."""
    if not rows:
        return 0
    values = [
        (r["ts"], r.get("device_id"), r.get("device_name", ""), r.get("source", ""),
         r.get("host", ""), r.get("topics", ""), r.get("severity", 6),
         r.get("severity_name", "info"), r.get("facility", 1),
         r.get("stamp", ""), r.get("message", ""), r.get("raw", ""))
        for r in rows
    ]
    with write_lock:
        conn = get_conn()
        conn.execute("BEGIN")
        try:
            conn.executemany(
                "INSERT INTO syslog (ts, device_id, device_name, source, host, topics, "
                "severity, severity_name, facility, stamp, message, raw) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                values,
            )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise
    state["stored"] += len(values)
    return len(values)


# ------------------------------------------------------------------ чистка
def prune(days: int | None = None, max_rows: int | None = None) -> int:
    """
    Убрать старые строки. Возвращает, сколько удалено.

    Ограничений два, и оба нужны. Срок отвечает на вопрос «сколько держим
    историю», потолок по числу строк спасает диск, когда одна точка за ночь
    пишет миллион строк об одной и той же ошибке.
    """
    days = settings.syslog_retention_days if days is None else days
    max_rows = settings.syslog_max_rows if max_rows is None else max_rows
    removed = 0

    if days > 0:
        removed += execute_changes(
            "DELETE FROM syslog WHERE ts < datetime('now', ?)", (f"-{days} days",))

    if max_rows > 0:
        row = query_one("SELECT COUNT(*) AS c FROM syslog")
        extra = (row["c"] if row else 0) - max_rows
        if extra > 0:
            removed += execute_changes(
                "DELETE FROM syslog WHERE id IN "
                "(SELECT id FROM syslog ORDER BY id LIMIT ?)", (extra,))
    return removed


def allow_source(address: str, device_id: int | None = None, note: str = "") -> None:
    """
    Разрешить приём с адреса и, если известно, закрепить его за точкой.

    Кнопкой, а не автоматически: syslog ничем не заверен, и решение
    «этому адресу верим» должен принимать человек. Зато принимает он его
    глядя на имя, которым отправитель подписался, а не на голый адрес.
    """
    execute(
        "INSERT INTO syslog_sources (address, device_id, note, created_at) "
        "VALUES (?,?,?,?) ON CONFLICT(address) DO UPDATE SET device_id = excluded.device_id",
        (address.strip(), device_id, note, utcnow()),
    )
    state["rejected"].pop(address.strip(), None)
    _sources.refresh(force=True)


def forget_source(address: str) -> int:
    """Перестать принимать с этого адреса."""
    removed = execute_changes(
        "DELETE FROM syslog_sources WHERE address = ?", (address.strip(),))
    _sources.refresh(force=True)
    return removed


def sources() -> list[dict[str, Any]]:
    """Разрешённые вручную адреса вместе с точками, за которыми закреплены."""
    return [dict(r) for r in query(
        "SELECT s.address, s.device_id, s.note, s.created_at, d.name AS device_name "
        "FROM syslog_sources s LEFT JOIN devices d ON d.id = s.device_id "
        "ORDER BY s.address")]


def clear(device_id: int | None = None) -> int:
    """Очистить журнал целиком или по одной точке."""
    if device_id:
        return execute_changes("DELETE FROM syslog WHERE device_id = ?", (device_id,))
    return execute_changes("DELETE FROM syslog", ())


def line_level(severity_name: str) -> str:
    """
    Уровень строки для оформления: те же три, что и в консоли панели.

    Восемь уровней syslog в интерфейсе избыточны: глаз всё равно делит
    строки на «плохо», «внимание» и «обычное». Точный уровень остаётся
    в колонке важности и в фильтре.
    """
    if severity_name in ("emerg", "alert", "crit", "error"):
        return "error"
    if severity_name == "warning":
        return "warning"
    return "info"


# ------------------------------------------------------------------ правила
#: Что правило делает со строкой.
ACTIONS = {
    "color": "подсветить",
    "hide": "не показывать",
    "drop": "не сохранять",
}

#: Правила, которые панель предлагает сама. Выключенные: решение прятать
#: часть журнала принимает человек, а не программа. Ключ нужен, чтобы
#: удалённое правило не возвращалось при следующем запуске.
BUILTIN_RULES = (
    {
        "key": "api-login",
        "pattern": r"logged in from .* via api",
        "is_regex": 1,
        "action": "hide",
        "note": "входы самой панели по API, их будет столько же, сколько проверок",
    },
)

#: Правила меняются редко, а спрашивают их на каждую принятую строку.
#: Пять секунд достаточно, чтобы новое правило заработало «сразу», и
#: достаточно, чтобы точка в петле не делала запрос к базе на строку.
_CACHE_SECONDS = 5.0
_cache: dict[str, Any] = {"at": 0.0, "items": []}


def rules() -> list[dict[str, Any]]:
    """Правила, в порядке применения."""
    return [dict(r) for r in query(
        "SELECT * FROM syslog_rules ORDER BY position, id")]


def active_rules() -> list[dict[str, Any]]:
    """Включённые правила из кэша: их спрашивают на каждую строку."""
    now = time.monotonic()
    if now - float(_cache["at"]) > _CACHE_SECONDS:
        _cache["items"] = [r for r in rules() if r.get("enabled", 1)]
        _cache["at"] = now
    return list(_cache["items"])


def forget_rules() -> None:
    """Сбросить кэш правил. Вызывается после любой правки."""
    _cache["at"] = 0.0


def match_rule(text: str, ruleset: list[dict[str, Any]] | None = None
               ) -> dict[str, Any] | None:
    """
    Первое подошедшее правило или None.

    Побеждает первое, а не последнее: порядок задаёт человек, и «первое
    сверху» это единственный порядок, который не надо объяснять.
    """
    lowered = text.lower()
    for rule in (active_rules() if ruleset is None else ruleset):
        if not rule.get("enabled", 1):
            continue
        pattern = str(rule.get("pattern") or "")
        if not pattern:
            continue
        if rule.get("is_regex"):
            try:
                if re.search(pattern, text, re.IGNORECASE):
                    return rule
            except re.error:
                continue
        elif pattern.lower() in lowered:
            return rule
    return None


def match_color(text: str, ruleset: list[dict[str, Any]] | None = None) -> str:
    """Цвет строки: пусто, если правила нет или оно не про цвет."""
    rule = match_rule(text, ruleset)
    if rule and str(rule.get("action") or "color") == "color":
        return str(rule.get("color") or "")
    return ""


def match_action(text: str, ruleset: list[dict[str, Any]] | None = None) -> str:
    """Что делать со строкой: color, hide или drop."""
    rule = match_rule(text, ruleset)
    return str(rule.get("action") or "color") if rule else "color"


def install_builtin_rules() -> int:
    """
    Завести предлагаемые правила, если их ещё не предлагали.

    Именно «не предлагали», а не «нет такого правила»: удалённое правило
    возвращаться не должно. Панель, которая раз за разом восстанавливает
    то, что человек убрал, воспринимается как сломанная.
    """
    added = 0
    for item in BUILTIN_RULES:
        known = query_one("SELECT key FROM syslog_builtin WHERE key = ?", (item["key"],))
        if known:
            continue
        row = query_one("SELECT COALESCE(MAX(position), 0) AS p FROM syslog_rules")
        execute(
            "INSERT INTO syslog_rules (pattern, is_regex, color, note, enabled, "
            "position, created_at, action, builtin) VALUES (?,?,?,?,0,?,?,?,?)",
            (item["pattern"], item["is_regex"], "warn", item["note"],
             (row["p"] if row else 0) + 1, utcnow(), item["action"], item["key"]),
        )
        execute("INSERT INTO syslog_builtin (key, added_at) VALUES (?,?)",
                (item["key"], utcnow()))
        added += 1
    if added:
        forget_rules()
    return added


# ------------------------------------------------------------------- запуск
def start() -> None:
    """Поднять слушателей и поток записи."""
    if not settings.syslog_enabled:
        log.info("Приём журнала отключён (SYSLOG_ENABLED=0)")
        return
    if _threads:
        return

    _stop.clear()
    state["error"] = ""
    _sources.refresh(force=True)

    started: list[str] = []

    if settings.syslog_udp_port:
        try:
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            udp.bind((settings.syslog_bind, settings.syslog_udp_port))
            thread = threading.Thread(target=_udp_loop, args=(udp,),
                                      name="syslog-udp", daemon=True)
            thread.start()
            _threads.append(thread)
            state["udp_port"] = settings.syslog_udp_port
            started.append("UDP %d" % settings.syslog_udp_port)
        except OSError as exc:
            state["error"] = f"UDP {settings.syslog_udp_port}: {exc}"
            log.error("Приём журнала по UDP не поднялся: %s", exc)

    if settings.syslog_tcp_port:
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.bind((settings.syslog_bind, settings.syslog_tcp_port))
            tcp.listen(64)
            thread = threading.Thread(target=_tcp_loop, args=(tcp,),
                                      name="syslog-tcp", daemon=True)
            thread.start()
            _threads.append(thread)
            state["tcp_port"] = settings.syslog_tcp_port
            started.append("TCP %d" % settings.syslog_tcp_port)
        except OSError as exc:
            state["error"] = (state["error"] + "; " if state["error"] else "") + \
                f"TCP {settings.syslog_tcp_port}: {exc}"
            log.error("Приём журнала по TCP не поднялся: %s", exc)

    if not _threads:
        return

    writer = threading.Thread(target=_writer_loop, name="syslog-writer", daemon=True)
    writer.start()
    _threads.append(writer)
    state["enabled"] = True
    log.info("Приём журнала запущен: %s", ", ".join(started))


def stop() -> None:
    """Остановить приём и дописать то, что уже принято."""
    _stop.set()
    for thread in _threads:
        thread.join(timeout=3)
    _threads.clear()
    state["enabled"] = False


def receive_for_tests(raw: str, address: str) -> None:
    """
    Отдать строку приёмнику напрямую, минуя сеть.

    Нужно тестам, которым интересен разбор и запись, а не работа сокета.
    Сам сокет проверяется отдельно, настоящей отправкой.
    """
    _accept(raw, address)


def flush() -> int:
    """Записать всё, что стоит в очереди, и вернуть число строк."""
    batch: list[dict[str, Any]] = []
    while True:
        try:
            batch.append(_queue.get_nowait())
        except queue.Empty:
            break
    return save(batch)
