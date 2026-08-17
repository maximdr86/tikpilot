"""
Трафик по интерфейсам.

Зачем
-----

Вопрос «почему на точке всё тормозит» без цифр не решается. Задержка и
потери говорят о канале, но не отвечают, кто его занял: то ли камеры
льют запись в облако, то ли кто-то качает обновления в разгар торговли.
Счётчики интерфейсов отвечают.

Откуда берутся цифры
--------------------

Не из `/interface/monitor-traffic`. Та команда меряет за одну секунду и
показывает мгновенный всплеск: на канале, где трафик идёт рывками, два
соседних замера отличаются в десять раз, и по ним ничего не понять.

Берём накопительные счётчики из `/interface/print`: сколько байт прошло
с момента загрузки. Разница между двумя обходами, делённая на время
между ними, это средняя скорость за интервал, а не за случайную секунду.
Заодно это одна команда на все интерфейсы сразу, а не по команде на
каждый: на тайговом канале разница заметна.

Счётчики иногда обнуляются: роутер перезагрузили, интерфейс пересоздали,
в шестой версии они ещё и тридцатидвухбитные и переполняются на быстрых
портах. Признак один и тот же: новое значение меньше прежнего. Такую
пару не считаем вовсе, а запоминаем новую точку отсчёта. Пропущенный
замер честнее выдуманного всплеска на два гигабита.

За чем следим
-------------

По умолчанию за аплинком: интерфейсом, через который у точки уходит
маршрут по умолчанию. Это тот самый канал, из-за которого звонят.
Остальные интерфейсы добавляются галочкой в карточке устройства, и
список живёт отдельно от паспорта: паспорт при каждом обходе
переписывается заново, а выбор человека переживать это обязан.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from .config import settings
from .database import (execute, execute_changes, get_conn, query, query_one, utcnow,
                       write_lock)

log = logging.getLogger("tikpilot.traffic")

#: Поля счётчиков, которые просим у роутера. Меньше полей - меньше байт
#: в ответе, а интерфейсов на коробке бывает три десятка.
PROPS = "name,rx-byte,tx-byte,running,disabled,type"

#: Ниже этого числа секунд между обходами замер не считаем: при коротком
#: интервале ошибка округления времени сравнима с самим интервалом.
MIN_SPAN = 20

#: Выше этого числа секунд прежний счётчик не годится: между обходами
#: прошло слишком много, и средняя за три часа скрывает всё, ради чего
#: её меряли. Точку отсчёта обновляем, замер пропускаем.
MAX_SPAN = 3600


# ------------------------------------------------------------------- выбор
def watched(device_id: int) -> set[str]:
    """Интерфейсы, отмеченные человеком. Аплинк сюда не входит."""
    rows = query("SELECT interface FROM traffic_watch WHERE device_id = ?", (device_id,))
    return {str(row["interface"]) for row in rows}


def set_watch(device_id: int, interface: str, on: bool) -> None:
    """Включить или выключить наблюдение за интерфейсом."""
    name = str(interface or "").strip()
    if not name:
        return
    if on:
        execute(
            "INSERT INTO traffic_watch (device_id, interface) VALUES (?,?)"
            " ON CONFLICT(device_id, interface) DO NOTHING",
            (device_id, name),
        )
    else:
        execute_changes(
            "DELETE FROM traffic_watch WHERE device_id = ? AND interface = ?",
            (device_id, name),
        )


def wanted(device: dict[str, Any]) -> set[str]:
    """
    За какими интерфейсами следим у этой точки.

    Пустое множество означает «за всеми»: так работает режим, в котором
    человек сознательно включил сбор по всему железу.
    """
    if settings.traffic_all_interfaces:
        return set()
    names = watched(int(device["id"]))
    uplink = str(device.get("uplink_interface") or "").strip()
    if uplink:
        names.add(uplink)
    return names


# ------------------------------------------------------------------- аплинк
def uplink_from_routes(routes: Iterable[dict[str, Any]]) -> str:
    """
    Имя интерфейса, через который уходит маршрут по умолчанию.

    В RouterOS 7 в маршруте есть готовое поле `immediate-gw` вида
    `10.8.0.1%ether1`: адрес соседа и интерфейс через знак процента.
    В шестой версии того же поля нет, зато есть `gateway-status`
    вида `10.8.0.1 reachable via ether1`. Разбираем обе формы, потому
    что парк почти всегда смешанный.
    """
    for route in routes:
        if str(route.get("dst-address") or "") not in ("0.0.0.0/0", "::/0"):
            continue
        if route.get("disabled") is True or str(route.get("disabled")) == "true":
            continue

        immediate = str(route.get("immediate-gw") or "")
        if "%" in immediate:
            return immediate.split("%", 1)[1].strip()

        status = str(route.get("gateway-status") or "")
        if " via " in status:
            return status.split(" via ", 1)[1].strip()
    return ""


def remember_uplink(device_id: int, name: str) -> None:
    """Запомнить аплинк точки, чтобы не спрашивать маршруты каждый обход."""
    execute_changes(
        "UPDATE devices SET uplink_interface = ? WHERE id = ?",
        (str(name or "").strip(), device_id),
    )


#: Что не показываем в списке галочек по умолчанию. Петля, туннели
#: клиентов и поднятые роутером сессии живут десятками, меняются сами
#: и следят за ними примерно никогда.
MINOR_KINDS = ("l2tp-in", "l2tp-out", "pptp-in", "pptp-out", "sstp-in", "sstp-out",
               "ovpn-in", "ovpn-out", "ppp-in", "ppp-out", "pppoe-in", "pppoe-out",
               "loopback")
MINOR_PREFIXES = ("lo", "sstp-", "l2tp-", "pptp-", "ovpn-", "ppp-", "pppoe-",
                  "<pptp-", "<l2tp-", "<sstp-", "<ovpn-", "<pppoe-")


def is_minor(name: str, kind: str = "") -> bool:
    """
    Служебный ли это интерфейс.

    Не запрет, а порядок показа: такие прячутся под «показать все»,
    но следить за ними можно, и если человек уже следит или замеры
    по интерфейсу есть, он показывается наравне с остальными.
    """
    lowered = str(name or "").strip().lower()
    if str(kind or "").strip().lower() in MINOR_KINDS:
        return True
    return lowered == "lo" or lowered.startswith(MINOR_PREFIXES[1:])


# ------------------------------------------------------------------- сбор
def read_counters(mt: Any) -> list[dict[str, Any]]:
    """Снять счётчики со всех интерфейсов одной командой."""
    return list(mt.cmd("/interface/print", **{".proplist": PROPS}))


def _int(value: Any) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def rate(previous: dict[str, Any] | None, current: dict[str, Any],
         span: float) -> tuple[int, int] | None:
    """
    Средняя скорость между двумя снятиями счётчиков, биты в секунду.

    Возвращает None, когда считать нечего или нельзя: нет прежнего
    значения, счётчик обнулился, интервал слишком мал или слишком велик.
    """
    if previous is None or span < MIN_SPAN or span > MAX_SPAN:
        return None

    was_rx, was_tx = _int(previous.get("rx_bytes")), _int(previous.get("tx_bytes"))
    now_rx, now_tx = _int(current.get("rx-byte")), _int(current.get("tx-byte"))
    if None in (was_rx, was_tx, now_rx, now_tx):
        return None
    if now_rx < was_rx or now_tx < was_tx:
        # Перезагрузка, пересоздание интерфейса или переполнение счётчика
        return None

    return (
        int((now_rx - was_rx) * 8 / span),
        int((now_tx - was_tx) * 8 / span),
    )


def collect(device: dict[str, Any], mt: Any) -> int:
    """
    Снять счётчики, посчитать скорость и сохранить.

    Возвращает число записанных замеров. Ноль это обычное дело: первый
    обход после запуска панели только запоминает точку отсчёта.
    """
    device_id = int(device["id"])
    names = wanted(device)

    try:
        rows = read_counters(mt)
    except Exception as exc:  # noqa: BLE001 - обход не должен падать из-за счётчиков
        log.debug("Счётчики не прочитаны для %s: %s", device.get("host"), exc)
        return 0

    # Именно dict, а не sqlite3.Row: у строки из базы нет .get, и в первой
    # же боевой сборке это уронило сбор целиком
    previous = {
        str(row["interface"]): dict(row)
        for row in query(
            "SELECT interface, ts, rx_bytes, tx_bytes FROM traffic_counters"
            " WHERE device_id = ?",
            (device_id,),
        )
    }

    now = utcnow()
    samples: list[tuple[Any, ...]] = []
    counters: list[tuple[Any, ...]] = []

    for row in rows:
        name = str(row.get("name") or "").strip()
        if not name or (names and name not in names):
            continue
        if row.get("disabled") is True or str(row.get("disabled")) == "true":
            continue

        was = previous.get(name)
        speed = rate(was, row, _span(was.get("ts") if was else None, now))
        if speed is not None:
            samples.append((device_id, name, now, speed[0], speed[1],
                            int(_span(was.get("ts") if was else None, now))))

        rx, tx = _int(row.get("rx-byte")), _int(row.get("tx-byte"))
        if rx is not None and tx is not None:
            counters.append((device_id, name, now, rx, tx))

    _save(samples, counters)
    return len(samples)


def _span(before: Any, after: str) -> float:
    """Секунды между двумя отметками времени. Ноль, если сравнить нечем."""
    from datetime import datetime

    if not before:
        return 0.0
    try:
        start = datetime.fromisoformat(str(before))
        end = datetime.fromisoformat(str(after))
    except ValueError:
        return 0.0
    return (end - start).total_seconds()


def _save(samples: list[tuple[Any, ...]], counters: list[tuple[Any, ...]]) -> None:
    """Записать замеры и обновить точки отсчёта одной транзакцией."""
    if not samples and not counters:
        return
    with write_lock:
        conn = get_conn()
        conn.execute("BEGIN")
        try:
            if samples:
                conn.executemany(
                    "INSERT INTO traffic_samples (device_id, interface, ts, rx_bps,"
                    " tx_bps, span) VALUES (?,?,?,?,?,?)",
                    samples,
                )
            if counters:
                conn.executemany(
                    "INSERT INTO traffic_counters (device_id, interface, ts, rx_bytes,"
                    " tx_bytes) VALUES (?,?,?,?,?)"
                    " ON CONFLICT(device_id, interface) DO UPDATE SET"
                    " ts = excluded.ts, rx_bytes = excluded.rx_bytes,"
                    " tx_bytes = excluded.tx_bytes",
                    counters,
                )
            conn.execute("COMMIT")
        except Exception:
            conn.execute("ROLLBACK")
            raise


# ------------------------------------------------------------------- чтение
def history(device_id: int, interface: str, hours: int = 24) -> list[Any]:
    """Замеры по интерфейсу за последние часы, по возрастанию времени."""
    from datetime import datetime, timedelta, timezone

    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    return query(
        "SELECT ts, rx_bps, tx_bps, span FROM traffic_samples"
        " WHERE device_id = ? AND interface = ? AND ts >= ? ORDER BY ts",
        (device_id, interface, since),
    )


def bucketed(rows: list[Any], hours: int, target: int = 120) -> list[dict[str, Any]]:
    """
    Свести замеры в равные корзины и усреднить.

    Зачем: обходы идут не строго по часам. Полный опрос раз в пятнадцать
    минут, между ними попадаются внеплановые проверки, и интервалы у
    соседних замеров получаются разной длины. На графике это выглядит
    пилой, по которой невозможно сказать, когда трафика было больше,
    хотя данные верные.

    Корзина одинаковой длины убирает пилу и оставляет то, ради чего
    график и смотрят: форму суток. Пустые корзины остаются пустыми
    (None), и линия в этом месте честно рвётся, а не соединяет два
    далёких значения прямой.
    """
    from datetime import datetime, timedelta, timezone

    if not rows:
        return []

    span = max(1, int(hours * 3600 / max(target, 1)))
    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=hours)

    slots: dict[int, list[tuple[float, float]]] = {}
    for row in rows:
        try:
            moment = datetime.fromisoformat(str(row["ts"])).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        index = int((moment - start).total_seconds() // span)
        slots.setdefault(index, []).append(
            (float(row["rx_bps"] or 0), float(row["tx_bps"] or 0)))

    total = int((end - start).total_seconds() // span) + 1
    result: list[dict[str, Any]] = []
    for index in range(total):
        ts = (start + timedelta(seconds=span * index)).strftime("%Y-%m-%d %H:%M:%S")
        values = slots.get(index)
        if values:
            result.append({
                "ts": ts,
                "rx_bps": sum(v[0] for v in values) / len(values),
                "tx_bps": sum(v[1] for v in values) / len(values),
            })
        else:
            result.append({"ts": ts, "rx_bps": None, "tx_bps": None})
    return result


def volume(device_id: int, interface: str, hours: int = 24) -> dict[str, float]:
    """
    Сколько байт прошло через интерфейс за период.

    Отдельного счётчика для этого не нужно. Каждый замер это средняя
    скорость за известное число секунд, то есть ровно та разница
    счётчиков, из которой он и получен. Сумма произведений возвращает
    исходные байты обратно, без второй таблицы и без второго обхода.

    Провалы в сборе при этом не выдумываются: пока точка лежала,
    замеров нет, и в сумму они не попадают. Поэтому вместе с объёмом
    возвращается `covered` - сколько секунд периода замеры покрывают.
    Показывать «за сутки», когда за сутки собрано три часа, нечестно,
    и решать это должен тот, кто рисует.
    """
    from datetime import datetime, timedelta, timezone

    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    row = query_one(
        "SELECT SUM(rx_bps * span) AS rx, SUM(tx_bps * span) AS tx,"
        " SUM(span) AS covered FROM traffic_samples"
        " WHERE device_id = ? AND interface = ? AND ts >= ?",
        (device_id, interface, since),
    )
    if row is None or row["covered"] is None:
        return {"rx": 0.0, "tx": 0.0, "covered": 0.0}
    return {
        "rx": float(row["rx"] or 0) / 8,
        "tx": float(row["tx"] or 0) / 8,
        "covered": float(row["covered"] or 0),
    }


def interfaces(device_id: int) -> list[str]:
    """Интерфейсы, по которым есть хоть один замер."""
    rows = query(
        "SELECT DISTINCT interface FROM traffic_samples WHERE device_id = ?"
        " ORDER BY interface",
        (device_id,),
    )
    return [str(row["interface"]) for row in rows]


def latest(device_id: int) -> dict[str, dict[str, int]]:
    """Последняя известная скорость по каждому интерфейсу точки."""
    rows = query(
        "SELECT interface, rx_bps, tx_bps, MAX(ts) AS ts FROM traffic_samples"
        " WHERE device_id = ? GROUP BY interface",
        (device_id,),
    )
    return {
        str(row["interface"]): {"rx": int(row["rx_bps"] or 0), "tx": int(row["tx_bps"] or 0)}
        for row in rows
    }


def human_volume(size: int | float | None) -> str:
    """
    Объём в человеческий вид: 4,2 ГиБ.

    Двоичные единицы, как и везде в панели: свободная память, место
    на флеше и размер бэкапа тоже считаются в МиБ, и одна страница
    не должна мерить одно и то же двумя разными способами.
    """
    value = float(size or 0)
    for unit in ("Б", "КиБ", "МиБ", "ГиБ", "ТиБ"):
        if value < 1024 or unit == "ТиБ":
            if unit == "Б":
                return f"{int(value)} {unit}"
            return f"{value:.1f}".replace(".", ",") + f" {unit}"
        value /= 1024
    return f"{value:.1f} ТиБ"


def human_rate(bps: int | float | None) -> str:
    """Скорость в человеческий вид: 12,4 Мбит/с."""
    value = float(bps or 0)
    for unit in ("бит/с", "Кбит/с", "Мбит/с", "Гбит/с"):
        if value < 1000 or unit == "Гбит/с":
            if unit == "бит/с":
                return f"{int(value)} {unit}"
            return f"{value:.1f}".replace(".", ",") + f" {unit}"
        value /= 1000
    return f"{value:.1f} Гбит/с"
