"""
Что требует внимания: один список вместо десяти экранов.

Зачем
-----

Панель умеет показывать состояние. Состояние это ответ на вопрос «как
дела», а у человека, который открыл панель утром, вопрос другой: «за что
хвататься». Ответ на него был размазан по разделам. Недоступные точки на
дашборде, пороги на мониторинге, возраст бэкапов в бэкапах, замолчавший
журнал в журнале, опасные сервисы в карточке. Чтобы собрать картину,
надо было обойти шесть страниц и помнить, что именно на них искать.

Здесь всё это считается разом и складывается в один список, отсортированный
по важности. Ничего нового не собирается: каждая проверка это запрос к уже
имеющимся таблицам. Поэтому блок ничего не стоит и не может «сломаться» -
в худшем случае одна проверка промолчит.

Как устроено
------------

Проверка это функция, которая возвращает `Item` или `None`. Item это
строка списка: важность, заголовок, пояснение, счётчик и куда вести.
Проверки перечислены в CHECKS и вызываются по очереди, каждая в своём
try: упавшая проверка не должна утаскивать за собой весь дашборд.

Область видимости соблюдается везде. Оператор, которому доступны две
группы, не должен узнавать из сводки, что где-то в другой группе лежит
точка: это ровно та утечка, ради которой область и заводилась.

Чего тут нет
------------

Здесь нет ни своих порогов, ни своего состояния, ни уведомлений. Пороги
живут в `alerts` и умеют выдержку по времени, а это другая задача: там
«пятнадцать минут подряд выше девяноста», здесь «прямо сейчас похоже на
беду». Поэтому числа тут простые и намеренно грубые, а тонкая настройка
остаётся правилам.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from .database import query

log = logging.getLogger("tikpilot.attention")

#: Сколько смен состояния за шесть часов уже считается миганием.
#: Четыре это два падения и два подъёма: одиночное падение с подъёмом
#: мигание не образует, а вот два за полсмены это уже характер канала.
FLAP_CHANGES = 4
FLAP_HOURS = 6

#: Потери на канале точки, при которых стоит смотреть. Пять процентов
#: это уже слышно в разговоре и видно в кассовой программе.
LOSS_PERCENT = 5.0

#: Возраст последнего бэкапа, после которого точка попадает в список.
BACKUP_DAYS = 7

#: Молчание журнала. Сутки выбраны потому, что ночью на закрытой точке
#: событий может не быть вовсе, а вот сутки тишины это уже не тишина,
#: а потерянная доставка.
SYSLOG_SILENT_HOURS = 24

#: Загрузка процессора в среднем за полчаса.
CPU_PERCENT = 85.0

#: Свободная память, доля от объёма платы. Именно доля, а не мегабайты:
#: 11 МиБ свободных это треть hAP lite с его 32 МиБ и последние крохи
#: на CCR с гигабайтом. Абсолютный порог ругался бы на здоровую мелкую
#: плату вечно, а памяти на ней больше не станет, и человек просто
#: перестал бы читать весь блок.
MEMORY_PERCENT = 15.0

#: Запасной порог для точек, которые ещё не сказали, сколько у них памяти
#: всего: старые записи до этой версии и те, кого ни разу не опросили.
MEMORY_MIB = 16.0

#: Свободное место на диске роутера, доля от объёма. Та же логика, что
#: и с памятью: 2 МиБ на плате с 16 МБ флеша означают, что обновление
#: не встанет, а на плате со 128 МБ это обычное дело. Забитый диск это
#: первая причина неудачного обновления RouterOS, и узнавать о нём
#: лучше заранее, а не когда половина парка не вернулась.
SPACE_PERCENT = 10.0

#: Сколько имён показывать в пояснении, прежде чем написать «и ещё N».
NAMES_SHOWN = 3


@dataclass
class Item:
    """Одна строка сводки."""

    key: str
    #: bad — уже больно, warn — будет больно, info — стоит знать
    level: str
    #: availability | hygiene | resources | security
    group: str
    title: str
    detail: str = ""
    count: int = 0
    href: str = ""
    link_text: str = ""
    devices: list[dict[str, Any]] = field(default_factory=list)


LEVEL_ORDER = {"bad": 0, "warn": 1, "info": 2}


def _names(rows: list[dict[str, Any]], key: str = "name") -> str:
    """«Магнит, Столовая и ещё 7» — перечисление, которое читают глазами."""
    titles = [str(row.get(key) or "").strip() for row in rows]
    titles = [t for t in titles if t]
    if not titles:
        return ""
    if len(titles) <= NAMES_SHOWN:
        return ", ".join(titles)
    return ", ".join(titles[:NAMES_SHOWN]) + f" и ещё {len(titles) - NAMES_SHOWN}"


# ---------------------------------------------------------------- доступность
def _check_offline(scope: tuple[str, list[Any]]) -> Item | None:
    """Точки, которые сейчас не отвечают ни по API, ни по ICMP."""
    rows = [dict(r) for r in query(
        "SELECT d.id, d.name, d.host, d.status_changed_at, d.last_error"
        " FROM devices d WHERE d.enabled = 1 AND d.status = 'offline'"
        f"{scope[0]} ORDER BY d.status_changed_at",
        tuple(scope[1]),
    )]
    if not rows:
        return None
    return Item(
        key="offline",
        level="bad",
        group="availability",
        title="Не в сети",
        detail=_names(rows),
        count=len(rows),
        href="/monitoring",
        link_text="мониторинг",
        devices=rows,
    )


def _check_flapping(scope: tuple[str, list[Any]]) -> Item | None:
    """
    Точки, у которых состояние скачет.

    Мигание хуже честного падения: карточка показывает то, что застал
    последний опрос, уведомления приходят парами, а человек считает, что
    «вроде работает». При этом канал в таком состоянии непригоден.
    """
    rows = [dict(r) for r in query(
        "SELECT d.id, d.name, COUNT(*) AS changes"
        " FROM status_events e JOIN devices d ON d.id = e.device_id"
        f" WHERE e.ts >= datetime('now', '-{FLAP_HOURS} hours') AND d.enabled = 1"
        f"{scope[0]} GROUP BY d.id HAVING changes >= {FLAP_CHANGES}"
        " ORDER BY changes DESC",
        tuple(scope[1]),
    )]
    if not rows:
        return None
    worst = rows[0]
    return Item(
        key="flapping",
        level="warn",
        group="availability",
        title="Мигают",
        detail=f"{_names(rows)} · чаще всех {worst['name']}, "
               f"{worst['changes']} смен за {FLAP_HOURS} ч",
        count=len(rows),
        href="/monitoring",
        link_text="мониторинг",
        devices=rows,
    )


def _check_loss(scope: tuple[str, list[Any]]) -> Item | None:
    """Канал с потерями по данным пинга с самой точки."""
    rows = [dict(r) for r in query(
        "SELECT d.id, d.name, ROUND(AVG(s.loss), 1) AS loss"
        " FROM latency_samples s JOIN devices d ON d.id = s.device_id"
        " WHERE s.ts >= datetime('now', '-2 hours') AND s.loss IS NOT NULL"
        f" AND d.enabled = 1{scope[0]} GROUP BY d.id"
        f" HAVING loss >= {LOSS_PERCENT} ORDER BY loss DESC",
        tuple(scope[1]),
    )]
    if not rows:
        return None
    worst = rows[0]
    return Item(
        key="loss",
        level="warn",
        group="availability",
        title="Потери на канале",
        detail=f"{_names(rows)} · хуже всех {worst['name']}, {worst['loss']}%",
        count=len(rows),
        href="/monitoring",
        link_text="мониторинг",
        devices=rows,
    )


# -------------------------------------------------------------------- гигиена
def _check_backups(scope: tuple[str, list[Any]]) -> Item | None:
    """
    Точки без свежего бэкапа, включая те, которых не бэкапили никогда.

    Никогда и «неделю назад» здесь одно и то же: и в том и в другом
    случае восстанавливать площадку придётся по памяти.
    """
    rows = [dict(r) for r in query(
        "SELECT d.id, d.name, MAX(b.created_at) AS last_backup"
        " FROM devices d LEFT JOIN backups b ON b.device_id = d.id"
        f" WHERE d.enabled = 1{scope[0]} GROUP BY d.id"
        f" HAVING last_backup IS NULL"
        f"     OR last_backup < datetime('now', '-{BACKUP_DAYS} days')"
        " ORDER BY last_backup",
        tuple(scope[1]),
    )]
    if not rows:
        return None
    never = sum(1 for row in rows if not row["last_backup"])
    detail = _names(rows)
    if never:
        detail += f" · без единого бэкапа: {never}"
    return Item(
        key="backups",
        level="warn",
        group="hygiene",
        title=f"Бэкап старше {BACKUP_DAYS} суток",
        detail=detail,
        count=len(rows),
        href="/backups",
        link_text="бэкапы",
        devices=rows,
    )


def _check_syslog(scope: tuple[str, list[Any]]) -> Item | None:
    """
    Точки, которые слали журнал и перестали.

    Именно «слали и перестали»: точка, которая не настроена на отправку,
    молчит законно, и записывать её в проблемы значит показывать сорок
    строк тем, кто журналом не пользуется.
    """
    rows = [dict(r) for r in query(
        "SELECT d.id, d.name, MAX(s.ts) AS last_line"
        " FROM syslog s JOIN devices d ON d.id = s.device_id"
        " WHERE s.ts >= datetime('now', '-7 days')"
        f" AND d.enabled = 1{scope[0]} GROUP BY d.id"
        f" HAVING last_line < datetime('now', '-{SYSLOG_SILENT_HOURS} hours')"
        " ORDER BY last_line",
        tuple(scope[1]),
    )]
    if not rows:
        return None
    return Item(
        key="syslog",
        level="warn",
        group="hygiene",
        title="Журнал замолчал",
        detail=f"{_names(rows)} · слали раньше, за последние "
               f"{SYSLOG_SILENT_HOURS} ч ни строки",
        count=len(rows),
        href="/syslog",
        link_text="журнал",
        devices=rows,
    )


def _check_rollbacks(scope: tuple[str, list[Any]]) -> Item | None:
    """Взведённые страховки: точка сама откатится и перезагрузится."""
    rows = [dict(r) for r in query(
        "SELECT r.device_id AS id, r.device_name AS name, r.expires_at"
        " FROM rollbacks r LEFT JOIN devices d ON d.id = r.device_id"
        f" WHERE r.state = 'armed'{scope[0]} ORDER BY r.expires_at",
        tuple(scope[1]),
    )]
    if not rows:
        return None
    return Item(
        key="rollbacks",
        level="bad",
        group="hygiene",
        title="Ждут подтверждения",
        detail=f"{_names(rows)} · без подтверждения откатят конфигурацию "
               "сами и перезагрузятся",
        count=len(rows),
        devices=rows,
    )


def _check_jobs(scope: tuple[str, list[Any]]) -> Item | None:
    """
    Задачи, где были ошибки, за последние сутки.

    Область видимости здесь не при чём: задача общая, а не устройства,
    и её номер и так виден в истории.
    """
    rows = [dict(r) for r in query(
        "SELECT id, action_label, fail_count FROM jobs"
        " WHERE fail_count > 0 AND finished_at >= datetime('now', '-1 day')"
        " ORDER BY id DESC"
    )]
    if not rows:
        return None
    failed = sum(int(row["fail_count"] or 0) for row in rows)
    return Item(
        key="jobs",
        level="warn",
        group="hygiene",
        title="Задачи с ошибками",
        # Без склонения числительного: строка уходит в перевод целиком,
        # а склеенное внутри неё русское слово переводом не заменится
        detail=f"за сутки задач: {len(rows)}, точек с ошибкой: {failed}",
        count=len(rows),
        href="/jobs",
        link_text="история задач",
    )


# -------------------------------------------------------------------- ресурсы
def _check_cpu(scope: tuple[str, list[Any]]) -> Item | None:
    """Процессор под потолком в среднем за полчаса."""
    rows = [dict(r) for r in query(
        "SELECT d.id, d.name, ROUND(AVG(m.cpu_load)) AS cpu"
        " FROM device_metrics m JOIN devices d ON d.id = m.device_id"
        " WHERE m.ts >= datetime('now', '-30 minutes') AND m.cpu_load IS NOT NULL"
        f" AND d.enabled = 1{scope[0]} GROUP BY d.id"
        f" HAVING cpu >= {CPU_PERCENT} ORDER BY cpu DESC",
        tuple(scope[1]),
    )]
    if not rows:
        return None
    worst = rows[0]
    return Item(
        key="cpu",
        level="warn",
        group="resources",
        title="Загружен процессор",
        detail=f"{_names(rows)} · выше всех {worst['name']}, {worst['cpu']:g}% "
               "в среднем за полчаса",
        count=len(rows),
        devices=rows,
    )


def _check_memory(scope: tuple[str, list[Any]]) -> Item | None:
    """
    Свободной памяти почти не осталось.

    Считается долей от объёма платы. Абсолютный порог здесь не работает:
    на hAP lite с его 32 МиБ свободные 11 МиБ это нормальная рабочая
    треть, и точка попадала бы в список каждый день до конца своих дней.
    Памяти на ней больше не станет, а список, в котором вечно висит одно
    и то же, перестают читать целиком.

    Платы, которые ещё не сообщили свой объём, судятся по-старому, по
    абсолютному запасу: это записи, сделанные до появления столбца.
    """
    rows = [dict(r) for r in query(
        "SELECT d.id, d.name, d.total_memory,"
        "       ROUND(MIN(m.free_memory) / 1048576.0, 1) AS free_mib,"
        "       CASE WHEN d.total_memory > 0"
        "            THEN ROUND(100.0 * MIN(m.free_memory) / d.total_memory, 1)"
        "            END AS free_percent"
        " FROM device_metrics m JOIN devices d ON d.id = m.device_id"
        " WHERE m.ts >= datetime('now', '-30 minutes') AND m.free_memory IS NOT NULL"
        f" AND d.enabled = 1{scope[0]} GROUP BY d.id"
        f" HAVING (free_percent IS NOT NULL AND free_percent <= {MEMORY_PERCENT})"
        f"     OR (free_percent IS NULL AND free_mib <= {MEMORY_MIB})"
        " ORDER BY COALESCE(free_percent, 0), free_mib",
        tuple(scope[1]),
    )]
    if not rows:
        return None
    worst = rows[0]
    share = (f", это {worst['free_percent']:g}% от платы"
             if worst["free_percent"] is not None else "")
    return Item(
        key="memory",
        level="warn",
        group="resources",
        title="Мало памяти",
        detail=f"{_names(rows)} · меньше всех у {worst['name']}, "
               f"{worst['free_mib']:g} МиБ{share}",
        count=len(rows),
        devices=rows,
    )


def _check_router_space(scope: tuple[str, list[Any]]) -> Item | None:
    """
    Мало места на диске самого роутера.

    Считается долей, а не мегабайтами, по той же причине, что и память.
    Платы, которые объём диска не сообщили, пропускаются: гадать не по чему,
    а ложная тревога хуже молчания.

    Данные берутся из карточки, а не из метрик: объём диска меняется редко,
    отдельный ряд наблюдений тут не нужен.
    """
    rows = [dict(r) for r in query(
        "SELECT d.id, d.name,"
        "       ROUND(d.free_space / 1048576.0, 1) AS free_mib,"
        "       ROUND(100.0 * d.free_space / d.total_space, 1) AS free_percent"
        " FROM devices d"
        f" WHERE d.enabled = 1 AND d.total_space > 0 AND d.free_space > 0{scope[0]}"
        f" AND (100.0 * d.free_space / d.total_space) <= {SPACE_PERCENT}"
        " ORDER BY free_percent",
        tuple(scope[1]),
    )]
    if not rows:
        return None
    worst = rows[0]
    return Item(
        key="space",
        level="warn",
        group="resources",
        # Название своё, а не «Мало места на диске»: так называется
        # проверка диска самой панели, и на дашборде две одинаковые
        # строки не дали бы понять, о чьём диске речь
        title="Мало места на роутерах",
        detail=f"{_names(rows)} · меньше всех у {worst['name']}, "
               f"{worst['free_mib']:g} МиБ, это {worst['free_percent']:g}% от диска."
               f" Обновление RouterOS на такой точке может не встать",
        count=len(rows),
        devices=rows,
    )


def _check_panel_disk(scope: tuple[str, list[Any]]) -> Item | None:
    """
    Место на диске самой панели.

    Единственная проверка, которая смотрит не на парк, а на себя. Стоит
    здесь потому, что кончившееся место останавливает вообще всё: панель
    уже однажды встала целиком, и узнать об этом хотелось бы раньше.
    """
    from . import disk

    if not disk.low():
        return None
    space = disk.free_space()
    parts = disk.sizes()
    return Item(
        key="panel_disk",
        level="bad",
        group="resources",
        title="Мало места на диске панели",
        detail=f"свободно {disk.human(space['free'])} из "
               f"{disk.human(space['total'])} ({disk.percent_free()}%) · "
               f"база {disk.human(parts['db'])}, бэкапы {disk.human(parts['backups'])}",
        count=1,
        href="/settings/system",
        link_text="настройки",
    )


# --------------------------------------------------------------- безопасность
def _check_risky_services(scope: tuple[str, list[Any]]) -> Item | None:
    """Опасные сервисы RouterOS, открытые без ограничения по адресам."""
    rows = [dict(r) for r in query(
        "SELECT d.id, d.name, GROUP_CONCAT(s.name) AS services"
        " FROM device_services s JOIN devices d ON d.id = s.device_id"
        f" WHERE s.risky = 1 AND d.enabled = 1{scope[0]}"
        " GROUP BY d.id ORDER BY d.name COLLATE NOCASE",
        tuple(scope[1]),
    )]
    if not rows:
        return None
    kinds: set[str] = set()
    for row in rows:
        kinds.update(str(row["services"] or "").split(","))
    kinds.discard("")
    return Item(
        key="risky",
        level="warn",
        group="security",
        title="Открытые сервисы",
        detail=f"{_names(rows)} · {', '.join(sorted(kinds))} доступны "
               "с любого адреса",
        count=len(rows),
        href="/devices",
        link_text="устройства",
        devices=rows,
    )


def _check_updates(scope: tuple[str, list[Any]]) -> Item | None:
    """Точки, где установленная версия старее найденной."""
    from .mikrotik import is_newer

    rows = [dict(r) for r in query(
        "SELECT d.id, d.name, d.ros_version, d.latest_version FROM devices d"
        f" WHERE d.enabled = 1 AND d.latest_version <> ''{scope[0]}"
        " ORDER BY d.name COLLATE NOCASE",
        tuple(scope[1]),
    )]
    pending = [r for r in rows if is_newer(r["latest_version"], r["ros_version"])]
    if not pending:
        return None
    return Item(
        key="updates",
        level="info",
        group="security",
        title="Доступно обновление RouterOS",
        detail=_names(pending),
        count=len(pending),
        href="/devices?status=update",
        link_text="показать списком",
        devices=pending,
    )


CHECKS: tuple[Callable[[tuple[str, list[Any]]], Item | None], ...] = (
    _check_offline,
    _check_rollbacks,
    _check_panel_disk,
    _check_flapping,
    _check_loss,
    _check_backups,
    _check_syslog,
    _check_cpu,
    _check_memory,
    _check_router_space,
    _check_risky_services,
    _check_jobs,
    _check_updates,
)


def collect(scope: tuple[str, list[Any]] = ("", [])) -> list[Item]:
    """
    Все проверки разом, важное сверху.

    Порядок внутри одной важности сохраняется тот, в котором проверки
    перечислены в CHECKS: доступность выше гигиены, гигиена выше
    ресурсов. Сортировка устойчивая, поэтому этого достаточно.
    """
    items: list[Item] = []
    for check in CHECKS:
        try:
            item = check(scope)
        except Exception:  # noqa: BLE001 — одна проверка не должна гасить сводку
            log.exception("Проверка %s не отработала", getattr(check, "__name__", "?"))
            continue
        if item is not None:
            items.append(item)
    items.sort(key=lambda i: LEVEL_ORDER.get(i.level, 9))
    return items


def worst_level(items: list[Item]) -> str:
    """Самая тяжёлая важность в списке — по ней красится заголовок блока."""
    for level in ("bad", "warn", "info"):
        if any(item.level == level for item in items):
            return level
    return ""
