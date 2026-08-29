"""Дашборд и журнал действий."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import RedirectResponse

from ..auth import client_ip, current_user, require
from ..config import settings
from ..database import log_audit, query, query_one, utcnow
from .. import permissions
from .deps import pager, render, render_partial, resolve_lang

router = APIRouter()

log = logging.getLogger("tikpilot.pages")


@router.get("/healthz")
async def healthz():
    """
    Жива ли панель. Без входа в систему и без ограничения по сетям.

    Спрашивает обычно не человек: установщик сразу после запуска службы,
    systemd, монитор контейнера, внешняя проверка вроде healthchecks.io.
    Раньше все они стучались в `/login` и получали либо 403 от проверки
    сетей, либо страницу входа, по которой нельзя отличить работающую
    панель от панели с мёртвой базой. Установщик из-за этого пугал
    сообщением «служба работает, но интерфейс не отвечает» на совершенно
    здоровой установке.

    Проверяется главное: отвечает ли база. Процесс, который поднялся,
    но не может прочитать SQLite, для наблюдателя ничем не лучше
    упавшего, и различать эти случаи должен он, а не человек в журнале.

    Ответ намеренно скудный. Страница открыта всем, и рассказывать
    в ней про версию, число устройств и время работы незачем.
    """
    from fastapi.responses import JSONResponse

    from ..database import query_one

    try:
        query_one("SELECT 1 AS ok")
    except Exception as exc:  # noqa: BLE001 — наружу уходит только «плохо»
        log.error("Проверка здоровья не прошла: %s", exc)
        return JSONResponse({"status": "error"}, status_code=503)

    return JSONResponse({"status": "ok"})


@router.get("/manifest.webmanifest")
async def manifest():
    """
    Описание веб-приложения для кнопки «На экран Домой».

    Лежит в корне, а не в статике: область действия по умолчанию
    считается от адреса самого файла, и манифест из `/static/` объявил
    бы приложением только эту папку.

    Открытая с домашнего экрана панель показывается без адресной строки
    и вкладок: телефон в кармане у человека, который смотрит парк
    на ходу, а не браузер.
    """
    from fastapi.responses import JSONResponse

    return JSONResponse(
        {
            "name": "Tikpilot",
            "short_name": "Tikpilot",
            "description": "Панель управления парком MikroTik",
            "start_url": "/",
            "scope": "/",
            "display": "standalone",
            "orientation": "portrait-primary",
            "background_color": "#f4f6f6",
            "theme_color": "#0f6156",
            "icons": [
                {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png"},
                {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png"},
                {"src": "/static/icon-maskable-512.png", "sizes": "512x512",
                 "type": "image/png", "purpose": "maskable"},
            ],
        },
        media_type="application/manifest+json",
    )


@router.get("/")
async def dashboard(request: Request, user=Depends(current_user)):
    """Главная страница: сводка по парку и последние задачи."""
    scope = permissions.scope_sql(user)
    stats = query_one(
        """
        SELECT COUNT(*)                                             AS total,
               SUM(CASE WHEN status='online'  THEN 1 ELSE 0 END)    AS online,
               SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END)    AS offline,
               SUM(CASE WHEN status='unknown' THEN 1 ELSE 0 END)    AS unknown,
               SUM(CASE WHEN enabled=0        THEN 1 ELSE 0 END)    AS disabled
        FROM devices d WHERE 1=1{scope}
        """.format(scope=scope[0]),
        tuple(scope[1]),
    )
    groups = query(
        """
        SELECT g.id, g.name, g.color,
               COUNT(d.id)                                          AS total,
               SUM(CASE WHEN d.status='online' THEN 1 ELSE 0 END)   AS online
        FROM groups g LEFT JOIN devices d ON d.group_id = g.id
        WHERE 1=1{scope}
        GROUP BY g.id ORDER BY total DESC, g.name COLLATE NOCASE
        """.format(scope=scope[0]),
        tuple(scope[1]),
    )
    recent_jobs = query("SELECT * FROM jobs ORDER BY id DESC LIMIT 8")
    versions = query(
        "SELECT d.ros_version, COUNT(*) AS c FROM devices d WHERE d.ros_version <> '' "
        f"{scope[0]} GROUP BY d.ros_version ORDER BY c DESC LIMIT 8",
        tuple(scope[1]),
    )

    from .. import attention, monitor, rollback
    from ..actions import list_actions

    # Просроченные страховки надо закрыть до того, как считать сводку:
    # иначе в «ждут подтверждения» попадут те, что уже сработали
    rollback.sweep()

    # Что требует внимания. Внутрь этого блока переехали и плашка диска,
    # и список недоступных, и напоминание про страховки: раньше они были
    # тремя отдельными сущностями наверху страницы и спорили за место
    todo = attention.collect(scope)

    return render(
        "dashboard.html",
        request,
        user,
        active="dashboard",
        attention=todo,
        attention_level=attention.worst_level(todo),
        stats=stats,
        groups=groups,
        recent_jobs=recent_jobs,
        versions=versions,
        monitor_state=monitor.state,
        actions=list_actions(),
    )


@router.get("/console")
async def console_page(request: Request, user=Depends(require("console.view"))):
    """
    Живая консоль: что панель делает прямо сейчас.

    Сама страница почти пустая, строки подгружаются опросом. Так проще
    и надёжнее постоянного соединения: панель часто стоит за прокси,
    а прокси любят рвать долгие запросы, и разбираться, почему консоль
    молчит, пришлось бы вместо работы.
    """
    from .. import activity

    return render(
        "console.html",
        request,
        user,
        active="console",
        rows=activity.tail(limit=300),
        capacity=activity.CAPACITY,
    )


@router.get("/api/console")
async def console_feed(after: int = 0, level: str = "", q: str = "",
                       user=Depends(require("console.view"))):
    """Строки новее уже показанных. Опрашивается страницей раз в две секунды."""
    from .. import activity

    rows = activity.tail(after=after, level=level, needle=q)
    return {"rows": rows, "last": rows[-1]["id"] if rows else after}


@router.get("/api/console/now")
async def console_now(user=Depends(require("console.view"))):
    """
    Что происходит прямо сейчас.

    Лента отвечает на вопрос «что было секунду назад», а этот ответ на
    «что идёт». Разные вопросы: задача на сорок точек час пишет по строке
    в минуту, и по ленте не понять, сколько ей осталось.
    """
    from .. import monitor, schedules

    jobs = query(
        "SELECT id, action_label, done, total, username FROM jobs "
        "WHERE status = 'running' ORDER BY id"
    )
    pending = query_one(
        "SELECT COUNT(*) AS c FROM jobs WHERE status = 'pending'") or {"c": 0}
    rule = query_one(
        "SELECT name, target, at_time, next_run_at FROM backup_schedules "
        "WHERE enabled = 1 AND next_run_at IS NOT NULL ORDER BY next_run_at LIMIT 1"
    )

    return {
        "jobs": [dict(j) for j in jobs],
        "pending": pending["c"],
        "monitor": {
            "enabled": monitor.state["enabled"],
            "last_cycle": monitor.state["last_cycle"],
            "duration": monitor.state["last_duration"],
            "checked": monitor.state["checked"],
            "sessions": monitor.state["sessions"],
        },
        "schedule": {
            "at": rule["next_run_at"] if rule else "",
            "what": (rule["name"] or schedules.TARGET_LABELS.get(rule["target"], ""))
            if rule else "",
        },
    }


@router.post("/api/console/clear")
async def console_clear(request: Request, user=Depends(require("console.view"))):
    """
    Очистить консоль.

    Очищается только буфер в памяти: журнал сервера и история задач лежат
    в других местах и остаются нетронутыми.
    """
    from .. import activity

    activity.clear()
    log_audit(user["username"], "Очищена консоль", ip=client_ip(request))
    return {"ok": True}


#: Пороги, по которым доступность красится в отчёте. Не из головы: за месяц
#: 99,5 % это около трёх с половиной часов простоя, а 98 % уже почти
#: пятнадцать часов, и это разные разговоры с провайдером.
REPORT_GOOD = 99.5
REPORT_FAIR = 98.0

#: Сколько записей о падениях показывать. За месяц по парку их бывают сотни,
#: а отчёт на сорок страниц никто не читает.
REPORT_OUTAGE_LIMIT = 200


#: Ниже этого столбик красный. Отдельно от порогов таблицы, и вот почему.
#: Столбик это не точка, а срез: час по всему парку или сутки по одной
#: площадке. При парке в полсотни одна лежащая точка даёт ровно 98%, то
#: есть по меркам таблицы «плохо», хотя это обычный день с одной аварией.
#: Красили по тем же порогам, и сутки покрывались сплошной красной стеной,
#: на которой не видно ни настоящей беды, ни спокойного дня.
CHART_BAD = 90.0


def _chart_color(percent: float) -> str:
    """
    Цвет столбика: спокойный по умолчанию, красный при настоящем провале.

    График отвечает на вопрос «когда и насколько», а вердикт «хорошо или
    плохо» дают крупные цифры сверху и цветные строки в таблице. Светофор
    ещё и здесь только мешает: он срабатывает от арифметики, а не от беды.
    """
    return "var(--err)" if percent < CHART_BAD else "var(--accent)"


def _chart_step_note(hours: int) -> str:
    """Подпись к графику: чем измеряется один столбик."""
    from .. import monitor

    step = monitor.bucket_step(hours)
    if step == 86400:
        return "по дням"
    if step == 3600:
        return "по часам"
    return "по пять минут"


def _report_color(percent: float) -> str:
    """Цвет по доступности: тот же в плитках и в таблице."""
    if percent >= REPORT_GOOD:
        return "var(--ok)"
    if percent >= REPORT_FAIR:
        return "var(--warn)"
    return "var(--err)"


#: Дальше месяца отчёт не строят, а окно на годы упрётся в журнал событий
REPORT_MAX_DAYS = 366


def _report_window(hours: int, since: str, until: str) -> tuple[int, Any, str]:
    """
    Окно отчёта: либо готовый период, либо интервал дат из формы.

    Возвращает `(hours, until_dt, note)`: длину окна в часах, правую
    границу (None означает «до сейчас») и подпись периода для шапки.

    Даты приходят из полей `<input type="date">`, то есть в местном
    времени человека, а внутри всё считается в UTC. Границы берём по
    местной полуночи: «отчёт с 1 по 7» для человека начинается в его
    полночь первого и заканчивается в его полночь восьмого, иначе
    последний день отчёта окажется обрезанным.
    """
    def parse(value: str):
        try:
            day = datetime.strptime(str(value or "").strip(), "%Y-%m-%d")
        except ValueError:
            return None
        return day.astimezone()

    start, end = parse(since), parse(until)
    if start and end:
        if end < start:
            start, end = end, start
        # Правая граница это конец указанного дня, а не его начало
        end = end + timedelta(days=1)
        end = min(end, datetime.now().astimezone())
        span = end - start
        days = max(1, min(REPORT_MAX_DAYS, span.days + (1 if span.seconds else 0)))
        return int(days * 24), end.astimezone(timezone.utc), "интервал дат"

    hours = hours if hours in (1, 24, 168, 720) else 720
    return hours, None, {1: "час", 24: "сутки", 168: "неделю", 720: "месяц"}[hours]


#: Ступеньки нижней границы шкалы на графике доступности.
#: Только круглые числа: «шкала с 79,5 процентов» выглядит как опечатка.
#: И только две: обрезка ниже девяноста девяти обманывает сильнее, чем
#: помогает. При шкале от 95 столбик в 97,6% рисуется вполовину высоты,
#: и день, когда парк почти не падал, выглядит как день, когда полпарка
#: лежало. Разница в два процента должна и выглядеть как два процента.
FLOOR_LADDER = (99.5, 99.0)


def _report_floor(percents: list[float]) -> float:
    """
    С какого значения начинать шкалу столбиков.

    Обрезанная шкала нужна ровно в одном случае: когда всё окно между
    девяноста девятью и сотней процентов и разница в доли процента иначе
    не видна вовсе. Во всех остальных она врёт глазу, причём в обе
    стороны. Один день на 79,7% опускал границу до 79,5, и его столбик
    ложился на саму ось: «площадка не работала вовсе», хотя она работала
    четыре пятых суток. А при границе в 95 обычный час с одной упавшей
    точкой из полусотни рисовался вполовину высоты.

    Поэтому ступенек всего две, 99 и 99,5, а во всех остальных случаях
    шкала обычная, от нуля до ста: два процента должны и выглядеть как
    два процента.
    """
    low = min(percents) if percents else 100.0
    for step in FLOOR_LADDER:
        # Запас нужен, чтобы худший столбик не сливался с осью
        if low >= step + 0.05:
            return step
    return 0.0


def _by_operator(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Итоги отчёта в разрезе оператора связи.

    Вопрос «какая точка хуже всех» таблица отвечает и без этого, а вопрос
    «какой провайдер хуже всех» из полусотни строк глазами не решается.

    Всё, кроме числа точек, приведено к одной точке. Сумма здесь не просто
    хуже, она врёт дважды. Растёт вместе с числом точек: у оператора
    с четырнадцатью площадками простой больше, чем у оператора с двумя,
    даже когда у первого всё лучше. И выглядит невозможной: в отчёте
    за сутки сумма по четырнадцати точкам показывала «1 дн 20 ч», и первая
    мысль у человека была не «это сумма», а «панель сломалась». То же
    решение и по той же причине уже принято в шапке отчёта.

    Точки, за которыми ещё не наблюдали, в среднее не идут: у них честно
    нет процента, и они утянули бы оператора вниз без всякой его вины.
    Точки без известного оператора собираются в отдельную строку: их
    не выкинуть молча, иначе итог не сойдётся с таблицей.
    """
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        groups.setdefault(str(row.get("operator") or ""), []).append(row)

    result: list[dict[str, Any]] = []
    for name, items in groups.items():
        seen = [r for r in items if r["covered"]]
        percent = (round(sum(r["uptime_percent"] for r in seen) / len(seen), 2)
                   if seen else 100.0)
        result.append({
            "operator": name,
            "devices": len(items),
            "watched": len(seen),
            "uptime_percent": percent,
            "color": _report_color(percent),
            "down_seconds": round(sum(r["down_seconds"] for r in items) / len(items)),
            "outages": round(sum(r["outages"] for r in items) / len(items), 1),
            "offline_now": sum(1 for r in items if r["status"] == "offline"),
        })

    # Худший оператор первым: отчёт открывают, чтобы найти виноватого,
    # а не чтобы прочитать список по алфавиту. Безымянные всегда внизу
    result.sort(key=lambda r: (not r["operator"], r["uptime_percent"],
                               -r["outages"], r["operator"].lower()))
    return result


def _report_scope(user, group_id: int, devices):
    """
    Область отчёта: право видеть плюс выбор человека.

    Возвращает `(scope, label, ids)`: кусок WHERE для запросов монитора,
    подпись для шапки документа и разобранный список отмеченных точек.

    Условия складываются, а не заменяют друг друга: выбор сужает то, что
    человеку и так видно, и расширить область через параметр в адресе
    нельзя. Проверять отдельно ничего не нужно, это следует из «И».

    Точки сильнее группы: если отмечены и то и другое, человек явно
    показал пальцем на конкретные строки.
    """
    scope = permissions.scope_sql(user)
    where, params = scope[0], list(scope[1])

    # Точки приходят двумя способами: галочками в форме (повторяющийся
    # параметр) и одной строкой через запятую в ссылке на CSV. Разбираем оба
    raw = devices if isinstance(devices, (list, tuple)) else [devices]
    ids: list[int] = []
    for chunk in raw:
        for part in str(chunk or "").replace(" ", "").split(","):
            if part.isdigit() and int(part) not in ids:
                ids.append(int(part))
    if ids:
        where += " AND d.id IN (%s)" % ",".join("?" * len(ids))
        params += ids
    elif group_id:
        where += " AND d.group_id = ?"
        params.append(group_id)

    # Подпись собирается из того, что человеку и правда видно, а не из
    # того, что он написал в адресе. Иначе по чужому номеру группы можно
    # было бы прочитать её название, пусть отчёт и оказался бы пустым
    visible = query(
        f"SELECT d.id, d.name FROM devices d WHERE d.enabled = 1{where}"
        " ORDER BY d.name COLLATE NOCASE", tuple(params))

    if not visible:
        return (where, params), "нет доступных точек", ids

    if ids:
        listed = ", ".join(str(r["name"]) for r in visible[:3])
        extra = " и ещё %d" % (len(visible) - 3) if len(visible) > 3 else ""
        return (where, params), listed + extra, [int(r["id"]) for r in visible]

    if group_id:
        row = query_one("SELECT name FROM groups WHERE id = ?", (group_id,))
        # Подпись переводится по шаблону: имя группы подставляется, само
        # слово «группа» лежит в словаре
        return (where, params), "группа %s" % (row["name"] if row else group_id), []

    return (where, params), "весь парк", []


@router.get("/devices/{device_id}/report")
async def device_report_page(request: Request, device_id: int, hours: int = 720,
                             since: str = "", until: str = "",
                             user=Depends(current_user)):
    """
    Отчёт по одной площадке: тот же документ, но про неё одну.

    Отдельная страница, а не галочка в общем отчёте, потому что вопрос
    другой. В отчёте по парку точка это строка из полусотни, и спрашивают
    там «как парк». Здесь спрашивают «как работала эта площадка», и ответ
    нужен развёрнутый: все падения за период, а не первые двадцать по
    всему парку, и трафик, которого в общем отчёте нет вовсе.

    Просят такое обычно не технари, а арендатор канала или начальник,
    поэтому документ печатается и уходит вложением, как и парковый.
    """
    from .. import charts, i18n, monitor, traffic

    scope = permissions.scope_sql(user)
    device = query_one(
        "SELECT d.*, g.name AS group_name FROM devices d"
        " LEFT JOIN groups g ON g.id = d.group_id"
        f" WHERE d.id = ?{scope[0]}",
        (device_id, *scope[1]),
    )
    if device is None:
        # Не «нет доступа», а «нет такой»: чужая точка не должна
        # подтверждать своё существование даже кодом ответа
        return RedirectResponse("/devices", status_code=303)

    hours, edge, period_note = _report_window(hours, since, until)
    one: tuple[str, list] = (" AND d.id = ?", [device_id])

    rows = monitor.availability(hours, one, edge)
    row = rows[0] if rows else {"uptime_percent": 100.0, "down_seconds": 0,
                                "outages": 0, "status": device["status"],
                                "covered": 100, "watched_since": None}
    buckets = monitor.availability_buckets(hours, one, edge)
    intervals = monitor.outage_intervals(hours, one, edge)

    now = edge or datetime.now(timezone.utc)
    start = now - timedelta(hours=hours)

    def local(moment: datetime) -> str:
        return moment.astimezone().strftime("%d.%m.%Y %H:%M")

    outages = [{
        "start": local(item["start"]),
        "end": "" if item["ongoing"] else local(item["end"]),
        "seconds": item["seconds"],
        "ongoing": item["ongoing"],
        "trimmed": item["trimmed"],
    } for item in intervals]

    # Трафик за тот же период. В отчёте по парку его нет и быть не может:
    # складывать мегабайты полусотни площадок бессмысленно, а по одной
    # это первое, о чём спрашивает арендатор канала
    lang = resolve_lang(request, user)
    uplink = str(device["uplink_interface"] or "").strip() \
        if "uplink_interface" in device.keys() else ""
    window = max(1, hours * 3600)
    totals, covered = [], []
    seen = query(
        "SELECT DISTINCT interface FROM traffic_samples WHERE device_id = ?"
        " AND ts >= datetime('now', ?)",
        (device_id, f"-{hours} hours"),
    )
    for item in seen:
        name = str(item["interface"])
        amount = traffic.volume(device_id, name, hours)
        if not amount["covered"]:
            continue
        covered.append(min(100, int(round(100 * amount["covered"] / window))))
        totals.append({
            "name": name,
            "uplink": name == uplink,
            "rx": i18n.translate_text(traffic.human_volume(amount["rx"]), lang),
            "tx": i18n.translate_text(traffic.human_volume(amount["tx"]), lang),
            "all": i18n.translate_text(
                traffic.human_volume(amount["rx"] + amount["tx"]), lang),
        })
    totals.sort(key=lambda t: (not t["uplink"], t["name"]))

    floor = _report_floor([b["percent"] for b in buckets])

    log_audit(user["username"], "Открыт отчёт по точке",
              str(device["name"]), f"{hours} ч", client_ip(request))

    return render(
        "report_device.html",
        request,
        user,
        title=settings.report_title,
        device=device,
        hours=hours,
        row=row,
        color=_report_color(row["uptime_percent"]),
        # Какую долю периода панель эту площадку вообще видела. Меньше ста
        # значит, что её завели уже внутри периода, и об этом надо сказать
        covered=int(row.get("covered", 100)),
        watch_text=local(row["watched_since"]) if row.get("watched_since") else "",
        longest=max((item["seconds"] for item in intervals), default=0),
        outages=outages,
        totals=totals,
        # Худшее покрытие из интерфейсов: если хоть по одному данных мало,
        # предупредить надо про всю таблицу
        partial=min(covered) if covered and min(covered) < 90 else 0,
        chart=charts.bar_chart(
            [(b["label"], b["percent"]) for b in buckets],
            unit="%", y_min=floor, y_max=100.0, color_of=_chart_color,
            width=880, height=210),
        chart_floor=floor,
        chart_floor_text=f"{floor:g}",
        chart_step=_chart_step_note(hours),
        period_note=period_note,
        today=datetime.now().astimezone().strftime("%Y-%m-%d"),
        since_param=since,
        until_param=until,
        since_text=local(start),
        until_text=local(now),
        made_at=local(now),
        author=user["username"],
    )


@router.get("/monitoring/report")
async def availability_report_page(request: Request, hours: int = 720,
                                   group_id: int = 0,
                                   devices: list[str] = Query(default=[]),
                                   since: str = "", until: str = "",
                                   user=Depends(current_user)):
    """
    Тот же отчёт, но в виде готового к печати документа.

    Зачем отдельная страница, а не только CSV: таблицу из сорока девяти
    строк несут руководству, и открывать её при этом в Excel неудобно всем.
    Страница печатается в PDF браузером, без единой новой зависимости.

    Своя разметка, а не общий макет панели: в документе не нужны меню,
    кнопки и тёмная тема, зато нужны поля страницы и переносы между
    разделами при печати.
    """
    from .. import charts, monitor

    hours, edge, period_note = _report_window(hours, since, until)
    scope, subject, chosen = _report_scope(user, group_id, devices)

    rows = monitor.availability(hours, scope, edge)
    rows.sort(key=lambda r: (r["uptime_percent"], -r["outages"], r["name"].lower()))
    for row in rows:
        row["color"] = _report_color(row["uptime_percent"])

    buckets = monitor.availability_buckets(hours, scope, edge)
    intervals = monitor.outage_intervals(hours, scope, edge)

    now = edge or datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    def local(moment: datetime) -> str:
        return moment.astimezone().strftime("%d.%m.%Y %H:%M")

    # Точка, заведённая внутри периода, наблюдалась не весь его. Её процент
    # честен только на своём куске, и в таблице это надо пометить, иначе
    # вчерашняя точка выглядит лучше всех остальных
    for row in rows:
        row["watch_text"] = local(row["watched_since"]) if row.get("watched_since") else ""
    # Средние и «без единого падения» считаем по тем, кого вообще видели
    seen = [r for r in rows if r["covered"]]

    outages = [{
        "name": row["name"],
        "group_name": row["group_name"],
        "host": row["host"],
        "start": local(row["start"]),
        "end": "" if row["ongoing"] else local(row["end"]),
        "seconds": row["seconds"],
        "ongoing": row["ongoing"],
        "trimmed": row["trimmed"],
    } for row in intervals[:REPORT_OUTAGE_LIMIT]]

    floor = _report_floor([b["percent"] for b in buckets])

    down_total = sum(r["down_seconds"] for r in rows)
    # Средний простой на точку, а не сумма по парку. Сумма растёт вместе
    # с числом точек и сравнивать по ней два отчёта нельзя: пятьдесят
    # часов на десяти точках и на пятидесяти это разные вещи. Среднее
    # сравнимо и с прошлым месяцем, и с соседней группой
    down_average = round(down_total / len(rows)) if rows else 0
    average = round(sum(r["uptime_percent"] for r in seen) / len(seen), 2) if seen else 100.0

    log_audit(user["username"], "Открыт отчёт по доступности",
              f"{hours} ч · {subject}", f"точек: {len(rows)}", client_ip(request))


    return render(
        "report.html",
        request,
        user,
        title=settings.report_title,
        hours=hours,
        rows=rows,
        outages=outages,
        outages_total=len(intervals),
        outages_limit=REPORT_OUTAGE_LIMIT,
        average=average,
        average_color=_report_color(average),
        down_total=down_total,
        down_average=down_average,
        outage_count=sum(r["outages"] for r in rows),
        offline_now=sum(1 for r in rows if r["status"] == "offline"),
        perfect=sum(1 for r in seen if r["uptime_percent"] >= 100 and not r["outages"]),
        worst=[r for r in seen if r["uptime_percent"] < 100 or r["outages"]][:7],
        operators=_by_operator(rows),
        chart=charts.bar_chart(
            [(b["label"], b["percent"]) for b in buckets],
            unit="%", y_min=floor, y_max=100.0, color_of=_chart_color,
            width=880, height=210),
        chart_floor=floor,
        chart_floor_text=f"{floor:g}",
        chart_step=_chart_step_note(hours),
        period_note=period_note,
        today=datetime.now().astimezone().strftime("%Y-%m-%d"),
        since_param=since,
        until_param=until,
        since_text=local(since),
        until_text=local(now),
        made_at=local(now),
        author=user["username"],
        subject=subject,
        group_id=group_id,
        chosen=chosen,
        devices_param=",".join(str(i) for i in chosen),
        all_groups=query("SELECT id, name FROM groups ORDER BY name COLLATE NOCASE"),
        all_devices=query(
            "SELECT d.id, d.name, g.name AS group_name FROM devices d "
            "LEFT JOIN groups g ON g.id = d.group_id "
            f"WHERE d.enabled = 1{permissions.scope_sql(user)[0]} "
            "ORDER BY d.name COLLATE NOCASE",
            tuple(permissions.scope_sql(user)[1])),
    )


@router.get("/monitoring/report.csv")
async def availability_report(request: Request, hours: int = 720,
                              group_id: int = 0,
                              devices: list[str] = Query(default=[]),
                              since: str = "", until: str = "",
                              user=Depends(current_user)):
    """
    Отчёт по доступности за период в виде CSV.

    Нужен для разговора с провайдером: «за месяц точка лежала 14 часов,
    падений 23». На словах это спор, с таблицей это факт.

    CSV, а не xlsx, по двум причинам: не нужна лишняя зависимость, и файл
    открывается чем угодно. Разделитель точка с запятой, а в начале файла
    метка BOM: Excel в русской локали иначе показывает всё одной колонкой
    и портит кириллицу.
    """
    import csv
    import io

    from fastapi.responses import StreamingResponse

    from .. import monitor

    hours, edge, _note = _report_window(hours, since, until)
    scope, subject, _chosen = _report_scope(user, group_id, devices)
    rows = monitor.availability(hours, scope, edge)
    rows.sort(key=lambda r: (r["uptime_percent"], r["name"].lower()))

    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow([
        "Точка", "Группа", "Адрес", "Состояние сейчас",
        "Доступность, %", "Простой, часов", "Простой, минут", "Падений",
        # Колонки про наблюдение приписаны в конец, чтобы не сломать
        # чужие сводные таблицы, собранные по прежним выгрузкам.
        # Оператор по той же причине здесь, а не рядом с группой
        "Наблюдение с", "Покрыто периода, %", "Оператор",
    ])
    for row in rows:
        minutes = round(row["down_seconds"] / 60)
        watched = row.get("watched_since")
        writer.writerow([
            row["name"],
            row["group_name"] or "",
            row["host"],
            {"online": "в сети", "offline": "не отвечает"}.get(row["status"], "неизвестно"),
            # Запятая как разделитель дробной части: с точкой Excel в русской
            # локали считает это текстом, и по колонке нельзя ни отсортировать,
            # ни посчитать среднее
            # Точку, заведённую после конца периода, оставляем пустой:
            # ноль наблюдения это не сто процентов доступности
            str(row["uptime_percent"]).replace(".", ",") if row["covered"] else "",
            str(round(row["down_seconds"] / 3600, 2)).replace(".", ","),
            minutes,
            row["outages"],
            watched.astimezone().strftime("%d.%m.%Y %H:%M") if watched else "",
            row["covered"],
            row.get("operator") or "",
        ])

    log_audit(user["username"], "Выгружен отчёт по доступности",
              f"{hours} ч · {subject}", f"точек: {len(rows)}", client_ip(request))

    # Имя файла латиницей: кириллица в заголовке Content-Disposition
    # доезжает по-разному, а файл потом лежит у человека в почте
    part = "group%d" % group_id if group_id else ("selected" if _chosen else "all")
    when = (since + "_" + until) if (since and until) else "%dh" % hours
    name = "tikpilot-availability-%s-%s-%s.csv" % (part, when, utcnow()[:10])
    return StreamingResponse(
        iter(["﻿" + buffer.getvalue()]),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.get("/monitoring")
async def monitoring(request: Request, hours: int = 24, user=Depends(current_user)):
    """
    Отдельная страница мониторинга: карта статусов и доступность за период.

    :param hours: окно расчёта доступности — 24 часа или 168 (неделя).
    """
    scope = permissions.scope_sql(user)
    from .. import monitor
    from . import alerts as alerts_page

    hours = hours if hours in (1, 24, 168, 720) else 24
    rows = monitor.availability(hours, scope)

    # Сначала самые проблемные — ради них страницу и открывают
    rows.sort(key=lambda r: (r["uptime_percent"], -r["outages"], r["name"].lower()))

    # В таблицу попадают все, у кого были сбои, плюс те, кто лежит прямо сейчас:
    # точка, упавшая минуту назад, по процентам ещё выглядит идеальной.
    troubled = [
        r for r in rows
        if r["uptime_percent"] < 100 or r["outages"] or r["status"] != "online"
    ]
    perfect = len(rows) - len(troubled)
    average = round(sum(r["uptime_percent"] for r in rows) / len(rows), 2) if rows else 100.0

    return render(
        "monitoring.html",
        request,
        user,
        active="monitoring",
        summary=monitor.summary(scope),
        groups=monitor.status_map(scope),
        rows=rows,
        troubled=troubled,
        perfect=perfect,
        average=average,
        events=monitor.recent_events(25, scope),
        latency=monitor.latency_summary(hours, scope),
        flapping=monitor.flapping_devices(scope=scope),
        monitor_state=monitor.state,
        hours=hours,
        # Пороги показываем здесь же: вопрос «что сейчас плохо» один,
        # и ответ на него не должен лежать на двух страницах
        **(alerts_page.live_context(resolve_lang(request, user))
           if permissions.has(user, "alerts.view")
           else {"firing": [], "pending": [], "alert_events": []}),
    )


@router.get("/monitoring/map")
async def monitoring_map(request: Request, user=Depends(current_user)):
    """HTML-фрагмент карты статусов — обновляется на лету."""
    scope = permissions.scope_sql(user)
    from .. import monitor

    return render_partial("partials/status_map.html", request, user, groups=monitor.status_map(scope))


@router.get("/dashboard/events")
async def dashboard_events(request: Request, user=Depends(current_user)):
    """HTML-фрагмент ленты событий — подгружается дашбордом на лету."""
    scope = permissions.scope_sql(user)
    from .. import monitor

    return render_partial(
        "partials/status_events.html", request, user, events=monitor.recent_events(15, scope)
    )


@router.get("/api/stats")
async def stats_json(user=Depends(current_user)):
    """Сводка в JSON — используется для автообновления плиток дашборда."""
    row = query_one(
        "SELECT COUNT(*) AS total, "
        "SUM(CASE WHEN status='online' THEN 1 ELSE 0 END) AS online, "
        "SUM(CASE WHEN status='offline' THEN 1 ELSE 0 END) AS offline, "
        "SUM(CASE WHEN status='unknown' THEN 1 ELSE 0 END) AS unknown "
        f"FROM devices d WHERE 1=1{permissions.scope_sql(user)[0]}",
        tuple(permissions.scope_sql(user)[1]),
    )
    return dict(row) if row else {}


@router.get("/history")
async def history(request: Request, q: str = "", page: int = 1,
                  user=Depends(require("history.view"))):
    """
    Журнал действий администраторов.

    Листается постранично: журнал растёт непрерывно, и показывать его
    целиком значит однажды подвесить браузер на своей же истории.
    """
    condition = "1=1"
    params: tuple = ()
    if q:
        condition = "(username LIKE ? OR action LIKE ? OR target LIKE ?)"
        like = f"%{q}%"
        params = (like, like, like)

    found = query_one(f"SELECT COUNT(*) AS c FROM audit_log WHERE {condition}", params)
    pages = pager(request, found["c"] if found else 0, page)
    rows = query(
        f"SELECT * FROM audit_log WHERE {condition} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + (pages["per_page"], pages["offset"]),
    )
    return render("history.html", request, user, active="history",
                  entries=rows, f_q=q, pager=pages)
