"""Дашборд и журнал действий."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request

from ..auth import client_ip, current_user, require
from ..config import settings
from ..database import log_audit, query, query_one, utcnow
from .. import permissions
from .deps import pager, render, render_partial

router = APIRouter()


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
    offline = query(
        "SELECT d.id, d.name, d.host, d.last_error, d.last_check FROM devices d "
        f"WHERE d.status='offline'{scope[0]} ORDER BY d.name COLLATE NOCASE LIMIT 15",
        tuple(scope[1]),
    )
    versions = query(
        "SELECT d.ros_version, COUNT(*) AS c FROM devices d WHERE d.ros_version <> '' "
        f"{scope[0]} GROUP BY d.ros_version ORDER BY c DESC LIMIT 8",
        tuple(scope[1]),
    )

    # Устройства, где найденная версия отличается от установленной
    from .devices import _fetch_devices

    pending = [d for d in _fetch_devices(user=user) if d["update_available"]]

    from .. import monitor, rollback
    from ..actions import list_actions

    # Взведённые страховки видны на первой странице, пока их не сняли:
    # забыть про них нельзя, точка сама откатится и перезагрузится
    rollback.sweep()

    return render(
        "dashboard.html",
        request,
        user,
        active="dashboard",
        armed_rollbacks=rollback.armed(scope),
        stats=stats,
        groups=groups,
        recent_jobs=recent_jobs,
        offline=offline,
        versions=versions,
        pending_updates=pending,
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


def _report_color(percent: float) -> str:
    """Цвет по доступности: тот же на графике, в плитках и в таблице."""
    if percent >= REPORT_GOOD:
        return "var(--ok)"
    if percent >= REPORT_FAIR:
        return "var(--warn)"
    return "var(--err)"


@router.get("/monitoring/report")
async def availability_report_page(request: Request, hours: int = 720,
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

    hours = hours if hours in (1, 24, 168, 720) else 720
    scope = permissions.scope_sql(user)

    rows = monitor.availability(hours, scope)
    rows.sort(key=lambda r: (r["uptime_percent"], -r["outages"], r["name"].lower()))
    for row in rows:
        row["color"] = _report_color(row["uptime_percent"])

    buckets = monitor.availability_buckets(hours, scope)
    intervals = monitor.outage_intervals(hours, scope)

    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=hours)

    def local(moment: datetime) -> str:
        return moment.astimezone().strftime("%d.%m.%Y %H:%M")

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

    # Нижняя граница шкалы графика: при жёстких ста процентах все столбики
    # выглядят одинаково, и провал в полпроцента на глаз не виден
    percents = [b["percent"] for b in buckets] or [100.0]
    floor = min(99.0, round(min(percents) - 0.2, 1))

    down_total = sum(r["down_seconds"] for r in rows)
    average = round(sum(r["uptime_percent"] for r in rows) / len(rows), 2) if rows else 100.0

    log_audit(user["username"], "Открыт отчёт по доступности",
              f"{hours} ч", f"точек: {len(rows)}", client_ip(request))

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
        outage_count=sum(r["outages"] for r in rows),
        offline_now=sum(1 for r in rows if r["status"] == "offline"),
        perfect=sum(1 for r in rows if r["uptime_percent"] >= 100 and not r["outages"]),
        worst=[r for r in rows if r["uptime_percent"] < 100 or r["outages"]][:7],
        chart=charts.bar_chart(
            [(b["label"], b["percent"]) for b in buckets],
            unit="%", y_min=floor, y_max=100.0, color_of=_report_color,
            width=880, height=210),
        chart_floor=floor,
        chart_step="по часам" if hours <= 24 else "по дням",
        since_text=local(since),
        until_text=local(now),
        made_at=local(now),
        author=user["username"],
    )


@router.get("/monitoring/report.csv")
async def availability_report(request: Request, hours: int = 720,
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

    hours = hours if hours in (1, 24, 168, 720) else 720
    rows = monitor.availability(hours, permissions.scope_sql(user))
    rows.sort(key=lambda r: (r["uptime_percent"], r["name"].lower()))

    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";")
    writer.writerow([
        "Точка", "Группа", "Адрес", "Состояние сейчас",
        "Доступность, %", "Простой, часов", "Простой, минут", "Падений",
    ])
    for row in rows:
        minutes = round(row["down_seconds"] / 60)
        writer.writerow([
            row["name"],
            row["group_name"] or "",
            row["host"],
            {"online": "в сети", "offline": "не отвечает"}.get(row["status"], "неизвестно"),
            # Запятая как разделитель дробной части: с точкой Excel в русской
            # локали считает это текстом, и по колонке нельзя ни отсортировать,
            # ни посчитать среднее
            str(row["uptime_percent"]).replace(".", ","),
            str(round(row["down_seconds"] / 3600, 2)).replace(".", ","),
            minutes,
            row["outages"],
        ])

    log_audit(user["username"], "Выгружен отчёт по доступности",
              f"{hours} ч", f"точек: {len(rows)}", client_ip(request))

    name = "tikpilot-availability-%dh-%s.csv" % (hours, utcnow()[:10])
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
