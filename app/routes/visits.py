"""Заходы по публичным ссылкам: кто смотрит сейчас и кто смотрел раньше."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request

from .. import publicviews
from ..auth import require
from ..database import query, query_one
from .deps import PAGE_SIZE, pager, render, render_partial

router = APIRouter()


def _filters(q: str, group_id: str, kind: str) -> tuple[str, list[Any]]:
    """Условие WHERE и параметры по фильтрам страницы."""
    where = ["1=1"]
    params: list[Any] = []

    if kind == "fail":
        where.append("ok = 0")
    elif kind == "bot":
        where.append("bot = 1")
    else:
        # По умолчанию показываем людей: предпросмотр ссылки в мессенджере
        # приходит на каждую отправку и заслоняет собой всё остальное
        where.append("ok = 1 AND bot = 0")

    if group_id.isdigit():
        where.append("group_id = ?")
        params.append(int(group_id))

    if q:
        where.append("(ip LIKE ? OR device LIKE ? OR agent LIKE ? OR group_name LIKE ?)")
        params.extend([f"%{q}%"] * 4)

    return " AND ".join(where), params


@router.get("/logs/visits")
async def visits_page(request: Request, q: str = "", group_id: str = "",
                      kind: str = "", page: int = 1,
                      user=Depends(require("visits.view"))):
    """
    Журнал заходов.

    Область видимости здесь намеренно не применяется. Публичная ссылка
    привязана к группе, и управляет ей тот, у кого есть право на группы;
    само право `visits.view` в набор по умолчанию не входит. Резать журнал
    по областям значило бы показывать половину картины там, где важна
    именно полная: ссылка ушла куда-то целиком, а не по частям.
    """
    q = q.strip()
    where, params = _filters(q, group_id, kind)

    total = query_one(f"SELECT COUNT(*) AS c FROM public_views WHERE {where}", tuple(params))
    page_info = pager(request, total["c"] if total else 0, page, PAGE_SIZE)

    rows = query(
        f"SELECT * FROM public_views WHERE {where} ORDER BY last_at DESC LIMIT ? OFFSET ?",
        (*params, page_info["per_page"], page_info["offset"]),
    )

    summary = query_one(
        "SELECT COUNT(*) AS sessions, COUNT(DISTINCT ip) AS addresses "
        "FROM public_views WHERE ok = 1 AND bot = 0 "
        "AND last_at > datetime('now','-7 day')"
    )
    fails = query_one(
        "SELECT COUNT(*) AS c FROM public_views WHERE ok = 0 "
        "AND last_at > datetime('now','-7 day')"
    )

    return render(
        "visits.html",
        request,
        user,
        active="visits",
        rows=rows,
        pager=page_info,
        watching=publicviews.watching(int(group_id) if group_id.isdigit() else None),
        groups=query("SELECT id, name FROM groups WHERE public_token <> '' "
                     "ORDER BY name COLLATE NOCASE"),
        week_sessions=summary["sessions"] if summary else 0,
        week_addresses=summary["addresses"] if summary else 0,
        week_fails=fails["c"] if fails else 0,
        online_seconds=publicviews.ONLINE_SECONDS,
        retention_days=_retention(),
        f_q=q,
        f_group=group_id,
        f_kind=kind,
    )


@router.get("/logs/visits/live")
async def visits_live(request: Request, group_id: str = "",
                      user=Depends(require("visits.view"))):
    """Блок «смотрят сейчас», обновляется страницей на лету."""
    return render_partial(
        "partials/watching.html", request, user,
        watching=publicviews.watching(int(group_id) if group_id.isdigit() else None),
        online_seconds=publicviews.ONLINE_SECONDS,
    )


def _retention() -> int:
    from ..config import settings

    return settings.public_view_retention_days
