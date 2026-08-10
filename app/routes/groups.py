"""Раздел «Группы»: справочник групп и массовые операции по группе."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from .. import permissions
from ..auth import client_ip, current_user, require
from ..database import execute, log_audit, query, query_one, utcnow
from .deps import render

router = APIRouter()

# Доступные цвета меток групп (используются в интерфейсе)
COLORS = ["slate", "blue", "green", "amber", "red", "violet", "cyan", "pink"]


@router.get("/groups")
async def groups_page(request: Request, user=Depends(current_user)):
    """Список групп со статистикой по устройствам."""
    rows = query(
        """
        SELECT g.*,
               COUNT(d.id)                                          AS total,
               SUM(CASE WHEN d.status='online'  THEN 1 ELSE 0 END)  AS online,
               SUM(CASE WHEN d.status='offline' THEN 1 ELSE 0 END)  AS offline
        FROM groups g
        LEFT JOIN devices d ON d.group_id = g.id
        GROUP BY g.id
        ORDER BY g.name COLLATE NOCASE
        """
    )
    # Обращения к публичным ссылкам: за сутки, за неделю и всего
    visits = {
        r["group_id"]: r
        for r in query(
            "SELECT group_id, "
            "  SUM(CASE WHEN day >= date('now','-1 day') THEN hits ELSE 0 END) AS day, "
            "  SUM(CASE WHEN day >= date('now','-7 day') THEN hits ELSE 0 END) AS week, "
            "  SUM(hits) AS total "
            "FROM public_visits GROUP BY group_id"
        )
    }

    # Кто держит публичную страницу открытой прямо сейчас: строка про то,
    # что ссылка живёт своей жизнью, нужна там же, где её создают
    from .. import publicviews

    ungrouped = query_one("SELECT COUNT(*) AS c FROM devices WHERE group_id IS NULL")
    from ..actions import list_actions

    return render(
        "groups.html",
        request,
        user,
        active="groups",
        groups=rows,
        ungrouped=ungrouped["c"] if ungrouped else 0,
        colors=COLORS,
        actions=list_actions(),
        visits=visits,
        watching=publicviews.watching_count(),
    )


@router.post("/api/groups")
async def create_group(request: Request, user=Depends(require("groups.manage"))):
    """Создать группу."""
    form = dict(await request.form())
    name = (form.get("name") or "").strip()
    if not name:
        return JSONResponse({"error": "Укажите название группы"}, status_code=400)
    try:
        group_id = execute(
            "INSERT INTO groups (name, comment, color, created_at) VALUES (?,?,?,?)",
            (name, (form.get("comment") or "").strip(), form.get("color") or "slate", utcnow()),
        )
    except Exception:  # noqa: BLE001 — единственная реальная причина: дубликат имени
        return JSONResponse({"error": "Группа с таким названием уже существует"}, status_code=400)
    log_audit(user["username"], "Создана группа", name, ip=client_ip(request))
    return {"ok": True, "id": group_id}


@router.post("/api/groups/{group_id}/update")
async def update_group(request: Request, group_id: int,
                       user=Depends(require("groups.manage"))):
    """Изменить название, комментарий или цвет группы."""
    form = dict(await request.form())
    name = (form.get("name") or "").strip()
    if not name:
        return JSONResponse({"error": "Укажите название группы"}, status_code=400)
    execute(
        "UPDATE groups SET name=?, comment=?, color=? WHERE id=?",
        (name, (form.get("comment") or "").strip(), form.get("color") or "slate", group_id),
    )
    log_audit(user["username"], "Изменена группа", name, ip=client_ip(request))
    return {"ok": True}


@router.post("/api/groups/{group_id}/delete")
async def delete_group(request: Request, group_id: int,
                       user=Depends(require("groups.manage"))):
    """Удалить группу. Устройства не удаляются — просто теряют группу."""
    row = query_one("SELECT name FROM groups WHERE id = ?", (group_id,))
    execute("DELETE FROM groups WHERE id = ?", (group_id,))
    log_audit(user["username"], "Удалена группа", row["name"] if row else str(group_id), ip=client_ip(request))
    return {"ok": True}


@router.post("/api/groups/{group_id}/public-link")
async def toggle_public_link(request: Request, group_id: int,
                             user=Depends(require("groups.manage"))):
    """
    Включить, обновить или отозвать публичную ссылку на состояние группы.

    Тело: {"enabled": true} — выдать новый токен, {"enabled": false} — отозвать.
    Повторное включение всегда создаёт новый токен: «обновить ссылку» и
    «отозвать старую» это одно и то же действие, и разделять их незачем.
    """
    from .public import new_token, public_url

    payload = await request.json()
    group = query_one("SELECT id, name FROM groups WHERE id = ?", (group_id,))
    if group is None:
        return JSONResponse({"error": "Группа не найдена"}, status_code=404)

    if payload.get("enabled"):
        token = new_token()
        execute("UPDATE groups SET public_token = ? WHERE id = ?", (token, group_id))
        log_audit(user["username"], "Выдана публичная ссылка", group["name"],
                  ip=client_ip(request))
        return {"ok": True, "url": public_url(request, token)}

    execute("UPDATE groups SET public_token = '' WHERE id = ?", (group_id,))
    log_audit(user["username"], "Отозвана публичная ссылка", group["name"],
              ip=client_ip(request))
    return {"ok": True, "url": ""}


@router.get("/api/groups/{group_id}/devices")
async def group_devices(group_id: int, user=Depends(current_user)):
    """Идентификаторы устройств группы — нужны для массовых действий."""
    rows = query("SELECT id FROM devices WHERE group_id = ? AND enabled = 1", (group_id,))
    return {"device_ids": [r["id"] for r in rows]}
