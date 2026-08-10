"""Раздел «Скрипты»: библиотека команд и то, что раскатано по парку."""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import JSONResponse

from .. import permissions, snippets
from ..auth import Forbidden, client_ip, current_user
from ..database import log_audit, query
from .deps import render

router = APIRouter()


def _can_edit(user: dict) -> bool:
    """
    Кто правит библиотеку.

    Отдельного права нет намеренно: библиотека это заготовки консольных
    команд, и держать её вправе тот, кому и так разрешено эти команды
    выполнять. Лишний ключ в списке прав никто бы не понял.
    """
    return permissions.can_run(user, "cli") or permissions.can_run(user, "safe_change")


@router.get("/scripts")
async def scripts_page(request: Request, user=Depends(current_user)):
    """Библиотека и сводка по парку."""
    scope = permissions.scope_sql(user)
    return render(
        "snippets.html",
        request,
        user,
        active="scripts",
        snippets=snippets.listing(scope),
        fleet=snippets.fleet(scope),
        groups=query("SELECT id, name FROM groups ORDER BY name COLLATE NOCASE"),
        all_devices=query(
            "SELECT d.id, d.name, g.name AS group_name FROM devices d "
            "LEFT JOIN groups g ON g.id = d.group_id "
            f"WHERE d.enabled = 1{scope[0]} ORDER BY d.name COLLATE NOCASE",
            tuple(scope[1]),
        ),
        can_edit=_can_edit(user),
        can_remove=permissions.can_run(user, "remove_script"),
    )


@router.post("/api/snippets")
async def snippet_save(request: Request, payload: dict = Body(default={}),
                       user=Depends(current_user)):
    """Создать или обновить запись библиотеки."""
    if not _can_edit(user):
        raise Forbidden()

    try:
        snippet_id = snippets.save(
            name=str(payload.get("name") or ""),
            body=str(payload.get("body") or ""),
            note=str(payload.get("note") or ""),
            marker=str(payload.get("marker") or ""),
            username=user["username"],
            snippet_id=int(payload.get("id") or 0) or None,
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    log_audit(user["username"], "Сохранена команда в библиотеке",
              str(payload.get("name") or ""), "", client_ip(request))
    return {"ok": True, "id": snippet_id}


@router.post("/api/snippets/{snippet_id}/delete")
async def snippet_delete(request: Request, snippet_id: int,
                         user=Depends(current_user)):
    """Удалить запись библиотеки. На устройствах при этом ничего не меняется."""
    if not _can_edit(user):
        raise Forbidden()

    row = snippets.remove(snippet_id)
    if row is None:
        return JSONResponse({"error": "Запись не найдена"}, status_code=404)

    log_audit(user["username"], "Удалена команда из библиотеки",
              str(row["name"]), "", client_ip(request))
    return {"ok": True}
