"""
Раздел «Бэкапы»: файлы копий, расписание их снятия и архив всей панели.

Три разные вещи в одном месте намеренно: человек, пришедший сюда за
бэкапом, должен видеть и то, что копии снимаются сами, и то, что саму
панель тоже стоит куда-то сохранить.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import FileResponse, JSONResponse

from .. import configdiff, panelbackup, permissions, schedules, worker
from ..auth import Forbidden, client_ip, current_user, require
from ..config import settings
from ..database import execute, log_audit, query, query_one, utcnow
from .deps import pager, render, resolve_lang

router = APIRouter()


@router.get("/backups")
async def backups_page(
    request: Request,
    q: str = "",
    device_id: str = "",
    kind: str = "",
    page: int = 1,
    user=Depends(require("backups.view")),
):
    """
    Список файлов резервных копий с поиском и фильтрами.

    Поиск идёт на сервере, а не по видимым строкам: копий со временем
    накапливаются тысячи, и фильтровать только показанные было бы нечестно.
    """
    where: list[str] = ["1=1"]
    params: list[Any] = []

    # Бэкап это копия конфигурации, поэтому чужие в списке видеть незачем.
    # Записи без device_id (устройство удалили) тоже прячем от урезанных
    # пользователей: понять, чьи они, уже нельзя.
    scope_where, scope_params = permissions.scope_sql(user)
    if scope_where:
        where.append(
            "b.device_id IN (SELECT d.id FROM devices d WHERE 1=1%s)" % scope_where
        )
        params += scope_params

    if q:
        where.append("(b.device_name LIKE ? OR b.filename LIKE ?)")
        like = f"%{q.strip()}%"
        params += [like, like]
    if device_id:
        where.append("b.device_id = ?")
        params.append(device_id)
    if kind in ("binary", "export"):
        where.append("b.kind = ?")
        params.append(kind)

    condition = " AND ".join(where)
    found = query_one(
        f"SELECT COUNT(*) AS c, COALESCE(SUM(b.size),0) AS s FROM backups b WHERE {condition}",
        params,
    )
    # Считаем сначала, показываем потом: номер страницы надо загнать
    # в границы до того, как из базы поедут строки
    pages = pager(request, found["c"] if found else 0, page)
    rows = query(
        f"SELECT b.* FROM backups b WHERE {condition} ORDER BY b.id DESC LIMIT ? OFFSET ?",
        params + [pages["per_page"], pages["offset"]],
    )
    total_where = "1=1"
    total_params: list[Any] = []
    if scope_where:
        total_where = "b.device_id IN (SELECT d.id FROM devices d WHERE 1=1%s)" % scope_where
        total_params = list(scope_params)
    total = query_one(
        f"SELECT COUNT(*) AS c, COALESCE(SUM(b.size),0) AS s FROM backups b WHERE {total_where}",
        total_params,
    )

    devices = query(
        "SELECT DISTINCT b.device_id AS id, b.device_name AS name FROM backups b "
        f"WHERE b.device_id IS NOT NULL AND {total_where} "
        "ORDER BY b.device_name COLLATE NOCASE",
        total_params,
    )

    return render(
        "backups.html",
        request,
        user,
        active="backups",
        backups=rows,
        pager=pages,
        devices=devices,
        found_count=found["c"] if found else 0,
        found_size=found["s"] if found else 0,
        total_count=total["c"] if total else 0,
        total_size=total["s"] if total else 0,
        filtered=bool(q or device_id or kind),
        f_q=q,
        f_device=device_id,
        f_kind=kind,
        rules=_rules(resolve_lang(request, user)),
        groups=query("SELECT id, name FROM groups ORDER BY name COLLATE NOCASE"),
        archives=panelbackup.listing() if permissions.has(user, "panel.backup") else [],
        weekdays=sorted(schedules.DAY_NAMES.items()),
    )


def _rules(lang: str = "ru") -> list[dict[str, Any]]:
    """
    Правила расписания с подписями для таблицы.

    Язык нужен здесь, а не в шаблоне: подпись собирается из нескольких
    дней («пн, ср, пт»), и целиком такой строки в словаре быть не может.
    Пока язык не передавали, на английской странице стояло «пн, ср, пт»
    посреди Mon-Tue-Wed в форме рядом.
    """
    rows = query(
        "SELECT s.*, g.name AS group_name FROM backup_schedules s "
        "LEFT JOIN groups g ON g.id = s.group_id ORDER BY s.at_time, s.id"
    )
    result = []
    for row in rows:
        item = dict(row)
        item["days_label"] = schedules.describe_days(schedules.parse_days(row["days"]), lang)
        item["target_label"] = (
            row["group_name"] or "группа удалена"
            if row["target"] == schedules.TARGET_GROUP
            else schedules.TARGET_LABELS.get(row["target"], row["target"])
        )
        result.append(item)
    return result


# ------------------------------------------------- сравнение конфигураций
@router.get("/backups/{backup_id}/diff")
async def diff_page(request: Request, backup_id: int, other: int = 0,
                    view: str = "", user=Depends(require("backups.download"))):
    """
    Что изменилось в конфигурации точки между двумя копиями.

    Право то же, что на скачивание: показать содержимое построчно и отдать
    файл целиком это одно и то же по последствиям, и разделять их значило
    бы обманывать себя.

    Второй копией по умолчанию берётся предыдущая для этого же устройства:
    в девяти случаях из десяти вопрос звучит как «что поменялось с прошлого
    раза».
    """
    row = query_one("SELECT * FROM backups WHERE id = ?", (backup_id,))
    if row is None:
        return JSONResponse({"error": "Файл не найден"}, status_code=404)
    if row["device_id"] and not permissions.can_touch(user, [row["device_id"]]):
        raise Forbidden()
    if row["kind"] != "export":
        return JSONResponse(
            {"error": "Сравнивать можно только текстовые export"}, status_code=400)

    history = query(
        "SELECT id, filename, created_at FROM backups "
        "WHERE device_id = ? AND kind = 'export' ORDER BY id DESC",
        (row["device_id"],),
    )

    previous = None
    if other:
        previous = query_one(
            "SELECT * FROM backups WHERE id = ? AND device_id = ? AND kind = 'export'",
            (other, row["device_id"]),
        )
    if previous is None:
        previous = query_one(
            "SELECT * FROM backups WHERE device_id = ? AND kind = 'export' AND id < ? "
            "ORDER BY id DESC LIMIT 1",
            (row["device_id"], backup_id),
        )

    old_lines = configdiff.read_lines(previous["filename"]) if previous else []
    new_lines = configdiff.read_lines(row["filename"])

    # Две колонки по умолчанию: так это показывают Winbox, GitHub и вообще
    # всё, чем человек пользовался раньше. Единый список остаётся под
    # ссылкой: на узком экране он читается лучше, и его удобно копировать
    side_by_side = view != "unified"
    result = (configdiff.compare_sides(old_lines, new_lines) if side_by_side
              else configdiff.compare(old_lines, new_lines))

    return render(
        "backup_diff.html",
        request,
        user,
        active="backups",
        current=row,
        previous=previous,
        history=history,
        result=result,
        side_by_side=side_by_side,
    )


# ---------------------------------------------------- поиск по содержимому
@router.get("/backups/search")
async def search_page(request: Request, q: str = "", device_id: str = "",
                      user=Depends(require("backups.download"))):
    """
    Поиск строки внутри текстовых экспортов.

    Ищем в последней копии каждого устройства, а не во всех подряд: вопрос
    почти всегда звучит как «где это есть сейчас», а полный перебор истории
    дал бы десять одинаковых ответов на каждую точку.
    """
    scope_where, scope_params = permissions.scope_sql(user)

    latest = query(
        "SELECT b.device_id, b.device_name, b.filename, b.created_at "
        "FROM backups b "
        "JOIN (SELECT device_id, MAX(id) AS top FROM backups "
        "      WHERE kind = 'export' GROUP BY device_id) last "
        "  ON last.top = b.id "
        f"WHERE b.device_id IN (SELECT d.id FROM devices d WHERE 1=1{scope_where})"
        + (" AND b.device_id = ?" if device_id.isdigit() else ""),
        tuple(scope_params) + ((int(device_id),) if device_id.isdigit() else ()),
    )

    found = configdiff.search(q, [dict(r) for r in latest]) if q else []

    return render(
        "backup_search.html",
        request,
        user,
        active="backups",
        q=q,
        found=found,
        scanned=len(latest),
        total_matches=sum(item["count"] for item in found),
        devices=query(
            "SELECT DISTINCT b.device_id AS id, b.device_name AS name FROM backups b "
            "WHERE b.device_id IS NOT NULL AND b.kind = 'export' "
            "ORDER BY b.device_name COLLATE NOCASE"
        ),
        f_device=device_id,
    )


# ------------------------------------------------------------- расписание
@router.post("/api/backup-schedules")
async def create_schedule(request: Request,
                          user=Depends(require("backups.schedule"))):
    """
    Создать правило расписания.

    Время следующего запуска считается сразу: правило, у которого его нет,
    молча ничего не делает, и понять это можно только через сутки.
    """
    payload = await request.json()

    target = str(payload.get("target") or schedules.TARGET_ALL)
    if target not in schedules.TARGET_LABELS:
        return JSONResponse({"error": "Неизвестный вид правила"}, status_code=400)
    if target == schedules.TARGET_PANEL and not permissions.has(user, "panel.backup"):
        raise Forbidden("Нет права на архив панели")

    at_time = str(payload.get("at_time") or "").strip()
    if schedules.parse_time(at_time) is None:
        return JSONResponse({"error": "Время укажите как 03:00"}, status_code=400)

    group_id = int(payload.get("group_id") or 0) or None
    if target == schedules.TARGET_GROUP and not group_id:
        return JSONResponse({"error": "Выберите группу"}, status_code=400)

    days = schedules.parse_days(payload.get("days"))
    keep = max(1, min(999, int(payload.get("keep") or 14)))

    execute(
        "INSERT INTO backup_schedules (name, target, group_id, at_time, days, keep, "
        "do_binary, do_export, enabled, next_run_at, created_at) "
        "VALUES (?,?,?,?,?,?,?,?,1,?,?)",
        (
            str(payload.get("name") or "").strip()[:100],
            target,
            group_id if target == schedules.TARGET_GROUP else None,
            at_time,
            schedules.dump_days(days),
            keep,
            1 if payload.get("do_binary", True) else 0,
            1 if payload.get("do_export", True) else 0,
            schedules.next_run(at_time, days),
            utcnow(),
        ),
    )
    log_audit(user["username"], "Создано правило бэкапов",
              schedules.TARGET_LABELS.get(target, target), at_time, client_ip(request))
    return {"ok": True}


@router.post("/api/backup-schedules/{rule_id}/toggle")
async def toggle_schedule(request: Request, rule_id: int,
                          user=Depends(require("backups.schedule"))):
    """Включить или выключить правило, не удаляя его."""
    row = query_one("SELECT * FROM backup_schedules WHERE id = ?", (rule_id,))
    if row is None:
        return JSONResponse({"error": "Правило не найдено"}, status_code=404)

    enabled = 0 if row["enabled"] else 1
    execute(
        "UPDATE backup_schedules SET enabled = ?, next_run_at = ? WHERE id = ?",
        (
            enabled,
            schedules.next_run(row["at_time"], schedules.parse_days(row["days"]))
            if enabled else None,
            rule_id,
        ),
    )
    log_audit(user["username"], "Правило бэкапов " + ("включено" if enabled else "выключено"),
              row["at_time"], ip=client_ip(request))
    return {"ok": True, "enabled": bool(enabled)}


@router.post("/api/backup-schedules/{rule_id}/run")
async def run_schedule_now(request: Request, rule_id: int,
                           user=Depends(require("backups.schedule"))):
    """
    Выполнить правило прямо сейчас.

    Нужно ровно для одного: проверить, что оно делает то, что задумано,
    не дожидаясь трёх часов ночи.
    """
    row = query_one("SELECT * FROM backup_schedules WHERE id = ?", (rule_id,))
    if row is None:
        return JSONResponse({"error": "Правило не найдено"}, status_code=404)
    if row["target"] == schedules.TARGET_PANEL and not permissions.has(user, "panel.backup"):
        raise Forbidden("Нет права на архив панели")

    worker._run_schedule(dict(row))
    log_audit(user["username"], "Правило бэкапов запущено вручную",
              row["at_time"], ip=client_ip(request))
    result = query_one("SELECT last_result FROM backup_schedules WHERE id = ?", (rule_id,))
    return {"ok": True, "result": result["last_result"] if result else ""}


@router.post("/api/backup-schedules/{rule_id}/delete")
async def delete_schedule(request: Request, rule_id: int,
                          user=Depends(require("backups.schedule"))):
    """Удалить правило. Снятые по нему копии остаются на месте."""
    execute("DELETE FROM backup_schedules WHERE id = ?", (rule_id,))
    log_audit(user["username"], "Удалено правило бэкапов", str(rule_id), ip=client_ip(request))
    return {"ok": True}


# ---------------------------------------------------------- архив панели
@router.post("/api/panel-backup")
async def create_panel_backup(request: Request,
                              user=Depends(require("panel.backup"))):
    """
    Собрать архив панели.

    В журнал пишется обязательно: в архиве ключ шифрования, а значит и
    пароли всех роутеров. Кто и когда его делал, должно быть видно.
    """
    payload = await request.json() if await request.body() else {}
    include = bool(payload.get("include_backups", True))

    path = panelbackup.build(include_device_backups=include)
    size = path.stat().st_size
    log_audit(user["username"], "Создан архив панели", path.name,
              "с бэкапами устройств" if include else "без бэкапов устройств",
              client_ip(request))
    return {"ok": True, "name": path.name, "size": size}


@router.get("/panel-backup/{name}")
async def download_panel_backup(request: Request, name: str,
                                user=Depends(require("panel.backup"))):
    """Отдать архив панели на скачивание."""
    path = panelbackup.resolve(name)
    if path is None:
        return JSONResponse({"error": "Архив не найден"}, status_code=404)

    log_audit(user["username"], "Скачан архив панели", name, ip=client_ip(request))
    return FileResponse(path, filename=name, media_type="application/gzip")


@router.post("/api/panel-backup/{name}/delete")
async def delete_panel_backup(request: Request, name: str,
                              user=Depends(require("panel.backup"))):
    """Удалить архив панели с диска."""
    path = panelbackup.resolve(name)
    if path is None:
        return JSONResponse({"error": "Архив не найден"}, status_code=404)

    path.unlink(missing_ok=True)
    log_audit(user["username"], "Удалён архив панели", name, ip=client_ip(request))
    return {"ok": True}


@router.get("/backups/{backup_id}/download")
async def download_backup(backup_id: int, user=Depends(require("backups.download"))):
    """Отдать файл бэкапа на скачивание."""
    row = query_one("SELECT * FROM backups WHERE id = ?", (backup_id,))
    if row is None:
        return JSONResponse({"error": "Файл не найден"}, status_code=404)

    if row["device_id"] and not permissions.can_touch(user, [row["device_id"]]):
        raise Forbidden()

    path = (settings.backup_dir / row["filename"]).resolve()
    # Защита от выхода за пределы каталога бэкапов
    if not str(path).startswith(str(settings.backup_dir.resolve())) or not path.exists():
        return JSONResponse({"error": "Файл отсутствует на диске"}, status_code=404)

    return FileResponse(path, filename=Path(row["filename"]).name, media_type="application/octet-stream")


@router.post("/api/backups/{backup_id}/delete")
async def delete_backup(request: Request, backup_id: int,
                        user=Depends(require("backups.delete"))):
    """Удалить файл бэкапа с сервера."""
    row = query_one("SELECT * FROM backups WHERE id = ?", (backup_id,))
    if row is None:
        return JSONResponse({"error": "Файл не найден"}, status_code=404)

    if row["device_id"] and not permissions.can_touch(user, [row["device_id"]]):
        raise Forbidden()

    path = (settings.backup_dir / row["filename"]).resolve()
    if str(path).startswith(str(settings.backup_dir.resolve())) and path.exists():
        path.unlink(missing_ok=True)
    execute("DELETE FROM backups WHERE id = ?", (backup_id,))
    log_audit(user["username"], "Удалён бэкап", row["filename"], ip=client_ip(request))
    return {"ok": True}
