"""Журнал устройств: страница, живая лента и правила подсветки."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, Request
from fastapi.responses import JSONResponse, StreamingResponse

from .. import permissions, syslog
from ..config import settings
from ..auth import client_ip, require
from ..database import execute, execute_changes, log_audit, query, query_one, utcnow
from .deps import render

router = APIRouter()

#: Сколько строк показывать сразу. Столько же подгружается при прокрутке
#: вверх: экран вмещает десятки, а не сотни, и тянуть больше незачем.
PAGE_LINES = 300

#: Цвета, которые можно назначить правилу. Список закрытый: свободное поле
#: для цвета означает подсветку белым по белому уже к третьему правилу.
COLORS = {
    "err": "красный",
    "warn": "жёлтый",
    "ok": "зелёный",
    "info": "синий",
    "muted": "серый",
}


def _filters(user: Any, q: str, device_id: str, severity: str,
             topics: str) -> tuple[str, list[Any]]:
    """
    Условие выборки, общее для страницы, ленты и выгрузки.

    Собрано в одном месте не для красоты: живая лента должна показывать
    ровно то же, что и таблица, иначе фильтр «только ошибки» отсекал бы
    старые строки и пропускал новые.
    """
    where = ["1=1"]
    params: list[Any] = []

    scope_where, scope_params = permissions.scope_sql(user)
    if scope_where:
        # Строки без устройства (пришли из разрешённой сети, но точка
        # в панели не заведена) урезанному пользователю не показываем:
        # понять, чьи они, он всё равно не сможет
        where.append("s.device_id IN (SELECT d.id FROM devices d WHERE 1=1%s)" % scope_where)
        params += list(scope_params)

    if q:
        where.append("(s.message LIKE ? OR s.topics LIKE ? OR s.device_name LIKE ?)")
        like = f"%{q.strip()}%"
        params += [like, like, like]
    if device_id.isdigit():
        where.append("s.device_id = ?")
        params.append(int(device_id))
    if severity in syslog.SEVERITIES:
        # Выбирается порог, а не точное совпадение: «предупреждения» без
        # ошибок это не то, что человек имеет в виду, выбирая уровень
        where.append("s.severity <= ?")
        params.append(syslog.SEVERITIES.index(severity))
    if topics:
        where.append("s.topics LIKE ?")
        params.append(f"%{topics.strip()}%")

    return " AND ".join(where), params


@router.get("/syslog")
async def syslog_page(
    request: Request,
    q: str = "",
    device_id: str = "",
    severity: str = "",
    topics: str = "",
    hidden: str = "",
    user=Depends(require("syslog.view")),
):
    """
    Журнал, присланный роутерами: фильтры, подсветка, живая лента.

    Страниц здесь нет намеренно, хотя на бэкапах и в истории они есть.
    Там данные стоят на месте, а тут поток: пока человек читает вторую
    страницу, сверху добавляются новые строки, всё съезжает, и одну и ту же
    запись можно увидеть дважды или не увидеть вовсе. Плюс за сутки этих
    страниц набирается больше тысячи, и листать их всё равно никто не станет.

    Поэтому лента с прокруткой, как в консоли панели: свежие внизу, старые
    подгружаются, когда доехали до верха.
    """
    condition, params = _filters(user, q, device_id, severity, topics)

    found = query_one(f"SELECT COUNT(*) AS c FROM syslog s WHERE {condition}", params)
    total = found["c"] if found else 0

    ruleset = syslog.rules()
    show_hidden = hidden == "1"
    hiding = any(r["enabled"] and r["action"] == "hide" for r in ruleset)

    # Строки, спрятанные правилом, выбрасываются уже после выборки: образец
    # может быть регулярным выражением, а SQLite такого не умеет. Поэтому
    # при включённых правилах берём запас, иначе на экране осталось бы
    # полторы строки из трёхсот.
    limit = PAGE_LINES * 4 if hiding and not show_hidden else PAGE_LINES

    # Берём последние строки, а показываем их в прямом порядке: свежие внизу,
    # как в любом журнале, который читают глазами
    rows = query(
        f"SELECT s.* FROM syslog s WHERE {condition} ORDER BY s.id DESC LIMIT ?",
        params + [limit],
    )

    entries = []
    skipped = 0
    for row in reversed(rows):
        item = dict(row)
        rule = syslog.match_rule(f"{item['message']} {item['topics']}", ruleset)
        action = str(rule.get("action") or "color") if rule else "color"
        if action == "hide" and not show_hidden:
            skipped += 1
            continue
        item["color"] = str(rule.get("color") or "") if rule and action == "color" else ""
        item["hidden"] = action == "hide"
        item["level"] = syslog.line_level(item["severity_name"])
        entries.append(item)
    entries = entries[-PAGE_LINES:]

    scope_where, scope_params = permissions.scope_sql(user)
    devices = query(
        "SELECT d.id, d.name FROM devices d WHERE 1=1%s ORDER BY d.name COLLATE NOCASE"
        % scope_where,
        tuple(scope_params),
    )

    return render(
        "syslog.html",
        request,
        user,
        active="syslog",
        entries=entries,
        total=total,
        page_lines=PAGE_LINES,
        devices=devices,
        rules=ruleset,
        colors=COLORS,
        severities=syslog.SEVERITIES,
        severity_labels=syslog.SEVERITY_LABELS,
        state=syslog.state,
        sources=syslog.sources(),
        retention_days=settings.syslog_retention_days,
        actions=syslog.ACTIONS,
        hiding=hiding,
        show_hidden=show_hidden,
        skipped=skipped,
        f_q=q,
        f_device=device_id,
        f_severity=severity,
        f_topics=topics,
        f_hidden="1" if show_hidden else "",
    )


@router.get("/api/syslog")
async def syslog_feed(
    after: int = 0,
    before: int = 0,
    q: str = "",
    device_id: str = "",
    severity: str = "",
    topics: str = "",
    hidden: str = "",
    limit: int = 200,
    user=Depends(require("syslog.view")),
):
    """
    Строки, которых на странице ещё нет.

    `after` это новые, для живой ленты. `before` это старые, их подгружают
    при прокрутке к верху. И те, и другие отдаются по возрастанию номера,
    чтобы страница просто вставляла их с нужного края, не переставляя
    уже показанное.
    """
    condition, params = _filters(user, q, device_id, severity, topics)
    limit = max(1, min(limit, 1000))

    if before:
        rows = query(
            f"SELECT s.* FROM syslog s WHERE {condition} AND s.id < ? "
            "ORDER BY s.id DESC LIMIT ?",
            params + [before, limit],
        )
        rows = list(reversed(rows))
    else:
        rows = query(
            f"SELECT s.* FROM syslog s WHERE {condition} AND s.id > ? "
            "ORDER BY s.id LIMIT ?",
            params + [after, limit],
        )
    ruleset = syslog.rules()
    show_hidden = hidden == "1"
    result = []
    for row in rows:
        item = dict(row)
        rule = syslog.match_rule(f"{item['message']} {item['topics']}", ruleset)
        action = str(rule.get("action") or "color") if rule else "color"
        if action == "hide" and not show_hidden:
            continue
        item["color"] = str(rule.get("color") or "") if rule and action == "color" else ""
        item["level"] = syslog.line_level(item["severity_name"])
        result.append(item)

    # Границы берём по всей выборке, а не по показанному: иначе спрятанная
    # строка на краю приезжала бы снова и снова, лента дёргалась бы на месте
    return {
        "rows": result,
        "last": rows[-1]["id"] if rows else after,
        "first": rows[0]["id"] if rows else before,
    }


@router.get("/syslog/export")
async def syslog_export(
    q: str = "",
    device_id: str = "",
    severity: str = "",
    topics: str = "",
    user=Depends(require("syslog.view")),
):
    """
    Выгрузка отфильтрованного журнала обычным текстом.

    Текст, а не CSV: журнал читают глазами и грепают, а не считают
    в таблице. Отдаётся потоком, чтобы миллион строк не собирался
    в памяти целиком.
    """
    condition, params = _filters(user, q, device_id, severity, topics)

    def lines():
        rows = query(
            f"SELECT s.* FROM syslog s WHERE {condition} ORDER BY s.id LIMIT 200000",
            params,
        )
        for row in rows:
            yield "%s  %-20s %-8s %-16s %s\n" % (
                row["ts"], (row["device_name"] or row["source"])[:20],
                row["severity_name"], row["topics"][:16], row["message"])

    return StreamingResponse(
        lines(),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition":
                 'attachment; filename="tikpilot-syslog-%s.txt"' % utcnow()[:10]},
    )


@router.post("/api/syslog/clear")
async def syslog_clear(request: Request, payload: dict = Body(default={}),
                       user=Depends(require("syslog.view"))):
    """Очистить журнал целиком или по одной точке."""
    device_id = payload.get("device_id")
    removed = syslog.clear(int(device_id) if device_id else None)
    log_audit(user["username"], "Очищен журнал устройств",
              f"строк: {removed}", "", client_ip(request))
    return {"ok": True, "removed": removed}


# ------------------------------------------------------- разрешённые адреса
@router.post("/api/syslog/sources")
async def source_allow(request: Request, payload: dict = Body(default={}),
                       user=Depends(require("syslog.view"))):
    """
    Разрешить приём с адреса.

    Точка привязывается по имени, которым она подписала свои строки:
    роутер шлёт свой identity, и он у панели уже есть. Не нашли по имени,
    строки всё равно будут приниматься, просто без привязки к устройству.
    """
    address = str(payload.get("address") or "").strip()
    if not address:
        return JSONResponse({"error": "Не указан адрес"}, status_code=400)

    import ipaddress

    try:
        # Принимаем и одиночный адрес, и сеть: при резервном туннеле
        # у каждой точки свой адрес, и разрешать их по одному значит
        # полсотни нажатий
        ipaddress.ip_network(address, strict=False)
    except ValueError:
        return JSONResponse({"error": "Это не адрес и не сеть"}, status_code=400)

    device_id = payload.get("device_id")
    if not device_id:
        host = str(payload.get("host") or "").strip()
        guess = syslog._sources.by_name(host) if host else None
        device_id = guess["id"] if guess else None

    device_id = int(device_id) if device_id else None
    syslog.allow_source(address, device_id)

    # В журнале действий пишем имя точки, а не её внутренний номер:
    # число вроде «37» человеку через месяц не скажет ничего
    device_name = ""
    if device_id:
        found = query_one("SELECT name FROM devices WHERE id = ?", (device_id,))
        device_name = found["name"] if found else ""

    log_audit(user["username"], "Разрешён источник журнала", address,
              device_name, client_ip(request))
    return {"ok": True, "device_id": device_id, "device_name": device_name}


@router.post("/api/syslog/sources/delete")
async def source_forget(request: Request, payload: dict = Body(default={}),
                        user=Depends(require("syslog.view"))):
    """Перестать принимать с адреса."""
    address = str(payload.get("address") or "").strip()
    if not syslog.forget_source(address):
        return JSONResponse({"error": "Адрес не найден"}, status_code=404)
    log_audit(user["username"], "Убран источник журнала", address, "",
              client_ip(request))
    return {"ok": True}


# ---------------------------------------------------------- правила подсветки
@router.post("/api/syslog/rules")
async def rule_create(request: Request, payload: dict = Body(default={}),
                      user=Depends(require("syslog.view"))):
    """Добавить правило подсветки."""
    pattern = str(payload.get("pattern") or "").strip()
    if not pattern:
        return JSONResponse({"error": "Пустой образец"}, status_code=400)

    color = str(payload.get("color") or "warn")
    if color not in COLORS:
        return JSONResponse({"error": "Неизвестный цвет"}, status_code=400)

    action = str(payload.get("action") or "color")
    if action not in syslog.ACTIONS:
        return JSONResponse({"error": "Неизвестное действие"}, status_code=400)

    is_regex = 1 if payload.get("is_regex") else 0
    if is_regex:
        # Кривое выражение уронило бы подсветку на каждой строке,
        # поэтому проверяем сразу, а не при первом совпадении
        import re

        try:
            re.compile(pattern)
        except re.error as exc:
            return JSONResponse(
                {"error": f"Не разобрать выражение: {exc}"}, status_code=400)

    row = query_one("SELECT COALESCE(MAX(position), 0) AS p FROM syslog_rules")
    execute(
        "INSERT INTO syslog_rules (pattern, is_regex, color, note, enabled, position, "
        "created_at, action) VALUES (?,?,?,?,1,?,?,?)",
        (pattern, is_regex, color, str(payload.get("note") or "").strip(),
         (row["p"] if row else 0) + 1, utcnow(), action),
    )
    syslog.forget_rules()
    log_audit(user["username"], "Добавлено правило журнала", pattern,
              syslog.ACTIONS[action] if action != "color" else color,
              client_ip(request))
    return {"ok": True}


@router.post("/api/syslog/rules/{rule_id}/toggle")
async def rule_toggle(request: Request, rule_id: int,
                      user=Depends(require("syslog.view"))):
    """Включить или выключить правило."""
    # Читаем до изменения: в журнале должен остаться образец, а не номер.
    # Номер правила через месяц не говорит ничего, а «login failure» говорит.
    rule = query_one("SELECT pattern, enabled FROM syslog_rules WHERE id = ?", (rule_id,))
    if not rule:
        return JSONResponse({"error": "Правило не найдено"}, status_code=404)

    execute_changes("UPDATE syslog_rules SET enabled = 1 - enabled WHERE id = ?", (rule_id,))
    syslog.forget_rules()
    log_audit(user["username"], "Изменено правило журнала", rule["pattern"],
              "выключено" if rule["enabled"] else "включено", client_ip(request))
    return {"ok": True}


@router.post("/api/syslog/rules/{rule_id}/delete")
async def rule_delete(request: Request, rule_id: int,
                      user=Depends(require("syslog.view"))):
    """Удалить правило."""
    rule = query_one("SELECT pattern FROM syslog_rules WHERE id = ?", (rule_id,))
    if not rule:
        return JSONResponse({"error": "Правило не найдено"}, status_code=404)

    execute_changes("DELETE FROM syslog_rules WHERE id = ?", (rule_id,))
    syslog.forget_rules()
    log_audit(user["username"], "Удалено правило журнала", rule["pattern"], "",
              client_ip(request))
    return {"ok": True}


@router.post("/api/syslog/rules/{rule_id}/move")
async def rule_move(request: Request, rule_id: int, payload: dict = Body(default={}),
                    user=Depends(require("syslog.view"))):
    """
    Передвинуть правило вверх или вниз.

    Порядок здесь не украшение: побеждает первое подошедшее правило,
    поэтому «ошибка» выше «интерфейс» и «ошибка интерфейса» покрасится
    в красный, а не в жёлтый.
    """
    direction = -1 if str(payload.get("direction")) == "up" else 1
    rules = [dict(r) for r in query("SELECT id FROM syslog_rules ORDER BY position, id")]
    index = next((i for i, r in enumerate(rules) if r["id"] == rule_id), None)
    if index is None:
        return JSONResponse({"error": "Правило не найдено"}, status_code=404)

    target = index + direction
    if 0 <= target < len(rules):
        rules[index], rules[target] = rules[target], rules[index]
        for position, rule in enumerate(rules, start=1):
            execute("UPDATE syslog_rules SET position = ? WHERE id = ?",
                    (position, rule["id"]))
        syslog.forget_rules()
    return {"ok": True}
