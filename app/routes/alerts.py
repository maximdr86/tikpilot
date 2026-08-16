"""Раздел «Пороги»: правила, что горит сейчас и лента срабатываний."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from .. import alerts, i18n, notify, permissions
from ..config import settings
from ..auth import Forbidden, client_ip, current_user
from ..database import log_audit, query, query_one
from .deps import render

router = APIRouter()


def _scope_label(rule: dict) -> str:
    """Человеческое описание области: весь парк, группа или точка."""
    if rule["scope_kind"] == "group":
        row = query_one("SELECT name FROM groups WHERE id = ?", (rule["scope_id"],))
        return str(row["name"]) if row else "группа удалена"
    if rule["scope_kind"] == "device":
        row = query_one("SELECT name FROM devices WHERE id = ?", (rule["scope_id"],))
        return str(row["name"]) if row else "точка удалена"
    return "весь парк"


@router.get("/alerts")
async def alerts_page(request: Request, user=Depends(current_user)):
    """Страница порогов. Правку закрывает отдельное право."""
    if not permissions.has(user, "alerts.view"):
        raise Forbidden()

    from .deps import resolve_lang

    lang = resolve_lang(request, user)

    firing = alerts.active()
    waiting = alerts.pending()
    for row in firing + waiting:
        row["value_text"] = alerts.format_value(row.get("metric"),
                                                row.get("last_value"), lang)

    feed = alerts.events(60)
    for row in feed:
        row["value_text"] = alerts.format_value(row.get("metric"), row.get("value"), lang)

    rows = alerts.rules()
    for rule in rows:
        rule["scope_label"] = _scope_label(rule)
        metric = alerts.BY_KEY.get(str(rule["metric"]))
        rule["metric_label"] = metric.label if metric else str(rule["metric"])
        rule["unit"] = metric.unit if metric else ""

    return render(
        "alerts.html",
        request,
        user,
        active="alerts",
        rules=rows,
        metrics=alerts.METRICS,
        firing=firing,
        pending=waiting,
        events=feed,
        groups=query("SELECT id, name FROM groups ORDER BY name COLLATE NOCASE"),
        devices=query("SELECT id, name FROM devices ORDER BY name COLLATE NOCASE"),
        channels=notify.channels(),
        notify_log=notify.history(10),
        # Что мешает отправке прямо сейчас: человек должен видеть это
        # рядом с кнопкой, а не узнавать, нажав её
        silent=notify.why_silent(),
        silent_text=i18n.translate_text(
            notify.REASONS.get(notify.why_silent(), ""), lang),
        notify_on=settings.notify_enabled,
    )


@router.post("/api/notify/channels")
async def save_channel(request: Request, user=Depends(current_user)):
    """Завести или изменить канал доставки."""
    if not permissions.has(user, "alerts.manage"):
        raise Forbidden()

    data = await request.json()
    try:
        channel_id = notify.save_channel(data)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    # В журнал идёт вид канала и адрес, но никогда не токен
    log_audit(user["username"], "Сохранён канал уведомлений",
              str(data.get("kind") or ""), str(data.get("address") or ""),
              client_ip(request))
    return {"ok": True, "id": channel_id}


@router.post("/api/notify/channels/{channel_id}/delete")
async def delete_channel(request: Request, channel_id: int, user=Depends(current_user)):
    """Убрать канал вместе с токеном."""
    if not permissions.has(user, "alerts.manage"):
        raise Forbidden()

    row = query_one("SELECT * FROM notify_channels WHERE id = ?", (channel_id,))
    if row is None:
        return JSONResponse({"error": "Канал не найден"}, status_code=404)

    notify.delete_channel(channel_id)
    log_audit(user["username"], "Удалён канал уведомлений", str(row["kind"]),
              str(row["address"]), client_ip(request))
    return {"ok": True}


@router.post("/api/notify/channels/{channel_id}/test")
def test_channel(request: Request, channel_id: int, user=Depends(current_user)):
    """
    Отправить проверочное сообщение.

    Обработчик обычный, а не async: внутри поход по сети, и в асинхронном
    виде он вставал бы поперёк цикла событий, останавливая панель целиком.
    """
    if not permissions.has(user, "alerts.manage"):
        raise Forbidden()

    from .deps import resolve_lang

    try:
        notify.test_send(channel_id, resolve_lang(request, user))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001 - причину показываем человеку
        return JSONResponse({"error": f"Не отправилось: {exc}"}, status_code=502)
    return {"ok": True}


@router.post("/api/notify/send")
def send_now(request: Request, user=Depends(current_user)):
    """
    Отправить накопившееся немедленно, не дожидаясь сводки.

    Кнопка обходит тихие часы и интервал сводки, но не выключатель:
    если отправка выключена, панель об этом честно говорит, а не молчит
    с ответом «отправлено: 0».
    """
    if not permissions.has(user, "alerts.manage"):
        raise Forbidden()

    from .deps import resolve_lang

    result = notify.dispatch(force=True)
    result["message"] = i18n.translate_text(
        notify.REASONS.get(str(result.get("reason")), ""),
        resolve_lang(request, user))
    return {"ok": True, **result}


@router.post("/api/alerts/rules")
async def save_rule(request: Request, user=Depends(current_user)):
    """Создать или изменить правило."""
    if not permissions.has(user, "alerts.manage"):
        raise Forbidden()

    data = await request.json()
    try:
        rule_id = alerts.save_rule(data, user["username"])
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    rule = query_one("SELECT * FROM alert_rules WHERE id = ?", (rule_id,))
    log_audit(user["username"], "Сохранён порог", str(rule["name"] if rule else rule_id),
              "", client_ip(request))
    return {"ok": True, "id": rule_id}


@router.post("/api/alerts/rules/{rule_id}/toggle")
async def toggle_rule(request: Request, rule_id: int, user=Depends(current_user)):
    """Включить или выключить правило, не удаляя его."""
    if not permissions.has(user, "alerts.manage"):
        raise Forbidden()

    rule = query_one("SELECT * FROM alert_rules WHERE id = ?", (rule_id,))
    if rule is None:
        return JSONResponse({"error": "Правило не найдено"}, status_code=404)

    on = not bool(rule["enabled"])
    alerts.toggle_rule(rule_id, on)
    log_audit(user["username"], "Порог включён" if on else "Порог выключен",
              str(rule["name"]), "", client_ip(request))
    return {"ok": True, "enabled": on}


@router.post("/api/alerts/rules/{rule_id}/delete")
async def delete_rule(request: Request, rule_id: int, user=Depends(current_user)):
    """Убрать правило. Записи в ленте остаются: это история, а не настройка."""
    if not permissions.has(user, "alerts.manage"):
        raise Forbidden()

    rule = query_one("SELECT * FROM alert_rules WHERE id = ?", (rule_id,))
    if rule is None:
        return JSONResponse({"error": "Правило не найдено"}, status_code=404)

    alerts.delete_rule(rule_id)
    log_audit(user["username"], "Удалён порог", str(rule["name"]), "", client_ip(request))
    return {"ok": True}


@router.post("/api/alerts/check")
async def check_now(request: Request, user=Depends(current_user)):
    """
    Пересчитать пороги прямо сейчас.

    Фоновый поток делает то же самое раз в минуту. Кнопка нужна, чтобы
    не гадать после правки правила, работает оно или нет.
    """
    if not permissions.has(user, "alerts.manage"):
        raise Forbidden()
    return {"ok": True, **alerts.evaluate()}
