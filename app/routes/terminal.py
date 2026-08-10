"""Терминал до устройства: страница и вебсокет."""

from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any

from fastapi import APIRouter, Body, Depends, Request, WebSocket, WebSocketDisconnect

from .. import permissions, terminal
from ..auth import client_ip, read_session, require
from ..config import settings
from ..database import log_audit, query, query_one
from .deps import render

router = APIRouter()
log = logging.getLogger("tikpilot.terminal")


def _device_for(user: dict[str, Any], device_id: int) -> dict[str, Any] | None:
    """
    Устройство с учётом области видимости.

    Проверять её здесь обязательно: терминал даёт полную власть над точкой,
    и «подрядчик видит только свою группу» должно работать и тут.
    """
    where, params = permissions.scope_sql(user)
    row = query_one(
        f"SELECT * FROM devices d WHERE d.id = ? AND d.enabled = 1{where}",
        (device_id, *params),
    )
    return dict(row) if row else None


@router.get("/terminal")
async def terminal_page(request: Request, device_id: str = "",
                        user=Depends(require("terminal.use"))):
    """Страница терминала: выбор точки и само окно."""
    where, params = permissions.scope_sql(user)
    devices = query(
        f"SELECT d.id, d.name, d.host, d.status FROM devices d WHERE d.enabled = 1{where} "
        "ORDER BY d.name COLLATE NOCASE",
        tuple(params),
    )

    device = _device_for(user, int(device_id)) if device_id.isdigit() else None
    return render(
        "terminal.html",
        request,
        user,
        active="terminal",
        devices=devices,
        device=device,
        fingerprint=terminal.known_fingerprint(device["id"]) if device else "",
        enabled=settings.terminal_enabled,
        idle_minutes=settings.terminal_idle_minutes,
    )


@router.post("/api/terminal/{device_id}/forget-key")
async def forget_key(request: Request, device_id: int, payload: dict = Body(default={}),
                     user=Depends(require("terminal.use"))):
    """
    Забыть запомненный ключ устройства.

    Нужно после законной смены ключа: перезалили роутер, сбросили к заводским.
    Отдельной кнопкой, а не автоматически: молча принять новый ключ значит
    отменить всю пользу от его запоминания.
    """
    device = _device_for(user, device_id)
    if not device:
        return {"ok": False, "error": "Устройство не найдено"}

    removed = terminal.forget_fingerprint(device_id)
    if removed:
        log_audit(user["username"], "Забыт ключ SSH", str(device["name"]), "",
                  client_ip(request))
    return {"ok": True, "removed": removed}


@router.websocket("/ws/terminal/{device_id}")
async def terminal_socket(socket: WebSocket, device_id: int):
    """
    Двусторонний обмен с устройством.

    Проверки здесь свои, а не «как на остальных страницах», и это не
    дублирование по невнимательности: ограничение панели по адресам сделано
    обычным HTTP-посредником, а он на вебсокеты не распространяется. Без
    этой проверки терминал оказался бы открыт оттуда, откуда не открывается
    ни одна страница панели.
    """
    from ..netguard import allowed

    await socket.accept()

    async def fail(text: str) -> None:
        await socket.send_text(json.dumps({"type": "error", "text": text}))
        await socket.close()

    if not settings.terminal_enabled:
        return await fail("Терминал выключен настройкой TERMINAL_ENABLED.")

    # 1. Тот же круг доверенных сетей, что и у страниц
    peer = socket.client.host if socket.client else ""
    forwarded = socket.headers.get("x-forwarded-for", "")
    if settings.admin_networks and not allowed(
            peer, forwarded, settings.admin_networks, settings.trusted_proxies):
        log.warning("Терминал с недоверенного адреса: %s", peer)
        return await fail("Панель доступна только из доверенной сети.")

    # 2. Кто пришёл. Сессия лежит в той же куке, что и у страниц
    # read_session принимает объект с куками, вебсокет подходит: там же
    # лежит та же сессионная кука, что и у страниц
    user = read_session(socket)
    if not user:
        return await fail("Нужен вход в систему.")

    if not permissions.has(user, "terminal.use"):
        return await fail("Нет права на терминал.")

    device = _device_for(user, device_id)
    if not device:
        return await fail("Устройство не найдено или недоступно вам.")

    loop = asyncio.get_running_loop()
    session_obj = terminal.Session(device, user["username"])
    stop = threading.Event()
    queue: asyncio.Queue[str] = asyncio.Queue()

    def on_data(text: str) -> None:
        """Из потока чтения в цикл событий: очередь потокобезопасна."""
        loop.call_soon_threadsafe(queue.put_nowait, text)

    try:
        await asyncio.to_thread(session_obj.open)
    except terminal.TerminalError as exc:
        return await fail(str(exc))
    except Exception as exc:  # noqa: BLE001 — показать человеку, а не молчать
        log.exception("Терминал не открылся")
        return await fail(f"Терминал не открылся: {exc}")

    reader = threading.Thread(
        target=session_obj.pump, args=(on_data, stop),
        name="terminal-reader", daemon=True)
    reader.start()

    async def to_browser() -> None:
        while True:
            chunk = await queue.get()
            await socket.send_text(json.dumps({"type": "data", "text": chunk}))

    pump = asyncio.create_task(to_browser())
    idle = max(1, settings.terminal_idle_minutes) * 60

    try:
        await socket.send_text(json.dumps({"type": "ready"}))
        while True:
            # Сессия без единого нажатия закрывается сама: забытая вкладка
            # держала бы открытый шелл к роутеру сутками
            raw = await asyncio.wait_for(socket.receive_text(), timeout=idle)
            message = json.loads(raw)
            if message.get("type") == "data":
                await asyncio.to_thread(session_obj.send, str(message.get("text", "")))
            elif message.get("type") == "resize":
                await asyncio.to_thread(
                    session_obj.resize,
                    int(message.get("cols") or 80), int(message.get("rows") or 24))
    except asyncio.TimeoutError:
        try:
            await socket.send_text(json.dumps(
                {"type": "error", "text": "Сессия закрыта: не было нажатий."}))
        except Exception:  # noqa: BLE001
            pass
    except (WebSocketDisconnect, RuntimeError):
        pass
    except Exception:  # noqa: BLE001 — терминал не должен ронять сервер
        log.exception("Ошибка в сессии терминала")
    finally:
        stop.set()
        pump.cancel()
        await asyncio.to_thread(session_obj.close)
        log_audit(user["username"], "Закрыт терминал", str(device["name"]), "", peer)
        try:
            await socket.close()
        except Exception:  # noqa: BLE001
            pass
