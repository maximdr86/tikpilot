"""
Раздел «Клиенты»: что подключено к площадкам.

Собирает панель сама, при полном опросе. Здесь только показ и своя
подпись: имя, под которым человек знает эту железку, роутер сообщить
не может.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from .. import clients as client_list
from .. import permissions
from ..auth import Forbidden, client_ip, require
from ..config import settings
from ..database import execute, log_audit, query, query_one
from .deps import render

router = APIRouter()

#: Больше этого на странице не показываем. Тысяча строк уже нечитаема,
#: а на парке в полсотни точек их бывает несколько тысяч.
LIMIT = 1000


def _filters(user: Any, q: str = "", device_id: str = "",
             seen: str = "", link: str = "") -> tuple[str, list[Any]]:
    """
    Условие выборки клиентов по фильтрам страницы.

    Вынесено отдельно, потому что «забыть всех» должно удалять ровно то,
    что человек видит на экране. Собирать условие второй раз рядом значило
    бы однажды разойтись с показанным и удалить не то.
    """
    where: list[str] = ["1=1"]
    params: list[Any] = []

    # Клиенты живут за устройствами, поэтому область видимости та же
    scope_where, scope_params = permissions.scope_sql(user)
    if scope_where:
        where.append("c.device_id IN (SELECT d.id FROM devices d WHERE 1=1%s)" % scope_where)
        params += scope_params

    if q:
        where.append(
            "(c.hostname LIKE ? OR c.label LIKE ? OR c.comment LIKE ?"
            " OR c.mac LIKE ? OR c.ip LIKE ? OR c.vendor LIKE ?)"
        )
        params += [f"%{q.strip()}%"] * 6
    if device_id.isdigit():
        where.append("c.device_id = ?")
        params.append(int(device_id))
    if link in ("wired", "wireless"):
        where.append("c.link = ?")
        params.append(link)
    if seen == "online":
        # «Сейчас» это последний полный опрос плюс запас: между опросами
        # проходит четверть часа, и требовать свежести до минуты нельзя
        where.append("c.last_seen > datetime('now', '-40 minutes')")
    elif seen == "gone":
        where.append("c.last_seen <= datetime('now', '-40 minutes')")

    return " AND ".join(where), params


@router.get("/clients")
async def clients_page(
    request: Request,
    q: str = "",
    device_id: str = "",
    seen: str = "",
    link: str = "",
    user=Depends(require("clients.view")),
):
    """
    Список клиентов с поиском и фильтрами.

    Поиск идёт по имени, подписи, комментарию с роутера, MAC, адресу
    и вендору: человек ищет тем, что помнит, а помнит он каждый раз разное.
    """
    condition, params = _filters(user, q, device_id, seen, link)
    scope_where, scope_params = permissions.scope_sql(user)

    rows = query(
        f"SELECT c.*, d.name AS device_name FROM clients c "
        f"JOIN devices d ON d.id = c.device_id WHERE {condition} "
        "ORDER BY c.last_seen DESC, c.mac LIMIT ?",
        (*params, LIMIT),
    )
    total = query_one(
        f"SELECT COUNT(*) AS c FROM clients c WHERE {condition}", tuple(params))
    fresh = query_one(
        f"SELECT COUNT(*) AS c FROM clients c WHERE {condition} "
        "AND c.last_seen > datetime('now', '-40 minutes')",
        tuple(params),
    )

    return render(
        "clients.html",
        request,
        user,
        active="clients",
        clients=rows,
        total=total["c"] if total else 0,
        fresh=fresh["c"] if fresh else 0,
        devices=query(
            "SELECT DISTINCT d.id, d.name FROM clients c JOIN devices d ON d.id = c.device_id "
            f"WHERE 1=1{scope_where} ORDER BY d.name COLLATE NOCASE",
            tuple(scope_params),
        ),
        f_q=q,
        f_device=device_id,
        f_seen=seen,
        f_link=link,
        limited=len(rows) >= LIMIT,
        full_minutes=max(1, settings.monitor_full_interval // 60),
    )


@router.post("/api/clients/{client_id}/label")
async def set_label(request: Request, client_id: int,
                    user=Depends(require("clients.view"))):
    """
    Задать свою подпись клиенту.

    Роутер знает MAC и вендора, но не знает, что это «касса 2» или
    «камера у входа». Подпись переживает и смену адреса, и переезд
    в другой порт, потому что привязана к MAC.

    Подписанные строки не удаляются при чистке старых: раз человек дал
    имя, значит запись ему зачем-то нужна.
    """
    payload = await request.json()
    row = query_one(
        "SELECT c.id, c.mac, c.device_id FROM clients c WHERE c.id = ?", (client_id,))
    if row is None:
        return JSONResponse({"error": "Клиент не найден"}, status_code=404)
    if not permissions.can_touch(user, [row["device_id"]]):
        raise Forbidden()

    label = str(payload.get("label") or "").strip()[:100]
    execute("UPDATE clients SET label = ? WHERE id = ?", (label, client_id))
    log_audit(user["username"],
              "Подпись клиента" if label else "Снята подпись клиента",
              row["mac"], label, client_ip(request))
    return {"ok": True, "label": label}


@router.post("/api/clients/{client_id}/delete")
async def forget_client(request: Request, client_id: int,
                        user=Depends(require("clients.view"))):
    """
    Забыть клиента.

    Нужно, когда железку увезли: иначе она будет висеть в списке до конца
    срока хранения, а подписанная — вечно. На саму сеть это не влияет,
    и если устройство снова появится, панель запишет его заново.
    """
    row = query_one("SELECT mac, device_id FROM clients WHERE id = ?", (client_id,))
    if row is None:
        return JSONResponse({"error": "Клиент не найден"}, status_code=404)
    if not permissions.can_touch(user, [row["device_id"]]):
        raise Forbidden()

    execute("DELETE FROM clients WHERE id = ?", (client_id,))
    log_audit(user["username"], "Забыт клиент", row["mac"], ip=client_ip(request))
    return {"ok": True}


@router.post("/api/clients/forget-all")
async def forget_all(request: Request, user=Depends(require("clients.view"))):
    """
    Забыть всех клиентов, попадающих под текущие фильтры.

    Удаляется ровно то, что человек видит на экране: те же условия, что
    и на странице. Выбрал точку — очистится только она, ничего не выбрал —
    весь список. Так проще объяснить себе, что произойдёт, чем кнопке
    «удалить всё вообще», которая рано или поздно нажимается не тогда.

    Строки со своей подписью по умолчанию остаются: их заводили руками,
    и стирать их заодно с мусором неправильно. Убрать и их можно явным
    флагом, тогда в ответе видно, сколько ушло.
    """
    payload = await request.json() if await request.body() else {}
    condition, params = _filters(
        user,
        str(payload.get("q") or ""),
        str(payload.get("device_id") or ""),
        str(payload.get("seen") or ""),
        str(payload.get("link") or ""),
    )
    keep_labeled = bool(payload.get("keep_labeled", True))
    if keep_labeled:
        condition += " AND c.label = ''"

    # Удаляем по списку номеров: `DELETE ... WHERE` с подзапросом на ту же
    # таблицу SQLite выполняет, но читается это заметно хуже
    ids = [row["id"] for row in query(
        f"SELECT c.id FROM clients c WHERE {condition}", tuple(params))]
    for client_id in ids:
        execute("DELETE FROM clients WHERE id = ?", (client_id,))

    log_audit(user["username"], "Забыты клиенты", f"записей: {len(ids)}",
              "кроме подписанных" if keep_labeled else "включая подписанные",
              client_ip(request))
    return {"ok": True, "removed": len(ids)}


@router.post("/api/clients/collect")
def collect_now(request: Request, device_id: str = "",
                user=Depends(require("clients.view"))):
    """
    Собрать клиентов прямо сейчас, не дожидаясь полного опроса.

    Полный опрос идёт раз в четверть часа, а когда стоишь на площадке
    с кабелем в руке, ждать столько незачем.

    Обработчик намеренно обычный, а не `async`. Внутри блокирующие походы
    по сети, и в асинхронном виде они вставали бы поперёк цикла событий:
    на все две минуты обхода замирала бы вся панель целиком, у всех сразу.
    Обычную функцию Starlette уводит в отдельный поток, и остальные страницы
    продолжают отвечать.

    Точки опрашиваются параллельно, как в мониторинге: полсотни площадок
    по очереди на плохих каналах это минуты, а пачкой по восемь секунды.
    Больше восьми одновременных подключений через один туннель смысла
    не имеют, канал становится узким местом раньше.

    Если на странице выбрана точка, опрашивается только она. Обычно
    кнопку жмут, глядя на конкретную площадку, а не на весь парк.
    """
    from concurrent.futures import ThreadPoolExecutor

    from ..sessions import pool

    where, params = permissions.scope_sql(user)
    # Заведомо упавшие пропускаем, а вот «неизвестно» опрашиваем: это
    # состояние только что добавленной точки, и не собрать с неё клиентов
    # было бы странно
    condition = f"SELECT * FROM devices d WHERE enabled = 1 AND status <> 'offline'{where}"
    values = list(params)
    if device_id.isdigit():
        condition += " AND d.id = ?"
        values.append(int(device_id))

    devices = query(condition, tuple(values))

    def one(device: dict) -> int:
        """Одна точка. Возвращает число записей или -1, если не вышло."""
        try:
            with pool.borrow(dict(device)) as mt:
                rows = client_list.collect(mt)
        except Exception:  # noqa: BLE001 — одна точка не должна ломать обход
            return -1
        return client_list.save(device["id"], rows)

    total, failed = 0, 0
    if devices:
        with ThreadPoolExecutor(max_workers=min(8, len(devices)),
                                thread_name_prefix="collect") as executor:
            for saved in executor.map(one, devices):
                if saved < 0:
                    failed += 1
                else:
                    total += saved

    log_audit(user["username"], "Собраны клиенты",
              f"устройств: {len(devices)}", f"клиентов: {total}", client_ip(request))
    return {"ok": True, "devices": len(devices), "clients": total, "failed": failed}
