"""Раздел «Задачи»: запуск массовых действий, прогресс и история."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse

from .. import i18n, permissions, worker
from ..actions import describe_params, get_action, list_actions
from ..auth import Forbidden, client_ip, current_user, require
from ..database import log_audit, query, query_one
from .deps import render, render_partial, templates

router = APIRouter()


# ------------------------------------------------------------------ запуск
@router.post("/api/jobs")
async def start_job(request: Request, user=Depends(current_user)):
    """
    Поставить массовую задачу в очередь.

    Тело запроса (JSON):
        {
          "action": "reboot",
          "device_ids": [1,2,3],      # либо
          "group_id": 4,              # все устройства группы
          "all": true,                # все устройства
          "params": {...}
        }
    """
    payload: dict[str, Any] = await request.json()
    action_name = payload.get("action", "")

    # Право на само действие. Проверяем до всего остального: незачем
    # разбирать параметры операции, которую запускать нельзя.
    if not permissions.can_run(user, action_name):
        raise Forbidden("Нет права запускать это действие")

    try:
        action = get_action(action_name)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    device_ids = _resolve_targets(payload, user)
    if not device_ids:
        return JSONResponse({"error": "Не выбрано ни одного устройства"}, status_code=400)

    # Явный список устройств приходит из браузера, а его можно подделать.
    # Проверяем, что каждое из них действительно доступно этому человеку.
    if not permissions.can_touch(user, device_ids):
        raise Forbidden("Среди выбранных устройств есть недоступные")

    params = payload.get("params") or {}
    # Проверяем обязательные параметры до постановки в очередь
    for p in action.params:
        if p.required and not str(params.get(p.name, "")).strip():
            return JSONResponse({"error": f"Не заполнено поле «{p.label}»"}, status_code=400)

    # Отложенный запуск это отдельное право. Проверяется здесь, а не только
    # прятанием поля в форме: запрос уходит из браузера, и подделать его
    # ничего не стоит
    scheduled_at = _parse_schedule(payload.get("scheduled_at"))
    if scheduled_at and not permissions.has(user, "jobs.schedule"):
        raise Forbidden("Нет права откладывать запуск")

    try:
        job_id = worker.create_job(
            action_name, device_ids, params, user["username"], scheduled_at=scheduled_at
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    log_audit(
        user["username"],
        f"Запуск: {action.label}",
        # Форму слова подбираем сразу: запись уходит в журнал как есть.
        "%d %s" % (len(device_ids),
                   i18n.plural(len(device_ids), ("устройство", "устройства", "устройств"))),
        describe_params(action, params)[:1000],
        client_ip(request),
    )
    return {"ok": True, "job_id": job_id}


def _parse_schedule(value: Any) -> str | None:
    """
    Время отложенного запуска из формы → строка UTC для базы.

    Браузер присылает местное время без зоны (формат datetime-local),
    поэтому переводим его в UTC по часовому поясу сервера.
    """
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in ("%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"):
        try:
            local = datetime.strptime(text, fmt).astimezone()
        except ValueError:
            continue
        return local.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    return None


def _resolve_targets(payload: dict[str, Any], user: dict[str, Any]) -> list[int]:
    """
    Определить список устройств: явный перечень, группа или все сразу.

    «Все» и «вся группа» означают всё, что видит этот пользователь. Иначе
    оператор с доступом к одной группе одним нажатием перезагрузил бы парк.
    """
    where, params = permissions.scope_sql(user)

    if payload.get("all"):
        return [r["id"] for r in query(
            f"SELECT d.id FROM devices d WHERE enabled = 1{where}", tuple(params))]
    if payload.get("group_id"):
        return [r["id"] for r in query(
            f"SELECT d.id FROM devices d WHERE group_id = ? AND enabled = 1{where}",
            (payload["group_id"], *params))]
    return [int(i) for i in payload.get("device_ids", [])]


def _job_items(job_id: int, user: dict[str, Any]) -> list[Any]:
    """
    Строки результата задачи, доступные этому пользователю.

    Задача могла охватить весь парк, а человек видит одну группу. Показывать
    ему имена и ошибки чужих точек незачем.
    """
    where, params = permissions.scope_sql(user)
    if not where:
        return query(
            "SELECT * FROM job_items WHERE job_id = ? ORDER BY device_name COLLATE NOCASE",
            (job_id,),
        )
    return query(
        "SELECT * FROM job_items WHERE job_id = ? AND device_id IN "
        f"(SELECT d.id FROM devices d WHERE 1=1{where}) "
        "ORDER BY device_name COLLATE NOCASE",
        (job_id, *params),
    )


@router.post("/api/jobs/{job_id}/cancel")
async def cancel(request: Request, job_id: int, user=Depends(require("jobs.cancel"))):
    """
    Отменить задачу: незапущенные устройства будут пропущены.

    В ответе итоговое состояние. Оно разное: отложенная задача закрывается
    сразу, а идущая доводит до конца устройства, которые уже в работе.
    Интерфейсу нужно сказать человеку, что именно произошло.
    """
    worker.cancel_job(job_id)
    row = query_one("SELECT status FROM jobs WHERE id = ?", (job_id,))
    log_audit(user["username"], "Отмена задачи", str(job_id), ip=client_ip(request))
    return {"ok": True, "status": row["status"] if row else "", "job_id": job_id}


# ---------------------------------------------------------------- страницы
@router.get("/jobs")
async def jobs_page(request: Request, user=Depends(current_user)):
    """История массовых задач."""
    rows = query("SELECT * FROM jobs ORDER BY id DESC LIMIT 200")
    return render("jobs.html", request, user, active="jobs", jobs=rows)


@router.get("/jobs/{job_id}")
async def job_detail(request: Request, job_id: int, user=Depends(current_user)):
    """Детали задачи с построчным результатом по устройствам."""
    job = query_one("SELECT * FROM jobs WHERE id = ?", (job_id,))
    if job is None:
        return RedirectResponse("/jobs", status_code=303)
    items = _job_items(job_id, user)
    raw = json.loads(job["params_json"] or "{}")
    raw.pop("_job_id", None)
    return render("job_detail.html", request, user, active="jobs", job=job, items=items,
                  params=_named_params(job["action"], raw))


def _named_params(action_name: str, raw: dict) -> list[dict]:
    """
    Параметры задачи с человеческими подписями.

    Ключи из формы (`script_name`, `kind`) понятны тому, кто писал
    действие, а не тому, кто через неделю разбирается, что именно
    запускали. Подписи и значения выпадающих списков берём из описания
    действия. Если действие с тех пор переименовали или удалили,
    показываем ключ как есть: страница задачи должна открываться всегда.
    """
    try:
        action = get_action(str(action_name))
    except ValueError:
        return [{"label": key, "value": value} for key, value in raw.items()]

    from ..actions import _device_name

    known = {p.name: p for p in action.params}
    result = []
    for key, value in raw.items():
        param = known.get(key)
        text = str(value)
        # Подпись из списка это наша же строка, её надо переводить.
        # Всё остальное человек вписал сам, и трогать это нельзя
        translate = False
        if param is not None and param.options:
            text = dict(param.options).get(text, text)
            translate = True
        elif param is not None and param.type == "device":
            # В параметрах лежит номер точки. «Куда мерить: 51» не говорит
            # ничего даже тому, кто эту задачу и запускал
            text = _device_name(text) or text
        result.append({"label": param.label if param else key, "value": text,
                       "translate": translate, "secret": "password" in key})
    return result


@router.get("/api/jobs/{job_id}")
async def job_status(job_id: int, user=Depends(current_user)):
    """Компактный JSON с прогрессом — опрашивается страницей задачи."""
    job = query_one("SELECT * FROM jobs WHERE id = ?", (job_id,))
    if job is None:
        return JSONResponse({"error": "Задача не найдена"}, status_code=404)
    data = dict(job)
    data.pop("params_json", None)
    return data


@router.get("/jobs/{job_id}/items")
async def job_items_fragment(request: Request, job_id: int, user=Depends(current_user)):
    """HTML-фрагмент с результатами — подгружается при опросе прогресса."""
    items = _job_items(job_id, user)
    return render_partial("partials/job_items.html", request, user, items=items)


@router.get("/api/actions")
async def actions_list(request: Request, user=Depends(current_user)):
    """
    Описание всех доступных массовых действий (для отрисовки форм).

    Диалог рисуется на стороне браузера, поэтому названия и подписи полей
    переводим здесь: до шаблонов они не доходят.
    """
    from .. import i18n
    from ..actions import action_to_dict
    from .deps import resolve_lang

    lang = resolve_lang(request, user)

    def localize(item: dict) -> dict:
        item = dict(item)
        for key in ("label", "description"):
            if item.get(key):
                item[key] = i18n.translate_text(item[key], lang)
        params = []
        for param in item.get("params") or []:
            param = dict(param)
            for key in ("label", "help", "placeholder"):
                if param.get(key):
                    param[key] = i18n.translate_text(param[key], lang)
            if param.get("options"):
                param["options"] = [
                    [value, i18n.translate_text(title, lang)]
                    for value, title in param["options"]
                ]
            params.append(param)
        if params:
            item["params"] = params
        return item

    # Показываем только то, что человеку разрешено запускать
    return [localize(action_to_dict(a)) for a in permissions.allowed_actions(user)]
