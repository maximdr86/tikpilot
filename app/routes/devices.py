"""Раздел «Устройства»: список, фильтры, CRUD и массовый импорт."""

from __future__ import annotations

import csv
import io
from typing import Any

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse

from .. import sessions
from ..auth import client_ip, current_user
from ..crypto import encrypt
from ..database import (execute, forget_device_traces, log_audit, query,
                        query_one, utcnow)
from ..mikrotik import is_newer
from .. import permissions
from ..auth import Forbidden, require
from .deps import form_bool, render, render_partial, resolve_lang, templates

router = APIRouter()


# ------------------------------------------------------------------ выборка
def _fetch_devices(q: str = "", group_id: str = "", status: str = "",
                   user: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """
    Список устройств с учётом фильтров.

    Пустые значения фильтров игнорируются, поиск идёт по имени, адресу,
    комментарию и identity. Дополнительно к полям таблицы возвращается
    признак update_available — доступно ли обновление RouterOS.

    Значение status='update' — особый фильтр: только устройства с обновлением.
    """
    sql = [
        "SELECT d.*, g.name AS group_name, g.color AS group_color",
        "FROM devices d LEFT JOIN groups g ON g.id = d.group_id",
        "WHERE 1=1",
    ]
    params: list[Any] = []

    # Область видимости пользователя. Без user (фоновые вызовы) виден весь парк.
    if user is not None:
        from .. import permissions

        where, scope_params = permissions.scope_sql(user)
        if where:
            sql.append(where.lstrip())
            params += scope_params

    if q:
        # Модель тоже ищется: «покажи все hAP ac lite» это обычный вопрос
        # перед обновлением прошивки или закупкой замены
        # lower_ru, а не LIKE напрямую: встроенное сравнение SQLite
        # приводит к нижнему регистру только латиницу, и поиск «магазин»
        # не находил «Магазин»
        sql.append("AND (lower_ru(d.name) LIKE ? OR lower_ru(d.host) LIKE ? "
                   "OR lower_ru(d.comment) LIKE ? OR lower_ru(d.identity) LIKE ? "
                   "OR lower_ru(d.board_name) LIKE ? OR lower_ru(d.operator) LIKE ?)")
        like = f"%{q.lower()}%"
        params += [like] * 6
    if group_id == "none":
        sql.append("AND d.group_id IS NULL")
    elif group_id:
        sql.append("AND d.group_id = ?")
        params.append(group_id)
    if status and status != "update":
        sql.append("AND d.status = ?")
        params.append(status)

    sql.append("ORDER BY g.name COLLATE NOCASE, d.name COLLATE NOCASE")

    rows = [dict(r) for r in query(" ".join(sql), params)]
    for row in rows:
        row["update_available"] = _update_available(row)
        row["ahead_of_channel"] = _ahead_of_channel(row)

    if status == "update":
        rows = [r for r in rows if r["update_available"]]
    return rows


def _update_available(row: dict[str, Any]) -> bool:
    """
    Есть ли на устройстве непоставленное обновление.

    Именно «доступная версия НОВЕЕ установленной», а не просто «другая»:
    после переключения канала stable → long-term доступная версия может
    оказаться старше, и это не обновление, а откат назад.
    """
    return is_newer(row.get("latest_version"), row.get("ros_version"))


def _ahead_of_channel(row: dict[str, Any]) -> bool:
    """Установлена версия новее, чем предлагает выбранный канал обновлений."""
    return is_newer(row.get("ros_version"), row.get("latest_version"))


def _groups() -> list[Any]:
    return query("SELECT * FROM groups ORDER BY name COLLATE NOCASE")


# -------------------------------------------------------------------- страницы
@router.get("/devices")
async def devices_page(
    request: Request,
    q: str = "",
    group_id: str = "",
    status: str = "",
    user=Depends(current_user),
):
    """Основная страница со списком устройств."""
    from ..actions import list_actions

    return render(
        "devices.html",
        request,
        user,
        active="devices",
        devices=_fetch_devices(q, group_id, status, user),
        groups=_groups(),
        actions=permissions.allowed_actions(user),
        f_q=q,
        f_group=group_id,
        f_status=status,
    )


@router.get("/devices/rows")
async def devices_rows(
    request: Request,
    q: str = "",
    group_id: str = "",
    status: str = "",
    user=Depends(current_user),
):
    """HTML-фрагмент с телом таблицы — используется для живого обновления."""
    return render_partial(
        "partials/device_rows.html",
        request,
        user,
        devices=_fetch_devices(q, group_id, status, user),
    )


#: Потолок на число клиентов в карточке. Не для красоты: на точке
#: с гостевым Wi-Fi их бывают сотни, и страница на пять тысяч строк
#: не помогает никому. Список прокручивается, поэтому потолок высокий
#: и упирается в него редко.
DEVICE_CLIENTS_LIMIT = 500


def _device_clients(device_id: int, user) -> list[dict[str, Any]]:
    """
    Клиенты этой точки: сначала те, кого видели недавно.

    Право на раздел «Клиенты» проверяется отдельно: список за точкой
    это те же данные, и показывать их тому, кому раздел закрыт, нельзя.
    """
    if not permissions.has(user, "clients.view"):
        return []
    return [dict(r) for r in query(
        "SELECT * FROM clients WHERE device_id = ? "
        "ORDER BY last_seen DESC, id DESC LIMIT ?",
        (device_id, DEVICE_CLIENTS_LIMIT))]


def _device_charts(device_id: int, hours: int, lang: str = "ru") -> dict[str, str]:
    """
    Подготовить SVG-графики задержки, потерь и нагрузки для карточки.

    Язык нужен из-за подписи цели: шлюз панель находит сама и подписывает
    словом «шлюз». Подпись собирается в Python вместе с адресом, поэтому
    в шаблон приходит готовой строкой и мимо переводчика проходит насквозь.
    """
    from .. import charts, i18n, monitor

    empty = i18n.translate_text("данных пока нет", lang)
    latency = monitor.latency_history(device_id, hours)
    metrics = monitor.metrics_history(device_id, hours)

    rtt_series, loss_series = [], []
    for index, (_key, rows) in enumerate(latency.items()):
        label = str(rows[0]["label"] or "") if rows else ""
        name = str(rows[0]["target"]) if rows else _key
        if label:
            name = f"{name} ({i18n.translate_text(label, lang)})"
        color = charts.COLORS[index % len(charts.COLORS)]
        rtt_series.append(charts.Series(name, [(r["ts"], r["rtt_avg"]) for r in rows], color))
        loss_series.append(charts.Series(name, [(r["ts"], r["loss"]) for r in rows], color))

    cpu_series = [charts.Series(
        "Загрузка CPU, %",
        [(r["ts"], r["cpu_load"]) for r in metrics],
        charts.COLORS[0],
    )]
    memory_series = [charts.Series(
        "Свободно памяти, МиБ",
        [(r["ts"], (r["free_memory"] / 1048576) if r["free_memory"] else None) for r in metrics],
        charts.COLORS[1],
    )]

    return {
        "rtt": charts.line_chart(rtt_series, unit=" мс", empty_text=empty, peak=True)
                if rtt_series else charts.line_chart([], empty_text=empty),
        "rtt_legend": charts.legend(rtt_series) if rtt_series else "",
        "loss": charts.line_chart(loss_series, unit=" %", y_min=0, empty_text=empty)
                 if loss_series else "",
        # Загрузка и память стоят по двое в ряд: рисуем в их настоящую
        # ширину, иначе подписи ужимаются вдвое вместе с картинкой
        "cpu": charts.line_chart(cpu_series, unit=" %", y_min=0, y_max=100,
                                 width=charts.HALF_WIDTH, height=charts.HALF_HEIGHT,
                                 empty_text=empty),
        "memory": charts.line_chart(memory_series, unit=" МиБ", y_min=0,
                                    width=charts.HALF_WIDTH, height=charts.HALF_HEIGHT,
                                    empty_text=empty),
        "has_latency": bool(latency),
        "has_metrics": bool(metrics),
    }


#: Заголовок таблицы объёма. Отдельными строками, а не склейкой из слов:
#: переводчику нужна целая фраза, иначе выходит «Объём за неделю» из
#: трёх кусков, каждый из которых по-английски звучит иначе.
PERIOD_TITLE = {
    1: "Объём за час",
    6: "Объём за 6 часов",
    24: "Объём за сутки",
    168: "Объём за неделю",
}


def _traffic_panel(device: dict, hours: int, lang: str) -> dict:
    """
    Данные для раздела «Трафик»: графики и список интерфейсов с галочками.

    В списке не только то, за чем следим, но и всё, что панель видела
    в паспорте: иначе включить наблюдение можно было бы только через базу.
    Интерфейсы, по которым уже есть замеры, показываются даже когда их
    удалили с роутера: график за прошлую неделю от этого не портится.
    """
    from .. import charts, i18n, traffic

    empty = i18n.translate_text("данных пока нет", lang)
    device_id = int(device["id"])
    uplink = str(device.get("uplink_interface") or "").strip()
    watched = traffic.watched(device_id)
    latest = traffic.latest(device_id)

    ports = {str(row["name"]): dict(row) for row in query(
        "SELECT name, kind, physical FROM device_ports WHERE device_id = ?",
        (device_id,),
    )}
    known = list(ports)
    for name in traffic.interfaces(device_id):
        if name not in known:
            known.append(name)
    # Аплинк и отмеченное показываем всегда, даже если паспорт ещё
    # не собран: иначе на свежей точке список пуст, а счётчики уже идут
    for name in ([uplink] if uplink else []) + sorted(watched):
        if name and name not in known:
            known.append(name)

    rows = []
    for name in known:
        port = ports.get(name, {})
        rows.append({
            "name": name,
            "uplink": name == uplink,
            "watched": name in watched,
            # Единицы рождаются русскими и в шаблон приходят готовой
            # строкой, куда автоматический перевод не заглядывает:
            # «12,0 Мбит/с» посреди английской страницы
            "rx": i18n.translate_text(traffic.human_rate(latest.get(name, {}).get("rx")), lang),
            "tx": i18n.translate_text(traffic.human_rate(latest.get(name, {}).get("tx")), lang),
            "has_data": name in latest,
            "physical": bool(port.get("physical")),
            # Служебное и временное: петля, туннели клиентов, поднятые
            # роутером сессии. Их десятки, а следят за ними примерно
            # никогда, поэтому по умолчанию они спрятаны
            "minor": traffic.is_minor(name, str(port.get("kind") or ""))
                     and name != uplink and name not in watched
                     and name not in latest,
        })

    # Аплинк первым, за ним отмеченные, потом физические порты, потом
    # остальное: в списке из четырнадцати галочек важное должно быть
    # в начале, а не десятым по алфавиту
    rows.sort(key=lambda r: (not r["uplink"], not r["watched"],
                             not r["has_data"], not r["physical"], r["name"]))

    # Единица выбирается по самому большому значению на графике. На парке,
    # где аплинки отдают десятки килобит, шкала в мегабитах давала три
    # одинаковых «0.0» вместо подписей
    series_data = {name: traffic.bucketed(traffic.history(device_id, name, hours), hours)
                   for name in sorted(latest)}
    peak = max((max((r["rx_bps"] or 0, r["tx_bps"] or 0)) for rows_ in series_data.values()
                for r in rows_), default=0)
    divisor, unit = (1_000_000, " Мбит/с") if peak >= 1_000_000 else (1_000, " Кбит/с")

    rx_series, tx_series = [], []
    for index, (name, history) in enumerate(series_data.items()):
        if not history:
            continue
        color = charts.COLORS[index % len(charts.COLORS)]
        rx_series.append(charts.Series(
            name, [(r["ts"], (r["rx_bps"] or 0) / divisor) for r in history], color))
        tx_series.append(charts.Series(
            name, [(r["ts"], (r["tx_bps"] or 0) / divisor) for r in history], color))

    # Объём за период. График отвечает на вопрос «когда», а разговор
    # с провайдером и с арендатором канала идёт про «сколько всего»,
    # и складывать это глазами по картинке невозможно
    window = max(1, hours * 3600)
    totals = []
    for name in series_data:
        amount = traffic.volume(device_id, name, hours)
        if not amount["covered"]:
            continue
        totals.append({
            "name": name,
            "rx": i18n.translate_text(traffic.human_volume(amount["rx"]), lang),
            "tx": i18n.translate_text(traffic.human_volume(amount["tx"]), lang),
            "all": i18n.translate_text(
                traffic.human_volume(amount["rx"] + amount["tx"]), lang),
            # Доля периода, за которую есть замеры. Пока точка лежала,
            # считать было нечего, и объём получается заниженным:
            # об этом честнее сказать прямо в строке
            "share": min(100, int(round(100 * amount["covered"] / window))),
        })

    # Счётчики сняты, а замеров нет: между обходами точка успела упасть,
    # и пара «прошлое и текущее» не сложилась. Молчаливое «замеров нет»
    # в этом случае врёт: сбор идёт, просто считать не из чего
    counted = query_one(
        "SELECT COUNT(*) AS c FROM traffic_counters WHERE device_id = ?", (device_id,))

    return {
        "interfaces": rows,
        "has_data": bool(rx_series),
        "counters": int(counted["c"]) if counted else 0,
        "totals": totals,
        "period": i18n.translate_text(PERIOD_TITLE.get(hours, PERIOD_TITLE[24]), lang),
        # Заливка и отметка пика: на трафике первым делом ищут глазами,
        # когда было больше всего, и подписанный максимум отвечает сразу
        "rx": charts.line_chart(rx_series, unit=" " + i18n.translate_text(unit.strip(), lang),
                                y_min=0, empty_text=empty, fill=True,
                                peak=True) if rx_series else "",
        "tx": charts.line_chart(tx_series, unit=" " + i18n.translate_text(unit.strip(), lang),
                                y_min=0, empty_text=empty, fill=True,
                                peak=True) if tx_series else "",
        "legend": charts.legend(rx_series) if rx_series else "",
        "uplink": uplink,
    }


@router.get("/devices/{device_id}")
async def device_detail(request: Request, device_id: int, hours: int = 24, user=Depends(current_user)):
    """Карточка устройства: параметры, последние задачи и бэкапы."""
    # Устройство вне области видимости для этого пользователя не существует
    if not permissions.can_touch(user, [device_id]):
        raise Forbidden()
    device = query_one(
        "SELECT d.*, g.name AS group_name FROM devices d "
        "LEFT JOIN groups g ON g.id = d.group_id WHERE d.id = ?",
        (device_id,),
    )
    if device is None:
        return RedirectResponse("/devices", status_code=303)

    items = query(
        "SELECT ji.*, j.action_label, j.username FROM job_items ji "
        "JOIN jobs j ON j.id = ji.job_id WHERE ji.device_id = ? "
        "ORDER BY ji.id DESC LIMIT 30",
        (device_id,),
    )
    backups = query(
        "SELECT * FROM backups WHERE device_id = ? ORDER BY id DESC LIMIT 20",
        (device_id,),
    )
    from .. import inventory, monitor, rollback
    from ..actions import list_actions

    return render(
        "device_detail.html",
        request,
        user,
        active="devices",
        device=device,
        passport=inventory.load(device_id),
        armed_rollback=rollback.current(device_id),
        update_available=_update_available(dict(device)),
        ahead_of_channel=_ahead_of_channel(dict(device)),
        groups=_groups(),
        items=items,
        backups=backups,
        timeline=monitor.device_timeline(device_id, 40),
        clients=_device_clients(device_id, user),
        clients_total=query_one(
            "SELECT COUNT(*) AS c FROM clients WHERE device_id = ?",
            (device_id,))["c"],
        charts=_device_charts(device_id, hours if hours in (1, 6, 24, 168) else 24,
                              resolve_lang(request, user)),
        traffic=_traffic_panel(dict(device), hours if hours in (1, 6, 24, 168) else 24,
                               resolve_lang(request, user)),
        hours=hours if hours in (1, 6, 24, 168) else 24,
        actions=permissions.allowed_actions(user),
    )


@router.post("/api/devices/{device_id}/traffic-watch")
async def toggle_traffic_watch(request: Request, device_id: int, user=Depends(current_user)):
    """
    Включить или выключить счётчики по интерфейсу.

    Право то же, что и на правку карточки: это настройка наблюдения,
    а не действие над роутером. На самом устройстве ничего не меняется,
    панель лишь начинает или перестаёт читать его счётчики.
    """
    from .. import traffic

    if not permissions.can_touch(user, [device_id]) or not permissions.has(user, "devices.edit"):
        raise Forbidden()

    device = query_one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if device is None:
        return JSONResponse({"error": "Устройство не найдено"}, status_code=404)

    data = await request.json()
    name = str(data.get("interface") or "").strip()
    on = bool(data.get("on"))
    if not name:
        return JSONResponse({"error": "Не указан интерфейс"}, status_code=400)

    traffic.set_watch(device_id, name, on)
    log_audit(user["username"],
              "Включены счётчики интерфейса" if on else "Выключены счётчики интерфейса",
              str(device["name"]), name, client_ip(request))
    return {"ok": True, "on": on}


@router.post("/api/devices/{device_id}/inventory/forget")
async def forget_inventory(request: Request, device_id: int, user=Depends(current_user)):
    """
    Забыть собранный паспорт. Устройство не трогаем.

    Право то же, что и на сбор: кто может перечитать паспорт, тот может
    и выбросить неудачный. Ничего необратимого здесь нет, следующий обход
    соберёт всё заново.
    """
    from .. import inventory

    if not permissions.can_touch(user, [device_id]):
        raise Forbidden()

    device = query_one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if device is None:
        return JSONResponse({"error": "Устройство не найдено"}, status_code=404)

    inventory.forget(device_id)
    log_audit(user["username"], "Забыт паспорт устройства", str(device["name"]), "",
              client_ip(request))
    return {"ok": True}


@router.post("/api/devices/{device_id}/inventory")
def collect_inventory(request: Request, device_id: int, user=Depends(current_user)):
    """
    Собрать паспорт точки прямо сейчас.

    Обработчик обычный, а не `async`: внутри поход по сети, и в асинхронном
    виде он вставал бы поперёк цикла событий, останавливая панель целиком
    для всех сразу.
    """
    from .. import inventory
    from ..sessions import pool

    if not permissions.can_touch(user, [device_id]):
        raise Forbidden()

    device = query_one("SELECT * FROM devices WHERE id = ? AND enabled = 1", (device_id,))
    if device is None:
        return JSONResponse({"error": "Устройство не найдено"}, status_code=404)

    try:
        with pool.borrow(dict(device)) as mt:
            data = inventory.collect(mt)
    except Exception as exc:  # noqa: BLE001 — показать человеку, а не молчать
        return JSONResponse({"error": str(exc)[:300]}, status_code=502)

    # Паспорт без единого порта и сервиса это не паспорт, а обрывок:
    # такое бывает, когда связь пропала посреди обхода. Затирать им
    # прежний снимок нельзя, вчерашние данные полезнее пустоты
    if not data.get("ports") and not data.get("services"):
        return JSONResponse(
            {"error": "Устройство ответило неполно, паспорт не сохранён. "
                      "Попробуйте ещё раз, когда связь станет устойчивее."},
            status_code=502)

    inventory.save(device_id, data)
    log_audit(user["username"], "Собран паспорт устройства", str(device["name"]),
              "портов: %d, сервисов: %d" % (len(data.get("ports", [])),
                                            len(data.get("services", []))),
              client_ip(request))
    return {"ok": True, "ports": len(data.get("ports", []))}


@router.post("/api/rollbacks/confirm-all")
def rollback_confirm_all(request: Request, user=Depends(current_user)):
    """
    Подтвердить все взведённые страховки сразу.

    Обработчик обычный, а не `async`: внутри обход устройств по сети.

    Кнопка нужна потому, что взвести страховку можно на весь парк одним
    нажатием. Раз есть массовое взведение, обязано быть и массовое
    снятие, иначе возможность превращается в ловушку.
    """
    from .. import rollback

    if not permissions.can_run(user, "safe_change"):
        raise Forbidden()

    result = rollback.confirm_all(user["username"], permissions.scope_sql(user))
    log_audit(user["username"], "Подтверждены все изменения",
              f"точек: {result['total']}", f"снято: {result['done']}",
              client_ip(request))
    return {"ok": True, **result}


@router.post("/api/devices/{device_id}/rollback/{what}")
def rollback_decide(request: Request, device_id: int, what: str,
                    user=Depends(current_user)):
    """
    Подтвердить изменение или откатить его немедленно.

    Обработчик обычный, а не `async`: внутри поход к устройству.

    Права те же, что на само изменение: подтверждение это его вторая
    половина, и разделять их значило бы, что взвести страховку может
    один человек, а снять её некому.
    """
    from .. import rollback
    from ..sessions import pool

    if not permissions.can_touch(user, [device_id]) or not permissions.can_run(user, "safe_change"):
        raise Forbidden()

    device = query_one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if device is None or rollback.current(device_id) is None:
        return JSONResponse({"error": "Страховка не найдена"}, status_code=404)

    try:
        with pool.borrow(dict(device)) as mt:
            if what == "confirm":
                rollback.confirm(mt, device_id, user["username"])
            else:
                rollback.rollback_now(mt, device_id, user["username"])
    except Exception as exc:  # noqa: BLE001 — показать человеку, а не молчать
        return JSONResponse({"error": str(exc)[:300]}, status_code=502)

    return {"ok": True}


# ---------------------------------------------------------------------- CRUD
def _device_form_values(form: dict[str, Any]) -> dict[str, Any]:
    """Нормализовать данные формы устройства."""
    return {
        "name": (form.get("name") or "").strip(),
        "host": (form.get("host") or "").strip(),
        "api_port": int(form.get("api_port") or 8728),
        "ftp_port": int(form.get("ftp_port") or 21),
        # Порт SSH нужен только терминалу. Двадцать второй тут значение
        # по умолчанию, а не допущение: в живых сетях его часто переносят
        "ssh_port": int(form.get("ssh_port") or 22),
        "use_ssl": form_bool(form.get("use_ssl")),
        "username": (form.get("username") or "").strip(),
        "group_id": int(form["group_id"]) if (form.get("group_id") or "").strip() else None,
        "comment": (form.get("comment") or "").strip(),
        "latency_targets": (form.get("latency_targets") or "").strip(),
        # Оператор, вписанный руками. Пустое поле не трогает найденное
        # автоматически: человек не обязан заполнять его на каждой правке
        "operator": (form.get("operator") or "").strip(),
        # Чем входить по SSH. Любое значение, кроме «key», считается
        # паролем: так опечатка в форме оставляет точку рабочей,
        # а не отключает ей вход молча
        "ssh_auth": "key" if (form.get("ssh_auth") or "") == "key" else "password",
        "enabled": form_bool(form.get("enabled") or "1"),
    }


@router.post("/api/devices")
async def create_device(request: Request, user=Depends(require("devices.edit"))):
    """Создать устройство (JSON-ответ, форма отправляется через fetch)."""
    form = dict(await request.form())
    values = _device_form_values(form)
    if not values["name"] or not values["host"] or not values["username"]:
        return JSONResponse({"error": "Заполните имя, адрес и логин"}, status_code=400)

    now = utcnow()
    device_id = execute(
        "INSERT INTO devices (name, host, api_port, ftp_port, ssh_port, use_ssl, username, "
        "password_enc, ssh_key_enc, ssh_auth, group_id, comment, latency_targets, enabled, "
        "created_at, updated_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (
            values["name"],
            values["host"],
            values["api_port"],
            values["ftp_port"],
            values["ssh_port"],
            values["use_ssl"],
            values["username"],
            encrypt(form.get("password") or ""),
            encrypt(form.get("ssh_key") or "") if (form.get("ssh_key") or "").strip() else "",
            values["ssh_auth"],
            values["group_id"],
            values["comment"],
            values["latency_targets"],
            values["enabled"],
            now,
            now,
        ),
    )
    log_audit(user["username"], "Добавлено устройство", values["name"], values["host"], client_ip(request))
    return {"ok": True, "id": device_id}


@router.post("/api/devices/{device_id}/update")
async def update_device(request: Request, device_id: int,
                        user=Depends(require("devices.edit"))):
    """Обновить устройство. Пустое поле пароля оставляет прежний пароль."""
    if not permissions.can_touch(user, [device_id]):
        raise Forbidden()
    form = dict(await request.form())
    values = _device_form_values(form)
    if not values["name"] or not values["host"] or not values["username"]:
        return JSONResponse({"error": "Заполните имя, адрес и логин"}, status_code=400)

    password = form.get("password") or ""
    sql = (
        "UPDATE devices SET name=?, host=?, api_port=?, ftp_port=?, ssh_port=?, use_ssl=?, "
        "username=?, ssh_auth=?, group_id=?, comment=?, latency_targets=?, enabled=?, "
        "updated_at=?"
    )

    # Оператор считается вписанным руками только если его действительно
    # поменяли. Поле в форме заполняется найденным значением, чтобы его
    # было видно, и без этой проверки любое сохранение карточки молча
    # превращало найденное в ручное: дальше опрос его уже не обновлял,
    # и в списке навсегда оставался оператор с первой проверки.
    current = query_one("SELECT operator FROM devices WHERE id = ?", (device_id,))
    was = str((current["operator"] if current else "") or "")
    typed = values["operator"]
    operator_params: list[Any] = []
    if typed and typed != was:
        sql += ", operator=?, operator_source='manual', operator_detail='', operator_at=?"
        operator_params = [typed, utcnow()]
    elif not typed and was:
        # Стёрли поле — вернули точку к автоопределению
        sql += ", operator='', operator_source='', operator_detail='', operator_at=NULL"
    params: list[Any] = [
        values["name"],
        values["host"],
        values["api_port"],
        values["ftp_port"],
        values["ssh_port"],
        values["use_ssl"],
        values["username"],
        values["ssh_auth"],
        values["group_id"],
        values["comment"],
        values["latency_targets"],
        values["enabled"],
        utcnow(),
    ]
    params += operator_params
    if password:
        sql += ", password_enc=?"
        params.append(encrypt(password))
    # Пустое поле ключа оставляет прежний, как и пустое поле пароля:
    # карточку правят ради имени или группы, и заставлять человека
    # каждый раз заново вставлять ключ значит гонять его по буферу обмена
    ssh_key = (form.get("ssh_key") or "").strip()
    if ssh_key:
        sql += ", ssh_key_enc=?"
        params.append(encrypt(ssh_key))
    sql += " WHERE id=?"
    params.append(device_id)

    execute(sql, params)
    # Адрес или учётные данные могли измениться — старая сессия больше не годится
    sessions.pool.drop(device_id)
    log_audit(user["username"], "Изменено устройство", values["name"], values["host"], client_ip(request))
    return {"ok": True}


@router.get("/api/devices/brief")
async def devices_brief(user=Depends(current_user)):
    """
    Короткий список точек: номер, имя, адрес.

    Нужен формам, где точка это параметр, а не цель действия: тест
    скорости меряет от одной до другой, и вторую надо где-то выбрать.
    Объявлен выше `/api/devices/{device_id}`, иначе адрес разбирался бы
    как номер и отвечал бы ошибкой разбора.

    Область видимости соблюдается: тот, кому доступны две группы, не
    должен узнавать имена остальных сорока точек из выпадающего списка.
    """
    scope = permissions.scope_sql(user)
    rows = query(
        "SELECT d.id, d.name, d.host, d.status FROM devices d"
        f" WHERE d.enabled = 1{scope[0]} ORDER BY d.name COLLATE NOCASE",
        tuple(scope[1]),
    )
    return {"devices": [dict(row) for row in rows]}


@router.get("/api/devices/{device_id}")
async def get_device(device_id: int, user=Depends(require("devices.edit"))):
    """Данные устройства для формы редактирования (пароль не отдаём)."""
    if not permissions.can_touch(user, [device_id]):
        raise Forbidden()
    row = query_one("SELECT * FROM devices WHERE id = ?", (device_id,))
    if row is None:
        return JSONResponse({"error": "Устройство не найдено"}, status_code=404)
    data = dict(row)
    data.pop("password_enc", None)
    # Ключ наружу не отдаём никогда, даже зашифрованным. Форме хватает
    # знать, что он заведён: поле ввода в карточке пустое, и пустым
    # оставленное поле означает «оставить прежний»
    data["has_ssh_key"] = bool(data.pop("ssh_key_enc", "") or "")
    return data


@router.post("/api/devices/{device_id}/delete")
async def delete_device(request: Request, device_id: int,
                        user=Depends(require("devices.edit"))):
    """Удалить устройство."""
    if not permissions.can_touch(user, [device_id]):
        raise Forbidden()
    row = query_one("SELECT name FROM devices WHERE id = ?", (device_id,))
    execute("DELETE FROM devices WHERE id = ?", (device_id,))
    # Пороги и счётчики трафика живут без внешнего ключа, каскад их
    # не заденет: убираем сами, иначе удалённая точка останется гореть
    forget_device_traces([device_id])
    sessions.pool.drop(device_id)
    log_audit(user["username"], "Удалено устройство", row["name"] if row else str(device_id), ip=client_ip(request))
    return {"ok": True}


@router.post("/api/devices/bulk-delete")
async def bulk_delete(request: Request, user=Depends(require("devices.edit"))):
    """Удалить несколько устройств разом."""
    payload = await request.json()
    ids = [int(i) for i in payload.get("device_ids", [])]
    if not ids:
        return JSONResponse({"error": "Не выбрано ни одного устройства"}, status_code=400)
    placeholders = ",".join("?" * len(ids))
    execute(f"DELETE FROM devices WHERE id IN ({placeholders})", ids)
    forget_device_traces(ids)
    for device_id in ids:
        sessions.pool.drop(device_id)
    log_audit(user["username"], "Массовое удаление устройств", f"{len(ids)} шт.", ip=client_ip(request))
    return {"ok": True, "deleted": len(ids)}


@router.post("/api/devices/bulk-group")
async def bulk_set_group(request: Request, user=Depends(require("devices.edit"))):
    """Переместить выбранные устройства в группу."""
    payload = await request.json()
    ids = [int(i) for i in payload.get("device_ids", [])]
    group_id = payload.get("group_id")
    group_id = int(group_id) if group_id else None
    if not ids:
        return JSONResponse({"error": "Не выбрано ни одного устройства"}, status_code=400)
    placeholders = ",".join("?" * len(ids))
    execute(
        f"UPDATE devices SET group_id = ?, updated_at = ? WHERE id IN ({placeholders})",
        [group_id, utcnow(), *ids],
    )
    log_audit(user["username"], "Смена группы устройств", f"{len(ids)} шт.", ip=client_ip(request))
    return {"ok": True}


# -------------------------------------------------------------------- импорт
@router.post("/api/devices/import")
async def import_devices(
    request: Request,
    file: UploadFile = File(...),
    default_group: str = Form(""),
    user=Depends(require("devices.edit")),
):
    """
    Импорт устройств из CSV.

    Ожидаемые колонки (регистр не важен, лишние игнорируются):
        name, host, username, password, api_port, ftp_port, ssh_port, group, comment
    Разделитель определяется автоматически (запятая или точка с запятой).
    """
    raw = (await file.read()).decode("utf-8-sig", errors="replace")
    try:
        dialect = csv.Sniffer().sniff(raw[:2048], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(raw), dialect=dialect)

    groups = {g["name"].lower(): g["id"] for g in _groups()}
    created = 0
    errors: list[str] = []
    now = utcnow()

    for line_no, row in enumerate(reader, start=2):
        row = { (k or "").strip().lower(): (v or "").strip() for k, v in row.items() }
        name, host = row.get("name"), row.get("host")
        if not name or not host:
            errors.append(f"строка {line_no}: не заполнены name/host")
            continue

        group_name = row.get("group", "")
        group_id: int | None = None
        if group_name:
            key = group_name.lower()
            if key not in groups:
                groups[key] = execute(
                    "INSERT INTO groups (name, comment, created_at) VALUES (?,?,?)",
                    (group_name, "Создана при импорте", now),
                )
            group_id = groups[key]
        elif default_group:
            group_id = int(default_group)

        execute(
            "INSERT INTO devices (name, host, api_port, ftp_port, ssh_port, username, password_enc, "
            "group_id, comment, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                name,
                host,
                int(row.get("api_port") or 8728),
                int(row.get("ftp_port") or 21),
                int(row.get("ssh_port") or 22),
                row.get("username") or "admin",
                encrypt(row.get("password") or ""),
                group_id,
                row.get("comment") or "",
                now,
                now,
            ),
        )
        created += 1

    log_audit(user["username"], "Импорт устройств", f"{created} шт.", "; ".join(errors[:10]), client_ip(request))
    return {"ok": True, "created": created, "errors": errors[:20]}


@router.get("/api/devices/export/csv")
async def export_devices(user=Depends(current_user)):
    """Выгрузить список устройств в CSV (без паролей)."""
    from fastapi.responses import Response

    rows = _fetch_devices(user=user)
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    # Модель в выгрузке нужна ровно за тем же, зачем в таблице: план
    # обновления парка обычно составляют в электронной таблице, и там
    # «какая это коробка» столбец не менее важный, чем версия
    writer.writerow(["name", "host", "api_port", "ftp_port", "ssh_port", "username", "group",
                     "comment", "status", "version", "model", "architecture"])
    for r in rows:
        writer.writerow(
            [r["name"], r["host"], r["api_port"], r["ftp_port"], r["ssh_port"], r["username"],
             r["group_name"] or "", r["comment"], r["status"], r["ros_version"],
             r["board_name"], r["architecture"]]
        )
    return Response(
        buf.getvalue().encode("utf-8-sig"),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="devices.csv"'},
    )
