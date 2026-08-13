"""Вход, выход и смена пароля администратора."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse

from ..auth import (
    authenticate,
    clear_session_cookie,
    client_ip,
    end_sessions,
    current_user,
    make_session_token,
    read_session,
    require,
    set_session_cookie,
)
from ..config import settings
from ..crypto import hash_password
from .. import demo, i18n, invites, loginguard, operator, permissions
from ..database import execute, log_audit, query, query_one, utcnow
from .deps import LANG_COOKIE, form_bool, render, resolve_lang, templates

router = APIRouter()


@router.get("/login")
async def login_page(request: Request, next: str = "/"):
    """Форма входа. Если сессия уже есть — сразу на главную."""
    if read_session(request):
        return RedirectResponse("/", status_code=303)
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "next": next,
            "error": None,
            "lang": resolve_lang(request),
            "languages": i18n.available_languages(),
            "js_i18n": i18n.js_catalog(resolve_lang(request)),
            "remember_days": settings.session_remember_age // 86400,
        },
    )


# Поля форм объявлены со значением по умолчанию, а не обязательными.
# Обязательное поле, пришедшее пустым, отбрасывает сам FastAPI, и человек
# вместо подсказки «Укажите имя пользователя» получает страницу с JSON
# про «Field required». Пустое поле это обычная человеческая ошибка,
# и отвечать на неё должна форма, а не обработчик протокола.
@router.post("/login")
async def login_submit(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    remember: str = Form(""),
    next: str = Form("/"),
):
    """
    Проверка учётных данных и выдача сессионной cookie.

    Пауза после нескольких промахов проверяется до сверки пароля: иначе
    она не экономила бы ничего, ведь основная цена попытки это как раз
    проверка хеша.
    """
    address = client_ip(request)

    waiting = loginguard.wait_seconds(address)
    if waiting:
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "next": next,
                "error": "Слишком много попыток. Подождите %d с" % waiting,
                "lang": resolve_lang(request),
                "languages": i18n.available_languages(),
                "js_i18n": i18n.js_catalog(resolve_lang(request)),
                "remember_days": settings.session_remember_age // 86400,
            },
            status_code=429,
        )

    user = authenticate(username, password)
    if user is None:
        delay = loginguard.register_miss(address)
        log_audit(username, "Неудачный вход",
                  "пауза %d с" % delay if delay else "", ip=address)
        return templates.TemplateResponse(
            request,
            "login.html",
            {
                "next": next,
                "error": "Неверный логин или пароль",
                "lang": resolve_lang(request),
                "languages": i18n.available_languages(),
                "js_i18n": i18n.js_catalog(resolve_lang(request)),
                "remember_days": settings.session_remember_age // 86400,
            },
            status_code=401,
        )
    loginguard.register_success(address)
    target = next if next.startswith("/") else "/"
    response = RedirectResponse(target, status_code=303)
    long = form_bool(remember) == 1
    set_session_cookie(response, make_session_token(user, long), long)
    log_audit(user["username"], "Вход в систему",
              "запомнить" if long else "", ip=address)
    return response


@router.get("/lang/{code}")
async def switch_language(request: Request, code: str, next: str = "/"):
    """
    Переключить язык интерфейса.

    Выбор запоминается двумя способами. В базе — чтобы он пережил смену
    браузера и был свой у каждого администратора. В cookie — чтобы страница
    входа тоже открывалась на выбранном языке: там пользователя ещё нет.
    """
    lang = i18n.normalize_lang(code)
    user = read_session(request)
    if user:
        execute("UPDATE users SET lang = ? WHERE id = ?", (lang, user["id"]))

    target = next if next.startswith("/") and not next.startswith("//") else "/"
    response = RedirectResponse(target, status_code=303)
    response.set_cookie(
        LANG_COOKIE,
        lang,
        max_age=60 * 60 * 24 * 365,
        httponly=False,
        samesite="lax",
    )
    return response

@router.get("/logout")
async def logout(request: Request):
    """Выход: чистим cookie."""
    user = read_session(request)
    response = RedirectResponse("/login", status_code=303)
    clear_session_cookie(response)
    if user:
        log_audit(user["username"], "Выход из системы", ip=client_ip(request))
    return response


def _diagnostics() -> dict[str, object]:
    """
    Сведения о запущенном экземпляре.

    Нужны, чтобы сразу видеть, какая именно копия программы запущена. Типичная
    путаница: рядом лежат «проект» и «проект — копия», сервер поднят из старой
    папки и работает с устаревшим кодом.
    """
    import platform
    import sys

    from .. import __version__
    from ..actions import list_actions
    from ..config import BASE_DIR, settings
    from ..mikrotik import MikroTik

    # Признак того, что модули согласованы между собой: действие обновления
    # RouterOS требует методов, появившихся в версии 1.1.
    required = ("update_info", "wait_until_back", "routerboard_info")
    missing = [name for name in required if not hasattr(MikroTik, name)]

    from .. import monitor

    return {
        "version": __version__,
        "base_dir": str(BASE_DIR),
        "db_path": str(settings.db_path),
        "python": f"{platform.python_version()} ({sys.executable})",
        "actions": [a.label for a in list_actions()],
        "missing_methods": missing,
        "admin_networks": settings.admin_networks_raw,
        "monitor": {
            "enabled": settings.monitor_enabled,
            "method": settings.monitor_probe_method,
            "interval": settings.monitor_interval,
            "full_interval": settings.monitor_full_interval,
            "threshold": settings.monitor_fail_threshold,
            "probe_timeout": settings.monitor_probe_timeout,
            "workers": settings.monitor_workers,
            **monitor.state,
        },
        "latency": {
            "enabled": settings.latency_enabled,
            "targets": settings.latency_targets,
            "ping_gateway": settings.latency_ping_gateway,
            "count": settings.latency_count,
            # Сколько точек переопределили цели у себя в карточке
            "custom": (
                query("SELECT COUNT(*) AS c FROM devices WHERE latency_targets <> ''")[0]["c"]
            ),
        },
    }


def _users_context(request: Request | None = None) -> dict[str, object]:
    """Данные для раздела «Пользователи»: список, права, объекты области."""
    from .. import permissions
    from ..config import settings

    users = query(
        "SELECT id, username, is_active, created_at, permissions, scope_all "
        "FROM users ORDER BY username"
    )
    rows = []
    for row in users:
        data = dict(row)
        data["perm_set"] = permissions.parse(row["permissions"])
        data["groups"] = {r["group_id"] for r in query(
            "SELECT group_id FROM user_groups WHERE user_id = ?", (row["id"],))}
        data["devices"] = {r["device_id"] for r in query(
            "SELECT device_id FROM user_devices WHERE user_id = ?", (row["id"],))}
        rows.append(data)

    return {
        "users": rows,
        "permission_list": permissions.all_permissions(),
        "permission_full": permissions.FULL,
        "presets": permissions.PRESETS,
        "preset_labels": permissions.PRESET_LABELS,
        "all_groups": query("SELECT id, name FROM groups ORDER BY name COLLATE NOCASE"),
        "all_devices": query(
            "SELECT id, name, host FROM devices ORDER BY name COLLATE NOCASE"),
        "invites": invites.listing(),
        # Адрес панели, а не публичный: страница регистрации открывается
        # только из доверенной сети, и внешний адрес в такой ссылке ведёт
        # человека не туда. По умолчанию берём тот, по которому смотрят
        # панель прямо сейчас: он заведомо рабочий
        "invite_base": settings.panel_base_url or (
            str(request.base_url).rstrip("/") if request is not None else ""),
        "invite_hours": invites.DEFAULT_HOURS,
        "fresh_invite": "",
        "unknown_operators": operator.unknown_names(),
        "operator_colors": operator.COLORS,
    }


@router.get("/settings")
async def settings_page(request: Request, user=Depends(require("settings.view"))):
    """Страница управления администраторами."""
    return render("settings.html", request, user, active="settings",
                  message=None, error=None, diag=_diagnostics(), **_users_context(request))


@router.post("/settings/password")
async def change_password(
    request: Request,
    old_password: str = Form(""),
    new_password: str = Form(""),
    new_password2: str = Form(""),
    user=Depends(current_user),
):
    """Смена собственного пароля."""
    error = message = None

    if authenticate(user["username"], old_password) is None:
        error = "Текущий пароль указан неверно"
    elif len(new_password) < 6:
        error = "Новый пароль должен быть не короче 6 символов"
    elif new_password != new_password2:
        error = "Новые пароли не совпадают"
    else:
        execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(new_password), user["id"]))
        # Прочие входы завершаются: сменить пароль обычно и означает
        # «выгнать того, кто мог его знать»
        end_sessions(user["id"])
        log_audit(user["username"], "Смена пароля", ip=client_ip(request))
        message = "Пароль изменён, прежние входы на других устройствах завершены"

    # Пароль меняет себе кто угодно, а список учётных записей на этой странице
    # видит только тот, кому положено видеть настройки: иначе ответ на смену
    # пароля показал бы чужие учётки тому, кто их не видит на самой странице.
    extra: dict[str, object] = {}
    if permissions.has(user, "settings.view"):
        extra = _users_context(request)
    else:
        extra = {"users": [], "permission_list": [], "permission_full": permissions.FULL,
                 "presets": {}, "preset_labels": {}, "all_groups": [], "all_devices": []}

    return render("settings.html", request, user, active="settings",
                  message=message, error=error, diag=_diagnostics(), **extra)


@router.post("/settings/users")
async def add_user(
    request: Request,
    new_username: str = Form(""),
    password: str = Form(""),
    user=Depends(require("users.manage")),
):
    """Добавить ещё одного администратора."""
    error = message = None
    new_username = new_username.strip()
    if not new_username:
        error = "Укажите имя пользователя"
    elif len(password) < 6:
        error = "Пароль должен быть не короче 6 символов"
    else:
        try:
            execute(
                # Права по умолчанию пустые: новый человек ничего не может,
                # пока ему явно не выдали. Обратное было бы опасным сюрпризом.
                "INSERT INTO users (username, password_hash, created_at, permissions)"
                " VALUES (?,?,?,'')",
                (new_username, hash_password(password), utcnow()),
            )
            log_audit(user["username"], "Добавлен администратор", new_username, ip=client_ip(request))
            message = f"Пользователь {new_username} добавлен"
        except Exception:  # noqa: BLE001 — почти всегда это дубликат имени
            error = "Пользователь с таким именем уже существует"

    return render("settings.html", request, user, active="settings",
                  message=message, error=error, diag=_diagnostics(), **_users_context(request))


@router.post("/settings/invites")
async def create_invite(request: Request, note: str = Form(""),
                        hours: int = Form(invites.DEFAULT_HOURS),
                        user=Depends(require("users.manage"))):
    """Выписать приглашение по ссылке."""
    token = invites.create(note, hours, user["username"])
    # В журнале только пометка, для кого. Сам токен это пароль от входа
    # в систему, и в истории действий ему не место
    log_audit(user["username"], "Создано приглашение", note.strip() or "без пометки",
              f"срок {hours} ч", client_ip(request))

    context = _users_context(request)
    context["fresh_invite"] = token
    return render("settings.html", request, user, active="settings",
                  message="Приглашение создано, скопируйте ссылку",
                  error=None, diag=_diagnostics(), **context)


@router.post("/settings/invites/{invite_id}/revoke")
async def revoke_invite(request: Request, invite_id: int,
                        user=Depends(require("users.manage"))):
    """Отозвать неиспользованное приглашение."""
    row = invites.revoke(invite_id)
    message = error = None
    if row:
        log_audit(user["username"], "Отозвано приглашение",
                  str(row["note"]) or "без пометки", ip=client_ip(request))
        message = "Приглашение отозвано"
    else:
        error = "Приглашение не найдено"

    return render("settings.html", request, user, active="settings",
                  message=message, error=error, diag=_diagnostics(),
                  **_users_context(request))


def _invite_page(request: Request, token: str, error: str | None = None,
                 status_code: int = 200):
    """Страница регистрации по приглашению. Общая для GET и неудачного POST."""
    lang = resolve_lang(request)
    invite = invites.find(token)
    return templates.TemplateResponse(
        request,
        "invite.html",
        {
            "lang": lang,
            "languages": i18n.available_languages(),
            "js_i18n": i18n.js_catalog(lang),
            "invite": invite,
            "token": token,
            "error": error,
        },
        status_code=status_code if invite else 404,
    )


@router.get("/invite/{token}")
async def invite_page(request: Request, token: str):
    """
    Регистрация по приглашению.

    Страница живёт внутри панели, а не в открытой части: ограничение по
    сетям на неё распространяется. Ссылка, улетевшая не туда, бесполезна
    тому, кто не попал в доверенную сеть, и это ровно тот запас прочности,
    которого не даёт один только секретный адрес.
    """
    if read_session(request):
        # Уже вошедшему регистрироваться незачем, а второй аккаунт себе
        # он бы завёл случайно
        return RedirectResponse("/", status_code=303)
    return _invite_page(request, token)


@router.post("/invite/{token}")
async def invite_submit(request: Request, token: str,
                        username: str = Form(""), password: str = Form(""),
                        password2: str = Form("")):
    """
    Создать учётную запись по приглашению и сразу впустить.

    Прав у неё нет ни одного. Регистрация это «человек завёл вход»,
    а не «человек получил доступ»: галочки выдаются руками, после.
    """
    invite = invites.find(token)
    if invite is None:
        return _invite_page(request, token, status_code=404)

    username = username.strip()
    if not username:
        return _invite_page(request, token, "Укажите имя пользователя", 400)
    if len(password) < 6:
        return _invite_page(request, token, "Пароль должен быть не короче 6 символов", 400)
    if password != password2:
        return _invite_page(request, token, "Пароли не совпадают", 400)
    if query_one("SELECT id FROM users WHERE username = ?", (username,)):
        return _invite_page(request, token, "Такое имя уже занято", 400)

    address = client_ip(request)
    execute(
        "INSERT INTO users (username, password_hash, created_at, permissions)"
        " VALUES (?,?,?,'')",
        (username, hash_password(password), utcnow()),
    )
    invites.consume(token, username, address)
    log_audit(username, "Регистрация по приглашению",
              str(invite["note"]) or "без пометки",
              "пригласил: %s" % invite["created_by"], address)

    user = query_one("SELECT * FROM users WHERE username = ?", (username,))
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, make_session_token(dict(user)))
    log_audit(username, "Вход в систему", ip=address)
    return response


@router.post("/settings/users/{user_id}/permissions")
async def save_permissions(request: Request, user_id: int,
                           user=Depends(require("users.manage"))):
    """
    Сохранить права и область видимости пользователя.

    Себе права урезать нельзя. Иначе первым же неверным нажатием можно
    запереть себя снаружи, и чинить придётся правкой базы на сервере.
    """
    from .. import permissions

    form = await request.form()
    error = message = None

    if user_id == user["id"]:
        error = "Свои права менять нельзя"
    else:
        target = query_one("SELECT username FROM users WHERE id = ?", (user_id,))
        if target is None:
            error = "Пользователь не найден"
        else:
            keys = form.getlist("perm")
            scope_all = form.get("scope_all") == "1"
            permissions.save(
                user_id,
                keys,
                scope_all,
                [int(g) for g in form.getlist("group")],
                [int(d) for d in form.getlist("device")],
            )
            log_audit(user["username"], "Изменены права", target["username"],
                      ", ".join(sorted(keys)) or "нет прав", ip=client_ip(request))
            message = f"Права пользователя {target['username']} сохранены"

    return render("settings.html", request, user, active="settings",
                  message=message, error=error, diag=_diagnostics(), **_users_context(request))


@router.post("/settings/users/{user_id}/password")
async def reset_user_password(request: Request, user_id: int,
                              password: str = Form(""),
                              user=Depends(require("users.manage"))):
    """
    Задать другому администратору новый пароль.

    Старый при этом не спрашивается: смысл сброса в том, что человек
    свой пароль как раз и не помнит. Право `users.manage` и так позволяет
    завести нового администратора с полными правами, так что ничего
    сверх этого сброс не даёт.

    Себе пароль так менять нельзя, для этого есть форма выше, и она
    спрашивает текущий. Разница не формальная: перехваченная сессия
    не должна давать возможность сменить пароль и закрепиться в панели,
    не зная прежнего.

    Все прежние входы этого человека завершаются. Сброшенный пароль,
    после которого чужая вкладка продолжает работать, бесполезен.
    """
    error = message = None
    target = query_one("SELECT id, username FROM users WHERE id = ?", (user_id,))

    if user_id == user["id"]:
        error = "Свой пароль меняйте через форму «Смена своего пароля»: она спросит текущий"
    elif target is None:
        error = "Пользователь не найден"
    elif len(password) < 6:
        error = "Пароль должен быть не короче 6 символов"
    else:
        execute("UPDATE users SET password_hash = ? WHERE id = ?",
                (hash_password(password), user_id))
        end_sessions(user_id)
        log_audit(user["username"], "Сброшен пароль администратора",
                  str(target["username"]), "прежние входы завершены", client_ip(request))
        message = f"Пароль пользователя {target['username']} изменён, прежние входы завершены"

    return render("settings.html", request, user, active="settings",
                  message=message, error=error, diag=_diagnostics(), **_users_context(request))


@router.post("/settings/users/{user_id}/delete")
async def delete_user(request: Request, user_id: int,
                      user=Depends(require("users.manage"))):
    """Удалить администратора (себя удалить нельзя, последнего — тоже)."""
    error = message = None
    total = query("SELECT id FROM users")
    if user_id == user["id"]:
        error = "Нельзя удалить собственную учётную запись"
    elif len(total) <= 1:
        error = "Нельзя удалить единственного администратора"
    else:
        execute("DELETE FROM users WHERE id = ?", (user_id,))
        log_audit(user["username"], "Удалён администратор", str(user_id), ip=client_ip(request))
        message = "Пользователь удалён"

    return render("settings.html", request, user, active="settings",
                  message=message, error=error, diag=_diagnostics(), **_users_context(request))


@router.post("/settings/operators")
async def name_operator(request: Request,
                        needle: str = Form(""),
                        name: str = Form(""),
                        color: str = Form("slate"),
                        user=Depends(require("devices.edit"))):
    """
    Назвать оператора по-человечески.

    Реестр отдаёт `RU-DANCER-20120101`, и в таблице это ничего не
    говорит. Правило запоминается в данных, поэтому обновление панели
    его не затрёт, и сразу применяется ко всем точкам этого провайдера.
    """
    operator.save_local(needle, name, color)
    touched = operator.rename_known()
    if name.strip():
        log_audit(user["username"], "Назван оператор", needle.strip(),
                  f"{name.strip()}, точек: {touched}", ip=client_ip(request))
        message = f"Оператор {needle.strip()} теперь называется {name.strip()}"
    else:
        log_audit(user["username"], "Убрано имя оператора", needle.strip(),
                  "", ip=client_ip(request))
        message = f"Имя для {needle.strip()} убрано"

    return render("settings.html", request, user, active="settings",
                  message=message, error=None, diag=_diagnostics(),
                  **_users_context(request))


def _back(request: Request, target: str) -> RedirectResponse:
    """Вернуться на ту же страницу, а не на общую. Свои страницы, чужие нет."""
    if not target.startswith("/") or target.startswith("//"):
        target = "/settings"
    return RedirectResponse(target, status_code=303)


@router.post("/demo/on")
async def demo_on(request: Request, next: str = Form("/settings"),
                  user=Depends(require("users.manage"))):
    """
    Включить режим витрины для этого браузера.

    Именно для браузера, а не для панели: остальные в это время работают
    с настоящими данными и ничего не замечают. Режим нужен тому, кто
    снимает экран, и мешать всем ради этого незачем.
    """
    response = _back(request, next)
    response.set_cookie(demo.COOKIE, "1", max_age=demo.HOURS * 3600,
                        httponly=True, samesite="lax")
    log_audit(user["username"], "Включён режим витрины", "",
              f"на {demo.HOURS} ч", ip=client_ip(request))
    return response


@router.post("/demo/off")
async def demo_off(request: Request, next: str = Form("/settings"),
                   user=Depends(current_user)):
    """
    Выключить режим витрины.

    Право здесь не нужно: выключение возвращает настоящие данные тому,
    кто их и так видит, а запертый в витрине человек это просто
    неудобство на ровном месте.
    """
    response = _back(request, next)
    response.delete_cookie(demo.COOKIE)
    return response
