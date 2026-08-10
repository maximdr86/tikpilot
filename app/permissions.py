"""
Права пользователей и область видимости.

Модель устроена как в MeshCentral: у пользователя не роль, а набор
галочек-возможностей плюс список объектов, к которым он допущен. Роли
остались только как пресеты в интерфейсе — нажал «Наблюдатель», галочки
проставились, дальше правь как хочешь.

Два независимых измерения:

* **Что человек умеет.** Набор ключей вида `devices.edit` или
  `action.reboot`. Каждое массовое действие автоматически превращается
  в отдельное право, поэтому оператору можно разрешить бэкапы и запретить
  перезагрузку.
* **С чем он это делает.** Пустая область видимости означает весь парк.
  Иначе видны только устройства из выбранных групп и отдельно
  перечисленные точки.

Важное правило: проверка живёт здесь и вызывается на сервере. Спрятать
кнопку в шаблоне это удобство, а не защита, поэтому каждый роут, который
что-то меняет или показывает чужие данные, обязан спросить разрешение сам.
"""

from __future__ import annotations

from typing import Any, Iterable

from .database import query, query_one

#: Полный доступ. Отдельный ключ, чтобы не перечислять все права поимённо
#: и чтобы новые возможности автоматически доставались администратору.
FULL = "full"

#: Права, не связанные с конкретными действиями над устройствами.
#: Ключ, раздел для группировки в интерфейсе, подпись, пояснение.
BASE_PERMISSIONS: list[tuple[str, str, str, str]] = [
    ("devices.edit", "Устройства", "Добавлять и изменять устройства",
     "Создание, правка карточки, удаление, импорт CSV."),
    ("devices.secrets", "Устройства", "Видеть и менять пароли устройств",
     "Без этого права поля пароля в карточке недоступны."),
    ("groups.manage", "Устройства", "Управлять группами",
     "Создание, переименование, удаление групп."),

    ("clients.view", "Устройства", "Видеть клиентов за роутерами",
     "Что подключено к площадкам: MAC, адреса, порты. Карта сети изнутри."),

    ("wireguard.manage", "Устройства", "Управлять связями WireGuard",
     "Создание и удаление линков между роутерами, маршруты и правила."),

    ("jobs.cancel", "Задачи", "Отменять задачи",
     "Свои и чужие. Уже начатые устройства доработают до конца."),
    ("jobs.schedule", "Задачи", "Откладывать запуск",
     "Ставить задачу на определённое время, например на 02:00."),

    ("backups.view", "Бэкапы", "Видеть список бэкапов",
     "Только перечень файлов, без содержимого."),
    ("backups.download", "Бэкапы", "Скачивать бэкапы",
     "В текстовом export лежит вся конфигурация: адреса, правила, ключи."),
    ("backups.delete", "Бэкапы", "Удалять бэкапы", ""),
    ("backups.schedule", "Бэкапы", "Настраивать расписание",
     "Создание и удаление правил автоматического снятия бэкапов."),
    ("panel.backup", "Бэкапы", "Архив всей панели",
     "В архиве база и ключ шифрования: из него достаются пароли всех роутеров."),

    ("terminal.use", "Устройства", "Терминал до устройства",
     "Полная командная строка RouterOS по SSH. Обходит подтверждения "
     "опасных действий: там достаточно опечатки. Всё набранное пишется "
     "в журнал действий."),
    ("syslog.view", "Система", "Видеть журнал устройств",
     "Строки syslog, присланные роутерами. Там бывают адреса и имена."),
    ("visits.view", "Система", "Видеть заходы по публичным ссылкам",
     "Кто открывал листы состояния: адрес, устройство, время. "
     "Сведения о людях, поэтому право отдельное."),
    ("console.view", "Система", "Видеть живую консоль",
     "Что панель делает прямо сейчас: проверки, задачи, ошибки устройств."),
    ("history.view", "Система", "Видеть журнал действий",
     "Кто, когда и что делал в системе."),
    ("settings.view", "Система", "Видеть настройки",
     "Состояние мониторинга, цели пинга, сведения о программе."),
    ("users.manage", "Система", "Управлять пользователями",
     "Создание учётных записей и выдача прав. Фактически полный контроль."),
]

#: Пресеты для кнопок в редакторе. Список ключей, а не отдельная сущность:
#: после нажатия человек волен править галочки дальше.
PRESETS: dict[str, list[str]] = {
    "viewer": [],
    "operator": [
        "backups.view", "history.view", "settings.view", "console.view",
        "clients.view", "syslog.view", "visits.view",
        "jobs.cancel", "jobs.schedule",
        "action.check", "action.check_updates", "action.backup",
    ],
    "admin": [FULL],
}

PRESET_LABELS = {
    "viewer": "Наблюдатель",
    "operator": "Оператор",
    "admin": "Администратор",
}


# ------------------------------------------------------------------ реестр
def action_permissions() -> list[tuple[str, str, str, str]]:
    """
    Права на массовые действия, по одному на каждое зарегистрированное.

    Собирается из реестра действий, поэтому новое действие само появляется
    в редакторе прав. Забыть его там невозможно.
    """
    from .actions import list_actions

    result = []
    for action in list_actions():
        note = "Необратимая операция." if action.dangerous else ""
        result.append((f"action.{action.name}", "Действия", action.label, note))
    return result


def all_permissions() -> list[tuple[str, str, str, str]]:
    """Все права: базовые плюс по действию на каждое массовое действие."""
    return BASE_PERMISSIONS + action_permissions()


def known_keys() -> set[str]:
    """Множество допустимых ключей. Всё остальное при сохранении отбрасывается."""
    return {FULL} | {key for key, *_ in all_permissions()}


# ------------------------------------------------------------- проверки
def parse(raw: Any) -> set[str]:
    """Строка из базы в множество прав."""
    return {part.strip() for part in str(raw or "").split(",") if part.strip()}


def dump(keys: Iterable[str]) -> str:
    """Множество прав в строку для базы, отбрасывая незнакомое."""
    allowed = known_keys()
    return ",".join(sorted(key for key in keys if key in allowed))


def has(user: dict[str, Any] | None, key: str) -> bool:
    """Есть ли у пользователя право. `full` перекрывает всё."""
    if not user:
        return False
    keys = user.get("permissions")
    if keys is None:
        keys = parse(user.get("permissions_raw"))
    return FULL in keys or key in keys


def can_run(user: dict[str, Any] | None, action_name: str) -> bool:
    """Разрешено ли пользователю запускать это массовое действие."""
    return has(user, f"action.{action_name}")


def allowed_actions(user: dict[str, Any] | None) -> list[Any]:
    """Действия, доступные пользователю. Остальные не показываем и не пускаем."""
    from .actions import list_actions

    return [a for a in list_actions() if can_run(user, a.name)]


# --------------------------------------------------------- область видимости
def load(user_id: int) -> dict[str, Any]:
    """Права и область видимости пользователя из базы."""
    row = query_one(
        "SELECT id, username, permissions, scope_all FROM users WHERE id = ?", (user_id,)
    )
    if row is None:
        return {"permissions": set(), "scope_all": True, "groups": set(), "devices": set()}

    return {
        "permissions": parse(row["permissions"]),
        "scope_all": bool(row["scope_all"]),
        "groups": {r["group_id"] for r in query(
            "SELECT group_id FROM user_groups WHERE user_id = ?", (user_id,))},
        "devices": {r["device_id"] for r in query(
            "SELECT device_id FROM user_devices WHERE user_id = ?", (user_id,))},
    }


def sees_everything(user: dict[str, Any] | None) -> bool:
    """Виден ли пользователю весь парк."""
    if not user:
        return False
    return bool(user.get("scope_all", True)) or has(user, FULL)


def scope_sql(user: dict[str, Any] | None, alias: str = "d") -> tuple[str, list[Any]]:
    """
    Кусок WHERE, ограничивающий выборку областью видимости.

    Возвращает пустую строку для тех, кто видит весь парк, поэтому вызов
    можно вставлять в любой запрос без условий вокруг.
    """
    if sees_everything(user):
        return "", []

    groups = sorted(user.get("groups") or ())
    devices = sorted(user.get("devices") or ())
    if not groups and not devices:
        # Область задана, но пуста: не видно ничего. Так и должно быть,
        # иначе урезанный пользователь случайно получил бы весь парк.
        return f" AND 0=1", []

    parts, params = [], []
    if groups:
        parts.append(f"{alias}.group_id IN (%s)" % ",".join("?" * len(groups)))
        params += groups
    if devices:
        parts.append(f"{alias}.id IN (%s)" % ",".join("?" * len(devices)))
        params += devices
    return " AND (%s)" % " OR ".join(parts), params


def visible_device_ids(user: dict[str, Any] | None) -> set[int] | None:
    """
    Идентификаторы видимых устройств. None означает «видно всё».

    None вместо полного списка возвращается намеренно: на парке в тысячи
    точек собирать множество ради проверки «можно ли» бессмысленно.
    """
    if sees_everything(user):
        return None

    where, params = scope_sql(user)
    rows = query(f"SELECT id FROM devices d WHERE 1=1{where}", tuple(params))
    return {r["id"] for r in rows}


def can_touch(user: dict[str, Any] | None, device_ids: Iterable[int]) -> bool:
    """Все ли указанные устройства попадают в область видимости."""
    visible = visible_device_ids(user)
    if visible is None:
        return True
    return set(int(i) for i in device_ids) <= visible


# -------------------------------------------------------------- сохранение
def save(user_id: int, permissions: Iterable[str], scope_all: bool,
         groups: Iterable[int], devices: Iterable[int]) -> None:
    """Записать права и область видимости."""
    from .database import execute

    execute(
        "UPDATE users SET permissions = ?, scope_all = ? WHERE id = ?",
        (dump(permissions), 1 if scope_all else 0, user_id),
    )
    execute("DELETE FROM user_groups WHERE user_id = ?", (user_id,))
    execute("DELETE FROM user_devices WHERE user_id = ?", (user_id,))
    if not scope_all:
        for group_id in {int(g) for g in groups}:
            execute("INSERT OR IGNORE INTO user_groups (user_id, group_id) VALUES (?,?)",
                    (user_id, group_id))
        for device_id in {int(d) for d in devices}:
            execute("INSERT OR IGNORE INTO user_devices (user_id, device_id) VALUES (?,?)",
                    (user_id, device_id))
