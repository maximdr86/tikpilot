"""
Реестр массовых действий.

КАК ДОБАВИТЬ НОВОЕ ДЕЙСТВИЕ
---------------------------
Достаточно описать его прямо здесь — интерфейс, форма параметров и запуск
подхватятся автоматически:

    @register(
        name="disable_wifi",
        label="Выключить Wi-Fi",
        description="Отключает все беспроводные интерфейсы",
        icon="wifi-off",
        dangerous=True,
        params=[ActionParam("confirm_text", "Комментарий", "text")],
    )
    def act_disable_wifi(mt, device, params):
        for iface in mt.cmd("/interface/wireless/print"):
            mt.cmd("/interface/wireless/set", **{".id": iface[".id"], "disabled": "yes"})
        return "Wi-Fi выключен"

Обработчик получает открытое соединение `mt` (класс MikroTik), строку
устройства из БД и словарь параметров. Он должен вернуть строку-результат
либо бросить DeviceError — воркер сам запишет это в историю.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .config import settings
from .database import execute, utcnow
from .mikrotik import DeviceError, MikroTik, flatten_rows, is_newer, safe_filename


# --------------------------------------------------------------------- модели
@dataclass
class ActionParam:
    """Описание одного поля формы параметров действия."""

    name: str
    label: str
    type: str = "text"  # text | textarea | checkbox | select | password
    required: bool = False
    default: str = ""
    placeholder: str = ""
    help: str = ""
    options: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Action:
    """Массовое действие, доступное в интерфейсе."""

    name: str
    label: str
    description: str
    handler: Callable[[MikroTik, dict[str, Any], dict[str, Any]], str]
    icon: str = "play"
    dangerous: bool = False
    params: list[ActionParam] = field(default_factory=list)
    # Действие обрывает соединение (перезагружает устройство). Для таких
    # постоянная сессия после выполнения закрывается — она всё равно мертва.
    disrupts_connection: bool = False
    # Нужно ли открывать соединение с устройством (пока всегда да,
    # но флаг оставлен для будущих локальных действий)
    needs_connection: bool = True
    # Действие написано и покрыто тестами на заглушке, но на живом парке
    # ещё не проверялось. Честно говорим об этом в форме: заглушка ловит
    # ошибки протокола, а не различия между версиями RouterOS и не то,
    # как поведёт себя конкретная плата. Снимается после первой удачной
    # проверки на настоящем устройстве.
    untested: bool = False


REGISTRY: dict[str, Action] = {}


def register(**kwargs: Any) -> Callable:
    """Декоратор регистрации действия в реестре."""

    def wrapper(func: Callable) -> Callable:
        action = Action(handler=func, **kwargs)
        REGISTRY[action.name] = action
        return func

    return wrapper


def get_action(name: str) -> Action:
    """Получить действие по имени (или бросить ValueError)."""
    if name not in REGISTRY:
        raise ValueError(f"Неизвестное действие: {name}")
    return REGISTRY[name]


def list_actions() -> list[Action]:
    """Все действия в порядке объявления — используется для отрисовки меню."""
    return list(REGISTRY.values())


def describe_params(action: Action, params: dict[str, Any]) -> str:
    """
    Параметры запуска человеческим языком, для журнала действий.

    Раньше туда клался JSON как есть, и в истории стояло `{"channel":
    "long-term"}`, а у действий без параметров и вовсе `{}`. Пустая пара
    скобок это чистый мусор на экране, а JSON человек читает медленнее,
    чем свою же подпись поля.

    Названия полей берутся на языке исходников: строка уходит в базу
    целиком и переводу по частям не поддаётся. Это осознанный размен,
    в остальном журнал действий и так хранится как есть.
    """
    labels = {p.name: p for p in action.params}
    parts: list[str] = []

    for name, value in params.items():
        # Пароли в журнал не попадают ни при каких обстоятельствах
        if "password" in name:
            continue
        text = str(value).strip()
        if not text:
            continue

        param = labels.get(name)
        if param is None:
            parts.append(f"{name}: {text}")
            continue

        if param.type == "checkbox":
            text = "да" if text in ("1", "true", "yes", "on") else "нет"
        elif param.options:
            # У выпадающих списков в журнале должна стоять подпись,
            # а не внутреннее значение вроде «bsd-syslog». Но только если
            # подпись короткая: у каналов обновлений там целое пояснение
            # на строку, и в журнале от него больше вреда, чем пользы.
            label = dict(param.options).get(text, text)
            text = label if len(label) <= 24 else text

        # Код скрипта или список сетей может быть на экран длиной,
        # а журнал читают строкой
        if len(text) > 120:
            text = text[:117] + "..."

        parts.append(f"{param.label}: {text}")

    return " · ".join(parts)


# ================================================================ ДЕЙСТВИЯ ===


@register(
    name="check",
    label="Проверить статус",
    description="Подключиться и обновить версию RouterOS, uptime и модель",
    icon="activity",
)
def act_check(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    """Опрос устройства. Кэш в таблице devices обновляет сам воркер."""
    # Воркер уже опросил /system/resource при подключении — переиспользуем.
    info = device.get("_info") or mt.system_info()
    return (
        f"RouterOS {info.get('ros_version', '?')}, "
        f"{info.get('board_name', '?')}, "
        f"uptime {info.get('uptime', '?')}, "
        f"CPU {info.get('cpu_load', '?')}%"
    )


@register(
    name="reboot",
    label="Перезагрузить",
    description="Отправить команду /system/reboot",
    icon="power",
    dangerous=True,
    disrupts_connection=True,
)
def act_reboot(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    """Перезагрузка. Обрыв соединения после команды — нормальная ситуация."""
    mt.cmd_fire_and_forget("/system/reboot")
    return "Команда перезагрузки отправлена"


@register(
    name="run_script",
    label="Запустить скрипт по имени",
    description="Выполнить скрипт, который уже сохранён на устройстве",
    icon="file-code",
    dangerous=True,
    params=[
        ActionParam(
            "script_name",
            "Имя скрипта на устройстве",
            "text",
            required=True,
            placeholder="например: backup-nightly",
        ),
        ActionParam(
            "wait_seconds",
            "Ждать выполнения, секунд",
            "text",
            default="120",
            help="RouterOS не отвечает, пока скрипт не отработает. "
                 "Для бэкапов и выгрузок конфигурации ставьте с запасом.",
        ),
    ],
)
def act_run_script(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    return mt.run_script_by_name(
        params["script_name"].strip(),
        wait_seconds=_as_int(params.get("wait_seconds"), 120),
    )


@register(
    name="run_source",
    label="Выполнить код скрипта",
    description="Вставить код RouterOS-скрипта и выполнить его на устройствах",
    icon="terminal",
    dangerous=True,
    params=[
        ActionParam(
            "source",
            "Код скрипта",
            "textarea",
            required=True,
            placeholder=':log info "hello from Tikpilot"',
            help="Код будет загружен как временный скрипт, выполнен и удалён.",
        ),
        ActionParam(
            "keep_name",
            "Сохранить на устройстве под именем",
            "text",
            placeholder="оставьте пустым, чтобы не сохранять",
        ),
        ActionParam(
            "wait_seconds",
            "Ждать выполнения, секунд",
            "text",
            default="120",
            help="RouterOS не отвечает, пока скрипт не отработает.",
        ),
    ],
)
def act_run_source(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    keep = (params.get("keep_name") or "").strip() or None
    return mt.run_source(
        params["source"],
        keep_name=keep,
        wait_seconds=_as_int(params.get("wait_seconds"), 120),
    )


@register(
    name="upload_script",
    label="Загрузить скрипт (без запуска)",
    description="Создать или обновить скрипт на устройствах, не выполняя его",
    icon="upload",
    params=[
        ActionParam("script_name", "Имя скрипта", "text", required=True),
        ActionParam("source", "Код скрипта", "textarea", required=True),
        ActionParam(
            "policy",
            "Политики",
            "text",
            default="read,write,policy,test,ftp,reboot",
            help="Список политик RouterOS через запятую.",
        ),
    ],
)
def act_upload_script(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    policy = (params.get("policy") or "read,write,policy,test").strip()
    return mt.upload_script(params["script_name"].strip(), params["source"], policy)


@register(
    name="remove_script",
    label="Удалить скрипт или расписание",
    description="Снять с точек скрипт или расписание с указанным именем",
    icon="trash-2",
    dangerous=True,
    params=[
        ActionParam("script_name", "Имя на устройстве", "text", required=True),
        ActionParam(
            "kind",
            "Что удалять",
            "select",
            default="script",
            options=[
                ("script", "скрипт"),
                ("scheduler", "расписание"),
                ("both", "и скрипт, и расписание с этим именем"),
            ],
            help="Расписание обычно называется иначе, чем скрипт, который "
                 "оно вызывает. Удалив только скрипт, вы оставите расписание "
                 "звать пустоту, и наоборот.",
        ),
    ],
)
def act_remove_script(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    """
    Удалить с точки скрипт или расписание по имени.

    Паспорт устройства правится сразу, не дожидаясь следующего обхода:
    иначе в разделе «Скрипты» удалённое висело бы до утра, а человек
    решал бы, что удаление не сработало, и жал кнопку второй раз.
    """
    from .database import execute_changes

    name = str(params.get("script_name") or "").strip()
    if not name:
        raise ValueError("Не указано имя")

    kinds = ["script", "scheduler"] if params.get("kind") == "both" else \
        [str(params.get("kind") or "script")]

    removed: list[str] = []
    for kind in kinds:
        count = mt.remove_named(name, kind)
        if count:
            word = "расписание" if kind == "scheduler" else "скрипт"
            removed.append(f"{word}: {count}" if count > 1 else word)
            execute_changes(
                "DELETE FROM device_scripts WHERE device_id = ? AND name = ? AND kind = ?",
                (device["id"], name, kind),
            )

    if not removed:
        return f"«{name}»: на этой точке не было, удалять нечего"
    return f"Удалено «{name}» ({', '.join(removed)})"


@register(
    name="command",
    label="Команда по API",
    description="Вызов API по имени и параметрам: точный ответ таблицей",
    icon="chevrons-right",
    dangerous=True,
    params=[
        ActionParam(
            "command",
            "Команда",
            "text",
            required=True,
            placeholder="/ip/address/print",
            help="Синтаксис API, а не консоли: путь через слэши, параметры "
                 "отдельно. Консольную команду выполняет действие "
                 "«Команда как в терминале (SSH)».",
        ),
        ActionParam(
            "arguments",
            "Аргументы (по одному в строке, вида ключ=значение)",
            "textarea",
            placeholder="interface=ether1\ndisabled=yes",
        ),
    ],
)
def act_command(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    command = params["command"].strip()
    if not command.startswith("/"):
        command = "/" + command
    kwargs = _parse_kv(params.get("arguments", ""))
    rows = mt.cmd(command, **kwargs)
    return flatten_rows(rows)


@register(
    name="cli",
    label="Команда как в терминале (SSH)",
    description="Выполнить команду в консольном синтаксисе RouterOS, как в Winbox",
    icon="terminal",
    dangerous=True,
    params=[
        ActionParam(
            "script",
            "Команды",
            "textarea",
            required=True,
            placeholder="/ip service\nset api address=192.168.0.0/16,10.0.0.0/8",
            help="Пишите как в терминале. Переносы длинных строк обратным слэшем "
                 "склеиваются сами, путь меню запоминается для следующих строк.",
        ),
        ActionParam(
            "stop_on_error",
            "Останавливаться на первой ошибке",
            "checkbox",
            default="1",
            help="Выключайте, только если команды независимы друг от друга.",
        ),
    ],
)
def act_cli(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    """
    Команда в консольном синтаксисе, через SSH.

    Единственное действие, которое не пользуется открытой сессией API:
    консольный синтаксис разбирает сам RouterOS, и другого способа
    выполнить его нет. Соединение SSH разовое, на время задачи.

    Требует у пользователя RouterOS политику `ssh`. Панели для всего
    остального хватает `api`, и это стоит помнить: действие честно
    скажет об этом в результате, а не притворится недоступным.
    """
    from . import cli as console
    from .terminal import TerminalError, connect

    commands = console.parse(params.get("script", ""))
    if not commands:
        raise DeviceError("Нечего выполнять: в поле только пустые строки")

    try:
        client = connect(device)
    except TerminalError as exc:
        raise DeviceError(str(exc)) from exc

    try:
        output, failed = console.run(
            client, commands,
            stop_on_error=str(params.get("stop_on_error", "1")) not in ("0", "", "false"),
        )
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001 — закрытие не должно ронять задачу
            pass

    if failed:
        # Ошибку поднимаем наверх вместе с выводом: без вывода человек
        # не поймёт, какая из строк не прошла и почему
        raise DeviceError(output)
    return output


@register(
    name="safe_change",
    label="Изменение со страховкой",
    description="Применить команды и откатиться самому, если не подтвердить",
    icon="shield-check",
    dangerous=True,
    params=[
        ActionParam(
            "script",
            "Команды",
            "textarea",
            required=True,
            placeholder="/ip firewall filter\nadd chain=input action=drop",
            help="Тот же консольный синтаксис, что и в обычной команде по SSH. "
                 "Страховка взводится на каждой выбранной точке отдельно, "
                 "и подтверждать надо тоже каждую: на дашборде есть кнопка "
                 "«Подтвердить все». Если просто смотрите, как это работает, "
                 "берите одну точку, которую не жалко перезагрузить.",
        ),
        ActionParam(
            "minutes",
            "Через сколько откатиться",
            "select",
            default="10",
            options=[("5", "5 минут"), ("10", "10 минут"), ("20", "20 минут"),
                     ("40", "40 минут"), ("60", "час")],
            help="Столько у вас есть, чтобы проверить точку и подтвердить.",
        ),
        ActionParam(
            "confirm",
            "Кто подтверждает",
            "select",
            default="panel",
            options=[
                ("panel", "Панель, если сможет подключиться заново"),
                ("me", "Я сам, панель дождётся"),
            ],
            help="Панель проверяет только одно: не закрыли ли вы себе доступ. "
                 "Сеть за роутером она не видит, поэтому для правил forward, "
                 "NAT, DHCP и портов моста берите второй вариант и посмотрите "
                 "сами. Но помните: если забыть, точка перезагрузится.",
        ),
    ],
)
def act_safe_change(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    """
    Изменение, которое устройство отменит само, если его не подтвердить.

    Порядок именно такой и другим быть не может: сначала снимок и
    отложенный откат, только потом изменение. Наоборот означало бы, что
    в промежутке между применением и взведением страховки её нет ровно
    тогда, когда она нужна.
    """
    from . import cli as console
    from . import rollback
    from .terminal import TerminalError, connect

    commands = console.parse(params.get("script", ""))
    if not commands:
        raise DeviceError("Нечего выполнять: в поле только пустые строки")

    minutes = int(params.get("minutes") or rollback.DEFAULT_MINUTES)
    username = str(params.get("_username") or "")

    try:
        armed = rollback.arm(mt, device, minutes, username,
                             note=commands[0][:200])
    except rollback.RollbackError as exc:
        raise DeviceError(str(exc)) from exc

    # Команды идут по SSH: консольный синтаксис разбирает сам RouterOS
    try:
        client = connect(device)
    except TerminalError as exc:
        rollback.confirm(mt, int(device["id"]), username, "изменение не применялось")
        raise DeviceError(str(exc)) from exc

    try:
        output, failed = console.run(client, commands, stop_on_error=True)
    finally:
        try:
            client.close()
        except Exception:  # noqa: BLE001
            pass

    deadline = _local_time(armed.get("expires_at"))

    if failed:
        # Команда не прошла. Это не повод оставлять взведённый откат
        # на устройстве, до которого мы достучались: ошибка в синтаксисе
        # превратилась бы в перезагрузку точки через десять минут, а
        # чинить синтаксис человек будет всё равно руками.
        #
        # Критерий тот же, что и при успехе, и это не совпадение: режим
        # подтверждения отвечает на вопрос «кто судит», а не «что судим».
        if _panel_confirms(params) and _still_answers(device):
            rollback.confirm(mt, int(device["id"]), username,
                             "команда не прошла, доступ остался")
            raise DeviceError(
                "%s\n\nСтраховка снята: доступ к устройству остался, "
                "перезагружать его из-за неудачной команды незачем." % output)
        raise DeviceError(
            "%s\n\nСтраховка оставлена взведённой, откат в %s."
            % (output, deadline))

    if _panel_confirms(params):
        if _still_answers(device):
            rollback.confirm(mt, int(device["id"]), username, "устройство ответило")
            # Честно говорим, что именно проверено: панель смогла войти
            # заново, и только это. Сеть за роутером она не видела
            return (f"{output}\n\nПодключение заново удалось, страховка снята. "
                    "Проверено только то, что доступ к роутеру остался.")
        return (f"{output}\n\nПодключиться заново не удалось. "
                f"Страховка оставлена, откат в {deadline}.")

    return (f"{output}\n\nСтраховка взведена: подтвердите изменение до {deadline}, "
            "иначе устройство откатится само и перезагрузится.")


def _local_time(value: Any) -> str:
    """
    Время из базы (UTC) в местное, для текста, который прочитает человек.

    Результат действия сохраняется строкой и потом показывается как есть,
    мимо шаблонных фильтров. Пока здесь стоял UTC, событие в 18:49 честно
    сообщало «подтвердите до 11:54», то есть на семь часов раньше, чем
    произошло. Срок страховки читают в спешке, и такой текст означает
    ровно одно: человек решит, что уже поздно, и не подтвердит.
    """
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        moment = datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return text
    return moment.astimezone().strftime("%d.%m.%Y %H:%M:%S")


def _panel_confirms(params: dict[str, Any]) -> bool:
    """
    Подтверждает ли панель сама.

    По умолчанию да, и это важнее, чем кажется. Цена забывчивости в двух
    режимах разная: если ждать человека, забытая страховка перезагружает
    точку, то есть делает хуже, чем если бы страховкой не пользовались
    вовсе. Если подтверждает панель, забывчивость кончается тем же, чем
    обычная команда по SSH: изменение осталось, никто не перезагрузился.
    Умолчанием должен быть тот режим, у которого промах дешевле.

    Старое имя параметра понимаем тоже: задачи, созданные до этой правки,
    могут повторяться из истории.
    """
    if "confirm" in params:
        return str(params.get("confirm") or "panel") != "me"
    if "auto_confirm" in params:
        return str(params.get("auto_confirm") or "") in ("1", "true", "yes", "on", "да")
    # Параметра нет вовсе: вызов из кода или задача, созданная до правки.
    # Умолчание то же самое, что в форме, иначе оно перестанет быть
    # умолчанием ровно там, где никто не смотрит
    return True


#: Пауза перед проверкой связи после изменения. Отдельной константой,
#: чтобы тесты не ждали её по-настоящему: проверяется логика, а не sleep.
CONFIRM_PAUSE = 5.0


def _still_answers(device: dict[str, Any], attempts: int = 2,
                   pause: float | None = None) -> bool:
    """
    Сможем ли мы подключиться к устройству заново после изменения.

    Именно заново, новым соединением, а не проверкой уже открытого. Это
    принципиально: RouterOS применяет и правила input, и ограничения
    `/ip service` по адресам к **новым** подключениям, а установленное
    живёт дальше. Проверка старой сессией отвечала бы «всё хорошо» ровно
    в том случае, ради которого страховка и заводилась: человек закрыл
    себе доступ, соединение ещё держится, панель радостно снимает откат.

    Пауза перед проверкой нужна потому, что часть изменений применяется
    не мгновенно: интерфейс успевает моргнуть, туннель пересобраться.
    Две попытки по пять секунд, дальше ждать смысла нет, страховка всё
    равно сработает сама.
    """
    from .crypto import decrypt

    pause = CONFIRM_PAUSE if pause is None else pause
    for _ in range(max(1, attempts)):
        time.sleep(pause)
        try:
            with MikroTik(device, decrypt(device["password_enc"]), timeout=8) as fresh:
                if fresh.cmd("/system/identity/print"):
                    return True
        except Exception:  # noqa: BLE001 — любая ошибка это «не отвечает»
            continue
    return False


@register(
    name="set_identity",
    label="Задать identity",
    description="Установить системное имя устройства (поддерживается шаблон {name})",
    icon="tag",
    params=[
        ActionParam(
            "identity",
            "Новое имя",
            "text",
            required=True,
            default="{name}",
            help="Подстановки: {name} это имя из Tikpilot, {host} адрес, {group} группа.",
        )
    ],
)
def act_set_identity(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    value = (
        params["identity"]
        .replace("{name}", device.get("name", ""))
        .replace("{host}", device.get("host", ""))
        .replace("{group}", device.get("group_name") or "")
    ).strip()
    mt.cmd("/system/identity/set", **{"name": value})
    return f"Identity установлен: {value}"


@register(
    name="logging_to_panel",
    label="Слать журнал в панель",
    description="Настроить на устройстве отправку syslog на адрес панели",
    icon="scroll-text",
    params=[
        ActionParam(
            "address", "Адрес панели", "text", required=True,
            help="Адрес, по которому роутер видит панель. Обычно её адрес в туннеле.",
        ),
        ActionParam("port", "Порт", "text", default="5514"),
        ActionParam(
            "protocol", "Протокол", "select", default="udp",
            options=[("udp", "UDP"), ("tcp", "TCP")],
            help="UDP ничего не ждёт и на плохом канале теряет часть строк, "
                 "TCP не теряет, но держит соединение.",
        ),
        ActionParam(
            "log_format", "Формат", "select", default="cef",
            options=[("cef", "CEF"), ("bsd-syslog", "BSD syslog")],
            help="CEF проверен на живом парке и работает надёжнее. "
                 "BSD оставлен на случай, если понадобится обычный вид строки.",
        ),
        ActionParam(
            "topics", "Темы", "text", default="info,error,warning,critical",
            help="Что отправлять. Через запятую, как в /system logging. "
                 "«debug» лучше не включать: на плохом канале это поток впустую.",
        ),
    ],
)
def act_logging_to_panel(mt: MikroTik, device: dict[str, Any],
                         params: dict[str, Any]) -> str:
    """
    Прописать отправку журнала в панель.

    Правило и получатель называются одинаково и узнаваемо, поэтому повторный
    запуск не плодит дубли, а переписывает своё. Чужие настройки логирования
    не трогаются вообще: на точке может стоять отправка ещё куда-то, и снести
    её молча было бы свинством.
    """
    address = str(params.get("address") or "").strip()
    if not address:
        raise DeviceError("Не указан адрес панели")

    port = str(params.get("port") or "5514").strip()
    protocol = "tcp" if str(params.get("protocol")).lower() == "tcp" else "udp"
    topics = [t.strip() for t in str(params.get("topics") or "info").split(",") if t.strip()]
    if not topics:
        topics = ["info"]

    name = "tikpilot"
    # Обязательные поля: их понимают и шестая версия, и седьмая
    fields = {
        "name": name,
        "target": "remote",
        "remote": address,
        "remote-port": port,
        "remote-protocol": protocol,
    }

    # Фильтруем в Python, а не запросом: набор поддерживаемых фильтров
    # у RouterOS 6 и 7 различается, а список получателей журнала короткий
    actions = mt.cmd("/system/logging/action/print")
    existing = [a for a in actions if str(a.get("name") or "") == name]
    if existing:
        action_id = str(existing[0].get(".id") or "")
        mt.cmd("/system/logging/action/set", **{".id": action_id},
               **{k: v for k, v in fields.items() if k != "name"})
        what = "обновлён"
    else:
        mt.cmd("/system/logging/action/add", **fields)
        created = [a for a in mt.cmd("/system/logging/action/print")
                   if str(a.get("name") or "") == name]
        action_id = str(created[0].get(".id") or "") if created else ""
        what = "создан"

    # Формат сообщений задаётся по-разному в разных версиях: в седьмой это
    # remote-log-format, в шестой отдельный флаг bsd-syslog. Спрашивать
    # версию не нужно: пробуем и молча пропускаем то, чего эта версия
    # не знает. Нужен BSD-формат, а не CEF: панель разбирает именно его,
    # и человеку в нём видно то же, что и в журнале самого роутера.
    # Адрес отправителя закрепляем за тем, по которому панель знает точку.
    # Иначе роутер возьмёт адрес того интерфейса, через который лежит
    # маршрут до панели (в туннеле это его туннельный адрес), панель
    # не узнает отправителя и молча отбросит строки.
    # Формат сообщений. По умолчанию CEF: именно он проверен на живом парке,
    # а с форматом по умолчанию строки до панели не доходили. Почему так,
    # до конца не выяснено, поэтому здесь стоит то, что работает, а не то,
    # что должно работать по документации.
    log_format = str(params.get("log_format") or "cef").strip().lower()
    if log_format not in ("cef", "bsd-syslog"):
        log_format = "cef"

    extras = [("src-address", str(device.get("host") or "").strip()),
              ("remote-log-format", log_format)]
    if log_format == "bsd-syslog":
        # В шестой версии того же добивались отдельным флагом
        extras.append(("bsd-syslog", "yes"))
    extras.append(("syslog-facility", "daemon"))

    applied: list[str] = []
    skipped: list[str] = []
    if action_id:
        for key, value in extras:
            if not value:
                continue
            if key == "bsd-syslog" and "remote-log-format" in applied:
                continue        # седьмая версия, второй флаг здесь лишний
            try:
                mt.cmd("/system/logging/action/set", **{".id": action_id, key: value})
                applied.append(key)
            except DeviceError:
                # Этой версии такой параметр незнаком. Молчать об этом нельзя:
                # именно так «настроено, а журнал пустой» и получается
                skipped.append(key)

    # Правила: по одному на тему, чтобы можно было выключить лишнее руками
    rules = [r for r in mt.cmd("/system/logging/print")
             if str(r.get("action") or "") == name]
    have = {str(r.get("topics") or "") for r in rules}
    added = 0
    for topic in topics:
        if topic in have:
            continue
        mt.cmd("/system/logging/add", action=name, topics=topic)
        added += 1

    result = (f"Получатель {what}: {address}:{port}/{protocol}, формат {log_format}, "
              f"правил добавлено: {added}, всего тем: {len(have) + added}")
    if skipped:
        result += ". Не приняты этой версией RouterOS: " + ", ".join(skipped)
    return result


#: Встроенные получатели журнала RouterOS. Их удаление ломает журнал
#: на самом устройстве, поэтому имя проверяется, даже если его ввёл человек.
BUILTIN_LOG_ACTIONS = {"memory", "disk", "echo", "remote"}


@register(
    name="logging_off",
    label="Перестать слать журнал",
    description="Убрать с устройства получателя и правила, созданные панелью",
    icon="scroll",
    params=[
        ActionParam(
            "name", "Имя получателя", "text", default="tikpilot",
            help="Панель создаёт получателя с именем tikpilot. Другие "
                 "настройки логирования не трогаются: на точке может стоять "
                 "отправка ещё куда-то.",
        ),
    ],
)
def act_logging_off(mt: MikroTik, device: dict[str, Any],
                    params: dict[str, Any]) -> str:
    """
    Отменить отправку журнала в панель.

    Убирается только своё, по имени получателя. Чужие правила остаются
    как были: у человека может быть свой сборщик, и снести его заодно
    было бы предательством доверия.
    """
    name = str(params.get("name") or "tikpilot").strip()
    if not name:
        raise DeviceError("Не указано имя получателя")
    if name in BUILTIN_LOG_ACTIONS:
        raise DeviceError(
            f"«{name}» это встроенный получатель RouterOS, удалять его нельзя")

    # Сначала правила, потом получатель: пока на него ссылаются,
    # RouterOS удалить его не даст
    rules = [r for r in mt.cmd("/system/logging/print")
             if str(r.get("action") or "") == name]
    for rule in rules:
        mt.cmd("/system/logging/remove", **{".id": rule[".id"]})

    actions = [a for a in mt.cmd("/system/logging/action/print")
               if str(a.get("name") or "") == name]
    for action in actions:
        mt.cmd("/system/logging/action/remove", **{".id": action[".id"]})

    if not rules and not actions:
        return f"Отправки с именем «{name}» на устройстве не было"
    return f"Убрано: правил {len(rules)}, получателей {len(actions)}"


@register(
    name="backup",
    label="Снять бэкап",
    description="Создать binary-бэкап и текстовый export, скачать их на сервер по FTP",
    icon="hard-drive-download",
    params=[
        ActionParam("do_binary", "Бинарный бэкап (.backup)", "checkbox", default="1"),
        ActionParam("do_export", "Текстовый экспорт (.rsc)", "checkbox", default="1"),
        ActionParam(
            "show_sensitive",
            "Включать пароли в export (show-sensitive)",
            "checkbox",
        ),
        ActionParam(
            "backup_password",
            "Пароль бэкапа",
            "password",
            placeholder="пусто: без шифрования (dont-encrypt)",
        ),
        ActionParam("cleanup", "Удалить файлы с устройства после скачивания", "checkbox", default="1"),
    ],
)
def act_backup(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    """Снятие бэкапа как отдельное массовое действие."""
    return _run_backup(mt, device, params)


def _run_backup(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    """
    Полный цикл резервного копирования:
    создать файлы на устройстве → дождаться их появления → скачать по FTP →
    убрать за собой.

    Вынесено в отдельную функцию, потому что используется ещё и обновлением
    RouterOS (бэкап перед установкой).
    """
    do_binary = _as_bool(params.get("do_binary", True))
    do_export = _as_bool(params.get("do_export", True))
    cleanup = _as_bool(params.get("cleanup", True))
    sensitive = _as_bool(params.get("show_sensitive", False))
    bpassword = (params.get("backup_password") or "").strip()

    if not do_binary and not do_export:
        raise DeviceError("Не выбран ни один тип бэкапа")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"tikpilot-{stamp}"

    dev_dir = _device_backup_dir(device)
    results: list[str] = []

    # --- бинарный бэкап ----------------------------------------------------
    if do_binary:
        args: dict[str, Any] = {"name": base}
        if bpassword:
            args["password"] = bpassword
        else:
            args["dont-encrypt"] = "yes"
        mt.cmd("/system/backup/save", **args)
        remote = f"{base}.backup"
        _wait_for_file(mt, remote)
        local = dev_dir / f"{safe_filename(device['name'])}_{stamp}.backup"
        size = mt.download_via_ftp(remote, local)
        _record_backup(device, "binary", local, size, params.get("_job_id"))
        results.append(f"{local.name} ({_kb(size)})")
        if cleanup:
            mt.remove_file(remote)

    # --- текстовый экспорт --------------------------------------------------
    if do_export:
        args = {"file": base}
        if sensitive:
            args["show-sensitive"] = "yes"
        try:
            mt.cmd("/export", **args)
        except DeviceError:
            # На части версий RouterOS флаг show-sensitive недоступен — повтор без него
            mt.cmd("/export", **{"file": base})
        remote = f"{base}.rsc"
        _wait_for_file(mt, remote)
        local = dev_dir / f"{safe_filename(device['name'])}_{stamp}.rsc"
        size = mt.download_via_ftp(remote, local)
        _record_backup(device, "export", local, size, params.get("_job_id"))
        results.append(f"{local.name} ({_kb(size)})")
        if cleanup:
            mt.remove_file(remote)

    return "Сохранено: " + ", ".join(results)


# ---------------------------------------------------------- обновление ROS ---
CHANNELS = [
    ("", "не менять (как настроено на устройстве)"),
    ("long-term", "long-term: только исправления, максимальная стабильность"),
    ("stable", "stable: обычная ветка"),
    ("testing", "testing: свежее, для лабораторных стендов"),
]


@register(
    name="check_updates",
    label="Проверить обновления RouterOS",
    description="Узнать текущую и доступную версию, ничего не устанавливая",
    icon="search",
    params=[
        ActionParam(
            "channel", "Канал обновлений", "select",
            options=CHANNELS,
            help="Если выбрать канал, он будет записан на устройство перед проверкой.",
        ),
    ],
)
def act_check_updates(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    """
    Безопасная разведка перед массовым обновлением.

    Устройство само ходит на серверы MikroTik, поэтому нужен доступ в интернет.
    Результат складывается в карточку устройства — в списке появится метка
    «доступно обновление».
    """
    channel = (params.get("channel") or "").strip()
    info = mt.update_info(set_channel=channel)

    installed = info.get("installed-version", "")
    latest = info.get("latest-version", "")
    status = info.get("status", "")

    # Кладём результат в device — воркер перенесёт его в базу
    device["_update"] = {
        "latest_version": latest,
        "update_status": status,
        "update_channel": info.get("channel", ""),
    }

    if not latest:
        raise DeviceError(f"Не удалось проверить обновления: {status or 'нет ответа'}")

    channel_name = info.get("channel", "?")
    if _same_version(installed, latest):
        return f"Актуальная версия {installed} (канал {channel_name})"
    if is_newer(latest, installed):
        return f"Доступно обновление: {installed} → {latest} (канал {channel_name})"
    # Установлена версия новее, чем есть в выбранном канале.
    # Обычная ситуация при переключении stable → long-term.
    return (
        f"Установлена {installed}, она новее, чем {latest} в канале {channel_name}. "
        "Обновлять нечего; переход на эту версию был бы откатом назад."
    )


@register(
    name="upgrade_ros",
    label="Обновить RouterOS",
    description="Скачать и установить обновление с перезагрузкой и проверкой результата",
    icon="arrow-up-circle",
    dangerous=True,
    disrupts_connection=True,
    params=[
        ActionParam(
            "channel", "Канал обновлений", "select",
            options=CHANNELS,
            default="long-term",
            help="long-term рекомендуется для рабочих точек.",
        ),
        ActionParam(
            "make_backup", "Снять бэкап перед обновлением", "checkbox", default="1",
            help="Бинарный бэкап и export скачиваются на сервер до установки.",
        ),
        ActionParam(
            "download_timeout", "Ждать загрузки пакетов, секунд", "text", default="1800",
            help="Загрузка идёт без перезагрузки, устройство всё это время работает. "
                 "На тонком канале ставьте с запасом: 1800 с это 30 минут.",
        ),
        ActionParam(
            "wait_back", "Ждать возврата устройства, секунд", "text", default="420",
            help="0: не ждать. Обычная перезагрузка занимает 60–180 секунд.",
        ),
        ActionParam(
            "upgrade_routerboard", "Обновить также загрузчик RouterBOOT", "checkbox",
            help="Требует ещё одной перезагрузки. Делайте, когда есть доступ к точке.",
        ),
        ActionParam(
            "batch_size", "Обновлять пачками по, устройств", "text", default="5",
            help="0: все сразу. Пачками безопаснее: успеете остановиться, если что-то пойдёт не так.",
        ),
        ActionParam(
            "batch_pause", "Пауза между пачками, секунд", "text", default="120",
        ),
    ],
)
def act_upgrade_ros(mt: MikroTik, device: dict[str, Any], params: dict[str, Any]) -> str:
    """
    Обновление RouterOS через интернет.

    Порядок действий:

    1. проверка обновлений и защита от отката;
    2. бэкап;
    3. **загрузка пакетов без перезагрузки** — самый долгий шаг, устройство
       всё это время работает как обычно;
    4. перезагрузка и ожидание, пока связь действительно пропадёт;
    5. ожидание возврата и сверка фактической версии;
    6. по желанию — RouterBOOT и ещё одна перезагрузка.

    Свободное место заранее не проверяется: сколько именно нужно, знает только
    RouterOS, и он сообщает это в ошибке загрузки. Любой наш порог был бы
    догадкой — например, на 16-мегабайтных устройствах свободно меньше двух
    мегабайт, и разумный на вид лимит отверг бы их все.

    Загрузка отделена от установки намеренно. Команда install делает и то и
    другое разом, из-за чего на медленном канале момент перезагрузки
    непредсказуем: устройство минутами качает пакеты и всё это время отвечает.

    Если обновления нет — устройство не трогается вообще.
    """
    channel = (params.get("channel") or "").strip()
    wait_back = _as_int(params.get("wait_back"), 420)
    download_timeout = _as_int(params.get("download_timeout"), 1800)
    log: list[str] = []

    # --- 1. Есть ли что ставить -------------------------------------------
    info = mt.update_info(set_channel=channel)
    installed = info.get("installed-version", "")
    latest = info.get("latest-version", "")
    status = info.get("status", "")

    device["_update"] = {
        "latest_version": latest,
        "update_status": status,
        "update_channel": info.get("channel", ""),
    }

    if not latest:
        raise DeviceError(f"Не удалось проверить обновления: {status or 'нет ответа'}")

    channel_name = info.get("channel", "?")
    if _same_version(installed, latest):
        return f"Пропущено: уже актуальная версия {installed} (канал {channel_name})"

    # Защита от отката. Если в выбранном канале версия старше установленной,
    # /system/package/update/install ничего не сделает: он умеет только вперёд.
    # Без этой проверки задача просто ждала бы перезагрузки, которой не будет.
    if not is_newer(latest, installed):
        return (
            f"Пропущено: установлена {installed}, а в канале {channel_name} только {latest}. "
            "Это откат назад, через обновление он не выполняется. "
            "Откат делается вручную, файлами .npk, и может испортить конфигурацию: "
            "настройки новых версий старая RouterOS не понимает, а бинарный бэкап "
            "с новой версии на старую не восстанавливается."
        )

    log.append(f"{installed} → {latest}")

    # --- 2. Бэкап ----------------------------------------------------------
    if _as_bool(params.get("make_backup", True)):
        try:
            log.append("бэкап: " + _run_backup(mt, device, {
                "do_binary": True, "do_export": True, "cleanup": True,
                "_job_id": params.get("_job_id"),
            }).replace("Сохранено: ", ""))
        except DeviceError as exc:
            # Обновляться без резервной копии не станем — это осознанный отказ
            raise DeviceError(f"Обновление отменено: не удалось снять бэкап ({exc})") from exc

    # --- 3. Загрузка пакетов (без перезагрузки) ----------------------------
    # Самый долгий шаг на тонком канале. Устройство остаётся на связи,
    # и если загрузка не удастся — оно просто продолжит работать на старой версии.
    started_download = time.monotonic()
    mt.download_update(timeout=download_timeout)
    log.append(f"пакеты загружены за {int(time.monotonic() - started_download)} с")

    # --- 4. Установка: перезагрузка -----------------------------------------
    mt.cmd_fire_and_forget("/system/reboot")

    if wait_back <= 0:
        return "; ".join(log) + "; перезагрузка отправлена (возврат не проверялся)"

    # Сначала убеждаемся, что связь действительно пропала. Иначе можно принять
    # ещё не перезагрузившееся устройство за вернувшееся и зря объявить ошибку.
    down_after = mt.wait_until_down(timeout=min(wait_back, 240))
    log.append(f"ушло в перезагрузку через {down_after} с")

    # --- 5. Ждём возврата и сверяем версию ---------------------------------
    seconds = mt.wait_until_back(timeout=wait_back)
    new_info = mt.system_info()
    new_version = new_info.get("ros_version", "")
    device["_info"] = new_info
    log.append(f"вернулось за {seconds} с, версия {new_version or '?'}")

    if not _same_version(new_version, latest):
        raise DeviceError(
            "; ".join(log) + f", а ОЖИДАЛАСЬ {latest}. Устройство на связи, но версия "
            "не та: возможно, установка не завершилась. Проверьте вручную."
        )

    # --- 5. Загрузчик RouterBOOT -------------------------------------------
    if _as_bool(params.get("upgrade_routerboard", False)):
        log.append(_upgrade_routerboard(mt, wait_back))

    return "Обновлено: " + "; ".join(log)


def _upgrade_routerboard(mt: MikroTik, wait_back: int) -> str:
    """Обновить прошивку загрузчика, если она отстаёт от версии RouterOS."""
    try:
        rb = mt.routerboard_info()
    except DeviceError:
        return "RouterBOOT: устройство не является RouterBOARD, пропущено"

    current = rb.get("current-firmware", "")
    available = rb.get("upgrade-firmware", "")
    if not available or current == available:
        return f"RouterBOOT: уже актуальный ({current or '?'})"

    mt.cmd("/system/routerboard/upgrade")
    mt.cmd_fire_and_forget("/system/reboot")
    seconds = mt.wait_until_back(timeout=wait_back)
    return f"RouterBOOT: {current} → {available}, вернулось за {seconds} с"


def _same_version(left: str, right: str) -> bool:
    """
    Сравнить версии RouterOS без учёта пометки канала.

    «7.14.3 (stable)» и «7.14.3» считаются одной и той же версией.
    """
    def clean(value: str) -> str:
        return re.sub(r"\s*\(.*?\)\s*", "", str(value or "")).strip()

    return bool(clean(left)) and clean(left) == clean(right)


# ================================================================ помощники ===
def _parse_kv(text: str) -> dict[str, str]:
    """Разобрать многострочный текст «ключ=значение» в словарь аргументов."""
    result: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise DeviceError(f"Некорректный аргумент: «{line}» (ожидается ключ=значение)")
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip()
    return result


def _as_bool(value: Any) -> bool:
    """Мягкое приведение значения формы к булеву."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "yes", "on", "да")


def _as_int(value: Any, default: int) -> int:
    """Мягкое приведение значения формы к целому числу."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _device_backup_dir(device: dict[str, Any]) -> Path:
    """Каталог бэкапов конкретного устройства."""
    folder = settings.backup_dir / f"{device['id']}-{safe_filename(device['name'])}"
    folder.mkdir(parents=True, exist_ok=True)
    return folder


def _wait_for_file(mt: MikroTik, filename: str, attempts: int = 15, delay: float = 1.0) -> None:
    """Дождаться появления файла на устройстве (backup save работает асинхронно)."""
    import time

    for _ in range(attempts):
        for row in mt.list_files():
            if row.get("name") == filename:
                return
        time.sleep(delay)
    raise DeviceError(f"Файл {filename} не появился на устройстве за отведённое время")


def _record_backup(device: dict[str, Any], kind: str, path: Path, size: int, job_id: Any) -> None:
    """Занести скачанный файл в таблицу backups."""
    execute(
        "INSERT INTO backups (device_id, device_name, job_id, kind, filename, size, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (device["id"], device["name"], job_id, kind, str(path.relative_to(settings.backup_dir)), size, utcnow()),
    )


def _kb(size: int) -> str:
    """Размер файла в КиБ для вывода в результате."""
    return f"{size / 1024:.1f} КиБ"


def action_to_dict(action: Action) -> dict[str, Any]:
    """Сериализация действия для шаблонов/JSON."""
    return {
        "name": action.name,
        "label": action.label,
        "description": action.description,
        "icon": action.icon,
        "dangerous": action.dangerous,
        "untested": action.untested,
        "params": [
            {
                "name": p.name,
                "label": p.label,
                "type": p.type,
                "required": p.required,
                "default": p.default,
                "placeholder": p.placeholder,
                "help": p.help,
                "options": p.options,
            }
            for p in action.params
        ],
    }


def actions_json() -> str:
    """JSON со всеми действиями — отдаётся во фронтенд для отрисовки форм."""
    return json.dumps([action_to_dict(a) for a in list_actions()], ensure_ascii=False)
