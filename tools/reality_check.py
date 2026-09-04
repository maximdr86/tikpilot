#!/usr/bin/env python3
"""
Сверка заглушки с настоящим RouterOS.

Зачем
-----

Все тесты панели гоняются против `tests/fake_router.py`. Это не RouterOS,
а наше представление о нём, и врать оно будет ровно там, где мы ошиблись.
Так уже случалось: формат `bsd-syslog`, разные ответы `/system/health`
в шестёрке и семёрке, поля `bandwidth-test`. Каждый раз ошибка жила
в заглушке и в коде одновременно, поэтому тесты были зелёными.

Скрипт задаёт настоящему роутеру те же команды, что и панель, и сравнивает
**набор полей** в ответах с тем, что отдаёт заглушка. Значения не сравниваются:
у живой коробки они свои, а важно, какие ключи вообще приходят.

Интересны два списка:

* поля, которые роутер шлёт, а заглушка нет — возможно, мы что-то полезное
  не замечаем;
* поля, которые есть у заглушки, а роутер их не шлёт — вот это опасно:
  значит, панель разбирает выдумку, и на живой точке эта ветка кода
  не работала никогда.

Только чтение
-------------

Выполняются лишь `print`, `monitor` и `/export`. Любая другая команда
отклоняется самим скриптом, до отправки на устройство. Ни одной записи,
ни перезагрузок, ни изменений конфигурации: скрипт можно наводить
на рабочую точку парка.

Запуск
------

    ROUTER_HOST=10.0.0.1 ROUTER_USER=tikpilot ROUTER_PASSWORD=secret \\
        python tools/reality_check.py

Необязательное: ROUTER_PORT (8728), ROUTER_SSL=1, ROUTER_TIMEOUT.

Первым доводом можно передать имя файла, и отчёт запишется туда же
в UTF-8. Это не украшение: консоль Windows перекодирует вывод по дороге,
и перенаправление через `>` даёт нечитаемый файл. Пишем сами:

    python tools/reality_check.py check.txt

Довод `--all` берёт точки из базы самой панели: адреса, логины и пароли
уже там, расшифровка идёт на этой же машине, пароли на экран не попадают.
Так за один прогон закрываются модели, которых нет под рукой поодиночке:

    python tools/reality_check.py --all check-fleet.txt

Что покажет CHR, а что нет
--------------------------

CHR это виртуалка: у неё нет PoE, беспроводного, LTE и датчиков. Ветки
заглушки про них останутся непроверенными, и для них нужна настоящая
коробка. Скрипт про это честно пишет в конце.
"""

from __future__ import annotations

import os
import re
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#: Что разрешено спрашивать. Проверяется до отправки: скрипт наводят
#: на рабочую точку, и одна опечатка не должна ничего изменить.
READ_ONLY = re.compile(r"^/[a-z0-9/-]+/(print|monitor)$|^/export$")

#: Поля, которых у живого роутера может не быть по совершенно законной
#: причине. Сравнение идёт по набору ключей, а RouterOS не присылает поле,
#: если оно пустое или если состояние ещё не наступило. Без этого списка
#: отчёт объявлял выдумкой заглушки нормальные вещи, а ложные тревоги
#: быстро отучают читать отчёт целиком.
CONDITIONAL: dict[str, dict[str, str]] = {
    "/system/package/update/print": {
        "latest-version": "появляется после check-for-updates",
        "status": "появляется после check-for-updates",
    },
    "/ip/arp/print": {
        "comment": "только у записей, которым его вписали",
    },
    "/interface/bridge/host/print": {
        "vid": "только на мосту с фильтрацией VLAN",
    },
    "/ip/neighbor/print": {
        "mac-address": "не все соседи его сообщают",
    },
    "/interface/ethernet/print": {
        # Заглушка держит это поле нарочно: его шлют три коробки
        # из сорока семи, и ветка с ним должна оставаться проверенной.
        # Скорость панель всё равно берёт из monitor, а не отсюда
        "speed": "шлют не все платы, панель берёт скорость из monitor",
    },
}

#: Команды, которые панель действительно задаёт. Список собран по вызовам
#: в `app/`, а не по тому, что умеет RouterOS: сверять то, чем мы не
#: пользуемся, значит разглядывать шум. Если добавится новый вызов,
#: место ему здесь.
COMMANDS: list[tuple[str, dict[str, Any]]] = [
    # обычный опрос
    ("/system/resource/print", {}),
    ("/system/identity/print", {}),
    ("/system/routerboard/print", {}),
    ("/system/package/update/print", {}),
    ("/ip/cloud/print", {}),
    # паспорт
    ("/interface/print", {}),
    ("/interface/ethernet/print", {}),
    ("/interface/ethernet/poe/print", {}),
    ("/interface/vlan/print", {}),
    ("/interface/wireless/print", {}),
    ("/interface/wireguard/print", {}),
    ("/interface/wireguard/peers/print", {}),
    ("/ip/service/print", {}),
    ("/ip/neighbor/print", {}),
    ("/ip/address/print", {}),
    ("/ip/route/print", {}),
    ("/system/health/print", {}),
    ("/system/script/print", {}),
    ("/system/scheduler/print", {}),
    # клиенты за роутером
    ("/ip/dhcp-server/lease/print", {}),
    ("/ip/arp/print", {}),
    ("/interface/bridge/host/print", {}),
    ("/interface/wireless/registration-table/print", {}),
    ("/interface/wifi/registration-table/print", {}),
    # мобильный канал и тест скорости
    ("/interface/lte/print", {}),
    ("/tool/bandwidth-server/print", {}),
    # файлы и журнал
    ("/file/print", {}),
    ("/system/logging/print", {}),
    ("/system/logging/action/print", {}),
]


#: Куда складывать отчёт помимо экрана. Заполняется в main().
_report: list[str] = []


def say(line: str = "") -> None:
    """Напечатать строку и запомнить её для файла отчёта."""
    print(line)
    _report.append(line)


def env(name: str, default: str = "") -> str:
    return str(os.environ.get(name, default) or "").strip()


def keys_of(rows: list[dict[str, Any]]) -> set[str]:
    """Объединение ключей по всем строкам ответа."""
    found: set[str] = set()
    for row in rows or []:
        if isinstance(row, dict):
            found |= {str(k) for k in row.keys()}
    # Служебные поля API интереса не представляют
    return {k for k in found if not k.startswith("!")}


def ask_real(mt: Any, cmd: str, args: dict[str, Any]) -> tuple[list[dict], str]:
    try:
        return list(mt.cmd(cmd, **args)), ""
    except Exception as exc:                      # noqa: BLE001 — печатаем как есть
        return [], f"{type(exc).__name__}: {exc}"


def ask_fake(fake: Any, cmd: str, args: dict[str, Any]) -> tuple[list[dict], str]:
    try:
        rows = fake._handle(cmd, {k: str(v) for k, v in args.items()})
        return list(rows or []), ""
    except Exception as exc:                      # noqa: BLE001
        return [], f"{type(exc).__name__}: {exc}"


def check_one(device: dict[str, Any], password: str, fake: Any,
              timeout: int) -> dict[str, set[str]]:
    """
    Сверить одну коробку и напечатать разбор.

    Возвращает три множества имён команд: где заглушка выдумывает поля,
    где не знает полей роутера и где роутер команду не понимает. Обход
    парка складывает их вместе, чтобы в конце сказать, какие расхождения
    общие для всех, а какие только у одной модели.
    """
    from app.mikrotik import MikroTik

    result = {"invented": set(), "missing": set(), "unsupported": set()}

    with MikroTik(device, password, timeout=timeout) as mt:
        info = mt.system_info()
        say(f"{info.get('board_name', '?')} · RouterOS {info.get('ros_version', '?')}"
            f" · {info.get('architecture', '?')}")

        for cmd, args in COMMANDS:
            real_rows, real_err = ask_real(mt, cmd, args)
            fake_rows, fake_err = ask_fake(fake, cmd, args)

            # Пустой ответ роутера сравнивать не с чем: полей нет не потому,
            # что их не бывает, а потому, что нет ни одной строки. Раньше
            # такие места помечались как выдумка заглушки, и половина
            # тревог в отчёте была ложной
            if not real_err and not real_rows:
                say(f"   {cmd}")
                say(f"     строк нет, сравнивать не с чем"
                    f" (у заглушки {len(fake_rows)})")
                continue

            real_keys, fake_keys = keys_of(real_rows), keys_of(fake_rows)
            only_real = sorted(real_keys - fake_keys)
            only_fake = sorted(fake_keys - real_keys)

            # Условные поля выносим отдельно и тревогой не считаем:
            # их отсутствие означает состояние коробки, а не ошибку
            условные = CONDITIONAL.get(cmd, {})
            ожидаемо = [f for f in only_fake if f in условные]
            only_fake = [f for f in only_fake if f not in условные]

            mark = "  "
            if real_err:
                mark = "!!" if not fake_err else "--"
            elif only_fake:
                mark = "!!"
            elif only_real:
                mark = " ~"

            say(f"{mark} {cmd}")
            if real_err:
                say(f"     роутер отказал: {real_err}")
                if not fake_err:
                    result["unsupported"].add(cmd)
                    say("     а заглушка отвечает: ветка кода тут не проверяется")
                continue
            say(f"     строк: роутер {len(real_rows)}, заглушка {len(fake_rows)}")
            for поле in ожидаемо:
                say(f"     нет у роутера, и это нормально: {поле}"
                    f" ({условные[поле]})")
            if only_fake:
                result["invented"].add(cmd)
                say(f"     ТОЛЬКО У ЗАГЛУШКИ: {', '.join(only_fake)}")
            if only_real:
                result["missing"].add(cmd)
                say(f"     только у роутера: {', '.join(only_real)}")

        say("")
        run_collectors(mt)

    return result


def fleet_from_db() -> list[dict[str, Any]]:
    """
    Точки из базы панели вместе с расшифрованными паролями.

    Расшифровка идёт тем же ключом, что и всегда, и происходит на этой же
    машине: пароли никуда не уходят и на экран не попадают. Выключенные
    точки пропускаем: их и панель не опрашивает.
    """
    from app.crypto import decrypt
    from app.database import query

    rows = []
    for row in query("SELECT id, name, host, api_port, username, password_enc,"
                     " use_ssl FROM devices WHERE enabled = 1"
                     " ORDER BY name COLLATE NOCASE"):
        item = dict(row)
        try:
            item["password"] = decrypt(item.pop("password_enc"))
        except Exception:                          # noqa: BLE001
            item["password"] = ""
        rows.append(item)
    return rows


def main() -> int:
    for cmd, _args in COMMANDS:
        if not READ_ONLY.match(cmd):
            say(f"Команда {cmd} не только на чтение, список составлен неверно.")
            return 2

    from tests.fake_router import FakeRouter

    timeout = int(env("ROUTER_TIMEOUT", "20"))
    args = [a for a in sys.argv[1:] if a != "--all"]
    whole_fleet = "--all" in sys.argv[1:]

    if whole_fleet:
        devices = fleet_from_db()
        if not devices:
            say("В базе панели нет включённых точек.")
            return 2
        say(f"Обход парка: {len(devices)} точек, только чтение\n")
    else:
        host, user = env("ROUTER_HOST"), env("ROUTER_USER")
        if not host or not user:
            say("Нужны переменные окружения ROUTER_HOST и ROUTER_USER"
                " (плюс ROUTER_PASSWORD), либо довод --all,"
                " чтобы взять точки из базы панели.")
            say("Необязательные: ROUTER_PORT (8728), ROUTER_SSL=1, ROUTER_TIMEOUT.")
            say("Подробности в начале файла tools/reality_check.py.")
            return 2
        devices = [{
            "name": host,
            "host": host,
            "api_port": int(env("ROUTER_PORT", "8728")),
            "username": user,
            "use_ssl": env("ROUTER_SSL") in ("1", "true", "yes"),
            "password": env("ROUTER_PASSWORD"),
        }]
        say(f"Роутер {host}:{devices[0]['api_port']}, пользователь {user}")
        say("Только чтение: print, monitor, export\n")

    fake = FakeRouter(username="tikpilot", password="x")
    seen = {"invented": {}, "missing": {}, "unsupported": {}}
    failed: list[str] = []

    for device in devices:
        name = str(device.get("name") or device["host"])
        if whole_fleet:
            say("\n" + "-" * 70)
            say(f"{name} · {device['host']}")
            say("-" * 70)
        try:
            found = check_one(device, str(device.get("password") or ""),
                              fake, timeout)
        except Exception as exc:                   # noqa: BLE001
            say(f"     не опрошена: {type(exc).__name__}: {exc}")
            failed.append(name)
            continue
        for kind, commands in found.items():
            for cmd in commands:
                seen[kind].setdefault(cmd, []).append(name)

    report_summary(seen, len(devices) - len(failed), failed, whole_fleet)
    return 0


def report_summary(seen: dict[str, dict[str, list[str]]], checked: int,
                   failed: list[str], whole_fleet: bool) -> None:
    """Свести расхождения по всем опрошенным коробкам."""
    say("\n" + "=" * 70)
    say("Итог")
    say("=" * 70)
    say(f"Опрошено точек: {checked}"
        + (f", не отозвалось: {len(failed)} ({', '.join(failed[:5])})" if failed else ""))

    titles = {
        "invented": "Заглушка выдумывает поля",
        "missing": "Заглушка не знает полей",
        "unsupported": "Роутер команду не умеет",
    }
    for kind in ("invented", "missing", "unsupported"):
        commands = seen[kind]
        say(f"\n{titles[kind]}: {len(commands)} команд")
        for cmd, names in sorted(commands.items()):
            # Расхождение на всех коробках сразу это про заглушку,
            # а на одной — про особенность модели
            where = "везде" if checked and len(names) >= checked else \
                    f"{len(names)} из {checked}: {', '.join(names[:4])}"
            say(f"   {cmd} — {where}")

    if not whole_fleet:
        say("\nОдна коробка показывает не всё: у CHR нет PoE, беспроводного,")
        say("LTE и датчиков. Довод --all обойдёт весь парк из базы панели.")


def run_collectors(mt: Any) -> None:
    """Прогнать разбор ответов теми же функциями, что и панель."""
    from app import clients, inventory, traffic

    try:
        passport = inventory.collect(mt)
        ports = passport.get("ports", []) + passport.get("logical", [])
        say(f"паспорт: портов {len(passport.get('ports', []))},"
              f" сервисов {len(passport.get('services', []))},"
              f" соседей {len(passport.get('neighbors', []))},"
              f" скриптов {len(passport.get('scripts', []))},"
              f" датчики {passport.get('temperature') or '-'}"
              f"/{passport.get('voltage') or '-'}")

        # Разобранные значения, а не только счётчики: по числу портов
        # не видно, заполнилось ли то, ради чего лезли на роутер
        powered = [p for p in ports if p.get("poe")]
        for port in powered[:4]:
            say(f"         PoE {port['name']}: настройка «{port['poe']}»,"
                f" состояние «{port.get('poe_status') or 'ПУСТО'}»")
        if not powered:
            say("         PoE: портов с питанием нет")

        vlans = [p for p in ports if p.get("kind") == "vlan"]
        for port in vlans[:4]:
            say(f"         VLAN {port['name']}:"
                f" «{port.get('detail') or 'ПУСТО'}»")
        if not vlans:
            say("         VLAN: интерфейсов нет")
    except Exception as exc:                      # noqa: BLE001
        say(f"паспорт: РАЗВАЛИЛСЯ — {type(exc).__name__}: {exc}")

    try:
        found = clients.collect(mt)
        say(f"клиенты: {len(found)}")
        if found:
            one = found[0]
            say(f"         пример: {one.get('mac')} {one.get('ip')}"
                  f" {one.get('hostname') or ''} порт {one.get('port') or '-'}")
    except Exception as exc:                      # noqa: BLE001
        say(f"клиенты: РАЗВАЛИЛИСЬ — {type(exc).__name__}: {exc}")

    try:
        counters = traffic.read_counters(mt)
        say(f"счётчики трафика: интерфейсов {len(counters)}")
    except Exception as exc:                      # noqa: BLE001
        say(f"счётчики трафика: РАЗВАЛИЛИСЬ — {type(exc).__name__}: {exc}")


def save_report() -> None:
    """Сложить отчёт в файл, если его имя передали доводом."""
    names = [a for a in sys.argv[1:] if not a.startswith("-")]
    if not names:
        return
    path = names[0]
    try:
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("\n".join(_report) + "\n")
        print(f"\nОтчёт записан в {path}")
    except OSError as exc:
        print(f"\nНе удалось записать {path}: {exc}")


if __name__ == "__main__":
    try:
        code = main()
    except KeyboardInterrupt:
        say("\nПрервано с клавиатуры.")
        code = 130
    except Exception as exc:                      # noqa: BLE001
        # Падение тоже попадает в отчёт: чаще всего это «не достучались
        # до роутера», и человеку нужен именно этот текст, а не пустой файл
        say(f"\nСорвалось: {type(exc).__name__}: {exc}")
        code = 1
    save_report()
    raise SystemExit(code)
