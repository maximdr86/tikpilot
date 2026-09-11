"""
Проверка, не вышла ли новая версия самой панели.

Что это делает и чего не делает
-------------------------------

Раз в сутки панель спрашивает у GitHub, какой выпуск последний, и если он
новее установленного, показывает об этом строку в блоке «требует внимания».
Всё.

Обновить себя она не может и не должна: панель ставится копированием
файлов, а не через git, и кнопка «обновить» здесь была бы обещанием,
которого не выполнить. Строка со ссылкой на выпуск честнее.

Про приватность
---------------

Запрос уходит пустой: обычный GET публичной страницы выпусков. Ни версии,
ни адреса установки, ни размера парка в нём нет, и заголовок `User-Agent`
одинаковый у всех. Это разница между «схожу посмотрю» и «доложу о себе»,
и для панели, которую человек ставит на свой сервер, она принципиальная.

Проверка выключается одной настройкой: у части людей сервер вообще без
выхода наружу, а на точках интернет бывает платным.
"""
from __future__ import annotations

import json
import logging
import re
import time
import urllib.request
from typing import Any

from . import __version__
from .config import settings

log = logging.getLogger("tikpilot.selfupdate")

#: Откуда узнаём про выпуски. Публичный адрес, ключей и токенов не нужно.
RELEASES_API = "https://api.github.com/repos/maximdr86/tikpilot/releases/latest"
RELEASES_PAGE = "https://github.com/maximdr86/tikpilot/releases"

#: Как часто спрашивать. Чаще незачем: выпуски выходят не ежечасно,
#: а канал у сервера может быть узким и платным.
CHECK_EVERY = 24 * 3600

#: Сколько ждать ответа. Проверка второстепенная, и подвешивать из-за неё
#: дашборд нельзя ни на секунду дольше необходимого.
TIMEOUT = 6.0

_state: dict[str, Any] = {"at": 0.0, "latest": "", "error": ""}


def parse_version(text: Any) -> tuple[int, ...]:
    """
    Версия числами: `v1.75.0` и `1.75.0` дают одно и то же.

    Сравнивать строками нельзя: «1.9.0» окажется больше «1.10.0», а тег
    с суффиксом вроде `v1.75.0-rc1` наивное сравнение объявит новее самого
    выпуска. Здесь берутся только числа, а всё после них отбрасывается
    вместе со строкой, если суффикс есть (см. `is_prerelease`).
    """
    match = re.match(r"^v?(\d+(?:\.\d+)*)", str(text or "").strip())
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def is_prerelease(text: Any) -> bool:
    """
    Тег с суффиксом после чисел: `1.75.0-rc1`, `1.75.0b2`.

    Про такие мы молчим. Человек, поставивший панель на рабочий сервер,
    не должен узнавать из плашки о черновике, который завтра перепишут.
    """
    return bool(re.match(r"^v?\d+(?:\.\d+)*[-+a-z]", str(text or "").strip(), re.I))


def _ask() -> tuple[str, str]:
    """Сходить к GitHub. Возвращает `(тег, ошибка)`, обе строки могут быть пустыми."""
    try:
        request = urllib.request.Request(
            RELEASES_API,
            headers={"Accept": "application/vnd.github+json",
                     # Одинаковый у всех: по нему нельзя отличить одну
                     # установку от другой, и это намеренно
                     "User-Agent": "tikpilot"},
        )
        with urllib.request.urlopen(request, timeout=TIMEOUT) as answer:  # noqa: S310
            data = json.loads(answer.read().decode("utf-8", "replace"))
    except Exception as exc:  # noqa: BLE001 — сеть, разбор, что угодно
        log.debug("Проверка обновлений не удалась: %s", exc)
        return "", str(exc)[:120]
    return str(data.get("tag_name") or ""), ""


def check(force: bool = False) -> dict[str, Any]:
    """
    Что известно о выпусках. Ходит наружу не чаще раза в сутки.

    Результат держится в памяти, а не в базе: он ничего не стоит собрать
    заново после перезапуска, а лишняя таблица потребовала бы чистки.
    """
    if not settings.update_check:
        return {"enabled": False, "latest": "", "newer": False, "error": ""}

    now = time.monotonic()
    if force or now - float(_state["at"]) > CHECK_EVERY:
        latest, error = _ask()
        _state.update({"at": now, "error": error})
        if latest:
            _state["latest"] = latest

    latest = str(_state["latest"] or "")
    newer = bool(
        latest
        and not is_prerelease(latest)
        and parse_version(latest) > parse_version(__version__)
    )
    return {
        "enabled": True,
        "latest": latest,
        "newer": newer,
        "error": str(_state["error"] or ""),
        "page": RELEASES_PAGE,
    }


def forget() -> None:
    """Сбросить запомненное. Нужно тестам и настройкам."""
    _state.update({"at": 0.0, "latest": "", "error": ""})
