"""
Доставка уведомлений: сводкой, а не потоком.

Зачем именно так
----------------

Обычные уведомления на парке с плохими каналами бесполезны через неделю:
точки дребезжат, сообщения идут пачками, человек перестаёт их читать
и пропускает то единственное, ради чего всё затевалось.

Поэтому здесь три ограничителя, и они включены по умолчанию:

* **Сводка.** Панель копит события и раз в N минут отправляет одно
  сообщение обо всём накопившемся. Пятнадцать падений это пятнадцать
  строк в одном сообщении, а не пятнадцать сообщений.
* **Тихие часы.** Ночью сообщения копятся и уходят утром. Исключение
  придётся делать руками: панель не знает, какая точка стоит того,
  чтобы будить человека.
* **Пауза по объекту.** Одно и то же правило по одной и той же точке
  не повторяется чаще заданного, даже если оно гаснет и загорается
  каждые пять минут.

Куда отправляем
---------------

В Телеграм. Это обычный POST на api.telegram.org с двумя полями, никакой
библиотеки для этого не нужно.

Токен бота лежит зашифрованным тем же ключом, что и пароли роутеров,
и обратно в интерфейс не отдаётся: в форме видно только «задан».

Почему панель молчит
--------------------

Причин, по которым сообщение не ушло, ровно пять: отправка выключена,
идут тихие часы, интервал сводки ещё не истёк, каналов нет и отправлять
нечего. Все они возвращаются наверх отдельным полем, и человек видит
причину, а не «отправлено: 0». Молчащая панель без объяснения хуже
не работающей: непонятно, чинить её или ждать.

Важное
------

Всё это выключено, пока человек не включил. Панель обещает работать
в сети без интернета, и поход на api.telegram.org, которого никто
не просил, был бы нарушением обещания.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any

from .config import settings
from .crypto import decrypt, encrypt
from .database import execute, execute_changes, query, query_one, utcnow

log = logging.getLogger("tikpilot.notify")

#: Адрес API Телеграма. Отдельной константой, чтобы тесты могли
#: подставить свой сервер и не ходить в интернет.
TELEGRAM_API = "https://api.telegram.org"

#: Потолок на длину сообщения. У Телеграма он 4096 символов, и сводка
#: за ночь на большом парке в него не влезает. Лишнее заменяется строкой
#: «и ещё столько-то»: обрезанное посередине сообщение хуже короткого.
MAX_LINES = 25

TIMEOUT = 15.0


# ------------------------------------------------------------------- каналы
def channels(only_enabled: bool = False) -> list[dict[str, Any]]:
    """Куда отправляем. Секрет наружу не отдаётся, только признак «задан»."""
    sql = "SELECT * FROM notify_channels"
    if only_enabled:
        sql += " WHERE enabled = 1"
    rows = []
    for row in query(sql + " ORDER BY id"):
        item = dict(row)
        item["has_secret"] = bool(item.pop("secret_enc", ""))
        rows.append(item)
    return rows


def save_channel(data: dict[str, Any]) -> int:
    """
    Завести или изменить чат.

    Пустой токен при правке означает «оставить прежний»: иначе каждое
    изменение чата требовало бы снова вводить токен бота, а человек,
    у которого он не под рукой, случайно затёр бы рабочий.
    """
    kind = "telegram"
    address = str(data.get("address") or "").strip()
    if not address:
        raise ValueError("Нужен идентификатор чата")

    secret = str(data.get("secret") or "").strip()
    channel_id = int(data.get("id") or 0)
    enabled = 0 if str(data.get("enabled") or "1") in ("0", "false", "no") else 1
    now = utcnow()

    if channel_id:
        if secret:
            execute_changes(
                "UPDATE notify_channels SET address = ?, secret_enc = ?, enabled = ?,"
                " updated_at = ? WHERE id = ?",
                (address, encrypt(secret), enabled, now, channel_id),
            )
        else:
            execute_changes(
                "UPDATE notify_channels SET address = ?, enabled = ?, updated_at = ?"
                " WHERE id = ?",
                (address, enabled, now, channel_id),
            )
        return channel_id

    if not secret:
        raise ValueError("Нужен токен бота")

    execute(
        "INSERT INTO notify_channels (kind, address, secret_enc, enabled,"
        " created_at, updated_at) VALUES (?,?,?,?,?,?)",
        (kind, address, encrypt(secret) if secret else "", enabled, now, now),
    )
    row = query_one("SELECT id FROM notify_channels ORDER BY id DESC LIMIT 1")
    return int(row["id"]) if row else 0


def delete_channel(channel_id: int) -> None:
    """Убрать канал вместе с токеном."""
    execute_changes("DELETE FROM notify_channels WHERE id = ?", (channel_id,))


# ------------------------------------------------------------------ отправка
def send(channel: dict[str, Any], text: str) -> None:
    """
    Отправить одно сообщение в чат. Ошибку поднимает наверх.

    Сеть здесь единственное место во всём модуле, и оно намеренно
    простое: обычный POST из стандартной библиотеки, без зависимостей.
    """
    row = query_one("SELECT secret_enc FROM notify_channels WHERE id = ?",
                    (channel["id"],))
    secret = decrypt(str(row["secret_enc"])) if row and row["secret_enc"] else ""

    url = f"{TELEGRAM_API}/bot{secret}/sendMessage"
    payload = {
        "chat_id": channel["address"],
        "text": text,
        # Без разметки: имена точек приходят от человека и могут содержать
        # что угодно, а сообщение с битой разметкой Телеграм не принимает
        "disable_web_page_preview": True,
    }

    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "tikpilot"},
    )
    with urllib.request.urlopen(request, timeout=TIMEOUT) as answer:  # noqa: S310
        answer.read()


# --------------------------------------------------------------- ограничители
def quiet_now(now: datetime | None = None) -> bool:
    """
    Идут ли сейчас тихие часы. Границы считаются по времени сервера.

    Промежуток может пересекать полночь: с 22 до 8 это нормальная запись,
    а не ошибка ввода.
    """
    start, end = settings.notify_quiet_from, settings.notify_quiet_to
    if start == end:
        return False
    hour = (now or datetime.now()).hour
    if start < end:
        return start <= hour < end
    return hour >= start or hour < end


def _recently_sent(event: dict[str, Any], minutes: int) -> bool:
    """
    Уходило ли такое же сообщение недавно.

    «Такое же» это то же правило по той же точке. Гаснет и загорается
    каждые пять минут только дребезжащая точка, и человеку от этого
    потока пользы нет.
    """
    if minutes <= 0:
        return False
    row = query_one(
        "SELECT COUNT(*) AS c FROM alert_events WHERE sent = 1 AND rule_id IS ?"
        " AND device_id IS ? AND kind = ? AND ts > datetime('now', ?)",
        (event.get("rule_id"), event.get("device_id"), event.get("kind"),
         f"-{minutes} minutes"),
    )
    return bool(row and row["c"])


def compose(events: list[dict[str, Any]], lang: str = "ru") -> str:
    """Собрать текст сводки. Одна строка на событие, сначала загоревшиеся."""
    from . import alerts, i18n

    fired = [e for e in events if e["kind"] == "fired"]
    resolved = [e for e in events if e["kind"] != "fired"]

    lines: list[str] = []
    if fired:
        lines.append(i18n.translate_text("Вышло за порог", lang) + f" ({len(fired)}):")
        for event in fired[:MAX_LINES]:
            lines.append("  " + alerts.describe(event, lang))
        if len(fired) > MAX_LINES:
            lines.append("  " + i18n.translate_text("и ещё", lang)
                         + f" {len(fired) - MAX_LINES}")
    if resolved:
        if lines:
            lines.append("")
        lines.append(i18n.translate_text("Вернулось в норму", lang)
                     + f" ({len(resolved)}):")
        for event in resolved[:MAX_LINES]:
            lines.append("  " + alerts.describe(event, lang))
        if len(resolved) > MAX_LINES:
            lines.append("  " + i18n.translate_text("и ещё", lang)
                         + f" {len(resolved) - MAX_LINES}")

    return "\n".join(lines)


def due(now: datetime | None = None) -> bool:
    """Пора ли отправлять сводку: прошёл ли интервал с прошлой отправки."""
    minutes = max(1, settings.notify_digest_minutes)
    row = query_one("SELECT MAX(ts) AS ts FROM notify_log WHERE ok = 1")
    if row is None or not row["ts"]:
        return True
    try:
        last = datetime.fromisoformat(str(row["ts"])).replace(tzinfo=timezone.utc)
    except ValueError:
        return True
    return (now or datetime.now(timezone.utc)) - last >= timedelta(minutes=minutes)


#: Почему сводка не ушла. Строки короткие и переводятся: они попадают
#: и в ответ кнопки, и в подпись на странице.
REASONS = {
    "off": "Отправка выключена в настройках панели",
    "quiet": "Идут тихие часы, события копятся",
    "waiting": "Интервал сводки ещё не истёк",
    "no_channels": "Не задан ни один чат",
    "nothing": "Отправлять нечего",
    "cooldown": "Всё накопившееся уже отправляли недавно",
    "sent": "Отправлено",
    "failed": "Не отправилось",
}


def dispatch(force: bool = False) -> dict[str, Any]:
    """
    Отправить накопившееся. Зовётся фоновым потоком раз в минуту.

    Возвращает счётчики и **причину**: молчание без объяснения хуже
    ошибки. Раньше выключенная отправка отвечала «отправлено: 0», и
    отличить её от «нечего отправлять» можно было только по коду.

    Ошибка не теряет события: неотправленное остаётся неотправленным
    и уедет со следующей сводкой.
    """
    from . import alerts, i18n

    if not settings.notify_enabled:
        return {"sent": 0, "failed": 0, "reason": "off"}
    if not force and quiet_now():
        return {"sent": 0, "failed": 0, "reason": "quiet"}
    if not force and not due():
        return {"sent": 0, "failed": 0, "reason": "waiting"}

    targets = channels(only_enabled=True)
    if not targets:
        return {"sent": 0, "failed": 0, "reason": "no_channels"}

    events = alerts.unsent()
    if not events:
        return {"sent": 0, "failed": 0, "reason": "nothing"}

    fresh = [e for e in events
             if not _recently_sent(e, settings.notify_cooldown_minutes)]
    if not settings.notify_resolved:
        fresh = [e for e in fresh if e["kind"] == "fired"]

    if not fresh:
        # Отложенные повторы всё равно помечаем: иначе они будут висеть
        # в очереди вечно и уедут разом, когда пауза кончится
        alerts.mark_sent([int(e["id"]) for e in events])
        return {"sent": 0, "failed": 0, "reason": "cooldown"}

    # Язык сводки берём из настроек панели: у сообщения в чат нет
    # пользователя, чей выбор можно было бы спросить, а на английской
    # панели русская сводка выглядит как чужое сообщение
    text = compose(fresh, i18n.normalize_lang(settings.default_lang))
    failed = 0
    delivered = False
    error = ""
    for channel in targets:
        try:
            send(channel, text)
            delivered = True
            _log(channel, True, "")
        except Exception as exc:  # noqa: BLE001 - причину показываем человеку
            failed += 1
            error = str(exc)[:200]
            _log(channel, False, error)
            log.warning("Уведомление не ушло в %s: %s", channel["kind"], exc)

    if delivered:
        alerts.mark_sent([int(e["id"]) for e in events])
    return {
        "sent": len(fresh) if delivered else 0,
        "failed": failed,
        "reason": "sent" if delivered else "failed",
        "error": error,
    }


def why_silent() -> str:
    """
    Что мешает отправке прямо сейчас. Пусто, если ничего не мешает.

    Нужно странице: человек должен видеть «отправка выключена» рядом
    с кнопкой, а не узнавать об этом, нажав её.
    """
    from . import alerts

    if not settings.notify_enabled:
        return "off"
    if not channels(only_enabled=True):
        return "no_channels"
    if quiet_now():
        return "quiet"
    if not alerts.unsent():
        return "nothing"
    return ""


def _log(channel: dict[str, Any], ok: bool, error: str) -> None:
    """Записать попытку отправки: без этого молчащий канал не отладить."""
    execute(
        "INSERT INTO notify_log (channel_id, kind, ok, error, ts) VALUES (?,?,?,?,?)",
        (channel["id"], channel["kind"], 1 if ok else 0, error, utcnow()),
    )


def heartbeat() -> bool:
    """
    Подать сигнал живости наружу. Возвращает, получилось ли.

    Панель не может сообщить о собственной смерти: мёртвая программа
    ничего не отправляет. Поэтому делаем наоборот - регулярно дёргаем
    чужой адрес, а тревогу поднимает тот, к кому сигнал перестал
    приходить. Это единственный способ узнать, что упал сервер, а не
    точка.

    Сигнал не зависит от того, включены ли уведомления: это разные
    вещи. Уведомления рассказывают о парке, сигнал живости о панели.
    """
    url = settings.heartbeat_url.strip()
    if not url:
        return False

    row = query_one("SELECT MAX(ts) AS ts FROM notify_log WHERE kind = 'heartbeat'"
                    " AND ok = 1")
    if row and row["ts"]:
        try:
            last = datetime.fromisoformat(str(row["ts"])).replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - last < timedelta(
                    minutes=max(1, settings.heartbeat_minutes)):
                return False
        except ValueError:
            pass

    channel = {"id": None, "kind": "heartbeat"}
    try:
        request = urllib.request.Request(
            url, method="GET", headers={"User-Agent": "tikpilot"})
        with urllib.request.urlopen(request, timeout=TIMEOUT) as answer:  # noqa: S310
            answer.read()
    except Exception as exc:  # noqa: BLE001 - молчащий сторож это не авария панели
        _log(channel, False, str(exc)[:200])
        log.debug("Сигнал живости не ушёл: %s", exc)
        return False

    _log(channel, True, "")
    return True


def history(limit: int = 20) -> list[dict[str, Any]]:
    """Последние попытки отправки для страницы настроек."""
    return [dict(row) for row in query(
        "SELECT * FROM notify_log ORDER BY id DESC LIMIT ?", (limit,))]


def test_send(channel_id: int, lang: str = "ru") -> None:
    """
    Отправить проверочное сообщение. Ошибку поднимает наверх.

    Нужна ровно один раз, зато обязательно: перепутанный идентификатор
    чата иначе выясняется в первую же аварию.
    """
    from . import i18n

    row = query_one("SELECT * FROM notify_channels WHERE id = ?", (channel_id,))
    if row is None:
        raise ValueError("Канал не найден")
    channel = dict(row)
    text = i18n.translate_text(
        "Проверка связи из Tikpilot. Если вы это читаете, уведомления настроены.",
        lang)
    try:
        send(channel, text)
        _log(channel, True, "")
    except Exception as exc:  # noqa: BLE001
        _log(channel, False, str(exc)[:200])
        raise
