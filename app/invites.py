"""
Приглашения: ссылка, по которой человек заводит себе учётную запись сам.

Зачем это вообще. Раньше администратор придумывал новому человеку логин
и пароль и пересылал их в переписке. Пароль, отправленный в мессенджер,
остаётся там навсегда, а половина таких паролей потом не меняется никогда.
По ссылке человек задаёт пароль сам, и в переписке остаётся одноразовый
адрес, который через двое суток ничего не значит.

Что здесь важнее удобства:

* **ссылка одноразовая.** После регистрации она мертва, повторный переход
  показывает то же самое, что и выдуманный токен;
* **у неё есть срок.** Приглашение, забытое в чате полгода назад, не должно
  открывать дверь;
* **учётная запись создаётся без единого права.** Регистрация это только
  «человек завёл вход», а не «человек получил доступ». Права выдаются
  руками, галочками, после;
* **страница регистрации живёт внутри панели,** то есть под тем же
  ограничением по сетям. Утёкшая ссылка бесполезна тому, кто не попал
  в доверенную сеть.

Токен нигде не показывается второй раз в открытом виде? Показывается:
ссылку надо скопировать и отправить, и прятать её от того, кто её создал,
незачем. Но в журнале действий её нет: там только пометка, для кого
приглашение выписано.
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from .database import execute, query, query_one, utcnow

#: Длина токена в байтах, как у публичной ссылки: подобрать нереально.
TOKEN_BYTES = 24

#: Сколько часов живёт приглашение по умолчанию. Двое суток это «отправил
#: вечером, человек дошёл до рабочего места завтра или послезавтра».
DEFAULT_HOURS = 48

#: Границы срока, которые можно задать при создании.
MIN_HOURS, MAX_HOURS = 1, 720


def create(note: str, hours: int, author: str) -> str:
    """Выписать приглашение и вернуть его токен."""
    hours = max(MIN_HOURS, min(MAX_HOURS, int(hours or DEFAULT_HOURS)))
    token = secrets.token_urlsafe(TOKEN_BYTES)
    expires = datetime.now(timezone.utc) + timedelta(hours=hours)

    execute(
        "INSERT INTO invites (token, note, created_by, created_at, expires_at)"
        " VALUES (?,?,?,?,?)",
        (token, note.strip()[:120], author, utcnow(),
         expires.strftime("%Y-%m-%d %H:%M:%S")),
    )
    return token


def find(token: str) -> dict[str, Any] | None:
    """
    Действующее приглашение по токену или None.

    Три причины отказа (нет такого, уже использовано, просрочено) отвечают
    одинаково и намеренно: разница в ответах подсказала бы перебирающему,
    что он на верном пути. Человеку с настоящей ссылкой она всё равно
    ничего не объяснит, ему нужна новая ссылка в любом из трёх случаев.
    """
    if len(token) < 16:
        return None

    row = query_one(
        "SELECT * FROM invites WHERE token = ? AND used_at IS NULL AND revoked = 0 "
        "AND expires_at > ?", (token, utcnow()),
    )
    return dict(row) if row else None


def consume(token: str, username: str, ip: str) -> None:
    """Пометить приглашение использованным."""
    execute(
        "UPDATE invites SET used_at = ?, used_by = ?, used_ip = ? WHERE token = ?",
        (utcnow(), username, ip, token),
    )


def revoke(invite_id: int) -> dict[str, Any] | None:
    """Отозвать приглашение. Возвращает отозванное, чтобы было что записать."""
    row = query_one("SELECT * FROM invites WHERE id = ?", (invite_id,))
    if not row:
        return None
    execute("UPDATE invites SET revoked = 1 WHERE id = ?", (invite_id,))
    return dict(row)


def listing() -> list[dict[str, Any]]:
    """
    Приглашения для страницы настроек: сначала живые, потом остальные.

    Использованные и просроченные не удаляются сразу: «кто кого позвал»
    это часть истории, и через месяц она отвечает на вопрос, откуда
    в системе взялся человек.
    """
    now = utcnow()
    rows = query(
        "SELECT * FROM invites ORDER BY "
        "  CASE WHEN used_at IS NULL AND revoked = 0 AND expires_at > ? THEN 0 ELSE 1 END, "
        "  id DESC LIMIT 50",
        (now,),
    )

    result = []
    for row in rows:
        item = dict(row)
        if item["used_at"]:
            item["state"] = "used"
        elif item["revoked"]:
            item["state"] = "revoked"
        elif str(item["expires_at"]) <= now:
            item["state"] = "expired"
        else:
            item["state"] = "live"
        result.append(item)
    return result


def cleanup(days: int = 180) -> None:
    """Убрать совсем старые записи, чтобы список не рос вечно."""
    execute("DELETE FROM invites WHERE created_at < datetime('now', ?)",
            (f"-{days} days",))
