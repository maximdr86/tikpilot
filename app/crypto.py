"""
Шифрование паролей устройств и хеширование паролей администраторов.

* Пароли MikroTik нужно уметь расшифровывать (мы ими логинимся),
  поэтому используется симметричное шифрование Fernet (AES-128-CBC + HMAC).
* Пароли администраторов интерфейса расшифровывать не нужно,
  поэтому для них используется односторонний bcrypt.
"""

from __future__ import annotations

import bcrypt
from cryptography.fernet import Fernet, InvalidToken

from .config import settings

_fernet = Fernet(settings.fernet_key.encode())


# --------------------------------------------------------------- устройства
def encrypt(plain: str) -> str:
    """Зашифровать пароль устройства для хранения в БД."""
    return _fernet.encrypt((plain or "").encode("utf-8")).decode("ascii")


def decrypt(token: str) -> str:
    """
    Расшифровать пароль устройства.

    При повреждённых данных или смене FERNET_KEY возвращает пустую строку —
    так операция просто завершится ошибкой авторизации, а не уронит воркер.
    """
    if not token:
        return ""
    try:
        return _fernet.decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError):
        return ""


# ------------------------------------------------------------ администраторы
def hash_password(plain: str) -> str:
    """Получить bcrypt-хеш пароля администратора."""
    return bcrypt.hashpw(_truncate(plain), bcrypt.gensalt()).decode("ascii")


def verify_password(plain: str, hashed: str) -> bool:
    """Проверить пароль администратора против сохранённого хеша."""
    try:
        return bcrypt.checkpw(_truncate(plain), hashed.encode("ascii"))
    except (ValueError, TypeError):
        return False


def _truncate(plain: str) -> bytes:
    """bcrypt работает максимум с 72 байтами — аккуратно обрезаем длинные пароли."""
    return (plain or "").encode("utf-8")[:72]
