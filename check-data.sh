#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Check the data directory after moving it to another server.
# Проверка каталога данных после переноса на другой сервер.
#
#   sudo bash /opt/tikpilot/check-data.sh
#
# It answers the main question of any migration: did data/fernet.key travel
# along with the database. Without it the device passwords cannot be decrypted,
# and you only find out during the first bulk operation, which is too late.
#
# Messages follow your locale. Force one with TIKPILOT_LANG=ru or TIKPILOT_LANG=en.
# ---------------------------------------------------------------------------
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/tikpilot}"
PY="$APP_DIR/.venv/bin/python"

UI_LANG="${TIKPILOT_LANG:-}"
if [ -z "$UI_LANG" ]; then
    case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in
        ru*|RU*) UI_LANG="ru" ;;
        *)       UI_LANG="en" ;;
    esac
fi

if [ ! -x "$PY" ]; then
    if [ "$UI_LANG" = "ru" ]; then
        echo "Не найдено окружение $PY" >&2
    else
        echo "No virtualenv found at $PY" >&2
    fi
    exit 1
fi

cd "$APP_DIR"
DATA_DIR="$APP_DIR/data" TIKPILOT_LANG="$UI_LANG" "$PY" - <<'PYCODE'
import os
import sys

from app.crypto import decrypt
from app.database import query, query_one

RU = os.getenv("TIKPILOT_LANG") == "ru"


def t(english: str, russian: str) -> str:
    return russian if RU else english


devices = query_one("SELECT COUNT(*) AS c FROM devices")["c"]
groups = query_one("SELECT COUNT(*) AS c FROM groups")["c"]
backups = query_one("SELECT COUNT(*) AS c FROM backups")["c"]
admins = [r["username"] for r in query("SELECT username FROM users ORDER BY username")]

print(f"  {t('devices:', 'устройств:'):<18}{devices}")
print(f"  {t('groups:', 'групп:'):<18}{groups}")
print(f"  {t('backup records:', 'записей бэкапов:'):<18}{backups}")
print(f"  {t('administrators:', 'администраторы:'):<18}{', '.join(admins) or '—'}")

# The main check: can the device passwords be read
broken = [
    r["name"] for r in query("SELECT name, password_enc FROM devices")
    if r["password_enc"] and not decrypt(r["password_enc"])
]
if broken:
    print()
    print("  [x] " + t(
        f"Passwords cannot be decrypted for {len(broken)} device(s).",
        f"Пароли не расшифровываются у {len(broken)} устройств.",
    ))
    print("      " + t(
        "Most likely data/fernet.key was not migrated.",
        "Скорее всего, не перенесён файл data/fernet.key.",
    ))
    print("      " + t(
        "Bring it over from the old machine, or the passwords have to be re-entered.",
        "Верните его со старой машины, иначе пароли придётся вводить заново.",
    ))
    print("      " + t("Examples:", "Примеры:"), ", ".join(broken[:5]))
    sys.exit(1)

print()
print("  [v] " + t(
    "The encryption key is in place, device passwords decrypt fine.",
    "Ключ шифрования на месте, пароли устройств читаются.",
))
PYCODE
