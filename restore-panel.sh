#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Deploy Tikpilot from a panel archive onto a clean Ubuntu machine.
# Разворачивание Tikpilot из архива панели на чистой Ubuntu.
#
#   sudo bash restore.sh          from inside the unpacked archive
#   sudo bash restore.sh --yes    without the confirmation question
#
# The archive already holds everything: the code, the database, the encryption
# key, the settings and the router backups. The script puts the data in place
# and then hands over to install-ubuntu.sh, which builds the environment and
# sets up the service.
#
# Nothing is deleted. An existing installation is moved aside to data.bak-<date>
# and .env.bak-<date>, so a mistake stays reversible.
#
# Messages follow your locale. Force one with TIKPILOT_LANG=ru or TIKPILOT_LANG=en.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

APP_DIR="${APP_DIR:-/opt/tikpilot}"
APP_USER="${APP_USER:-tikpilot}"
SERVICE="${SERVICE:-tikpilot}"
STAMP="$(date '+%Y%m%d-%H%M%S')"
ASSUME_YES=0
[ "${1:-}" = "--yes" ] && ASSUME_YES=1

UI_LANG="${TIKPILOT_LANG:-}"
if [ -z "$UI_LANG" ]; then
    case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in
        ru*|RU*) UI_LANG="ru" ;;
        *)       UI_LANG="en" ;;
    esac
fi
t() { if [ "$UI_LANG" = "ru" ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m [!]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m [v]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m [x]\033[0m %s\n\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "$(t \
    "Run it with sudo:  sudo bash restore.sh" \
    "Запустите через sudo:  sudo bash restore.sh")"

# --- 1. Is this really an archive -------------------------------------------
# Checked before anything is touched: a wrong folder must not cost the current
# installation.
for required in data/tikpilot.db app/main.py install-ubuntu.sh requirements.txt; do
    [ -e "$required" ] || die "$(t \
        "No $required next to the script. Run it from inside the unpacked archive." \
        "Рядом со скриптом нет $required. Запустите его из распакованного архива.")"
done

if [ -f manifest.json ]; then
    say "$(t "Archive" "Архив")"
    python3 - <<'PY' || true
import json
data = json.load(open("manifest.json", encoding="utf-8"))
rows = [
    ("версия панели", data.get("version", "?")),
    ("создан", data.get("created", "?")),
    ("устройств", data.get("devices", "?")),
    ("пользователей", data.get("users", "?")),
    ("копий роутеров", data.get("device_backups", "?")),
]
for name, value in rows:
    print("    %-16s %s" % (name, value))
PY
fi

# --- 2. An existing installation is moved aside, never deleted --------------
HAD_OLD=0
if [ -f "$APP_DIR/data/tikpilot.db" ]; then
    HAD_OLD=1
    warn "$(t "There is already a panel in $APP_DIR with its own database." \
             "В $APP_DIR уже стоит панель со своей базой.")"
    echo "    $(t "It will be moved to data.bak-$STAMP, nothing is deleted." \
                  "Она будет отодвинута в data.bak-$STAMP, ничего не удаляется.")"
    if [ "$ASSUME_YES" != "1" ]; then
        printf '\n    %s ' "$(t "Continue? [y/N]" "Продолжить? [y/N]")"
        read -r answer </dev/tty || answer=""
        case "$answer" in
            [yY]|[yY][eE][sS]|[dD]|[dD][aA]) ;;
            *) die "$(t "Cancelled, nothing was changed." "Отменено, ничего не менялось.")" ;;
        esac
    fi
fi

if systemctl list-unit-files 2>/dev/null | grep -q "^$SERVICE.service"; then
    say "$(t "Stopping the service" "Останавливаю службу")"
    systemctl stop "$SERVICE" || true
fi

if [ "$HAD_OLD" = "1" ]; then
    say "$(t "Moving the old data aside" "Отодвигаю старые данные")"
    mv "$APP_DIR/data" "$APP_DIR/data.bak-$STAMP"
    echo "    $APP_DIR/data.bak-$STAMP"
    if [ -f "$APP_DIR/.env" ]; then
        mv "$APP_DIR/.env" "$APP_DIR/.env.bak-$STAMP"
        echo "    $APP_DIR/.env.bak-$STAMP"
    fi
fi

# --- 3. Data into place before the installer runs ---------------------------
# The installer leaves an existing database and .env alone, so putting them
# first means it will not create an empty base with a random password.
say "$(t "Unpacking the data" "Раскладываю данные")"
mkdir -p "$APP_DIR/data/backups"
cp data/tikpilot.db "$APP_DIR/data/tikpilot.db"
echo "    tikpilot.db"

if [ -f data/fernet.key ]; then
    cp data/fernet.key "$APP_DIR/data/fernet.key"
    chmod 600 "$APP_DIR/data/fernet.key"
    echo "    fernet.key"
else
    warn "$(t "There is no fernet.key in the archive: device passwords will not decrypt." \
             "В архиве нет fernet.key: пароли устройств не расшифруются.")"
fi

if [ -d data/backups ] && [ -n "$(ls -A data/backups 2>/dev/null)" ]; then
    cp -r data/backups/. "$APP_DIR/data/backups/"
    echo "    $(t "router backups" "копии роутеров"): $(ls -1 data/backups | wc -l)"
fi

if [ -f env ]; then
    cp env "$APP_DIR/.env"
    chmod 600 "$APP_DIR/.env"
    echo "    .env"
fi

# --- 4. The installer does the rest -----------------------------------------
say "$(t "Installing the application" "Ставлю приложение")"
bash install-ubuntu.sh

# --- 5. Verification --------------------------------------------------------
# Not «the service is up» but «the data really arrived»: a running panel with
# an empty base is the failure that hurts most.
say "$(t "Checking the restored data" "Проверяю восстановленные данные")"
"$APP_DIR/.venv/bin/python" - <<PY
import sqlite3, sys
sys.path.insert(0, "$APP_DIR")
conn = sqlite3.connect("$APP_DIR/data/tikpilot.db")
devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
row = conn.execute(
    "SELECT password_enc FROM devices WHERE password_enc <> '' LIMIT 1").fetchone()
conn.close()
print("    $(t "devices" "устройств"): %d, $(t "users" "пользователей"): %d" % (devices, users))
if row:
    import os
    os.environ.setdefault("DATA_DIR", "$APP_DIR/data")
    from app.crypto import decrypt
    try:
        decrypt(row[0])
        print("    $(t "device passwords decrypt" "пароли устройств расшифровываются")")
    except Exception as exc:
        print("    [x] $(t "passwords do NOT decrypt" "пароли НЕ расшифровываются"): %s" % exc)
        raise SystemExit(1)
PY

echo
ok "$(t "The panel has been restored." "Панель восстановлена.")"
echo "    $(t "Log in with the same username and password as before: they live in the database." \
              "Вход тем же логином и паролем, что и раньше: они лежат в базе.")"
if [ "$HAD_OLD" = "1" ]; then
    echo
    warn "$(t "The previous installation is kept in:" "Прежняя установка лежит в:")"
    echo "    $APP_DIR/data.bak-$STAMP"
    echo "    $(t "Remove it once you are sure everything works." \
                  "Удалите её, когда убедитесь, что всё работает.")"
fi
