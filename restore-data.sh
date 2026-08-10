#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Safely restore the Tikpilot data directory.
# Безопасное восстановление каталога данных Tikpilot.
#
#   sudo bash restore-data.sh /home/user/tikpilot-data
#
# The order of steps is chosen so that nothing can be lost:
#   1. validate the source first, is the database and the key there;
#   2. only then stop the service;
#   3. the current data is NOT deleted but moved to data.bak-<date>;
#   4. copy, fix the permissions, start;
#   5. verify that the database reads and the passwords decrypt.
#
# If anything goes wrong at any step, the previous data stays where it was.
#
# Messages follow your locale. Force one with TIKPILOT_LANG=ru or TIKPILOT_LANG=en.
# ---------------------------------------------------------------------------
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/tikpilot}"
APP_USER="${APP_USER:-tikpilot}"
SERVICE="${SERVICE:-tikpilot}"
SRC="${1:-}"

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
die()  { printf '\n\033[1;31m [x]\033[0m %s\n\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "$(t "Run it with sudo" "Запустите через sudo")"

# --- 1. Where to look for the data ------------------------------------------
if [ -z "$SRC" ]; then
    say "$(t "No path given, looking for the data directory" \
            "Путь не указан, ищу каталог данных")"
    # Any folder with tikpilot.db inside will do. After a migration the name
    # often differs: it can be "data" or "tikpilot-data".
    for candidate in \
        /home/*/tikpilot-data /root/tikpilot-data /tmp/tikpilot-data \
        /home/*/data /root/data /tmp/data \
        /home/*/*/data; do
        if [ -f "$candidate/tikpilot.db" ]; then
            SRC="$candidate"
            echo "    $(t "found:" "нашёл:") $SRC"
            break
        fi
    done
fi

[ -n "$SRC" ] || die "$(t \
    "Could not find the data folder. Pass the path explicitly:  sudo bash restore-data.sh /path/to/tikpilot-data" \
    "Не нашёл папку с данными. Укажите путь явно:  sudo bash restore-data.sh /путь/к/tikpilot-data")"
[ -d "$SRC" ] || die "$(t "Folder not found:" "Папка не найдена:") $SRC"

# --- 2. Validate the source BEFORE touching anything ------------------------
say "$(t "Checking the contents of $SRC" "Проверяю содержимое $SRC")"
[ -f "$SRC/tikpilot.db" ] || die "$(t \
    "There is no tikpilot.db in that folder. You may have pointed at the project directory instead of its data directory: try a path ending in /data." \
    "В папке нет tikpilot.db. Возможно, вы указали каталог проекта вместо каталога data: попробуйте путь, оканчивающийся на /data.")"

DB_SIZE=$(stat -c%s "$SRC/tikpilot.db")
echo "    $(t "database:" "база данных:") $((DB_SIZE / 1024)) $(t "KiB" "КиБ")"

if [ ! -f "$SRC/fernet.key" ]; then
    warn "$(t "There is NO fernet.key in that folder. It is the key that encrypts device passwords." \
             "В папке НЕТ файла fernet.key, это ключ шифрования паролей устройств.")"
    warn "$(t "Without it the devices will be listed, but nothing will connect to them." \
             "Без него устройства будут в списке, но подключиться к ним не выйдет.")"
    printf '\n    %s [y/N] ' "$(t "Continue anyway?" "Продолжить всё равно?")"
    # Read from the terminal. With no terminal (called from a script) assume "no".
    answer="n"
    if [ -r /dev/tty ]; then
        read -r answer < /dev/tty || answer="n"
    fi
    case "$answer" in
        [yY]) ;;
        *) die "$(t "Cancelled. Copy fernet.key from the old machine and try again." \
                    "Отменено. Скопируйте fernet.key со старой машины и повторите.")" ;;
    esac
else
    echo "    $(t "encryption key: present" "ключ шифрования: на месте")"
fi

# --- 3. Stop the service ----------------------------------------------------
say "$(t "Stopping the service" "Останавливаю службу")"
systemctl stop "$SERVICE" 2>/dev/null || true

# --- 4. Move the old data aside instead of deleting it ----------------------
if [ -d "$APP_DIR/data" ] && [ -n "$(ls -A "$APP_DIR/data" 2>/dev/null)" ]; then
    BACKUP="$APP_DIR/data.bak-$(date +%Y%m%d-%H%M%S)"
    say "$(t "Moving the previous data to $BACKUP" \
            "Прежние данные отодвигаю в $BACKUP")"
    mv "$APP_DIR/data" "$BACKUP"
fi

# --- 5. Copy ----------------------------------------------------------------
say "$(t "Copying the data" "Копирую данные")"
mkdir -p "$APP_DIR"
cp -r "$SRC" "$APP_DIR/data"
mkdir -p "$APP_DIR/data/backups"
chown -R "$APP_USER":"$APP_USER" "$APP_DIR/data"

# --- 6. Start ---------------------------------------------------------------
say "$(t "Starting the service" "Запускаю службу")"
systemctl start "$SERVICE"
sleep 4

if ! systemctl is-active --quiet "$SERVICE"; then
    warn "$(t "The service did not come up. Last lines of the log:" \
             "Служба не поднялась. Последние строки журнала:")"
    journalctl -u "$SERVICE" -n 25 --no-pager || true
    die "$(t "The previous data is kept next to it, you can put it back." \
             "Прежние данные сохранены рядом, можно вернуть их обратно.")"
fi

# --- 7. Verify that the data reads ------------------------------------------
say "$(t "Checking the data" "Проверяю данные")"
if [ -f "$APP_DIR/check-data.sh" ]; then
    bash "$APP_DIR/check-data.sh" || warn "$(t \
        "The check found problems, see above" "Проверка нашла проблемы, смотрите выше")"
fi

printf '\n\033[1;32m============================================================\033[0m\n'
printf '  %s\n' "$(t \
    "Data restored. Sign in with the login and password from the old machine." \
    "Данные восстановлены. Вход логином и паролем со старой машины.")"
if ls -d "$APP_DIR"/data.bak-* >/dev/null 2>&1; then
    printf '\n  %s\n' "$(t "The previous data is next to it:" "Прежние данные лежат рядом:")"
    ls -d "$APP_DIR"/data.bak-* | sed 's/^/    /'
    printf '  %s\n' "$(t "Make sure everything is in place, then delete it by hand." \
                         "Убедитесь, что всё на месте, и удалите их вручную.")"
fi
printf '\033[1;32m============================================================\033[0m\n\n'
