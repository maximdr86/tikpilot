#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Move an existing ROSmanager install to Tikpilot.
# Перенос установленного ROSmanager на новое имя Tikpilot.
#
#   sudo bash migrate-from-rosmanager.sh
#
# The project used to be called ROSmanager. The name collided with an existing
# project, so everything was renamed. This script moves a running install to
# the new name without losing any data.
#
# What happens, in this order:
#   1. the old install is validated, is the database there;
#   2. the old service is stopped and disabled;
#   3. install-ubuntu.sh installs the new one into /opt/tikpilot;
#   4. data and .env are copied over, the database file is renamed;
#   5. the new service is started and verified.
#
# The old directory is NOT deleted. It is renamed to /opt/rosmanager.old so
# that you can go back if anything looks wrong.
#
# Messages follow your locale. Force one with TIKPILOT_LANG=ru or TIKPILOT_LANG=en.
# ---------------------------------------------------------------------------
set -euo pipefail

OLD_DIR="/opt/rosmanager"
OLD_SERVICE="rosmanager"
NEW_DIR="/opt/tikpilot"
NEW_SERVICE="tikpilot"

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

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

# --- 1. Validate the old install BEFORE touching anything -------------------
say "$(t "Checking the old install" "Проверяю прежнюю установку")"

[ -d "$OLD_DIR" ] || die "$(t \
    "There is no $OLD_DIR. Nothing to migrate: install Tikpilot with install-ubuntu.sh." \
    "Каталога $OLD_DIR нет. Переносить нечего: ставьте Tikpilot через install-ubuntu.sh.")"

OLD_DB=""
for candidate in "$OLD_DIR/data/rosmanager.db" "$OLD_DIR/data/tikpilot.db"; do
    [ -f "$candidate" ] && OLD_DB="$candidate" && break
done
[ -n "$OLD_DB" ] || die "$(t \
    "No database found in $OLD_DIR/data. Migrating would lose everything, so stopping here." \
    "В $OLD_DIR/data нет базы. Перенос в таком виде потерял бы все данные, поэтому останавливаюсь.")"

echo "    $(t "database:" "база данных:") $(( $(stat -c%s "$OLD_DB") / 1024 )) $(t "KiB" "КиБ")"

if [ -f "$OLD_DIR/data/fernet.key" ]; then
    echo "    $(t "encryption key: present" "ключ шифрования: на месте")"
else
    warn "$(t "There is no fernet.key. Device passwords will not decrypt." \
             "Файла fernet.key нет. Пароли устройств не расшифруются.")"
fi

[ -f "$SRC_DIR/install-ubuntu.sh" ] || die "$(t \
    "install-ubuntu.sh is not next to this script. Run it from the project folder." \
    "Рядом нет install-ubuntu.sh. Запускайте из папки проекта.")"

if [ -d "$NEW_DIR/data" ] && [ -n "$(ls -A "$NEW_DIR/data" 2>/dev/null)" ]; then
    die "$(t \
        "$NEW_DIR/data already has data in it. Remove or rename it first, so that nothing is overwritten by accident." \
        "В $NEW_DIR/data уже есть данные. Уберите или переименуйте их, чтобы ничего не затёрлось случайно.")"
fi

# --- 2. Stop the old service ------------------------------------------------
say "$(t "Stopping the old service" "Останавливаю прежнюю службу")"
systemctl stop "$OLD_SERVICE" 2>/dev/null || true
systemctl disable "$OLD_SERVICE" 2>/dev/null || true

# --- 3. Install under the new name ------------------------------------------
# Настройки переносим ДО установщика. Иначе он решит, что установка новая,
# создаст свой .env со случайным паролем и напечатает его на экране, хотя
# работать будет старый пароль. Человек запомнит не тот.
if [ -f "$OLD_DIR/.env" ]; then
    say "$(t "Moving .env" "Переношу .env")"
    mkdir -p "$NEW_DIR"
    cp "$OLD_DIR/.env" "$NEW_DIR/.env"
fi

say "$(t "Installing Tikpilot" "Ставлю Tikpilot")"
TIKPILOT_LANG="$UI_LANG" bash "$SRC_DIR/install-ubuntu.sh"

# The installer starts the service; stop it while the data is being moved
systemctl stop "$NEW_SERVICE" 2>/dev/null || true

# --- 4. Move the data -------------------------------------------------------
say "$(t "Moving the data" "Переношу данные")"
rm -rf "$NEW_DIR/data"
cp -r "$OLD_DIR/data" "$NEW_DIR/data"

# The database changes its name along with the project
if [ -f "$NEW_DIR/data/rosmanager.db" ] && [ ! -f "$NEW_DIR/data/tikpilot.db" ]; then
    for suffix in "" "-wal" "-shm"; do
        [ -f "$NEW_DIR/data/rosmanager.db$suffix" ] && \
            mv "$NEW_DIR/data/rosmanager.db$suffix" "$NEW_DIR/data/tikpilot.db$suffix"
    done
    echo "    $(t "database renamed to tikpilot.db" "база переименована в tikpilot.db")"
fi

chown -R "$NEW_SERVICE":"$NEW_SERVICE" "$NEW_DIR/data" "$NEW_DIR/.env"
chmod 600 "$NEW_DIR/.env"

# --- 5. Start and verify ----------------------------------------------------
say "$(t "Starting Tikpilot" "Запускаю Tikpilot")"
systemctl start "$NEW_SERVICE"
sleep 4

if ! systemctl is-active --quiet "$NEW_SERVICE"; then
    warn "$(t "The service did not come up. Last lines of the log:" \
             "Служба не поднялась. Последние строки журнала:")"
    journalctl -u "$NEW_SERVICE" -n 25 --no-pager || true
    die "$(t "The old install is untouched at $OLD_DIR, you can go back to it." \
             "Прежняя установка не тронута и лежит в $OLD_DIR, к ней можно вернуться.")"
fi

if [ -f "$NEW_DIR/check-data.sh" ]; then
    say "$(t "Checking the data" "Проверяю данные")"
    bash "$NEW_DIR/check-data.sh" || warn "$(t \
        "The check found problems, see above" "Проверка нашла проблемы, смотрите выше")"
fi

# --- 6. Move the old directory aside ----------------------------------------
mv "$OLD_DIR" "$OLD_DIR.old"
rm -f "/etc/systemd/system/$OLD_SERVICE.service"
systemctl daemon-reload

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$IP" ] || IP="$(t "server-address" "адрес-сервера")"
PORT="$(grep -oP '^PORT=\K\d+' "$NEW_DIR/.env" 2>/dev/null || echo 8080)"

printf '\n\033[1;32m============================================================\033[0m\n'
printf '  %s  \033[1mhttp://%s:%s\033[0m\n' \
    "$(t "Tikpilot is running:" "Tikpilot работает:")" "$IP" "$PORT"
printf '\n  %s\n' "$(t \
    "The database, the accounts and the backups were carried over." \
    "База, учётные записи и бэкапы перенесены.")"
printf '  %s\n' "$(t \
    "Sign in with the same login and password as before." \
    "Вход тем же логином и паролем, что и раньше.")"
printf '\n  %s %s\n' "$(t "The old install was moved to" "Прежняя установка отодвинута в")" "$OLD_DIR.old"
printf '  %s\n' "$(t \
    "Check that everything is in place, then delete it by hand." \
    "Убедитесь, что всё на месте, и удалите её вручную.")"
printf '\n  %s\n' "$(t "Managing the service:" "Управление службой:")"
printf '    sudo systemctl status %s\n' "$NEW_SERVICE"
printf '    sudo journalctl -u %s -f\n' "$NEW_SERVICE"
printf '\033[1;32m============================================================\033[0m\n\n'
