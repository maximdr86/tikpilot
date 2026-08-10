#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Install Tikpilot on Ubuntu as a system service.
# Установка Tikpilot на Ubuntu как системной службы.
#
#   sudo bash install-ubuntu.sh
#
# Safe to run again: it doubles as an updater. Dependencies are reinstalled and
# the service restarted, while the database, the keys and .env are left alone.
#
# What it does:
#   * installs python3-venv and curl from the repositories;
#   * copies the project to /opt/tikpilot;
#   * creates a system user with no login shell;
#   * builds a virtualenv and installs the dependencies;
#   * writes .env with a random admin password (only if there is none);
#   * sets up a systemd service with autostart.
#
# Messages follow your locale. Force one with TIKPILOT_LANG=ru or TIKPILOT_LANG=en.
# ---------------------------------------------------------------------------
set -euo pipefail

APP_DIR="/opt/tikpilot"
APP_USER="tikpilot"
SERVICE="tikpilot"
PORT="${PORT:-8080}"

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- Язык сообщений ---------------------------------------------------------
# Русская локаль на сервере значит, что администратору привычнее по-русски.
# Во всех прочих случаях английский: проект международный.
UI_LANG="${TIKPILOT_LANG:-}"
if [ -z "$UI_LANG" ]; then
    case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in
        ru*|RU*) UI_LANG="ru" ;;
        *)       UI_LANG="en" ;;
    esac
fi

# t "english text" "русский текст"
t() { if [ "$UI_LANG" = "ru" ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m [!]\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m [x]\033[0m %s\n\n' "$*" >&2; exit 1; }

# --- 0. Checks --------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "$(t \
    "Run it with sudo:  sudo bash install-ubuntu.sh" \
    "Запустите через sudo:  sudo bash install-ubuntu.sh")"

[ -f "$SRC_DIR/requirements.txt" ] || die "$(t \
    "There is no requirements.txt next to the script. It looks like you are not in the project folder." \
    "Рядом со скриптом нет requirements.txt. Похоже, скрипт запущен не из папки проекта.")"

say "$(t "Installing Tikpilot into $APP_DIR" "Устанавливаю Tikpilot в $APP_DIR")"

# --- 1. System packages -----------------------------------------------------
say "$(t "Installing system packages" "Ставлю системные пакеты")"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3 python3-venv python3-pip ca-certificates curl >/dev/null
echo "    python3 $(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:3])))')"

# --- 2. User ----------------------------------------------------------------
if ! id "$APP_USER" >/dev/null 2>&1; then
    say "$(t "Creating system user $APP_USER" "Создаю системного пользователя $APP_USER")"
    useradd --system --home-dir "$APP_DIR" --shell /usr/sbin/nologin "$APP_USER"
else
    echo "    $(t "user $APP_USER already exists" "пользователь $APP_USER уже есть")"
fi

# --- 3. Application files ---------------------------------------------------
say "$(t "Copying application files" "Копирую файлы приложения")"
mkdir -p "$APP_DIR"
# Data, the virtualenv and .env are left alone: they survive an update
for item in app templates static requirements.txt requirements-dev.txt tests \
            README.md README.ru.md CHANGELOG.md LICENSE .env.example \
            run.sh check-data.sh restore-data.sh migrate-from-rosmanager.sh; do
    [ -e "$SRC_DIR/$item" ] && cp -r "$SRC_DIR/$item" "$APP_DIR/" || true
done
mkdir -p "$APP_DIR/data/backups"

# --- 4. Configuration -------------------------------------------------------
FRESH_INSTALL=0
if [ ! -f "$APP_DIR/data/tikpilot.db" ]; then
    FRESH_INSTALL=1
fi

if [ -f "$SRC_DIR/.env" ] && [ ! -f "$APP_DIR/.env" ]; then
    say "$(t "Moving .env from the project folder" "Переношу .env из папки проекта")"
    cp "$SRC_DIR/.env" "$APP_DIR/.env"
fi

if [ ! -f "$APP_DIR/.env" ]; then
    say "$(t "Creating .env" "Создаю .env")"
    ADMIN_PASS="$(python3 -c 'import secrets; print(secrets.token_urlsafe(12))')"
    cat > "$APP_DIR/.env" <<EOF
# $(t "Written by the installer on" "Создано установщиком") $(date '+%Y-%m-%d %H:%M')
# $(t "The full list of options with comments is in .env.example" \
     "Полный список параметров с пояснениями в .env.example")

ADMIN_USERNAME=admin
ADMIN_PASSWORD=$ADMIN_PASS

HOST=0.0.0.0
PORT=$PORT

# $(t "Interface language: en or ru" "Язык интерфейса: en или ru")
DEFAULT_LANG=$UI_LANG

# $(t "Ping targets: address=label, comma-separated" \
     "Цели пинга: адрес=подпись, через запятую")
LATENCY_TARGETS=8.8.8.8=$(t "internet" "интернет")
# $(t "ISP gateways often do not answer ICMP" \
     "Шлюзы провайдеров часто не отвечают на ICMP")
LATENCY_PING_GATEWAY=0
EOF
else
    ADMIN_PASS=""
    echo "    $(t ".env already exists, leaving it as is" ".env уже есть, оставляю как есть")"
fi

# --- 5. Virtualenv ----------------------------------------------------------
say "$(t "Building the environment and installing dependencies" \
        "Собираю окружение и ставлю зависимости")"
if [ ! -x "$APP_DIR/.venv/bin/python" ]; then
    python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/python" -m pip install --upgrade pip --quiet --disable-pip-version-check
"$APP_DIR/.venv/bin/pip" install -r "$APP_DIR/requirements.txt" --quiet --disable-pip-version-check
echo "    $(t "dependencies installed" "зависимости установлены")"

# --- 6. Permissions ---------------------------------------------------------
chown -R "$APP_USER":"$APP_USER" "$APP_DIR"
chmod 750 "$APP_DIR"
chmod 600 "$APP_DIR/.env"

# --- 7. systemd service -----------------------------------------------------
say "$(t "Setting up the systemd service" "Настраиваю службу systemd")"
cat > "/etc/systemd/system/$SERVICE.service" <<EOF
[Unit]
Description=Tikpilot, a web UI for managing a MikroTik fleet
Documentation=file://$APP_DIR/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=$APP_USER
Group=$APP_USER
WorkingDirectory=$APP_DIR
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=$APP_DIR/.venv/bin/uvicorn app.main:app --host 0.0.0.0 --port $PORT
Restart=always
RestartSec=5

# The service only needs its own directory and the network
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$APP_DIR/data
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

# With a firewall enabled the port has to be opened, or the UI is unreachable
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "^Status: active"; then
    say "$(t "Opening port $PORT in ufw" "Открываю порт $PORT в ufw")"
    ufw allow "$PORT/tcp" >/dev/null 2>&1 || warn "$(t \
        "Could not add the ufw rule, open the port manually" \
        "Не удалось добавить правило ufw, откройте порт вручную")"
    # Приём журнала с роутеров. Порт высокий, особых прав не требует.
    SYSLOG_PORT="$(grep -E "^SYSLOG_UDP_PORT=" "$APP_DIR/.env" 2>/dev/null | cut -d= -f2)"
    SYSLOG_PORT="${SYSLOG_PORT:-5514}"
    ufw allow "$SYSLOG_PORT/udp" >/dev/null 2>&1 || true
    ufw allow "$SYSLOG_PORT/tcp" >/dev/null 2>&1 || true
fi

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1
systemctl restart "$SERVICE"

# --- 8. Verification --------------------------------------------------------
say "$(t "Checking that the service is up" "Проверяю, что служба поднялась")"
sleep 4
if ! systemctl is-active --quiet "$SERVICE"; then
    warn "$(t "The service did not start. Last lines of the log:" \
             "Служба не запустилась. Последние строки журнала:")"
    journalctl -u "$SERVICE" -n 30 --no-pager || true
    die "$(t "Fix the error above and run the script again." \
             "Разберитесь с ошибкой выше и запустите скрипт заново.")"
fi

for _ in $(seq 1 10); do
    if curl -fsS "http://127.0.0.1:$PORT/login" >/dev/null 2>&1; then
        OK=1; break
    fi
    sleep 1
done

IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
[ -n "$IP" ] || IP="$(t "server-address" "адрес-сервера")"

printf '\n\033[1;32m============================================================\033[0m\n'
if [ "${OK:-0}" = "1" ]; then
    printf '  %s  \033[1mhttp://%s:%s\033[0m\n' \
        "$(t "Tikpilot is running:" "Tikpilot работает:")" "$IP" "$PORT"
else
    warn "$(t "The service is running but the UI does not answer yet, check the log." \
             "Служба запущена, но интерфейс пока не отвечает, проверьте журнал.")"
fi

if [ "$FRESH_INSTALL" = "1" ] && [ -n "${ADMIN_PASS:-}" ]; then
    printf '\n  %s  \033[1madmin\033[0m\n' "$(t "Login:   " "Логин:  ")"
    printf '  %s \033[1m%s\033[0m\n' "$(t "Password:" "Пароль: ")" "$ADMIN_PASS"
    printf '\n  \033[1;33m%s\033[0m\n' "$(t \
        "Write the password down, it is shown only once." \
        "Запишите пароль, он показывается один раз.")"
    printf '  %s\n' "$(t "You can change it under Settings." \
                         "Сменить можно в разделе «Настройки».")"
elif [ "$FRESH_INSTALL" = "1" ]; then
    printf '\n  %s %s/.env\n' \
        "$(t "The login and password are in" "Логин и пароль в файле")" "$APP_DIR"
else
    printf '\n  %s\n' "$(t \
        "The database and the accounts were kept from the previous install." \
        "База и учётные записи сохранены от прошлой установки.")"
fi

cat <<EOF

  $(t "Managing the service:" "Управление службой:")
    sudo systemctl status $SERVICE      $(t "state" "состояние")
    sudo systemctl restart $SERVICE     $(t "restart" "перезапуск")
    sudo journalctl -u $SERVICE -f      $(t "live log" "журнал в реальном времени")

  $(t "Settings:" "Настройки:")  $APP_DIR/.env   $(t "(restart after editing)" "(после правки restart)")
  $(t "Data:    " "Данные:   ")  $APP_DIR/data   $(t "(database, keys, backups)" "(база, ключи шифрования, бэкапы)")

EOF
printf '\033[1;32m============================================================\033[0m\n\n'
