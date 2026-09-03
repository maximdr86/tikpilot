#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Run Tikpilot without Docker.
# Запуск Tikpilot без Docker.
#
# Creates a virtualenv if there is none, installs the dependencies and starts.
#
#   ./run.sh            normal start
#   ./run.sh --reload   development mode with auto-reload
#
# Messages follow your locale. Force one with TIKPILOT_LANG=ru or TIKPILOT_LANG=en.
# ---------------------------------------------------------------------------
set -euo pipefail

cd "$(dirname "$0")"

VENV=".venv"
PYTHON="${PYTHON:-python3}"

UI_LANG="${TIKPILOT_LANG:-}"
if [ -z "$UI_LANG" ]; then
    case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in
        ru*|RU*) UI_LANG="ru" ;;
        *)       UI_LANG="en" ;;
    esac
fi
t() { if [ "$UI_LANG" = "ru" ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }

# Наличия папки мало. Окружение, приехавшее вместе с проектом с другой
# машины, хранит абсолютный путь к прежнему интерпретатору в каждом
# скрипте bin, и запуск падает с невнятной ошибкой. Поэтому спрашиваем
# у окружения, работает ли оно, и пересобираем, когда нет.
if [ -x "$VENV/bin/python" ] && "$VENV/bin/python" -c "import uvicorn, fastapi" >/dev/null 2>&1; then
    :
else
    if [ -d "$VENV" ]; then
        echo "==> $(t "Environment in $VENV does not work here, rebuilding" \
                     "Окружение в $VENV здесь не работает, пересобираю")"
    else
        echo "==> $(t "Creating virtualenv $VENV" "Создаю виртуальное окружение $VENV")"
    fi
    "$PYTHON" -m venv --clear "$VENV"
    "$VENV/bin/python" -m pip install --upgrade pip
    "$VENV/bin/python" -m pip install -r requirements.txt
fi

# Pick up the settings from .env if it exists
if [ -f .env ]; then
    set -a; . ./.env; set +a
fi

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-8080}"

EXTRA=()
if [ "${1:-}" = "--reload" ]; then
    EXTRA+=(--reload)
fi

echo "==> $(t "Tikpilot is starting at" "Tikpilot запускается на") http://$HOST:$PORT"
# python -m, а не bin/uvicorn: у скрипта в bin в первой строке записан
# абсолютный путь к интерпретатору, с которым его ставили, и после
# переноса папки он указывает в никуда
exec "$VENV/bin/python" -m uvicorn app.main:app --host "$HOST" --port "$PORT" "${EXTRA[@]}"
