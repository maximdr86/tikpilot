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

if [ ! -d "$VENV" ]; then
    echo "==> $(t "Creating virtualenv $VENV" "Создаю виртуальное окружение $VENV")"
    "$PYTHON" -m venv "$VENV"
    "$VENV/bin/pip" install --upgrade pip
    "$VENV/bin/pip" install -r requirements.txt
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
exec "$VENV/bin/uvicorn" app.main:app --host "$HOST" --port "$PORT" "${EXTRA[@]}"
