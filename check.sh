#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Одна команда, которой проверяют правку.
#
#   ./check.sh          быстро: тесты без ожиданий, переводы, импорт модулей
#   ./check.sh --all    всё целиком, включая тесты с настоящими паузами
#
# Быстрый режим пропускает проверки с меткой slow: они ждут по-настоящему
# (перезагрузка устройства, медленная загрузка пакетов, отложенный запуск),
# и время там не накладные расходы, а предмет проверки. Перед выпуском
# и в CI гоняется всё.
#
# Переводы проверяются здесь же, а не только тестом: забытая строка это
# самая частая мелкая поломка, и узнавать о ней хочется сразу.
# ---------------------------------------------------------------------------
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

ALL=0
[ "${1:-}" = "--all" ] && ALL=1

PY=python3
[ -x .venv/bin/python ] && PY=.venv/bin/python

# Свой каталог данных: проверка не должна трогать рабочую базу
export DATA_DIR="${DATA_DIR:-$(mktemp -d)}"
export MONITOR_ENABLED=0
# Настройки рабочего .env мешают: ограничение по сетям закрывает панель
# от тестового клиента, внешний адрес подменяет ссылки
export ADMIN_NETWORKS=""
export PUBLIC_BASE_URL=""

fail=0
step() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
bad()  { printf '\033[1;31m [x]\033[0m %s\n' "$*"; fail=1; }
ok()   { printf '\033[1;32m [v]\033[0m %s\n' "$*"; }

step "Модули"
if $PY -c "import app.main" 2>/dev/null; then
    ok "импортируются"
else
    bad "приложение не импортируется"
    $PY -c "import app.main"
fi

step "Переводы"
$PY - <<'PY' || fail=1
from pathlib import Path

from app import i18n

i18n.load_catalogs()
problems = 0

for lang in ("en",):
    missing = i18n.missing_translations(lang, Path("templates"))
    if missing:
        problems += len(missing)
        print(f" [x] нет перевода на {lang}: {len(missing)}")
        for line in missing[:10]:
            print("     " + line[:100])

    catalog = i18n.js_catalog(lang)
    js = [s for s in i18n.js_strings() if s not in catalog]
    if js:
        problems += len(js)
        print(f" [x] нет перевода строк из браузера: {len(js)}")
        for line in js[:10]:
            print("     " + line[:100])

if not problems:
    print(" [v] всё переведено")
raise SystemExit(1 if problems else 0)
PY

step "Тесты"
if [ "$ALL" = "1" ]; then
    $PY -m pytest -q -p no:cacheprovider || fail=1
else
    $PY -m pytest -q -p no:cacheprovider -m "not slow" || fail=1
    printf '\033[1;33m [!]\033[0m %s\n' "пропущены тесты с ожиданиями, перед выпуском: ./check.sh --all"
fi

echo
if [ "$fail" = "0" ]; then
    printf '\033[1;32m========== порядок ==========\033[0m\n'
else
    printf '\033[1;31m========== есть проблемы ==========\033[0m\n'
fi
exit "$fail"
