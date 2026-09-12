#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# Update a copy-installed Tikpilot in place.
# Обновление установленной копированием панели Tikpilot.
#
#   bash tools/update.sh              latest release / последний выпуск
#   bash tools/update.sh v1.75.0      a particular one / конкретный
#   bash tools/update.sh main         a branch, between releases / ветка
#   bash tools/update.sh ~/panel.tar.gz   from a local archive, no internet
#   bash tools/update.sh --check      only say what is available
#
# Without the script on disk yet, from the panel directory:
# Если скрипта в каталоге панели ещё нет, из него же:
#
#   curl -fsSL https://raw.githubusercontent.com/maximdr86/tikpilot/main/tools/update.sh \
#       | bash -s -- main
#
# Why this script exists: the panel is installed by copying files, not with
# git, so "git pull" is not an option and replacing directories by hand is
# easy to get wrong. Here the order is fixed: keep a copy, replace the code,
# restart, check, and roll back if the panel did not come up.
#
# What it never touches: data/ (database, keys, backups) and .env.
#
# Messages follow your locale. Force one with TIKPILOT_LANG=ru or TIKPILOT_LANG=en.
# ---------------------------------------------------------------------------
set -euo pipefail

REPO="maximdr86/tikpilot"

# Скрипт обновляет и сам себя, а bash читает файл по мере выполнения:
# подмена tools/update.sh на ходу рвёт разбор где-то на середине. Поэтому
# первым делом перезапускаемся из копии во временной папке и дальше
# работаем оттуда: тогда файл в проекте можно спокойно заменить.
#
# Если скрипт пришёл по конвейеру (`curl ... | bash`), подменять нечего:
# файла на диске нет, а чтение идёт из сети и от правок в каталоге панели
# не зависит. Тогда перезапуск не нужен, а каталогом считается текущий.
if [ "${TIKPILOT_UPDATE_COPY:-}" != "1" ]; then
    if [ -f "$0" ]; then
        SELF="$(mktemp "${TMPDIR:-/tmp}/tikpilot-update.XXXXXX")"
        cat "$0" > "$SELF"
        TIKPILOT_UPDATE_COPY=1 \
        TIKPILOT_UPDATE_ROOT="$(cd "$(dirname "$0")/.." && pwd)" \
        TIKPILOT_UPDATE_SELF="$SELF" \
            exec bash "$SELF" "$@"
    fi
    TIKPILOT_UPDATE_ROOT="$PWD"
    TIKPILOT_UPDATE_SELF=""
fi

ROOT="${TIKPILOT_UPDATE_ROOT:?}"
SELF="${TIKPILOT_UPDATE_SELF:-}"

UI_LANG="${TIKPILOT_LANG:-}"
if [ -z "$UI_LANG" ]; then
    case "${LC_ALL:-${LC_MESSAGES:-${LANG:-}}}" in
        ru*|RU*) UI_LANG="ru" ;;
        *)       UI_LANG="en" ;;
    esac
fi
t() { if [ "$UI_LANG" = "ru" ]; then printf '%s' "$2"; else printf '%s' "$1"; fi; }
say()  { echo "==> $*"; }
die()  { echo "ОШИБКА: $*" >&2; exit 1; }

cd "$ROOT"
[ -f app/main.py ] && [ -f app/__init__.py ] || die "$(t \
    "$ROOT does not look like a Tikpilot directory" \
    "в $ROOT не похоже на каталог панели Tikpilot")"

# --- что просили ------------------------------------------------------------
WANT=""
CHECK=0
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --check) CHECK=1 ;;
        --force) FORCE=1 ;;
        -*)      die "$(t "unknown option $arg" "неизвестный ключ $arg")" ;;
        *)       WANT="$arg" ;;
    esac
done

CURRENT="$(sed -n 's/^__version__ *= *"\(.*\)"/\1/p' app/__init__.py | head -1)"
[ -n "$CURRENT" ] || die "$(t "cannot read the installed version" \
                              "не удалось прочитать установленную версию")"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/tikpilot-src.XXXXXX")"
cleanup() { rm -rf "$WORK"; rm -f "$SELF"; }
trap cleanup EXIT

# Довод может быть и путём к архиву: на сервере без выхода в интернет выпуск
# приносят файлом, и отдельный способ обновления для такого случая был бы
# вторым скриптом, который расходится с первым.
if [ -n "$WANT" ] && [ -f "$WANT" ]; then
    cp "$WANT" "$WORK/src.tar.gz"
    SOURCE="$(t "local archive" "локальный архив")"
else
    if [ -n "$WANT" ]; then
        TAG="$WANT"
    else
        say "$(t "Asking GitHub for the latest release" "Спрашиваю у GitHub последний выпуск")"
        TAG="$(curl -fsSL -H 'User-Agent: tikpilot' \
               "https://api.github.com/repos/$REPO/releases/latest" \
               | sed -n 's/.*"tag_name" *: *"\([^"]*\)".*/\1/p' | head -1)" \
            || die "$(t "GitHub is unreachable" "GitHub недоступен")"
        [ -n "$TAG" ] || die "$(t "could not read the release tag" \
                                  "не удалось прочитать тег выпуска")"
    fi

    # Тег пишется как v1.75.0, в коде версия без «v». Сверяем до загрузки:
    # качать архив, чтобы узнать, что версия та же, незачем.
    #
    # `--check` отвечает на вопрос «что есть», поэтому печатает обе версии
    # всегда, в том числе когда они совпали: спросили про наличие
    # обновления, а не про то, надо ли что-то делать.
    if [ "$CHECK" = "1" ]; then
        echo "    $(t "installed" "установлено"): $CURRENT"
        echo "    $(t "available" "доступно"):    ${TAG#v}"
        if [ "${TAG#v}" = "$CURRENT" ]; then
            say "$(t "This is the latest release" "Это последний выпуск")"
        fi
        exit 0
    fi

    # Сначала пробуем тег, потом ветку. Так один и тот же довод работает
    # и для выпуска (`v1.75.0`), и для ветки (`main`): между выпусками код
    # берут из ветки, и отдельная команда для этого означала бы, что её
    # придётся помнить.
    say "$(t "Downloading" "Скачиваю") $TAG"
    if curl -fsSL -o "$WORK/src.tar.gz" \
            "https://github.com/$REPO/archive/refs/tags/$TAG.tar.gz" 2>/dev/null; then
        SOURCE="$TAG"
    elif curl -fsSL -o "$WORK/src.tar.gz" \
            "https://github.com/$REPO/archive/refs/heads/$TAG.tar.gz" 2>/dev/null; then
        SOURCE="$(t "branch" "ветка") $TAG"
        # У ветки версия в коде обычно та же, что установлена, а код другой.
        # Сравнивать версии тут бессмысленно, поэтому обновляем всегда.
        FORCE=1
    else
        die "$(t "could not download $TAG: no such tag or branch" \
               "не удалось скачать $TAG: нет такого тега или ветки")"
    fi
fi

tar xzf "$WORK/src.tar.gz" -C "$WORK" \
    || die "$(t "the archive is broken" "архив испорчен")"

SRC=""
for candidate in "$WORK"/*/; do
    [ -f "$candidate/app/main.py" ] && SRC="${candidate%/}" && break
done
# Архив панели из самой панели кладёт код в подкаталог иначе, чем GitHub,
# поэтому ищем каталог с app/main.py, а не верим имени. Проверка до подмены,
# а не после: испорченный архив, замеченный уже поверх рабочих файлов, это
# авария, а замеченный здесь просто осечка.
[ -n "$SRC" ] || die "$(t "the archive has no app/main.py inside" \
                          "в архиве нет app/main.py")"

# Версия берётся из самого кода, а не из имени тега: так надпись в конце
# не соврёт, даже если тег назвали не так, как версию внутри.
TARGET="$(sed -n 's/^__version__ *= *"\(.*\)"/\1/p' "$SRC/app/__init__.py" | head -1)"
TARGET="${TARGET:-${TAG:-?}}"
echo "    $(t "installed" "установлено"): $CURRENT"
echo "    $(t "available" "доступно"):    $TARGET  ($SOURCE)"

if [ "$CHECK" = "1" ]; then
    exit 0
fi
if [ "$TARGET" = "$CURRENT" ] && [ "$FORCE" = "0" ]; then
    say "$(t "Already up to date, nothing to do" "Уже эта версия, делать нечего")"
    exit 0
fi

# --- копия на случай отката --------------------------------------------------
BACKUP="$ROOT/.update-backup"
rm -rf "$BACKUP"
mkdir -p "$BACKUP"

# Что переносим: всё, что лежит в архиве, кроме настроек и данных.
# Список берётся из архива, а не задаётся здесь, иначе новый файл в выпуске
# пришлось бы не забыть дописать в скрипт, и однажды его забудут.
ITEMS=""
for path in "$SRC"/* "$SRC"/.[!.]*; do
    [ -e "$path" ] || continue
    name="$(basename "$path")"
    case "$name" in
        .env|data|.venv|.git|.github) continue ;;
    esac
    ITEMS="$ITEMS $name"
    [ -e "$ROOT/$name" ] && cp -R "$ROOT/$name" "$BACKUP/$name"
done
[ -n "$ITEMS" ] || die "$(t "nothing to copy from the archive" "из архива нечего копировать")"

restore() {
    say "$(t "Rolling back" "Откатываю")"
    for name in $ITEMS; do
        rm -rf "$ROOT/$name"
        [ -e "$BACKUP/$name" ] && cp -R "$BACKUP/$name" "$ROOT/$name"
    done
}

# --- подмена ----------------------------------------------------------------
say "$(t "Replacing the code" "Подменяю код")"
for name in $ITEMS; do
    # Старый каталог удаляется целиком: иначе файлы, исчезнувшие в новой
    # версии, остаются лежать и продолжают работать. Данные и .env в список
    # не попадают, поэтому удалять здесь нечего дорогого.
    rm -rf "$ROOT/$name"
    cp -R "$SRC/$name" "$ROOT/$name"
done

# --- зависимости, только если менялись --------------------------------------
if ! cmp -s "$BACKUP/requirements.txt" "$ROOT/requirements.txt"; then
    if [ -x "$ROOT/.venv/bin/python" ]; then
        say "$(t "Dependencies changed, installing" "Зависимости изменились, ставлю")"
        "$ROOT/.venv/bin/python" -m pip install -q -r "$ROOT/requirements.txt" \
            || { restore; die "$(t "pip failed, rolled back" "pip не справился, откатил")"; }
    else
        say "$(t "Dependencies changed; there is no .venv here, install them yourself" \
               "Зависимости изменились, окружения .venv здесь нет, поставьте сами")"
    fi
fi

# --- перезапуск --------------------------------------------------------------
PLIST="/Library/LaunchDaemons/ru.tikpilot.panel.plist"
UNIT="/etc/systemd/system/tikpilot.service"

restart() {
    if [ -f "$PLIST" ]; then
        sudo launchctl kickstart -k system/ru.tikpilot.panel
    elif [ -f "$UNIT" ]; then
        sudo systemctl restart tikpilot
    else
        return 1
    fi
}

if restart; then
    :
else
    say "$(t "No service found: restart the panel yourself" \
           "Службы не нашлось: перезапустите панель сами")"
    say "$(t "The code is updated to" "Код обновлён до") $TARGET"
    exit 0
fi

# --- проверка, что поднялась --------------------------------------------------
# Порт из .env: человек мог его сменить, и тогда стук в 8080 объявил бы
# здоровую панель мёртвой и откатил бы рабочее обновление.
PORT="$(sed -n 's/^ *PORT *= *\([0-9][0-9]*\).*/\1/p' "$ROOT/.env" 2>/dev/null | tail -1)"
PORT="${PORT:-8080}"

say "$(t "Waiting for the panel on port" "Жду панель на порту") $PORT"
ALIVE=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if curl -fsS "http://127.0.0.1:$PORT/healthz" >/dev/null 2>&1; then
        ALIVE=1
        break
    fi
    sleep 2
done

if [ "$ALIVE" = "0" ]; then
    restore
    restart || true
    echo ""
    die "$(t "the panel did not come up, rolled back to $CURRENT; look at data/panel.log" \
           "панель не поднялась, откатил на $CURRENT; смотрите data/panel.log")"
fi

if [ "$CURRENT" = "$TARGET" ]; then
    say "$(t "Done:" "Готово:") $TARGET ($SOURCE)"
else
    say "$(t "Done:" "Готово:") $CURRENT -> $TARGET ($SOURCE)"
fi
say "$(t "The previous code is in .update-backup, remove it when you are sure" \
       "Прежний код лежит в .update-backup, удалите, когда убедитесь")"
