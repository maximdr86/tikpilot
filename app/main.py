"""
Точка входа приложения Tikpilot.

Запуск:
    uvicorn app.main:app --host 0.0.0.0 --port 8080
или просто:
    python -m app.main
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from . import __version__, demo, monitor, operator, prefs, snippets, syslog, worker
from .auth import Forbidden, RedirectException, read_session, redirect_exception_handler
from .config import BASE_DIR, settings
from . import activity
from .database import init_db
from .routes.deps import LANG_COOKIE
from .routes import (
    auth_routes, backups, clients, devices, groups, jobs, pages, public,
    snippets as snippet_routes, syslog as syslog_routes,
    terminal as terminal_routes, visits, wireguard,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("tikpilot")


def _self_check() -> None:
    """
    Убедиться, что модули согласованы между собой.

    Если рядом лежат несколько копий проекта и сервер запущен из старой,
    отдельные действия падают с невнятной ошибкой посреди массовой задачи.
    Лучше сказать об этом громко и сразу при старте.
    """
    from .mikrotik import MikroTik

    required = ("update_info", "wait_until_back", "routerboard_info")
    missing = [name for name in required if not hasattr(MikroTik, name)]
    if missing:
        log.error("=" * 70)
        log.error("ВНИМАНИЕ: загружен устаревший код (нет методов: %s)", ", ".join(missing))
        log.error("Каталог программы: %s", BASE_DIR)
        log.error("Похоже, сервер запущен не из той папки. Обновление RouterOS работать не будет.")
        log.error("=" * 70)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Инициализация БД и запуск фонового воркера на старте, остановка — на выходе."""
    init_db()
    _self_check()
    # Предлагаемые правила журнала заводятся выключенными и только один раз:
    # решение прятать часть журнала принимает человек. Ставим до приёмника,
    # чтобы первая же строка проверялась по полному набору
    syslog.install_builtin_rules()
    # Маркеры записей библиотеки: у старых записей имя одно, а создают они
    # и скрипт, и расписание. Проход разовый по сути, но дешёвый
    # Сохранённые в панели настройки накладываются до запуска монитора:
    # иначе первый цикл пройдёт по интервалам из .env
    tuned = prefs.apply()
    if tuned:
        log.info("Настройки из панели применены: %s", tuned)

    filled = snippets.backfill_markers()
    if filled:
        log.info("Библиотека: уточнены имена у записей: %s", filled)
    # Список соответствий для операторов пополняется чаще, чем опрашивается
    # парк: применяем его сразу ко всему, что уже найдено
    renamed = operator.rename_known()
    if renamed:
        log.info("Операторы: приведены к человеческим именам: %s", renamed)
    # Буфер живой консоли подключаем до фоновых потоков: иначе первые
    # строки, самые интересные при разборе проблем со стартом, пропадут
    activity.install()
    worker.start()
    monitor.start()
    syslog.start()
    log.info("Tikpilot %s готов: http://%s:%s", __version__, settings.host, settings.port)
    log.info("Каталог программы: %s | база: %s", BASE_DIR, settings.db_path)
    yield
    syslog.stop()
    monitor.stop()
    worker.stop()


app = FastAPI(
    title="Tikpilot",
    description="Веб-интерфейс управления парком MikroTik",
    version=__version__,
    lifespan=lifespan,
    docs_url=None,       # встроенная документация не нужна и лишний раз светит API
    redoc_url=None,
    openapi_url=None,
)

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")

@app.middleware("http")
async def restrict_to_admin_networks(request: Request, call_next):
    """
    Пускать в панель только с доверенных сетей.

    Публичный лист состояния и его оформление открыты всем: ради них порт
    и пробрасывают наружу. Всё остальное, включая форму входа, отвечает 403.

    Настройка пустая по умолчанию, поэтому обновление программы ни у кого
    ничего не отнимает.
    """
    from .netguard import allowed, is_public_path

    if settings.admin_networks and not is_public_path(request.url.path):
        peer = request.client.host if request.client else ""
        forwarded = request.headers.get("x-forwarded-for", "")
        if not allowed(peer, forwarded, settings.admin_networks, settings.trusted_proxies):
            log.warning("Доступ к панели с недоверенного адреса: %s %s",
                        peer, request.url.path)
            return PlainTextResponse(
                "Панель доступна только из доверенной сети.\n"
                "The panel is only available from a trusted network.",
                status_code=403,
            )

    return await call_next(request)


@app.middleware("http")
async def screenshot_mode(request: Request, call_next):
    """
    Подменить настоящие данные вымышленными, если включён режим витрины.

    Подмена делается на выходе, над готовым ответом. Так она не может
    испортить базу и не может что-то пропустить: страница, кусок таблицы,
    ответ живой ленты - всё уходит в браузер через одно место.

    Трогаем только страницы и JSON. Выгрузки, бэкапы и картинки идут
    мимо: человек качает их себе, а не показывает на экране.
    """
    response = await call_next(request)
    if not demo.enabled(request) or request.url.path.startswith("/static"):
        return response

    kind = response.headers.get("content-type", "")
    if not kind.startswith(("text/html", "application/json", "text/plain")):
        return response

    body = b"".join([chunk async for chunk in response.body_iterator])
    try:
        # Язык страницы важен и для подмен: русское «Кафе Ромашка»
        # посреди английской таблицы выглядит случайностью
        lang = request.cookies.get(LANG_COOKIE, "") or "ru"
        masked = demo.mask(body.decode("utf-8"), lang).encode("utf-8")
    except UnicodeDecodeError:
        masked = body

    headers = dict(response.headers)
    headers.pop("content-length", None)
    return Response(content=masked, status_code=response.status_code,
                    headers=headers, media_type=kind)


# Порядок подключения роутеров значения не имеет — пути не пересекаются
app.include_router(auth_routes.router)
app.include_router(pages.router)
app.include_router(devices.router)
app.include_router(groups.router)
app.include_router(jobs.router)
app.include_router(backups.router)
app.include_router(wireguard.router)
# Публичный лист состояния: единственный роут без авторизации
app.include_router(clients.router)
app.include_router(syslog_routes.router)
app.include_router(terminal_routes.router)
app.include_router(visits.router)
app.include_router(snippet_routes.router)
app.include_router(public.router)

# Незалогиненный пользователь на обычной странице → редирект на форму входа
app.add_exception_handler(RedirectException, redirect_exception_handler)


@app.exception_handler(Forbidden)
async def forbidden(request: Request, exc: Forbidden):
    """
    Не хватило прав.

    Для API отвечаем кодом 403, для страницы показываем понятное объяснение
    вместо пустого экрана: человек должен понять, что дело в правах, а не
    в поломке.
    """
    from .routes.deps import render

    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": exc.detail}, status_code=403)

    user = read_session(request)
    if user is None:
        return RedirectResponse("/login", status_code=303)
    return render("forbidden.html", request, user, status_code=403)


@app.exception_handler(404)
async def not_found(request: Request, _exc):
    """Аккуратная обработка несуществующих адресов."""
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "Не найдено"}, status_code=404)
    return RedirectResponse("/", status_code=303)


def main() -> None:
    """Запуск через `python -m app.main` — удобно без внешнего uvicorn."""
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
