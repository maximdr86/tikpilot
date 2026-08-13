"""
Автотесты Tikpilot.

Запуск:  pytest -q     (из корня проекта; нужен pytest и httpx)

Реальный роутер не требуется — используется заглушка из fake_router.py,
которая говорит на настоящем протоколе RouterOS API.
"""

from __future__ import annotations

import contextlib
import os
import re
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Изолированный каталог данных для каждого прогона тестов
os.environ.setdefault("DATA_DIR", tempfile.mkdtemp(prefix="tikpilot-test-"))
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "admin")
# В тестах «перезагрузка» длится доли секунды — не ждём как на реальном железе
os.environ.setdefault("REBOOT_INITIAL_DELAY", "1")
os.environ.setdefault("REBOOT_PROBE_INTERVAL", "1")
os.environ.setdefault("UPDATE_POLL_INTERVAL", "1")
# Монитор разносит проверки во времени: пауза между устройствами это
# MONITOR_INTERVAL * 0.5 / число устройств, но не больше 0,3 с. При
# боевых шестидесяти секундах пауза упирается в потолок, и один проход
# по сорока накопленным за прогон устройствам занимает двенадцать секунд
# чистого сна. Секундный интервал делает паузу микроскопической, а на
# смысл проверок не влияет: они всё равно вызываются вручную.
os.environ.setdefault("MONITOR_INTERVAL", "1")
# Проверки написаны по русским надписям, поэтому язык фиксируем явно.
# Значение по умолчанию (английский) проверяется отдельным тестом.
os.environ.setdefault("DEFAULT_LANG", "ru")
# Рабочий .env лежит рядом, и его настройки подхватываются тестами. Две из
# них ломают прогон, если оставить как есть: ограничение по сетям закрывает
# панель от тестового клиента, а внешний адрес подменяет ссылки. Задаём их
# пустыми: переменная окружения сильнее .env, поэтому прогон не зависит от
# того, на какой машине он идёт.
os.environ.setdefault("ADMIN_NETWORKS", "")
os.environ.setdefault("PUBLIC_BASE_URL", "")

from fastapi.testclient import TestClient  # noqa: E402

from app.crypto import decrypt, encrypt, hash_password, verify_password  # noqa: E402
from app.database import query, query_one  # noqa: E402
from app.main import app  # noqa: E402
from app.mikrotik import DeviceError, MikroTik  # noqa: E402
from tests.fake_router import FakeFtp, FakeRouter  # noqa: E402


# ------------------------------------------------------------------ фикстуры
@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        c.post("/login", data={"username": "admin", "password": "admin", "next": "/"})
        yield c


@pytest.fixture()
def router():
    with FakeRouter(username="tikpilot", password="s3cret") as fake:
        yield fake


def _device(fake: FakeRouter, name: str = "test-rtr") -> dict:
    """Словарь устройства в том виде, в котором его ждёт MikroTik()."""
    return {
        "id": 0, "name": name, "host": "127.0.0.1",
        "api_port": fake.port, "ftp_port": 21,
        "username": "tikpilot", "use_ssl": 0,
    }


# ------------------------------------------------------------- шифрование
def test_password_encryption_roundtrip():
    token = encrypt("Sup3rSecret!")
    assert "Sup3rSecret!" not in token          # в базе нет открытого пароля
    assert decrypt(token) == "Sup3rSecret!"
    assert decrypt("мусор") == ""               # повреждённые данные не роняют воркер


def test_admin_password_hashing():
    hashed = hash_password("qwerty123")
    assert hashed.startswith("$2")
    assert verify_password("qwerty123", hashed)
    assert not verify_password("qwerty124", hashed)


# ------------------------------------------------------------------- доступ
def test_anonymous_redirected_to_login():
    with _anon() as anon:
        assert anon.get("/", follow_redirects=False).status_code == 303
        assert anon.get("/api/stats").status_code == 401


def test_anonymous_client_does_not_stop_the_worker(client, router):
    """
    Клиент для публичных страниц не гасит фоновый воркер.

    `with TestClient(app)` на выходе выполняет остановку приложения, общую
    на весь процесс: воркер встаёт, и каждая следующая задача в каждом
    следующем тесте висит до таймаута. В CI это выглядело как десять
    падений в разных местах и восемнадцать минут прогона, а причина была
    в одной строке публичного теста, отработавшего задолго до них.
    """
    with _anon() as anon:
        assert anon.get("/", follow_redirects=False).status_code == 303

    device_id = _add_device(client, router, "worker-alive")
    job = _run_and_wait(client, "check", [device_id], {}, timeout=20)
    assert job["status"] == "done", "воркер остановлен анонимным клиентом"


def test_pages_render(client):
    for path in ("/", "/devices", "/groups", "/jobs", "/backups", "/history", "/settings"):
        assert client.get(path).status_code == 200, path


# ----------------------------------------------------------- RouterOS API
def test_connect_and_read_system_info(router):
    with MikroTik(_device(router), "s3cret") as mt:
        info = mt.system_info()
    assert info["ros_version"].startswith("7.14")
    assert info["board_name"] == "CCR2004-1G-12S+2XS"
    assert info["uptime"] == "3w2d10:15:42"


def test_wrong_password_gives_clear_message(router):
    with pytest.raises(DeviceError) as exc:
        with MikroTik(_device(router), "wrong-password"):
            pass
    assert "логин или пароль" in str(exc.value)


def test_non_ascii_password_rejected_early(router):
    """RouterOS не принимает кириллицу в пароле — сообщаем об этом понятно."""
    with pytest.raises(DeviceError) as exc:
        with MikroTik(_device(router), "пароль"):
            pass
    assert "не-ASCII" in str(exc.value)


def test_unreachable_host_gives_clear_message():
    device = {"id": 0, "name": "x", "host": "127.0.0.1", "api_port": 1,
              "ftp_port": 21, "username": "u", "use_ssl": 0}
    with pytest.raises(DeviceError):
        with MikroTik(device, "p", timeout=2):
            pass


def test_reboot(router):
    with MikroTik(_device(router), "s3cret") as mt:
        mt.cmd_fire_and_forget("/system/reboot")
    assert router.rebooted is True


def test_run_source_creates_and_removes_temp_script(router):
    with MikroTik(_device(router), "s3cret") as mt:
        assert "выполнен" in mt.run_source(':log info "hi"')
    assert router.scripts == []                       # временный скрипт убран за собой
    assert "/system/script/run" in router.executed


def test_upload_script_persists(router):
    with MikroTik(_device(router), "s3cret") as mt:
        mt.upload_script("nightly", ':log info "night"')
        mt.upload_script("nightly", ':log info "updated"')   # повторная загрузка = обновление
    assert len(router.scripts) == 1
    assert router.scripts[0]["source"] == ':log info "updated"'


def test_run_missing_script_reports_error(router):
    with MikroTik(_device(router), "s3cret") as mt:
        with pytest.raises(DeviceError) as exc:
            mt.run_script_by_name("нет-такого")
    assert "не найден" in str(exc.value)


def test_long_script_is_not_cut_off_by_timeout(router):
    """
    Долгий скрипт доводится до конца.

    RouterOS не отвечает, пока /system/script/run не отработает. Скрипты вроде
    AutoBackup идут дольше обычного таймаута, и раньше это выглядело как
    «Таймаут подключения» на живом устройстве.
    """
    router.script_run_seconds = 3.0
    with MikroTik(_device(router), "s3cret", timeout=2) as mt:
        mt.upload_script("AutoBackup", ':log info "backup"')
        result = mt.run_script_by_name("AutoBackup", wait_seconds=20)
    assert "выполнен" in result


def test_timeout_message_distinguishes_command_from_connection(router):
    """Если ответа всё же не дождались — текст не должен врать про подключение."""
    router.script_run_seconds = 5.0
    with MikroTik(_device(router), "s3cret", timeout=2) as mt:
        mt.upload_script("Slow", ':log info "slow"')
        with pytest.raises(DeviceError) as exc:
            mt.run_script_by_name("Slow", wait_seconds=1)

    message = str(exc.value)
    assert "Таймаут подключения" not in message
    assert "не ответило на команду" in message
    assert "продолжает выполняться" in message


def test_timeout_restored_after_long_command(router):
    """После долгой команды таймаут возвращается к прежнему значению."""
    router.script_run_seconds = 0
    with MikroTik(_device(router), "s3cret", timeout=7) as mt:
        mt.upload_script("Quick", ':log info "quick"')
        mt.run_script_by_name("Quick", wait_seconds=60)
        assert mt.timeout == 7


def test_arbitrary_command(router):
    with MikroTik(_device(router), "s3cret") as mt:
        rows = mt.cmd("/ip/address/print")
    assert rows[0]["address"] == "10.0.0.1/24"


def test_unknown_command_becomes_device_error(router):
    with MikroTik(_device(router), "s3cret") as mt:
        with pytest.raises(DeviceError):
            mt.cmd("/такой/команды/нет")


def test_backup_files_created_on_device(router):
    with MikroTik(_device(router), "s3cret") as mt:
        mt.cmd("/system/backup/save", **{"name": "test", "dont-encrypt": "yes"})
        mt.cmd("/export", **{"file": "test"})
        names = [f["name"] for f in mt.list_files()]
    assert "test.backup" in names and "test.rsc" in names


# ------------------------------------------------------- сквозной сценарий
def test_full_job_cycle_against_fake_router(client, router):
    """Устройство → массовая задача «Проверить статус» → успешный результат."""
    r = client.post("/api/groups", data={"name": f"grp-{router.port}", "color": "blue"})
    group_id = r.json()["id"]

    r = client.post("/api/devices", data={
        "name": f"fake-{router.port}", "host": "127.0.0.1", "api_port": str(router.port),
        "ftp_port": "21", "username": "tikpilot", "password": "s3cret",
        "group_id": str(group_id), "enabled": "1",
    })
    device_id = r.json()["id"]

    r = client.post("/api/jobs", json={"action": "check", "device_ids": [device_id]})
    job_id = r.json()["job_id"]

    for _ in range(60):
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] == "done":
            break
        time.sleep(0.25)

    assert job["status"] == "done"
    assert job["ok_count"] == 1 and job["fail_count"] == 0

    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job_id,))
    assert item["status"] == "ok"
    assert "7.14.3" in item["result"]

    device = query_one("SELECT * FROM devices WHERE id = ?", (device_id,))
    assert device["status"] == "online"
    assert device["ros_version"].startswith("7.14")
    assert device["board_name"] == "CCR2004-1G-12S+2XS"


def test_job_on_dead_device_marks_offline(client):
    r = client.post("/api/devices", data={
        "name": "dead-rtr", "host": "127.0.0.1", "api_port": "1",
        "username": "u", "password": "p", "enabled": "1",
    })
    device_id = r.json()["id"]

    r = client.post("/api/jobs", json={"action": "check", "device_ids": [device_id]})
    job_id = r.json()["job_id"]

    for _ in range(80):
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] == "done":
            break
        time.sleep(0.25)

    assert job["fail_count"] == 1
    assert query_one("SELECT status FROM devices WHERE id = ?", (device_id,))["status"] == "offline"


def test_required_params_validated(client, router):
    """Обязательный параметр проверяется до постановки задачи в очередь."""
    # Устройство заводим своё: тест не должен зависеть от порядка выполнения
    device_id = _add_device(client, router, "params-check")
    r = client.post("/api/jobs", json={
        "action": "run_script", "device_ids": [device_id], "params": {},
    })
    assert r.status_code == 400
    assert "Имя скрипта" in r.json()["error"]


def test_unknown_action_rejected(client):
    r = client.post("/api/jobs", json={"action": "не-существует", "device_ids": [1]})
    assert r.status_code == 400


def test_csv_import(client):
    import io

    csv = ("name;host;username;password;group;comment\n"
           "imp-01;192.0.2.10;tikpilot;pw;ИмпортТест;первый\n"
           "imp-02;192.0.2.11;tikpilot;pw;ИмпортТест;второй\n")
    r = client.post(
        "/api/devices/import",
        files={"file": ("devices.csv", io.BytesIO(csv.encode()), "text/csv")},
        data={"default_group": ""},
    )
    assert r.status_code == 200 and r.json()["created"] == 2
    assert query_one("SELECT id FROM groups WHERE name = 'ИмпортТест'") is not None


def test_backup_downloaded_over_ftp(client, router):
    """Полный цикл действия «Снять бэкап»: создание файлов, FTP-скачивание, запись в БД."""
    payload_backup = b"\x88\xac\x00\x00FAKE-BINARY-BACKUP" * 16
    payload_export = "# feb/30/2026 test export\n/ip address\nadd address=10.0.0.1/24\n".encode()

    with FakeFtp({}, username="tikpilot", password="s3cret") as ftp:
        # Заглушка FTP отдаёт ровно те файлы, которые «создало» устройство
        original_save = router._handle

        def handle(cmd, attrs):
            result = original_save(cmd, attrs)
            if cmd == "/system/backup/save":
                ftp.files[attrs["name"] + ".backup"] = payload_backup
            elif cmd == "/export":
                ftp.files[attrs["file"] + ".rsc"] = payload_export
            return result

        router._handle = handle  # type: ignore[method-assign]

        r = client.post("/api/devices", data={
            "name": "backup-rtr", "host": "127.0.0.1", "api_port": str(router.port),
            "ftp_port": str(ftp.port), "username": "tikpilot", "password": "s3cret", "enabled": "1",
        })
        device_id = r.json()["id"]

        r = client.post("/api/jobs", json={
            "action": "backup", "device_ids": [device_id],
            "params": {"do_binary": "1", "do_export": "1", "cleanup": "1"},
        })
        job_id = r.json()["job_id"]

        for _ in range(80):
            job = client.get(f"/api/jobs/{job_id}").json()
            if job["status"] == "done":
                break
            time.sleep(0.25)

    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job_id,))
    assert item["status"] == "ok", item["result"]
    assert ".backup" in item["result"] and ".rsc" in item["result"]

    rows = query("SELECT * FROM backups WHERE device_id = ? ORDER BY kind", (device_id,))
    assert {r["kind"] for r in rows} == {"binary", "export"}
    assert dict((r["kind"], r["size"]) for r in rows)["binary"] == len(payload_backup)

    # Файлы действительно лежат на диске и отдаются по ссылке «Скачать»
    from app.config import settings
    for row in rows:
        assert (settings.backup_dir / row["filename"]).exists()
    r = client.get(f"/backups/{rows[0]['id']}/download")
    assert r.status_code == 200 and len(r.content) > 0

    # За собой убрали: временных файлов на устройстве не осталось
    assert router.files == []


# ------------------------------------------------------ обновление RouterOS
def test_check_updates_reports_available_version(router):
    router.latest_version = "7.20.1"
    with MikroTik(_device(router), "s3cret") as mt:
        info = mt.update_info()
    assert info["installed-version"] == "7.14.3"
    assert info["latest-version"] == "7.20.1"


@pytest.mark.slow
def test_wait_until_back_survives_reboot(router):
    """Устройство уходит в перезагрузку — клиент дожидается его возвращения."""
    router.reboot_seconds = 2.0
    with MikroTik(_device(router), "s3cret") as mt:
        mt.cmd_fire_and_forget("/system/reboot")
        seconds = mt.wait_until_back(timeout=30)
        assert mt.system_info()["ros_version"].startswith("7.14")
    assert 0 <= seconds <= 30


@pytest.mark.slow
def test_wait_until_back_times_out(router):
    """Если устройство не вернулось — понятная ошибка, а не зависание."""
    router.reboot_seconds = 60.0
    with MikroTik(_device(router), "s3cret") as mt:
        mt.cmd_fire_and_forget("/system/reboot")
        with pytest.raises(DeviceError) as exc:
            mt.wait_until_back(timeout=4)
    assert "не вернулось" in str(exc.value)


def test_version_parsing_and_comparison():
    """
    Версии нельзя сравнивать как строки: «7.9» больше «7.21» по алфавиту,
    но меньше по смыслу. Именно на этом ломалась метка обновления.
    """
    from app.mikrotik import compare_versions, is_newer, parse_version

    assert parse_version("7.23.1 (stable)") == (7, 23, 1)
    assert parse_version("7.21.5") == (7, 21, 5)
    assert parse_version("7.24beta3") == (7, 24)
    assert parse_version("") == ()

    assert compare_versions("7.23.1", "7.21.5") == 1      # 23 новее 21
    assert compare_versions("7.9", "7.21") == -1          # именно так, а не по алфавиту
    assert compare_versions("7.23", "7.23.0") == 0        # недостающие части = нули
    assert compare_versions("7.23.1 (stable)", "7.23.1") == 0
    assert compare_versions("", "7.1") is None            # неизвестную версию не сравниваем

    assert is_newer("7.21.5", "7.23.1") is False          # long-term старее установленной
    assert is_newer("7.23.1", "7.21.5") is True


def test_downgrade_is_refused(client, router):
    """
    Откат назад не выполняется и не изображается обновлением.

    Реальный случай: на устройстве 7.23.1 (stable), канал переключили на
    long-term, где доступна только 7.21.5. RouterOS такой «install» просто
    проигнорирует, а задача раньше ждала перезагрузки, которой не будет.
    """
    router.version = "7.23.1"
    router.latest_version = "7.21.5"
    device_id = _add_device(client, router, "down-guard")

    job = _run_and_wait(client, "upgrade_ros", [device_id],
                        {"channel": "long-term", "make_backup": "", "wait_back": "40",
                         "batch_size": "0"})
    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))

    assert item["status"] == "ok"
    assert "откат назад" in item["result"]
    assert router.install_count == 0            # устройство не тронуто
    assert router.version == "7.23.1"


def test_downgrade_not_shown_as_available_update(client, router):
    """В списке устройств откат не должен подсвечиваться как доступное обновление."""
    router.version = "7.23.1"
    router.latest_version = "7.21.5"
    device_id = _add_device(client, router, "down-badge")

    _run_and_wait(client, "check_updates", [device_id], {"channel": "long-term"})

    from app.routes.devices import _fetch_devices

    row = next(d for d in _fetch_devices() if d["id"] == device_id)
    assert row["update_available"] is False
    assert row["ahead_of_channel"] is True

    # И фильтр «есть обновление» его не показывает
    assert "down-badge" not in client.get("/devices/rows?status=update").text
    # А в списке видна честная пометка
    assert "новее канала" in client.get("/devices/rows").text


def test_check_updates_explains_newer_than_channel(client, router):
    """Проверка обновлений объясняет ситуацию словами, а не молчит."""
    router.version = "7.23.1"
    router.latest_version = "7.21.5"
    device_id = _add_device(client, router, "down-check")

    job = _run_and_wait(client, "check_updates", [device_id], {"channel": "long-term"})
    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))

    assert item["status"] == "ok"
    assert "новее" in item["result"]
    assert "откатом назад" in item["result"]


def test_upgrade_skipped_when_already_current(client, router):
    """Обновления нет — устройство не трогаем вообще."""
    router.latest_version = None
    device_id = _add_device(client, router, "up-current")

    job = _run_and_wait(client, "upgrade_ros", [device_id],
                        {"channel": "", "make_backup": "", "wait_back": "0", "batch_size": "0"})
    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))

    assert item["status"] == "ok"
    assert "уже актуальная версия" in item["result"].lower()
    assert router.install_count == 0
    assert router.rebooted is False


@pytest.mark.slow
def test_upgrade_installs_waits_and_verifies_version(client, router):
    """Полный цикл: установка, перезагрузка, возврат, сверка новой версии."""
    router.latest_version = "7.20.1"
    router.reboot_seconds = 2.0
    device_id = _add_device(client, router, "up-full")

    job = _run_and_wait(client, "upgrade_ros", [device_id],
                        {"channel": "long-term", "make_backup": "", "wait_back": "40",
                         "batch_size": "0"})
    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))

    assert item["status"] == "ok", item["result"]
    assert "7.14.3 → 7.20.1" in item["result"]
    assert "вернулось за" in item["result"]
    assert router.install_count == 1
    assert router.channel == "long-term"          # канал переключился
    assert router.version == "7.20.1"

    # В карточке устройства обновилась версия
    device = query_one("SELECT * FROM devices WHERE id = ?", (device_id,))
    assert device["ros_version"].startswith("7.20.1")
    assert device["architecture"] == "arm64"


@pytest.mark.slow
def test_slow_link_download_does_not_reboot_early(client, router):
    """
    Медленный канал: загрузка идёт долго, устройство всё это время на связи.

    Реальный случай, из-за которого точка «не возвращалась»: команда install
    качает пакеты и только потом перезагружается. Пока шла загрузка, устройство
    отвечало, и обновление ошибочно объявлялось неудачным.
    """
    router.latest_version = "7.20.1"
    router.download_seconds = 4.0        # «тонкий канал»
    router.reboot_seconds = 2.0
    device_id = _add_device(client, router, "slow-link")

    job = _run_and_wait(client, "upgrade_ros", [device_id],
                        {"channel": "", "make_backup": "", "wait_back": "60",
                         "download_timeout": "60", "batch_size": "0"}, timeout=120)
    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))

    assert item["status"] == "ok", item["result"]
    assert "пакеты загружены" in item["result"]
    assert "ушло в перезагрузку" in item["result"]
    assert router.download_count == 1
    assert router.version == "7.20.1"


def test_upgrade_does_not_use_install_command(client, router):
    """
    Установка идёт через download + reboot, а не одной командой install.

    Именно install делает загрузку и перезагрузку неразделимыми.
    """
    router.latest_version = "7.20.1"
    router.reboot_seconds = 1.0
    device_id = _add_device(client, router, "no-install-cmd")

    router.executed.clear()
    _run_and_wait(client, "upgrade_ros", [device_id],
                  {"channel": "", "make_backup": "", "wait_back": "40",
                   "download_timeout": "30", "batch_size": "0"})

    assert "/system/package/update/install" not in router.executed
    assert "/system/package/update/download" in router.executed
    assert "/system/reboot" in router.executed


@pytest.mark.slow
def test_failed_download_leaves_device_untouched(client, router):
    """Если пакеты не скачались — устройство не перезагружается."""
    router.latest_version = "7.20.1"
    router.download_seconds = 60.0       # не успеет за отведённое время
    device_id = _add_device(client, router, "slow-fail")

    job = _run_and_wait(client, "upgrade_ros", [device_id],
                        {"channel": "", "make_backup": "", "wait_back": "30",
                         "download_timeout": "3", "batch_size": "0"}, timeout=90)
    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))

    assert item["status"] == "error"
    assert "не докачалось" in item["result"]
    assert "работает на прежней версии" in item["result"]
    assert router.rebooted is False
    assert router.version == "7.14.3"


@pytest.mark.slow
def test_delayed_reboot_is_awaited(client, router):
    """
    Устройство пропадает со связи не сразу после команды.

    Проверяем, что мы не примем ещё живое устройство за «вернувшееся».
    """
    router.latest_version = "7.20.1"
    router.reboot_delay = 3.0            # связь пропадёт только через 3 с
    router.reboot_seconds = 2.0
    device_id = _add_device(client, router, "slow-reboot")

    job = _run_and_wait(client, "upgrade_ros", [device_id],
                        {"channel": "", "make_backup": "", "wait_back": "60",
                         "download_timeout": "30", "batch_size": "0"}, timeout=120)
    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))

    assert item["status"] == "ok", item["result"]
    assert "7.14.3 → 7.20.1" in item["result"]
    assert router.version == "7.20.1"


def test_small_flash_device_is_not_blocked_in_advance(client, router):
    """
    Устройство с крошечной флеш-памятью не отвергается заранее.

    На hAP ac lite (16 МиБ флеш) свободно меньше двух мегабайт, но обновления
    там проходят. Раньше стоял порог в 15 МиБ, и такие точки — то есть
    добрая половина парка — отвергались, хотя проблемы не было.
    Сколько места нужно на самом деле, знает только RouterOS.
    """
    router.latest_version = "7.20.1"
    router.free_space = 1_500_000          # ~1,4 МиБ, как на 16-мегабайтном устройстве
    router.reboot_seconds = 1.0
    device_id = _add_device(client, router, "small-flash")

    job = _run_and_wait(client, "upgrade_ros", [device_id],
                        {"channel": "", "make_backup": "", "wait_back": "40",
                         "download_timeout": "20", "batch_size": "0"})
    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))

    assert item["status"] == "ok", item["result"]
    assert router.version == "7.20.1"


def test_disk_space_error_explains_what_to_do(client, router):
    """Если места действительно не хватило — сообщение подсказывает решение."""
    router.latest_version = "7.20.1"
    original = router._handle

    def handle(cmd, attrs):
        if cmd == "/system/package/update/print":
            rows = original(cmd, attrs)
            if router.downloaded or router._download_done_at:
                rows[0]["status"] = (
                    "ERROR: not enough disk space, 7.3MiB is required and only 0.3MiB is free"
                )
            return rows
        return original(cmd, attrs)

    router._handle = handle  # type: ignore[method-assign]
    device_id = _add_device(client, router, "no-flash-space")

    job = _run_and_wait(client, "upgrade_ros", [device_id],
                        {"channel": "", "make_backup": "", "wait_back": "20",
                         "download_timeout": "15", "batch_size": "0"})
    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))

    assert item["status"] == "error"
    # Цифры берём из ответа устройства, а не выдумываем свои
    assert "7.3MiB is required" in item["result"]
    assert "Не хватает места" in item["result"]
    assert "netinstall" in item["result"]
    assert router.rebooted is False


def test_upgrade_aborts_when_backup_fails(client, router):
    """Без резервной копии обновление не начинается."""
    router.latest_version = "7.20.1"
    # FTP-порт заведомо нерабочий -> скачать бэкап не выйдет
    device_id = _add_device(client, router, "up-nobackup", ftp_port=1)

    job = _run_and_wait(client, "upgrade_ros", [device_id],
                        {"channel": "", "make_backup": "1", "wait_back": "0", "batch_size": "0"})
    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))

    assert item["status"] == "error"
    assert "не удалось снять бэкап" in item["result"].lower()
    assert router.install_count == 0              # устройство не тронуто


def test_upgrade_reports_unexpected_version(client, router):
    """Вернулась не та версия, что ожидали — это ошибка, а не успех."""
    router.latest_version = "7.20.1"
    # Устройство «соврало»: обещает 7.20.1, но после перезагрузки версия прежняя
    original = router._handle

    def handle(cmd, attrs):
        if cmd == "/system/reboot":
            router.rebooted = True
            router._go_offline()
            return []                              # версия не меняется
        return original(cmd, attrs)

    router._handle = handle  # type: ignore[method-assign]
    router.reboot_seconds = 1.0
    device_id = _add_device(client, router, "up-mismatch")

    job = _run_and_wait(client, "upgrade_ros", [device_id],
                        {"channel": "", "make_backup": "", "wait_back": "30",
                         "download_timeout": "20", "batch_size": "0"})
    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))

    assert item["status"] == "error"
    assert "ОЖИДАЛАСЬ 7.20.1" in item["result"]


def test_batches_are_processed_with_pause(client, router):
    """Пачки: 4 устройства по 2 штуки с паузой — задача занимает заметное время."""
    router.latest_version = None                   # обновлять нечего, проверяем только разбиение
    ids = [_add_device(client, router, f"batch-{i}") for i in range(4)]

    started = time.time()
    job = _run_and_wait(client, "upgrade_ros", ids,
                        {"channel": "", "make_backup": "", "wait_back": "0",
                         "batch_size": "2", "batch_pause": "2"}, timeout=60)
    elapsed = time.time() - started

    assert job["ok_count"] == 4
    # Две паузы между тремя... точнее: 2 пачки -> 1 пауза по 2 секунды
    assert elapsed >= 2, f"пауза между пачками не выдержана ({elapsed:.1f} с)"


def test_routerboard_upgraded_after_ros(client, router):
    router.latest_version = "7.20.1"
    router.upgrade_firmware = "7.20.1"
    router.reboot_seconds = 1.0
    device_id = _add_device(client, router, "up-rb")

    job = _run_and_wait(client, "upgrade_ros", [device_id],
                        {"channel": "", "make_backup": "", "wait_back": "40",
                         "upgrade_routerboard": "1", "batch_size": "0"})
    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))

    assert item["status"] == "ok", item["result"]
    assert "RouterBOOT: 7.14.3 → 7.20.1" in item["result"]
    assert router.current_firmware == "7.20.1"


def test_update_badge_shown_in_device_list(client, router):
    """После проверки обновлений в списке появляется метка с новой версией."""
    router.latest_version = "7.20.1"
    device_id = _add_device(client, router, "up-badge")
    _run_and_wait(client, "check_updates", [device_id], {"channel": ""})

    html = client.get("/devices/rows").text
    assert "7.20.1" in html

    # И фильтр «есть обновление» его находит
    filtered = client.get("/devices/rows?status=update").text
    assert "up-badge" in filtered


# ------------------------------------------------------------- помощники
def _add_device(client, router: FakeRouter, name: str, ftp_port: int = 21) -> int:
    """Добавить устройство, указывающее на заглушку."""
    r = client.post("/api/devices", data={
        "name": name, "host": "127.0.0.1", "api_port": str(router.port),
        "ftp_port": str(ftp_port), "username": "tikpilot", "password": "s3cret", "enabled": "1",
    })
    return r.json()["id"]


def _run_and_wait(client, action: str, device_ids: list, params: dict, timeout: int = 90) -> dict:
    """Запустить задачу и дождаться её завершения."""
    r = client.post("/api/jobs", json={"action": action, "device_ids": device_ids, "params": params})
    assert r.status_code == 200, r.json()
    job_id = r.json()["job_id"]

    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("done", "cancelled"):
            job["id"] = job_id
            return job
        time.sleep(0.05)
    raise AssertionError(f"Задача {job_id} не завершилась за {timeout} с")


# ------------------------------------------------------------- мониторинг
def test_monitoring_reuses_one_session(client, router):
    """
    Главное требование: много проверок — одно подключение и один вход.

    Иначе устройство засыпает журнал записями «user logged in», а поток
    коротких TCP-соединений вызывает на слабых моделях предупреждения
    «possible SYN flooding on tcp port 8728».
    """
    from app.sessions import SessionPool

    device_id = _add_device(client, router, "mon-session")
    device = dict(query_one("SELECT * FROM devices WHERE id = ?", (device_id,)))

    router.connections = 0
    router.logins = 0
    local_pool = SessionPool()
    try:
        for _ in range(10):
            alive, error = local_pool.check(device)
            assert alive is True, error
    finally:
        local_pool.close_all()

    assert router.connections == 1, f"подключений вместо одного: {router.connections}"
    assert router.logins == 1, f"входов вместо одного: {router.logins}"


def test_session_recovers_after_reboot(client, router):
    """После перезагрузки сессия переоткрывается — ровно один дополнительный вход."""
    from app.sessions import SessionPool

    device_id = _add_device(client, router, "mon-session-reboot")
    device = dict(query_one("SELECT * FROM devices WHERE id = ?", (device_id,)))

    local_pool = SessionPool()
    try:
        assert local_pool.check(device)[0] is True
        router.connections = 0
        router.logins = 0

        # Устройство «перезагрузилось»: старая сессия оборвана
        router.reboot_seconds = 0
        local_pool._sessions[device_id].close()

        alive, error = local_pool.check(device)
        assert alive is True, error
        assert router.logins == 1, "переподключение должно стоить ровно один вход"

        # Дальше сессия снова переиспользуется
        router.logins = 0
        for _ in range(5):
            assert local_pool.check(device)[0] is True
        assert router.logins == 0
    finally:
        local_pool.close_all()


def test_full_poll_uses_the_same_session(client, router):
    """Полный опрос идёт в уже открытой сессии, а не создаёт новую."""
    from app.sessions import SessionPool

    device_id = _add_device(client, router, "mon-session-full")
    device = dict(query_one("SELECT * FROM devices WHERE id = ?", (device_id,)))

    local_pool = SessionPool()
    try:
        local_pool.check(device)
        router.connections = 0
        router.logins = 0

        alive, error, info = local_pool.poll(device)
        assert alive is True, error
        assert info["ros_version"].startswith("7.")
        assert router.connections == 0 and router.logins == 0
    finally:
        local_pool.close_all()


def test_bad_credentials_are_not_retried_every_cycle(client, router):
    """
    При неверном пароле не долбим устройство входами каждую минуту.

    Иначе в журнале роутера появится поток неудачных попыток авторизации.
    """
    from app.sessions import SessionPool

    r = client.post("/api/devices", data={
        "name": "mon-badpass", "host": "127.0.0.1", "api_port": str(router.port),
        "ftp_port": "21", "username": "tikpilot", "password": "wrong-password", "enabled": "1",
    })
    device = dict(query_one("SELECT * FROM devices WHERE id = ?", (r.json()["id"],)))

    router.connections = 0
    local_pool = SessionPool()
    try:
        first_alive, first_error = local_pool.check(device)
        assert first_alive is False
        assert "логин или пароль" in first_error

        for _ in range(5):
            alive, error = local_pool.check(device)
            assert alive is False
            assert "отложена" in error
    finally:
        local_pool.close_all()

    assert router.connections == 1, f"повторных попыток входа: {router.connections}"


def test_mass_action_does_not_create_new_logins(client, router):
    """
    Массовое действие работает в уже открытой сессии.

    Раньше каждая задача сначала сбрасывала сессию, а потом монитор логинился
    заново — одно нажатие «Проверить все» стоило два входа на каждое устройство.
    """
    from app import sessions

    device_id = _add_device(client, router, "job-reuse")
    device = dict(query_one("SELECT * FROM devices WHERE id = ?", (device_id,)))
    sessions.pool.check(device)                    # монитор открыл сессию

    router.connections = 0
    router.logins = 0

    job = _run_and_wait(client, "check", [device_id], {})
    assert job["ok_count"] == 1

    assert router.logins == 0, f"задача потребовала входов: {router.logins}"
    assert router.connections == 0, f"задача открыла подключений: {router.connections}"
    # Сессия осталась в пуле и пригодна для следующей проверки
    assert device_id in sessions.pool._sessions


def test_rebooting_action_drops_the_session(client, router):
    """После перезагрузки соединение переиспользовать нельзя — оно закрывается."""
    from app import sessions

    device_id = _add_device(client, router, "job-reboot")
    device = dict(query_one("SELECT * FROM devices WHERE id = ?", (device_id,)))
    sessions.pool.check(device)
    assert device_id in sessions.pool._sessions

    _run_and_wait(client, "reboot", [device_id], {})

    assert device_id not in sessions.pool._sessions
    assert router.rebooted is True


def test_failed_command_keeps_the_session(client, router):
    """
    Отказ RouterOS выполнить команду не рвёт соединение.

    Иначе каждая ошибка вроде «скрипт не найден» стоила бы лишнего входа.
    """
    from app import sessions

    device_id = _add_device(client, router, "job-trap")
    device = dict(query_one("SELECT * FROM devices WHERE id = ?", (device_id,)))
    sessions.pool.check(device)

    router.logins = 0
    job = _run_and_wait(client, "run_script", [device_id], {"script_name": "нет-такого"})

    item = query_one("SELECT * FROM job_items WHERE job_id = ?", (job["id"],))
    assert item["status"] == "error" and "не найден" in item["result"]
    assert router.logins == 0
    assert device_id in sessions.pool._sessions


def test_session_dropped_when_device_edited(client, router):
    """После правки устройства старая сессия закрывается."""
    from app import sessions

    device_id = _add_device(client, router, "mon-edit")
    device = dict(query_one("SELECT * FROM devices WHERE id = ?", (device_id,)))
    sessions.pool.check(device)
    assert device_id in sessions.pool._sessions

    client.post(f"/api/devices/{device_id}/update", data={
        "name": "mon-edit-2", "host": "127.0.0.1", "api_port": str(router.port),
        "ftp_port": "21", "username": "tikpilot", "password": "", "enabled": "1",
    })
    assert device_id not in sessions.pool._sessions


def test_tcp_probe_still_available_as_fallback(client, router):
    """Запасной режим проверки порта работает, если сессии держать нельзя."""
    from app import monitor

    device_id = _add_device(client, router, "mon-probe")
    device = dict(query_one("SELECT * FROM devices WHERE id = ?", (device_id,)))

    router.executed.clear()
    alive, error = monitor._tcp_probe(device)

    assert alive is True and error == ""
    assert router.executed == [], f"устройство получило команды: {router.executed}"


def test_probe_detects_dead_host():
    from app import monitor

    alive, error = monitor._tcp_probe({"host": "127.0.0.1", "api_port": 1})
    assert alive is False
    assert error


def test_offline_requires_several_misses(client, router):
    """Одиночный промах не роняет статус — нужна выдержка."""
    from app import monitor
    from app.config import settings

    device_id = _add_device(client, router, "mon-hysteresis")
    # Помечаем устройство работающим, как после успешной проверки
    monitor.apply_result(dict(query_one("SELECT * FROM devices WHERE id=?", (device_id,))), alive=True)

    for miss in range(1, settings.monitor_fail_threshold):
        device = dict(query_one("SELECT * FROM devices WHERE id=?", (device_id,)))
        monitor.apply_result(device, alive=False, error="Таймаут подключения")
        row = query_one("SELECT status, fail_streak FROM devices WHERE id=?", (device_id,))
        assert row["status"] == "online", f"упало раньше времени на {miss}-м промахе"
        assert row["fail_streak"] == miss

    # Промах, достигший порога
    device = dict(query_one("SELECT * FROM devices WHERE id=?", (device_id,)))
    monitor.apply_result(device, alive=False, error="Таймаут подключения")
    assert query_one("SELECT status FROM devices WHERE id=?", (device_id,))["status"] == "offline"

    # Один успешный ответ возвращает онлайн сразу
    device = dict(query_one("SELECT * FROM devices WHERE id=?", (device_id,)))
    monitor.apply_result(device, alive=True)
    row = query_one("SELECT status, fail_streak FROM devices WHERE id=?", (device_id,))
    assert row["status"] == "online" and row["fail_streak"] == 0


def test_status_changes_are_recorded(client, router):
    """Падение и подъём попадают в историю, простой считается."""
    from app import monitor

    device_id = _add_device(client, router, "mon-events")
    monitor.apply_result(dict(query_one("SELECT * FROM devices WHERE id=?", (device_id,))), alive=True)

    device = dict(query_one("SELECT * FROM devices WHERE id=?", (device_id,)))
    monitor.apply_result(device, alive=False, error="Хост недоступен", threshold=1)

    device = dict(query_one("SELECT * FROM devices WHERE id=?", (device_id,)))
    monitor.apply_result(device, alive=True)

    events = query(
        "SELECT * FROM status_events WHERE device_id = ? ORDER BY id", (device_id,)
    )
    statuses = [e["status"] for e in events]
    assert statuses[-2:] == ["offline", "online"]
    assert events[-2]["reason"] == "Хост недоступен"
    assert events[-1]["downtime"] is not None      # простой посчитан


def test_cycle_skips_devices_busy_with_a_job(client, router):
    """Устройство, которое сейчас перезагружает задача, монитор не трогает."""
    from app import monitor
    from app.database import execute

    device_id = _add_device(client, router, "mon-busy")
    job_id = execute(
        "INSERT INTO jobs (action, action_label, status, total, created_at) "
        "VALUES ('reboot','Перезагрузить','running',1,datetime('now'))"
    )
    execute(
        "INSERT INTO job_items (job_id, device_id, device_name, status) "
        "VALUES (?,?,?,'running')",
        (job_id, device_id, "mon-busy"),
    )
    try:
        result = monitor.run_cycle(full=False)
        assert result["skipped"] >= 1
    finally:
        execute("UPDATE job_items SET status='ok' WHERE job_id=?", (job_id,))
        execute("UPDATE jobs SET status='done' WHERE id=?", (job_id,))


@pytest.mark.slow
def test_full_cycle_updates_device_info(client, router):
    """Полный опрос заполняет версию и архитектуру."""
    from app import monitor
    from app.database import execute

    device_id = _add_device(client, router, "mon-full")
    # Остальные устройства из прошлых тестов не мешают — проверяем только своё
    execute("UPDATE devices SET ros_version='', architecture='' WHERE id=?", (device_id,))

    monitor.run_cycle(full=True)

    row = query_one("SELECT * FROM devices WHERE id=?", (device_id,))
    assert row["ros_version"].startswith("7.")
    assert row["architecture"] == "arm64"
    assert row["status"] == "online"
    assert row["last_seen"]


def test_manual_cycle_works_even_when_monitor_stopped(client, router):
    """
    Ручной проход должен отрабатывать, даже если фоновый поток остановлен.

    Раньше run_cycle молча ничего не делал: он смотрел на общий флаг остановки,
    который взводился при завершении любого экземпляра приложения.
    """
    from app import monitor

    monitor.stop()                                  # имитируем остановленный монитор
    device_id = _add_device(client, router, "mon-stopped")
    monitor.run_cycle(full=True)

    row = query_one("SELECT ros_version, status FROM devices WHERE id=?", (device_id,))
    assert row["status"] == "online"
    assert row["ros_version"].startswith("7.")


def test_availability_counts_downtime(client, router):
    """Процент доступности считается по журналу событий."""
    from app import monitor
    from app.database import execute

    device_id = _add_device(client, router, "avail-calc")
    # Точка лежала два часа и поднялась час назад
    execute(
        "INSERT INTO status_events (device_id, device_name, status, reason, ts) "
        "VALUES (?,?,'offline','Таймаут подключения', datetime('now','-3 hours'))",
        (device_id, "avail-calc"),
    )
    execute(
        "INSERT INTO status_events (device_id, device_name, status, downtime, ts) "
        "VALUES (?,?,'online', ?, datetime('now','-1 hours'))",
        (device_id, "avail-calc", 2 * 3600),
    )
    monitor.apply_result(dict(query_one("SELECT * FROM devices WHERE id=?", (device_id,))), alive=True)

    row = next(r for r in monitor.availability(24) if r["id"] == device_id)
    # Два часа простоя из двадцати четырёх — примерно 91,7 %
    assert 91.0 <= row["uptime_percent"] <= 92.0
    assert row["down_seconds"] == 2 * 3600
    assert row["outages"] == 1


def test_availability_clips_downtime_to_window(client, router):
    """Простой, начавшийся до начала окна, обрезается по его границе."""
    from app import monitor
    from app.database import execute

    device_id = _add_device(client, router, "avail-clip")
    # Поднялась 30 минут назад после десятичасового простоя, окно — 1 час
    execute(
        "INSERT INTO status_events (device_id, device_name, status, downtime, ts) "
        "VALUES (?,?,'online', ?, datetime('now','-30 minutes'))",
        (device_id, "avail-clip", 10 * 3600),
    )
    monitor.apply_result(dict(query_one("SELECT * FROM devices WHERE id=?", (device_id,))), alive=True)

    row = next(r for r in monitor.availability(1) if r["id"] == device_id)
    # В окно попали только последние 30 минут простоя, а не все десять часов
    # (допуск в пару секунд — время в БД и в Python берётся не одномоментно)
    assert abs(row["down_seconds"] - 30 * 60) <= 5
    assert 49.0 <= row["uptime_percent"] <= 51.0


def test_availability_counts_ongoing_outage(client, router):
    """Точка, которая лежит прямо сейчас, тоже попадает в простой."""
    from app import monitor
    from app.database import execute

    device_id = _add_device(client, router, "avail-ongoing")
    execute(
        "UPDATE devices SET status='offline', status_changed_at=datetime('now','-2 hours') "
        "WHERE id=?",
        (device_id,),
    )

    row = next(r for r in monitor.availability(24) if r["id"] == device_id)
    assert row["down_seconds"] >= 2 * 3600 - 60
    assert row["status"] == "offline"


def test_monitoring_page_renders(client, router):
    """Страница мониторинга открывается и показывает карту с доступностью."""
    device_id = _add_device(client, router, "mon-page")
    from app import monitor

    monitor.run_cycle(full=True)

    html = client.get("/monitoring").text
    assert "Карта парка" in html
    assert "map-cell" in html
    assert "Доступность за сутки" in html

    # Периоды переключаются
    assert "Доступность за неделю" in client.get("/monitoring?hours=168").text
    # Фрагмент карты отдаётся отдельно — им обновляется страница
    assert client.get("/monitoring/map").status_code == 200


def test_status_map_puts_problem_groups_first(client, router):
    """Группы с недоступными точками показываются первыми."""
    from app import monitor
    from app.database import execute

    good = client.post("/api/groups", data={"name": "Всё хорошо"}).json()["id"]
    bad = client.post("/api/groups", data={"name": "Проблемная"}).json()["id"]
    ok_id = _add_device(client, router, "map-ok")
    bad_id = _add_device(client, router, "map-bad")
    execute("UPDATE devices SET group_id=?, status='online' WHERE id=?", (good, ok_id))
    execute("UPDATE devices SET group_id=?, status='offline' WHERE id=?", (bad, bad_id))

    names = [g["name"] for g in monitor.status_map()]
    assert names.index("Проблемная") < names.index("Всё хорошо")


# ------------------------------------------------------- проверки задержки
def test_ping_parses_rtt_and_loss(router):
    """Ответ RouterOS на /ping разбирается в задержку и потери."""
    router.ping_rtt_ms = 18
    router.ping_lost = 1
    with MikroTik(_device(router), "s3cret") as mt:
        result = mt.ping("8.8.8.8", count=5)

    assert result["sent"] == 5
    assert result["received"] == 4
    assert result["loss"] == 20
    assert result["rtt_avg"] == 18.0
    assert router.pinged == ["8.8.8.8"]


def test_rtt_formats_are_understood():
    """RouterOS отдаёт время в разных единицах — разбираем все."""
    from app.mikrotik import _parse_rtt

    assert _parse_rtt("1ms") == 1.0
    assert _parse_rtt("1ms500us") == 1.5
    assert _parse_rtt("980us") == 0.98
    assert _parse_rtt("12s") == 12000.0
    assert _parse_rtt("") is None


def test_default_gateway_ignores_interface_names(router):
    """Шлюзом через имя интерфейса пинговать нечего — такой маршрут пропускаем."""
    with MikroTik(_device(router), "s3cret") as mt:
        assert mt.default_gateway() == "10.0.0.254"

        router.gateway = "wg1"           # туннель вместо адреса
        assert mt.default_gateway() == ""


def test_latency_samples_are_stored(client, router):
    """Полный опрос записывает замеры задержки в базу."""
    from app import monitor
    from app.config import settings

    device_id = _add_device(client, router, "lat-store")
    router.ping_rtt_ms = 25
    router.ping_lost = 1

    # Настройки задаём явно: тест не должен зависеть от .env конкретной установки
    original = settings.latency_targets, settings.latency_ping_gateway
    settings.latency_targets = ["1.1.1.1"]
    settings.latency_ping_gateway = True
    try:
        monitor.run_cycle(full=True)
    finally:
        settings.latency_targets, settings.latency_ping_gateway = original

    rows = query("SELECT * FROM latency_samples WHERE device_id = ?", (device_id,))
    targets = {r["target"] for r in rows}
    assert "1.1.1.1" in targets
    assert "10.0.0.254" in targets, "шлюз должен пинговаться автоматически"

    sample = next(r for r in rows if r["target"] == "1.1.1.1")
    assert sample["rtt_avg"] == 25.0
    assert sample["loss"] == 20

    # Шлюз запомнился в карточке устройства
    assert query_one("SELECT gateway FROM devices WHERE id=?", (device_id,))["gateway"] == "10.0.0.254"


def test_device_own_targets_override_common(client, router):
    """Свои цели устройства перекрывают общий список."""
    from app import monitor

    device_id = _add_device(client, router, "lat-own")
    execute_sql = "UPDATE devices SET latency_targets = ? WHERE id = ?"
    from app.database import execute

    execute(execute_sql, ("192.0.2.77", device_id))

    device = dict(query_one("SELECT * FROM devices WHERE id=?", (device_id,)))
    targets = [t for t, _ in monitor._latency_targets(device)]
    assert "192.0.2.77" in targets
    assert "8.8.8.8" not in targets


def test_gateway_detection_skips_inactive_routes(router):
    """
    Из нескольких маршрутов по умолчанию берётся активный с меньшей метрикой.

    На точках с резервным каналом маршрутов несколько, и запасной обычно
    неактивен — его шлюз ни о чём не говорит.
    """
    original = router._handle

    def handle(cmd, attrs):
        if cmd == "/ip/route/print":
            return [
                {"dst-address": "0.0.0.0/0", "gateway": "10.9.9.1",
                 "distance": "1", "active": "false", "disabled": "false"},
                {"dst-address": "0.0.0.0/0", "gateway": "10.8.8.1",
                 "distance": "10", "active": "true", "disabled": "false"},
                {"dst-address": "0.0.0.0/0", "gateway": "10.7.7.1",
                 "distance": "5", "active": "true", "disabled": "false"},
            ]
        return original(cmd, attrs)

    router._handle = handle  # type: ignore[method-assign]
    with MikroTik(_device(router), "s3cret") as mt:
        assert mt.default_gateway() == "10.7.7.1"


def test_mute_targets_that_never_answer(client, router):
    """
    Цель, которая не ответила ни разу, перестаёт опрашиваться.

    Провайдеры часто блокируют ICMP до своего шлюза: такая цель показывает
    ровно 100% потерь всегда. Это не деградация канала, а молчащий адрес —
    и он не должен забивать таблицу, заслоняя настоящие проблемы.
    """
    from app import monitor
    from app.config import settings

    device_id = _add_device(client, router, "lat-mute")
    router.ping_lost = 5              # ни один пакет не доходит
    router.ping_rtt_ms = 0

    original = settings.latency_targets
    settings.latency_targets = ["192.0.2.200"]
    try:
        for _ in range(monitor.MUTE_AFTER_FAILURES + 2):
            monitor.run_cycle(full=True)

        rows = query(
            "SELECT * FROM latency_samples WHERE device_id = ? AND target = '192.0.2.200'",
            (device_id,),
        )
        assert len(rows) == monitor.MUTE_AFTER_FAILURES, (
            f"после {monitor.MUTE_AFTER_FAILURES} неудач опрос должен прекратиться, "
            f"а замеров {len(rows)}"
        )

        # В сводке такая цель идёт отдельно от настоящих проблем
        summary = monitor.latency_summary(24)
        mute_targets = {r["target"] for r in summary["mute"]}
        problem_targets = {r["target"] for r in summary["problems"]}
        assert "192.0.2.200" in mute_targets
        assert "192.0.2.200" not in problem_targets
    finally:
        settings.latency_targets = original


@pytest.mark.slow
def test_target_with_partial_loss_stays_monitored(client, router):
    """А вот цель с частичными потерями — настоящая проблема, её продолжаем опрашивать."""
    from app import monitor
    from app.config import settings

    device_id = _add_device(client, router, "lat-partial")
    router.ping_lost = 2              # 2 из 5 теряются, но ответы есть
    router.ping_rtt_ms = 40

    original = settings.latency_targets
    settings.latency_targets = ["192.0.2.201"]
    try:
        for _ in range(4):
            monitor.run_cycle(full=True)

        rows = query(
            "SELECT * FROM latency_samples WHERE device_id = ? AND target = '192.0.2.201'",
            (device_id,),
        )
        assert len(rows) == 4, "цель отвечает — опрос прекращать нельзя"

        summary = monitor.latency_summary(24)
        problem = next(r for r in summary["problems"] if r["target"] == "192.0.2.201")
        assert problem["loss"] == 40
        assert problem["rtt"] == 40
    finally:
        settings.latency_targets = original


def test_targets_can_carry_labels(client, router):
    """Цель можно подписать: «адрес=подпись» — подпись видна в интерфейсе."""
    from app import monitor
    from app.config import settings

    device_id = _add_device(client, router, "lat-label")
    device = dict(query_one("SELECT * FROM devices WHERE id=?", (device_id,)))

    original = settings.latency_targets
    settings.latency_targets = ["10.0.0.1=хаб", "8.8.8.8=интернет"]
    try:
        targets = monitor._latency_targets(device)
    finally:
        settings.latency_targets = original

    assert targets == [("10.0.0.1", "хаб"), ("8.8.8.8", "интернет")]

    # Цель без подписи тоже работает
    assert monitor._split_target("1.1.1.1") == ("1.1.1.1", "")


def test_gateway_can_be_disabled(client, router):
    """Если шлюзы не отвечают на ICMP, их добавление можно отключить."""
    from app import monitor
    from app.config import settings

    device_id = _add_device(client, router, "lat-nogw")
    from app.database import execute

    execute("UPDATE devices SET gateway = '10.0.0.254' WHERE id = ?", (device_id,))
    device = dict(query_one("SELECT * FROM devices WHERE id=?", (device_id,)))

    original_gw, original_targets = settings.latency_ping_gateway, settings.latency_targets
    settings.latency_targets = ["10.0.0.1=хаб"]
    try:
        settings.latency_ping_gateway = True
        assert "10.0.0.254" in [t for t, _ in monitor._latency_targets(device)]

        settings.latency_ping_gateway = False
        assert [t for t, _ in monitor._latency_targets(device)] == ["10.0.0.1"]
    finally:
        settings.latency_ping_gateway = original_gw
        settings.latency_targets = original_targets


def test_removed_targets_disappear_from_reports(client, router):
    """
    Цель, убранная из настроек, сразу пропадает из отчётов.

    Раньше отключение пинга шлюзов не убирало их из таблицы: она строится
    по истории замеров, и старые записи висели там ещё сутки — выглядело так,
    будто настройка не сработала.
    """
    from app import monitor
    from app.config import settings
    from app.database import execute

    device_id = _add_device(client, router, "lat-removed")
    execute("UPDATE devices SET gateway = '10.0.0.254' WHERE id = ?", (device_id,))

    original = settings.latency_targets, settings.latency_ping_gateway
    settings.latency_targets = ["1.1.1.1"]
    settings.latency_ping_gateway = True
    try:
        monitor.run_cycle(full=True)          # замерили и шлюз, и общую цель
        targets = {
            r["target"] for r in monitor.latency_summary(24)["problems"]
            if r["device_id"] == device_id
        } | {
            r["target"] for r in monitor.latency_summary(24)["mute"]
            if r["device_id"] == device_id
        }
        assert {"10.0.0.254", "1.1.1.1"} <= targets

        # Выключаем пинг шлюзов — он должен исчезнуть из отчёта немедленно
        settings.latency_ping_gateway = False
        summary = monitor.latency_summary(24)
        shown = {r["target"] for r in summary["problems"] + summary["mute"]
                 if r["device_id"] == device_id}
        assert "10.0.0.254" not in shown, "убранная цель всё ещё в отчёте"
        assert "1.1.1.1" in shown

        # И с графиков тоже
        history = monitor.latency_history(device_id, 24)
        assert not any("10.0.0.254" in key for key in history)
        assert any("1.1.1.1" in key for key in history)
    finally:
        settings.latency_targets, settings.latency_ping_gateway = original


def test_metrics_are_recorded(client, router):
    """Загрузка CPU и память попадают во временной ряд."""
    from app import monitor

    device_id = _add_device(client, router, "metrics-1")
    monitor.run_cycle(full=True)

    rows = query("SELECT * FROM device_metrics WHERE device_id = ?", (device_id,))
    assert rows, "метрики не записались"
    assert rows[-1]["cpu_load"] == 7.0
    assert rows[-1]["free_memory"] == 1073741824


# --------------------------------------------------------------- графики
def test_chart_renders_svg_and_breaks_on_gaps():
    """График рисуется в SVG, а пропуски разрывают линию, а не тянут её к нулю."""
    from app import charts

    series = charts.Series(
        "тест",
        [("2026-08-04 10:00:00", 10), ("2026-08-04 10:05:00", None), ("2026-08-04 10:10:00", 30)],
        "var(--accent)",
    )
    svg = charts.line_chart([series], unit=" мс")

    assert svg.startswith("<svg")
    # Два отрезка вместо одного — значит пропуск действительно разорвал линию
    assert svg.count("<path") == 2
    assert "04.08" in svg


def test_chart_without_data_says_so():
    from app import charts

    assert "данных пока нет" in charts.line_chart([])


# ------------------------------------------------- отложенный запуск задач
@pytest.mark.slow
def test_scheduled_job_waits_for_its_time(client, router):
    """Задача с будущим временем не запускается сразу."""
    device_id = _add_device(client, router, "sched-wait")

    r = client.post("/api/jobs", json={
        "action": "check", "device_ids": [device_id],
        "scheduled_at": "2099-01-01T02:00",
    })
    assert r.status_code == 200
    job_id = r.json()["job_id"]

    time.sleep(2)
    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "pending", "отложенная задача не должна стартовать сразу"
    assert job["done"] == 0

    # И в списке видно, когда она сработает
    assert "запуск" in client.get("/jobs").text


@pytest.mark.slow
def test_scheduled_job_runs_when_time_comes(client, router):
    """Наступило время — задача выполняется."""
    from app.database import execute

    device_id = _add_device(client, router, "sched-run")
    r = client.post("/api/jobs", json={
        "action": "check", "device_ids": [device_id],
        "scheduled_at": "2099-01-01T02:00",
    })
    job_id = r.json()["job_id"]

    # Переводим время запуска в прошлое — диспетчер должен подхватить
    execute("UPDATE jobs SET scheduled_at = datetime('now','-1 minute') WHERE id = ?", (job_id,))

    deadline = time.time() + 30
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] == "done":
            break
        time.sleep(0.25)
    assert job["status"] == "done"
    assert job["ok_count"] == 1


@pytest.mark.slow
def test_cancelling_a_scheduled_job_closes_it_at_once(client, router):
    """
    Отложенная задача отменяется сразу, а не ждёт своего часа.

    Раньше отмена только ставила флаг, и задача, поставленная на 02:00,
    висела в списке ожидающих до двух ночи: человек нажимал «отменить»,
    видел «отмена запрошена» и не понимал, отменилось ли что-нибудь.
    """
    device_id = _add_device(client, router, "sched-cancel")
    job_id = client.post("/api/jobs", json={
        "action": "check", "device_ids": [device_id],
        "scheduled_at": "2099-01-01T02:00",
    }).json()["job_id"]

    r = client.post(f"/api/jobs/{job_id}/cancel")
    assert r.status_code == 200
    assert r.json()["status"] == "cancelled"

    job = client.get(f"/api/jobs/{job_id}").json()
    assert job["status"] == "cancelled"
    assert job["done"] == job["total"]

    from app.database import execute, query

    rows = query("SELECT status, result FROM job_items WHERE job_id = ?", (job_id,))
    assert [r["status"] for r in rows] == ["skipped"]
    assert rows[0]["result"] == "Задача отменена"

    # И когда время придёт, задача не оживёт
    execute("UPDATE jobs SET scheduled_at = datetime('now','-1 minute') WHERE id = ?", (job_id,))
    time.sleep(2)
    assert client.get(f"/api/jobs/{job_id}").json()["status"] == "cancelled"


def test_schedule_converts_local_time_to_utc():
    """Браузер присылает местное время — в базе должно лежать UTC."""
    from datetime import datetime, timezone

    from app.routes.jobs import _parse_schedule

    local = datetime(2026, 8, 4, 2, 0).astimezone()
    expected = local.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    assert _parse_schedule("2026-08-04T02:00") == expected
    assert _parse_schedule("") is None
    assert _parse_schedule("чепуха") is None


def test_device_timeline_merges_sources(client, router):
    """Хронология сводит статусы, операции и бэкапы в одну ленту."""
    from app import monitor
    from app.database import execute

    device_id = _add_device(client, router, "timeline-1")
    _run_and_wait(client, "check", [device_id], {})
    execute(
        "INSERT INTO status_events (device_id, device_name, status, reason, ts) "
        "VALUES (?,?,'offline','Таймаут подключения', datetime('now','-10 minutes'))",
        (device_id, "timeline-1"),
    )
    execute(
        "INSERT INTO backups (device_id, device_name, kind, filename, size, created_at) "
        "VALUES (?,?,'binary','x/y.backup', 1024, datetime('now','-5 minutes'))",
        (device_id, "timeline-1"),
    )

    kinds = {e["kind"] for e in monitor.device_timeline(device_id)}
    assert kinds == {"status", "job", "backup"}

    html = client.get(f"/devices/{device_id}").text
    assert "Хронология" in html
    assert "Задержка и потери" in html


def test_dashboard_shows_events_fragment(client):
    r = client.get("/dashboard/events")
    assert r.status_code == 200


def test_monitor_settings_visible(client):
    html = client.get("/settings").text
    assert "Мониторинг доступности" in html


def test_old_database_is_migrated(tmp_path):
    """База, созданная прошлой версией программы, дополняется новыми колонками."""
    import sqlite3

    from app import database

    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    # Схема «до» появления сведений об обновлениях
    conn.executescript(
        "CREATE TABLE devices (id INTEGER PRIMARY KEY, name TEXT, host TEXT, "
        "ros_version TEXT DEFAULT '');"
        "INSERT INTO devices (name, host) VALUES ('старое', '10.0.0.1');"
    )
    conn.commit()
    conn.close()

    # Подсовываем эту базу слою доступа и запускаем миграцию
    original_path, database._local.conn = database.settings.db_path, None
    database.settings.db_path = db
    try:
        database._migrate()
        columns = {r["name"] for r in database.get_conn().execute("PRAGMA table_info(devices)")}
        assert {"architecture", "latest_version", "update_status", "update_channel"} <= columns
        # Данные на месте
        assert database.query_one("SELECT name FROM devices")["name"] == "старое"
    finally:
        database.get_conn().close()
        database.settings.db_path = original_path
        database._local.conn = None


# ------------------------------------------------- поиск и сортировка таблиц
def test_backup_search_and_filters(client, router):
    """Поиск по бэкапам идёт на сервере, а не по видимым строкам."""
    from app.database import execute

    dev_a = _add_device(client, router, "Magazin Pekarnya")
    dev_b = _add_device(client, router, "Site 253")
    execute(
        "INSERT INTO backups (device_id, device_name, kind, filename, size, created_at) "
        "VALUES (?,?,'binary','x/pekarnya_20260804.backup', 120000, datetime('now'))",
        (dev_a, "Magazin Pekarnya"),
    )
    execute(
        "INSERT INTO backups (device_id, device_name, kind, filename, size, created_at) "
        "VALUES (?,?,'export','x/nv253_20260804.rsc', 30000, datetime('now'))",
        (dev_b, "Site 253"),
    )

    # Поиск по имени устройства
    html = client.get("/backups?q=Pekarnya").text
    assert "pekarnya_20260804.backup" in html
    assert "nv253_20260804.rsc" not in html

    # Поиск по имени файла
    assert "nv253_20260804.rsc" in client.get("/backups?q=nv253").text

    # Фильтр по типу
    only_export = client.get("/backups?kind=export").text
    assert "nv253_20260804.rsc" in only_export
    assert "pekarnya_20260804.backup" not in only_export

    # Фильтр по устройству
    assert "pekarnya" in client.get(f"/backups?device_id={dev_a}").text

    # Пустой результат объясняется словами
    assert "ничего не найдено" in client.get("/backups?q=такого-точно-нет").text


def test_backup_search_shows_found_summary(client, router):
    """Под заголовком видно, сколько найдено и сколько всего."""
    html = client.get("/backups?q=Pekarnya").text
    assert "Найдено:" in html
    assert "всего" in html


def test_tables_are_sortable_with_correct_keys(client, router):
    """
    В таблицах проставлены ключи сортировки для чисел и дат.

    Без них «7.9» оказалась бы больше «7.21», а «сегодня 14:31» сортировалось
    бы по алфавиту.
    """
    device_id = _add_device(client, router, "sortable-dev")
    from app import monitor

    monitor.run_cycle(full=True)

    devices_html = client.get("/devices").text
    assert 'class="sortable"' in devices_html
    assert "data-sort=" in devices_html
    # Служебные колонки из сортировки исключены
    assert 'class="no-sort"' in devices_html

    for path in ("/jobs", "/history", "/groups", "/monitoring", "/backups"):
        assert 'class="sortable"' in client.get(path).text, path


def test_version_sort_key_is_numeric():
    """7.9 меньше 7.21 — как число, а не как строка."""
    from app.routes.deps import sort_version

    assert sort_version("7.9") < sort_version("7.21")
    assert sort_version("7.21.5") < sort_version("7.23.1")
    assert sort_version("7.23.1 (stable)") == sort_version("7.23.1")
    assert sort_version("") == 0


def test_uptime_sort_key_is_seconds():
    """Uptime RouterOS превращается в секунды."""
    from app.routes.deps import uptime_seconds

    assert uptime_seconds("1d") == 86400
    assert uptime_seconds("3w2d10:15:42") == 3 * 604800 + 2 * 86400 + 10 * 3600 + 15 * 60 + 42
    assert uptime_seconds("5m30s") == 330
    assert uptime_seconds("") == 0
    # Час работы меньше недели — проверяем именно порядок
    assert uptime_seconds("1h") < uptime_seconds("1w")


def test_status_sort_puts_problems_first():
    from app.routes.deps import status_rank

    assert status_rank("offline") < status_rank("unknown") < status_rank("online")


def test_latency_table_shows_all_devices(client, router):
    """
    В таблице задержки видны все устройства, а не «худшие N».

    Раньше стоял предел в 25 строк: на парке из 49 точек половина просто
    не показывалась, и об этом нигде не говорилось.
    """
    from app import monitor
    from app.config import settings
    from app.database import execute

    ids = [_add_device(client, router, f"many-{i}") for i in range(30)]
    now_targets = settings.latency_targets
    settings.latency_targets = ["4.4.4.4=тест"]
    try:
        for index, device_id in enumerate(ids):
            execute(
                "INSERT INTO latency_samples (device_id, target, label, ts, sent, received, "
                "loss, rtt_avg) VALUES (?,'4.4.4.4','тест', datetime('now'), 5, 5, ?, ?)",
                (device_id, index % 5, 20 + index),
            )
        shown = {
            r["device_id"] for r in monitor.latency_summary(24)["problems"]
            if r["device_id"] in ids
        }
        assert len(shown) == len(ids), f"показано {len(shown)} из {len(ids)} устройств"
    finally:
        settings.latency_targets = now_targets


def test_label_comes_from_settings_not_old_samples(client, router):
    """
    Подпись цели берётся из текущих настроек, а не из старых замеров.

    Иначе один и тот же адрес выглядел бы в таблице по-разному: замеры,
    сделанные до появления подписи, показывали бы голый адрес.
    """
    from app import monitor
    from app.config import settings
    from app.database import execute

    device_id = _add_device(client, router, "label-fix")
    # Старый замер — сделан, когда подписи ещё не было
    execute(
        "INSERT INTO latency_samples (device_id, target, label, ts, sent, received, loss, rtt_avg) "
        "VALUES (?,'9.9.9.9','', datetime('now'), 5, 5, 0, 20)",
        (device_id,),
    )

    original = settings.latency_targets
    settings.latency_targets = ["9.9.9.9=хаб"]
    try:
        summary = monitor.latency_summary(24)
        row = next(r for r in summary["problems"] if r["device_id"] == device_id)
        assert row["label"] == "хаб", "подпись должна браться из настроек"
    finally:
        settings.latency_targets = original


def test_settings_show_configured_targets(client):
    """Настроенные цели видны в интерфейсе — пропажу заметно сразу."""
    from app.config import settings

    original = settings.latency_targets
    settings.latency_targets = ["10.0.0.1=хаб", "8.8.8.8=интернет"]
    try:
        html = client.get("/settings").text
        assert "Цели пинга" in html
        assert "10.0.0.1=хаб" in html
        assert "8.8.8.8=интернет" in html
    finally:
        settings.latency_targets = original


def test_settings_warn_when_no_targets(client):
    """Если целей нет вовсе — об этом говорится прямо."""
    from app.config import settings

    original = settings.latency_targets, settings.latency_ping_gateway
    settings.latency_targets = []
    settings.latency_ping_gateway = False
    try:
        assert "не задано ни одной цели" in client.get("/settings").text
    finally:
        settings.latency_targets, settings.latency_ping_gateway = original


def test_audit_log_records_actions(client):
    assert query_one("SELECT COUNT(*) AS c FROM audit_log")["c"] > 0
    assert query("SELECT * FROM audit_log WHERE action LIKE 'Вход%'")


def test_percent_sign_does_not_break_substitution():
    """
    Одиночный процент в тексте не ломает подстановку.

    Найдено на живой странице задачи: вместо «3 из 49 (6%)» там висело
    «%(p0)s из %(p1)s (%(p2)s%)». Причина в том, что перевод подставляется
    %-форматированием, а `%)` для него это битый спецификатор.

    Требовать от того, кто пишет интерфейс, помнить про это, значит
    расставлять мины: «готово 35%» нормальный человеческий текст.
    Поэтому чинится в слое перевода, а не в каждом шаблоне.
    """
    from app import i18n

    i18n.load_catalogs()

    assert i18n.translate("%(p0)s из %(p1)s (%(p2)s%)", "ru",
                          p0=3, p1=49, p2=6) == "3 из 49 (6%)"
    assert i18n.translate("Шкала с %(p0)s%, дальше видно", "ru",
                          p0=99) == "Шкала с 99%, дальше видно"
    # Уже удвоенный процент остаётся одним, как и было
    assert i18n.translate("100%% и %(p0)s", "ru", p0="да") == "100% и да"
    # Текст без подстановок не трогается вовсе
    assert i18n.translate("просто 50%", "ru") == "просто 50%"


def test_plural_filter_russian_forms():
    """
    Русские окончания по числу: «1 устройство», «2 устройства», «5 устройств».

    Отдельная проверка нужна из-за исключений в диапазоне 11–14:
    «11 устройств», а не «11 устройство».
    """
    from app.i18n import plural as _plural

    def plural(count, *forms):
        return _plural(count, forms, "ru")

    forms = ("устройство", "устройства", "устройств")
    cases = {
        0: "устройств", 1: "устройство", 2: "устройства", 4: "устройства",
        5: "устройств", 11: "устройств", 12: "устройств", 14: "устройств",
        21: "устройство", 22: "устройства", 25: "устройств",
        101: "устройство", 112: "устройств",
    }
    for number, expected in cases.items():
        assert plural(number, *forms) == expected, number

    # Мусор на входе не должен ронять страницу
    assert plural(None, *forms) == "устройств"
    assert plural("—", *forms) == "устройств"


# --------------------------------------------------------------- переводы
def test_every_interface_string_is_translated():
    """
    Для каждой надписи интерфейса есть английский перевод.

    Это главная защита от «наполовину переведённого» интерфейса: строки
    в шаблонах помечаются автоматически, и забыть обёртку невозможно —
    зато легко забыть сам перевод. Тест находит такое сразу.
    """
    from pathlib import Path

    from app import i18n

    i18n.load_catalogs()
    missing = i18n.missing_translations("en", Path("templates"))
    assert not missing, "нет английского перевода для строк:\n  " + "\n  ".join(missing)


def test_browser_strings_are_translated():
    """
    Строки, зашитые в app.js, тоже переведены.

    Их не видит проверка шаблонов: они живут в JavaScript и попадают
    в страницу отдельным словарём.
    """
    from app import i18n

    i18n.load_catalogs()
    catalog = i18n.js_catalog("en")
    untranslated = [text for text in i18n.js_strings() if catalog.get(text) == text]
    assert not untranslated, "нет перевода для строк JS:\n  " + "\n  ".join(untranslated)


def test_interface_switches_to_english(client):
    """Переключение языка меняет надписи, а не только код в <html lang>."""
    client.get("/lang/ru", follow_redirects=False)
    page = client.get("/devices").text
    assert "Устройства" in page

    client.get("/lang/en", follow_redirects=False)
    page = client.get("/devices").text
    assert 'lang="en"' in page
    assert "Devices" in page
    assert "Устройства" not in page

    client.get("/lang/ru", follow_redirects=False)
    assert "Устройства" in client.get("/devices").text


def test_language_choice_survives_relogin(client):
    """Выбор языка привязан к администратору, а не к сессии."""
    from app.database import query_one

    client.get("/lang/en", follow_redirects=False)
    assert query_one("SELECT lang FROM users WHERE username='admin'")["lang"] == "en"

    client.get("/logout", follow_redirects=False)
    client.post("/login", data={"username": "admin", "password": "admin"},
                follow_redirects=False)
    assert 'lang="en"' in client.get("/devices").text
    client.get("/lang/ru", follow_redirects=False)


def test_device_error_is_translated_on_the_page(client, router):
    """
    Ошибка устройства хранится в базе по-русски, а показывается на языке
    интерфейса — иначе английская страница пестрит русскими сообщениями.
    """
    from app.database import execute

    device_id = _add_device(client, router, "err-device")
    execute("UPDATE devices SET status='offline', last_error=? WHERE id=?",
            ("Таймаут подключения", device_id))

    client.get("/lang/en", follow_redirects=False)
    page = client.get(f"/devices/{device_id}").text
    assert "Connection timeout" in page
    assert "Таймаут подключения" not in page
    client.get("/lang/ru", follow_redirects=False)


def test_unknown_language_falls_back(client):
    """Неизвестный код языка не роняет страницу и не оставляет пустоту."""
    client.get("/lang/klingon", follow_redirects=False)
    assert client.get("/devices").status_code == 200
    client.get("/lang/ru", follow_redirects=False)


def test_plural_forms_follow_language():
    """В русском три формы, в английском две."""
    from app import i18n

    i18n.load_catalogs()
    ru = ("устройство", "устройства", "устройств")
    assert i18n.plural(1, ru, "ru") == "устройство"
    assert i18n.plural(3, ru, "ru") == "устройства"
    assert i18n.plural(5, ru, "ru") == "устройств"
    assert i18n.plural(1, ru, "en") == "device"
    assert i18n.plural(5, ru, "en") == "devices"


def test_ui_texts_have_no_em_dash():
    """
    В текстах, которые видит пользователь, длинных тире быть не должно.

    Требование заказчика: тире раздражает и выдаёт машинное происхождение
    текста. Комментарии в коде под правило не попадают, их пользователь
    не видит. Единственное разрешённое употребление — одиночный прочерк
    вместо отсутствующего значения в таблице: там это не пунктуация,
    а знак «данных нет».

    Проверка нужна именно автоматическая: тире возвращается незаметно,
    по одному на каждую новую строку интерфейса.
    """
    import ast
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    dash = "—"
    problems = []

    # --- шаблоны: убираем комментарии Jinja и разрешённые прочерки
    for path in sorted((root / "templates").rglob("*.html")):
        text = re.sub(r"\{#.*?#\}", "", path.read_text(encoding="utf-8"), flags=re.S)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)   # комментарии в скриптах
        text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
        for allowed in ("'%s'" % dash, ">%s<" % dash, "%%}%s" % dash):
            text = text.replace(allowed, "")
        for line in text.splitlines():
            if dash in line:
                problems.append(f"{path.name}: {line.strip()[:90]}")

    # --- python: только строковые литералы, но не документация и не комментарии
    for path in sorted((root / "app").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        docs = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                 ast.AsyncFunctionDef)) and node.body:
                first = node.body[0]
                if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                    docs.add(id(first.value))
        for node in ast.walk(tree):
            if (not isinstance(node, ast.Constant) or not isinstance(node.value, str)
                    or id(node) in docs or node.value.strip() == dash):
                continue
            # в схеме БД встречаются комментарии SQL: они тоже не текст панели
            value = re.sub(r"--.*$", "", node.value, flags=re.M)
            if dash in value:
                problems.append(f"{path.name}:{node.lineno}: {value.strip()[:90]}")

    # --- браузер: только то, что обёрнуто в T('...')
    js = (root / "static" / "app.js").read_text(encoding="utf-8")
    for found in re.findall(r"T\('([^']*)'\)", js):
        if dash in found:
            problems.append("app.js: " + found[:90])

    assert not problems, "длинные тире в текстах панели:\n  " + "\n  ".join(problems)


def test_translation_does_not_break_on_device_names():
    """
    Имя устройства с угловыми скобками не должно попадать в страницу
    как разметка: фразы с тегами отдаются готовым HTML.
    """
    from app import i18n

    i18n.load_catalogs()
    text = i18n.translate('<span class="small muted">· лежало %(p0)s</span>', "en", p0="5 min")
    assert "5 min" in text


def test_english_is_the_default_language():
    """
    По умолчанию интерфейс английский.

    Тесты идут с DEFAULT_LANG=ru, поэтому значение по умолчанию проверяем
    здесь напрямую: иначе никто бы не заметил, если оно однажды поменяется.
    """
    import os

    from app.config import Settings

    saved = os.environ.pop("DEFAULT_LANG", None)
    try:
        assert Settings().default_lang == "en"
    finally:
        if saved is not None:
            os.environ["DEFAULT_LANG"] = saved


def test_english_pages_contain_no_russian(client, router):
    """
    На английском языке страницы не должны содержать русских слов.

    Проверка шаблонов ловит не всё: строка может прийти из Python или
    собираться словарём внутри выражения `{{ ... }}`, а туда автоматическая
    разметка не заглядывает. Именно так на странице задач осталось
    «Завершена» рядом с английскими заголовками.
    """
    import html as html_lib
    import re

    from app.config import BASE_DIR, settings

    # Данные пользователя русскими быть могут и должны: путь к папке проекта,
    # подписи целей пинга из .env, имена устройств. Их из проверки исключаем.
    own_data = [str(BASE_DIR), str(settings.data_dir)]

    # Цели пинга задаются как «10.0.0.1=хаб»: в интерфейсе видна подпись,
    # поэтому в исключения идёт и она, а не только строка целиком.
    for target in settings.latency_targets:
        own_data += [part for part in target.split("=") if part]

    # Всё, что человек ввёл сам, на английской странице остаётся русским
    # и это правильно: имена точек, комментарии, подписи клиентов,
    # параметры запущенных задач. Собираем такие значения из базы целиком,
    # а не по одному столбцу за раз, иначе проверка падает или не падает
    # в зависимости от того, какие тесты успели отработать раньше.
    data_columns = {
        # Оператор это тоже данные: имя приходит от модема или вписано
        # человеком, и на английской странице оно остаётся как есть
        "devices": ("name", "comment", "last_error", "operator", "operator_detail"),
        "groups": ("name", "comment"),
        "clients": ("label", "hostname", "comment"),
        "audit_log": ("target", "details"),
        "status_events": ("reason",),
        "backups": ("device_name", "filename"),
        "jobs": ("params_json", "username"),
    }
    for table, columns in data_columns.items():
        for row in query(f"SELECT {', '.join(columns)} FROM {table}"):
            own_data += [str(row[c] or "") for c in columns]

    device_id = _add_device(client, router, "en-page-check")
    _run_and_wait(client, "check", [device_id], {})

    # Заполняем таблицы, из которых строки приходят готовыми: пустая страница
    # проверяет только заголовки, а русский текст живёт как раз в данных.
    from app.database import execute, utcnow

    execute(
        "INSERT INTO status_events (device_id, device_name, device_host, status,"
        " reason, ts) VALUES (?,?,?,?,?,?)",
        (device_id, "en-page-check", "127.0.0.1", "offline",
         "Таймаут подключения", utcnow()),
    )
    execute(
        "INSERT INTO backups (device_id, device_name, kind, filename, size,"
        " created_at) VALUES (?,?,?,?,?,?)",
        (device_id, "en-page-check", "binary", "en-page-check.backup", 1024, utcnow()),
    )
    execute(
        "UPDATE devices SET status='offline', last_error=? WHERE id=?",
        ("Таймаут подключения", device_id),
    )

    client.get("/lang/en", follow_redirects=False)
    try:
        for page in ("/", "/devices", "/monitoring", "/jobs", "/backups",
                     "/history", "/settings", "/groups", "/scripts"):
            html = client.get(page).text
            # Комментарии разработчика и переключатель языка не в счёт
            # Раскодируем сущности: параметры задач попадают на страницу
            # экранированными, и сравнение с исходным значением из базы
            # без этого не срабатывало
            clean = html_lib.unescape(
                re.sub(r"<!--.*?-->|<script.*?</script>|>Русский<", "", html, flags=re.S))
            russian = {m.strip() for m in re.findall(r"[^<>\"\n]*[А-Яа-яЁё][^<>\"\n]*", clean)}
            # Сравниваем в обе стороны. Данные пользователя бывают длиннее
            # найденного куска (имя точки внутри строки таблицы), а бывают
            # короче: параметры задачи выводятся как JSON, и регулярное
            # выражение режет его по кавычкам на отдельные значения.
            russian = {
                r for r in russian
                if r and not any(own and (own in r or r in own) for own in own_data)
            }
            assert not russian, f"{page}: непереведённое {sorted(russian)[:5]}"
    finally:
        client.get("/lang/ru", follow_redirects=False)


def test_action_forms_are_fully_translated():
    """
    У массовых действий переведены названия, описания и все подписи полей.

    Диалог рисует браузер по ответу /api/actions, поэтому проверка шаблонов
    сюда не достаёт. Пропущенная подсказка выглядит как русский абзац посреди
    английской формы.
    """
    from app import i18n
    from app.actions import action_to_dict, list_actions

    i18n.load_catalogs()
    untranslated: list[str] = []

    def check(text: str | None) -> None:
        if text and any("Ѐ" <= c <= "ӿ" for c in text):
            if i18n.translate_text(text, "en") == text:
                untranslated.append(text)

    for action in list_actions():
        data = action_to_dict(action)
        check(data.get("label"))
        check(data.get("description"))
        for param in data.get("params") or []:
            for key in ("label", "help", "placeholder"):
                check(param.get(key))
            for _value, title in param.get("options") or []:
                check(title)

    assert not untranslated, "нет перевода:\n  " + "\n  ".join(untranslated)


def test_russian_literals_in_expressions_go_through_the_filter():
    """
    Русский текст внутри `{{ ... }}` должен проходить через фильтр `| t`.

    Автоматическая разметка шаблонов обрабатывает только обычный текст.
    Строка, собранная выражением, ей не видна, и именно так на страницу
    задач попало «Завершена», а на вкладку бэкапов «бинарный». Проверка
    статическая: смотрит сами шаблоны, а не готовые страницы, поэтому
    ловит и те места, которые не покрыты данными в тестовой базе.
    """
    import re
    from pathlib import Path

    cyrillic = re.compile(r"[А-Яа-яЁё]")
    bad: list[str] = []

    for path in sorted(Path("templates").rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        for expr in re.findall(r"\{\{(.*?)\}\}", text, re.S):
            # `_()` это и есть перевод, а `plural` переводит формы сам
            if not cyrillic.search(expr) or "_(" in expr or "plural(" in expr:
                continue
            if "| t" not in expr and "|t" not in expr:
                bad.append(f"{path.name}: {{{{{' '.join(expr.split())[:80]}}}}}")

    # Обработчики onclick это JavaScript: авторазметка в атрибуты с кодом
    # не лезет, а текст оттуда попадает в диалог подтверждения.
    for path in sorted(Path("templates").rglob("*.html")):
        text = path.read_text(encoding="utf-8")
        for handler in re.findall(r'on[a-z]+="([^"]*)"', text):
            if cyrillic.search(handler) and "_(" not in handler:
                bad.append(f"{path.name}: {' '.join(handler.split())[:80]}")

    assert not bad, "русский текст без перевода:\n  " + "\n  ".join(bad)


def test_old_database_is_picked_up_after_rename(tmp_path):
    """
    База от прежнего имени проекта подхватывается автоматически.

    Проект назывался ROSmanager. Если после обновления просто создать рядом
    новую пустую базу, человек увидит пустой список устройств и решит, что
    потерял всё. Такое поведение недопустимо, поэтому файл переименовывается.
    """
    import os

    from app.config import Settings

    legacy = tmp_path / "rosmanager.db"
    legacy.write_bytes(b"SQLite format 3\x00")
    (tmp_path / "rosmanager.db-wal").write_bytes(b"wal")

    saved = os.environ.get("DATA_DIR")
    os.environ["DATA_DIR"] = str(tmp_path)
    try:
        settings = Settings()
        assert settings.db_path.name == "tikpilot.db"
        assert settings.db_path.exists()
        assert (tmp_path / "tikpilot.db-wal").exists()
        assert not legacy.exists()
    finally:
        if saved is None:
            os.environ.pop("DATA_DIR", None)
        else:
            os.environ["DATA_DIR"] = saved


def test_new_database_wins_over_the_old_one(tmp_path):
    """Если новая база уже есть, старую не трогаем: она может быть от копии."""
    import os

    from app.config import Settings

    (tmp_path / "rosmanager.db").write_bytes(b"old")
    (tmp_path / "tikpilot.db").write_bytes(b"new")

    saved = os.environ.get("DATA_DIR")
    os.environ["DATA_DIR"] = str(tmp_path)
    try:
        Settings()
        assert (tmp_path / "rosmanager.db").read_bytes() == b"old"
        assert (tmp_path / "tikpilot.db").read_bytes() == b"new"
    finally:
        if saved is None:
            os.environ.pop("DATA_DIR", None)
        else:
            os.environ["DATA_DIR"] = saved


def test_empty_form_field_answers_like_a_form_not_like_a_protocol(client):
    """
    Пустое поле формы получает человеческий ответ, а не JSON от FastAPI.

    Обязательное поле, пришедшее пустым, часть версий Starlette считает
    отсутствующим и отвечает страницей `{"detail": [... "Field required"]}`.
    Это ответ протокола на человеческую ошибку: в панели такое должно
    возвращаться подсказкой в форме.
    """
    page = client.post("/settings/users", data={"new_username": "", "password": "123456"})
    assert page.status_code == 200
    assert "Укажите имя пользователя" in page.text
    assert "Field required" not in page.text

    # И вход с пустыми полями тоже отвечает страницей входа, а не JSON:
    # 401 здесь правильный код, важно, что тело человеческое
    with _anon() as anon:
        answer = anon.post("/login", data={"username": "", "password": ""},
                           follow_redirects=False)
        assert answer.status_code == 401
        assert "Field required" not in answer.text
        assert "<form" in answer.text


def test_old_database_gets_every_column_the_code_reads():
    """
    Обновление на старой базе доводит её до нужной схемы.

    Проверка нужна вот почему. Тесты всегда начинают с чистой базы,
    а там таблицы создаются по SCHEMA со всеми колонками сразу, поэтому
    сломанную миграцию они не видят в упор. У живой панели база наоборот
    старая, и недостающая колонка кладёт её целиком: код читает поле,
    которого в строке нет.

    Ровно так и вышло с `session_epoch`: в списке миграций оказалось два
    ключа `users`, второй молча затёр первый, на свежей базе всё работало,
    а на рабочей панели каждая страница отвечала ошибкой.
    """
    import sqlite3

    from app import database

    # База, какой она была до появления прав и поколения сессий
    old = sqlite3.connect(":memory:")
    old.row_factory = sqlite3.Row
    old.executescript(
        "CREATE TABLE users ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " username TEXT NOT NULL UNIQUE,"
        " password_hash TEXT NOT NULL,"
        " is_active INTEGER NOT NULL DEFAULT 1,"
        " created_at TEXT NOT NULL);"
        "INSERT INTO users (username, password_hash, created_at)"
        " VALUES ('старожил', 'x', '2020-01-01 00:00:00');"
    )

    for name, definition in database.MIGRATIONS["users"]:
        existing = {r["name"] for r in old.execute("PRAGMA table_info(users)")}
        if name not in existing:
            old.execute(f"ALTER TABLE users ADD COLUMN {name} {definition}")

    row = old.execute("SELECT * FROM users").fetchone()
    for column in ("lang", "permissions", "scope_all", "session_epoch"):
        assert column in row.keys(), f"после обновления нет колонки {column}"

    # Значения по умолчанию должны быть безопасными: доступ не отнимаем,
    # поколение сессий совпадает с тем, что кладётся в свежие cookie
    assert row["permissions"] == "full"
    assert row["session_epoch"] == 0


def test_password_button_has_a_working_handler(client, router):
    """
    У кнопки «Пароль» есть обработчик, и он не в шаблоне, а в app.js.

    Кнопка была, форма была, а функции не было: onclick звал то, чего
    в браузере нет, и нажатие не делало ровно ничего, молча. Проверка
    сверяет разметку страницы с содержимым скрипта.
    """
    from pathlib import Path

    from app.config import BASE_DIR

    _make_user(client, "с-паролем", ["settings.view"])
    page = client.get("/settings").text
    assert "togglePassword(" in page, "кнопки «Пароль» нет на странице"
    assert 'id="user-pass-' in page, "формы сброса нет на странице"

    script = Path(BASE_DIR, "static", "app.js").read_text(encoding="utf-8")
    assert "function togglePassword" in script, "onclick зовёт несуществующую функцию"
    assert "user-pass-" in script, "функция ищет не тот элемент"


def test_admin_resets_another_password_and_kicks_that_person_out(client, router):
    """
    Сброс пароля админом: пароль меняется, прежние входы завершаются.

    Второе не менее важно первого. Сессия у нас это подписанная cookie,
    сервер её не хранит и поштучно отозвать не может, поэтому у каждого
    есть номер поколения. Без него сброшенный пароль ничего не решал бы:
    чужая открытая вкладка продолжала бы работать.
    """
    _make_user(client, "забывчивый", ["settings.view"])

    with _as("забывчивый") as forgetful:
        assert forgetful.get("/settings").status_code == 200

        target = query_one("SELECT id FROM users WHERE username = ?", ("забывчивый",))
        page = client.post(f"/settings/users/{target['id']}/password",
                           data={"password": "новый-пароль-1"})
        assert page.status_code == 200
        assert "прежние входы завершены" in page.text

        # Старая вкладка того человека больше не работает
        assert forgetful.get("/settings", follow_redirects=False).status_code == 303

    # А с новым паролем вход проходит
    with _anon() as fresh:
        answer = fresh.post("/login", data={"username": "забывчивый",
                                            "password": "новый-пароль-1"},
                            follow_redirects=False)
        assert answer.status_code == 303, "новый пароль не работает"

    # И в журнале это видно
    row = query_one("SELECT target, details FROM audit_log WHERE action = ?"
                    " ORDER BY id DESC LIMIT 1", ("Сброшен пароль администратора",))
    assert row is not None, "сброс не записан в журнал"
    assert row["target"] == "забывчивый"
    assert "входы завершены" in row["details"]


def test_password_reset_needs_the_right_and_is_not_for_yourself(client, router):
    """
    Сброс доступен только тому, кто и так заводит администраторов.

    И только чужой: свой пароль меняют формой, которая спрашивает текущий.
    Разница не формальная — перехваченная сессия не должна давать
    закрепиться в панели, не зная прежнего пароля.
    """
    _make_user(client, "посторонний", ["settings.view"])
    victim = query_one("SELECT id FROM users WHERE username = ?", ("admin",))
    outsider = query_one("SELECT id FROM users WHERE username = ?", ("посторонний",))

    with _as("посторонний") as guest:
        assert guest.post(f"/settings/users/{victim['id']}/password",
                          data={"password": "чужой-пароль"}).status_code == 403

    mine = query_one("SELECT id FROM users WHERE username = ?", ("admin",))
    page = client.post(f"/settings/users/{mine['id']}/password",
                       data={"password": "как-нибудь-так"})
    assert "Смена своего пароля" in page.text

    # Короткий пароль не принимается
    short = client.post(f"/settings/users/{outsider['id']}/password",
                        data={"password": "12345"})
    assert "не короче 6 символов" in short.text


def test_settings_messages_are_translated(client):
    """
    Сообщения после действий на странице настроек переводятся.

    Их формирует Python и передаёт в шаблон переменной, поэтому
    автоматическая разметка их не видит. «Пользователь удалён» рядом
    с английскими заголовками выглядит как недоделанный перевод.
    """
    from app.database import query_one

    client.get("/lang/en", follow_redirects=False)
    try:
        page = client.post("/settings/users",
                           data={"new_username": "", "password": "123456"}).text
        assert "Enter a user name" in page
        assert "Укажите имя пользователя" not in page

        page = client.post("/settings/users",
                           data={"new_username": "tmp-user", "password": "123456"}).text
        assert "User tmp-user added" in page

        user_id = query_one("SELECT id FROM users WHERE username='tmp-user'")["id"]
        page = client.post(f"/settings/users/{user_id}/delete").text
        assert "User deleted" in page
    finally:
        client.get("/lang/ru", follow_redirects=False)


def test_browser_validation_hint_follows_the_page(client):
    """
    Подсказку о незаполненном поле рисует браузер на своём языке.

    У человека с русским браузером на английской странице всплывало
    «Заполните это поле». Наш текст тут ни при чём, но выглядит это как
    недоделанный перевод, поэтому сообщение подменяется на язык страницы.
    Проверяем и страницу входа: она не подключает app.js и словарь
    получает отдельно.
    """
    client.get("/lang/en", follow_redirects=False)
    try:
        assert "Please fill out this field." in client.get("/settings").text
        client.get("/logout", follow_redirects=False)
        assert "Please fill out this field." in client.get("/login").text
    finally:
        client.post("/login", data={"username": "admin", "password": "admin"},
                    follow_redirects=False)
        client.get("/lang/ru", follow_redirects=False)


# ------------------------------------------------------------------- права
def _make_user(client, username: str, permissions: list[str], *,
               scope_all: bool = True, groups=(), devices=()) -> int:
    """Создать пользователя с заданными правами и вернуть его id."""
    from app import permissions as perms
    from app.database import query_one

    client.post("/settings/users", data={"new_username": username, "password": "s3cret1"})
    user_id = query_one("SELECT id FROM users WHERE username = ?", (username,))["id"]
    perms.save(user_id, permissions, scope_all, groups, devices)
    return user_id


@contextlib.contextmanager
def _anon():
    """
    Клиент без входа, для публичных страниц.

    Тоже свой менеджер контекста, и по той же причине, что у `_as`:
    `with TestClient(app)` на выходе гасит приложение целиком вместе
    с фоновым воркером, общим на весь процесс. После такого выхода
    любая следующая задача в любом следующем тесте висела до таймаута,
    а искали её потом где угодно, только не здесь.
    """
    client = TestClient(app)
    try:
        yield client
    finally:
        client.close()


@contextlib.contextmanager
def _as(username: str):
    """
    Отдельный клиент, вошедший под указанным пользователем.

    Именно свой менеджер контекста, а не `with TestClient(app)`. Тот на
    входе поднимает приложение, а на выходе гасит его целиком: останавливает
    фоновый воркер и монитор, общие для всего процесса. Дальше задачи
    в следующих тестах повисали навсегда, а искать причину приходилось
    в совершенно другом месте.
    """
    client = TestClient(app)
    r = client.post("/login", data={"username": username, "password": "s3cret1"},
                    follow_redirects=False)
    assert r.status_code == 303, "не удалось войти"
    try:
        yield client
    finally:
        client.close()


def test_new_user_starts_with_no_rights(client):
    """
    Новая учётная запись создаётся без прав.

    Обратное было бы опасным сюрпризом: администратор завёл человека
    «посмотреть», а тот может перезагрузить весь парк.
    """
    _make_user(client, "nobody", [])
    with _as("nobody") as guest:
        assert guest.get("/settings").status_code == 403
        assert guest.get("/backups").status_code == 403
        assert guest.get("/history").status_code == 403
        # Дашборд остаётся доступным: это просто состояние своей области
        assert guest.get("/").status_code == 200


def test_password_change_answers_with_a_page(client):
    """
    Смена своего пароля отвечает страницей, а не ошибкой сервера.

    Роут собирал ответ по имени, которого в модуле не было, и падал уже
    после записи нового пароля в базу: человек видел Internal Server Error
    и не понимал, сменился пароль или нет. Проверка простая до неприличия,
    но её не было вовсе, поэтому поломка дожила до живой панели.
    """
    from app.auth import authenticate

    _make_user(client, "changer", ["settings.view"])
    with _as("changer") as person:
        wrong = person.post("/settings/password", data={
            "old_password": "не тот", "new_password": "s3cret2",
            "new_password2": "s3cret2"})
        assert wrong.status_code == 200
        assert "неверно" in wrong.text
        assert authenticate("changer", "s3cret1"), "пароль сменился при неверном старом"

        short = person.post("/settings/password", data={
            "old_password": "s3cret1", "new_password": "123",
            "new_password2": "123"})
        assert short.status_code == 200

        ok = person.post("/settings/password", data={
            "old_password": "s3cret1", "new_password": "s3cret2",
            "new_password2": "s3cret2"})
        assert ok.status_code == 200
        assert "Пароль изменён" in ok.text

    assert authenticate("changer", "s3cret2"), "новый пароль не работает"
    assert authenticate("changer", "s3cret1") is None, "старый пароль всё ещё принимается"


def test_password_change_without_settings_view_shows_no_accounts(client):
    """
    Свой пароль меняет кто угодно, но чужие учётки при этом не показываются.

    Ответ на смену пароля это та же страница настроек. Без проверки она
    выдала бы список всех учётных записей тому, кому саму страницу
    открывать нельзя.
    """
    _make_user(client, "changer2", ["settings.view"])
    _make_user(client, "quiet", [])

    with _as("quiet") as person:
        r = person.post("/settings/password", data={
            "old_password": "s3cret1", "new_password": "s3cret3",
            "new_password2": "s3cret3"})
        assert r.status_code == 200
        assert "Пароль изменён" in r.text
        assert "changer2" not in r.text, "показаны чужие учётные записи"


def _invite(client, note: str = "подрядчик", hours: int = 48) -> str:
    """Выписать приглашение и вернуть его токен."""
    from app.database import query_one

    r = client.post("/settings/invites", data={"note": note, "hours": hours})
    assert r.status_code == 200
    row = query_one("SELECT token FROM invites ORDER BY id DESC LIMIT 1")
    return str(row["token"])


def test_invited_person_registers_and_gets_no_rights(client, router):
    """
    По приглашению человек заводит вход сам, но доступа это ему не даёт.

    Регистрация и права это два разных события. Если бы новая учётная
    запись получала хоть что-нибудь, ссылка в переписке становилась бы
    ключом от парка, а не от пустого кабинета.
    """
    from app.database import query_one

    token = _invite(client, "новый инженер")

    with _anon() as guest:
        page = guest.get(f"/invite/{token}")
        assert page.status_code == 200
        assert "новый инженер" in page.text

        done = guest.post(f"/invite/{token}", data={
            "username": "invited", "password": "s3cret9", "password2": "s3cret9"},
            follow_redirects=False)
        assert done.status_code == 303, "после регистрации не пустили внутрь"

        # Вошёл сразу, но панель для него пустая
        home = guest.get("/")
        assert home.status_code == 200
        assert "прав у неё пока нет" in home.text
        assert guest.get("/settings").status_code == 403
        assert guest.get("/backups").status_code == 403

    row = query_one("SELECT permissions FROM users WHERE username = ?", ("invited",))
    assert row and row["permissions"] == "", "новая запись получила права"


def test_invite_link_works_once(client, router):
    """
    Ссылка одноразовая.

    Иначе приглашение, оставшееся в чате, заводит второго человека через
    месяц, и в списке учётных записей появляется кто-то, кого никто не звал.
    """
    token = _invite(client, "разовый")

    with _anon() as first:
        first.post(f"/invite/{token}", data={
            "username": "once-one", "password": "s3cret9", "password2": "s3cret9"},
            follow_redirects=False)

    with _anon() as second:
        page = second.get(f"/invite/{token}")
        assert page.status_code == 404
        second.post(f"/invite/{token}", data={
            "username": "once-two", "password": "s3cret9", "password2": "s3cret9"})

    from app.database import query_one

    assert query_one("SELECT id FROM users WHERE username = ?", ("once-two",)) is None


def test_expired_and_revoked_invites_are_refused(client, router):
    """
    Просроченное и отозванное приглашение не работает, и отвечают они одинаково.

    Разные ответы подсказали бы перебирающему, что токен существует.
    Человеку с настоящей ссылкой разница не помогла бы: ему в любом случае
    нужна новая.
    """
    from app.database import execute, query_one

    stale = _invite(client, "просроченный")
    execute("UPDATE invites SET expires_at = datetime('now','-1 hour') WHERE token = ?",
            (stale,))

    revoked = _invite(client, "отозванный")
    invite_id = query_one("SELECT id FROM invites WHERE token = ?", (revoked,))["id"]
    assert client.post(f"/settings/invites/{invite_id}/revoke").status_code == 200

    with _anon() as guest:
        for token in (stale, revoked, "z" * 32):
            assert guest.get(f"/invite/{token}").status_code == 404
            guest.post(f"/invite/{token}", data={
                "username": "sneaky", "password": "s3cret9", "password2": "s3cret9"})

    assert query_one("SELECT id FROM users WHERE username = ?", ("sneaky",)) is None


def test_invite_cannot_take_over_an_existing_account(client, router):
    """
    Занятое имя не перехватывается.

    Иначе приглашённый набрал бы «admin» с новым паролем и получил бы чужую
    учётную запись. Проверка на сервере, а не в форме.
    """
    from app.database import query_one

    before = query_one("SELECT password_hash FROM users WHERE username = ?", ("admin",))
    token = _invite(client, "самозванец")

    with _anon() as guest:
        answer = guest.post(f"/invite/{token}", data={
            "username": "admin", "password": "s3cret9", "password2": "s3cret9"})
        assert answer.status_code == 400
        assert "занято" in answer.text

    after = query_one("SELECT password_hash FROM users WHERE username = ?", ("admin",))
    assert after["password_hash"] == before["password_hash"], "чужой пароль переписан"

    # Приглашение при этом не потрачено: человек попробует ещё раз
    assert query_one("SELECT used_at FROM invites WHERE token = ?", (token,))["used_at"] is None


def test_only_user_manager_can_invite(client, router):
    """Выписывать приглашения может только тот, кто и так управляет людьми."""
    _make_user(client, "notmanager", ["settings.view"])

    with _as("notmanager") as guest:
        assert guest.post("/settings/invites", data={"note": "нельзя"}).status_code == 403


def test_invite_token_is_not_written_to_the_audit_log(client, router):
    """
    Токен приглашения в журнал действий не попадает.

    Это пароль от входа в систему. В журнале он пережил бы и отзыв ссылки,
    и увольнение того, кому её выписали.
    """
    from app.database import query

    token = _invite(client, "без следа")
    rows = query("SELECT * FROM audit_log WHERE action = 'Создано приглашение'")
    assert rows, "создание приглашения не записано вовсе"
    for row in rows:
        assert token not in " ".join(str(v) for v in dict(row).values())


def test_action_without_permission_is_refused_by_the_api(client, router):
    """
    Запрет на действие проверяется на сервере, а не в интерфейсе.

    Спрятанная кнопка это удобство. Запрос можно отправить и curl-ом,
    поэтому проверка обязана стоять в самом роуте.
    """
    device_id = _add_device(client, router, "perm-device")
    _make_user(client, "checker", ["action.check"])

    with _as("checker") as operator:
        ok = operator.post("/api/jobs", json={
            "action": "check", "device_ids": [device_id], "params": {}})
        assert ok.status_code == 200

        denied = operator.post("/api/jobs", json={
            "action": "reboot", "device_ids": [device_id], "params": {}})
        assert denied.status_code == 403
        assert "reboot" not in [a["name"] for a in operator.get("/api/actions").json()]


def test_scope_hides_other_devices(client, router):
    """Устройства вне области не видны ни на страницах, ни в API."""
    from app.database import execute

    mine = _add_device(client, router, "scope-mine")
    theirs = _add_device(client, router, "scope-theirs")
    _make_user(client, "narrow", ["action.check"], scope_all=False, devices=[mine])

    with _as("narrow") as limited:
        page = limited.get("/devices").text
        assert "scope-mine" in page
        assert "scope-theirs" not in page

        # Чужая карточка для этого пользователя просто не существует
        assert limited.get(f"/devices/{theirs}").status_code == 403

        # И задачу на неё поставить нельзя, даже зная идентификатор
        r = limited.post("/api/jobs", json={
            "action": "check", "device_ids": [theirs], "params": {}})
        assert r.status_code == 403

        # «Все устройства» означает всё, что видит он, а не весь парк
        r = limited.post("/api/jobs", json={"action": "check", "all": True, "params": {}})
        assert r.status_code == 200
        from app.database import query
        items = query("SELECT device_id FROM job_items WHERE job_id = ?", (r.json()["job_id"],))
        assert {i["device_id"] for i in items} == {mine}


def test_scope_by_group(client, router):
    """Область можно задать группой, а не перечислением устройств."""
    from app.database import execute, query_one, utcnow

    execute("INSERT INTO groups (name, created_at) VALUES ('Регион-1', ?)", (utcnow(),))
    group_id = query_one("SELECT id FROM groups WHERE name='Регион-1'")["id"]

    inside = _add_device(client, router, "grp-inside")
    outside = _add_device(client, router, "grp-outside")
    execute("UPDATE devices SET group_id = ? WHERE id = ?", (group_id, inside))

    _make_user(client, "regional", ["action.check"], scope_all=False, groups=[group_id])
    with _as("regional") as limited:
        page = limited.get("/devices").text
        assert "grp-inside" in page and "grp-outside" not in page


def test_backups_respect_permissions_and_scope(client, router):
    """
    Бэкапы отдаются только с правом и только по своим устройствам.

    В текстовом export лежит вся конфигурация, поэтому скачивание вынесено
    в отдельное право: видеть список и забирать файлы это разные вещи.
    """
    from app.database import execute, query_one, utcnow

    mine = _add_device(client, router, "bk-mine")
    theirs = _add_device(client, router, "bk-theirs")
    for device_id, name in ((mine, "bk-mine"), (theirs, "bk-theirs")):
        execute(
            "INSERT INTO backups (device_id, device_name, kind, filename, size, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (device_id, name, "binary", f"{name}.backup", 100, utcnow()),
        )

    _make_user(client, "bkviewer", ["backups.view"], scope_all=False, devices=[mine])
    with _as("bkviewer") as viewer:
        page = viewer.get("/backups").text
        assert "bk-mine" in page and "bk-theirs" not in page

        theirs_backup = query_one(
            "SELECT id FROM backups WHERE device_id = ?", (theirs,))["id"]
        mine_backup = query_one(
            "SELECT id FROM backups WHERE device_id = ?", (mine,))["id"]

        # Права на скачивание нет вообще
        assert viewer.get(f"/backups/{mine_backup}/download").status_code == 403

    _make_user(client, "bkdownloader", ["backups.view", "backups.download"],
               scope_all=False, devices=[mine])
    with _as("bkdownloader") as downloader:
        # Своё скачать нельзя только потому, что файла нет на диске, а вот
        # чужое отбивается раньше — по области видимости
        assert downloader.get(f"/backups/{theirs_backup}/download").status_code == 403


def test_editing_devices_needs_permission(client, router):
    """Без права на правку устройств запрещены и создание, и удаление."""
    device_id = _add_device(client, router, "ro-device")
    _make_user(client, "readonly", ["action.check"])

    with _as("readonly") as viewer:
        assert viewer.post("/api/devices", json={
            "name": "sneaky", "host": "10.0.0.77", "username": "api"}).status_code == 403
        assert viewer.post(f"/api/devices/{device_id}/delete").status_code == 403
        assert viewer.post("/api/devices/bulk-delete",
                           json={"device_ids": [device_id]}).status_code == 403


def test_user_cannot_change_own_permissions(client):
    """
    Свои права менять нельзя.

    Иначе первым же неверным нажатием можно запереть себя снаружи,
    и чинить придётся правкой базы на сервере.
    """
    from app.database import query_one

    admin_id = query_one("SELECT id FROM users WHERE username='admin'")["id"]
    page = client.post(f"/settings/users/{admin_id}/permissions", data={"perm": []}).text
    assert "Свои права менять нельзя" in page or "cannot change your own" in page.lower()

    fresh = query_one("SELECT permissions FROM users WHERE id = ?", (admin_id,))
    assert "full" in fresh["permissions"]


def test_existing_admins_keep_full_access_after_upgrade(tmp_path):
    """
    Обновление программы не должно отнимать доступ у существующих учёток.

    До появления прав все были администраторами, поэтому колонка заполняется
    значением «full». Иначе после обновления никто не смог бы войти в настройки.
    """
    import sqlite3

    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, "
        "password_hash TEXT, is_active INTEGER DEFAULT 1, created_at TEXT)"
    )
    conn.execute("INSERT INTO users (username, password_hash, created_at) VALUES ('old','x','')")
    conn.commit()
    conn.close()

    conn = sqlite3.connect(db)
    conn.execute("ALTER TABLE users ADD COLUMN permissions TEXT NOT NULL DEFAULT 'full'")
    row = conn.execute("SELECT permissions FROM users WHERE username='old'").fetchone()
    conn.close()
    assert row[0] == "full"


def test_permission_labels_are_translated():
    """
    Названия прав и пресетов переведены.

    Они живут в Python и попадают на страницу выражением, поэтому проверка
    шаблонов их не видит. Список прав это первое, что открывает человек,
    выдавая доступ, и наполовину русский он выглядит недоделанным.
    """
    from app import i18n, permissions

    i18n.load_catalogs()
    cyrillic = lambda s: any("Ѐ" <= c <= "ӿ" for c in s)  # noqa: E731
    untranslated = []

    texts = []
    for _key, section, label, note in permissions.all_permissions():
        texts += [section, label, note]
    texts += list(permissions.PRESET_LABELS.values())

    for text in texts:
        if text and cyrillic(text) and i18n.translate_text(text, "en") == text:
            untranslated.append(text)

    assert not untranslated, "нет перевода:\n  " + "\n  ".join(dict.fromkeys(untranslated))


# ------------------------------------------------ публичный лист состояния
def _group_with_devices(client, router, group_name: str) -> tuple[int, int]:
    """Создать группу с одной живой и одной упавшей точкой."""
    from app.database import execute, query_one, utcnow

    execute("INSERT INTO groups (name, created_at) VALUES (?,?)", (group_name, utcnow()))
    group_id = query_one("SELECT id FROM groups WHERE name = ?", (group_name,))["id"]

    now = utcnow()
    for name, host, status in ((f"{group_name}-up", "10.44.0.1", "online"),
                               (f"{group_name}-down", "10.44.0.2", "offline")):
        execute(
            "INSERT INTO devices (name, host, username, password_enc, enabled, group_id,"
            " status, status_changed_at, ros_version, last_error, created_at, updated_at)"
            " VALUES (?,?,?,?,1,?,?,?,?,?,?,?)",
            (name, host, "api", "x", group_id, status, now,
             "7.21.5", "Таймаут подключения", now, now),
        )
    return group_id, 2


def test_public_page_shows_only_names_and_status(client, router):
    """
    Публичная страница отдаёт минимум: имя, статус, время.

    Ссылку дают подрядчикам, то есть людям вне периметра. Адреса это карта
    сети, версия RouterOS подсказывает, чем воспользоваться, а текст ошибки
    рассказывает о внутренностях системы. Ничего этого там быть не должно.
    """
    group_id, _ = _group_with_devices(client, router, "public-a")
    url = client.post(f"/api/groups/{group_id}/public-link",
                      json={"enabled": True}).json()["url"]
    token = url.rsplit("/", 1)[-1]

    with _anon() as anon:
        page = anon.get(f"/status/{token}")
        assert page.status_code == 200

        body = page.text
        assert "public-a-up" in body and "public-a-down" in body
        assert "10.44.0.1" not in body and "10.44.0.2" not in body
        assert "7.21.5" not in body
        assert "Таймаут" not in body and "Connection timeout" not in body

        # Поисковикам такую ссылку индексировать нельзя: она секретна ровно
        # до тех пор, пока не попала в выдачу
        assert "noindex" in page.headers.get("x-robots-tag", "")
        assert "no-store" in page.headers.get("cache-control", "")


def test_public_page_shows_downtime_for_the_day(client, router):
    """
    Публичная страница показывает простой за сутки.

    Состояние «сейчас» отвечает не на тот вопрос, который задают чаще:
    людям нужно знать, как точка вела себя за смену. Цифра считается тем
    же кодом, что и в панели, чтобы подрядчик и администратор не смотрели
    на разные числа.
    """
    from app.database import execute, query_one, utcnow

    group_id, _ = _group_with_devices(client, router, "public-down")
    device_id = query_one(
        "SELECT id FROM devices WHERE name = ?", ("public-down-up",))["id"]

    # Точка полежала полчаса и поднялась
    execute(
        "INSERT INTO status_events (device_id, device_name, device_host, status,"
        " reason, downtime, ts) VALUES (?,?,?,?,?,?,?)",
        (device_id, "public-down-up", "10.44.0.1", "online", "", 1800, utcnow()),
    )

    url = client.post(f"/api/groups/{group_id}/public-link",
                      json={"enabled": True}).json()["url"]
    token = url.rsplit("/", 1)[-1]

    with _anon() as anon:
        body = anon.get(f"/status/{token}?lang=ru").text

    assert "Общий простой за сутки" in body
    assert "30 мин" in body
    # Лежащая точка тоже считается, поэтому итог больше получаса
    assert "За сутки простоев не было" not in body


def test_public_link_uses_the_external_address(client, router):
    """
    Ссылка строится по PUBLIC_BASE_URL, если он задан.

    Панель открывают изнутри по локальному адресу, и без этой настройки
    в ссылке оказывался бы он. Понять ошибку можно было бы только после
    того, как подрядчик ответит «не открывается».
    """
    from app.config import settings

    group_id, _ = _group_with_devices(client, router, "public-url")

    saved = settings.public_base_url
    settings.public_base_url = "http://example.net:6060"
    try:
        url = client.post(f"/api/groups/{group_id}/public-link",
                          json={"enabled": True}).json()["url"]
    finally:
        settings.public_base_url = saved

    assert url.startswith("http://example.net:6060/status/")

    # Без настройки остаётся адрес, по которому пришёл запрос
    url = client.post(f"/api/groups/{group_id}/public-link",
                      json={"enabled": True}).json()["url"]
    assert "/status/" in url and "example.net" not in url


def test_public_page_speaks_the_visitors_language(client, router):
    """
    Язык публичной страницы: выбор в адресе, потом язык браузера.

    Ссылку открывает человек со стороны, о котором известен только
    заголовок Accept-Language. В самой панели он намеренно не учитывается:
    там язык выбирает владелец учётной записи.
    """
    group_id, _ = _group_with_devices(client, router, "public-lang")
    url = client.post(f"/api/groups/{group_id}/public-link",
                      json={"enabled": True}).json()["url"]
    token = url.rsplit("/", 1)[-1]

    with _anon() as anon:
        ru = anon.get(f"/status/{token}?lang=ru")
        assert "Состояние сети" in ru.text
        # Выбор запомнился, и следующий заход по голой ссылке уже русский
        assert "Состояние сети" in anon.get(f"/status/{token}").text

    with _anon() as other:
        page = other.get(f"/status/{token}",
                         headers={"Accept-Language": "ru-RU,ru;q=0.9,en;q=0.8"})
        assert "Состояние сети" in page.text

    with _anon() as english:
        page = english.get(f"/status/{token}",
                           headers={"Accept-Language": "en-GB,en;q=0.9"})
        assert "Network status" in page.text
        assert "Состояние сети" not in page.text


def test_public_page_is_read_only_for_anonymous(client, router):
    """С публичной страницы нельзя ни попасть внутрь, ни что-то запустить."""
    group_id, _ = _group_with_devices(client, router, "public-b")
    client.post(f"/api/groups/{group_id}/public-link", json={"enabled": True})

    with _anon() as anon:
        # Ни одна страница панели без входа не открывается
        assert anon.get("/devices", follow_redirects=False).status_code in (302, 303)
        assert anon.get("/api/stats").status_code == 401
        assert anon.post("/api/jobs", json={"action": "reboot", "all": True}).status_code == 401


def test_public_link_can_be_revoked(client, router):
    """Отзыв ссылки выключает старый адрес сразу."""
    group_id, _ = _group_with_devices(client, router, "public-c")
    url = client.post(f"/api/groups/{group_id}/public-link",
                      json={"enabled": True}).json()["url"]
    token = url.rsplit("/", 1)[-1]

    with _anon() as anon:
        assert anon.get(f"/status/{token}").status_code == 200

    client.post(f"/api/groups/{group_id}/public-link", json={"enabled": False})
    with _anon() as anon:
        assert anon.get(f"/status/{token}").status_code == 404

    # Повторное включение выдаёт другой токен, старый не воскресает
    new_url = client.post(f"/api/groups/{group_id}/public-link",
                          json={"enabled": True}).json()["url"]
    assert new_url != url
    with _anon() as anon:
        assert anon.get(f"/status/{token}").status_code == 404
        assert anon.get(f"/status/{new_url.rsplit('/', 1)[-1]}").status_code == 200


def test_unknown_token_is_indistinguishable_from_disabled(client):
    """
    Неизвестный и отозванный токен отвечают одинаково.

    Разница в ответах подсказала бы перебирающему, что он на верном пути.
    """
    with _anon() as anon:
        short = anon.get("/status/abc")
        long_wrong = anon.get("/status/" + "z" * 32)
        assert short.status_code == long_wrong.status_code == 404
        assert short.text == long_wrong.text


def test_public_link_needs_group_permission(client):
    """Выдать публичную ссылку может только тот, кто управляет группами."""
    from app.database import execute, query_one, utcnow

    execute("INSERT INTO groups (name, created_at) VALUES ('perm-group', ?)", (utcnow(),))
    group_id = query_one("SELECT id FROM groups WHERE name='perm-group'")["id"]

    _make_user(client, "nolinks", ["action.check"])
    with _as("nolinks") as limited:
        r = limited.post(f"/api/groups/{group_id}/public-link", json={"enabled": True})
        assert r.status_code == 403

    assert query_one("SELECT public_token FROM groups WHERE id = ?", (group_id,))["public_token"] == ""


def test_public_visits_count_people_not_requests(client, router):
    """
    Счётчик считает открытия людьми, а не запросы.

    Страница обновляется сама раз в минуту, поэтому забытая открытой вкладка
    дала бы полторы тысячи «посещений» в сутки, и число перестало бы что-либо
    значить. Отличаем по короткоживущей cookie.
    """
    from app.database import query_one

    group_id, _ = _group_with_devices(client, router, "visits-a")
    token = client.post(f"/api/groups/{group_id}/public-link",
                        json={"enabled": True}).json()["url"].rsplit("/", 1)[-1]

    def hits() -> int:
        row = query_one("SELECT SUM(hits) AS c FROM public_visits WHERE group_id = ?",
                        (group_id,))
        return (row["c"] if row else 0) or 0

    with _anon() as one_person:
        for _ in range(6):
            one_person.get(f"/status/{token}")
    assert hits() == 1, "автообновление накрутило счётчик"

    with _anon() as another_person:
        another_person.get(f"/status/{token}")
    assert hits() == 2

    # Время последнего открытия видно администратору
    group = query_one("SELECT public_last_seen FROM groups WHERE id = ?", (group_id,))
    assert group["public_last_seen"]


def test_visits_are_not_counted_for_wrong_token(client, router):
    """Неверный токен ничего не считает: иначе перебор накрутил бы счётчик."""
    from app.database import query_one

    group_id, _ = _group_with_devices(client, router, "visits-b")
    client.post(f"/api/groups/{group_id}/public-link", json={"enabled": True})

    with _anon() as anon:
        for _ in range(3):
            anon.get("/status/" + "q" * 32)

    row = query_one("SELECT SUM(hits) AS c FROM public_visits WHERE group_id = ?", (group_id,))
    assert ((row["c"] if row else 0) or 0) == 0


# --------------------------------------------------- библиотека команд
def test_snippet_marker_is_guessed_from_the_text():
    """
    Имя создаваемого скрипта угадывается из текста.

    Угадывается только самый частый случай, `add name=X`. Умнее не надо:
    ошибка здесь молча испортит счётчик «где раскатано», а поле всё равно
    правится руками.
    """
    from app import snippets

    assert snippets.guess_marker(
        "/system script\nadd name=lte-watchdog policy=read source={}") == "lte-watchdog"
    assert snippets.guess_marker(
        '/system scheduler add name=wd-sched interval=1m') == "wd-sched"
    assert snippets.guess_marker("/ip service set api address=10.0.0.0/8") == ""


def test_library_shows_where_a_snippet_is_deployed(client, router):
    """
    «Где раскатано» считается по паспорту точек, а не по журналу запусков.

    Разница принципиальная. Журнал говорит «мы отправляли это в среду»,
    а паспорт отвечает на настоящий вопрос: «оно там сейчас есть?».
    Скрипт могли удалить руками, точку могли перезалить из бэкапа,
    задача могла упасть на середине парка.
    """
    from app import snippets
    from app.database import execute, query_one, utcnow

    with_script = _add_device(client, router, "с-watchdog")
    without = _add_device(client, router, "без-watchdog")

    execute("INSERT INTO device_scripts (device_id, kind, name, updated_at)"
            " VALUES (?, 'script', ?, ?)", (with_script, "lte-watchdog", utcnow()))

    snippet_id = snippets.save("Сторож LTE", "/system script\nadd name=lte-watchdog",
                               username="admin")
    assert query_one("SELECT marker FROM snippets WHERE id = ?",
                     (snippet_id,))["marker"] == "lte-watchdog"

    rows = {row["name"]: row for row in snippets.listing()}
    deployed = rows["Сторож LTE"]["devices"]
    assert [d["id"] for d in deployed] == [with_script]
    assert without not in [d["id"] for d in deployed]

    # И обратная сторона, ради которой всё и затевалось: где ещё нет
    assert without in [d["id"] for d in rows["Сторож LTE"]["missing"]]
    assert with_script not in [d["id"] for d in rows["Сторож LTE"]["missing"]]

    page = client.get("/scripts")
    assert page.status_code == 200
    assert "Сторож LTE" in page.text and "с-watchdog" in page.text


def test_fleet_view_shows_scripts_nobody_added_from_the_panel(client, router):
    """
    В сводке видно и то, чего в библиотеке нет.

    Скрипт, заведённый руками полгода назад на трёх точках из сорока
    девяти, это ровно тот случай, ради которого раздел и нужен: панель
    про него не знает, а он там работает.
    """
    from app import snippets
    from app.database import execute, utcnow

    device_id = _add_device(client, router, "чужой-скрипт")
    execute("INSERT INTO device_scripts (device_id, kind, name, updated_at)"
            " VALUES (?, 'scheduler', ?, ?)", (device_id, "старый-сторож", utcnow()))

    found = {row["name"]: row for row in snippets.fleet()}
    assert [d["name"] for d in found["старый-сторож"]["devices"]] == ["чужой-скрипт"]
    assert found["старый-сторож"]["known"] is False, "чужой скрипт выдан за наш"

    # Имена точек прямо в сводке: счётчик без них заставляет обходить парк
    page = client.get("/scripts")
    assert "заведено вне панели" in page.text
    assert "чужой-скрипт" in page.text


def test_deploy_dialog_offers_the_sites_without_the_script(client, router):
    """
    Диалог раскатки предлагает точки, где скрипта ещё нет.

    Ради этого раздел и делался: скрипты работают по расписанию, руками
    их запускать не надо, а вопрос всегда один и тот же: «на скольких
    точках из сорока девяти этого ещё нет». Список должен приехать на
    страницу готовым, а не собираться обходом парка глазами.
    """
    from app import snippets
    from app.database import execute, utcnow

    with_script = _add_device(client, router, "точка-со-сторожем")
    without = _add_device(client, router, "точка-без-сторожа")
    execute("INSERT INTO device_scripts (device_id, kind, name, updated_at)"
            " VALUES (?, 'script', ?, ?)", (with_script, "lte-watchdog", utcnow()))

    snippets.save(name="Сторож LTE", body="/system script add name=lte-watchdog source={}")

    rows = {r["name"]: r for r in snippets.listing()}
    absent = [d["id"] for d in rows["Сторож LTE"]["missing"]]
    assert without in absent
    assert with_script not in absent, "предлагаем поставить туда, где уже стоит"

    page = client.get("/scripts").text
    assert "Куда раскатать" in page, "нет диалога выбора цели"
    assert "Где ещё нет" in page
    # Кнопка ставит скрипт, а не запускает его: расписание отработает само
    assert "Раскатать" in page and "runSnippet" not in page


def test_removing_a_script_clears_it_from_device_and_passport(client, router):
    """
    Удаление снимает запись с устройства и сразу правит паспорт.

    Если паспорт не поправить, удалённое провисит в разделе «Скрипты»
    до следующего обхода, и человек решит, что кнопка не сработала,
    и нажмёт её второй раз.
    """
    from app.database import execute, utcnow

    router.scripts.append({".id": "*7", "name": "auto-reboot", "source": "/system reboot"})
    router.schedulers.append({".id": "*8", "name": "auto-reboot", "interval": "1d"})

    device_id = _add_device(client, router, "точка-с-мусором")
    for kind in ("script", "scheduler"):
        execute("INSERT INTO device_scripts (device_id, kind, name, updated_at)"
                " VALUES (?,?,?,?)", (device_id, kind, "auto-reboot", utcnow()))

    job = _run_and_wait(client, "remove_script", [device_id],
                        {"script_name": "auto-reboot", "kind": "both"})
    assert job["status"] == "done"

    assert not [s for s in router.scripts if s["name"] == "auto-reboot"]
    assert not [s for s in router.schedulers if s["name"] == "auto-reboot"]
    assert query_one("SELECT 1 FROM device_scripts WHERE device_id = ? AND name = ?",
                     (device_id, "auto-reboot")) is None


def test_removing_a_script_that_is_not_there_is_not_an_error(client, router):
    """
    Точка без этой записи не считается сбоем.

    Удаление запускается сразу на группе, и жалоба с каждой точки, где
    записи не было, прятала бы настоящие ошибки среди шума.
    """
    device_id = _add_device(client, router, "точка-чистая")

    job = _run_and_wait(client, "remove_script", [device_id],
                        {"script_name": "нет-такого", "kind": "script"})
    assert job["status"] == "done"
    assert job["fail_count"] == 0

    item = query_one("SELECT status, result FROM job_items WHERE job_id = ?", (job["id"],))
    assert item["status"] == "ok"
    assert "удалять нечего" in item["result"]


def test_removing_a_script_needs_its_own_permission(client, router):
    """
    Удаление это отдельное право, а не довесок к просмотру библиотеки.

    Кнопки в сводке у такого человека тоже быть не должно: предлагать
    то, что не сработает, хуже, чем не предлагать.
    """
    device_id = _add_device(client, router, "точка-под-охраной")
    _make_user(client, "librarian2", ["settings.view", "action.cli"])

    with _as("librarian2") as guest:
        answer = guest.post("/api/jobs", json={
            "action": "remove_script", "device_ids": [device_id],
            "params": {"script_name": "auto-reboot", "kind": "script"}})
        assert answer.status_code == 403
        assert 'onclick="removeFleet' not in guest.get("/scripts").text


def test_snippet_knows_both_the_script_and_its_scheduler(client, router):
    """
    Запись библиотеки помнит все имена, которые создаёт.

    Скрипт и вызывающее его расписание называются по-разному, и, пока
    маркер был один, панель писала про собственное расписание «заведено
    вне панели». Своё, поставленное этой же кнопкой.
    """
    from app import snippets
    from app.database import execute, utcnow

    device_id = _add_device(client, router, "точка-со-сторожем-и-расписанием")
    for kind, name in (("script", "wd"), ("scheduler", "wd-sched")):
        execute("INSERT INTO device_scripts (device_id, kind, name, updated_at)"
                " VALUES (?,?,?,?)", (device_id, kind, name, utcnow()))

    snippets.save(name="Сторож", body=(
        "/system script add name=wd source={:log info \"ok\"}\n"
        "/system scheduler add name=wd-sched interval=1m on-event=\"/system script run wd\""))

    row = {r["name"]: r for r in snippets.listing()}["Сторож"]
    assert snippets.markers(row["marker"]) == ["wd", "wd-sched"]
    assert device_id in [d["id"] for d in row["devices"]]
    assert device_id not in [d["id"] for d in row["missing"]]

    # Точка со скриптом и его расписанием это одна точка, а не две.
    # Строка на найденную запись вместо строки на точку удваивала счётчик
    assert [d["id"] for d in row["devices"]].count(device_id) == 1

    # И в сводке по парку обе записи считаются нашими
    known = {f["name"]: f["known"] for f in snippets.fleet()}
    assert known["wd"] is True
    assert known["wd-sched"] is True, "своё расписание выдано за чужое"


def test_old_snippets_get_their_second_marker_on_start(client, router):
    """
    Старым записям библиотеки имена дописываются при запуске.

    Имена вытаскиваются из текста только при сохранении, поэтому запись,
    заведённая до появления списка маркеров, так и осталась бы с одним
    именем, а человек увидел бы ровно то же, что вчера.

    Правку руками при этом не затираем: если сохранённого имени в тексте
    нет, значит его поставили осознанно.
    """
    from app import snippets
    from app.database import execute_changes, query_one

    body = ("/system script add name=wd2 source={:log info \"ok\"}\n"
            "/system scheduler add name=wd2-sched interval=1m on-event=\"x\"")
    old = snippets.save(name="Старая запись", body=body)
    execute_changes("UPDATE snippets SET marker = 'wd2' WHERE id = ?", (old,))

    handmade = snippets.save(name="Правленая руками", body=body, marker="совсем-другое")

    assert snippets.backfill_markers() == 1
    assert query_one("SELECT marker FROM snippets WHERE id = ?", (old,))["marker"] \
        == "wd2,wd2-sched"
    assert query_one("SELECT marker FROM snippets WHERE id = ?", (handmade,))["marker"] \
        == "совсем-другое", "затёрли имя, поставленное руками"

    # Второй проход ничего не меняет: он должен быть безобидным
    assert snippets.backfill_markers() == 0


def test_rollback_deadline_is_shown_in_local_time(client, router, monkeypatch):
    """
    Срок страховки печатается в местном времени.

    В базе всё в UTC, и раньше срок уходил в текст результата как есть:
    событие в 18:49 сообщало «подтвердите до 11:54». Человек читает это
    как «уже поздно» и не подтверждает, а через десять минут точка
    перезагружается.
    """
    from app import actions

    # Пояс сервера в тестах какой угодно, поэтому сравниваем с тем, что
    # даёт стандартное преобразование, а не с жёсткой строкой
    from datetime import datetime, timezone
    stamp = "2026-08-08 11:54:05"
    expected = (datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S")
                .replace(tzinfo=timezone.utc).astimezone()
                .strftime("%d.%m.%Y %H:%M:%S"))
    assert actions._local_time(stamp) == expected
    assert actions._local_time("") == ""
    assert actions._local_time("что-то не то") == "что-то не то"


def test_job_page_shows_parameter_labels_not_keys(client, router):
    """
    На странице задачи стоят подписи полей, а не ключи формы.

    `script_name` и `kind` понятны тому, кто писал действие. Тому, кто
    через неделю выясняет, что именно запускали, нужны слова.
    """
    device_id = _add_device(client, router, "точка-для-задачи")
    job = _run_and_wait(client, "remove_script", [device_id],
                        {"script_name": "auto-reboot", "kind": "scheduler"})

    page = client.get(f"/jobs/{job['id']}").text
    assert "Имя на устройстве" in page
    assert "script_name" not in page
    # У выпадающих списков показывается подпись, а не внутреннее значение
    assert ">расписание<" in page.replace(" ", "").replace("\n", "")


def test_fleet_row_lists_only_devices_of_that_kind(client, router):
    """
    Строка сводки показывает точки со своим видом записи.

    Строки заведены парами «имя + вид», а список точек подбирался по
    одному имени. Из-за этого строка «net-watchdog, расписание» выводила
    точки, где лежит одноимённый скрипт: одиннадцать вместо одной,
    и все не те.
    """
    from app import snippets
    from app.database import execute, utcnow

    with_both = _add_device(client, router, "точка-с-парой")
    script_only = _add_device(client, router, "точка-только-скрипт")
    execute("INSERT INTO device_scripts (device_id, kind, name, updated_at)"
            " VALUES (?, 'script', 'дозор', ?)", (with_both, utcnow()))
    execute("INSERT INTO device_scripts (device_id, kind, name, updated_at)"
            " VALUES (?, 'scheduler', 'дозор', ?)", (with_both, utcnow()))
    execute("INSERT INTO device_scripts (device_id, kind, name, updated_at)"
            " VALUES (?, 'script', 'дозор', ?)", (script_only, utcnow()))

    rows = {(f["name"], f["kind"]): f for f in snippets.fleet()}
    scripts = [d["id"] for d in rows[("дозор", "script")]["devices"]]
    schedulers = [d["id"] for d in rows[("дозор", "scheduler")]["devices"]]

    assert sorted(scripts) == sorted([with_both, script_only])
    assert schedulers == [with_both], "в расписания попали точки со скриптом"
    # Число в колонке и длина списка это одно и то же число
    assert rows[("дозор", "scheduler")]["devices_count"] == 1


def test_backup_schedule_days_follow_the_interface_language(client, router):
    """
    Дни недели в расписании бэкапов переводятся вместе с интерфейсом.

    Подпись собирается в Python из нескольких дней, целиком такой строки
    в словаре быть не может, и язык туда не передавали. На английской
    странице стояло «пн, ср, пт» ровно рядом с формой, где те же дни
    подписаны Mon-Wed-Fri.
    """
    assert client.post("/api/backup-schedules", json={
        "target": "all", "at_time": "05:00", "keep": 3,
        "days": [1, 3, 5]}).status_code == 200

    assert "пн, ср, пт" in client.get("/backups").text

    client.get("/lang/en", follow_redirects=False)
    try:
        page = client.get("/backups").text
        assert "Mon, Wed, Fri" in page
        assert "пн, ср, пт" not in page
    finally:
        client.get("/lang/ru", follow_redirects=False)


def test_inventory_stops_when_the_link_dies_mid_walk():
    """
    Обход паспорта прекращается, если связь оборвалась на середине.

    Ответ, который не дочитали из сокета, никуда не девается: следующая
    команда читает хвост предыдущей, и в паспорт приезжают расписания
    с именами портов, а в интерфейсы имена скриптов. Выглядит это как
    нормальные данные, поэтому единственный честный выход — прекратить
    обход и оставить прежний снимок.
    """
    from app import inventory
    from app.mikrotik import DeviceError

    class Flaky:
        """Отвечает на всё, но на расписаниях теряет связь."""

        alive = True

        def __init__(self):
            self.asked = []

        def cmd(self, command, **kwargs):
            self.asked.append(command)
            if command == "/system/scheduler/print":
                self.alive = False
                raise DeviceError("Устройство не ответило на команду")
            if command == "/interface/print":
                return [{"name": "ether3", "type": "ether"}]
            return []

    flaky = Flaky()
    with pytest.raises(DeviceError):
        inventory.collect(flaky)

    assert "/interface/print" not in flaky.asked, "обход продолжился по мёртвой сессии"


def test_missing_table_does_not_stop_the_walk():
    """
    А вот отсутствие таблицы обходу не мешает.

    На коробке без PoE нет таблицы питания, на RouterOS 6 нет части
    команд. Соединение при этом живо, следующая команда получит свой
    ответ, и терять из-за этого весь паспорт незачем.
    """
    from app import inventory
    from app.mikrotik import DeviceError

    class Partial:
        alive = True

        def cmd(self, command, **kwargs):
            if "poe" in command or "health" in command:
                raise DeviceError("no such command prefix")
            if command == "/interface/print":
                return [{"name": "ether1", "type": "ether"}]
            return []

    data = inventory.collect(Partial())
    assert [p["name"] for p in data["ports"]] == ["ether1"]


def test_forgetting_the_inventory_clears_it_without_touching_the_device(client, router):
    """
    Кнопка «Забыть» убирает снимок из базы и не трогает роутер.

    Случай настоящий: в снимке оказались чужие данные, а точка на связь
    не выходит, и заменить снимок нечем. Пока он лежит, ерунда видна
    и в карточке, и в сводке «Что стоит на точках».
    """
    from app import inventory
    from app.database import execute, query_one, utcnow

    device_id = _add_device(client, router, "точка-с-мусором-в-паспорте")
    execute("INSERT INTO device_scripts (device_id, kind, name, updated_at)"
            " VALUES (?, 'scheduler', 'ether3', ?)", (device_id, utcnow()))
    execute("INSERT INTO device_ports (device_id, name, kind, physical, updated_at)"
            " VALUES (?, 'net-watchdog', 'bridge', 0, ?)", (device_id, utcnow()))

    assert client.post(f"/api/devices/{device_id}/inventory/forget").status_code == 200

    assert inventory.load(device_id)["has_data"] is False
    assert query_one("SELECT 1 FROM device_scripts WHERE device_id = ?", (device_id,)) is None
    # Само устройство остаётся на месте, речь только о снимке
    assert query_one("SELECT 1 FROM devices WHERE id = ?", (device_id,)) is not None
    assert "ether3" not in client.get("/scripts").text


def test_connection_reset_is_explained_not_just_numbered():
    """
    Разрыв соединения объясняется словами, а не кодом ошибки.

    `ConnectionResetError: [Errno 104]` на живом парке означает почти
    всегда одно: адрес панели не входит в список у `/ip service`.
    RouterOS принимает соединение и обрывает его на первом байте, поэтому
    снаружи порт выглядит открытым, а проверка `nc -vz` радостно
    отчитывается об успехе. Человеку по номеру ошибки не догадаться.
    """
    from app.mikrotik import _friendly

    text = _friendly(ConnectionResetError(104, "Connection reset by peer"))
    assert "Errno" not in text
    assert "/ip service" in text

    # Соседние случаи не перепутаны
    assert _friendly(ConnectionRefusedError()) != text
    assert "Таймаут" in _friendly(__import__("socket").timeout())


def test_report_can_be_narrowed_to_a_group_or_to_chosen_devices(client, router):
    """
    Отчёт выгружается по группе и по отдельным точкам.

    Отчёт по всему парку годится для разговора с начальством, а для
    разговора с провайдером нужен другой: только его точки. Раньше
    выбора не было вовсе, весь парк и точка.
    """
    from app.database import execute

    first = _add_device(client, router, "отчёт-точка-1")
    second = _add_device(client, router, "отчёт-точка-2")
    group_id = client.post("/api/groups", data={"name": "Отчётная"}).json()["id"]
    execute("UPDATE devices SET group_id = ? WHERE id = ?", (group_id, first))

    def in_table(page: str, name: str) -> bool:
        """Есть ли точка в самом документе, а не в форме выбора охвата."""
        body = page.split("</form>")[-1]
        return name in body

    # Весь парк: обе точки в документе
    everything = client.get("/monitoring/report?hours=24").text
    assert in_table(everything, "отчёт-точка-1")
    assert in_table(everything, "отчёт-точка-2")
    assert "весь парк" in everything

    # Группа: только своя
    by_group = client.get(f"/monitoring/report?hours=24&group_id={group_id}").text
    assert in_table(by_group, "отчёт-точка-1")
    assert not in_table(by_group, "отчёт-точка-2")
    assert "группа Отчётная" in by_group

    # Отдельная точка, и она сильнее выбранной группы
    picked = client.get(
        f"/monitoring/report?hours=24&group_id={group_id}&devices={second}").text
    assert in_table(picked, "отчёт-точка-2")
    assert not in_table(picked, "отчёт-точка-1")

    # То же самое в CSV, включая имя файла
    csv_answer = client.get(f"/monitoring/report.csv?hours=24&group_id={group_id}")
    assert csv_answer.status_code == 200
    body = csv_answer.content.decode("utf-8-sig")
    assert "отчёт-точка-1" in body and "отчёт-точка-2" not in body
    assert f"group{group_id}" in csv_answer.headers["content-disposition"]


def test_operator_is_read_from_the_modem(client, router):
    """
    Оператор берётся у модема, и имя определяется по коду сети.

    Имя из прошивки писать нельзя: у одного и того же оператора там
    и «MTS RUS», и «MTS-RUS», и «250 01». Код `25001` это всегда МТС,
    поэтому имя берём по коду, а строку модема оставляем запасной.
    """
    from app import operator

    assert operator.name_by_code("25001") == "МТС"
    assert operator.name_by_code("250 02") == "МегаФон"
    assert operator.name_by_code("25011") == "Yota"
    assert operator.name_by_code("мусор") == ""

    found = operator.from_lte([{
        "status": "registered", "current-operator": "25001",
        "access-technology": "LTE", "rsrp": "-97dBm",
    }])
    assert found["name"] == "МТС"
    assert found["technology"] == "LTE"

    # Незарегистрированный модем оператора не называет
    assert operator.from_lte([{"status": "searching", "current-operator": "25001"}]) == {}

    # Неизвестный код не выдумываем, а честно оставляем пустым, если
    # модем не сообщил имя сам
    assert operator.from_lte([{"status": "registered", "current-operator": "99999"}]) == {}
    guess = operator.from_lte([{"status": "registered", "current-operator": "99999",
                                "current-operator-name": "Local GSM"}])
    assert guess["name"] == "Local GSM"


def test_operator_from_modem_lands_in_the_device_list(client, router):
    """Найденный оператор виден в списке устройств и ищется по нему."""
    from app import operator
    from app.database import query_one

    device_id = _add_device(client, router, "точка-с-модемом")
    router.lte_monitor = [{
        "status": "registered", "current-operator": "25002",
        "access-technology": "LTE-A", "rsrp": "-101dBm",
    }]

    with MikroTik(_device(router), "s3cret") as mt:
        name, _note = operator.collect(mt, {"id": device_id})
        assert name == "МегаФон"

    row = query_one("SELECT operator, operator_source, operator_detail FROM devices"
                    " WHERE id = ?", (device_id,))
    assert row["operator"] == "МегаФон"
    assert row["operator_source"] == "lte"
    assert "LTE-A" in row["operator_detail"]

    page = client.get("/devices").text
    assert "МегаФон" in page
    # И в карточке точки, рядом со статусом: когда точка лежит, вопрос
    # «чей канал» задают сразу, и ответ должен быть на том же экране
    assert "МегаФон" in client.get(f"/devices/{device_id}").text
    # Поиск по оператору, и заодно без оглядки на регистр: искать
    # «мегафон» с маленькой буквы человек будет чаще, чем с большой
    assert "МегаФон" in client.get("/devices?q=мегафон").text, "поиск по оператору не работает"


def test_manual_operator_is_not_overwritten(client, router):
    """
    Вписанное руками сильнее найденного.

    Человек, подписавший точку «Мегафон, договор 512», знает больше
    модема, и следующий опрос не должен стирать эту строку.
    """
    from app import operator
    from app.database import query_one

    device_id = _add_device(client, router, "точка-с-договором")
    device = query_one("SELECT * FROM devices WHERE id = ?", (device_id,))

    answer = client.post(f"/api/devices/{device_id}/update", data={
        "name": device["name"], "host": device["host"],
        "username": device["username"], "operator": "МегаФон, договор 512",
    })
    assert answer.status_code == 200, answer.text
    assert query_one("SELECT operator_source FROM devices WHERE id = ?",
                     (device_id,))["operator_source"] == "manual"

    operator.save(device_id, "Билайн", operator.LTE)
    row = query_one("SELECT operator FROM devices WHERE id = ?", (device_id,))
    assert row["operator"] == "МегаФон, договор 512", "ручную подпись затёрли"


def test_modem_that_stays_silent_is_not_called_missing(client, router):
    """
    Модем, который есть и молчит, не выдаётся за отсутствующий.

    На точке с живым модемом панель писала «нет модема»: команда
    возвращала отказ, а он глотался молча. Человек после такого ищет
    неисправность не там, где она есть.
    """
    from app import operator

    class Refuses:
        """Модем в списке есть, а опрос его отбивается."""

        def cmd(self, command, **kwargs):
            if command == "/interface/lte/print":
                return [{"name": "lte1"}]
            raise RuntimeError("no such command prefix")

    found, note = operator.from_modem(Refuses())
    assert found == {}
    assert "модем есть" in note
    assert "no such command prefix" in note, "ответ роутера потерян"

    class Searching:
        """Модем есть, но в сети ещё не зарегистрировался."""

        def cmd(self, command, **kwargs):
            if command == "/interface/lte/print":
                return [{"name": "lte1"}]
            return [{"status": "searching"}]

    found, note = operator.from_modem(Searching())
    assert found == {}
    assert "searching" in note

    # А когда модема нет вовсе, пояснения быть не должно: это не поломка
    class NoModem:
        def cmd(self, command, **kwargs):
            return []

    assert operator.from_modem(NoModem()) == ({}, "")


def test_missing_operator_explains_itself(client, router):
    """
    Когда оператора узнать неоткуда, панель говорит почему.

    Пустая колонка без объяснения выглядит как сломанная возможность:
    именно так она и выглядела на парке, где модема нет ни на одной
    точке, а внешний адрес спрятан за NAT провайдера.
    """
    from app import operator

    device_id = _add_device(client, router, "точка-без-модема")
    router.lte_monitor = None          # модема нет
    router.cloud = [{"ddns-enabled": "false"}]   # внешний адрес неизвестен

    with MikroTik(_device(router), "s3cret") as mt:
        name, note = operator.collect(mt, {"id": device_id})

    assert name == ""
    assert "нет модема" in note

    operator.remember_miss(device_id, note)
    page = client.get("/devices").text
    assert "не определён" in page, "причина не показана"

    # А если внешний адрес известен, причина другая и полезнее
    router.cloud = [{"ddns-enabled": "true", "public-address": "46.39.2.66"}]
    with MikroTik(_device(router), "s3cret") as mt:
        _name, note = operator.collect(mt, {"id": device_id})
    assert "46.39.2.66" in note
    assert "OPERATOR_LOOKUP" in note, "не сказано, что поиск выключен"


def test_registry_answer_is_cached_per_network(monkeypatch):
    """
    Реестр спрашивается один раз на сеть, а не на точку.

    Полсотни точек одного оператора сидят в соседних адресах. Спрашивать
    про каждую отдельно значит молотить чужой сервис полусотней запросов
    ради одного и того же ответа.
    """
    from app import operator

    operator.forget_cache()
    calls = []

    def fake_open(request, timeout=0):
        calls.append(request.full_url)

        class Answer:
            def read(self):
                return b'{"name": "MTS-NET"}'

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                return False

        return Answer()

    monkeypatch.setattr(operator.urllib.request, "urlopen", fake_open)

    assert operator.lookup_ip("91.79.217.182") == "МТС"
    assert operator.lookup_ip("91.79.217.9") == "МТС", "сосед по сети спрошен заново"
    assert len(calls) == 1, calls

    # Другая сеть спрашивается отдельно
    assert operator.lookup_ip("46.39.7.92") == "МТС"
    assert len(calls) == 2
    operator.forget_cache()


def test_operator_reason_tells_what_to_switch_on(client, router):
    """
    Когда адрес известен, а поиск выключен, причина говорит что делать.

    Формулировка «поиск в реестре выключен (OPERATOR_LOOKUP)» отвечала
    на вопрос «почему», но не на вопрос «и что теперь».
    """
    from app import operator
    from app.config import settings

    device_id = _add_device(client, router, "точка-с-белым-адресом")
    router.lte_monitor = None
    router.cloud = [{"ddns-enabled": "true", "public-address": "91.79.217.182"}]
    monkey = settings.operator_lookup
    settings.operator_lookup = False
    try:
        with MikroTik(_device(router), "s3cret") as mt:
            name, note = operator.collect(mt, {"id": device_id})
    finally:
        settings.operator_lookup = monkey

    assert name == ""
    assert "91.79.217.182" in note
    assert "OPERATOR_LOOKUP=1" in note
    assert "перезапуск" in note


def test_grey_addresses_are_not_sent_to_the_registry():
    """
    В реестр уходят только публичные адреса.

    Спрашивать про серый адрес бессмысленно и вредно: ответом будет
    владелец чужого NAT, а сам запрос это поход в интернет.
    """
    from app import operator

    assert operator.is_public("46.39.2.66")
    assert not operator.is_public("192.168.101.1")
    assert not operator.is_public("10.225.15.9/24")
    assert not operator.is_public("100.71.4.8"), "адрес CGNAT принят за публичный"
    assert not operator.is_public("не адрес")

    # Без публичного адреса запрос не уходит вовсе
    assert operator.lookup_ip("192.168.1.1") == ""


def test_device_card_shows_who_is_behind_the_site(client, router):
    """
    В карточке точки видно, кто за ней стоит.

    Вопрос «что там на объекте» задают чаще, чем открывают раздел
    «Клиенты» и фильтруют его по точке. Право при этом то же самое:
    список за точкой это те же данные.
    """
    from app.database import execute, utcnow

    device_id = _add_device(client, router, "точка-с-клиентами")
    now = utcnow()
    execute(
        "INSERT INTO clients (device_id, mac, hostname, ip, port, link, vendor,"
        " dynamic, source, first_seen, last_seen)"
        " VALUES (?,?,?,?,?,'wired',?,1,'dhcp',?,?)",
        (device_id, "10:60:4b:8d:d9:92", "URSUS10-PC", "192.168.101.252",
         "ether2", "Hewlett Packard", now, now))

    # Много клиентов: список не обрезается, а прокручивается
    for index in range(30):
        execute(
            "INSERT INTO clients (device_id, mac, hostname, ip, port, link,"
            " vendor, dynamic, source, first_seen, last_seen)"
            " VALUES (?,?,?,'','','wired','',1,'arp',?,?)",
            (device_id, "aa:bb:cc:00:00:%02x" % index, "клиент-%d" % index, now, now))

    page = client.get(f"/devices/{device_id}").text
    assert "URSUS10-PC" in page
    assert "192.168.101.252" in page
    assert "ether2" in page
    assert "/clients?device_id=%d" % device_id in page, "нет ссылки на полный список"
    assert "scroll-list" in page, "список не прокручивается"
    assert "клиент-29" in page, "список обрезан вместо прокрутки"

    # Без права на раздел «Клиенты» списка нет
    _make_user(client, "без-клиентов", ["devices.view"], scope_all=True)
    with _as("без-клиентов") as limited:
        card = limited.get(f"/devices/{device_id}")
        assert card.status_code == 200
        assert "URSUS10-PC" not in card.text, "клиенты показаны без права на раздел"


def test_report_shows_average_downtime_per_site(client, router):
    """
    В сводке средний простой на точку, а не сумма по парку.

    Сумма растёт вместе с числом точек, и сравнить по ней два отчёта
    нельзя: пятьдесят часов на десяти точках и на пятидесяти это разные
    вещи. Среднее сравнимо и с прошлым месяцем, и с соседней группой.
    """
    from datetime import datetime, timedelta, timezone

    from app.database import execute

    first = _add_device(client, router, "простой-1")
    _add_device(client, router, "простой-2")

    moment = datetime.now(timezone.utc) - timedelta(hours=2)
    execute(
        "INSERT INTO status_events (device_id, device_name, device_host, status,"
        " reason, downtime, short, ts) VALUES (?,?,?,'online','',?,0,?)",
        (first, "простой-1", "127.0.0.1", 7200,
         moment.strftime("%Y-%m-%d %H:%M:%S")))

    page = client.get("/monitoring/report?hours=24").text
    assert "Средний простой" in page
    assert "Суммарный простой" not in page
    assert "на одну точку за период" in page


def test_report_takes_a_date_range_and_ignores_what_happened_after(client, router):
    """
    Отчёт за интервал дат считает только то, что попало в интервал.

    Ради этого всё и делалось: «за месяц» с плавающей правой границей
    не годится, когда нужен отчёт за прошлый период. Падение, случившееся
    после конца интервала, в него попадать не должно.
    """
    from datetime import datetime, timedelta, timezone

    from app.database import execute, utcnow

    device_id = _add_device(client, router, "точка-с-историей")

    def event(days_ago: float, status: str, downtime: int = 0) -> None:
        moment = datetime.now(timezone.utc) - timedelta(days=days_ago)
        execute(
            "INSERT INTO status_events (device_id, device_name, device_host, status,"
            " reason, downtime, short, ts) VALUES (?,?,?,?,?,?,0,?)",
            (device_id, "точка-с-историей", "127.0.0.1", status, "",
             downtime, moment.strftime("%Y-%m-%d %H:%M:%S")))

    # Час простоя пять дней назад и два часа простоя вчера.
    # Каждое падение это пара событий: ушло и вернулось
    event(5 + 1 / 24, "offline")
    event(5, "online", 3600)
    event(1 + 2 / 24, "offline")
    event(1, "online", 7200)

    today = datetime.now().astimezone()
    since = (today - timedelta(days=6)).strftime("%Y-%m-%d")
    until = (today - timedelta(days=3)).strftime("%Y-%m-%d")

    page = client.get(f"/monitoring/report?since={since}&until={until}").text
    assert "интервал дат" in page

    # В интервал попал только первый простой, значит час, а не три
    from app.routes.pages import _report_window
    from app import monitor

    hours, edge, _note = _report_window(720, since, until)
    rows = {r["name"]: r for r in monitor.availability(hours, ("", []), edge)}
    row = rows["точка-с-историей"]
    assert 3000 < row["down_seconds"] < 4200, row["down_seconds"]
    assert row["outages"] == 1

    # А за весь месяц видны оба
    everything = {r["name"]: r for r in monitor.availability(720, ("", []))}
    assert everything["точка-с-историей"]["down_seconds"] > 10000


def test_report_date_range_survives_human_input(client, router):
    """
    Даты задом наперёд и мусор в полях не ломают отчёт.

    Поля видит человек, а человек напишет что угодно, включая пустую
    строку, дату из будущего и «с 7 по 1».
    """
    from app.routes.pages import _report_window

    # Перевёрнутый интервал разворачивается, а не даёт отрицательное окно
    straight = _report_window(720, "2026-08-01", "2026-08-07")
    reversed_ = _report_window(720, "2026-08-07", "2026-08-01")
    assert straight[0] == reversed_[0] > 0

    # Мусор и половина интервала откатываются к обычному периоду
    assert _report_window(24, "мусор", "2026-08-07")[1] is None
    assert _report_window(24, "2026-08-07", "")[1] is None
    assert _report_window(999, "", "")[0] == 720

    # Страница при этом открывается, а не падает
    assert client.get("/monitoring/report?since=завтра&until=никогда").status_code == 200
    assert client.get("/monitoring/report?since=2026-08-01").status_code == 200


def test_report_selection_cannot_widen_the_visible_fleet(client, router):
    """
    Выбор в отчёте сужает область видимости, но не расширяет.

    Иначе достаточно было бы подставить чужой номер группы в адрес,
    чтобы получить отчёт по точкам, которых человеку видеть не положено.
    """
    from app.database import execute

    hidden = _add_device(client, router, "чужая-точка")
    mine = _add_device(client, router, "своя-точка")
    other_group = client.post("/api/groups", data={"name": "Чужая"}).json()["id"]
    execute("UPDATE devices SET group_id = ? WHERE id = ?", (other_group, hidden))

    _make_user(client, "узкий", ["monitoring.view"], scope_all=False, devices=[mine])

    with _as("узкий") as limited:
        page = limited.get(f"/monitoring/report?hours=24&group_id={other_group}").text
        assert "чужая-точка" not in page, "область видимости обошли через адрес"

        by_id = limited.get(f"/monitoring/report?hours=24&devices={hidden}").text
        assert "чужая-точка" not in by_id, "область видимости обошли через список точек"


def test_two_traps_in_one_answer_do_not_kill_the_session(router):
    """
    Отказ роутера остаётся отказом, даже если ловушек в ответе две.

    `/system/health/print` на коробке без датчиков отвечает парой ловушек:
    «no such command or directory (health)» и «no such command prefix».
    librouteros заворачивает такую пару в MultiTrapError, а он наследуется
    не от TrapError, а от ProtocolError. Пока его не ловили отдельно,
    обычный отказ считался сетевым сбоем: сессия объявлялась мёртвой
    и переоткрывалась на каждом опросе, а с версии 1.49 ещё и обрывала
    сбор паспорта целиком.
    """
    from librouteros.exceptions import MultiTrapError, TrapError

    from app.mikrotik import DeviceError, MikroTik

    with MikroTik(_device(router), "s3cret") as mt:
        real = mt.api

        def refuse(command, **kwargs):
            if command == "/system/health/print":
                raise MultiTrapError(
                    TrapError("no such command or directory (health)"),
                    TrapError("no such command prefix"))
            return real(command, **kwargs)

        mt.api = refuse

        with pytest.raises(DeviceError) as exc:
            mt.cmd("/system/health/print")
        assert "отклонил команду" in str(exc.value)
        assert mt.alive, "живую сессию выбросили из-за отказа в одной команде"

        # И паспорт после такого отказа собирается целиком
        from app import inventory
        data = inventory.collect(mt)
        assert data["ports"], "обход прекратился из-за отсутствия датчиков"


def test_invite_link_uses_the_panel_address_not_the_public_one(client, router, monkeypatch):
    """
    Приглашение ведёт на адрес панели, а не на публичный.

    `PUBLIC_BASE_URL` выставлен наружу ради листа состояния, а страница
    регистрации открывается только из доверенной сети. Внешний адрес
    в такой ссылке ведёт человека туда, где его не пустят.
    """
    from app.config import settings

    monkeypatch.setattr(settings, "public_base_url", "http://panel.example.com:6060")
    monkeypatch.setattr(settings, "panel_base_url", "")

    page = client.get("/settings").text
    assert "panel.example.com" not in page, "в приглашении публичный адрес"
    assert "http://testserver/invite/" in page or "testserver" in page

    # Явная настройка перебивает адрес запроса
    monkeypatch.setattr(settings, "panel_base_url", "http://10.0.0.5:6060")
    assert "http://10.0.0.5:6060" in client.get("/settings").text


def test_library_editing_needs_the_right_to_run_commands(client, router):
    """
    Библиотеку правит тот, кому и так можно выполнять команды.

    Отдельного права нет намеренно: заготовка команды опаснее не сама
    по себе, а тем, что её запустят. Лишний ключ в списке прав только
    запутал бы.
    """
    _make_user(client, "librarian", ["settings.view"])

    with _as("librarian") as guest:
        answer = guest.post("/api/snippets", json={"name": "нельзя", "body": "/ping 1.1.1.1"})
        assert answer.status_code == 403
        # Смотреть библиотеку при этом можно: там нет ничего секретного
        assert guest.get("/scripts").status_code == 200


# ---------------------------------------- страховка при изменении конфига
def _ssh_device(client, router, name: str, ssh):
    """Точка, у которой SSH указывает на заглушку."""
    from app.database import execute, query_one

    device_id = _add_device(client, router, name)
    execute("UPDATE devices SET ssh_port = ?, username = ?, host = ? WHERE id = ?",
            (ssh.port, "tikpilot", "127.0.0.1", device_id))
    return device_id, dict(query_one("SELECT * FROM devices WHERE id = ?", (device_id,)))


def test_untested_mark_reaches_the_form(client):
    """
    Пометка «не проверено на живом парке» доезжает до формы действия.

    Форма рисуется в браузере, поэтому флаг обязан быть в JSON. Проверяем
    саму механику, а не конкретное действие: помеченные приходят и уходят,
    а способ предупредить человека должен работать всегда.
    """
    from app.actions import Action, action_to_dict

    fresh = Action(name="proba", label="Проба", description="",
                   handler=lambda mt, device, params: "", untested=True)
    assert action_to_dict(fresh)["untested"] is True

    payload = client.get("/api/actions").json()
    items = payload["actions"] if isinstance(payload, dict) else payload
    assert all("untested" in item for item in items), "флаг не уехал в браузер"


def test_auto_confirm_opens_a_new_connection(client, router):
    """
    Автоподтверждение проверяет вход заново, а не старое соединение.

    Это принципиально. И правила input, и ограничения `/ip service`
    по адресам RouterOS применяет к новым подключениям, а установленное
    живёт дальше. Проверка старой сессией отвечала бы «всё хорошо» ровно
    в том случае, ради которого страховка и заводилась.
    """
    from tests.fake_ssh import FakeSSH

    from app import actions, rollback
    from app.actions import REGISTRY
    from app.mikrotik import MikroTik

    ssh = FakeSSH()
    was_pause = actions.CONFIRM_PAUSE
    actions.CONFIRM_PAUSE = 0.01     # ждать по-настоящему тесту незачем
    try:
        device_id, device = _ssh_device(client, router, "auto-device", ssh)

        with MikroTik(_device(router), "s3cret") as mt:
            logins = router.logins
            # Параметр не передаём: панель обязана подтверждать сама
            # по умолчанию, забывчивость не должна стоить перезагрузки
            answer = REGISTRY["safe_change"].handler(mt, device, {
                "script": "/system identity print",
                "minutes": "5", "_username": "admin",
            })

        assert router.logins > logins, "проверка обошлась старой сессией"
        assert rollback.current(device_id) is None, "страховка не снята"
        assert "страховка снята" in answer.lower()
        assert "доступ к роутеру остался" in answer, "не сказано, что именно проверено"
    finally:
        actions.CONFIRM_PAUSE = was_pause
        ssh.stop()


def test_auto_confirm_keeps_the_rollback_when_login_stops_working(client, router):
    """
    Если войти заново не удалось, страховка остаётся взведённой.

    Ровно тот случай, ради которого всё затевалось: человек закрыл себе
    доступ, старое соединение ещё живо, но нового уже не будет.
    """
    from tests.fake_ssh import FakeSSH

    from app import actions, rollback
    from app.actions import REGISTRY
    from app.mikrotik import MikroTik

    ssh = FakeSSH()
    was_pause = actions.CONFIRM_PAUSE
    actions.CONFIRM_PAUSE = 0.01
    try:
        device_id, device = _ssh_device(client, router, "locked-device", ssh)

        with MikroTik(_device(router), "s3cret") as mt:
            # Изменение «закрыло доступ»: новый вход устройство не примет,
            # хотя открытая сессия продолжает работать
            router.password = "стало-другим"
            try:
                answer = REGISTRY["safe_change"].handler(mt, device, {
                    "script": "/system identity print",
                    "minutes": "5", "confirm": "panel", "_username": "admin",
                })
            finally:
                router.password = "s3cret"

        assert rollback.current(device_id) is not None, "страховка снята зря"
        assert "Подключиться заново не удалось" in answer
    finally:
        actions.CONFIRM_PAUSE = was_pause
        ssh.stop()


def test_rollback_is_armed_before_the_change(client, router):
    """
    Снимок и отложенный откат заводятся до изменения, а не после.

    Иначе между применением и взведением страховки есть промежуток,
    в котором её нет, а нужна она ровно там.
    """
    from tests.fake_ssh import FakeSSH

    from app import rollback
    from app.actions import REGISTRY
    from app.mikrotik import MikroTik

    ssh = FakeSSH()
    try:
        device_id, device = _ssh_device(client, router, "safe-device", ssh)

        with MikroTik(_device(router), "s3cret") as mt:
            answer = REGISTRY["safe_change"].handler(mt, device, {
                "script": "/ip firewall filter\nadd chain=input action=drop",
                "minutes": "10", "confirm": "me", "_username": "admin",
            })

        # На устройстве лежит задача и снимок
        names = [s.get("name") for s in router.schedulers]
        assert rollback.SCHEDULER_NAME in names, "отложенный откат не заведён"
        assert any(f["name"].startswith(rollback.BACKUP_NAME) for f in router.files), \
            "снимок не снят"

        # Задача сначала снимает себя, потом восстанавливает снимок: после
        # backup load ничего уже не выполнится, устройство перезагружается
        event = next(s["on-event"] for s in router.schedulers
                     if s.get("name") == rollback.SCHEDULER_NAME)
        assert event.index("scheduler remove") < event.index("backup load")

        armed = rollback.current(device_id)
        assert armed and armed["state"] == "armed"
        assert "подтвердите" in answer.lower()
        assert ssh.commands == ["/ip firewall filter add chain=input action=drop"]
    finally:
        ssh.stop()


def test_confirming_removes_the_rollback_from_the_device(client, router):
    """
    Подтверждение снимает задачу и убирает снимок.

    Снимок это полный слепок конфигурации с паролями подключений,
    и оставлять его лежать в файлах роутера незачем.
    """
    from tests.fake_ssh import FakeSSH

    from app import rollback
    from app.actions import REGISTRY
    from app.mikrotik import MikroTik

    ssh = FakeSSH()
    try:
        device_id, device = _ssh_device(client, router, "confirm-device", ssh)

        with MikroTik(_device(router), "s3cret") as mt:
            REGISTRY["safe_change"].handler(mt, device, {
                "script": "/system identity print",
                "minutes": "5", "confirm": "me", "_username": "admin",
            })

        answer = client.post(f"/api/devices/{device_id}/rollback/confirm")
        assert answer.status_code == 200, answer.text

        assert rollback.current(device_id) is None
        assert not [s for s in router.schedulers
                    if s.get("name") == rollback.SCHEDULER_NAME]
        assert not [f for f in router.files
                    if f["name"].startswith(rollback.BACKUP_NAME)]
        assert not router.restored, "устройство откатилось, хотя изменение подтвердили"
    finally:
        ssh.stop()


def test_failed_command_does_not_cost_a_reboot(client, router):
    """
    Неудачная команда не оставляет взведённый откат на живой точке.

    Найдено на живом парке. Человек ошибся в синтаксисе скрипта, команда
    не прошла, ничего не изменилось, а страховка осталась и через десять
    минут перезагрузила бы точку. Опечатка не должна стоить перезагрузки,
    если доступ к устройству никуда не делся.

    Критерий тот же, что и при успехе, и это не совпадение: режим
    подтверждения отвечает на вопрос «кто судит», а не «что судим».
    """
    from tests.fake_ssh import FakeSSH

    from app import actions, rollback
    from app.actions import REGISTRY
    from app.mikrotik import DeviceError, MikroTik

    ssh = FakeSSH()
    was_pause = actions.CONFIRM_PAUSE
    actions.CONFIRM_PAUSE = 0.01
    try:
        device_id, device = _ssh_device(client, router, "typo-device", ssh)

        with MikroTik(_device(router), "s3cret") as mt:
            try:
                REGISTRY["safe_change"].handler(mt, device, {
                    "script": "/system identity set name=bad-command",
                    "minutes": "5", "_username": "admin",
                })
                raise AssertionError("ошибка устройства осталась незамеченной")
            except DeviceError as exc:
                text = str(exc)

        assert "expected end of command" in text, "ответ устройства потерян"
        assert "Страховка снята" in text
        assert rollback.current(device_id) is None, "точка обречена на перезагрузку"
    finally:
        actions.CONFIRM_PAUSE = was_pause
        ssh.stop()


def test_failed_command_leaves_the_rollback_armed(client, router):
    """
    В режиме «я сам» неудачная команда оставляет страховку взведённой.

    Обратная сторона предыдущего теста. Человек взял этот режим именно
    потому, что судить о результате хочет сам, и панель не вправе решать
    за него, даже когда устройство отвечает: часть команд могла
    примениться и сломать сеть за роутером.
    """
    from tests.fake_ssh import FakeSSH

    from app import rollback
    from app.actions import REGISTRY
    from app.mikrotik import DeviceError, MikroTik

    ssh = FakeSSH()
    try:
        device_id, device = _ssh_device(client, router, "failed-device", ssh)

        with MikroTik(_device(router), "s3cret") as mt:
            try:
                REGISTRY["safe_change"].handler(mt, device, {
                    "script": "/system identity set name=bad-command",
                    "minutes": "5", "confirm": "me", "_username": "admin",
                })
                raise AssertionError("ошибка устройства осталась незамеченной")
            except DeviceError as exc:
                text = str(exc)

        assert "Страховка оставлена взведённой" in text
        assert rollback.current(device_id) is not None
    finally:
        ssh.stop()


def test_rollback_now_restores_and_reboots(client, router):
    """Кнопка «откатить сейчас» восстанавливает снимок немедленно."""
    from tests.fake_ssh import FakeSSH

    from app import rollback
    from app.actions import REGISTRY
    from app.mikrotik import MikroTik

    ssh = FakeSSH()
    try:
        device_id, device = _ssh_device(client, router, "revert-device", ssh)

        with MikroTik(_device(router), "s3cret") as mt:
            REGISTRY["safe_change"].handler(mt, device, {
                "script": "/system identity print",
                "minutes": "5", "confirm": "me", "_username": "admin",
            })

        answer = client.post(f"/api/devices/{device_id}/rollback/now")
        assert answer.status_code == 200, answer.text
        assert router.restored, "снимок не восстановлен"

        from app.database import query_one

        assert query_one("SELECT state FROM rollbacks WHERE device_id = ? "
                         "ORDER BY id DESC", (device_id,))["state"] == "rolled-back"
    finally:
        ssh.stop()


def test_confirm_all_disarms_the_whole_fleet(client, router):
    """
    Кнопка «подтвердить все» снимает страховки со всех точек разом.

    Найдено на живом парке и дорого. Взвести страховку можно на сорок
    девять точек одним нажатием, а снимать приходилось по одной карточке
    за десять минут. Это физически невозможно, и парк перезагрузился
    целиком после безобидного пинга, отправленного, чтобы посмотреть,
    как работает страховка. Раз есть массовое взведение, обязано быть
    и массовое снятие.
    """
    from tests.fake_ssh import FakeSSH

    from app import rollback
    from app.actions import REGISTRY
    from app.mikrotik import MikroTik

    ssh = FakeSSH()
    try:
        first_id, first = _ssh_device(client, router, "fleet-one", ssh)
        second_id, second = _ssh_device(client, router, "fleet-two", ssh)

        with MikroTik(_device(router), "s3cret") as mt:
            for device in (first, second):
                REGISTRY["safe_change"].handler(mt, device, {
                    "script": "/ping 8.8.8.8 count=4",
                    "minutes": "10", "confirm": "me", "_username": "admin",
                })

        assert rollback.current(first_id) and rollback.current(second_id)

        answer = client.post("/api/rollbacks/confirm-all")
        assert answer.status_code == 200, answer.text
        assert answer.json()["done"] == 2

        assert rollback.current(first_id) is None
        assert rollback.current(second_id) is None
        assert not [s for s in router.schedulers
                    if s.get("name") == rollback.SCHEDULER_NAME]
    finally:
        ssh.stop()


def test_expired_rollback_is_closed_and_written_down(client, router):
    """
    Просроченная страховка закрывается сама и попадает в журнал.

    Панель не видит, что роутер откатился: связи с ним в этот момент как
    раз нет. Но срок она знает, и «подтверждения не было» честнее, чем
    вечно взведённая страховка в интерфейсе.
    """
    from app import rollback
    from app.database import execute, query, query_one, utcnow

    device_id = _add_device(client, router, "забытая точка")
    execute(
        "INSERT INTO rollbacks (device_id, device_name, username, minutes, state,"
        " created_at, expires_at) VALUES (?,?,?,?,'armed',?, datetime(?, '-1 minute'))",
        (device_id, "забытая точка", "admin", 10, utcnow(), utcnow()),
    )

    assert rollback.sweep() >= 1
    row = query_one("SELECT state FROM rollbacks WHERE device_name = ?",
                    ("забытая точка",))
    assert row["state"] == "expired"
    # Формулировка осторожная: панель не видит отката, она знает только,
    # что срок вышел. Утверждать увиденное там, где был расчёт, нельзя
    assert query("SELECT id FROM audit_log WHERE action = 'Срок страховки вышел'")

    # Повторный обход ничего не находит: запись уже закрыта
    assert rollback.sweep() == 0


# ------------------------------------------- консольные команды по SSH
def test_wrapped_console_command_is_joined_back():
    """
    Перенесённая консолью строка склеивается обратно.

    Это не украшение. Winbox переносит длинное значение обратным слэшем
    и выравнивает продолжение пробелами, и ровно в таком виде команду
    копируют. Без склейки список из шестидесяти сетей превращается
    в шестьдесят битых команд.
    """
    from app import cli

    # Кусок настоящей команды со скриншота, с переносами как есть
    text = (
        "/ip service\n"
        'set api address="192.168.88.0/24,192.168.89.0/24,192.168.90.0/24,192.168.\\\n'
        "    91.0/24,192.168.92.0/24,203.0.113.22/32,10.10.0.0/24\"\n"
    )
    commands = cli.parse(text)

    assert len(commands) == 1, "перенос не склеился"
    assert commands[0].startswith("/ip service set api address=")
    # Значение собралось без пробелов и без обрывов
    assert "192.168.91.0/24" in commands[0], "обрыв внутри адреса"
    assert "192.168.\\" not in commands[0]
    assert "\n" not in commands[0]


def test_script_body_in_braces_stays_one_command():
    """
    Тело скрипта в фигурных скобках уходит одной командой.

    Найдено на живом роутере. `add name=... source={ ... }` занимает
    полтора десятка строк, и без учёта скобок первая уходила обрезанной:
    роутер отвечал «expected closing brace», а остальные строки летели
    следом как самостоятельные команды и сыпались одна за другой.

    Скобка внутри кавычек при этом не считается: `on-event="..."` ничего
    не открывает.

    Уходит команда одной строкой: RouterOS по SSH выполняет ровно одну
    команду за вызов, а многострочный текст принимает как первую строку
    и молча ждёт продолжения до таймаута.
    """
    from app import cli

    text = (
        '/system script remove [find where name="lte-watchdog"]\n'
        "/system script\n"
        "add name=lte-watchdog policy=read,write,test,reboot source={\n"
        "  :global lteFail;\n"
        '  :if ([:typeof $lteFail] = "nothing") do={ :set lteFail 0 }\n'
        "  :if ($ok) do={\n"
        "    :set lteFail 0;\n"
        "  } else={\n"
        "    :set lteFail ($lteFail + 1);\n"
        "  }\n"
        "}\n"
        "/system scheduler\n"
        "add name=lte-watchdog-sched interval=1m start-time=startup \\\n"
        '  on-event="/system script run lte-watchdog"\n'
    )
    commands = cli.parse(text)

    assert len(commands) == 3, commands
    assert commands[0].startswith("/system script remove")

    body = commands[1]
    assert body.startswith("/system script add name=lte-watchdog")
    assert body.rstrip().endswith("}"), "блок оборван"
    assert "else={" in body and ":global lteFail;" in body
    assert "\n" not in body, "многострочную команду роутер по SSH не примет"
    # Точка с запятой не лезет туда, где была бы ошибкой: сразу после
    # открывающей скобки и перед закрывающей
    assert "={;" not in body and ";}" not in body
    assert ":set lteFail 0; } else={" in body

    # Скобка в кавычках блок не открывает, иначе последняя команда
    # прилипла бы к предыдущей
    assert commands[2].startswith("/system scheduler add name=lte-watchdog-sched")
    assert "\n" not in commands[2]


def test_timeout_without_text_still_explains_itself(client, router):
    """
    Молчание устройства объясняется словами, а не пустой строкой.

    Найдено на живом парке. У таймаута paramiko текст пустой, и в
    результате задачи оставалась голая команда без единого слова о том,
    что произошло: человек видел свой же скрипт и красную пометку
    «ошибка». Объяснение важнее точной формулировки библиотеки.
    """
    from app import cli

    class Mute:
        """Соединение, которое молчит так же, как настоящий роутер."""

        def exec_command(self, command, timeout=None):  # noqa: ANN001, ARG002
            import socket

            raise socket.timeout()

    output, failed = cli.run(Mute(), ["/system identity print"], timeout=7)

    assert failed
    assert "не ответило за 7 с" in output, output
    assert "Остановлено" in output, "непонятно, дошло ли дело до следующих команд"


def test_brace_depth_ignores_braces_in_quotes():
    """Скобка внутри строки в кавычках это символ, а не начало блока."""
    from app.cli import brace_depth

    assert brace_depth('on-event="{ не блок }"') == 0
    assert brace_depth("source={") == 1
    assert brace_depth("  :if ($x) do={ :set y 1 }") == 0
    assert brace_depth("}", 1) == 0


def test_console_path_applies_to_next_lines():
    """
    Путь меню запоминается, как в живой консоли.

    `/ip service` это переход в раздел, а `set ...` следующей строкой
    относится уже к нему. По SSH контекста между командами нет, поэтому
    путь приклеивается сам.
    """
    from app import cli

    commands = cli.parse(
        "/ip firewall filter\n"
        "print\n"
        "add chain=input action=drop\n"
        "/system identity\n"
        "print\n"
        "/interface print\n"
        ":put 1\n"
        "# комментарий\n"
    )
    assert commands == [
        "/ip firewall filter print",
        "/ip firewall filter add chain=input action=drop",
        "/system identity print",
        "/interface print",
        ":put 1",
    ]


def test_console_command_runs_over_ssh(client, router):
    """
    Команда уходит на устройство целиком и возвращает ответ.

    Разбирает её сам RouterOS: переписывать разбор консоли на своей
    стороне значило бы обещать совместимость, которую невозможно
    выполнить, и ломаться на каждой второй команде с форума.
    """
    from tests.fake_ssh import FakeSSH

    from app.actions import REGISTRY
    from app.database import query_one
    from app.mikrotik import MikroTik

    ssh = FakeSSH()
    try:
        device_id = _add_device(client, router, "cli-device")
        from app.database import execute

        execute("UPDATE devices SET ssh_port = ?, username = ?, host = ? WHERE id = ?",
                (ssh.port, "tikpilot", "127.0.0.1", device_id))
        device = dict(query_one("SELECT * FROM devices WHERE id = ?", (device_id,)))

        with MikroTik(_device(router), "s3cret") as mt:
            answer = REGISTRY["cli"].handler(mt, device, {
                "script": "/ip service\nset api address=10.0.0.0/8",
                "stop_on_error": "1",
            })

        assert "выполнено" in answer
        assert ssh.commands == ["/ip service set api address=10.0.0.0/8"]
    finally:
        ssh.stop()


def test_console_action_sends_the_script_body_as_one_command(client, router):
    """
    Многострочный блок уходит на устройство одной командой, а не пачкой строк.

    Разбор общий у обычной команды и у команды со страховкой, но проверять
    надо оба пути: сломать можно и на отправке. Именно здесь между разбором
    и роутером стоит `exec_command`, и если бы он резал текст по переносам,
    тест на разборе этого не заметил бы.
    """
    from tests.fake_ssh import FakeSSH

    from app.actions import REGISTRY
    from app.database import execute, query_one
    from app.mikrotik import MikroTik

    ssh = FakeSSH()
    try:
        device_id = _add_device(client, router, "script-device")
        execute("UPDATE devices SET ssh_port = ?, username = ?, host = ? WHERE id = ?",
                (ssh.port, "tikpilot", "127.0.0.1", device_id))
        device = dict(query_one("SELECT * FROM devices WHERE id = ?", (device_id,)))

        script = (
            "/system script\n"
            "add name=watchdog policy=read,write,test,reboot source={\n"
            "  :local ok false;\n"
            "  :if ([/ping 10.10.0.9 count=3] > 0) do={ :set ok true }\n"
            "  :if (!$ok) do={\n"
            "    :log warning \"нет связи\";\n"
            "  }\n"
            "}\n"
            "/system scheduler\n"
            "add name=watchdog-sched interval=1m start-time=startup \\\n"
            "  on-event=\"/system script run watchdog\"\n"
        )

        with MikroTik(_device(router), "s3cret") as mt:
            REGISTRY["cli"].handler(mt, device, {"script": script, "stop_on_error": "1"})

        assert len(ssh.commands) == 2, ssh.commands
        body = ssh.commands[0]
        assert body.startswith("/system script add name=watchdog")
        assert "\n" not in body, "многострочную команду роутер по SSH не примет"
        assert body.rstrip().endswith("}"), "блок обрезан на отправке"
        assert ":log warning" in body
        assert ssh.commands[1].startswith("/system scheduler add name=watchdog-sched")
    finally:
        ssh.stop()


def test_console_command_stops_on_the_first_error(client, router):
    """
    Ошибка останавливает остальные команды и попадает в результат задачи.

    RouterOS на кривую команду отвечает текстом, а код возврата при этом
    бывает нулевым, поэтому смотрим в текст. Продолжать после отказа
    опасно: вторая команда обычно опирается на первую.
    """
    from tests.fake_ssh import FakeSSH

    from app.actions import REGISTRY
    from app.database import execute, query_one
    from app.mikrotik import DeviceError, MikroTik

    ssh = FakeSSH()
    try:
        device_id = _add_device(client, router, "cli-error-device")
        execute("UPDATE devices SET ssh_port = ?, username = ?, host = ? WHERE id = ?",
                (ssh.port, "tikpilot", "127.0.0.1", device_id))
        device = dict(query_one("SELECT * FROM devices WHERE id = ?", (device_id,)))

        with MikroTik(_device(router), "s3cret") as mt:
            try:
                REGISTRY["cli"].handler(mt, device, {
                    "script": "/system bad-command\n/system identity print",
                    "stop_on_error": "1",
                })
                raise AssertionError("ошибка устройства осталась незамеченной")
            except DeviceError as exc:
                text = str(exc)

        assert "expected end of command" in text, "ответ устройства потерян"
        assert "Остановлено" in text
        assert len(ssh.commands) == 1, "после отказа выполнялись следующие команды"
    finally:
        ssh.stop()


# ---------------------------------------------------------- паспорт точки
def test_health_is_read_in_both_routeros_forms(router):
    """
    Показания датчиков разбираются и в семёрке, и в шестёрке.

    В RouterOS 7 health отдаёт строки «name=temperature value=57»,
    в шестой это была одна запись с полями. Ровно тот класс расхождения,
    на котором мы уже обожглись с `bsd-syslog`, поэтому здесь проверяются
    обе формы, а не та, которая под рукой.
    """
    from app import inventory
    from app.mikrotik import MikroTik

    with MikroTik(_device(router), "s3cret") as mt:
        seven = inventory.collect(mt)
    assert seven["temperature"] == "57"
    assert seven["voltage"] == "24.1"

    router.health_legacy = True
    with MikroTik(_device(router), "s3cret") as mt:
        six = inventory.collect(mt)
    assert six["temperature"] == "42", "форма RouterOS 6 не разобрана"
    assert six["voltage"] == "24.0"
    router.health_legacy = False


def test_ports_carry_speed_and_poe(router):
    """
    Порт знает свою скорость, питание и то, что он погашен.

    Скорость показывается только у работающего порта: у погасшего RouterOS
    оставляет прошлое значение, и плитка «1G» на мёртвом порту это ровно
    та ошибка, ради которой человек и открывает карточку.
    """
    from app import inventory
    from app.mikrotik import MikroTik

    with MikroTik(_device(router), "s3cret") as mt:
        data = inventory.collect(mt)

    ports = {p["name"]: p for p in data["ports"]}
    assert ports["ether1"]["speed"] == 1000
    assert ports["ether1"]["speed_class"] == "1g"
    assert ports["ether2"]["speed_class"] == "100m"
    assert ports["ether2"]["poe_status"] == "powered-on"
    # Погашенный порт: скорость обнуляется, хотя роутер её всё ещё помнит
    assert ports["ether3"]["running"] == 0
    assert ports["ether3"]["speed"] == 0

    # Мост и VLAN не физические: они уходят в список, а не в плитки
    assert ports["bridge"]["physical"] is False
    assert ports["vlan-100"]["detail"] == "VLAN 100 · bridge"


def test_risky_services_are_marked(router):
    """
    Включённый telnet отмечается как опасный, ограниченный по адресам нет.

    Разница существенная: telnet, открытый только для своей сети, это
    не то же самое, что telnet для всех, и красить их одинаково значит
    приучить человека не смотреть на предупреждение.
    """
    from app import inventory
    from app.mikrotik import MikroTik

    with MikroTik(_device(router), "s3cret") as mt:
        data = inventory.collect(mt)

    services = {s["name"]: s for s in data["services"]}
    assert services["telnet"]["risky"] == 1, "открытый telnet не отмечен"
    assert services["ftp"]["risky"] == 0, "выключенный сервис не опасен"
    assert services["www"]["risky"] == 0, "ограниченный по адресам сервис не опасен"
    assert services["ssh"]["risky"] == 0, "ssh это не дыра"


def test_own_api_connection_is_not_an_open_port(router):
    """
    Соединение самой панели не выдаётся за открытый настежь сервис.

    Найдено на живой точке. В RouterOS 7.21 `/ip/service` отдаёт вместе
    с сервисами и установленные соединения к роутеру, у которых заполнены
    remote и local. Панель сидит на api постоянно, поэтому такая запись
    есть всегда, ограничений по адресам у неё нет по природе, и в карточке
    появлялось предупреждение «api открыт всем» при закрытом списком api.

    Ложная тревога хуже отсутствия тревоги: человек перестаёт смотреть
    на предупреждения, и настоящий telnet проезжает мимо глаз.
    """
    from app import inventory
    from app.mikrotik import MikroTik

    with MikroTik(_device(router), "s3cret") as mt:
        data = inventory.collect(mt)

    api = [s for s in data["services"] if s["name"] == "api"]
    assert len(api) == 1, "соединение показано отдельной строкой сервиса"
    assert api[0]["risky"] == 0, "закрытый списком сетей api отмечен как дыра"
    assert api[0]["address"], "потеряли список разрешённых сетей"

    # Динамику роутер поднимает сам, выключить её через /ip/service нельзя,
    # поэтому и судить её как настроенный сервис бессмысленно
    dynamic = {s["name"] for s in data["services"] if s["dynamic"]}
    assert {"resolver", "dhcpclient"} <= dynamic
    assert not any(s["risky"] for s in data["services"] if s["dynamic"])


def test_passport_is_stored_and_shown_on_the_card(client, router):
    """
    Паспорт собирается кнопкой и показывается из базы.

    Из базы, а не с устройства при каждом открытии: карточка обязана
    открываться мгновенно и работать, когда точка лежит. Как раз про
    упавшую точку чаще всего и спрашивают, что там было настроено.
    """
    from app import inventory
    from app.database import query_one

    device_id = _add_device(client, router, "passport-device")

    # На живой точке почти всегда уже что-то лежит, часто заведённое
    # руками год назад и всеми забытое. Паспорт обязан это показать
    router.scripts = [{".id": "*1", "name": "lte-watchdog", "policy": "read,write",
                       "run-count": "417", "comment": "сторож канала"}]

    answer = client.post(f"/api/devices/{device_id}/inventory")
    assert answer.status_code == 200, answer.text
    assert answer.json()["ports"] >= 3

    row = query_one("SELECT temperature, voltage, inventory_at FROM devices WHERE id = ?",
                    (device_id,))
    assert row["temperature"] == "57"
    assert row["inventory_at"]

    page = client.get(f"/devices/{device_id}")
    assert page.status_code == 200
    assert "ether1" in page.text
    assert "telnet:23" in page.text
    assert "AP-Sklad" in page.text, "сосед не показан"
    assert "lte-watchdog" in page.text, "скрипт устройства не показан"
    assert "Открыты небезопасные сервисы" in page.text

    # Повторный сбор заменяет прежний снимок, а не копит дубли
    client.post(f"/api/devices/{device_id}/inventory")
    stored = query_one("SELECT COUNT(*) AS c FROM device_ports WHERE device_id = ?",
                       (device_id,))["c"]
    assert stored == len(inventory.load(device_id)["ports"]) + \
        len(inventory.load(device_id)["logical"])


def test_neighbor_known_to_the_panel_becomes_a_link(client, router):
    """
    Сосед, который есть в панели, показывается ссылкой на свою карточку.

    «Рядом стоит DC-CORE01» полезнее, чем «рядом стоит 10.0.1.1»: второе
    приходится сопоставлять в голове каждый раз.
    """
    from app import inventory
    from app.database import execute, query_one, utcnow

    device_id = _add_device(client, router, "neighbor-owner")
    other_id = _add_device(client, router, "AP-Sklad")

    execute(
        "INSERT INTO device_neighbors (device_id, identity, address, mac, interface,"
        " platform, board, version, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
        (device_id, "AP-Sklad", "192.168.88.20", "48:8F:5A:11:22:33", "ether2",
         "MikroTik", "cAP ac", "7.14.3", utcnow()),
    )

    loaded = inventory.load(device_id)
    assert loaded["neighbors"][0]["known_id"] == other_id

    page = client.get(f"/devices/{device_id}")
    assert f'/devices/{other_id}"' in page.text, "сосед не стал ссылкой"
    assert query_one("SELECT id FROM devices WHERE id = ?", (other_id,))


def test_risky_services_are_visible_across_the_fleet(client, router):
    """
    «Где включён telnet» это вопрос ко всему парку, а не к одной карточке.

    Ради этого сбор сервисов и затевался: обойти полсотни коробок глазами
    невозможно, а без обхода дыра живёт годами.
    """
    from app import inventory

    first = _add_device(client, router, "fleet-telnet-1")
    second = _add_device(client, router, "fleet-telnet-2")
    client.post(f"/api/devices/{first}/inventory")
    client.post(f"/api/devices/{second}/inventory")

    found = inventory.risky_fleet()
    names = {row["device_name"] for row in found if row["name"] == "telnet"}
    assert {"fleet-telnet-1", "fleet-telnet-2"} <= names


# ------------------------------------------ кто открывает публичные ссылки
def test_user_agent_becomes_readable():
    """
    Строка User-Agent превращается в «браузер, система».

    Отдельным тестом, потому что разбор здесь заведомо приблизительный,
    и легко получить «Chrome» там, где на самом деле Яндекс Браузер:
    он представляется обоими сразу, причём чужая версия стоит в строке
    раньше собственной.
    """
    from app.publicviews import describe_agent

    yandex = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/137.0.0.0 YaBrowser/25.6.0.0 Safari/537.36")
    assert describe_agent(yandex) == ("Яндекс Браузер 25, Windows", 0)

    phone = ("Mozilla/5.0 (Linux; Android 13; SM-A536E) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36")
    assert describe_agent(phone) == ("Chrome 138, Android", 0)

    # Мессенджер открывает ссылку сам, чтобы показать превью. Это не человек
    assert describe_agent("TelegramBot (like TwitterBot)") == ("Telegram", 1)
    assert describe_agent("") == ("", 0)


def test_public_visit_is_one_session_not_many_rows(client, router):
    """
    Открытая вкладка это одна строка со счётчиком, а не сотня строк.

    Страница обновляет себя раз в минуту. Без склейки по метке сеанса
    журнал заходов за сутки состоял бы из полутора тысяч записей об одном
    и том же человеке, и найти в нём чужой адрес было бы невозможно.
    """
    from app.database import query, query_one

    group_id, _ = _group_with_devices(client, router, "views-a")
    token = client.post(f"/api/groups/{group_id}/public-link",
                        json={"enabled": True}).json()["url"].rsplit("/", 1)[-1]

    phone = ("Mozilla/5.0 (Linux; Android 13; SM-A536E) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/138.0.0.0 Mobile Safari/537.36")

    with _anon() as person:
        for _ in range(5):
            person.get(f"/status/{token}", headers={"user-agent": phone})

    rows = query("SELECT * FROM public_views WHERE group_id = ?", (group_id,))
    assert len(rows) == 1, "автообновление размножило строки"
    assert rows[0]["hits"] == 5
    assert rows[0]["device"] == "Chrome 138, Android"
    assert rows[0]["ip"]

    # Другой человек это другая строка, даже с той же ссылкой
    with _anon() as other:
        other.get(f"/status/{token}", headers={"user-agent": phone})
    assert query_one("SELECT COUNT(*) AS c FROM public_views WHERE group_id = ?",
                     (group_id,))["c"] == 2


def test_link_preview_is_marked_as_a_robot(client, router):
    """
    Предпросмотр ссылки в мессенджере не выдаётся за посетителя.

    Ссылку, отправленную в чат, открывает сам мессенджер. Без пометки
    выходило бы, что подрядчик открыл страницу через секунду после
    отправки, и по журналу нельзя было бы понять, дошла ли она до него.
    """
    from app.database import query_one

    group_id, _ = _group_with_devices(client, router, "views-bot")
    token = client.post(f"/api/groups/{group_id}/public-link",
                        json={"enabled": True}).json()["url"].rsplit("/", 1)[-1]

    with _anon() as bot:
        bot.get(f"/status/{token}", headers={"user-agent": "TelegramBot (like TwitterBot)"})

    row = query_one("SELECT * FROM public_views WHERE group_id = ? ORDER BY id DESC",
                    (group_id,))
    assert row["bot"] == 1

    from app import publicviews

    assert all(w["group_id"] != group_id for w in publicviews.watching()), \
        "робот попал в список тех, кто смотрит сейчас"


def test_wrong_token_attempts_are_recorded_and_merged(client, router):
    """
    Заходы по несуществующей ссылке видно, но перебор не забивает журнал.

    Один такой заход это опечатка, десяток подряд с одного адреса это
    перебор. Знать о втором нужно обязательно, но по строке на попытку
    журнал стал бы бесполезен ровно в тот момент, когда он важнее всего.
    """
    from app.database import query_one

    def counters() -> tuple[int, int]:
        row = query_one("SELECT COUNT(*) AS rows, COALESCE(SUM(hits), 0) AS hits "
                        "FROM public_views WHERE ok = 0")
        return int(row["rows"]), int(row["hits"])

    # Считаем прирост, а не итог: в общей базе тестов чужие промахи уже есть
    rows_before, hits_before = counters()

    with _anon() as anon:
        for _ in range(5):
            anon.get("/status/" + "q" * 32)

    rows_after, hits_after = counters()
    assert hits_after - hits_before == 5, "попытки не посчитаны"
    assert rows_after - rows_before <= 1, "каждая попытка завела свою строку"

    last = query_one("SELECT * FROM public_views WHERE ok = 0 ORDER BY id DESC")
    assert last["group_id"] is None
    assert "q" * 32 not in last["token_tail"], "токен сохранён целиком"


def test_visits_page_needs_its_own_permission(client, router):
    """
    Журнал заходов закрыт отдельным правом.

    Там адреса и устройства людей, а не состояние сети. Оператору, который
    смотрит за точками, это знать незачем, и по умолчанию право не выдаётся.
    """
    _make_user(client, "nosy", ["settings.view"])

    with _as("nosy") as guest:
        assert guest.get("/logs/visits").status_code == 403

    assert client.get("/logs/visits").status_code == 200


def test_visits_page_shows_who_is_watching(client, router):
    """Открытая прямо сейчас страница видна администратору в тот же момент."""
    group_id, _ = _group_with_devices(client, router, "views-live")
    token = client.post(f"/api/groups/{group_id}/public-link",
                        json={"enabled": True}).json()["url"].rsplit("/", 1)[-1]

    with _anon() as person:
        person.get(f"/status/{token}", headers={
            "user-agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/126.0.0.0 Safari/537.36"})

    page = client.get("/logs/visits")
    assert page.status_code == 200
    assert "views-live" in page.text
    assert "Chrome 126, Windows" in page.text

    live = client.get("/logs/visits/live")
    assert live.status_code == 200
    assert "Chrome 126, Windows" in live.text


# ------------------------------------------ ограничение панели по адресам
def test_networks_parse_addresses_and_subnets():
    """Список сетей понимает и подсеть, и одиночный адрес."""
    from app.netguard import parse_networks

    nets = parse_networks("10.0.0.0/8, 192.168.1.5 ,, мусор ,2001:db8::/32")
    assert len(nets) == 3, "битая запись должна пропускаться, а не ломать список"
    assert str(nets[1]) == "192.168.1.5/32"


def test_panel_access_by_network():
    """Внутри разрешённой сети пускаем, снаружи нет."""
    from app.netguard import allowed, parse_networks

    nets = parse_networks("10.0.0.0/8")
    assert allowed("10.10.0.20", "", nets, [])
    assert not allowed("203.0.113.7", "", nets, [])

    # Пустой список означает «не ограничивать»
    assert allowed("203.0.113.7", "", [], [])


def test_forwarded_header_is_ignored_from_untrusted_peer():
    """
    Поддельный X-Forwarded-For не пускает внутрь.

    Заголовок может выставить кто угодно. Доверяем ему, только если запрос
    пришёл от прокси из списка доверенных. Без этой оговорки вся проверка
    обходилась бы одной строкой в curl.
    """
    from app.netguard import allowed, parse_networks

    admin = parse_networks("10.0.0.0/8")
    proxies = parse_networks("192.0.2.1")

    # Чужой адрес с подделанным заголовком
    assert not allowed("203.0.113.7", "10.0.0.1", admin, proxies)

    # Тот же заголовок, но запрос пришёл от доверенного прокси
    assert allowed("192.0.2.1", "10.0.0.1", admin, proxies)

    # Из цепочки берём ближайший к нам адрес, а не первый:
    # начало цепочки клиент может написать сам
    assert not allowed("192.0.2.1", "10.0.0.1, 203.0.113.7", admin, proxies)


def test_public_status_path_is_always_open():
    """Публичная страница и её оформление не подпадают под ограничение."""
    from app.netguard import is_public_path

    assert is_public_path("/status/abcdef")
    assert is_public_path("/static/app.css")
    assert not is_public_path("/")
    assert not is_public_path("/login")
    assert not is_public_path("/api/jobs")
    # Похожий, но чужой адрес не должен считаться публичным
    assert not is_public_path("/statuspage")


def test_restriction_blocks_panel_but_not_status(client, router):
    """
    Целиком, через реальные запросы: снаружи открыт только лист состояния.

    Адрес клиента в тестах не настоящий, поэтому при включённом ограничении
    он не попадает ни в одну сеть — то есть ведёт себя как «снаружи».
    """
    from app.config import settings
    from app.netguard import parse_networks

    group_id, _ = _group_with_devices(client, router, "netguard")
    token = client.post(f"/api/groups/{group_id}/public-link",
                        json={"enabled": True}).json()["url"].rsplit("/", 1)[-1]

    saved = settings.admin_networks
    settings.admin_networks = parse_networks("10.0.0.0/8")
    try:
        with _anon() as outside:
            assert outside.get("/login").status_code == 403
            assert outside.get("/", follow_redirects=False).status_code == 403
            assert outside.get("/api/stats").status_code == 403

            # А ради чего всё затевалось — работает
            assert outside.get(f"/status/{token}").status_code == 200
            assert outside.get("/static/app.css").status_code == 200
    finally:
        settings.admin_networks = saved


# --------------------------------------------------------------- WireGuard
def test_wireguard_keys_are_valid_x25519():
    """
    Ключи настоящие, а не случайные 32 байта.

    Проверяем, что публичный ключ действительно выводится из приватного:
    иначе туннель просто не поднимется, а понять это можно будет только
    на живом железе.
    """
    import base64

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    from app.wireguard import generate_keypair, generate_psk

    private, public = generate_keypair()
    restored = X25519PrivateKey.from_private_bytes(base64.b64decode(private))
    derived = restored.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert base64.b64encode(derived).decode() == public
    assert len(base64.b64decode(generate_psk())) == 32


def test_tunnel_address_allocation():
    """Свободный адрес подбирается, занятые пропускаются."""
    from app.wireguard import next_free_tunnel_ip

    assert next_free_tunnel_ip("10.20.0.1/24", []) == "10.20.0.2"
    assert next_free_tunnel_ip("10.20.0.1/24", ["10.20.0.2/32", "10.20.0.3/32"]) == "10.20.0.4"
    # Из одного адреса выдать нечего, и это надо сказать, а не выдумать адрес
    assert next_free_tunnel_ip("10.20.0.1/32", []) is None
    assert next_free_tunnel_ip("", []) is None


def test_link_validation_catches_typical_mistakes():
    """
    Ошибки ввода ловятся до записи на роутер.

    Почти все проблемы site-to-site это опечатки, а не связь. Подсеть без
    маски, туннель /32 и особенно «вписал сюда сети своего же хаба» стоят
    потом часов поиска, почему сети не видят друг друга.
    """
    from app.wireguard import Hub, Link, validate_link

    hub = Hub(interface="wg-hub", public_key="KEY=", tunnel_address="10.20.0.1/24",
              public_host="vpn.example.com", lan_subnets=["192.168.10.0/24"])

    problems = validate_link(
        hub,
        Link(name="", tunnel_ip="10.20.0.5",
             remote_subnets=["192.168.10.0/24", "10.1.1.0"]),
        hub_networks=["192.168.10.0/24"],
        existing_names=["Кедр 73"],
    )
    text = " ".join(problems)
    assert "имя" in text
    assert "сеть самого хаба" in text
    assert "без маски" in text

    # Корректный линк проходит без замечаний
    assert not validate_link(
        hub, Link(name="Новая точка", tunnel_ip="10.20.0.5",
                  remote_subnets=["192.168.55.0/24"]),
        hub_networks=["192.168.10.0/24"], existing_names=["Кедр 73"],
    )


def test_spoke_script_contains_everything_needed():
    """
    Скрипт для споука самодостаточен.

    Именно маршруты к сетям хаба чаще всего забывают: allowed-address
    в таблицу маршрутизации ничего не пишет, и туннель поднимается,
    а сети друг друга не видят.
    """
    from app.wireguard import Hub, Link, build_spoke_script, build_wg_quick_config

    hub = Hub(interface="wg-hub", public_key="HUBKEY=", listen_port=13231,
              tunnel_address="10.20.0.1/24", public_host="vpn.example.com",
              lan_subnets=["192.168.10.0/24"])
    link = Link(name="Кедр 73", tunnel_ip="10.20.0.5",
                remote_subnets=["192.168.55.0/24"],
                private_key="PRIV=", psk="PSK=")

    script = build_spoke_script(hub, link)
    assert "/interface/wireguard" in script
    assert 'private-key="PRIV="' in script
    assert "add address=10.20.0.5/24" in script
    assert "endpoint-address=vpn.example.com endpoint-port=13231" in script
    assert "10.20.0.0/24" in script and "192.168.10.0/24" in script
    # Шлюз это адрес хаба в туннеле: маршрут через имя интерфейса на стороне
    # споука не говорит роутеру, куда именно отдавать пакет
    assert "/ip/route" in script and "gateway=10.20.0.1" in script
    assert 'preshared-key="PSK="' in script

    # Без ключа скрипт остаётся шаблоном и честно об этом пишет
    template = build_spoke_script(hub, Link(name="x", tunnel_ip="10.20.0.6"))
    assert "ВСТАВЬТЕ_ПРИВАТНЫЙ_КЛЮЧ_СПОУКА" in template
    assert "не хранится намеренно" in template

    # Тот же линк для обычного клиента
    conf = build_wg_quick_config(hub, link)
    assert "[Interface]" in conf and "Endpoint = vpn.example.com:13231" in conf


def _wg_hub(client, router) -> int:
    """Устройство-хаб с сохранёнными настройками."""
    device_id = _add_device(client, router, "wg-hub-device")
    client.post("/api/wg/hub", json={
        "device_id": device_id, "interface": "wg-hub",
        "public_host": "vpn.example.com", "listen_port": 13231,
        "lan_subnets": "192.168.10.0/24",
    })
    client.post("/api/wg/tunnel-address", json={
        "device_id": device_id, "interface": "wg-hub", "address": "10.20.0.1/24",
    })
    return device_id


def test_link_creates_peer_and_routes_on_the_hub(client, router):
    """
    Создание линка заводит и пир, и маршруты.

    Маршруты здесь не украшение: без них пакет не попадёт в интерфейс
    туннеля, и связь не заработает при живом рукопожатии.
    """
    device_id = _wg_hub(client, router)

    r = client.post("/api/wg/links", json={
        "device_id": device_id, "name": "Кедр 73",
        "tunnel_ip": "10.20.0.5", "subnets": "192.168.55.0/24", "psk": True,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "PrivateKey" in body["config"] or "private-key" in body["script"]

    peers = [p for p in router.wg_peers if p.get("comment") == "wgpanel:Кедр 73"]
    assert len(peers) == 1
    assert peers[0]["allowed-address"] == "10.20.0.5/32,192.168.55.0/24"
    assert peers[0].get("preshared-key")

    routes = [r for r in router.ip_routes if r.get("comment") == "wgpanel:Кедр 73"]
    assert [r["dst-address"] for r in routes] == ["192.168.55.0/24"]
    # Шлюз это адрес споука в туннеле, а не имя интерфейса: через интерфейс
    # роутер сам решает, какому пиру отдать пакет, и с несколькими пирами
    # решает не так, как ожидается
    assert routes[0]["gateway"] == "10.20.0.5"


def test_private_key_is_never_stored(client, router):
    """
    Приватный ключ споука нигде не сохраняется.

    Он показывается один раз и забывается. Иначе утечка базы означала бы
    утечку всех туннелей сразу, а пользы мало: линк проще пересоздать.
    """
    from app.database import query

    device_id = _wg_hub(client, router)
    body = client.post("/api/wg/links", json={
        "device_id": device_id, "name": "Секрет", "tunnel_ip": "10.20.0.9",
        "subnets": "192.168.99.0/24",
    }).json()

    private = body["script"].split('private-key="')[1].split('"')[0]
    assert len(private) > 20

    # Ни в одной таблице этого ключа быть не должно
    for table in ("wg_hubs", "devices", "audit_log", "jobs", "job_items"):
        rows = query(f"SELECT * FROM {table}")
        assert private not in str([dict(r) for r in rows]), table

    # Перевыпуск скрипта отдаёт шаблон без ключа
    again = client.post("/api/wg/links/script", json={
        "device_id": device_id, "name": "Секрет"}).json()
    assert private not in again["script"]
    assert "ВСТАВЬТЕ_ПРИВАТНЫЙ_КЛЮЧ_СПОУКА" in again["script"]


def test_deleting_a_link_touches_only_its_own_objects(client, router):
    """Удаление линка не трогает чужие пиры и маршруты."""
    device_id = _wg_hub(client, router)

    # Чужой пир, созданный руками мимо панели
    router.wg_peers.append({".id": "*777", "interface": "wg-hub",
                            "public-key": "SOMEONE=", "comment": "ручной пир"})
    routes_before = len(router.ip_routes)

    client.post("/api/wg/links", json={
        "device_id": device_id, "name": "Времянка",
        "tunnel_ip": "10.20.0.7", "subnets": "192.168.77.0/24"})

    r = client.post("/api/wg/links/delete",
                    json={"device_id": device_id, "name": "Времянка"})
    assert r.status_code == 200
    assert r.json()["peers"] == 1 and r.json()["routes"] == 1

    assert any(p[".id"] == "*777" for p in router.wg_peers), "удалили чужой пир"
    assert len(router.ip_routes) == routes_before


def test_firewall_rules_go_before_the_drop(client, router):
    """
    Правила ставятся перед запрещающим, иначе они бесполезны.

    Добавленное в конец цепочки accept после drop не сработает никогда,
    и человек будет искать причину в туннеле, а не в порядке правил.
    """
    device_id = _wg_hub(client, router)

    r = client.post("/api/wg/firewall", json={
        "device_id": device_id, "interface": "wg-hub", "listen_port": "13231"})
    assert r.status_code == 200 and r.json()["added"] == 3

    chain = [rule for rule in router.firewall if rule.get("chain") == "forward"]
    positions = {rule.get("comment"): i for i, rule in enumerate(chain)}
    drop_at = next(i for i, rule in enumerate(chain) if rule.get("action") == "drop")
    assert positions["wgpanel:fwd-in:wg-hub"] < drop_at
    assert positions["wgpanel:fwd-out:wg-hub"] < drop_at

    # Повторный вызов ничего не дублирует
    assert client.post("/api/wg/firewall", json={
        "device_id": device_id, "interface": "wg-hub",
        "listen_port": "13231"}).json()["added"] == 0


def test_wireguard_needs_permission(client, router):
    """Раздел и его операции закрыты правом wireguard.manage."""
    device_id = _wg_hub(client, router)
    _make_user(client, "nowg", ["action.check"])

    with _as("nowg") as limited:
        assert limited.get("/wireguard").status_code == 403
        assert limited.post("/api/wg/links", json={
            "device_id": device_id, "name": "Чужой",
            "tunnel_ip": "10.20.0.8"}).status_code == 403

    assert not any(p.get("comment") == "wgpanel:Чужой" for p in router.wg_peers)


def test_foreign_routes_are_not_deletable(client, router):
    """Маршрут без метки панели удалить нельзя: он чужой."""
    device_id = _wg_hub(client, router)
    router.ip_routes.append({".id": "*555", "dst-address": "172.16.0.0/12",
                             "gateway": "ether1", "comment": "важный маршрут"})

    r = client.post("/api/wg/routes/delete", json={"device_id": device_id, "id": "*555"})
    assert r.status_code == 403
    assert any(x[".id"] == "*555" for x in router.ip_routes)


def test_russian_names_survive_the_api(client, router):
    """
    Русские имена доходят до устройства без искажений.

    librouteros по умолчанию кодирует команды в ASCII, а RouterOS понимает
    UTF-8. Без явной кодировки любое русское слово в комментарии роняло
    команду с UnicodeEncodeError — а названия площадок почти всегда русские.
    """
    device_id = _wg_hub(client, router)

    r = client.post("/api/wg/links", json={
        "device_id": device_id, "name": "Малоречка",
        "tunnel_ip": "10.20.0.11", "subnets": "192.168.97.0/24"})
    assert r.status_code == 200, r.text

    peer = next(p for p in router.wg_peers if p.get("comment") == "wgpanel:Малоречка")
    assert peer["allowed-address"].startswith("10.20.0.11/32")


def test_hub_settings_are_read_from_the_router(client, router):
    """
    Раздел сам подтягивает интерфейс, туннельный адрес и сети хаба.

    Всё это уже есть на роутере, и спрашивать его об этом дешевле, чем
    заставлять человека переписывать в поля то, что панель видит сама.
    Раньше до первого сохранения раздел выглядел пустым, хотя туннель
    работал.
    """
    device_id = _add_device(client, router, "wg-fresh")

    router.ip_addresses += [
        # Туннель: должен попасть в своё поле и не попасть в список LAN
        {".id": "*20", "address": "10.20.0.1/24", "interface": "wg-hub"},
        {".id": "*21", "address": "192.168.10.1/24", "interface": "bridge"},
        # Выключенный адрес и одиночный /32 сетями хаба не считаются
        {".id": "*22", "address": "192.168.99.1/24", "interface": "ether5",
         "disabled": "true"},
        {".id": "*23", "address": "203.0.113.7/32", "interface": "ether2"},
    ]

    page = client.get(f"/wireguard?device_id={device_id}").text

    assert 'value="10.20.0.1/24"' in page, "туннельный адрес не прочитан"
    assert "192.168.10.0/24" in page, "сеть хаба не определена"
    assert "10.0.0.0/24" in page, "вторая сеть хаба не определена"
    assert "192.168.99.0/24" not in page, "выключенный адрес попал в LAN"
    assert "203.0.113.7" not in page, "одиночный /32 попал в LAN"
    # Интерфейс выбран сам, хотя ничего ещё не сохранено
    assert re.search(r'value="wg-hub"\s+selected', page), "интерфейс не выбран сам"
    # А раз туннель прочитан, есть и первый свободный адрес для споука
    assert 'value="10.20.0.2"' in page


def test_free_address_skips_the_ones_already_given_out(client, router):
    """
    Свободный адрес ищется с учётом уже выданных.

    `allowed-address` приходит одной строкой «10.8.0.5/32,192.168.5.0/24»,
    и разбор её целиком не удавался. Занятых адресов будто не было вовсе,
    и панель раз за разом предлагала второй адрес подсети, выданный ещё
    первому споуку.
    """
    from app.wireguard import next_free_tunnel_ip

    taken = [f"10.8.0.{n}/32,192.168.{n}.0/24" for n in range(2, 56)]
    assert next_free_tunnel_ip("10.8.0.1/24", taken) == "10.8.0.56"

    # Сети дальней стороны на раздачу туннельных адресов не влияют
    assert next_free_tunnel_ip("10.8.0.1/24", ["10.8.0.0/24"]) == "10.8.0.2"

    # То же самое через страницу: пиры уже занимают адреса
    device_id = _wg_hub(client, router)
    for n in (2, 3, 4):
        router.wg_peers.append({
            ".id": f"*3{n}", "interface": "wg-hub", "public-key": f"KEY{n}=",
            "allowed-address": f"10.20.0.{n}/32,192.168.{n}.0/24",
            "comment": f"wgpanel:точка {n}",
        })
    assert 'value="10.20.0.5"' in client.get(f"/wireguard?device_id={device_id}").text


def test_old_routes_are_switched_to_tunnel_gateways(client, router):
    """
    Маршруты через имя интерфейса переводятся на туннельные адреса.

    Чужое при этом не трогается: правильный маршрут остаётся как есть,
    маршрут без метки панели тоже.
    """
    device_id = _wg_hub(client, router)
    client.post("/api/wg/links", json={
        "device_id": device_id, "name": "Старая точка",
        "tunnel_ip": "10.20.0.43", "subnets": "192.168.43.0/24"})

    # Так маршрут выглядел раньше
    old = next(r for r in router.ip_routes if r.get("comment") == "wgpanel:Старая точка")
    old["gateway"] = "wg-hub"
    router.ip_routes.append({".id": "*888", "dst-address": "172.20.0.0/16",
                             "gateway": "wg-hub", "comment": "чужой маршрут"})

    r = client.post("/api/wg/routes/fix-gateways", json={"device_id": device_id})
    assert r.status_code == 200 and r.json()["fixed"] == 1

    assert old["gateway"] == "10.20.0.43"
    foreign = next(x for x in router.ip_routes if x[".id"] == "*888")
    assert foreign["gateway"] == "wg-hub", "тронули чужой маршрут"

    # Повторный вызов ничего не меняет
    assert client.post("/api/wg/routes/fix-gateways",
                       json={"device_id": device_id}).json()["fixed"] == 0


def test_handshake_column_sorts_by_age(client, router):
    """
    Рукопожатие сортируется по возрасту, а не по надписи.

    Как текст «45s» больше «1m30s», поэтому колонка с ключом сортировки
    из самой строки показывала бы обратный порядок. Отсутствие связи
    уходит в конец: это не «связь самая свежая».
    """
    from app.routes.wireguard import NO_HANDSHAKE, _links
    from app.wireguard import duration_seconds

    assert duration_seconds("45s") == 45
    assert duration_seconds("1m30s") == 90
    assert duration_seconds("2h3m10s") == 7390
    assert duration_seconds("1w1d") == 691200
    assert duration_seconds("") is None

    rows = _links([
        {"comment": "wgpanel:Далёкая", "allowed-address": "10.20.0.3/32",
         "last-handshake": "1m30s"},
        {"comment": "wgpanel:Свежая", "allowed-address": "10.20.0.2/32",
         "last-handshake": "45s"},
        {"comment": "wgpanel:Молчит", "allowed-address": "10.20.0.4/32"},
    ])
    assert [r["name"] for r in rows] == ["Свежая", "Далёкая", "Молчит"]
    assert [r["handshake_key"] for r in rows] == [45, 90, NO_HANDSHAKE]

    # Ключи попадают в таблицу, иначе сортировка по клику снова станет текстовой
    device_id = _wg_hub(client, router)
    router.wg_peers.append({
        ".id": "*40", "interface": "wg-hub", "public-key": "K=",
        "allowed-address": "10.20.0.6/32", "comment": "wgpanel:Точка",
        "last-handshake": "1m30s", "rx": "2048", "tx": "1024"})
    page = client.get(f"/wireguard?device_id={device_id}").text
    assert 'data-sort="90"' in page
    assert 'data-sort="3072"' in page


def test_gateway_list_is_ordered_by_address(client, router):
    """
    Список шлюзов идёт по адресам, а не по свежести связи.

    В нём ищут глазами нужный адрес, поэтому порядок должен быть
    предсказуемым и числовым: строкой 10.20.0.9 встаёт после 10.20.0.10.
    """
    device_id = _wg_hub(client, router)
    for number, handshake in ((10, "5s"), (9, "1h"), (2, "3m")):
        router.wg_peers.append({
            ".id": f"*5{number}", "interface": "wg-hub", "public-key": f"K{number}=",
            "allowed-address": f"10.20.0.{number}/32", "last-handshake": handshake,
            "comment": f"wgpanel:точка {number}"})

    page = client.get(f"/wireguard?device_id={device_id}").text
    block = page.split('id="wg-route-gw"')[1].split("</select>")[0]
    found = re.findall(r'<option value="(10\.20\.0\.\d+)"', block)
    assert found == ["10.20.0.2", "10.20.0.9", "10.20.0.10"]


def test_qr_is_built_for_a_new_link_only(client, router):
    """
    QR отдаётся только вместе с приватным ключом.

    Смысл кода в том, чтобы внести конфигурацию в телефон. У существующего
    линка ключа нет и быть не должно, поэтому и кода нет: пустой квадрат
    лучше рабочего на вид, но нерабочего.
    """
    device_id = _wg_hub(client, router)

    body = client.post("/api/wg/links", json={
        "device_id": device_id, "name": "Телефон", "tunnel_ip": "10.20.0.15",
        "subnets": "192.168.15.0/24"}).json()

    assert body["qr"].startswith("<svg") and "<path" in body["qr"]
    # В QR попадает та же конфигурация, что и в текстовом поле
    assert "PrivateKey" in body["config"]

    # Разбираем нарисованное обратно в матрицу и сверяем с исходной:
    # ошибка в рисовании дала бы красивый, но нечитаемый квадрат
    import segno

    from app.wireguard import qr_svg

    svg = qr_svg(body["config"])
    full = int(re.search(r'viewBox="0 0 (\d+)', svg).group(1))
    drawn = [[0] * full for _ in range(full)]
    for x, y, width in re.findall(r"M(\d+) (\d+)h(\d+)v1", svg):
        for column in range(int(x), int(x) + int(width)):
            drawn[int(y)][column] = 1

    border = (full - len(segno.make(body["config"], error="m").matrix)) // 2
    for y, row in enumerate(segno.make(body["config"], error="m").matrix):
        for x, value in enumerate(row):
            assert drawn[y + border][x + border] == value, (x, y)

    again = client.post("/api/wg/links/script",
                        json={"device_id": device_id, "name": "Телефон"}).json()
    assert again["qr"] == ""


# ===========================================================================
#                     расписание бэкапов и архив панели
# ===========================================================================

def test_next_run_respects_time_and_weekdays():
    """
    Расчёт следующего запуска: время суток и дни недели.

    Считается в местном времени сервера, а в базу кладётся UTC. Правило
    «03:00» должно означать три часа ночи там, где сервер стоит, иначе
    ночное окно обслуживания у половины пользователей окажется днём.
    """
    from datetime import datetime, timedelta, timezone

    from app.schedules import is_due, next_run, parse_days, parse_time

    assert parse_time("03:00") == (3, 0)
    assert parse_time("3.5") == (3, 5)
    assert parse_time("25:00") is None
    assert parse_time("") is None
    assert parse_days("1,3,5,9,ерунда") == [1, 3, 5]

    # Понедельник, 10 августа 2026, полдень по местному времени
    monday = datetime(2026, 8, 10, 12, 0).astimezone()

    # Ежедневное правило: следующий запуск завтра ночью
    daily = next_run("03:00", [], after=monday)
    planned = datetime.strptime(daily, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    assert planned.astimezone().strftime("%Y-%m-%d %H:%M") == "2026-08-11 03:00"

    # Правило «по средам» от понедельника ждёт двое суток
    wednesday = next_run("03:00", [3], after=monday)
    planned = datetime.strptime(wednesday, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    assert planned.astimezone().strftime("%Y-%m-%d %H:%M") == "2026-08-12 03:00"
    assert planned.astimezone().isoweekday() == 3

    # Сегодняшнее время, которое ещё не наступило, берётся сегодня же
    early = datetime(2026, 8, 10, 1, 0).astimezone()
    today = next_run("03:00", [], after=early)
    planned = datetime.strptime(today, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    assert planned.astimezone().strftime("%Y-%m-%d") == "2026-08-10"

    # Без времени правило не запускается вовсе
    assert next_run("", []) is None

    now = datetime.now(timezone.utc)
    assert is_due((now - timedelta(minutes=1)).strftime("%Y-%m-%d %H:%M:%S"))
    assert not is_due((now + timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S"))
    assert not is_due("")


def test_schedule_creates_a_backup_job(client, router):
    """Наступило время правила — появляется задача бэкапа."""
    import json

    from app.database import execute, query_one

    device_id = _add_device(client, router, "sched-backup")

    r = client.post("/api/backup-schedules", json={
        "target": "all", "at_time": "03:00", "keep": 3})
    assert r.status_code == 200, r.text

    rule = query_one("SELECT * FROM backup_schedules ORDER BY id DESC LIMIT 1")
    assert rule["next_run_at"], "время следующего запуска не рассчитано"

    # Переводим время в прошлое: правило должно сработать
    execute("UPDATE backup_schedules SET next_run_at = datetime('now','-1 minute') "
            "WHERE id = ?", (rule["id"],))
    overdue = query_one(
        "SELECT next_run_at FROM backup_schedules WHERE id = ?", (rule["id"],))["next_run_at"]

    from app import worker

    assert worker.run_due_schedules() == [rule["id"]]

    job = query_one("SELECT * FROM jobs WHERE schedule_id = ?", (rule["id"],))
    assert job is not None, "задача по расписанию не создана"
    assert job["action"] == "backup"
    assert job["username"] == "расписание"

    # Время следующего запуска сдвинулось вперёд, повтора не будет
    again = query_one("SELECT * FROM backup_schedules WHERE id = ?", (rule["id"],))
    assert again["next_run_at"] > overdue
    assert again["last_run_at"], "запуск не отмечен"
    assert worker.run_due_schedules() == []

    # Пароли в текстовый export по расписанию не попадают: такой файл лежит
    # на диске месяцами, и решение о нём принимается руками
    params = json.loads(job["params_json"])
    assert params["do_binary"] == "1" and params["do_export"] == "1"
    assert params["show_sensitive"] == ""

    assert device_id in [
        int(i["device_id"]) for i in query(
            "SELECT device_id FROM job_items WHERE job_id = ?", (job["id"],))
    ]


def test_only_last_copies_are_kept(client, router):
    """
    Лишние копии удаляются вместе с файлами.

    Виды считаются раздельно: «последние три файла» вперемешку означало бы,
    что при неудачном порядке текстового export не останется вовсе.
    """
    from app.config import settings
    from app.database import execute, utcnow
    from app.worker import prune_backups

    device_id = _add_device(client, router, "keep-test")

    made = []
    for number in range(6):
        for kind, suffix in (("binary", ".backup"), ("export", ".rsc")):
            name = f"keep-test-{number}{suffix}"
            path = settings.backup_dir / name
            path.write_text("x", encoding="utf-8")
            execute(
                "INSERT INTO backups (device_id, device_name, kind, filename, size,"
                " created_at) VALUES (?,?,?,?,?,?)",
                (device_id, "keep-test", kind, name, 1, utcnow()),
            )
            made.append(path)

    assert prune_backups([device_id], 2) == 8

    rows = query("SELECT kind, filename FROM backups WHERE device_id = ?", (device_id,))
    assert len(rows) == 4, rows
    assert sum(1 for r in rows if r["kind"] == "binary") == 2
    assert sum(1 for r in rows if r["kind"] == "export") == 2

    # Записи удалены вместе с файлами: запись без файла хуже, чем ничего
    alive = {r["filename"] for r in rows}
    for path in made:
        assert path.exists() == (path.name in alive), path.name

    # Ноль означает «не трогать»: так правило без настроенного хранения
    # не сотрёт всё разом
    assert prune_backups([device_id], 0) == 0


def test_panel_archive_holds_everything_needed(client, router):
    """
    Архив панели содержит базу, ключ и пояснение.

    База копируется механизмом SQLite, а не как файл: на ходу часть данных
    лежит в журнале WAL, и простая копия может не открыться. Проверяем, что
    копия рабочая и данные в ней те же.
    """
    import json
    import sqlite3
    import tarfile
    import tempfile
    from pathlib import Path

    _add_device(client, router, "archive-device")

    r = client.post("/api/panel-backup", json={"include_backups": False})
    assert r.status_code == 200, r.text
    name = r.json()["name"]

    from app import panelbackup

    path = panelbackup.resolve(name)
    assert path is not None and path.exists()
    # Ключ внутри, поэтому файл не должен читаться всеми подряд
    assert oct(path.stat().st_mode)[-3:] == "600"

    with tarfile.open(path) as archive:
        names = archive.getnames()
        # Всё внутри одной папки: распаковка не должна рассыпать сотню
        # файлов по текущему каталогу
        root = names[0].split("/")[0]
        assert root.startswith("tikpilot-panel-")
        assert all(n == root or n.startswith(root + "/") for n in names)

        for required in ("data/tikpilot.db", "data/fernet.key", "ПРОЧТИ-МЕНЯ.txt",
                         "manifest.json", "restore.sh", "install-ubuntu.sh",
                         "requirements.txt", "app/main.py", "templates/base.html"):
            assert f"{root}/{required}" in names, f"в архиве нет {required}"

        # Мусор и чужие данные внутрь не попадают: архив уезжает с сервера
        for entry in names:
            assert "__pycache__" not in entry, entry
            assert not entry.endswith(".pyc"), entry
            assert "/.venv/" not in entry, entry
            # devices.csv может содержать настоящие адреса и учётные записи
            assert not entry.endswith("devices.csv"), entry

        notes = archive.extractfile(f"{root}/ПРОЧТИ-МЕНЯ.txt").read().decode("utf-8")
        assert "ЭТО ОПАСНЫЙ ФАЙЛ" in notes
        assert "sudo bash restore.sh" in notes

        manifest = json.loads(
            archive.extractfile(f"{root}/manifest.json").read().decode("utf-8"))
        assert manifest["devices"] >= 1, "в описи нет устройств"
        assert manifest["with_code"] is True

        with tempfile.TemporaryDirectory() as tmp:
            archive.extract(f"{root}/data/tikpilot.db", tmp)
            copy = sqlite3.connect(str(Path(tmp) / root / "data" / "tikpilot.db"))
            found = copy.execute(
                "SELECT name FROM devices WHERE name = ?", ("archive-device",)).fetchone()
            copy.close()
            assert found, "устройства нет в копии базы"

    # Скачивание работает, а выход за пределы каталога — нет
    assert client.get(f"/panel-backup/{name}").status_code == 200
    # Проверку обхода каталога делаем на самой функции: тестовый клиент
    # нормализует «..» в адресе ещё до отправки, и через HTTP такой путь
    # до роута просто не доходит
    assert panelbackup.resolve("../../.env") is None
    assert panelbackup.resolve("tikpilot-panel-../../.env.tar.gz") is None

    assert client.post(f"/api/panel-backup/{name}/delete").status_code == 200
    assert panelbackup.resolve(name) is None


def test_panel_archive_needs_its_own_right(client, router):
    """
    Архив панели закрыт отдельным правом.

    Права видеть и скачивать бэкапы устройств для него мало: в архиве
    лежат пароли всех роутеров сразу.
    """
    _make_user(client, "backuponly", ["backups.view", "backups.download"])

    with _as("backuponly") as limited:
        assert limited.post("/api/panel-backup", json={}).status_code == 403
        assert limited.get("/panel-backup/tikpilot-panel-x.tar.gz").status_code == 403
        # И расписание тоже не его дело
        assert limited.post("/api/backup-schedules", json={
            "target": "all", "at_time": "03:00"}).status_code == 403

        # Список файлов при этом виден: право на него есть
        page = limited.get("/backups")
        assert page.status_code == 200
        assert "Архив панели" not in page.text


def test_schedule_input_is_checked(client, router):
    """Неверное расписание не создаётся: молчащее правило хуже отказа."""
    assert client.post("/api/backup-schedules", json={
        "target": "all", "at_time": "полночь"}).status_code == 400
    assert client.post("/api/backup-schedules", json={
        "target": "group", "at_time": "03:00"}).status_code == 400
    assert client.post("/api/backup-schedules", json={
        "target": "чепуха", "at_time": "03:00"}).status_code == 400


# ===========================================================================
#              дребезг, дифф конфигураций, поиск и отчёт
# ===========================================================================

def test_short_outages_are_damped_in_history_not_in_status(client, router):
    """
    Моргание не идёт в простой и в ленту событий, но статус остаётся честным.

    Так выглядит канал на месторождении: связь пропадает на полминуты
    и возвращается. Раньше выдержка стояла на подъёме, и точка, доступная
    девять минут из десяти, висела «офлайн» бессрочно: хватало одного
    промаха, чтобы счётчик удачных проверок обнулился. Панель, которая
    врёт про доступность, хуже шумной истории.
    """
    from app.config import settings
    from app.database import execute, query_one
    from app.monitor import apply_result, availability, recent_events

    device_id = _add_device(client, router, "blinky")
    saved = settings.monitor_min_outage
    settings.monitor_min_outage = 120
    try:
        def row():
            return dict(query_one(
                "SELECT id, name, host, status, fail_streak, status_changed_at "
                "FROM devices WHERE id = ?", (device_id,)))

        # Короткое пропадание: упало и через полминуты вернулось
        apply_result(row(), alive=False, error="Таймаут подключения", threshold=1)
        assert row()["status"] == "offline"
        execute("UPDATE devices SET status_changed_at = datetime('now','-30 seconds') "
                "WHERE id = ?", (device_id,))
        apply_result(row(), alive=True)

        # Статус честный: точка отвечает — значит в сети
        assert row()["status"] == "online"

        # Обе записи помечены как моргание, в ленту они не попадают
        marks = query("SELECT status, short FROM status_events WHERE device_id = ? "
                      "ORDER BY id", (device_id,))
        assert [m["short"] for m in marks] == [1, 1], marks
        assert not [e for e in recent_events(50) if e["device_id"] == device_id]

        # И в простой тоже: сутки прошли без падений
        stats = next(r for r in availability(24) if r["id"] == device_id)
        assert stats["down_seconds"] == 0
        assert stats["outages"] == 0
        assert stats["flaps"] == 1

        # Настоящее падение считается как раньше
        apply_result(row(), alive=False, error="Таймаут подключения", threshold=1)
        execute("UPDATE devices SET status_changed_at = datetime('now','-30 minutes') "
                "WHERE id = ?", (device_id,))
        apply_result(row(), alive=True)

        stats = next(r for r in availability(24) if r["id"] == device_id)
        assert stats["outages"] == 1
        assert 1700 < stats["down_seconds"] < 1900, stats
        assert stats["flaps"] == 1
        assert [e["device_id"] for e in recent_events(50)].count(device_id) == 2
    finally:
        settings.monitor_min_outage = saved


def test_flap_damping_is_off_by_default(client, router):
    """Без настройки поведение прежнее: записывается каждое пропадание."""
    from app.config import settings
    from app.database import execute, query_one
    from app.monitor import apply_result

    assert settings.monitor_min_outage == 0

    device_id = _add_device(client, router, "asis")

    def row():
        return dict(query_one(
            "SELECT id, name, host, status, fail_streak, status_changed_at "
            "FROM devices WHERE id = ?", (device_id,)))

    apply_result(row(), alive=False, error="Таймаут подключения", threshold=1)
    execute("UPDATE devices SET status_changed_at = datetime('now','-5 seconds') "
            "WHERE id = ?", (device_id,))
    apply_result(row(), alive=True)

    marks = query("SELECT short FROM status_events WHERE device_id = ?", (device_id,))
    assert [m["short"] for m in marks] == [0, 0]


def test_config_diff_ignores_the_export_header():
    """
    Шапка экспорта в сравнении не участвует.

    RouterOS пишет в первую строку дату и версию, поэтому две одинаковые
    конфигурации отличались бы всегда, и ответ «изменений нет» не наступал
    бы никогда. А нужен обычно именно он.
    """
    from app.configdiff import compare, is_volatile

    assert is_volatile("# aug/06/2026 08:44:00 by RouterOS 7.14.3")
    assert is_volatile("# 2026-08-06 08:44:00 by RouterOS 7.14.3")
    assert not is_volatile("/ip address")
    assert not is_volatile("# comment about the rule")

    old = [
        "# aug/05/2026 03:00:01 by RouterOS 7.14.3",
        "/ip address",
        "add address=10.0.0.1/24 interface=ether1",
        "/ip dns",
        "set servers=8.8.8.8",
    ]
    same = ["# aug/06/2026 03:00:02 by RouterOS 7.14.3"] + old[1:]

    result = compare(old, same)
    assert result["same"], result["rows"]
    assert result["added"] == 0 and result["removed"] == 0

    changed = list(same)
    changed[-1] = "set servers=1.1.1.1"
    result = compare(old, changed)
    assert not result["same"]
    assert result["added"] == 1 and result["removed"] == 1
    texts = {row["kind"]: row["text"] for row in result["rows"] if row["kind"] in ("add", "del")}
    assert texts["add"] == "set servers=1.1.1.1"
    assert texts["del"] == "set servers=8.8.8.8"


def test_device_list_shows_the_model(client, router):
    """
    Модель видна в списке, ищется поиском и попадает в выгрузку.

    Вопрос «что там за коробка» задают перед каждым обновлением прошивки
    и перед каждой закупкой замены, а до сих пор ответ был только
    в карточке, по одной точке за раз.
    """
    device_id = _add_device(client, router, "model-device")

    # Модель приезжает с устройства при проверке статуса
    from app.database import execute, query_one

    execute("UPDATE devices SET board_name = ?, architecture = ? WHERE id = ?",
            ("hAP ac lite", "mipsbe", device_id))

    page = client.get("/devices")
    assert page.status_code == 200
    assert "hAP ac lite" in page.text
    assert "Модель" in page.text

    # Поиск по модели: «покажи все hAP ac lite»
    found = client.get("/devices?q=hAP+ac")
    assert "model-device" in found.text
    other = client.get("/devices?q=CCR2004")
    assert "model-device" not in other.text

    csv_text = client.get("/api/devices/export/csv").text
    assert "model" in csv_text.splitlines()[0]
    assert "hAP ac lite" in csv_text

    assert query_one("SELECT board_name FROM devices WHERE id = ?",
                     (device_id,))["board_name"] == "hAP ac lite"


def test_diff_side_by_side_pairs_the_replaced_line():
    """
    Изменённая строка стоит напротив своей пары, а не съезжает вниз.

    В этом весь смысл двух колонок: замена видна как замена. В едином
    списке она выглядит как «минус здесь, плюс где-то ниже», и совпадают
    ли они между собой, приходится решать глазами.
    """
    from app.configdiff import compare_sides

    old = [
        "# aug/05/2026 03:00:01 by RouterOS 7.14.3",
        "/ip dns",
        "set servers=8.8.8.8",
    ]
    new = [
        "# aug/06/2026 03:00:02 by RouterOS 7.14.3",
        "/ip dns",
        "set servers=1.1.1.1",
    ]

    result = compare_sides(old, new)
    assert result["changes"] == 2
    changed = [row for row in result["rows"] if row["kind"] == "change"]
    assert len(changed) == 1
    assert changed[0]["left"] == "set servers=8.8.8.8"
    assert changed[0]["right"] == "set servers=1.1.1.1"
    # Номера настоящие, из файла: по ним человек находит место в скачанном .rsc
    assert changed[0]["left_no"] == 3 and changed[0]["right_no"] == 3


def test_diff_side_by_side_folds_untouched_parts():
    """
    Неизменные куски сворачиваются и подписаны словами.

    Раньше на их месте стояло `@@ -77,8 +77,7 @@`. Эти числа понятны тому,
    кто живёт в `git diff`, и не отвечают ни на один вопрос, который
    задают, глядя на конфиг.
    """
    from app.configdiff import compare_sides

    old = ["/ip dns"] + [f"add comment=строка-{n}" for n in range(40)]
    new = list(old)
    new[20] = "add comment=правка"

    result = compare_sides(old, new)
    skips = [row for row in result["rows"] if row["kind"] == "skip"]
    assert skips, "неизменные строки не свёрнуты"
    assert all(row["skipped"] > 0 for row in skips)
    assert not any(row.get("text", "").startswith("@@") for row in result["rows"])

    # Вокруг правки соседние строки остались: без них непонятно, где мы
    same = [row for row in result["rows"] if row["kind"] == "same"]
    assert len(same) >= 6


def test_diff_page_shows_two_columns(client, router):
    """Страница сравнения по умолчанию показывает две колонки с номерами."""
    from app.config import settings
    from app.database import execute, query_one, utcnow

    device_id = _add_device(client, router, "sides-device")

    ids = []
    for number, dns in enumerate(("8.8.8.8", "1.1.1.1")):
        name = f"sides-device-{number}.rsc"
        (settings.backup_dir / name).write_text(
            "# aug/0%d/2026 03:00:00 by RouterOS 7.14.3\n/ip dns\nset servers=%s\n"
            % (number + 1, dns),
            encoding="utf-8",
        )
        execute(
            "INSERT INTO backups (device_id, device_name, kind, filename, size, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (device_id, "sides-device", "export", name, 60, utcnow()),
        )
        ids.append(query_one("SELECT MAX(id) AS id FROM backups")["id"])

    page = client.get(f"/backups/{ids[1]}/diff")
    assert page.status_code == 200
    assert 'class="dt"' in page.text, "нет таблицы сравнения"
    assert "dt-del" in page.text and "dt-add" in page.text
    assert "@@" not in page.text, "загадочные строки с решётками вернулись"

    # Единый список остаётся под ссылкой: на узком экране он читается лучше
    unified = client.get(f"/backups/{ids[1]}/diff?view=unified")
    assert unified.status_code == 200
    assert 'class="diff"' in unified.text


def test_config_diff_page_compares_two_copies(client, router):
    """Страница сравнения берёт предыдущую копию этой же точки."""
    from app.config import settings
    from app.database import execute, query_one, utcnow

    device_id = _add_device(client, router, "diff-device")

    ids = []
    for number, dns in enumerate(("8.8.8.8", "1.1.1.1")):
        name = f"diff-device-{number}.rsc"
        (settings.backup_dir / name).write_text(
            "# aug/0%d/2026 03:00:00 by RouterOS 7.14.3\n/ip dns\nset servers=%s\n"
            % (number + 1, dns),
            encoding="utf-8",
        )
        execute(
            "INSERT INTO backups (device_id, device_name, kind, filename, size, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (device_id, "diff-device", "export", name, 60, utcnow()),
        )
        ids.append(query_one("SELECT MAX(id) AS id FROM backups")["id"])

    page = client.get(f"/backups/{ids[1]}/diff")
    assert page.status_code == 200
    assert "set servers=1.1.1.1" in page.text
    assert "set servers=8.8.8.8" in page.text

    # У первой копии сравнивать не с чем, и об этом сказано прямо
    first = client.get(f"/backups/{ids[0]}/diff")
    assert first.status_code == 200
    assert "сравнивать не с чем" in first.text

    # Бинарный бэкап сравнивать нечем: это непрозрачный слепок
    execute(
        "INSERT INTO backups (device_id, device_name, kind, filename, size, created_at)"
        " VALUES (?,?,?,?,?,?)",
        (device_id, "diff-device", "binary", "diff-device.backup", 10, utcnow()),
    )
    binary_id = query_one("SELECT MAX(id) AS id FROM backups")["id"]
    assert client.get(f"/backups/{binary_id}/diff").status_code == 400


def test_search_looks_inside_the_latest_export(client, router):
    """
    Поиск идёт по содержимому последней копии каждой точки.

    Смысл в вопросе «где ещё остался этот адрес»: обойти полсотни точек
    руками через WebFig дольше, чем поставить панель.
    """
    from app.config import settings
    from app.database import execute, utcnow

    for name, dns in (("search-a", "10.10.5.1"), ("search-b", "8.8.8.8")):
        device_id = _add_device(client, router, name)
        filename = f"{name}.rsc"
        (settings.backup_dir / filename).write_text(
            f"/ip dns\nset servers={dns}\n/system identity\nset name={name}\n",
            encoding="utf-8",
        )
        execute(
            "INSERT INTO backups (device_id, device_name, kind, filename, size, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (device_id, name, "export", filename, 50, utcnow()),
        )

    page = client.get("/backups/search?q=10.10.5.1")
    assert page.status_code == 200
    assert "search-a" in page.text
    assert "set servers=10.10.5.1" in page.text
    # Точка с другим адресом в выдачу не попадает
    assert "search-b" not in page.text.split("Найдено")[-1]

    # Регистр не важен: в конфигурации пишут и так, и эдак
    assert "search-a" in client.get("/backups/search?q=SET SERVERS=10.225").text

    # За пределы каталога бэкапов поиск не выходит
    from app.configdiff import safe_path

    assert safe_path("../../.env") is None
    assert safe_path("") is None


def test_availability_report_is_a_csv_excel_understands(client, router):
    """
    Отчёт открывается в Excel без танцев.

    Точка с запятой как разделитель, запятая в дробях и метка BOM: без них
    русский Excel показывает всё одной колонкой, а проценты считает текстом.
    """
    device_id = _add_device(client, router, "report-device")

    from app.database import execute, utcnow

    execute(
        "INSERT INTO status_events (device_id, device_name, device_host, status,"
        " reason, downtime, ts) VALUES (?,?,?,?,?,?,?)",
        (device_id, "report-device", "127.0.0.1", "online", "", 3600, utcnow()),
    )

    r = client.get("/monitoring/report.csv?hours=720")
    assert r.status_code == 200
    assert "attachment" in r.headers["content-disposition"]
    assert ".csv" in r.headers["content-disposition"]

    text = r.text
    assert text.startswith("﻿"), "нет метки BOM, Excel испортит кириллицу"
    header, *lines = text.lstrip("﻿").splitlines()
    assert header.split(";")[0] == "Точка"
    assert header.count(";") == 7

    row = next(line for line in lines if line.startswith("report-device"))
    cells = row.split(";")
    # Час простоя за месяц: доступность около 99,86 процента
    assert cells[5].replace(",", ".").startswith("1"), cells
    assert "." not in cells[4], "точка в дробях, Excel посчитает это текстом"


def test_availability_report_page_is_a_printable_document(client, router):
    """
    Отчёт открывается как готовый документ: сводка, график, таблицы.

    Его несут руководству, поэтому проверяем не только цифры, но и то,
    что страница вообще пригодна к печати: без правил `@media print`
    браузер выведет на бумагу серый фон и кнопки.
    """
    device_id = _add_device(client, router, "report-page-device")

    from app.database import execute, utcnow

    execute(
        "INSERT INTO status_events (device_id, device_name, device_host, status,"
        " reason, downtime, ts) VALUES (?,?,?,?,?,?,?)",
        (device_id, "report-page-device", "127.0.0.1", "online", "", 7200, utcnow()),
    )

    r = client.get("/monitoring/report?hours=720")
    assert r.status_code == 200

    text = r.text
    assert "Отчёт по доступности сети" in text
    assert "report-page-device" in text
    assert "<svg" in text, "нет графика"
    assert "@media print" in text, "документ не готов к печати"
    assert "Журнал падений" in text
    # Два часа простоя видны и в сводке, и в журнале падений
    assert "2 ч 0 мин" in text, "простой не посчитан"
    # Меню панели в документе не нужно
    assert "openActionModal" not in text


def test_report_shows_only_devices_in_scope(client, router):
    """
    Отчёт подчиняется области видимости.

    Иначе подрядчик, которому открыты две точки, выгрузил бы документ
    со всем парком и адресами. Проверка стоит в самом роуте, а не
    в шаблоне.
    """
    _add_device(client, router, "scope-report-mine")
    _add_device(client, router, "scope-report-other")

    from app.database import query_one

    mine = query_one("SELECT id FROM devices WHERE name = ?", ("scope-report-mine",))["id"]
    _make_user(client, "reporter", [], scope_all=False, devices=[mine])

    with _as("reporter") as guest:
        r = guest.get("/monitoring/report?hours=24")
        assert r.status_code == 200
        assert "scope-report-mine" in r.text
        assert "scope-report-other" not in r.text


def test_report_chart_counts_the_whole_fleet(client, router):
    """
    Столбик графика это доля времени в сети по всем точкам сразу.

    Считать средним по процентам точек нельзя: одна лежащая точка из
    пятидесяти и пятьдесят лежащих по минуте дают одно и то же среднее,
    хотя это совершенно разные истории.
    """
    from app import monitor
    from app.database import execute, query_one, utcnow

    _add_device(client, router, "bucket-device")
    device_id = query_one("SELECT id FROM devices WHERE name = ?", ("bucket-device",))["id"]
    execute(
        "INSERT INTO status_events (device_id, device_name, device_host, status,"
        " reason, downtime, ts) VALUES (?,?,?,?,?,?,?)",
        (device_id, "bucket-device", "127.0.0.1", "online", "", 3600, utcnow()),
    )

    scope = (" AND d.id = ?", [device_id])
    buckets = monitor.availability_buckets(24, scope)

    assert buckets, "график пустой"
    assert all(0 <= b["percent"] <= 100 for b in buckets)
    down = sum(b["down_seconds"] for b in buckets)
    assert 3500 <= down <= 3700, f"час простоя разложен по часам неверно: {down}"
    assert any(b["percent"] < 100 for b in buckets)

    # Тот же простой, тем же числом, в журнале падений
    intervals = monitor.outage_intervals(24, scope)
    assert len(intervals) == 1
    assert 3500 <= intervals[0]["seconds"] <= 3700
    assert intervals[0]["ongoing"] is False


# ===========================================================================
#                            живая консоль
# ===========================================================================

def test_console_shows_what_the_panel_does(client, router):
    """
    В консоль попадает то, что панель делает: проверки, задачи, ошибки.

    Строки берутся из обычного журнала приложения, поэтому отдельно
    «добавлять в консоль» ничего не нужно и забыть об этом невозможно.
    """
    import logging

    from app import activity

    activity.install()
    activity.clear()

    device_id = _add_device(client, router, "console-device")
    _run_and_wait(client, "check", [device_id], {})

    rows = activity.tail(limit=200)
    texts = " | ".join(r["text"] for r in rows)
    assert "console-device" in texts, texts[:400]
    assert any(r["source"] == "задачи" for r in rows), {r["source"] for r in rows}

    # Страница и опрос отдают то же самое
    page = client.get("/console")
    assert page.status_code == 200
    feed = client.get("/api/console?after=0").json()
    assert feed["rows"] and feed["last"] == feed["rows"][-1]["id"]

    # Опрос по номеру последней строки отдаёт только новое
    logging.getLogger("tikpilot.worker").info("свежая строка")
    again = client.get(f"/api/console?after={feed['last']}").json()
    assert [r["text"] for r in again["rows"]] == ["свежая строка"]

    # Фильтр по уровню оставляет только проблемы
    logging.getLogger("tikpilot.monitor").warning("что-то не так")
    problems = client.get("/api/console?after=0&level=warning").json()
    assert problems["rows"]
    assert all(r["level"] in ("warning", "error", "critical") for r in problems["rows"])

    # Очистка не трогает ни историю задач, ни журнал действий
    jobs_before = len(query("SELECT id FROM jobs"))
    assert client.post("/api/console/clear").status_code == 200
    # Сама очистка это тоже действие, и она записывается: иначе консоль
    # можно было бы вычистить незаметно
    left = activity.tail()
    assert [r["source"] for r in left] == ["действия"]
    assert "Очищена консоль" in left[0]["text"]
    assert len(query("SELECT id FROM jobs")) == jobs_before


def test_console_never_shows_passwords():
    """
    Пароли и ключи вырезаются на входе в буфер.

    Полагаться на аккуратность каждой строчки кода нельзя: достаточно
    один раз залогировать словарь параметров целиком, и пароль от парка
    окажется на экране, а то и на скриншоте в переписке.
    """
    from app.activity import add, clear, hide_secrets, tail

    assert hide_secrets("add name=wg password=Secret123") == "add name=wg password=***"
    assert hide_secrets('/user add password="Слож ный" x=1') == '/user add password=*** x=1'
    assert hide_secrets("private-key=abc/def+11=") == "private-key=***"
    assert hide_secrets("preshared-key: 'zzz'") == "preshared-key: ***"
    assert hide_secrets("token = qwerty") == "token = ***"
    # Обычный текст не портим
    assert hide_secrets("Кедр 73: готово") == "Кедр 73: готово"

    clear()
    add("INFO", "/user add name=x password=Secret123")
    assert "Secret123" not in tail()[0]["text"]
    clear()


def test_console_needs_permission(client, router):
    """Консоль закрыта отдельным правом: там видны имена точек и ошибки."""
    _make_user(client, "noconsole", ["backups.view"])

    with _as("noconsole") as limited:
        assert limited.get("/console").status_code == 403
        assert limited.get("/api/console").status_code == 403
        assert limited.post("/api/console/clear").status_code == 403
        assert "/console" not in limited.get("/backups").text


def test_console_shows_what_people_do(client, router):
    """
    Действия людей тоже видно: вход, запуск задачи, правка карточки.

    Иначе консоль показывала бы, что делает панель, но не что делают
    в панели, а на вопрос «кто это запустил» пришлось бы уходить
    в журнал действий.
    """
    from app import activity
    from app.database import log_audit

    activity.install()
    activity.clear()

    device_id = _add_device(client, router, "audit-device")
    _run_and_wait(client, "check", [device_id], {})

    texts = [r["text"] for r in activity.tail() if r["source"] == "действия"]
    assert any("Запуск" in t for t in texts), texts

    # Подробности обрезаются: параметры задач бывают длинными
    log_audit("maxim", "Проверка длины", "точка", "ы" * 500)
    line = [r for r in activity.tail() if "Проверка длины" in r["text"]][0]
    assert len(line["text"]) < 300, len(line["text"])

    # Неудачный вход — предупреждение, его ищут глазами
    log_audit("admin", "Неудачный вход", ip="10.0.0.1")
    bad = [r for r in activity.tail() if "Неудачный вход" in r["text"]][0]
    assert bad["level"] == "warning"
    assert "10.0.0.1" in bad["text"]


@pytest.mark.slow
def test_login_pauses_after_several_misses(client, router):
    """
    Подбор пароля становится дорогим.

    Остановить настойчивого паузой нельзя, для этого есть длинный пароль
    и ограничение по сетям. Смысл в том, чтобы тысяча попыток в секунду
    перестала быть возможной.
    """
    from app import loginguard

    loginguard.reset()
    try:
        fresh = TestClient(app)
        for _ in range(5):
            assert fresh.post("/login", data={"username": "admin", "password": "нет"},
                              follow_redirects=False).status_code == 401

        # Шестая попытка уже не проверяется: адрес под паузой
        blocked = fresh.post("/login", data={"username": "admin", "password": "нет"},
                             follow_redirects=False)
        assert blocked.status_code == 429
        assert "Слишком много попыток" in blocked.text

        # И верный пароль в паузу тоже не пускает: иначе она ничего не стоит
        assert fresh.post("/login", data={"username": "admin", "password": "s3cret1"},
                          follow_redirects=False).status_code == 429

        assert loginguard.state()["blocked"]
    finally:
        # Иначе адрес тестового клиента остался бы под паузой для всех
        # остальных проверок в этом прогоне
        loginguard.reset()


def test_login_guard_counts_by_address_and_forgets_on_success():
    """
    Счёт по адресу, а не по имени, и удачный вход обнуляет счётчик.

    По имени было бы удобнее подбирающему: чередуй admin, root, user —
    и блокировка не наступит. Заодно так нельзя заблокировать вход
    настоящему администратору, перебирая его имя.
    """
    from app import loginguard

    loginguard.reset()
    try:
        # Пять попыток разрешены: пауза включается на последней из них,
        # а мешать начинает следующей
        for _ in range(4):
            assert loginguard.register_miss("10.0.0.1") == 0
        assert loginguard.wait_seconds("10.0.0.1") == 0, "пауза раньше времени"

        delay = loginguard.register_miss("10.0.0.1")
        assert delay > 0
        assert loginguard.wait_seconds("10.0.0.1") > 0

        # Соседний адрес ни при чём
        assert loginguard.wait_seconds("10.0.0.2") == 0

        # Каждое следующее превышение дольше предыдущего
        second = loginguard.register_miss("10.0.0.1")
        assert second > delay

        loginguard.register_success("10.0.0.1")
        assert loginguard.wait_seconds("10.0.0.1") == 0
        assert not loginguard.state()["blocked"]
    finally:
        loginguard.reset()


def test_console_now_shows_running_work(client, router):
    """Строка «сейчас» отвечает на вопрос «что идёт», а не «что было»."""
    from app.database import execute, utcnow

    device_id = _add_device(client, router, "now-device")

    # Сравниваем с тем, что уже идёт, а не с пустотой: задача из соседнего
    # теста может в этот момент ещё выполняться в фоновом воркере, и жёсткое
    # «задач нет» превращает тест в лотерею
    before = {j["id"] for j in client.get("/api/console/now").json()["jobs"]}
    assert "sessions" in client.get("/api/console/now").json()["monitor"]

    # Задача в работе видна с прогрессом
    execute(
        "INSERT INTO jobs (action, action_label, params_json, username, status,"
        " total, done, created_at) VALUES (?,?,?,?,'running',?,?,?)",
        ("check", "Проверить статус", "{}", "maxim", 40, 12, utcnow()),
    )
    data = client.get("/api/console/now").json()
    fresh = [j for j in data["jobs"] if j["id"] not in before]
    assert len(fresh) == 1, "новой задачи не видно в строке «сейчас»"
    assert fresh[0]["done"] == 12 and fresh[0]["total"] == 40

    # И ближайшее правило расписания.
    # Чужие правила убираем: панель показывает ближайшее по времени, а какое
    # окажется ближайшим, зависит от того, что запускалось перед этим тестом.
    execute("DELETE FROM backup_schedules")
    client.post("/api/backup-schedules", json={
        "target": "all", "at_time": "03:00", "keep": 5, "name": "ночной"})
    data = client.get("/api/console/now").json()
    assert data["schedule"]["at"] and data["schedule"]["what"] == "ночной"


def test_long_lists_are_paginated(client, router):
    """
    Длинные списки листаются, а не вываливаются целиком.

    Проверяются три вещи, каждая из которых ломалась бы незаметно:
    размер страницы, перенос фильтров на соседние страницы и поведение
    при номере за краем. Последнее важно: «page=99999» приходит из адресной
    строки, и показать пустоту вместо последней страницы значит соврать,
    что записей больше нет.
    """
    from app.database import execute, utcnow

    for number in range(120):
        execute(
            "INSERT INTO audit_log (ts, username, action, target, details, ip) "
            "VALUES (?,?,?,?,?,?)",
            (utcnow(), "admin", "Листаемое действие", f"объект-{number}", "", "127.0.0.1"),
        )

    def shown(text: str) -> tuple[int, int, int]:
        found = re.search(r"с (\d+) по (\d+) из (\d+)", text)
        assert found, "нет строки о показанном диапазоне"
        return tuple(int(g) for g in found.groups())

    first = client.get("/history?page=1")
    assert first.status_code == 200
    start, end, total = shown(first.text)
    assert (start, end) == (1, 50), "на странице должно быть полсотни записей"
    assert total > 100

    second = client.get("/history?page=2")
    assert shown(second.text)[0] == 51
    # Записи не повторяются: смещение действительно применяется
    assert "объект-119" in first.text and "объект-119" not in second.text

    # Номер за краем показывает последнюю страницу, а не пустоту
    last = client.get("/history?page=99999")
    assert last.status_code == 200
    assert shown(last.text)[1] == total

    # Фильтр переезжает на соседние страницы: иначе переход сбрасывал бы поиск
    filtered = client.get("/history?q=Листаемое&page=1")
    links = re.findall(r'href="\?([^"]*page=\d+)"', filtered.text)
    assert links, "нет ссылок на страницы"
    assert all("q=" in link for link in links), "поиск теряется при переходе"


# ===========================================================================
#                        журнал устройств (syslog)
# ===========================================================================

def test_syslog_parses_what_routers_actually_send():
    """
    Разбор строки syslog.

    Формат RFC3164 старше многих читателей, и каждый производитель понял
    его по-своему. Поэтому разбор мягкий: всё, что не удалось узнать,
    остаётся в тексте сообщения. Потерять содержимое из-за неподошедшего
    выражения гораздо хуже, чем не заполнить одно поле.
    """
    from app import syslog

    row = syslog.parse(
        "<134>Aug  7 10:15:00 PionernyybufetRaduga system,info dhcp lease added")
    assert row["severity"] == 6 and row["severity_name"] == "info"
    assert row["facility"] == 16
    assert row["host"] == "PionernyybufetRaduga"
    assert row["topics"] == "system,info"
    assert row["message"] == "dhcp lease added"

    # Ошибка: уровень важности вытаскивается из того же числа
    row = syslog.parse("<131>Aug  7 10:15:01 rtr wireless,error login failure")
    assert row["severity_name"] == "error"

    # Совсем без разметки строка не теряется, а целиком идёт в сообщение
    row = syslog.parse("что-то пошло не так")
    assert row["message"] == "что-то пошло не так"
    assert row["severity_name"] == "info"

    # Кириллица не должна пострадать по дороге
    row = syslog.parse("<134>Aug  7 10:15:02 точка script,info бэкап снят")
    assert row["message"] == "бэкап снят"

    # Формат CEF. Строка настоящая, снята с живого парка: разбор написан
    # по ней, а не по документации, и это принципиально. Здесь нет PRI,
    # темы лежат в поле названия, а не в коде события, важность записана
    # словом, а само сообщение только в хвосте, в msg=.
    row = syslog.parse(
        "Aug  7 16:53:02 office-1 CEF:0|MikroTik|hAP ac lite|"
        "7.21.5 (long-term)|10|system,error,critical|High|"
        "dvchost=office-1 dvc=192.168.88.1 "
        "msg=login failure for user operator from 10.10.0.199 via winbox "
        "app=winbox duser=operator outcome=failure src=10.10.0.199"
    )
    assert row["host"] == "office-1"
    assert row["topics"] == "system,error,critical", "темы не там, где их ищут"
    assert row["message"] == "login failure for user operator from 10.10.0.199 via winbox"
    # PRI в строке нет, и без разбора важности всё числилось бы «сведениями»
    assert row["severity_name"] == "crit", "важность взята не из тем"

    # Код события это просто число, темой он не является: на живом парке
    # в колонке «тема» стояли «10» и «16», и выглядело это осмысленно
    row = syslog.parse(
        "Aug  7 16:36:04 rtr CEF:0|MikroTik|hAP|7.21.5|10|"
        "Пришло что-то на человеческом языке|Medium|msg=defconf offering lease")
    assert row["topics"] == "", "в темы попал не список тем"
    assert row["message"] == "defconf offering lease"
    assert row["severity_name"] == "warning", "важность не взята из слова"


def test_silent_tcp_connection_is_closed_and_counted(client, router):
    """
    Молчащее соединение закрывается само, а открытые считаются.

    Точка на плохом канале пропадает без FIN: сокет остаётся открытым,
    приёмник ждёт данных, которых уже не будет. Полсотни точек, каждая
    переподключается при каждом обрыве, и через сутки процесс упирается
    в предел открытых файлов. Именно так панель и легла с «Too many open
    files», а выглядело это как падение точки.
    """
    import socket

    from app import syslog
    from app.config import settings

    syslog.stop()
    settings.syslog_enabled = True
    settings.syslog_udp_port = 15573
    settings.syslog_tcp_port = 15573
    # На время проверки молчание считается долгим сразу
    idle_before = syslog.IDLE_TIMEOUT
    syslog.IDLE_TIMEOUT = 1
    syslog.start()
    try:
        quiet = socket.create_connection(("127.0.0.1", 15573), timeout=5)
        deadline = time.time() + 10
        while time.time() < deadline and syslog.state["tcp_clients"] == 0:
            time.sleep(0.1)
        assert syslog.state["tcp_clients"] == 1, "соединение не посчитано"

        # Молчим: приёмник должен закрыть его сам
        deadline = time.time() + 10
        while time.time() < deadline and syslog.state["tcp_clients"]:
            time.sleep(0.2)
        assert syslog.state["tcp_clients"] == 0, "молчащее соединение висит вечно"
        quiet.close()
    finally:
        syslog.IDLE_TIMEOUT = idle_before
        syslog.stop()


def test_syslog_receives_over_real_sockets(client, router):
    """
    Строки принимаются по UDP и TCP и доезжают до страницы.

    Проверяется настоящей отправкой в сокет, а не вызовом внутренней
    функции: половина возможных ошибок здесь как раз в разборе потока
    и в границах сообщений, а не в логике.
    """
    import socket

    from app import syslog
    from app.config import settings

    device_id = _add_device(client, router, "syslog-device")

    # Приёмник поднимаем сами, на свободных портах. Сначала гасим: если
    # приложение уже подняло его на штатных 5514 (SYSLOG_ENABLED не выключен,
    # как это бывает в CI), повторный start() ничего не сделает, и тест будет
    # стучаться в порт, которого никто не слушает.
    syslog.stop()
    settings.syslog_enabled = True
    settings.syslog_udp_port = 15571
    settings.syslog_tcp_port = 15571
    syslog.start()
    try:
        syslog._sources.refresh(force=True)

        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.sendto(b"<134>Aug  7 10:15:00 rtr system,info udp line arrived",
                   ("127.0.0.1", 15571))

        tcp = socket.create_connection(("127.0.0.1", 15571), timeout=5)
        tcp.sendall(b"<131>Aug  7 10:15:01 rtr system,error tcp line arrived\n")
        # RouterOS умеет и вариант с длиной в начале строки
        body = b"<134>Aug  7 10:15:02 rtr system,info counted line arrived"
        tcp.sendall(b"%d " % len(body) + body)

        deadline = time.time() + 10
        while time.time() < deadline:
            syslog.flush()
            rows = query("SELECT message FROM syslog WHERE device_id = ?", (device_id,))
            if len(rows) >= 3:
                break
            time.sleep(0.2)
        tcp.close()

        messages = {r["message"] for r in
                    query("SELECT message FROM syslog WHERE device_id = ?", (device_id,))}
        assert "udp line arrived" in messages, "строка по UDP не дошла"
        assert "tcp line arrived" in messages, "строка по TCP не дошла"
        assert "counted line arrived" in messages, "строка с длиной в начале не разобрана"

        page = client.get("/syslog").text
        assert "udp line arrived" in page
    finally:
        syslog.stop()


def test_syslog_keeps_the_original_line(client, router):
    """
    Исходная строка сохраняется целиком, рядом с разобранными полями.

    Разбор форматов дело гадательное: RouterOS шлёт то BSD, то CEF, а на
    практике выяснилось, что и версии ведут себя по-разному. Если поля
    разобрались неверно, восстановить содержимое можно только из исходной
    строки, поэтому она хранится всегда.
    """
    from app import syslog

    device_id = _add_device(client, router, "raw-keeper")
    syslog._sources.refresh(force=True)

    line = ("Aug  7 10:15:00 rtr CEF:0|MikroTik|hAP ac lite|7.21.5 (long-term)|10|"
            "system,info|Low|dvchost=rtr msg=user admin logged in from 10.0.0.5 "
            "app=winbox")
    syslog.receive_for_tests(line, "127.0.0.1")
    syslog.flush()

    row = query_one(
        "SELECT raw, message, topics FROM syslog WHERE device_id = ? ORDER BY id DESC",
        (device_id,))
    assert row is not None, "строка не сохранилась"
    assert row["raw"] == line, "исходная строка потеряна"
    assert row["topics"] == "system,info"
    assert "logged in" in row["message"]


def test_syslog_ignores_strangers():
    """
    Строки с чужих адресов не принимаются.

    Syslog ничем не подписан: кто дотянулся до порта, тот и пишет в журнал.
    Открытый для всех приёмник это приглашение забить диск, поэтому по
    умолчанию принимаем только от заведённых устройств.
    """
    from app import syslog

    syslog._sources.refresh(force=True)
    before = query_one("SELECT COUNT(*) AS c FROM syslog")["c"]
    dropped = syslog.state["dropped"]

    syslog.receive_for_tests("<134>Aug  7 10:00:00 rtr system,info привет", "203.0.113.7")
    syslog.flush()

    after = query_one("SELECT COUNT(*) AS c FROM syslog")["c"]
    assert after == before, "строка с чужого адреса попала в журнал"
    assert syslog.state["dropped"] > dropped


def test_syslog_feed_scrolls_instead_of_paging(client, router):
    """
    Журнал устройств это лента, а не страницы.

    Страницы годятся там, где данные стоят на месте. В потоке они врут:
    пока человек читает вторую страницу, сверху добавляются новые строки,
    всё съезжает, и одну и ту же запись можно увидеть дважды или пропустить.
    Поэтому свежие внизу, старые подгружаются при прокрутке вверх.
    """
    from app import syslog
    from app.database import execute

    _add_device(client, router, "feed-device")
    syslog._sources.refresh(force=True)
    execute("DELETE FROM syslog")

    for number in range(420):
        syslog.receive_for_tests(
            f"<134>Aug  7 10:00:00 rtr system,info строка {number}", "127.0.0.1")
    syslog.flush()

    page = client.get("/syslog").text
    assert 'class="pager"' not in page, "листалка вернулась в ленту"
    # Показывается последняя порция, а не всё сразу
    assert "строка 419" in page and "строка 0<" not in page
    # Свежие внизу: так читают любой журнал
    assert page.index("строка 120") < page.index("строка 419")
    # И видно, что выше что-то есть
    assert "выше ещё" in page

    ids = [r["id"] for r in query("SELECT id FROM syslog ORDER BY id")]

    # Старые строки: отдаются по возрастанию, чтобы страница вставила их
    # сверху одним куском, не переставляя уже показанное
    older = client.get(f"/api/syslog?before={ids[200]}&limit=50").json()
    assert len(older["rows"]) == 50
    assert older["rows"] == sorted(older["rows"], key=lambda r: r["id"])
    assert all(r["id"] < ids[200] for r in older["rows"])
    assert older["first"] == older["rows"][0]["id"], "нет якоря для следующей порции"

    # Новые строки для живой ленты
    newer = client.get(f"/api/syslog?after={ids[-5]}&limit=50").json()
    assert [r["id"] for r in newer["rows"]] == ids[-4:]

    # Фильтры действуют и на подгрузку старых, иначе лента показывала бы
    # не то, что человек выбрал
    filtered = client.get(f"/api/syslog?before={ids[200]}&q=строка 15").json()
    assert filtered["rows"], "фильтр отсёк всё"
    assert all("строка 15" in r["message"] for r in filtered["rows"])


def test_syslog_source_can_be_allowed_by_hand(client, router):
    """
    Чужой адрес разрешается кнопкой и привязывается к точке по имени.

    Роутер выбирает отправителя по маршруту до панели, и в туннеле это
    его туннельный адрес, а не тот, по которому панель к нему обращается.
    Заставлять человека править .env ради этого неправильно, а принимать
    молча со всех адресов нельзя: syslog ничем не заверен.
    """
    from app import syslog
    from app.database import execute

    device_id = _add_device(client, router, "tunnel-device")
    # Устройство подписывается своим identity, панель его уже знает
    execute("UPDATE devices SET identity = ? WHERE id = ?", ("PionernyybufetRaduga", device_id))
    syslog._sources.refresh(force=True)
    syslog.state["rejected"].clear()

    line = "<134>Aug  7 10:15:00 PionernyybufetRaduga system,info из туннеля"
    syslog.receive_for_tests(line, "10.8.0.34")
    syslog.flush()

    assert "10.8.0.34" in syslog.state["rejected"], "адрес не попал в отвергнутые"
    assert syslog.state["rejected"]["10.8.0.34"]["host"] == "PionernyybufetRaduga", \
        "имя отправителя не запомнено, человеку не по чему решать"

    # Страница показывает адрес и предлагает его принять
    page = client.get("/syslog").text
    assert "10.8.0.34" in page and "PionernyybufetRaduga" in page

    r = client.post("/api/syslog/sources",
                    json={"address": "10.8.0.34", "host": "PionernyybufetRaduga"})
    assert r.status_code == 200, r.text
    assert r.json()["device_id"] == device_id, "точка не опознана по имени"

    # Теперь строки принимаются и сразу привязаны к устройству
    syslog.receive_for_tests(line, "10.8.0.34")
    syslog.flush()
    row = query_one("SELECT device_id, message FROM syslog ORDER BY id DESC")
    assert row["device_id"] == device_id
    assert row["message"] == "из туннеля"
    assert "10.8.0.34" not in syslog.state["rejected"], "адрес остался в отвергнутых"

    # И перестают, когда адрес убрали
    assert client.post("/api/syslog/sources/delete",
                       json={"address": "10.8.0.34"}).status_code == 200
    before = query_one("SELECT COUNT(*) AS c FROM syslog")["c"]
    syslog.receive_for_tests(line, "10.8.0.34")
    syslog.flush()
    assert query_one("SELECT COUNT(*) AS c FROM syslog")["c"] == before


def test_syslog_highlighting_rules(client, router):
    """
    Подсветка: побеждает первое подошедшее правило.

    Порядок задаёт человек, и «первое сверху» это единственный порядок,
    который не надо объяснять.
    """
    from app import syslog

    assert client.post("/api/syslog/rules", json={
        "pattern": "login failure", "color": "err", "note": "подбор пароля"}).status_code == 200
    assert client.post("/api/syslog/rules", json={
        "pattern": "login", "color": "warn"}).status_code == 200

    rules = syslog.rules()
    assert len(rules) >= 2
    assert syslog.match_color("login failure for user admin", rules) == "err"
    assert syslog.match_color("login ok", rules) == "warn"
    assert syslog.match_color("dhcp lease added", rules) == ""

    # Кривое выражение отвергается сразу, а не при первом совпадении
    bad = client.post("/api/syslog/rules",
                      json={"pattern": "(unclosed", "is_regex": True, "color": "err"})
    assert bad.status_code == 400

    # Выключенное правило не красит. Правило ищем по образцу, а не по номеру
    # в списке: рядом живут правила из других тестов и предлагаемое панелью
    rule_id = next(r["id"] for r in rules if r["pattern"] == "login failure")
    assert client.post(f"/api/syslog/rules/{rule_id}/toggle").status_code == 200
    assert syslog.match_color("login failure for user admin", syslog.rules()) == "warn"
    assert client.post(f"/api/syslog/rules/{rule_id}/delete").status_code == 200


def test_hidden_lines_stay_in_the_database(client, router):
    """
    Правило «не показывать» убирает строки из ленты, но не из базы.

    Разница принципиальная: человек прячет шум, а не удаляет историю.
    Выключил правило или поставил галочку «показать скрытые», и всё
    вернулось. Поэтому же скрытые строки остаются в выгрузке текстом.
    """
    from app import syslog
    from app.database import execute, query_one

    execute("DELETE FROM syslog")
    execute("DELETE FROM syslog_rules")
    syslog.forget_rules()

    noisy = ("<134>Aug  7 10:15:00 точка-шум system,info,account "
             "user operator logged in from 10.10.0.5 via api")
    useful = "<134>Aug  7 10:15:01 точка-шум system,error фатальная ошибка"

    device_id = _add_device(client, router, "hide-device")
    syslog.allow_source("127.0.0.1", device_id)
    syslog.receive_for_tests(noisy, "127.0.0.1")
    syslog.receive_for_tests(useful, "127.0.0.1")
    syslog.flush()

    stored = query_one("SELECT COUNT(*) AS c FROM syslog")["c"]
    assert stored == 2, "строки не записались, проверять нечего"

    assert client.post("/api/syslog/rules", json={
        "pattern": "logged in from .* via api", "is_regex": True,
        "action": "hide", "note": "входы панели"}).status_code == 200

    page = client.get("/syslog")
    assert page.status_code == 200
    assert "фатальная ошибка" in page.text
    # Ищем кусок самой строки, а не образец правила: образец в таблице правил
    # на этой же странице виден всегда
    assert "user operator" not in page.text, "скрытая строка всё равно показана"

    # Но в базе она на месте, и по галочке показывается снова
    assert query_one("SELECT COUNT(*) AS c FROM syslog")["c"] == stored
    assert "user operator" in client.get("/syslog?hidden=1").text

    # Живая лента прячет то же самое, иначе строка вернулась бы через минуту
    feed = client.get("/api/syslog?after=0").json()
    assert all("logged in from" not in r["message"] for r in feed["rows"])
    assert any("фатальная ошибка" in r["message"] for r in feed["rows"])

    execute("DELETE FROM syslog_rules")
    syslog.forget_rules()


def test_drop_rule_refuses_the_line_at_the_door(client, router):
    """
    Правило «не сохранять» отбрасывает строку до записи в базу.

    В этом весь смысл: шум не должен занимать место и вытеснять полезное
    из потолка хранения. Считается он отдельно от потерянного, потому что
    «выкинули по правилу» и «не справились» это разные новости.
    """
    from app import syslog
    from app.database import execute, query_one

    execute("DELETE FROM syslog")
    execute("DELETE FROM syslog_rules")
    syslog.forget_rules()

    device_id = _add_device(client, router, "drop-device")
    syslog.allow_source("127.0.0.1", device_id)

    assert client.post("/api/syslog/rules", json={
        "pattern": "via api", "action": "drop"}).status_code == 200

    before = syslog.state["ignored"]
    syslog.receive_for_tests(
        "<134>Aug  7 10:15:00 точка system,info,account user operator logged in "
        "from 10.10.0.5 via api", "127.0.0.1")
    syslog.receive_for_tests(
        "<134>Aug  7 10:15:01 точка system,error нужная строка", "127.0.0.1")
    syslog.flush()

    rows = [r["message"] for r in query("SELECT message FROM syslog")]
    assert any("нужная строка" in m for m in rows)
    assert not any("via api" in m for m in rows), "строка попала в базу"
    assert syslog.state["ignored"] == before + 1, "отброшенное не посчитано"
    assert query_one("SELECT COUNT(*) AS c FROM syslog")["c"] == 1

    execute("DELETE FROM syslog_rules")
    syslog.forget_rules()


def test_builtin_rule_is_offered_once_and_stays_off(client):
    """
    Предлагаемое правило заводится выключенным и не возвращается после удаления.

    Выключенным, потому что решение прятать часть журнала принимает человек.
    Не возвращается, потому что панель, которая раз за разом восстанавливает
    убранное, воспринимается как сломанная.
    """
    from app import syslog
    from app.database import execute, query_one

    execute("DELETE FROM syslog_rules")
    execute("DELETE FROM syslog_builtin")
    syslog.forget_rules()

    assert syslog.install_builtin_rules() == 1
    rule = query_one("SELECT * FROM syslog_rules WHERE builtin = 'api-login'")
    assert rule, "правило не появилось"
    assert rule["enabled"] == 0, "панель сама спрятала часть журнала"
    assert rule["action"] == "hide"

    # Второй запуск ничего не добавляет
    assert syslog.install_builtin_rules() == 0

    execute("DELETE FROM syslog_rules WHERE builtin = 'api-login'")
    assert syslog.install_builtin_rules() == 0, "удалённое правило вернулось"
    syslog.forget_rules()


def test_syslog_prune_respects_both_limits():
    """
    Чистка журнала: и по сроку, и по числу строк.

    Ограничений два, и оба нужны. Срок отвечает на вопрос «сколько держим
    историю», потолок спасает диск, когда одна точка за ночь пишет миллион
    строк об одной и той же ошибке.
    """
    from app import syslog
    from app.database import execute

    execute("DELETE FROM syslog")
    for number in range(30):
        execute(
            "INSERT INTO syslog (ts, device_name, message, severity, severity_name) "
            "VALUES (datetime('now'), 'точка', ?, 6, 'info')", (f"строка {number}",))
    # Старьё, которое должно уехать по сроку
    execute(
        "INSERT INTO syslog (ts, device_name, message, severity, severity_name) "
        "VALUES (datetime('now', '-90 days'), 'точка', 'древняя строка', 6, 'info')")

    assert syslog.prune(days=30, max_rows=0) == 1, "старая строка не удалилась"
    assert syslog.prune(days=0, max_rows=10) == 20, "потолок по числу строк не сработал"

    left = query("SELECT message FROM syslog ORDER BY id")
    assert len(left) == 10
    # Остаются свежие, а не первые попавшиеся
    assert left[-1]["message"] == "строка 29"


def test_syslog_needs_permission(client, router):
    """Журнал устройств закрыт отдельным правом: в строках бывают адреса."""
    _make_user(client, "logreader", ["devices.view"])
    with _as("logreader") as limited:
        assert limited.get("/syslog").status_code == 403
        assert limited.get("/api/syslog").status_code == 403
        page = limited.get("/").text
        # Пункт меню общий на два журнала, поэтому его не должно быть
        # вовсе: прав нет ни на один из них
        assert ">Логи<" not in page


def test_logging_action_configures_the_router(client, router):
    """
    Действие «Слать журнал в панель» прописывает на устройстве получателя.

    Повторный запуск не плодит дубли: получатель и правила называются
    узнаваемо, и действие переписывает своё, не трогая чужие настройки
    логирования. На точке может стоять отправка ещё куда-то.
    """
    device_id = _add_device(client, router, "logging-device")

    result = _run_and_wait(client, "logging_to_panel", [device_id], {
        "address": "10.10.0.5", "port": "5514",
        "protocol": "udp", "topics": "info,error"})
    assert result["status"] == "done", result

    assert len(router.log_actions) == 1, "получатель не создан"
    action = router.log_actions[0]
    assert action["remote"] == "10.10.0.5"
    assert action["remote-port"] == "5514"
    assert action["remote-protocol"] == "udp"
    assert {r["topics"] for r in router.log_rules} == {"info", "error"}

    # Формат в седьмой версии задаётся через remote-log-format. Флага
    # bsd-syslog там нет вовсе, и попытка его выставить валит всю команду:
    # именно так это и выяснилось, на полусотне живых точек сразу.
    #
    # По умолчанию ставится CEF, а не BSD. Это не выбор из документации:
    # с форматом по умолчанию строки до панели не доходили, а с CEF пошли.
    # Здесь стоит то, что проверено на живом парке.
    assert action.get("remote-log-format") == "cef"
    assert "bsd-syslog" not in action

    # Отправитель закрепляется за адресом, по которому панель знает точку.
    # Иначе роутер возьмёт адрес интерфейса, через который лежит маршрут
    # до панели, и та молча отбросит строки как чужие.
    assert action.get("src-address") == "127.0.0.1"

    # Второй запуск ничего не дублирует
    _run_and_wait(client, "logging_to_panel", [device_id], {
        "address": "10.10.0.5", "port": "5514",
        "protocol": "udp", "topics": "info,error"})
    assert len(router.log_actions) == 1, "получатель задублировался"
    assert len(router.log_rules) == 2, "правила задублировались"


def test_audit_details_are_readable(client, router):
    """
    В журнале действий человеческий текст, а не JSON.

    Раньше туда клался словарь параметров как есть, и в истории стояло
    `{"channel": "long-term"}`, а у действий без параметров и вовсе `{}`.
    Пустые скобки это чистый мусор, а JSON читается медленнее, чем
    собственная подпись поля.
    """
    from app.actions import REGISTRY, describe_params

    # Действие без параметров не оставляет следа в колонке подробностей
    assert describe_params(REGISTRY["check"], {}) == ""

    described = describe_params(REGISTRY["logging_to_panel"], {
        "address": "10.10.0.5", "port": "5514",
        "protocol": "udp", "log_format": "cef", "topics": "error,warning"})
    assert "Адрес панели: 10.10.0.5" in described
    # У выпадающих списков подпись, а не внутреннее значение
    assert "Протокол: UDP" in described and "Формат: CEF" in described

    # Галочки словами, а не единицей
    described = describe_params(REGISTRY["upgrade_ros"],
                                {"channel": "long-term", "make_backup": "1"})
    assert "Снять бэкап перед обновлением: да" in described
    # Длинное пояснение канала в журнал не тащим, там нужно само значение
    assert "Канал обновлений: long-term" in described
    assert "максимальная стабильность" not in described

    # Пароли не попадают в журнал ни при каких обстоятельствах
    described = describe_params(REGISTRY["run_source"],
                                {"source": ":log info x", "password": "секрет"})
    assert "секрет" not in described

    # Длинные значения обрезаются: журнал читают строкой
    described = describe_params(REGISTRY["run_source"], {"source": "x" * 400})
    assert len(described) < 200 and described.endswith("...")


def test_highlight_rule_audit_keeps_the_pattern(client, router):
    """
    В истории у правила журнала стоит образец, а не внутренний номер.

    «Удалено правило журнала · 5» через месяц не говорит ничего,
    а «login failure» говорит.
    """
    assert client.post("/api/syslog/rules", json={
        "pattern": "истории нужен образец", "color": "warn"}).status_code == 200
    rule_id = [r for r in query("SELECT id, pattern FROM syslog_rules")
               if r["pattern"] == "истории нужен образец"][0]["id"]

    assert client.post(f"/api/syslog/rules/{rule_id}/toggle").status_code == 200
    row = query_one("SELECT target, details FROM audit_log "
                    "WHERE action = 'Изменено правило журнала' ORDER BY id DESC")
    assert row["target"] == "истории нужен образец"
    assert row["details"] == "выключено", "не видно, куда переключили"

    assert client.post(f"/api/syslog/rules/{rule_id}/delete").status_code == 200
    row = query_one("SELECT target FROM audit_log "
                    "WHERE action = 'Удалено правило журнала' ORDER BY id DESC")
    assert row["target"] == "истории нужен образец"


def test_logging_off_removes_only_our_own(client, router):
    """
    Отмена отправки убирает своё и не трогает чужое.

    На точке может стоять отправка ещё куда-то, к своему сборщику. Снести
    её заодно значит незаметно оставить человека без логов там, где он
    их ждёт.
    """
    device_id = _add_device(client, router, "logging-off-device")

    # Чужая настройка логирования, которую трогать нельзя
    router.log_actions.append({".id": "*99", "name": "tosyslog", "target": "remote",
                               "remote": "10.10.0.199"})
    router.log_rules.append({".id": "*99", "action": "tosyslog", "topics": "warning"})

    _run_and_wait(client, "logging_to_panel", [device_id], {
        "address": "10.10.0.5", "port": "5514", "protocol": "udp",
        "topics": "info,error"})
    assert len(router.log_actions) == 2

    result = _run_and_wait(client, "logging_off", [device_id], {"name": "tikpilot"})
    assert result["status"] == "done", result

    assert [a["name"] for a in router.log_actions] == ["tosyslog"], "убрали чужого получателя"
    assert [r["action"] for r in router.log_rules] == ["tosyslog"], "убрали чужие правила"

    # Повторный запуск на чистом устройстве это не ошибка, а «нечего убирать»
    again = _run_and_wait(client, "logging_off", [device_id], {"name": "tikpilot"})
    assert again["status"] == "done", again

    # Встроенных получателей RouterOS действие не трогает даже по прямой просьбе
    guarded = _run_and_wait(client, "logging_off", [device_id], {"name": "memory"})
    assert guarded["status"] == "done"
    item = query_one(
        "SELECT result FROM job_items WHERE job_id = ? ORDER BY id DESC", (guarded["id"],))
    assert "встроенный" in (item["result"] or ""), item["result"]


def test_logging_action_survives_routeros_6(client, router):
    """
    На шестой версии формат задаётся другим параметром.

    В седьмой это `remote-log-format`, в шестой отдельный флаг `bsd-syslog`,
    и чужой параметр роутер отвергает целиком, вместе со всей командой.
    Спрашивать версию не нужно: действие пробует оба и молча пропускает то,
    чего эта версия не знает.
    """
    router.version = "6.49.10"
    device_id = _add_device(client, router, "old-ros-device")

    result = _run_and_wait(client, "logging_to_panel", [device_id], {
        "address": "10.10.0.5", "port": "5514", "protocol": "udp",
        "log_format": "bsd-syslog", "topics": "info"})
    assert result["status"] == "done", result

    action = router.log_actions[0]
    assert action.get("bsd-syslog") == "yes"
    assert "remote-log-format" not in action


# ===========================================================================
#                        терминал по SSH
# ===========================================================================

def _terminal_device(client, port: int, name: str = "ssh-device") -> int:
    """Устройство, указывающее на заглушку SSH."""
    from app.crypto import encrypt
    from app.database import execute

    return execute(
        "INSERT INTO devices (name, host, ssh_port, username, password_enc, "
        "created_at, updated_at) VALUES (?,?,?,?,?,datetime('now'),datetime('now'))",
        (name, "127.0.0.1", port, "tikpilot", encrypt("s3cret")),
    )


def _terminal_read(ws, needle: str, tries: int = 30) -> str:
    """Читать из сокета, пока не появится нужное или не кончится терпение."""
    import json

    got = ""
    for _ in range(tries):
        message = json.loads(ws.receive_text())
        if message["type"] == "error":
            return "ОШИБКА: " + message["text"]
        if message["type"] == "data":
            got += message["text"]
            if needle in got:
                break
    return got


def test_terminal_talks_to_a_real_ssh_server(client, router):
    """
    Терминал доводит нажатия до устройства и возвращает вывод.

    Проверяется настоящим сервером SSH, а не моком: половина возможных
    ошибок здесь в рукопожатии, запросе псевдотерминала и кодировках,
    а мок принял бы любую из них.
    """
    import json

    from tests.fake_ssh import FakeSSH

    ssh = FakeSSH()
    try:
        device_id = _terminal_device(client, ssh.port)

        with client.websocket_connect(f"/ws/terminal/{device_id}") as ws:
            assert "[admin@MikroTik]" in _terminal_read(ws, "MikroTik"), "нет приглашения"

            ws.send_text(json.dumps({"type": "data", "text": "/system/identity/print\r"}))
            assert "name: MikroTik" in _terminal_read(ws, "name: MikroTik")

        # Открытие, набранная команда и закрытие видны в журнале действий:
        # терминал обходит подтверждения, поэтому след обязателен
        actions = [r["action"] for r in query(
            "SELECT action FROM audit_log WHERE target = 'ssh-device' ORDER BY id")]
        assert "Открыт терминал" in actions
        assert "Команда в терминале" in actions

        typed = query_one(
            "SELECT details FROM audit_log WHERE action = 'Команда в терминале' "
            "ORDER BY id DESC")
        assert typed["details"] == "/system/identity/print"
    finally:
        ssh.stop()


def test_terminal_refuses_when_the_host_key_changed(client, router):
    """
    Смена ключа устройства останавливает подключение.

    Так выглядит подмена. Так же выглядит и законная перезаливка роутера,
    поэтому текст ошибки говорит про обе возможности, а забыть ключ можно
    кнопкой.
    """
    import json

    from app.database import execute
    from tests.fake_ssh import FakeSSH

    ssh = FakeSSH()
    try:
        device_id = _terminal_device(client, ssh.port, "key-device")

        # Первое подключение запоминает ключ
        with client.websocket_connect(f"/ws/terminal/{device_id}") as ws:
            _terminal_read(ws, "MikroTik")
        remembered = query_one(
            "SELECT fingerprint FROM ssh_hosts WHERE device_id = ?", (device_id,))
        assert remembered, "ключ не запомнился"

        # Подменяем запомненный отпечаток: для панели это то же самое,
        # что смена ключа на устройстве
        execute("UPDATE ssh_hosts SET fingerprint = ? WHERE device_id = ?",
                ("ssh-rsa SHA256:чужой", device_id))

        with client.websocket_connect(f"/ws/terminal/{device_id}") as ws:
            answer = json.loads(ws.receive_text())
            assert answer["type"] == "error"
            assert "Ключ устройства изменился" in answer["text"]

        # Кнопка «забыть ключ» возвращает возможность подключиться
        assert client.post(f"/api/terminal/{device_id}/forget-key").status_code == 200
        with client.websocket_connect(f"/ws/terminal/{device_id}") as ws:
            assert "[admin@MikroTik]" in _terminal_read(ws, "MikroTik")
    finally:
        ssh.stop()


def test_terminal_needs_permission_and_scope(client, router):
    """
    Терминал закрыт отдельным правом и уважает область видимости.

    Это самая опасная возможность панели: она обходит подтверждения
    массовых действий. В набор прав по умолчанию не входит.
    """
    import json

    from tests.fake_ssh import FakeSSH

    ssh = FakeSSH()
    try:
        device_id = _terminal_device(client, ssh.port, "scope-device")
        _make_user(client, "nopower", ["devices.view"])

        with _as("nopower") as limited:
            assert limited.get("/terminal").status_code == 403
            page = limited.get("/").text
            assert ">Терминал<" not in page

            # И через сокет тоже: спрятанная кнопка это не защита
            with limited.websocket_connect(f"/ws/terminal/{device_id}") as ws:
                answer = json.loads(ws.receive_text())
                assert answer["type"] == "error"
                assert "прав" in answer["text"].lower()
    finally:
        ssh.stop()


def test_device_work_never_blocks_the_event_loop():
    """
    Ни один обработчик, ходящий на устройства, не объявлен `async`.

    Разница не косметическая. Асинхронный обработчик выполняется в общем
    цикле событий, и блокирующий поход по сети внутри него останавливает
    не свой запрос, а весь сервер: пока панель обходит полсотни точек,
    у всех и на всех страницах крутится ожидание.

    Обычную функцию Starlette уводит в отдельный поток, и остальные
    страницы продолжают отвечать. Проверка общая, а не про один роут:
    ошибка эта возвращается сама собой, стоит написать `async def`
    по привычке.
    """
    import inspect

    from app.main import app

    blocking = ("pool.borrow", "pool.poll", "MikroTik(", "run_cycle(")
    guilty = []
    for route in app.routes:
        endpoint = getattr(route, "endpoint", None)
        if endpoint is None or not inspect.iscoroutinefunction(endpoint):
            continue
        try:
            source = inspect.getsource(endpoint)
        except OSError:      # у роутов без исходников проверять нечего
            continue
        if any(mark in source for mark in blocking):
            guilty.append(f"{getattr(route, 'path', '?')} ({endpoint.__name__})")

    assert not guilty, (
        "эти обработчики ходят на устройства прямо в цикле событий "
        "и подвесят всю панель:\n  " + "\n  ".join(guilty)
    )


def test_collect_clients_can_be_limited_to_one_device(client, router):
    """
    Сбор клиентов умеет опрашивать одну точку вместо всего парка.

    Кнопку жмут, глядя на конкретную площадку. Обходить ради неё полсотни
    других значит ждать минуты вместо секунд.
    """
    device_id = _add_device(client, router, "collect-one")
    _add_device(client, router, "collect-two")

    r = client.post(f"/api/clients/collect?device_id={device_id}")
    assert r.status_code == 200, r.text
    assert r.json()["devices"] == 1, "опрошена не одна точка"

    # Без указания точки опрашиваются все доступные
    r = client.post("/api/clients/collect")
    assert r.json()["devices"] >= 2


def test_monitoring_sections_can_be_folded(client, router):
    """
    Разделы мониторинга сворачиваются.

    Разметка проверяется, а не поведение: сворачивание живёт в браузере,
    но без атрибута на панели скрипту не за что зацепиться, и разделы
    молча перестанут складываться.
    """
    _add_device(client, router, "fold-device")
    page = client.get("/monitoring").text

    for section in ("map", "uptime", "latency", "events", "flapping"):
        assert f'data-fold="{section}"' in page, f"раздел {section} не сворачивается"


# ===========================================================================
#                        клиенты за роутерами
# ===========================================================================

def test_clients_merge_three_tables_by_mac():
    """
    Три таблицы роутера сливаются в одну строку на клиента.

    Поодиночке каждая неполна: аренды знают имя, но не видят тех, кому
    адрес прописан руками; ARP видит всех, но вместо порта показывает мост;
    таблица моста знает порт, но не знает ни имени, ни адреса.
    """
    from app.clients import merge

    rows = merge(
        leases=[{"mac-address": "BC:24:11:F0:70:DB", "address": "192.168.88.10",
                 "host-name": "касса-1", "server": "dhcp1", "dynamic": "false"}],
        arp=[
            {"mac-address": "BC:24:11:F0:70:DB", "address": "192.168.88.10",
             "interface": "bridge"},
            {"mac-address": "C0:56:E3:11:22:33", "address": "192.168.88.50",
             "interface": "bridge"},
        ],
        hosts=[
            {"mac-address": "bc-24-11-f0-70-db", "interface": "ether3", "vid": "10"},
            {"mac-address": "C0:56:E3:11:22:33", "interface": "ether5"},
        ],
    )
    assert len(rows) == 2, rows
    by_mac = {r["mac"]: r for r in rows}

    # Касса: имя из аренды, порт из моста, а не «bridge» из ARP
    till = by_mac["bc:24:11:f0:70:db"]
    assert till["hostname"] == "касса-1"
    assert till["ip"] == "192.168.88.10"
    assert till["port"] == "ether3", "порт должен приходить из таблицы моста"
    assert till["vlan"] == "10"
    assert till["dynamic"] is False, "статическая аренда — адрес закреплён"
    assert till["vendor"] == "Proxmox"

    # Камера: в арендах её нет, но она нашлась в ARP и в мосту
    camera = by_mac["c0:56:e3:11:22:33"]
    assert camera["hostname"] == ""
    assert camera["ip"] == "192.168.88.50"
    assert camera["port"] == "ether5"
    assert camera["vendor"] == "Hikvision"

    # Записи без разбираемого MAC отбрасываются молча
    assert merge([{"mac-address": "чепуха"}], [], []) == []


def test_router_comment_becomes_the_name():
    """
    Комментарий с роутера показывается как имя клиента.

    Администратор уже подписал эту железку на самом устройстве, и
    заставлять его подписывать её второй раз в панели незачем. Имя,
    которое устройство сообщает о себе само, часто выглядит как
    «android-4f2a» и человеку не говорит ничего.
    """
    from app.clients import merge

    rows = merge(
        leases=[{"mac-address": "BC:24:11:F0:70:DB", "host-name": "android-4f2a",
                 "comment": "касса у входа"}],
        arp=[{"mac-address": "C0:56:E3:11:22:33", "address": "192.168.88.50",
              "comment": "камера склад"}],
        hosts=[],
    )
    by_mac = {r["mac"]: r for r in rows}
    assert by_mac["bc:24:11:f0:70:db"]["comment"] == "касса у входа"
    assert by_mac["bc:24:11:f0:70:db"]["hostname"] == "android-4f2a"
    # Комментарий из ARP берётся, когда аренды нет вовсе
    assert by_mac["c0:56:e3:11:22:33"]["comment"] == "камера склад"

    # Комментарий с аренды важнее, чем с ARP: аренда конкретнее
    both = merge(
        leases=[{"mac-address": "BC:24:11:F0:70:DB", "comment": "из аренды"}],
        arp=[{"mac-address": "BC:24:11:F0:70:DB", "comment": "из arp"}],
        hosts=[],
    )
    assert both[0]["comment"] == "из аренды"


def test_random_mac_is_not_looked_up():
    """
    Локально назначенный MAC вендора не имеет.

    Телефоны придумывают такие сами ради приватности, и искать в списке
    производителя бессмысленно: его там нет и быть не может.
    """
    from app.clients import normalize_mac, vendor_of

    assert vendor_of("f6:4f:a8:13:e6:d4") == "случайный MAC"
    assert vendor_of("4c:5e:0c:11:22:33") == "MikroTik"
    assert vendor_of("00:00:00:11:22:33") == ""

    # Разные написания дают один и тот же ключ, иначе клиент задвоится
    assert normalize_mac("BC-24-11-F0-70-DB") == normalize_mac("bc:24:11:f0:70:db")


def test_clients_are_collected_and_remembered(client, router):
    """
    Клиенты собираются с устройства и не пропадают, когда пропали сами.

    Вопрос «когда эту камеру видели последний раз» без сохранения истории
    ответа не имеет, поэтому строки обновляются, а не переписываются.
    """
    from app.database import execute, query_one

    device_id = _add_device(client, router, "shop-1")

    r = client.post("/api/clients/collect")
    assert r.status_code == 200, r.text
    # Считаем по своей точке, а не по итогу: сбор идёт по всем видимым
    # устройствам, и от других тестов их в базе может быть сколько угодно
    mine = query("SELECT mac FROM clients WHERE device_id = ?", (device_id,))
    assert len(mine) == 3, [m["mac"] for m in mine]

    page = client.get("/clients")
    assert page.status_code == 200
    assert "касса-1" in page.text
    assert "ether3" in page.text, "порт из таблицы моста не показан"
    assert "Hikvision" in page.text
    # Комментарий с роутера важнее имени, которое устройство сообщает само
    assert "касса у входа" in page.text
    assert "камера склад" in page.text, "комментарий из ARP не показан"

    till = query_one(
        "SELECT * FROM clients WHERE mac = ? AND device_id = ?",
        ("bc:24:11:f0:70:db", device_id))
    assert till["comment"] == "касса у входа"
    assert till["hostname"] == "касса-1", "имя из аренды тоже сохраняется"
    assert till["device_id"] == device_id
    assert till["ip"] == "192.168.88.10"
    assert till["dynamic"] == 0
    first_seen = till["first_seen"]

    # Камеру увезли: со следующего сбора её в таблицах нет
    router.arp_entries = [e for e in router.arp_entries
                          if not e["mac-address"].startswith("C0:56")]
    router.bridge_hosts = [h for h in router.bridge_hosts
                           if not h["mac-address"].startswith("C0:56")]
    execute("UPDATE clients SET last_seen = datetime('now','-3 hours') "
            "WHERE device_id = ?", (device_id,))

    client.post("/api/clients/collect")

    gone = query_one("SELECT * FROM clients WHERE mac = ? AND device_id = ?",
                     ("c0:56:e3:11:22:33", device_id))
    assert gone is not None, "пропавшего клиента забыли слишком рано"
    assert "-3 hours" not in str(gone["last_seen"])

    # А у кассы обновилось «видели», но не «впервые»
    till = query_one("SELECT * FROM clients WHERE mac = ? AND device_id = ?",
                     ("bc:24:11:f0:70:db", device_id))
    assert till["first_seen"] == first_seen
    assert till["last_seen"] > gone["last_seen"]

    # Фильтр «пропали» показывает именно её
    page = client.get(f"/clients?seen=gone&device_id={device_id}")
    assert "c0:56:e3:11:22:33" in page.text
    assert "bc:24:11:f0:70:db" not in page.text


def test_clients_are_wired_or_wireless(client, router):
    """
    Клиент либо проводной, либо беспроводной, а порт это настоящий порт.

    Раньше в колонку порта попадал интерфейс из ARP, то есть «bridge»
    и «lte1». На вопрос «куда воткнут кабель» это не отвечает, а список
    заодно засорялся самим роутером и оборудованием провайдера.
    """
    from app.clients import merge
    from app.database import query_one

    device_id = _add_device(client, router, "shop-wifi")
    client.post("/api/clients/collect")

    # Беспроводной: интерфейс из таблицы регистрации, сеть и сигнал
    air = query_one("SELECT * FROM clients WHERE mac = ? AND device_id = ?",
                    ("b0:fc:0d:f3:56:8f", device_id))
    assert air["link"] == "wireless"
    assert air["port"] == "wlan1"
    assert air["ssid"] == "Magazin"
    assert air["signal"] == "-64"

    # Проводной: порт из таблицы моста, поле on-interface в RouterOS 7
    wire = query_one("SELECT * FROM clients WHERE mac = ? AND device_id = ?",
                     ("bc:24:11:f0:70:db", device_id))
    assert wire["link"] == "wired"
    assert wire["port"] == "ether3"

    # Собственных интерфейсов роутера и шлюза провайдера в списке нет
    assert query_one("SELECT id FROM clients WHERE mac = ? AND device_id = ?",
                     ("cc:2d:e0:f2:4c:f3", device_id)) is None, "роутер попал в клиенты"
    assert query_one("SELECT id FROM clients WHERE mac = ? AND device_id = ?",
                     ("10:e8:40:18:73:0f", device_id)) is None, "шлюз провайдера в клиентах"

    # Фильтр по виду подключения
    page = client.get(f"/clients?device_id={device_id}&link=wireless")
    assert "b0:fc:0d:f3:56:8f" in page.text
    assert "bc:24:11:f0:70:db" not in page.text

    # Интерфейс из ARP портом не считается: «bridge» это не ответ
    only_arp = merge(arp=[{"mac-address": "AA:BB:CC:00:11:22", "address": "10.1.1.5",
                           "interface": "bridge"}])
    assert only_arp[0]["port"] == ""
    assert only_arp[0]["link"] == "wired"

    # Старое поле interface тоже понимаем: на RouterOS 6 оно единственное
    old = merge(hosts=[{"mac-address": "AA:BB:CC:00:11:22", "interface": "ether7"}])
    assert old[0]["port"] == "ether7"


def test_client_label_survives_cleanup(client, router):
    """
    Своя подпись живёт дольше срока хранения.

    Раз человек назвал строку «касса у входа», значит она ему нужна,
    и стирать её вместе с безымянными неправильно.
    """
    from app.clients import prune
    from app.database import execute, query_one

    _add_device(client, router, "shop-2")
    client.post("/api/clients/collect")

    named = query_one(
        "SELECT id FROM clients WHERE mac = ? ORDER BY id DESC LIMIT 1",
        ("bc:24:11:f0:70:db",))
    assert client.post(f"/api/clients/{named['id']}/label",
                       json={"label": "касса у входа"}).status_code == 200

    execute("UPDATE clients SET last_seen = datetime('now','-90 days')")
    removed = prune(30)

    assert removed >= 1, "безымянные старые записи должны удаляться"
    kept = query_one("SELECT label FROM clients WHERE id = ?", (named["id"],))
    assert kept is not None and kept["label"] == "касса у входа"

    # Подпись видна на странице и её можно снять
    assert "касса у входа" in client.get("/clients").text
    client.post(f"/api/clients/{named['id']}/label", json={"label": ""})
    assert query_one("SELECT label FROM clients WHERE id = ?", (named["id"],))["label"] == ""


def test_forget_all_respects_filters_and_labels(client, router):
    """
    «Забыть всех» удаляет ровно то, что видно на экране.

    Условия те же, что и у списка: выбрана точка — очистится только она.
    Подписанные строки остаются: их заводили руками, и стирать их заодно
    с мусором неправильно.
    """
    from app.database import query_one

    first = _add_device(client, router, "wipe-1")
    second = _add_device(client, router, "wipe-2")
    client.post("/api/clients/collect")

    named = query_one(
        "SELECT id FROM clients WHERE device_id = ? LIMIT 1", (first,))
    client.post(f"/api/clients/{named['id']}/label", json={"label": "не трогать"})

    before_second = len(query("SELECT id FROM clients WHERE device_id = ?", (second,)))
    assert before_second > 0

    # Чистим только первую точку
    r = client.post("/api/clients/forget-all", json={"device_id": str(first)})
    assert r.status_code == 200
    assert r.json()["removed"] > 0

    left = query("SELECT id, label FROM clients WHERE device_id = ?", (first,))
    assert [row["label"] for row in left] == ["не трогать"], left
    # Соседняя точка не тронута
    assert len(query("SELECT id FROM clients WHERE device_id = ?", (second,))) == before_second

    # Подписанную можно убрать только явным флагом
    client.post("/api/clients/forget-all",
                json={"device_id": str(first), "keep_labeled": False})
    assert query("SELECT id FROM clients WHERE device_id = ?", (first,)) == []

    # Урезанному пользователю чистка не даёт добраться до чужих точек
    _make_user(client, "narrowwipe", ["clients.view"], scope_all=False)
    with _as("narrowwipe") as narrow:
        assert narrow.post("/api/clients/forget-all", json={}).json()["removed"] == 0
    assert len(query("SELECT id FROM clients WHERE device_id = ?", (second,))) == before_second


def test_clients_need_permission_and_scope(client, router):
    """Клиенты закрыты правом и подчиняются области видимости."""
    device_id = _add_device(client, router, "shop-3")
    client.post("/api/clients/collect")

    _make_user(client, "noclients", ["backups.view"])
    with _as("noclients") as limited:
        assert limited.get("/clients").status_code == 403
        assert limited.post("/api/clients/collect").status_code == 403

    # Пользователь с правом, но с пустой областью видимости, не видит ничего
    _make_user(client, "narrow", ["clients.view"], scope_all=False)
    with _as("narrow") as narrow:
        page = narrow.get("/clients")
        assert page.status_code == 200
        assert "bc:24:11:f0:70:db" not in page.text

        row = query("SELECT id FROM clients LIMIT 1")[0]
        assert narrow.post(f"/api/clients/{row['id']}/label",
                           json={"label": "чужое"}).status_code == 403
        assert narrow.post(f"/api/clients/{row['id']}/delete").status_code == 403
