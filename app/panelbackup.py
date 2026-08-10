"""
Архив всей панели: база, ключ шифрования, настройки, бэкапы устройств.

Зачем отдельно от бэкапов роутеров
----------------------------------

Бэкапы устройств лежат на сервере панели. Если сервер погибнет, вместе
с ним погибнет и список устройств, и история, и все снятые копии, то есть
ровно то, ради чего бэкапы и делались. Архив панели закрывает этот случай:
разворачивается на новой машине и продолжает работать как был.

Что внутри и почему это опасный файл
------------------------------------

В архиве лежит `data/fernet.key`, а вместе с базой он даёт пароли всех
роутеров в открытом виде. Это осознанный выбор: архив самодостаточен и
разворачивается одной командой, не требуя искать ключ, сохранённый
где-то отдельно полгода назад.

Плата за удобство прямая: кто получил файл, получил парк. Поэтому архив
создаётся только по явной кнопке, требует отдельного права, попадает
в журнал действий и лежит на диске с правами 600. Хранить его на флешке
в столе или отправлять почтой нельзя.

Про согласованность базы
------------------------

SQLite нельзя просто скопировать на ходу: часть данных в этот момент
может быть в журнале WAL, и копия получится битой ровно тогда, когда
понадобится. Поэтому снимок делается штатным механизмом `backup()`,
который для того и существует.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from .config import BASE_DIR, settings

#: Куда складываются архивы панели.
ARCHIVE_DIR_NAME = "panel"

#: Пояснение внутри архива. Человек, нашедший файл через год, должен
#: понять, что это, чем оно опасно и что с ним делать.
README = """Архив панели Tikpilot {version}
Создан: {created}

ЧТО ВНУТРИ

  restore.sh            разворачивание на чистой Ubuntu одной командой
  install-ubuntu.sh     установщик, его вызывает restore.sh
  manifest.json         версия, дата, сколько чего внутри
  data/tikpilot.db      база: устройства, группы, пользователи, история
  data/fernet.key       ключ шифрования паролей устройств
  data/backups/         снятые копии роутеров, если они включались в архив
  env                   файл настроек (.env)
  app/ templates/ ...   код панели этой же версии

ЭТО ОПАСНЫЙ ФАЙЛ

  База и ключ лежат рядом, поэтому из архива достаются пароли всех
  роутеров в открытом виде. Считайте его равным связке ключей от всех
  площадок: не оставляйте на флешке, не отправляйте почтой и не кладите
  в облако без своего шифрования.

КАК РАЗВЕРНУТЬ НА ЧИСТОЙ UBUNTU

  tar xzf tikpilot-panel-*.tar.gz
  cd tikpilot-panel-*
  sudo bash restore.sh

  Скрипт разложит данные, поставит зависимости, заведёт службу systemd,
  откроет порт и проверит, что база читается, а пароли расшифровываются.
  Интернет нужен только для установки пакетов Python.

  Если панель на этой машине уже стоит, прежние данные не удаляются,
  а отодвигаются в /opt/tikpilot/data.bak-<дата>.

  Вход тем же логином и паролем, что и раньше: они лежат в базе.

ЕСЛИ НАДО РУКАМИ

  1. Остановите службу:            sudo systemctl stop tikpilot
  2. Скопируйте на место:
       data/tikpilot.db  ->  /opt/tikpilot/data/tikpilot.db
       data/fernet.key   ->  /opt/tikpilot/data/fernet.key
       data/backups/     ->  /opt/tikpilot/data/backups/
       env               ->  /opt/tikpilot/.env
  3. Проверьте владельца:  sudo chown -R tikpilot:tikpilot /opt/tikpilot
  4. Запустите:            sudo systemctl start tikpilot
"""

#: Что кладём из папки проекта. Список, а не «всё подряд»: в архив не должны
#: попасть ни рабочие данные, ни виртуальное окружение, ни devices.csv
#: с настоящими адресами и учётными записями.
CODE_ITEMS = (
    "app", "templates", "static", "tests", "docs",
    "requirements.txt", "requirements-dev.txt", "pytest.ini",
    "install-ubuntu.sh", "run.sh", "run.bat", "check.sh", "check-data.sh",
    "restore-data.sh", "migrate-from-rosmanager.sh",
    "Dockerfile", "docker-compose.yml",
    "README.md", "README.ru.md", "CHANGELOG.md", "CONTRIBUTING.md",
    "SECURITY.md", "LICENSE", ".env.example",
)

#: Мусор, который в архиве не нужен и только раздувает его.
SKIP_PARTS = ("__pycache__", ".pytest_cache", ".venv", ".git")


def archive_dir() -> Path:
    """Каталог с архивами панели, создаётся при первом обращении."""
    path = settings.backup_dir / ARCHIVE_DIR_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def snapshot_database(target: Path) -> None:
    """
    Согласованная копия базы.

    Именно копия механизмом SQLite, а не `cp`: на ходу часть данных лежит
    в журнале WAL, и простое копирование файла даёт базу, которая может
    не открыться. Узнать об этом получилось бы в худший момент.
    """
    source = sqlite3.connect(str(settings.db_path))
    try:
        destination = sqlite3.connect(str(target))
        try:
            source.backup(destination)
        finally:
            destination.close()
    finally:
        source.close()


def _counts(db_copy: Path, device_backups: int) -> dict[str, Any]:
    """Сколько чего в архиве. Нужно, чтобы при разворачивании было что сверить."""
    conn = sqlite3.connect(str(db_copy))
    try:
        def one(sql: str) -> int:
            try:
                return int(conn.execute(sql).fetchone()[0])
            except sqlite3.Error:
                return 0

        return {
            "devices": one("SELECT COUNT(*) FROM devices"),
            "users": one("SELECT COUNT(*) FROM users"),
            "groups": one("SELECT COUNT(*) FROM groups"),
            "status_events": one("SELECT COUNT(*) FROM status_events"),
            "device_backups": device_backups,
        }
    finally:
        conn.close()


def _skip(path: Path) -> bool:
    """Служебные каталоги и скомпилированные файлы в архив не идут."""
    return any(part in SKIP_PARTS for part in path.parts) or path.suffix == ".pyc"


def build(include_device_backups: bool = True, include_code: bool = True) -> Path:
    """
    Собрать архив и вернуть путь к нему.

    Внутри лежит не только копия данных, но и код этой же версии вместе
    со скриптом разворачивания. Причина простая: архив нужен ровно тогда,
    когда сервер погиб, а в этот момент искать подходящую версию панели
    на GitHub и вспоминать, какие файлы куда класть, будет некогда.
    Распаковал, запустил один скрипт, работает.

    Всё складывается в одну папку внутри архива, чтобы распаковка не
    рассыпала полсотни файлов по текущему каталогу.

    Права на файл сразу 600: архив с ключом не должен читаться всеми
    пользователями сервера, и выставлять это потом, отдельным шагом,
    значит однажды забыть.
    """
    created = datetime.now(timezone.utc)
    stamp = created.strftime("%Y%m%d-%H%M%S")
    name = "tikpilot-panel-%s.tar.gz" % stamp
    root = "tikpilot-panel-%s" % stamp
    path = archive_dir() / name

    with tempfile.TemporaryDirectory() as tmp:
        db_copy = Path(tmp) / "tikpilot.db"
        snapshot_database(db_copy)

        notes = Path(tmp) / "ПРОЧТИ-МЕНЯ.txt"
        notes.write_text(
            README.format(
                version=__version__,
                created=created.strftime("%Y-%m-%d %H:%M:%S UTC"),
            ),
            encoding="utf-8",
        )

        device_backups = sorted(
            item for item in settings.backup_dir.glob("*") if item.is_file()
        ) if include_device_backups else []

        manifest = Path(tmp) / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "version": __version__,
                    "created": created.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "with_code": include_code,
                    "with_device_backups": include_device_backups,
                    "db_sha256": hashlib.sha256(db_copy.read_bytes()).hexdigest(),
                    **_counts(db_copy, len(device_backups)),
                },
                ensure_ascii=False,
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )

        with tarfile.open(path, "w:gz") as archive:
            archive.add(db_copy, arcname=f"{root}/data/tikpilot.db")
            archive.add(notes, arcname=f"{root}/ПРОЧТИ-МЕНЯ.txt")
            archive.add(manifest, arcname=f"{root}/manifest.json")

            key = settings.data_dir / "fernet.key"
            if key.exists():
                archive.add(key, arcname=f"{root}/data/fernet.key")

            env = BASE_DIR / ".env"
            if env.exists():
                archive.add(env, arcname=f"{root}/env")

            # Прошлые архивы панели внутрь не кладём: иначе каждый следующий
            # вдвое больше предыдущего
            for item in device_backups:
                archive.add(item, arcname=f"{root}/data/backups/" + item.name)

            if include_code:
                for item_name in CODE_ITEMS:
                    item = BASE_DIR / item_name
                    if not item.exists():
                        continue
                    archive.add(
                        item,
                        arcname=f"{root}/{item_name}",
                        filter=lambda info: None if _skip(Path(info.name)) else info,
                    )
                # Скрипт разворачивания кладём под коротким именем: в
                # пояснении внутри архива написано «sudo bash restore.sh»,
                # и это должно совпадать с тем, что человек видит рядом
                restore = BASE_DIR / "restore-panel.sh"
                if restore.exists():
                    archive.add(restore, arcname=f"{root}/restore.sh")

    os.chmod(path, 0o600)
    return path


def listing() -> list[dict[str, Any]]:
    """Существующие архивы, свежие сверху."""
    result = []
    for item in archive_dir().glob("tikpilot-panel-*.tar.gz"):
        stat = item.stat()
        result.append({
            "name": item.name,
            "size": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime, timezone.utc)
                                  .strftime("%Y-%m-%d %H:%M:%S"),
        })
    result.sort(key=lambda r: r["name"], reverse=True)
    return result


def resolve(name: str) -> Path | None:
    """
    Путь к архиву по имени, с проверкой, что это действительно наш архив.

    Имя приходит из браузера, поэтому проверяется и шаблон, и итоговый
    путь: «../../etc/passwd» не должен вести никуда.
    """
    if not name.startswith("tikpilot-panel-") or not name.endswith(".tar.gz"):
        return None
    path = (archive_dir() / name).resolve()
    if not str(path).startswith(str(archive_dir().resolve())) or not path.exists():
        return None
    return path


def prune(keep: int) -> int:
    """Оставить только `keep` последних архивов. Возвращает число удалённых."""
    if keep <= 0:
        return 0
    extra = listing()[keep:]
    for item in extra:
        path = resolve(item["name"])
        if path:
            path.unlink(missing_ok=True)
    return len(extra)
