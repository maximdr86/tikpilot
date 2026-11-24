"""Focused tests for the device-list RouterOS version filter."""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3

from cryptography.fernet import Fernet
import pytest

# Do not read the protected local Fernet key when importing application config.
os.environ.setdefault("FERNET_KEY", Fernet.generate_key().decode())

from fastapi.responses import JSONResponse
from starlette.requests import Request

from app.routes import devices


def _request(path: str = "/devices") -> Request:
    return Request({
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [],
        "server": ("testserver", 80),
        "client": ("testclient", 50000),
        "root_path": "",
    })


@pytest.fixture
def device_database(monkeypatch):
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    connection.create_function(
        "lower_ru", 1,
        lambda value: value.lower() if isinstance(value, str) else value,
        deterministic=True,
    )
    connection.executescript("""
        CREATE TABLE groups (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL DEFAULT '',
            color TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            group_id INTEGER,
            name TEXT NOT NULL,
            host TEXT NOT NULL DEFAULT '',
            comment TEXT NOT NULL DEFAULT '',
            identity TEXT NOT NULL DEFAULT '',
            board_name TEXT NOT NULL DEFAULT '',
            operator TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'unknown',
            enabled INTEGER NOT NULL DEFAULT 1,
            ros_version TEXT NOT NULL DEFAULT '',
            latest_version TEXT NOT NULL DEFAULT ''
        );
    """)

    def query(sql, params=()):
        return connection.execute(sql, tuple(params)).fetchall()

    monkeypatch.setattr(devices, "query", query)
    yield connection
    connection.close()


def test_devices_page_filters_by_exact_routeros_version(monkeypatch, device_database):
    connection = device_database
    connection.executemany(
        "INSERT INTO devices (id, name, ros_version, latest_version) VALUES (?, ?, ?, ?)",
        [
            (1, "router-7.9", "7.9", "7.9"),
            (2, "router-7.14.3", "7.14.3", "7.14.3"),
            (3, "router-version-unknown", "", ""),
        ],
    )
    monkeypatch.setattr(
        devices,
        "render",
        lambda _template, _request, _user, **context: JSONResponse({
            "names": [device["name"] for device in context["devices"]],
            "selected_version": context["f_ros_version"],
        }),
    )

    response = asyncio.run(devices.devices_page(
        _request(),
        ros_version="7.14.3",
        user=None,
    ))

    assert json.loads(response.body) == {
        "names": ["router-7.14.3"],
        "selected_version": "7.14.3",
    }


def test_routeros_version_options_only_include_visible_devices(monkeypatch, device_database):
    connection = device_database
    connection.executemany(
        "INSERT INTO groups (id, name) VALUES (?, ?)",
        [(1, "visible"), (2, "hidden")],
    )
    connection.executemany(
        "INSERT INTO devices (id, group_id, name, ros_version) VALUES (?, ?, ?, ?)",
        [
            (1, 1, "visible-router-7.9", "7.9"),
            (2, 1, "visible-router-7.14.3", "7.14.3"),
            (3, 1, "visible-router-unknown", ""),
            (4, 2, "hidden-router", "7.15.0"),
        ],
    )
    monkeypatch.setattr(
        devices,
        "render",
        lambda _template, _request, _user, **context: JSONResponse({
            "names": [device["name"] for device in context["devices"]],
            "versions": context["ros_versions"],
        }),
    )
    user = {
        "scope_all": False,
        "groups": {1},
        "devices": set(),
        "permissions": set(),
    }

    response = asyncio.run(devices.devices_page(_request(), user=user))

    assert json.loads(response.body) == {
        "names": [
            "visible-router-7.14.3",
            "visible-router-7.9",
            "visible-router-unknown",
        ],
        "versions": ["7.9", "7.14.3"],
    }


def test_device_rows_endpoint_preserves_routeros_version_filter(monkeypatch, device_database):
    connection = device_database
    connection.executemany(
        "INSERT INTO devices (id, name, ros_version, latest_version) VALUES (?, ?, ?, ?)",
        [
            (1, "router-7.9", "7.9", "7.9"),
            (2, "router-7.14.3", "7.14.3", "7.14.3"),
        ],
    )
    monkeypatch.setattr(
        devices,
        "render_partial",
        lambda _template, _request, _user, **context: JSONResponse({
            "names": [device["name"] for device in context["devices"]],
        }),
    )

    response = asyncio.run(devices.devices_rows(
        _request("/devices/rows"),
        ros_version="7.14.3",
        user=None,
    ))

    assert json.loads(response.body) == {"names": ["router-7.14.3"]}
