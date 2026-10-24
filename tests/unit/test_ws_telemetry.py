"""Canal WebSocket /ws/telemetry : authentification par premier message, rôles, flux."""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from app.api import ws as ws_module
from app.api.deps import CurrentUser
from app.main import app


def _user(*roles: str) -> CurrentUser:
    return CurrentUser(
        id=uuid4(),
        username="u",
        email="u@securiglass.local",
        roles=list(roles),
        clearance_level=3,
        jti=str(uuid4()),
        token_exp=datetime.now(timezone.utc) + timedelta(minutes=5),
    )


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    @asynccontextmanager
    async def fake_conn() -> Any:
        yield object()

    monkeypatch.setattr(ws_module.db, "acquire_conn", fake_conn)
    monkeypatch.setattr(ws_module, "POLL_INTERVAL_S", 0.05)
    return TestClient(app)


def _patch_auth(monkeypatch: pytest.MonkeyPatch, user: CurrentUser | None) -> None:
    async def fake_auth(_conn: Any, token: str) -> CurrentUser:
        if user is None or token != "good":
            raise HTTPException(401, "bad")
        return user

    monkeypatch.setattr(ws_module, "authenticate_token", fake_auth)


def test_bad_token_gets_auth_error_and_policy_close(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_auth(monkeypatch, _user("PLANT_MANAGER"))
    with client.websocket_connect("/ws/telemetry") as sock:
        sock.send_json({"type": "auth", "token": "bad"})
        assert sock.receive_json() == {"type": "auth_error"}
        with pytest.raises(WebSocketDisconnect) as exc:
            sock.receive_json()
        assert exc.value.code == 1008


@pytest.mark.parametrize(
    "first",
    [
        {"type": "subscribe"},
        {"type": "auth"},
        {"type": "auth", "token": 5},
        {"type": "auth", "token": "x" * 3000},
    ],
)
def test_malformed_first_message_rejected(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, first: dict[str, Any]
) -> None:
    _patch_auth(monkeypatch, _user("PLANT_MANAGER"))
    with client.websocket_connect("/ws/telemetry") as sock:
        sock.send_json(first)
        assert sock.receive_json() == {"type": "auth_error"}


def test_role_without_telemetry_access_is_refused(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_auth(monkeypatch, _user("SERVICE_ACCOUNT_EDGE"))
    with client.websocket_connect("/ws/telemetry") as sock:
        sock.send_json({"type": "auth", "token": "good"})
        assert sock.receive_json() == {"type": "auth_error"}


def test_authenticated_client_receives_each_new_sample_once(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_auth(monkeypatch, _user("OT_OPERATOR"))
    samples = [
        (1, {"furnace_temp_c": 650.0}, {}),
        (1, {"furnace_temp_c": 650.0}, {}),
        (2, {"furnace_temp_c": 655.5}, {}),
    ]
    calls = {"n": 0}

    async def fake_latest(
        previous: dict[str, float] | None,
    ) -> tuple[int, dict[str, Any], dict[str, float]] | None:
        calls["n"] += 1
        return samples[min(calls["n"] - 1, len(samples) - 1)]

    monkeypatch.setattr(ws_module, "_latest_sample", fake_latest)
    with client.websocket_connect("/ws/telemetry") as sock:
        sock.send_json({"type": "auth", "token": "good"})
        assert sock.receive_json() == {"type": "auth_ok"}
        sock.send_json({"type": "subscribe", "channels": ["telemetry"]})
        first = sock.receive_json()
        second = sock.receive_json()  # l'échantillon identique (id 1) n'est pas renvoyé
    assert first == {"type": "telemetry", "payload": {"furnace_temp_c": 650.0}}
    assert second == {"type": "telemetry", "payload": {"furnace_temp_c": 655.5}}


def test_subscribe_to_unknown_channel_closes(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _patch_auth(monkeypatch, _user("PLANT_MANAGER"))
    with client.websocket_connect("/ws/telemetry") as sock:
        sock.send_json({"type": "auth", "token": "good"})
        assert sock.receive_json() == {"type": "auth_ok"}
        sock.send_json({"type": "subscribe", "channels": ["secrets"]})
        with pytest.raises(WebSocketDisconnect) as exc:
            sock.receive_json()
        assert exc.value.code == 1008


def test_connection_cap_refuses_extra_clients(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ws_module, "_active", ws_module.MAX_CONNECTIONS)
    with client.websocket_connect("/ws/telemetry") as sock:
        with pytest.raises(WebSocketDisconnect) as exc:
            sock.receive_json()
        assert exc.value.code == 1013
