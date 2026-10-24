"""Tests unitaires du chaînage cryptographique SHA-256 d'audit (IEC 62443)."""

from datetime import datetime, timezone
import pytest

from app.services.audit_service import (
    calculate_record_hash,
    verify_chain_in_memory,
)


def test_audit_chain_valid_sequence() -> None:
    t1 = datetime(2026, 10, 24, 8, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 24, 8, 1, 0, tzinfo=timezone.utc)
    t3 = datetime(2026, 10, 24, 8, 2, 0, tzinfo=timezone.utc)

    # Log 1 (Genesis)
    h1 = calculate_record_hash(
        prev_hash=None,
        event_time=t1,
        event_type="AUTH_LOGIN",
        actor_username="operator_01",
        actor_ip="10.10.20.15",
        action="LOGIN",
        resource="/api/v1/auth/login",
        outcome="SUCCESS",
        details={"shift": "morning"},
    )
    rec1 = {
        "id": "log-001",
        "event_time": t1,
        "event_type": "AUTH_LOGIN",
        "actor_username": "operator_01",
        "actor_ip": "10.10.20.15",
        "action": "LOGIN",
        "resource": "/api/v1/auth/login",
        "outcome": "SUCCESS",
        "details": {"shift": "morning"},
        "prev_log_hash": None,
        "current_hash": h1,
    }

    # Log 2 (enchaîné sur h1)
    h2 = calculate_record_hash(
        prev_hash=h1,
        event_time=t2,
        event_type="FURNACE_SETPOINT_UPDATE",
        actor_username="operator_01",
        actor_ip="10.10.20.15",
        action="WRITE",
        resource="urn:securiglass:ot:furnace:line-01",
        outcome="SUCCESS",
        details={"temp_zone1_target": 680.0},
    )
    rec2 = {
        "id": "log-002",
        "event_time": t2,
        "event_type": "FURNACE_SETPOINT_UPDATE",
        "actor_username": "operator_01",
        "actor_ip": "10.10.20.15",
        "action": "WRITE",
        "resource": "urn:securiglass:ot:furnace:line-01",
        "outcome": "SUCCESS",
        "details": {"temp_zone1_target": 680.0},
        "prev_log_hash": h1,
        "current_hash": h2,
    }

    # Log 3 (enchaîné sur h2)
    h3 = calculate_record_hash(
        prev_hash=h2,
        event_time=t3,
        event_type="AUTH_LOGOUT",
        actor_username="operator_01",
        actor_ip="10.10.20.15",
        action="LOGOUT",
        resource="/api/v1/auth/logout",
        outcome="SUCCESS",
        details=None,
    )
    rec3 = {
        "id": "log-003",
        "event_time": t3,
        "event_type": "AUTH_LOGOUT",
        "actor_username": "operator_01",
        "actor_ip": "10.10.20.15",
        "action": "LOGOUT",
        "resource": "/api/v1/auth/logout",
        "outcome": "SUCCESS",
        "details": None,
        "prev_log_hash": h2,
        "current_hash": h3,
    }

    valid, broken_id = verify_chain_in_memory([rec1, rec2, rec3])
    assert valid is True
    assert broken_id is None


def test_audit_chain_detects_data_tampering() -> None:
    t1 = datetime(2026, 10, 24, 8, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 24, 8, 1, 0, tzinfo=timezone.utc)

    h1 = calculate_record_hash(
        None, t1, "EVENT1", "alice", "10.10.20.1", "READ", "res1", "SUCCESS"
    )
    rec1 = {
        "id": "id-1",
        "event_time": t1,
        "event_type": "EVENT1",
        "actor_username": "alice",
        "actor_ip": "10.10.20.1",
        "action": "READ",
        "resource": "res1",
        "outcome": "SUCCESS",
        "details": None,
        "prev_log_hash": None,
        "current_hash": h1,
    }

    h2 = calculate_record_hash(
        h1, t2, "EVENT2", "bob", "10.10.20.2", "WRITE", "res2", "SUCCESS"
    )
    rec2 = {
        "id": "id-2",
        "event_time": t2,
        "event_type": "EVENT2",
        "actor_username": "bob",
        "actor_ip": "10.10.20.2",
        "action": "WRITE",
        "resource": "res2",
        "outcome": "SUCCESS",
        "details": None,
        "prev_log_hash": h1,
        "current_hash": h2,
    }

    # Tentative d'effacement de trace : modification de l'acteur de rec1
    falsified_rec1 = dict(rec1)
    falsified_rec1["actor_username"] = "eve"

    valid, broken_id = verify_chain_in_memory([falsified_rec1, rec2])
    assert valid is False
    assert broken_id == "id-1"


def test_audit_chain_detects_record_deletion_or_insertion() -> None:
    t1 = datetime(2026, 10, 24, 8, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 24, 8, 1, 0, tzinfo=timezone.utc)

    h1 = calculate_record_hash(
        None, t1, "EV1", "u1", "10.10.20.1", "A1", "R1", "SUCCESS"
    )
    rec1 = {
        "id": "rec-1",
        "event_time": t1,
        "event_type": "EV1",
        "actor_username": "u1",
        "actor_ip": "10.10.20.1",
        "action": "A1",
        "resource": "R1",
        "outcome": "SUCCESS",
        "prev_log_hash": None,
        "current_hash": h1,
    }

    h2 = calculate_record_hash(h1, t2, "EV2", "u1", "10.10.20.1", "A2", "R2", "SUCCESS")
    rec2 = {
        "id": "rec-2",
        "event_time": t2,
        "event_type": "EV2",
        "actor_username": "u1",
        "actor_ip": "10.10.20.1",
        "action": "A2",
        "resource": "R2",
        "outcome": "SUCCESS",
        "prev_log_hash": "f" * 64,  # Lien prev rompu
        "current_hash": h2,
    }

    valid, broken_id = verify_chain_in_memory([rec1, rec2])
    assert valid is False
    assert broken_id == "rec-2"
