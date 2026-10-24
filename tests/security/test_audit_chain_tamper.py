"""Chaîne d'audit : immuabilité SQL et détection de rupture cryptographique.

Cible : `app.services.audit_service` + trigger `sec_data.audit_logs`.
Toute écriture de test est annulée (rollback) : le journal reste vierge.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import asyncpg
import pytest

from app.services.audit_service import (
    calculate_record_hash,
    record_event,
    verify_chain_in_memory,
    verify_stored_chain,
)

from tests.integration.helpers import RollbackSentinel


def _row(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "00000000-0000-4000-8000-000000000001",
        "event_time": datetime(2026, 10, 24, 12, 0, 0, tzinfo=timezone.utc),
        "event_type": "AUTH_LOGIN",
        "actor_username": "operator1",
        "actor_ip": "10.10.20.15",
        "action": "LOGIN",
        "resource": "urn:securiglass:iam:session",
        "outcome": "SUCCESS",
        "details": {"user_agent": "pytest"},
        "prev_log_hash": None,
    }
    base.update(overrides)
    base["current_hash"] = calculate_record_hash(
        prev_hash=base["prev_log_hash"],
        event_time=base["event_time"],
        event_type=base["event_type"],
        actor_username=base["actor_username"],
        actor_ip=base["actor_ip"],
        action=base["action"],
        resource=base["resource"],
        outcome=base["outcome"],
        details=base["details"],
    )
    return base


def test_intact_chain_is_valid_in_memory() -> None:
    first = _row()
    second = _row(
        id="00000000-0000-4000-8000-000000000002",
        event_time=first["event_time"] + timedelta(seconds=1),
        prev_log_hash=first["current_hash"],
        event_type="OT_CONTROL_WRITE",
    )
    ok, broken = verify_chain_in_memory([first, second])
    assert ok is True
    assert broken is None


def test_tampered_content_is_detected_in_memory() -> None:
    first = _row()
    tampered = dict(first)
    tampered["actor_username"] = "attacker"
    ok, broken = verify_chain_in_memory([tampered])
    assert ok is False
    assert broken == str(first["id"])


def test_tampered_previous_link_is_detected_in_memory() -> None:
    first = _row()
    second = _row(
        id="00000000-0000-4000-8000-000000000002",
        event_time=first["event_time"] + timedelta(seconds=1),
        prev_log_hash="de" * 32,
    )
    ok, broken = verify_chain_in_memory([first, second])
    assert ok is False
    assert broken == str(second["id"])


def test_reordered_records_are_detected_in_memory() -> None:
    first = _row()
    second = _row(
        id="00000000-0000-4000-8000-000000000002",
        event_time=first["event_time"] + timedelta(seconds=1),
        prev_log_hash=first["current_hash"],
    )
    ok, broken = verify_chain_in_memory([second, first])
    assert ok is False
    assert broken == str(second["id"])


def test_json_string_details_are_supported() -> None:
    """asyncpg renvoie une colonne JSONB sous forme de chaîne : la vérification
    doit parser ce JSON avant de recalculer l'empreinte."""
    row = _row()
    row["details"] = json.dumps(row["details"], sort_keys=True)
    ok, broken = verify_chain_in_memory([row])
    assert ok is True
    assert broken is None


def test_injection_of_forged_log_in_middle_detected() -> None:
    """Attaque Red Team : insertion d'un faux événement au milieu d'une chaîne existante."""
    first = _row()
    second = _row(
        id="00000000-0000-4000-8000-000000000002",
        event_time=first["event_time"] + timedelta(seconds=1),
        prev_log_hash=first["current_hash"],
        event_type="OT_CONTROL_WRITE",
    )
    # L'attaquant forge un événement intermédiaire se réclamant être le fils du premier
    forged = _row(
        id="00000000-0000-4000-8000-000000000003",
        event_time=first["event_time"] + timedelta(milliseconds=500),
        prev_log_hash=first["current_hash"],
        event_type="UNAUTHORIZED_FURNACE_COMMAND",
    )
    # Dans la chaîne [first, forged, second], second n'a pas prev_log_hash pointant sur forged
    ok, broken = verify_chain_in_memory([first, forged, second])
    assert ok is False
    assert broken == str(second["id"])


def test_tampered_current_hash_detected() -> None:
    """Attaque Red Team : altération du hash courant (ex: bit-flip ou hash invalide)."""
    first = _row()
    tampered = dict(first)
    tampered["current_hash"] = "00" * 32
    ok, broken = verify_chain_in_memory([tampered])
    assert ok is False
    assert broken == str(first["id"])


def test_tampered_actor_ip_detected() -> None:
    """Attaque Red Team : tentative de masquer l'adresse IP de l'attaquant dans les logs."""
    first = _row()
    tampered = dict(first)
    tampered["actor_ip"] = "192.168.1.99"
    ok, broken = verify_chain_in_memory([tampered])
    assert ok is False
    assert broken == str(first["id"])


def test_tampered_event_time_detected() -> None:
    """Attaque Red Team : antidatage d'un événement d'audit."""
    first = _row()
    tampered = dict(first)
    tampered["event_time"] = first["event_time"] - timedelta(days=1)
    ok, broken = verify_chain_in_memory([tampered])
    assert ok is False
    assert broken == str(first["id"])


def test_forged_first_log_with_non_null_prev_hash() -> None:
    """Attaque Red Team : création d'un premier log avec un hash précédent inventé."""
    first = _row(prev_log_hash="aa" * 32)
    ok, broken = verify_chain_in_memory([first])
    assert ok is False
    assert broken == str(first["id"])


# ---------------------------------------------------------------------------
# Tests PostgreSQL (transaction annulée)
# ---------------------------------------------------------------------------
async def _audit_rows(conn: asyncpg.Connection) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        "SELECT id, event_time, event_type, actor_username, actor_ip, action, resource,"
        " outcome, details, prev_log_hash, current_hash"
        " FROM sec_data.audit_logs ORDER BY event_time ASC, id ASC"
    )
    return [dict(r) for r in rows]


async def _expect_sql_error(
    conn: asyncpg.Connection, sql: str, exc_type: type[Exception], *args: Any
) -> None:
    """Exécute une requête dans un point de sauvegarde en attendant une erreur SQL."""
    with pytest.raises(exc_type):
        async with conn.transaction():
            await conn.execute(sql, *args)


async def test_audit_table_is_append_only(db_conn: asyncpg.Connection) -> None:
    try:
        async with db_conn.transaction():
            await record_event(
                db_conn,
                event_type="QA_TRIGGER_TEST",
                actor_username="qa",
                actor_ip="10.10.20.5",
                action="TEST",
                resource="urn:securiglass:test:append-only",
                outcome="SUCCESS",
            )
            await _expect_sql_error(
                db_conn,
                "UPDATE sec_data.audit_logs SET actor_username = 'x' "
                "WHERE event_type = 'QA_TRIGGER_TEST'",
                asyncpg.exceptions.RaiseError,
            )
            await _expect_sql_error(
                db_conn,
                "DELETE FROM sec_data.audit_logs WHERE event_type = 'QA_TRIGGER_TEST'",
                asyncpg.exceptions.RaiseError,
            )
            raise RollbackSentinel
    except RollbackSentinel:
        pass


async def test_db_chain_is_valid_after_three_events(
    db_conn: asyncpg.Connection,
) -> None:
    try:
        async with db_conn.transaction():
            hashes = [
                await record_event(
                    db_conn,
                    event_type="QA_CHAIN_TEST",
                    actor_username=f"qa-{i}",
                    actor_ip="10.10.20.5",
                    action="TEST",
                    resource=f"urn:securiglass:test:{i}",
                    outcome="SUCCESS",
                    details={"index": i},
                )
                for i in range(3)
            ]
            ok, broken = await verify_stored_chain(db_conn)
            assert ok is True, f"chaîne invalide au niveau {broken}"
            rows = [
                r
                for r in await _audit_rows(db_conn)
                if r["event_type"] == "QA_CHAIN_TEST"
            ]
            assert [r["current_hash"] for r in rows] == hashes
            assert rows[1]["prev_log_hash"] == hashes[0]
            raise RollbackSentinel
    except RollbackSentinel:
        pass


async def test_dba_tampering_is_detected_by_chain(db_conn: asyncpg.Connection) -> None:
    """Un attaquant disposant des droits DBA peut désactiver le trigger :
    la chaîne SHA-256 doit alors détecter l'altération.
    """
    try:
        async with db_conn.transaction():
            target = await record_event(
                db_conn,
                event_type="QA_TAMPER_TARGET",
                actor_username="victim",
                actor_ip="10.10.20.9",
                action="LOGIN",
                resource="urn:securiglass:iam:session",
                outcome="FAILURE",
            )
            await record_event(
                db_conn,
                event_type="QA_TAMPER_AFTER",
                actor_username="qa",
                actor_ip="10.10.20.9",
                action="TEST",
                resource="urn:securiglass:test:after",
                outcome="SUCCESS",
            )
            await db_conn.execute(
                "ALTER TABLE sec_data.audit_logs DISABLE TRIGGER trg_audit_logs_immutable"
            )
            await db_conn.execute(
                "UPDATE sec_data.audit_logs SET outcome = 'SUCCESS' "
                "WHERE event_type = 'QA_TAMPER_TARGET'"
            )
            ok, broken = await verify_stored_chain(db_conn)
            assert ok is False
            assert broken is not None
            tampered = await db_conn.fetchrow(
                "SELECT id FROM sec_data.audit_logs WHERE event_type = 'QA_TAMPER_TARGET'"
            )
            assert tampered is not None
            assert str(tampered["id"]) == broken
            assert len(target) == 64
            raise RollbackSentinel
    except RollbackSentinel:
        pass


async def test_deleting_a_row_breaks_the_chain(db_conn: asyncpg.Connection) -> None:
    try:
        async with db_conn.transaction():
            first = await record_event(
                db_conn,
                event_type="QA_DELETE_A",
                actor_username="qa",
                actor_ip="10.10.20.5",
                action="TEST",
                resource="urn:securiglass:test:a",
                outcome="SUCCESS",
            )
            await record_event(
                db_conn,
                event_type="QA_DELETE_B",
                actor_username="qa",
                actor_ip="10.10.20.5",
                action="TEST",
                resource="urn:securiglass:test:b",
                outcome="SUCCESS",
            )
            await db_conn.execute(
                "ALTER TABLE sec_data.audit_logs DISABLE TRIGGER trg_audit_logs_immutable"
            )
            await db_conn.execute(
                "DELETE FROM sec_data.audit_logs WHERE event_type = 'QA_DELETE_A'"
            )
            ok, broken = await verify_stored_chain(db_conn)
            assert ok is False
            assert broken is not None
            assert first not in [r["current_hash"] for r in await _audit_rows(db_conn)]
            raise RollbackSentinel
    except RollbackSentinel:
        pass


async def test_record_event_is_deterministic_on_details_order(
    db_conn: asyncpg.Connection,
) -> None:
    """Les détails JSON sont sérialisés en JSON canonique (clés triées)."""
    h1 = calculate_record_hash(
        prev_hash=None,
        event_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        event_type="X",
        actor_username="u",
        actor_ip="10.0.0.1",
        action="A",
        resource="R",
        outcome="SUCCESS",
        details={"b": 2, "a": 1},
    )
    h2 = calculate_record_hash(
        prev_hash=None,
        event_time=datetime(2026, 1, 1, tzinfo=timezone.utc),
        event_type="X",
        actor_username="u",
        actor_ip="10.0.0.1",
        action="A",
        resource="R",
        outcome="SUCCESS",
        details=json.loads('{"a": 1, "b": 2}'),
    )
    assert h1 == h2
    assert len(h1) == 64
