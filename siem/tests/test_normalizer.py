"""Tests du normalisateur d'audit (services/soc-siem/normalizer.py)."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

SOC_SIEM = Path(__file__).resolve().parents[2] / "services" / "soc-siem"
if str(SOC_SIEM) not in sys.path:
    sys.path.insert(0, str(SOC_SIEM))

from normalizer import (  # noqa: E402
    AuditNormalizer,
    normalize_batch,
    parse_timestamp,
    to_jsonl,
)


def _event(
    *,
    event_type: str = "AUTH_LOGIN",
    outcome: str = "FAILURE",
    actor: str = "alice",
    when: str = "2026-10-24T18:00:00Z",
    details: dict | None = None,
) -> dict:
    return {
        "event_time": when,
        "event_type": event_type,
        "actor_username": actor,
        "actor_ip": "10.10.20.15",
        "action": "LOGIN",
        "resource": "/api/v1/auth/login",
        "outcome": outcome,
        "details": details or {},
        "prev_log_hash": "a" * 64,
        "current_hash": "b" * 64,
    }


def test_parse_timestamp_variants() -> None:
    assert parse_timestamp("2026-10-24T18:00:00Z") == datetime(
        2026, 10, 24, 18, 0, tzinfo=timezone.utc
    )
    naive = parse_timestamp(datetime(2026, 10, 24, 18, 0))
    assert naive.tzinfo == timezone.utc
    assert parse_timestamp(0).year == 1970


def test_force_brute_puis_succes() -> None:
    rows = [
        _event(when="2026-10-24T18:00:00Z"),
        _event(when="2026-10-24T18:01:00Z"),
        _event(when="2026-10-24T18:02:00Z"),
        _event(
            outcome="SUCCESS",
            when="2026-10-24T18:03:00Z",
            details={"roles": ["OT_OPERATOR"]},
        ),
        _event(when="2026-10-24T18:04:00Z"),
    ]
    events = normalize_batch(rows)
    assert [e["details"]["prior_failures"] for e in events[:3]] == [0, 1, 2]
    assert events[3]["details"]["prior_failures"] == 3
    assert events[3]["details"]["roles"] == ["OT_OPERATOR"]
    # La remise a zero apres succes remet le compteur a 0.
    assert events[4]["details"]["prior_failures"] == 0
    assert events[4]["details"]["attempt_count"] == 1


def test_attempt_count_backend_preserve() -> None:
    event = AuditNormalizer().normalize(
        _event(details={"reason": "invalid_password", "attempt_count": 5})
    )
    assert event["details"]["attempt_count"] == 5
    assert event["details"]["prior_failures"] == 0


def test_fenetre_echecs_15_minutes() -> None:
    normalizer = AuditNormalizer()
    first = normalizer.normalize(_event(when="2026-10-24T18:00:00Z"))
    # 20 minutes plus tard : le premier echec est hors fenetre.
    second = normalizer.normalize(_event(when="2026-10-24T18:20:00Z"))
    assert first["details"]["prior_failures"] == 0
    assert second["details"]["prior_failures"] == 0


def test_refus_rbac_repetes() -> None:
    rows = [
        _event(event_type="ACCESS_DENIED_RBAC", when=f"2026-10-24T18:0{i}:00Z")
        for i in range(5)
    ]
    events = normalize_batch(rows)
    assert [e["details"]["denied_count"] for e in events] == [1, 2, 3, 4, 5]


def test_refus_rbac_fenetre_10_minutes() -> None:
    normalizer = AuditNormalizer()
    for i in range(3):
        normalizer.normalize(
            _event(event_type="ACCESS_DENIED_RBAC", when=f"2026-10-24T18:0{i}:00Z")
        )
    after = normalizer.normalize(
        _event(event_type="ACCESS_DENIED_RBAC", when="2026-10-24T18:30:00Z")
    )
    assert after["details"]["denied_count"] == 1


def test_champs_normalises_et_hashes() -> None:
    event = AuditNormalizer().normalize(_event())
    assert event["source"] == "securiglass.audit"
    assert event["srcip"] == "10.10.20.15"
    assert event["prev_log_hash"] == "a" * 64
    assert event["current_hash"] == "b" * 64
    assert event["event_time"].endswith("+00:00")


def test_entree_non_mutee() -> None:
    details = {"reason": "invalid_password"}
    row = _event(details=details)
    AuditNormalizer().normalize(row)
    assert details == {"reason": "invalid_password"}
    assert "prior_failures" not in details


def test_jsonl_serialisable() -> None:
    event = AuditNormalizer().normalize(_event())
    line = to_jsonl(event)
    assert "\n" not in line
    decoded = json.loads(line)
    assert decoded["source"] == "securiglass.audit"
    assert decoded["details"]["prior_failures"] == 0


def test_evenement_non_auth_ne_contient_pas_de_compteur() -> None:
    event = AuditNormalizer().normalize(
        _event(event_type="CUSTOMER_LISTED", outcome="SUCCESS", details={"record_count": 10})
    )
    assert "prior_failures" not in event["details"]
    assert "denied_count" not in event["details"]
    assert event["details"]["record_count"] == 10
