"""Cohérence base ↔ moteur : les politiques ABAC persistées sont-elles sûres ?

Charge `sec_data.abac_policies` et rejoue les scénarios critiques à travers le
moteur réel. Cela verrouille le correctif D1 (règle inversée) au niveau des données.
"""

from __future__ import annotations

import json
from datetime import time
from typing import Any

import asyncpg
import pytest

from app.services.abac_engine import Policy, decide

FURNACE_URN = "urn:securiglass:ot:furnace:line-01"
RECIPE_URN = "urn:securiglass:it:recipe:RCP-2026-0042"
OPERATOR_ID = "11111111-1111-4111-8111-111111111111"
MANAGER_ID = "22222222-2222-4222-8222-222222222222"


async def _load_policies(conn: asyncpg.Connection) -> list[Policy]:
    rows = await conn.fetch(
        "SELECT policy_name, effect, subject_role, action_verb, resource_urn,"
        " rule_condition, is_active FROM sec_data.abac_policies ORDER BY policy_name"
    )
    policies: list[Policy] = []
    for row in rows:
        raw = row["rule_condition"]
        condition = json.loads(raw) if isinstance(raw, str) else dict(raw)
        policies.append(
            Policy(
                name=row["policy_name"],
                effect=row["effect"],
                subject_role=row["subject_role"],
                action_verb=row["action_verb"],
                resource_urn=row["resource_urn"],
                condition=condition,
                is_active=row["is_active"],
            )
        )
    return policies


def _ot_ctx(**overrides: Any) -> dict[str, Any]:
    ctx: dict[str, Any] = {
        "client_ip": "10.10.20.15",
        "environment": {"time": time(8, 0), "maintenance_lock": False},
        "subject": {"user_id": OPERATOR_ID, "is_active": True, "clearance_level": 2},
        "resource": {"line": "line-01"},
        "client_cert": {},
        "lists": {"REVOKED_CERTS_LIST": ["DEADBEEF01"]},
    }
    ctx.update(overrides)
    return ctx


def _edge_ctx(**cert: Any) -> dict[str, Any]:
    return {
        "client_ip": "10.10.30.12",
        "environment": {"time": time(10, 0), "maintenance_lock": False},
        "subject": {"user_id": "edge-service", "is_active": True, "clearance_level": 2},
        "resource": {"line": "line-01"},
        "client_cert": {
            "issuer": "CN=SecuriGlass-OT-CA,O=SecuriGlass",
            "san_dns": "edge-gateway.ot.local",
            "serial": "A1B2C3D4",
            **cert,
        },
        "lists": {"REVOKED_CERTS_LIST": ["DEADBEEF01"]},
    }


def _manager_ctx(creator: str, clearance: int = 3) -> dict[str, Any]:
    return {
        "client_ip": "10.40.10.7",
        "environment": {"time": time(11, 0), "maintenance_lock": False},
        "subject": {
            "user_id": MANAGER_ID,
            "is_active": True,
            "clearance_level": clearance,
        },
        "resource": {"recipe": {"created_by": creator}},
        "client_cert": {},
        "lists": {},
    }


async def test_seeded_policy_names_are_the_expected_pack(
    db_conn: asyncpg.Connection,
) -> None:
    names = {p.name for p in await _load_policies(db_conn)}
    assert names == {
        "ALLOW_TELEMETRY_READ",
        "ALLOW_OT_CONTROL_CONTEXTUAL",
        "DENY_OT_CONTROL_DURING_MAINTENANCE",
        "ALLOW_EDGE_TELEMETRY_INSERT",
        "DENY_REVOKED_CLIENT_CERT",
        "ALLOW_RECIPE_APPROVAL_FOUR_EYES",
        "DENY_SELF_RECIPE_APPROVAL",
    }


async def test_seeded_operator_policy_allows_nominal_and_denies_remote(
    db_conn: asyncpg.Connection,
) -> None:
    policies = await _load_policies(db_conn)
    nominal = decide(
        policies, ["OT_OPERATOR"], "ot:control:write", FURNACE_URN, _ot_ctx()
    )
    assert nominal.allowed is True, nominal.reason
    assert nominal.policy == "ALLOW_OT_CONTROL_CONTEXTUAL"

    remote = decide(
        policies,
        ["OT_OPERATOR"],
        "ot:control:write",
        FURNACE_URN,
        _ot_ctx(client_ip="10.40.5.23"),
    )
    assert remote.allowed is False

    off_shift = decide(
        policies,
        ["OT_OPERATOR"],
        "ot:control:write",
        FURNACE_URN,
        _ot_ctx(environment={"time": time(23, 30), "maintenance_lock": False}),
    )
    assert off_shift.allowed is False


async def test_seeded_maintenance_lock_is_a_hard_deny(
    db_conn: asyncpg.Connection,
) -> None:
    policies = await _load_policies(db_conn)
    decision = decide(
        policies,
        ["OT_OPERATOR"],
        "ot:control:write",
        FURNACE_URN,
        _ot_ctx(environment={"time": time(9, 0), "maintenance_lock": True}),
    )
    assert decision.allowed is False
    assert decision.policy == "DENY_OT_CONTROL_DURING_MAINTENANCE"


async def test_seeded_edge_policy_rejects_revoked_certificate(
    db_conn: asyncpg.Connection,
) -> None:
    policies = await _load_policies(db_conn)
    valid = decide(
        policies,
        ["SERVICE_ACCOUNT_EDGE"],
        "ot:telemetry:insert",
        FURNACE_URN,
        _edge_ctx(),
    )
    assert valid.allowed is True, valid.reason

    revoked = decide(
        policies,
        ["SERVICE_ACCOUNT_EDGE"],
        "ot:telemetry:insert",
        FURNACE_URN,
        _edge_ctx(serial="DEADBEEF01"),
    )
    assert revoked.allowed is False
    assert revoked.policy == "DENY_REVOKED_CLIENT_CERT"


async def test_seeded_four_eyes_policy(db_conn: asyncpg.Connection) -> None:
    policies = await _load_policies(db_conn)
    own = decide(
        policies,
        ["PLANT_MANAGER"],
        "it:recipe:approve",
        RECIPE_URN,
        _manager_ctx(MANAGER_ID),
    )
    assert own.allowed is False
    assert own.policy == "DENY_SELF_RECIPE_APPROVAL"

    colleague = decide(
        policies,
        ["PLANT_MANAGER"],
        "it:recipe:approve",
        RECIPE_URN,
        _manager_ctx(OPERATOR_ID),
    )
    assert colleague.allowed is True, colleague.reason


async def test_every_seeded_condition_is_evaluable(db_conn: asyncpg.Connection) -> None:
    """Aucune politique seedée ne doit produire d'erreur d'évaluation silencieuse."""
    from app.services.abac_engine import evaluate_condition

    for policy in await _load_policies(db_conn):
        # Un contexte volontairement pauvre : l'évaluation doit rester booléenne.
        result = evaluate_condition(policy.condition, {})
        assert isinstance(result, bool)


@pytest.mark.parametrize(
    "role", ["OT_OPERATOR", "PLANT_MANAGER", "SERVICE_ACCOUNT_EDGE"]
)
async def test_roles_have_permissions_seeded(
    db_conn: asyncpg.Connection, role: str
) -> None:
    count = await db_conn.fetchval(
        """
        SELECT count(*) FROM sec_data.role_permissions rp
        JOIN sec_data.roles r ON r.id = rp.role_id
        WHERE r.role_code = $1
        """,
        role,
    )
    assert count > 0
