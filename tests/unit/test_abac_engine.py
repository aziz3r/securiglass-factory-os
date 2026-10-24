"""Tests du moteur ABAC (PDP) : Default Deny, Deny-Overrides, fail-closed.

Cible : `app.services.abac_engine` - OWASP ASVS V4.1/V4.2, IEC 62443-3-3 SR 2.x.

Modèle de politiques retenu (corrige le défaut D1 de la matrice d'origine) :
  * une politique ALLOW porte la condition contextuelle **complète** (réseau, horaire,
    verrou de maintenance, attributs sujet) ;
  * une politique DENY est un **blocage dur** qui l'emporte sur tout ALLOW ;
  * l'absence de politique ALLOW applicable => Default Deny.
"""

from __future__ import annotations

from datetime import time
from typing import Any

import pytest

from app.services.abac_engine import Decision, Policy, decide, evaluate_condition

FURNACE_URN = "urn:securiglass:ot:furnace:line-01"
RECIPE_URN = "urn:securiglass:it:recipe:RCP-2026-0042"

OPERATOR_ID = "11111111-1111-4111-8111-111111111111"
MANAGER_ID = "22222222-2222-4222-8222-222222222222"

# ---------------------------------------------------------------------------
# Pack de politiques de référence (identique au seed SQL `database/schemas/06`)
# ---------------------------------------------------------------------------
ALLOW_TELEMETRY_READ = Policy(
    name="ALLOW_TELEMETRY_READ",
    effect="ALLOW",
    subject_role="*",
    action_verb="ot:telemetry:read",
    resource_urn="urn:securiglass:ot:*",
    condition={"equals": {"subject.is_active": True}},
)

ALLOW_OT_CONTROL = Policy(
    name="ALLOW_OT_CONTROL_CONTEXTUAL",
    effect="ALLOW",
    subject_role="OT_OPERATOR",
    action_verb="ot:control:write",
    resource_urn="urn:securiglass:ot:furnace:*",
    condition={
        "and": [
            {"in_cidr": {"client_ip": "10.10.20.0/24"}},
            {"time_between": {"start": "05:45:00", "end": "22:15:00"}},
            {"equals": {"environment.maintenance_lock": False}},
            {"equals": {"subject.is_active": True}},
        ]
    },
)

DENY_OT_MAINTENANCE = Policy(
    name="DENY_OT_CONTROL_DURING_MAINTENANCE",
    effect="DENY",
    subject_role="OT_OPERATOR",
    action_verb="ot:control:write",
    resource_urn="urn:securiglass:ot:furnace:*",
    condition={"equals": {"environment.maintenance_lock": True}},
)

ALLOW_EDGE_INSERT = Policy(
    name="ALLOW_EDGE_TELEMETRY_INSERT",
    effect="ALLOW",
    subject_role="SERVICE_ACCOUNT_EDGE",
    action_verb="ot:telemetry:insert",
    resource_urn="urn:securiglass:ot:furnace:*",
    condition={
        "and": [
            {"in_cidr": {"client_ip": "10.10.30.0/24"}},
            {"equals": {"client_cert.issuer": "CN=SecuriGlass-OT-CA,O=SecuriGlass"}},
            {"equals": {"client_cert.san_dns": "edge-gateway.ot.local"}},
            {"not_in": {"client_cert.serial": "REVOKED_CERTS_LIST"}},
        ]
    },
)

DENY_REVOKED_CERT = Policy(
    name="DENY_REVOKED_CLIENT_CERT",
    effect="DENY",
    subject_role="*",
    action_verb="*",
    resource_urn="*",
    condition={"in": {"client_cert.serial": "REVOKED_CERTS_LIST"}},
)

ALLOW_RECIPE_APPROVAL = Policy(
    name="ALLOW_RECIPE_APPROVAL_FOUR_EYES",
    effect="ALLOW",
    subject_role="PLANT_MANAGER",
    action_verb="it:recipe:approve",
    resource_urn="urn:securiglass:it:recipe:*",
    condition={
        "and": [
            {"greater_or_equal": {"subject.clearance_level": 3}},
            {"not_equals": {"subject.user_id": "resource.recipe.created_by"}},
        ]
    },
)

DENY_SELF_APPROVAL = Policy(
    name="DENY_SELF_RECIPE_APPROVAL",
    effect="DENY",
    subject_role="PLANT_MANAGER",
    action_verb="it:recipe:approve",
    resource_urn="urn:securiglass:it:recipe:*",
    condition={"equals": {"subject.user_id": "resource.recipe.created_by"}},
)

OT_POLICIES = [ALLOW_OT_CONTROL, DENY_OT_MAINTENANCE]
EDGE_POLICIES = [ALLOW_EDGE_INSERT, DENY_REVOKED_CERT]
RECIPE_POLICIES = [ALLOW_RECIPE_APPROVAL, DENY_SELF_APPROVAL]


# ---------------------------------------------------------------------------
# Contextes
# ---------------------------------------------------------------------------
def ot_context(**overrides: Any) -> dict[str, Any]:
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


def edge_context(**cert: Any) -> dict[str, Any]:
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


def manager_context(creator: str, clearance: int = 3) -> dict[str, Any]:
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


def operator_decision(ctx: dict[str, Any]) -> Decision:
    return decide(OT_POLICIES, ["OT_OPERATOR"], "ot:control:write", FURNACE_URN, ctx)


def edge_decision(ctx: dict[str, Any]) -> Decision:
    return decide(
        EDGE_POLICIES, ["SERVICE_ACCOUNT_EDGE"], "ot:telemetry:insert", FURNACE_URN, ctx
    )


def manager_decision(ctx: dict[str, Any]) -> Decision:
    return decide(
        RECIPE_POLICIES, ["PLANT_MANAGER"], "it:recipe:approve", RECIPE_URN, ctx
    )


# ---------------------------------------------------------------------------
# Default Deny
# ---------------------------------------------------------------------------
def test_no_policy_means_default_deny() -> None:
    result = decide([], ["OT_OPERATOR"], "ot:control:write", FURNACE_URN, ot_context())
    assert result.allowed is False
    assert result.policy is None
    assert "Default-Deny" in result.reason


def test_unknown_role_cannot_use_role_scoped_policy() -> None:
    result = decide(
        OT_POLICIES,
        ["QUALITY_INSPECTOR"],
        "ot:control:write",
        FURNACE_URN,
        ot_context(),
    )
    assert result.allowed is False


def test_unknown_action_is_denied() -> None:
    result = decide(
        OT_POLICIES, ["OT_OPERATOR"], "ot:telemetry:delete", FURNACE_URN, ot_context()
    )
    assert result.allowed is False


def test_resource_outside_urn_pattern_is_denied() -> None:
    result = decide(
        OT_POLICIES,
        ["OT_OPERATOR"],
        "ot:control:write",
        "urn:securiglass:it:recipe:RCP-1",
        ot_context(),
    )
    assert result.allowed is False


def test_inactive_policy_is_ignored() -> None:
    inactive = Policy(
        name="ALLOW_OT_CONTROL_CONTEXTUAL",
        effect="ALLOW",
        subject_role="OT_OPERATOR",
        action_verb="ot:control:write",
        resource_urn="urn:securiglass:ot:furnace:*",
        condition={"equals": {"subject.is_active": True}},
        is_active=False,
    )
    result = decide(
        [inactive], ["OT_OPERATOR"], "ot:control:write", FURNACE_URN, ot_context()
    )
    assert result.allowed is False


def test_disabled_subject_is_denied() -> None:
    ctx = ot_context(
        subject={"user_id": OPERATOR_ID, "is_active": False, "clearance_level": 2}
    )
    assert operator_decision(ctx).allowed is False


# ---------------------------------------------------------------------------
# ABAC-01 : salle de contrôle OT (réseau, horaires, maintenance)
# ---------------------------------------------------------------------------
def test_operator_in_control_room_within_shift_is_allowed() -> None:
    result = operator_decision(ot_context())
    assert result.allowed is True
    assert result.policy == "ALLOW_OT_CONTROL_CONTEXTUAL"


def test_operator_from_it_network_is_denied() -> None:
    ctx = ot_context(client_ip="10.40.5.23")
    assert operator_decision(ctx).allowed is False


def test_operator_from_isolated_gateway_subnet_is_denied() -> None:
    # 10.10.30.0/24 est le réseau de la gateway edge, pas la salle de contrôle.
    ctx = ot_context(client_ip="10.10.30.12")
    assert operator_decision(ctx).allowed is False


def test_operator_outside_shift_is_denied() -> None:
    ctx = ot_context(environment={"time": time(23, 30), "maintenance_lock": False})
    assert operator_decision(ctx).allowed is False


def test_operator_before_shift_start_is_denied() -> None:
    ctx = ot_context(environment={"time": time(5, 44), "maintenance_lock": False})
    assert operator_decision(ctx).allowed is False


@pytest.mark.parametrize("boundary", [time(5, 45), time(22, 15)])
def test_operator_at_shift_boundaries_is_allowed(boundary: time) -> None:
    ctx = ot_context(environment={"time": boundary, "maintenance_lock": False})
    assert operator_decision(ctx).allowed is True


def test_operator_during_maintenance_lock_hits_explicit_deny() -> None:
    ctx = ot_context(environment={"time": time(9, 0), "maintenance_lock": True})
    result = operator_decision(ctx)
    assert result.allowed is False
    assert result.policy == "DENY_OT_CONTROL_DURING_MAINTENANCE"


def test_opaque_ip_string_is_denied_without_crash() -> None:
    assert operator_decision(ot_context(client_ip="not-an-ip")).allowed is False


def test_missing_environment_time_fails_closed_D6() -> None:
    """D6 (résolu) : `time_between` applique le fail-closed si `environment.time`
    est absent (KeyError intercepté et condition évaluée à False).
    """
    ctx = ot_context()
    del ctx["environment"]["time"]
    assert (
        evaluate_condition(
            {"time_between": {"start": "00:00:00", "end": "23:59:59"}}, ctx
        )
        is False
    )


# ---------------------------------------------------------------------------
# ABAC-02 : mTLS Edge Gateway / Data Diode
# ---------------------------------------------------------------------------
def test_edge_gateway_with_valid_mtls_can_insert_telemetry() -> None:
    result = edge_decision(edge_context())
    assert result.allowed is True
    assert result.policy == "ALLOW_EDGE_TELEMETRY_INSERT"


def test_edge_gateway_outside_gateway_subnet_is_denied() -> None:
    ctx = edge_context()
    ctx["client_ip"] = "10.20.1.9"
    assert edge_decision(ctx).allowed is False


def test_edge_gateway_with_wrong_cert_issuer_is_denied() -> None:
    assert edge_decision(edge_context(issuer="CN=Evil-CA,O=Attacker")).allowed is False


def test_edge_gateway_with_wrong_san_is_denied() -> None:
    assert edge_decision(edge_context(san_dns="attacker.ot.local")).allowed is False


def test_edge_gateway_with_revoked_serial_is_denied() -> None:
    result = edge_decision(edge_context(serial="DEADBEEF01"))
    assert result.allowed is False
    assert result.policy == "DENY_REVOKED_CLIENT_CERT"


def test_edge_gateway_without_certificate_fails_closed() -> None:
    ctx = edge_context()
    del ctx["client_cert"]
    assert edge_decision(ctx).allowed is False


# ---------------------------------------------------------------------------
# ABAC-03 : quatre yeux sur les recettes thermiques
# ---------------------------------------------------------------------------
def test_manager_cannot_approve_his_own_recipe() -> None:
    result = manager_decision(manager_context(creator=MANAGER_ID))
    assert result.allowed is False
    assert result.policy == "DENY_SELF_RECIPE_APPROVAL"


def test_manager_can_approve_a_colleague_recipe() -> None:
    assert manager_decision(manager_context(creator=OPERATOR_ID)).allowed is True


def test_manager_with_insufficient_clearance_cannot_approve() -> None:
    assert (
        manager_decision(manager_context(creator=OPERATOR_ID, clearance=2)).allowed
        is False
    )


# ---------------------------------------------------------------------------
# Deny-Overrides & robustesse
# ---------------------------------------------------------------------------
def test_explicit_deny_overrides_wildcard_allow() -> None:
    deny_all = Policy(
        "DENY_ALL_OT_TELEMETRY",
        "DENY",
        "*",
        "ot:telemetry:read",
        "urn:securiglass:ot:*",
        {"equals": {"environment.maintenance_lock": False}},
    )
    result = decide(
        [ALLOW_TELEMETRY_READ, deny_all],
        ["OT_OPERATOR"],
        "ot:telemetry:read",
        FURNACE_URN,
        ot_context(),
    )
    assert result.allowed is False
    assert result.policy == "DENY_ALL_OT_TELEMETRY"


def test_deny_precedence_is_order_independent() -> None:
    deny_all = Policy(
        "DENY_ALL_OT_TELEMETRY",
        "DENY",
        "*",
        "ot:telemetry:read",
        "urn:securiglass:ot:*",
        {"equals": {"environment.maintenance_lock": False}},
    )
    for policies in (
        [deny_all, ALLOW_TELEMETRY_READ],
        [ALLOW_TELEMETRY_READ, deny_all],
    ):
        result = decide(
            policies, ["OT_OPERATOR"], "ot:telemetry:read", FURNACE_URN, ot_context()
        )
        assert result.allowed is False


def test_wildcard_role_matches_any_authenticated_role() -> None:
    result = decide(
        [ALLOW_TELEMETRY_READ],
        ["QUALITY_INSPECTOR"],
        "ot:telemetry:read",
        FURNACE_URN,
        ot_context(),
    )
    assert result.allowed is True


def test_regression_d1_inverted_deny_policy_is_detected() -> None:
    """D1 : un DENY dont la condition décrit le cas *autorisé* inverse la règle.
    Ce test verrouille la démonstration du défaut : le cas nominal est refusé.
    """
    inverted = Policy(
        name="ABAC_ENFORCE_OPERATOR_SUBNET_INVERTED",
        effect="DENY",
        subject_role="OT_OPERATOR",
        action_verb="ot:control:write",
        resource_urn="urn:securiglass:ot:furnace:*",
        condition={
            "and": [
                {"in_cidr": {"client_ip": "10.10.20.0/24"}},
                {"time_between": {"start": "05:45:00", "end": "22:15:00"}},
                {"equals": {"environment.maintenance_lock": False}},
            ]
        },
    )
    result = decide(
        [ALLOW_OT_CONTROL, inverted],
        ["OT_OPERATOR"],
        "ot:control:write",
        FURNACE_URN,
        ot_context(),
    )
    assert result.allowed is False
    assert result.policy == "ABAC_ENFORCE_OPERATOR_SUBNET_INVERTED"


@pytest.mark.parametrize(
    "condition",
    [
        {},
        {"unknown_op": {"client_ip": "10.0.0.0/8"}},
        {"in_cidr": {"missing.attribute": "10.0.0.0/8"}},
        {"equals": "not-a-dict"},
        {"and": "not-a-list-of-nodes"},
        {"in_cidr": {"client_ip": "not-an-ip"}},
        {"time_between": {"start": "25:99", "end": "26:00"}},
        {"equals": {"subject.clearance_level": 1, "subject.user_id": "x"}},
    ],
)
def test_malformed_conditions_fail_closed(condition: dict[str, Any]) -> None:
    assert evaluate_condition(condition, ot_context()) is False


def test_overnight_time_window() -> None:
    night = {"time_between": {"start": "22:00:00", "end": "06:00:00"}}
    assert evaluate_condition(night, {"environment": {"time": time(23, 30)}}) is True
    assert evaluate_condition(night, {"environment": {"time": time(2, 0)}}) is True
    assert evaluate_condition(night, {"environment": {"time": time(12, 0)}}) is False


@pytest.mark.parametrize(
    ("operator", "expected", "ctx", "result"),
    [
        ("equals", 3, {"subject": {"clearance_level": 3}}, True),
        ("equals", 3, {"subject": {"clearance_level": 4}}, False),
        ("not_equals", 3, {"subject": {"clearance_level": 4}}, True),
        ("greater_or_equal", 3, {"subject": {"clearance_level": 5}}, True),
        ("greater_or_equal", 3, {"subject": {"clearance_level": 2}}, False),
        ("less_or_equal", 3, {"subject": {"clearance_level": 2}}, True),
        ("in", [1, 2, 3], {"subject": {"clearance_level": 2}}, True),
        ("not_in", [1, 2], {"subject": {"clearance_level": 2}}, False),
    ],
)
def test_scalar_operators(
    operator: str, expected: Any, ctx: dict[str, Any], result: bool
) -> None:
    assert (
        evaluate_condition({operator: {"subject.clearance_level": expected}}, ctx)
        is result
    )


def test_clearance_level_shortcut_operator() -> None:
    assert (
        evaluate_condition(
            {"clearance_level": {"min": 3}}, {"subject": {"clearance_level": 4}}
        )
        is True
    )
    assert (
        evaluate_condition(
            {"clearance_level": {"min": 4}}, {"subject": {"clearance_level": 3}}
        )
        is False
    )


def test_named_list_reference_is_resolved_from_context() -> None:
    condition = {"in": {"subject.user_id": "ALLOWED_USERS"}}
    ctx = {"subject": {"user_id": "u1"}, "lists": {"ALLOWED_USERS": ["u0", "u1"]}}
    assert evaluate_condition(condition, ctx) is True
    ctx["subject"]["user_id"] = "u9"
    assert evaluate_condition(condition, ctx) is False


def test_boolean_combinators() -> None:
    ctx = {
        "subject": {"clearance_level": 4},
        "environment": {"maintenance_lock": False},
    }
    condition = {
        "or": [
            {"equals": {"subject.clearance_level": 5}},
            {
                "and": [
                    {"greater_or_equal": {"subject.clearance_level": 3}},
                    {"not": {"equals": {"environment.maintenance_lock": True}}},
                ]
            },
        ]
    }
    assert evaluate_condition(condition, ctx) is True
    ctx["environment"]["maintenance_lock"] = True
    assert evaluate_condition(condition, ctx) is False


def test_empty_boolean_groups_are_fail_closed() -> None:
    assert evaluate_condition({"and": []}, {}) is False
    assert evaluate_condition({"or": []}, {}) is False


def test_ip_alias_resolution_from_environment() -> None:
    ctx = {"environment": {"client_ip": "10.10.20.9"}}
    assert evaluate_condition({"in_cidr": {"client_ip": "10.10.20.0/24"}}, ctx) is True
