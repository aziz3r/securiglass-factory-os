"""Tests de sécurité offensifs et scénarios adversariaux sur le moteur ABAC.

Conformité : IEC 62443-3-3, NIST SP 800-162, OWASP ASVS v4.0 (V4 Access Control).
Vérifie la résistance aux attaques :
- Usurpation d'IP / IP hors sous-réseau Purdue (IP spoofing)
- Contournement d'horaires d'équipe (Shift bypass)
- Contournement du verrouillage de sécurité de maintenance
- Certificats mTLS révoqués, faux émetteurs (Rogue CA) ou faux SAN DNS
- Tentative d'auto-approbation illicite de recette thermique (Principe des 4 yeux)
- Escalade de privilèges via falsification de clearance ou de rôles
- Résilience aux injections de contexte malformé (fail-closed)
"""

from __future__ import annotations

import pytest
from app.services.abac_engine import Decision, Policy, decide

# Jeu complet des politiques industrielles SecuriGlass
SECURIGLASS_POLICIES: list[Policy] = [
    Policy(
        name="ALLOW_TELEMETRY_READ",
        effect="ALLOW",
        subject_role="*",
        action_verb="ot:telemetry:read",
        resource_urn="urn:securiglass:ot:*",
        condition={"equals": {"subject.is_active": True}},
        description="Lecture télémétrie pour tout compte actif.",
    ),
    Policy(
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
        description="ABAC-01 : écriture procédé uniquement depuis salle de contrôle et quart.",
    ),
    Policy(
        name="DENY_OT_CONTROL_DURING_MAINTENANCE",
        effect="DENY",
        subject_role="OT_OPERATOR",
        action_verb="ot:control:write",
        resource_urn="urn:securiglass:ot:furnace:*",
        condition={"equals": {"environment.maintenance_lock": True}},
        description="Blocage dur pendant maintenance planifiée.",
    ),
    Policy(
        name="ALLOW_EDGE_TELEMETRY_INSERT",
        effect="ALLOW",
        subject_role="SERVICE_ACCOUNT_EDGE",
        action_verb="ot:telemetry:insert",
        resource_urn="urn:securiglass:ot:furnace:*",
        condition={
            "and": [
                {"in_cidr": {"client_ip": "10.10.30.0/24"}},
                {
                    "equals": {
                        "client_cert.issuer": "CN=SecuriGlass-OT-CA,O=SecuriGlass"
                    }
                },
                {"equals": {"client_cert.san_dns": "edge-gateway.ot.local"}},
                {"not_in": {"client_cert.serial": "REVOKED_CERTS_LIST"}},
            ]
        },
        description="ABAC-02 : Ingestion Edge Gateway certifiée mTLS Purdue L3.",
    ),
    Policy(
        name="DENY_REVOKED_CLIENT_CERT",
        effect="DENY",
        subject_role="*",
        action_verb="*",
        resource_urn="*",
        condition={"in": {"client_cert.serial": "REVOKED_CERTS_LIST"}},
        description="Blocage absolu de tout certificat révoqué.",
    ),
    Policy(
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
        description="ABAC-03 : Approbation recette thermique par manager distinct du créateur.",
    ),
    Policy(
        name="DENY_SELF_RECIPE_APPROVAL",
        effect="DENY",
        subject_role="PLANT_MANAGER",
        action_verb="it:recipe:approve",
        resource_urn="urn:securiglass:it:recipe:*",
        condition={"equals": {"subject.user_id": "resource.recipe.created_by"}},
        description="Principe des quatre yeux : interdiction d'auto-approbation.",
    ),
]


# ============================================================================
# 1. SCÉNARIOS OFFENSIFS : CONTRÔLE FOUR OT (ABAC-01)
# ============================================================================


def test_adversarial_ot_control_nominal_allowed() -> None:
    """Cas nominal de référence : opérateur en salle de contrôle pendant son quart."""
    ctx = {
        "client_ip": "10.10.20.15",
        "environment": {
            "time": "14:30:00",
            "maintenance_lock": False,
        },
        "subject": {
            "is_active": True,
            "clearance_level": 2,
        },
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["OT_OPERATOR"],
        "ot:control:write",
        "urn:securiglass:ot:furnace:zone1",
        ctx,
    )
    assert decision.allowed is True
    assert decision.policy == "ALLOW_OT_CONTROL_CONTEXTUAL"


@pytest.mark.parametrize(
    "spoofed_ip",
    [
        "10.10.10.50",  # Réseau Bureautique IT (Purdue Niveau 4)
        "10.10.30.15",  # Réseau Edge Gateway (Purdue Niveau 3)
        "192.168.1.100",  # Réseau externe / VPN non autorisé
        "172.16.0.1",  # Docker bridge standard
        "8.8.8.8",  # Internet public
    ],
)
def test_adversarial_ot_control_ip_spoofing_denied(spoofed_ip: str) -> None:
    """Attaque Red Team : Commande sur le four émise hors de la salle de contrôle (Purdue L2)."""
    ctx = {
        "client_ip": spoofed_ip,
        "environment": {
            "time": "14:30:00",
            "maintenance_lock": False,
        },
        "subject": {"is_active": True},
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["OT_OPERATOR"],
        "ot:control:write",
        "urn:securiglass:ot:furnace:zone1",
        ctx,
    )
    assert decision.allowed is False


@pytest.mark.parametrize(
    "attack_time",
    [
        "02:00:00",  # Pleine nuit (aucun quart prévu)
        "05:44:59",  # 1 seconde avant ouverture quart
        "22:15:01",  # 1 seconde après fin quart
        "23:59:59",  # Fin de soirée
    ],
)
def test_adversarial_ot_control_out_of_shift_hours_denied(attack_time: str) -> None:
    """Attaque Red Team : Tentative de commande physique hors plage horaire de quart."""
    ctx = {
        "client_ip": "10.10.20.15",
        "environment": {
            "time": attack_time,
            "maintenance_lock": False,
        },
        "subject": {"is_active": True},
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["OT_OPERATOR"],
        "ot:control:write",
        "urn:securiglass:ot:furnace:zone1",
        ctx,
    )
    assert decision.allowed is False


def test_adversarial_ot_control_maintenance_lock_override_denied() -> None:
    """Attaque Red Team : Tentative d'écriture malgré le verrouillage de maintenance actif."""
    ctx = {
        "client_ip": "10.10.20.15",
        "environment": {
            "time": "14:00:00",
            "maintenance_lock": True,  # Ligne arrêtée pour maintenance
        },
        "subject": {"is_active": True},
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["OT_OPERATOR"],
        "ot:control:write",
        "urn:securiglass:ot:furnace:zone1",
        ctx,
    )
    assert decision.allowed is False
    assert decision.policy == "DENY_OT_CONTROL_DURING_MAINTENANCE"


def test_adversarial_ot_control_inactive_account_denied() -> None:
    """Attaque Red Team : Compte opérateur révoqué/suspendu."""
    ctx = {
        "client_ip": "10.10.20.15",
        "environment": {
            "time": "14:00:00",
            "maintenance_lock": False,
        },
        "subject": {"is_active": False},
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["OT_OPERATOR"],
        "ot:control:write",
        "urn:securiglass:ot:furnace:zone1",
        ctx,
    )
    assert decision.allowed is False


# ============================================================================
# 2. SCÉNARIOS OFFENSIFS : DATA DIODE & EDGE GATEWAY mTLS (ABAC-02)
# ============================================================================


def test_adversarial_edge_telemetry_nominal_allowed() -> None:
    """Cas nominal de référence : Gateway authentifiée avec certificat mTLS valide."""
    ctx = {
        "client_ip": "10.10.30.12",
        "client_cert": {
            "issuer": "CN=SecuriGlass-OT-CA,O=SecuriGlass",
            "san_dns": "edge-gateway.ot.local",
            "serial": "VALID_SN_9948271",
        },
        "lists": {
            "REVOKED_CERTS_LIST": ["REVOKED_001", "REVOKED_002"],
        },
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["SERVICE_ACCOUNT_EDGE"],
        "ot:telemetry:insert",
        "urn:securiglass:ot:furnace:telemetry",
        ctx,
    )
    assert decision.allowed is True
    assert decision.policy == "ALLOW_EDGE_TELEMETRY_INSERT"


def test_adversarial_edge_revoked_certificate_attack_denied() -> None:
    """Attaque Red Team : Injection de télémétrie avec un certificat volé mais révoqué."""
    ctx = {
        "client_ip": "10.10.30.12",
        "client_cert": {
            "issuer": "CN=SecuriGlass-OT-CA,O=SecuriGlass",
            "san_dns": "edge-gateway.ot.local",
            "serial": "COMPROMISED_REVOKED_SERIAL_123",
        },
        "lists": {
            "REVOKED_CERTS_LIST": ["COMPROMISED_REVOKED_SERIAL_123"],
        },
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["SERVICE_ACCOUNT_EDGE"],
        "ot:telemetry:insert",
        "urn:securiglass:ot:furnace:telemetry",
        ctx,
    )
    assert decision.allowed is False
    assert decision.policy == "DENY_REVOKED_CLIENT_CERT"


def test_adversarial_edge_rogue_ca_denied() -> None:
    """Attaque Red Team : Présentation d'un certificat émis par une fausse autorité de certification."""
    ctx = {
        "client_ip": "10.10.30.12",
        "client_cert": {
            "issuer": "CN=Rogue-Hacker-CA,O=ShadowCorp",
            "san_dns": "edge-gateway.ot.local",
            "serial": "SN_FAKE_1234",
        },
        "lists": {"REVOKED_CERTS_LIST": []},
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["SERVICE_ACCOUNT_EDGE"],
        "ot:telemetry:insert",
        "urn:securiglass:ot:furnace:telemetry",
        ctx,
    )
    assert decision.allowed is False


def test_adversarial_edge_san_dns_spoofing_denied() -> None:
    """Attaque Red Team : Certificat issu de la bonne CA mais pour une station SCADA bureautique."""
    ctx = {
        "client_ip": "10.10.30.12",
        "client_cert": {
            "issuer": "CN=SecuriGlass-OT-CA,O=SecuriGlass",
            "san_dns": "operator-workstation-03.ot.local",
            "serial": "SN_VALID_BUT_WRONG_HOST",
        },
        "lists": {"REVOKED_CERTS_LIST": []},
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["SERVICE_ACCOUNT_EDGE"],
        "ot:telemetry:insert",
        "urn:securiglass:ot:furnace:telemetry",
        ctx,
    )
    assert decision.allowed is False


def test_adversarial_edge_ip_spoofing_denied() -> None:
    """Attaque Red Team : Injection prétendue Gateway depuis un sous-réseau non autorisé."""
    ctx = {
        "client_ip": "10.10.20.15",  # Salle de contrôle au lieu du réseau Edge 10.10.30.0/24
        "client_cert": {
            "issuer": "CN=SecuriGlass-OT-CA,O=SecuriGlass",
            "san_dns": "edge-gateway.ot.local",
            "serial": "VALID_SN_9948271",
        },
        "lists": {"REVOKED_CERTS_LIST": []},
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["SERVICE_ACCOUNT_EDGE"],
        "ot:telemetry:insert",
        "urn:securiglass:ot:furnace:telemetry",
        ctx,
    )
    assert decision.allowed is False


# ============================================================================
# 3. SCÉNARIOS OFFENSIFS : RECETTES DE TREMPE & PRINCIPE DES 4 YEUX (ABAC-03)
# ============================================================================


def test_adversarial_recipe_approval_nominal_allowed() -> None:
    """Cas nominal de référence : Manager A approuve la recette créée par l'ingénieur B."""
    ctx = {
        "subject": {
            "user_id": "usr-plant-manager-001",
            "clearance_level": 3,
        },
        "resource": {
            "recipe": {
                "created_by": "usr-process-engineer-999",
            }
        },
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["PLANT_MANAGER"],
        "it:recipe:approve",
        "urn:securiglass:it:recipe:tempered-10mm",
        ctx,
    )
    assert decision.allowed is True
    assert decision.policy == "ALLOW_RECIPE_APPROVAL_FOUR_EYES"


def test_adversarial_recipe_self_approval_sabotage_attempt_denied() -> None:
    """Attaque Red Team : Le créateur d'une recette thermique tente de l'approuver lui-même.
    Risque critique : modification frauduleuse de courbe thermique non relue, conduisant
    au bris de verre thermique ou sabotage du cycle de trempe.
    """
    malicious_manager_id = "usr-manager-rogue-007"
    ctx = {
        "subject": {
            "user_id": malicious_manager_id,
            "clearance_level": 4,  # Même avec une très haute clearance
        },
        "resource": {
            "recipe": {
                "created_by": malicious_manager_id,  # Auto-créée !
            }
        },
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["PLANT_MANAGER"],
        "it:recipe:approve",
        "urn:securiglass:it:recipe:high-temp-furnace",
        ctx,
    )
    # Rejet obligatoire par la politique de blocage dur DENY_SELF_RECIPE_APPROVAL
    assert decision.allowed is False
    assert decision.policy == "DENY_SELF_RECIPE_APPROVAL"


def test_adversarial_recipe_insufficient_clearance_denied() -> None:
    """Attaque Red Team : Manager intérimaire avec clearance 2 tente d'approuver une recette."""
    ctx = {
        "subject": {
            "user_id": "usr-junior-manager",
            "clearance_level": 2,  # Insuffisant (< 3)
        },
        "resource": {
            "recipe": {
                "created_by": "usr-senior-engineer",
            }
        },
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["PLANT_MANAGER"],
        "it:recipe:approve",
        "urn:securiglass:it:recipe:bulletproof-glass",
        ctx,
    )
    assert decision.allowed is False


def test_adversarial_unauthorized_role_recipe_approval_denied() -> None:
    """Attaque Red Team : Opérateur ou auditeur tentant d'approuver une recette technique."""
    ctx = {
        "subject": {
            "user_id": "usr-operator-01",
            "clearance_level": 3,
        },
        "resource": {
            "recipe": {
                "created_by": "usr-engineer-02",
            }
        },
    }
    for role in ["OT_OPERATOR", "QUALITY_INSPECTOR", "SECURITY_AUDITOR"]:
        decision = decide(
            SECURIGLASS_POLICIES,
            [role],
            "it:recipe:approve",
            "urn:securiglass:it:recipe:windshield-v2",
            ctx,
        )
        assert decision.allowed is False


# ============================================================================
# 4. RÉSILIENCE DU MOTEUR ABAC AUX ANOMALIES & ATTRIBUTS MALFORMÉS (FAIL-CLOSED)
# ============================================================================


def test_adversarial_missing_context_attributes_fail_closed() -> None:
    """Le moteur doit fail-closed (Default-Deny) si le contexte est tronqué ou vide."""
    empty_ctx: dict[str, object] = {}
    decision = decide(
        SECURIGLASS_POLICIES,
        ["OT_OPERATOR"],
        "ot:control:write",
        "urn:securiglass:ot:furnace:zone1",
        empty_ctx,
    )
    assert decision.allowed is False


def test_adversarial_type_confusion_in_context_fail_closed() -> None:
    """Injection de types inattendus (ex: dict au lieu de string, ou liste au lieu d'IP)."""
    corrupted_ctx = {
        "client_ip": {"$ne": "127.0.0.1"},  # Type injection
        "environment": {
            "time": 1234567,  # Int au lieu de str
            "maintenance_lock": "not_a_bool",
        },
        "subject": {"is_active": [True]},
    }
    decision = decide(
        SECURIGLASS_POLICIES,
        ["OT_OPERATOR"],
        "ot:control:write",
        "urn:securiglass:ot:furnace:zone1",
        corrupted_ctx,
    )
    assert decision.allowed is False
