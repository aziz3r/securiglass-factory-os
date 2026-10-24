"""Étape 1 - Seed IAM : rôles/permissions, politiques ABAC, compte d'amorçage.

Corrige le défaut **D1** de la matrice d'origine : les politiques ABAC sont
exprimées selon le modèle sûr « ALLOW contextuel complet + DENY de blocage dur »,
et non plus `DENY` avec une condition décrivant le cas autorisé (règle inversée).

Revision ID: 0002_seed_iam_abac
Revises: 0001_initial_schema
"""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Sequence
from typing import Any

from alembic import context, op
from argon2 import PasswordHasher, Type
from sqlalchemy.engine import Connection

revision: str = "0002_seed_iam_abac"
down_revision: str | None = "0001_initial_schema"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# ---------------------------------------------------------------------------
# Politiques ABAC de référence (miroir exact de tests/unit/test_abac_engine.py)
# ---------------------------------------------------------------------------
_POLICIES: tuple[dict[str, Any], ...] = (
    {
        "policy_name": "ALLOW_TELEMETRY_READ",
        "effect": "ALLOW",
        "subject_role": "*",
        "action_verb": "ot:telemetry:read",
        "resource_urn": "urn:securiglass:ot:*",
        "condition": {"equals": {"subject.is_active": True}},
        "description": "Lecture télémétrie pour tout compte actif (niveaux 2-4).",
    },
    {
        "policy_name": "ALLOW_OT_CONTROL_CONTEXTUAL",
        "effect": "ALLOW",
        "subject_role": "OT_OPERATOR",
        "action_verb": "ot:control:write",
        "resource_urn": "urn:securiglass:ot:furnace:*",
        "condition": {
            "and": [
                {"in_cidr": {"client_ip": "10.10.20.0/24"}},
                {"time_between": {"start": "05:45:00", "end": "22:15:00"}},
                {"equals": {"environment.maintenance_lock": False}},
                {"equals": {"subject.is_active": True}},
            ]
        },
        "description": "ABAC-01 corrigée : écriture procédé uniquement depuis la salle de contrôle, pendant le quart, hors verrou de maintenance.",
    },
    {
        "policy_name": "DENY_OT_CONTROL_DURING_MAINTENANCE",
        "effect": "DENY",
        "subject_role": "OT_OPERATOR",
        "action_verb": "ot:control:write",
        "resource_urn": "urn:securiglass:ot:furnace:*",
        "condition": {"equals": {"environment.maintenance_lock": True}},
        "description": "Blocage dur (deny-overrides) pendant une maintenance planifiée.",
    },
    {
        "policy_name": "ALLOW_EDGE_TELEMETRY_INSERT",
        "effect": "ALLOW",
        "subject_role": "SERVICE_ACCOUNT_EDGE",
        "action_verb": "ot:telemetry:insert",
        "resource_urn": "urn:securiglass:ot:furnace:*",
        "condition": {
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
        "description": "ABAC-02 corrigée : ingestion unidirectionnelle depuis la Data Diode, mTLS émis par la CA OT, hors liste de révocation.",
    },
    {
        "policy_name": "DENY_REVOKED_CLIENT_CERT",
        "effect": "DENY",
        "subject_role": "*",
        "action_verb": "*",
        "resource_urn": "*",
        "condition": {"in": {"client_cert.serial": "REVOKED_CERTS_LIST"}},
        "description": "Blocage absolu de tout certificat présent dans la liste de révocation.",
    },
    {
        "policy_name": "ALLOW_RECIPE_APPROVAL_FOUR_EYES",
        "effect": "ALLOW",
        "subject_role": "PLANT_MANAGER",
        "action_verb": "it:recipe:approve",
        "resource_urn": "urn:securiglass:it:recipe:*",
        "condition": {
            "and": [
                {"greater_or_equal": {"subject.clearance_level": 3}},
                {"not_equals": {"subject.user_id": "resource.recipe.created_by"}},
            ]
        },
        "description": "ABAC-03 : approbation d'une recette thermique par un manager de clearance >= 3, distinct du créateur.",
    },
    {
        "policy_name": "DENY_SELF_RECIPE_APPROVAL",
        "effect": "DENY",
        "subject_role": "PLANT_MANAGER",
        "action_verb": "it:recipe:approve",
        "resource_urn": "urn:securiglass:it:recipe:*",
        "condition": {"equals": {"subject.user_id": "resource.recipe.created_by"}},
        "description": "Principe des quatre yeux : interdiction d'auto-approbation.",
    },
)

# ---------------------------------------------------------------------------
# Matrice RBAC (docs/specifications/RBAC_ABAC_MATRIX.md) -> role_permissions
# ---------------------------------------------------------------------------
_ROLE_PERMISSIONS: dict[str, tuple[str, ...]] = {
    "SUPER_ADMIN": (
        "sec:users:manage",
        "sec:audit:read",
        "sec:abac:configure",
        "it:orders:read",
        "it:orders:write",
        "it:recipes:manage",
        "it:recipes:approve",
        "it:batches:schedule",
        "ot:telemetry:read",
        "ot:telemetry:insert",
        "ot:quality:record",
        "ot:control:write",
    ),
    "SECURITY_AUDITOR": (
        "sec:audit:read",
        "it:orders:read",
        "ot:telemetry:read",
    ),
    "PLANT_MANAGER": (
        "it:orders:read",
        "it:orders:write",
        "it:recipes:manage",
        "it:recipes:approve",
        "it:batches:schedule",
        "ot:telemetry:read",
        "ot:quality:record",
    ),
    "OT_OPERATOR": (
        "it:orders:read",
        "ot:telemetry:read",
        "ot:control:write",
    ),
    "QUALITY_INSPECTOR": (
        "it:orders:read",
        "ot:telemetry:read",
        "ot:quality:record",
    ),
    "SERVICE_ACCOUNT_EDGE": ("ot:telemetry:insert",),
}


def _upsert_policies(bind: Connection) -> None:
    statement = """
        INSERT INTO sec_data.abac_policies
            (policy_name, effect, subject_role, action_verb, resource_urn,
             rule_condition, description, is_active)
        VALUES (%s, %s, %s, %s, %s, %s::jsonb, %s, TRUE)
        ON CONFLICT (policy_name) DO UPDATE SET
            effect = EXCLUDED.effect,
            subject_role = EXCLUDED.subject_role,
            action_verb = EXCLUDED.action_verb,
            resource_urn = EXCLUDED.resource_urn,
            rule_condition = EXCLUDED.rule_condition,
            description = EXCLUDED.description,
            is_active = TRUE
    """
    for policy in _POLICIES:
        bind.exec_driver_sql(
            statement,
            (
                policy["policy_name"],
                policy["effect"],
                policy["subject_role"],
                policy["action_verb"],
                policy["resource_urn"],
                json.dumps(policy["condition"]),
                policy["description"],
            ),
        )


def _seed_role_permissions(bind: Connection) -> None:
    statement = """
        INSERT INTO sec_data.role_permissions (role_id, permission_id)
        SELECT r.id, p.id
        FROM sec_data.roles r
        JOIN sec_data.permissions p ON p.perm_code = ANY(%s)
        WHERE r.role_code = %s
        ON CONFLICT DO NOTHING
    """
    for role_code, permissions in _ROLE_PERMISSIONS.items():
        bind.exec_driver_sql(statement, (list(permissions), role_code))


def _hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=int(os.environ.get("ARGON2_TIME_COST", "3")),
        memory_cost=int(os.environ.get("ARGON2_MEMORY_COST", "65536")),
        parallelism=int(os.environ.get("ARGON2_PARALLELISM", "4")),
        hash_len=32,
        salt_len=int(os.environ.get("ARGON2_SALT_LENGTH", "16")),
        type=Type.ID,
    )


def _seed_admin(bind: Connection) -> None:
    existing = bind.exec_driver_sql(
        "SELECT id FROM sec_data.users WHERE username = 'admin'"
    ).scalar()
    if existing is not None:
        return

    hasher = _hasher()
    password = os.environ.get("SECURIGLASS_ADMIN_PASSWORD")
    generated = password is None
    if password is None:
        password = secrets.token_urlsafe(24)

    password_hash = hasher.hash(password)
    # Le sel est embarqué dans la chaîne PHC ; la colonne est renseignée pour
    # l'audit/conformité (dictionnaire de données) et non pour la vérification.
    salt = password_hash.split("$")[4]

    user_id = bind.exec_driver_sql(
        """
        INSERT INTO sec_data.users (username, email, password_hash, salt, clearance_level)
        VALUES ('admin', 'admin@securiglass.local', %s, %s, 5)
        RETURNING id
        """,
        (password_hash, salt),
    ).scalar_one()

    bind.exec_driver_sql(
        """
        INSERT INTO sec_data.user_roles (user_id, role_id)
        SELECT %s, id FROM sec_data.roles WHERE role_code = 'SUPER_ADMIN'
        ON CONFLICT DO NOTHING
        """,
        (user_id,),
    )

    if generated:
        print(
            "[0002] Compte 'admin' créé avec un mot de passe aléatoire (affiché une seule fois) :\n"
            f"       {password}\n"
            "       Définir SECURIGLASS_ADMIN_PASSWORD avant migration pour le maîtriser."
        )


def _configure_pgaudit(bind: Connection) -> None:
    # Rôle d'audit dédié : ne s'applique qu'aux sessions de role_super_admin.
    bind.exec_driver_sql(
        "ALTER ROLE role_super_admin SET pgaudit.role = 'role_super_admin'"
    )


def upgrade() -> None:
    if context.is_offline_mode():
        for policy in _POLICIES:
            p_name = policy["policy_name"].replace("'", "''")
            eff = policy["effect"].replace("'", "''")
            s_role = policy["subject_role"].replace("'", "''")
            act = policy["action_verb"].replace("'", "''")
            res = policy["resource_urn"].replace("'", "''")
            cond = json.dumps(policy["condition"]).replace("'", "''")
            desc = policy["description"].replace("'", "''")
            op.execute(
                f"INSERT INTO sec_data.abac_policies (policy_name, effect, subject_role, action_verb, resource_urn, rule_condition, description, is_active) "
                f"VALUES ('{p_name}', '{eff}', '{s_role}', '{act}', '{res}', '{cond}'::jsonb, '{desc}', TRUE) "
                f"ON CONFLICT (policy_name) DO UPDATE SET effect = EXCLUDED.effect, subject_role = EXCLUDED.subject_role, action_verb = EXCLUDED.action_verb, resource_urn = EXCLUDED.resource_urn, rule_condition = EXCLUDED.rule_condition, description = EXCLUDED.description, is_active = TRUE;"
            )
        for role_code, perms in _ROLE_PERMISSIONS.items():
            perms_arr = "ARRAY[" + ", ".join(f"'{p}'" for p in perms) + "]::varchar[]"
            op.execute(
                f"INSERT INTO sec_data.role_permissions (role_id, permission_id) "
                f"SELECT r.id, p.id FROM sec_data.roles r JOIN sec_data.permissions p ON p.perm_code = ANY({perms_arr}) "
                f"WHERE r.role_code = '{role_code}' ON CONFLICT DO NOTHING;"
            )
        op.execute("ALTER ROLE role_super_admin SET pgaudit.role = 'role_super_admin';")
        return

    bind = op.get_bind()
    _upsert_policies(bind)
    _seed_role_permissions(bind)
    _seed_admin(bind)
    _configure_pgaudit(bind)


def downgrade() -> None:
    if context.is_offline_mode():
        names = tuple(p["policy_name"] for p in _POLICIES)
        names_str = ", ".join(f"'{n}'" for n in names)
        op.execute(
            f"DELETE FROM sec_data.abac_policies WHERE policy_name IN ({names_str});"
        )
        op.execute(
            "DELETE FROM sec_data.user_roles WHERE user_id IN (SELECT id FROM sec_data.users WHERE username = 'admin');"
        )
        op.execute("DELETE FROM sec_data.users WHERE username = 'admin';")
        return

    bind = op.get_bind()
    names = tuple(p["policy_name"] for p in _POLICIES)
    placeholders = ", ".join(["%s"] * len(names))
    bind.exec_driver_sql(
        f"DELETE FROM sec_data.abac_policies WHERE policy_name IN ({placeholders})",
        names,
    )
    bind.exec_driver_sql(
        "DELETE FROM sec_data.user_roles WHERE user_id IN "
        "(SELECT id FROM sec_data.users WHERE username = 'admin')"
    )
    bind.exec_driver_sql("DELETE FROM sec_data.users WHERE username = 'admin'")
