"""Étape 1 - Schéma initial (Purdue : ot_data / it_data / sec_data + rôles SQL).

Cette révision applique les scripts DDL de référence de l'architecte
(`database/schemas/*.sql`) dans l'ordre. Elle est **idempotente** : si les schémas
ont déjà été créés par `docker-entrypoint-initdb.d`, la révision se contente de
les baseliner (utile pour adopter Alembic sur une base existante).

Revision ID: 0001_initial_schema
Revises:
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import context, op
from sqlalchemy.engine import Connection

revision: str = "0001_initial_schema"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SCHEMA_FILES: tuple[str, ...] = (
    "01_init_extensions.sql",
    "02_ot_data_schema.sql",
    "03_it_data_schema.sql",
    "04_sec_data_schema.sql",
    "05_rbac_abac_grants.sql",
)

# .../database/migrations/versions/0001_initial_schema.py -> racine du dépôt
_REPO_ROOT = Path(__file__).resolve().parents[3]
_SCHEMA_DIR = _REPO_ROOT / "database" / "schemas"


def _schema_already_present(bind: Connection) -> bool:
    result = bind.exec_driver_sql("SELECT to_regclass('sec_data.users') IS NOT NULL")
    return bool(result.scalar())


def upgrade() -> None:
    if not context.is_offline_mode():
        bind = op.get_bind()
        if _schema_already_present(bind):
            print(
                "[0001] schémas déjà présents (initdb Docker) -> baseline sans ré-exécution"
            )
            return

    for filename in _SCHEMA_FILES:
        path = _SCHEMA_DIR / filename
        if not path.is_file():
            raise FileNotFoundError(f"script DDL introuvable : {path}")
        op.execute(path.read_text(encoding="utf-8"))
        print(f"[0001] appliqué {filename}")


def downgrade() -> None:
    for schema in ("ot_data", "it_data", "sec_data"):
        op.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
    for role in (
        "role_edge_service",
        "role_quality_inspector",
        "role_ot_operator",
        "role_plant_manager",
        "role_security_auditor",
        "role_super_admin",
    ):
        op.execute(f"DROP ROLE IF EXISTS {role}")
