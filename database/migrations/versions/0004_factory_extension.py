"""Extension usine : stocks de matières premières (`it_data.raw_materials`).

Applique `database/schemas/06_factory_extension.sql` (idempotent : `IF NOT EXISTS`,
`ON CONFLICT DO NOTHING`).

Revision ID: 0004_factory_extension
Revises: 0003_audit_actor_no_fk
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from alembic import op

revision: str = "0004_factory_extension"
down_revision: str | None = "0003_audit_actor_no_fk"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_SQL = (
    Path(__file__).resolve().parents[3]
    / "database"
    / "schemas"
    / "06_factory_extension.sql"
)


def upgrade() -> None:
    if not _SQL.is_file():
        raise FileNotFoundError(f"script DDL introuvable : {_SQL}")
    op.execute(_SQL.read_text(encoding="utf-8"))


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS it_data.raw_materials")
