"""Étape 1 - Correctif D10 : suppression de la FK `audit_logs.actor_id`.

Défaut constaté : `actor_id UUID REFERENCES sec_data.users(id)
ON DELETE SET NULL` est incompatible avec le trigger d'immuabilité
`trg_audit_logs_immutable`. Supprimer un utilisateur déclenche un `UPDATE` de
`sec_data.audit_logs` (mise à NULL), que le trigger refuse :

    VIOLATION CRITIQUE DE SÉCURITÉ : Le journal d audit ... est strictement immuable

Conséquences : aucun compte ne peut être supprimé (exigence RGPD art. 17) et la
purge d'un compte compromis est impossible.

Correctif : l'audit conserve un **instantané** de l'identité (`actor_id`,
`actor_username`) sans contrainte référentielle. C'est la pratique recommandée
pour une piste d'audit : elle ne doit jamais être réécrite, même par effet de bord.

Revision ID: 0003_audit_actor_no_fk
Revises: 0002_seed_iam_abac
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import context, op
from sqlalchemy.engine import Connection

revision: str = "0003_audit_actor_no_fk"
down_revision: str | None = "0002_seed_iam_abac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FK_NAME = "audit_logs_actor_id_fkey"


def _fk_exists(bind: Connection) -> bool:
    result = bind.exec_driver_sql(
        """
        SELECT 1 FROM pg_constraint
        WHERE conrelid = 'sec_data.audit_logs'::regclass
          AND conname = %s
        """,
        (_FK_NAME,),
    )
    return result.first() is not None


def upgrade() -> None:
    op.execute(f"ALTER TABLE sec_data.audit_logs DROP CONSTRAINT IF EXISTS {_FK_NAME}")
    op.execute(
        "COMMENT ON COLUMN sec_data.audit_logs.actor_id IS "
        "'Instantané immuable de l''identité (UUID), sans FK : see migration 0003 (D10)'"
    )


def downgrade() -> None:
    if not context.is_offline_mode():
        bind = op.get_bind()
        if _fk_exists(bind):
            return
    op.execute(
        "ALTER TABLE sec_data.audit_logs "
        "ADD CONSTRAINT audit_logs_actor_id_fkey "
        "FOREIGN KEY (actor_id) REFERENCES sec_data.users(id) ON DELETE SET NULL"
    )
