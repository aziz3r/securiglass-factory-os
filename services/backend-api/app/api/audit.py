"""Endpoints de consultation et de vérification d'intégrité du journal d'audit immuable.

Conforme IEC 62443-3-3 et OWASP ASVS v4 (Audit Trail Integrity).
Accès restreint à SUPER_ADMIN et SECURITY_AUDITOR.
"""

from __future__ import annotations

import json
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Request, status

from app.api.deps import Conn, CurrentUserDep, client_ip, require_roles
from app.models.schemas import AuditLogOut, AuditVerifyOut
from app.services import audit_service

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


def _parse_details(raw: Any) -> dict[str, Any] | None:
    """asyncpg renvoie une colonne JSONB sous forme de chaîne : on la normalise.

    Sans cette normalisation, la sérialisation Pydantic échoue (500) dès qu'une
    ligne d'audit possède des `details` — cas de tous les événements d'authentification.
    """
    if raw is None:
        return None
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return None
        return parsed if isinstance(parsed, dict) else None
    return None


# Accès strictement limité aux auditeurs de sécurité et super-administrateurs
AuditReader = Annotated[
    CurrentUserDep,
    Depends(require_roles("SUPER_ADMIN", "SECURITY_AUDITOR")),
]


@router.get(
    "/logs",
    response_model=list[AuditLogOut],
    status_code=status.HTTP_200_OK,
    summary="Consultation des journaux d'audit de sécurité",
)
async def get_audit_logs(
    conn: Conn,
    user: AuditReader,
    limit: Annotated[int, Query(ge=1, le=500, description="Nombre de lignes")] = 100,
    offset: Annotated[int, Query(ge=0, description="Décalage de pagination")] = 0,
    event_type: Annotated[
        str | None, Query(description="Filtrer par type d'événement")
    ] = None,
) -> list[AuditLogOut]:
    """Récupère les pistes d'audit horodatées avec leurs empreintes cryptographiques."""
    if event_type:
        query = """
            SELECT id, event_time, event_type, actor_username, actor_ip, action,
                   resource, outcome, details, prev_log_hash, current_hash
            FROM sec_data.audit_logs
            WHERE event_type = $1
            ORDER BY event_time DESC, id DESC
            LIMIT $2 OFFSET $3
        """
        rows = await conn.fetch(query, event_type, limit, offset)
    else:
        query = """
            SELECT id, event_time, event_type, actor_username, actor_ip, action,
                   resource, outcome, details, prev_log_hash, current_hash
            FROM sec_data.audit_logs
            ORDER BY event_time DESC, id DESC
            LIMIT $1 OFFSET $2
        """
        rows = await conn.fetch(query, limit, offset)

    return [
        AuditLogOut(
            id=r["id"],
            event_time=r["event_time"],
            event_type=r["event_type"],
            actor_username=r["actor_username"],
            actor_ip=str(r["actor_ip"]),
            action=r["action"],
            resource=r["resource"],
            outcome=r["outcome"],
            details=_parse_details(r["details"]),
            prev_log_hash=r["prev_log_hash"],
            current_hash=r["current_hash"],
        )
        for r in rows
    ]


@router.get(
    "/verify",
    response_model=AuditVerifyOut,
    status_code=status.HTTP_200_OK,
    summary="Vérification cryptographique de l'intégrité de la chaîne d'audit",
)
async def verify_audit_chain(
    request: Request,
    conn: Conn,
    user: AuditReader,
) -> AuditVerifyOut:
    """Parcourt l'ensemble du journal sec_data.audit_logs pour détecter toute rupture ou altération.

    Recalcule chaque hachage SHA-256 à partir du log initial (Genesis) jusqu'au plus récent.
    """
    total_count: int = (
        await conn.fetchval("SELECT count(*) FROM sec_data.audit_logs") or 0
    )
    is_valid, broken_id_str = await audit_service.verify_stored_chain(conn)

    first_broken_uuid = None
    if broken_id_str is not None:
        import uuid

        try:
            first_broken_uuid = uuid.UUID(broken_id_str)
        except ValueError:
            first_broken_uuid = None

    # Consignation de l'opération d'audit elle-même
    await audit_service.record_event(
        conn,
        event_type="AUDIT_CHAIN_INTEGRITY_CHECK",
        actor_id=str(user.id),
        actor_username=user.username,
        actor_ip=client_ip(request),
        action="VERIFY",
        resource="sec_data.audit_logs",
        outcome="SUCCESS" if is_valid else "FAILURE",
        details={
            "chain_valid": is_valid,
            "total_records_checked": total_count,
            "first_broken_id": broken_id_str,
        },
    )

    return AuditVerifyOut(
        chain_valid=is_valid,
        first_broken_id=first_broken_uuid,
        total_records_checked=total_count,
    )
