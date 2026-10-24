"""Service d'enregistrement et de vérification des pistes d'audit immuables (IEC 62443).

Garantit la détection infaillible de toute altération par chaînage cryptographique SHA-256.
Chaque enregistrement scelle le hash du précédent :
current_hash = SHA-256(prev_hash || Canonical(actor, event, timestamp, resource, action, outcome, details))
"""

import hashlib
import ipaddress
import json
import logging
from collections.abc import Sequence
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

import asyncpg

from app.core.db import DbConn

from app.core.security import compute_audit_hash

logger = logging.getLogger("securiglass.audit")

_CHAIN_LOCK_KEY = (
    0x5EC0_A0D1  # Verrou consultatif PostgreSQL pour sérialiser l'insertion
)
_GENESIS_HASH: str | None = None


def _format_event_time(dt: datetime) -> str:
    """Normalise l'horodatage en UTC ISO-8601 pour un calcul de hachage reproductible."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat()


def calculate_record_hash(
    prev_hash: str | None,
    event_time: datetime,
    event_type: str,
    actor_username: str,
    actor_ip: str,
    action: str,
    resource: str,
    outcome: str,
    details: dict[str, Any] | None = None,
) -> str:
    """Calcule le hash cryptographique SHA-256 d'une ligne d'audit."""
    try:
        ip_str = str(ipaddress.ip_address(actor_ip))
    except ValueError:
        ip_str = str(actor_ip)
    return compute_audit_hash(
        prev_hash=prev_hash,
        actor=actor_username,
        event=event_type,
        timestamp=_format_event_time(event_time),
        resource=resource,
        action=action,
        outcome=outcome,
        details=details,
        actor_ip=ip_str,
    )


async def record_event(
    conn: DbConn,
    *,
    event_type: str,
    actor_username: str,
    actor_ip: str,
    action: str,
    resource: str,
    outcome: str,
    actor_id: str | None = None,
    client_cert_fingerprint: str | None = None,
    details: dict[str, Any] | None = None,
) -> str:
    """Enregistre un événement audité dans sec_data.audit_logs avec scellement SHA-256."""
    async with conn.transaction():
        # Verrou consultatif de transaction pour éviter tout conflit de concurrence sur le hash
        await conn.execute("SELECT pg_advisory_xact_lock($1)", _CHAIN_LOCK_KEY)

        # Récupération du dernier hash enregistré
        last_row = await conn.fetchrow(
            "SELECT current_hash, event_time FROM sec_data.audit_logs "
            "ORDER BY event_time DESC, id DESC LIMIT 1"
        )
        prev_hash: str | None = last_row["current_hash"] if last_row else _GENESIS_HASH

        now = datetime.now(timezone.utc)
        if last_row and now <= last_row["event_time"]:
            # Horloge non strictement croissante : garantit la stricte séquentialité
            now = last_row["event_time"] + timedelta(microseconds=1)

        current_hash = calculate_record_hash(
            prev_hash=prev_hash,
            event_time=now,
            event_type=event_type,
            actor_username=actor_username,
            actor_ip=actor_ip,
            action=action,
            resource=resource,
            outcome=outcome,
            details=details,
        )

        details_json = json.dumps(details) if details is not None else None

        await conn.execute(
            """
            INSERT INTO sec_data.audit_logs (
                event_time, event_type, actor_id, actor_username, actor_ip,
                client_cert_fingerprint, action, resource, outcome, details,
                prev_log_hash, current_hash
            ) VALUES (
                $1, $2, $3::uuid, $4, $5::inet, $6, $7, $8, $9, $10::jsonb, $11, $12
            )
            """,
            now,
            event_type,
            actor_id,
            actor_username,
            actor_ip,
            client_cert_fingerprint,
            action,
            resource,
            outcome,
            details_json,
            prev_hash,
            current_hash,
        )

        logger.info(
            "AUDIT: Événement %s consigné pour %s (outcome=%s, hash=%s)",
            event_type,
            actor_username,
            outcome,
            current_hash[:12],
        )
        return current_hash


def verify_chain_in_memory(records: Sequence[Any]) -> tuple[bool, str | None]:
    """Vérifie l'intégrité séquentielle d'une liste ordonnée d'enregistrements d'audit.

    Retourne:
    - (True, None) si la chaîne est valide.
    - (False, broken_record_id) dès la première anomalie ou altération détectée.
    """
    expected_prev_hash: str | None = None

    for idx, item in enumerate(records):
        rec = dict(item)
        rec_id = str(rec.get("id", f"record-idx-{idx}"))
        row_prev = rec.get("prev_log_hash")
        row_current = rec.get("current_hash")

        # 1. Vérification de la liaison au hash précédent
        if row_prev != expected_prev_hash:
            logger.warning(
                "RUPTURE D'AUDIT (Liaison rompue) sur %s : attendu %s, obtenu %s",
                rec_id,
                expected_prev_hash,
                row_prev,
            )
            return False, rec_id

        # 2. Recalcul et comparaison de l'empreinte intrinsèque
        details_val = rec.get("details")
        if isinstance(details_val, str):
            try:
                details_dict = json.loads(details_val)
            except Exception:
                details_dict = None
        elif isinstance(details_val, dict):
            details_dict = details_val
        else:
            details_dict = None

        raw_event_time = rec["event_time"]
        if isinstance(raw_event_time, str):
            parsed_time = datetime.fromisoformat(raw_event_time)
        else:
            parsed_time = raw_event_time

        recalculated = calculate_record_hash(
            prev_hash=row_prev,
            event_time=parsed_time,
            event_type=rec["event_type"],
            actor_username=rec["actor_username"],
            actor_ip=str(rec["actor_ip"]),
            action=rec["action"],
            resource=rec["resource"],
            outcome=rec["outcome"],
            details=details_dict,
        )

        if recalculated != row_current:
            logger.warning(
                "RUPTURE D'AUDIT (Altération de contenu) sur %s : hash recalculé %s != stocké %s",
                rec_id,
                recalculated,
                row_current,
            )
            return False, rec_id

        expected_prev_hash = row_current

    return True, None


async def verify_stored_chain(conn: DbConn) -> tuple[bool, str | None]:
    """Exécute un contrôle d'intégrité exhaustif sur la table sec_data.audit_logs."""
    rows = await conn.fetch(
        "SELECT id, event_time, event_type, actor_username, actor_ip, action, resource, "
        "outcome, details, prev_log_hash, current_hash "
        "FROM sec_data.audit_logs ORDER BY event_time ASC, id ASC"
    )
    return verify_chain_in_memory([dict(r) for r in rows])
