"""Endpoint FastAPI pour le RAG Sécurisé et la Sandbox LLM Guard (EN 12150)."""

from __future__ import annotations

import logging
import re
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.api import factory
from app.api.deps import get_current_active_user
from app.core import db
from app.services import audit_service
from app.core.rate_limiter import rag_rate_limiter
from app.models.schemas import RAGQueryIn, RAGQueryOut
from app.services.llm_guard import (
    PromptInjectionDetected,
    RAGQueryRequest,
    UnsafeOutputBlocked,
    llm_guard_service,
)

logger = logging.getLogger("securiglass.api.rag")
audit_logger = logging.getLogger("securiglass.security.audit")


async def _record_blocked(
    event_type: str,
    *,
    user_id: str,
    username: str,
    actor_ip: str,
    details: dict[str, Any],
) -> None:
    """Consigne l'incident dans la piste d'audit chaînée (source du flux d'alertes SOC).

    Au mieux : un échec de journalisation ne doit jamais transformer un rejet de
    sécurité en réponse acceptée, ni masquer le rejet.
    """
    try:
        async with db.acquire_conn() as conn:
            await audit_service.record_event(
                conn,
                event_type=event_type,
                actor_id=user_id if _is_uuid(user_id) else None,
                actor_username=username,
                actor_ip=actor_ip,
                action="POST",
                resource="/api/v1/rag/query",
                outcome="DENIED",
                details=details,
            )
    except Exception:  # noqa: BLE001 - journalisation au mieux
        logger.warning("audit de l'incident %s impossible", event_type, exc_info=True)


_REPORT_RE = re.compile(
    r"\b(rapport|report|bilan)\b.*\bproduction\b|\bproduction\b.*\b(rapport|report|bilan)\b",
    re.I,
)
_SENSITIVE_RE = re.compile(
    r"chiffre d.?affaires|financ|factur|\bprix\b|tarif|revenue|invoice|salaire|"
    r"\biban\b|coordonn|e-?mail|t[ée]l[ée]phone|\bclients?\b.*\b(donn|liste|contact)",
    re.I,
)


def _intent(prompt: str) -> str | None:
    """Intentions servies depuis la base ; évaluées APRÈS le scanner d'injection."""
    if _SENSITIVE_RE.search(prompt):
        return "sensitive"
    if _REPORT_RE.search(prompt):
        return "report"
    return None


async def _production_report() -> str | None:
    try:
        async with db.acquire_conn() as conn:
            return await factory.production_report(conn)
    except Exception:  # noqa: BLE001 - repli sur la réponse documentaire
        logger.warning("rapport de production indisponible", exc_info=True)
        return None


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


router = APIRouter(prefix="/api/v1/rag", tags=["RAG & LLM Guard"])

ALLOWED_RAG_ROLES = frozenset(
    {"OT_OPERATOR", "QUALITY_ENGINEER", "PLANT_MANAGER", "SUPER_ADMIN"}
)


@router.post(
    "/query",
    response_model=RAGQueryOut,
    summary="Interrogation de l'assistant technique RAG EN 12150 en sandbox sécurisée",
    dependencies=[Depends(rag_rate_limiter)],
)
async def query_rag_assistant(
    request_data: RAGQueryIn,
    http_request: Request,
    current_user: Annotated[Any, Depends(get_current_active_user)],
) -> RAGQueryOut:
    """Interroge l'assistant RAG protégé par les 4 barrières de sûreté hermétiques."""
    roles = (
        current_user.roles
        if hasattr(current_user, "roles")
        else current_user.get("roles", [])
    )
    if not any(r in ALLOWED_RAG_ROLES for r in roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Accès refusé : Seuls les opérateurs OT, ingénieurs qualité et responsables d'usine peuvent interroger l'assistant RAG.",
        )

    user_id = str(
        current_user.id if hasattr(current_user, "id") else current_user.get("id", "")
    )
    username = str(
        current_user.username
        if hasattr(current_user, "username")
        else current_user.get("username", "anonymous")
    )
    actor_ip = http_request.client.host if http_request.client else "127.0.0.1"

    rag_req = RAGQueryRequest(
        prompt=request_data.prompt,
        user_id=user_id,
        role=roles[0] if roles else "OT_OPERATOR",
    )

    try:
        response = llm_guard_service.query(rag_req)
        intent = _intent(request_data.prompt)
        if intent == "sensitive":
            await _record_blocked(
                "SENSITIVE_DATA_REQUEST_REFUSED",
                user_id=user_id,
                username=username,
                actor_ip=actor_ip,
                details={"category": "financial_or_personal_data"},
            )
            return RAGQueryOut(
                query=response.query,
                answer=(
                    "Demande refusée : l'assistant n'a accès ni aux données financières "
                    "ni aux données personnelles des clients. L'incident est consigné."
                ),
                retrieved_sources=[],
                confidence_score=1.0,
                safety_checked=True,
                processing_time_ms=response.processing_time_ms,
            )
        if intent == "report":
            report = await _production_report()
            if report is not None:
                return RAGQueryOut(
                    query=response.query,
                    answer=report,
                    retrieved_sources=["PostgreSQL ot_data / it_data (lecture seule)"],
                    confidence_score=1.0,
                    safety_checked=True,
                    processing_time_ms=response.processing_time_ms,
                )
        return RAGQueryOut(
            query=response.query,
            answer=response.answer,
            retrieved_sources=response.retrieved_sources,
            confidence_score=response.confidence_score,
            safety_checked=response.safety_checked,
            processing_time_ms=response.processing_time_ms,
        )

    except PromptInjectionDetected as exc:
        audit_logger.warning(
            "EVENT=PROMPT_INJECTION_BLOCKED actor=%s ip=%s action=RAG_QUERY reason=%s pattern='%s'",
            username,
            actor_ip,
            exc.reason,
            exc.detected_pattern,
        )
        await _record_blocked(
            "PROMPT_INJECTION_BLOCKED",
            user_id=user_id,
            username=username,
            actor_ip=actor_ip,
            details={"reason": exc.reason, "pattern": exc.detected_pattern},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Rejet de sécurité : Motif hostile intercepté par LLM Guard ({exc.reason}). Incident consigné.",
        ) from exc

    except UnsafeOutputBlocked as exc:
        audit_logger.critical(
            "EVENT=UNSAFE_RECIPE_BLOCKED actor=%s ip=%s action=RAG_OUTPUT_GUARD reason=%s invalid_value=%s safe_range=%s",
            username,
            actor_ip,
            exc.reason,
            exc.invalid_value,
            exc.safe_range,
        )
        await _record_blocked(
            "UNSAFE_RECIPE_BLOCKED",
            user_id=user_id,
            username=username,
            actor_ip=actor_ip,
            details={"reason": exc.reason, "invalid_value": str(exc.invalid_value)},
        )
        return RAGQueryOut(
            query=request_data.prompt,
            answer=(
                f"[CONSIGNE NON SÉCURISÉE REJETÉE] : La réponse proposée violait les bornes physiques "
                f"de la norme EN 12150 ({exc.reason} : {exc.invalid_value} hors plage autorisée "
                f"[{exc.safe_range[0]}, {exc.safe_range[1]}]). Application interdite sur l'automate four."
            ),
            retrieved_sources=["EN12150-URGENCE (NF EN 60204-1 / EN 12150)"],
            confidence_score=0.0,
            safety_checked=True,
            processing_time_ms=5.0,
        )
