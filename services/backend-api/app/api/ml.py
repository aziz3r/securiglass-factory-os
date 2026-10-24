"""Endpoints d'API FastAPI pour le Machine Learning et la Détection d'Anomalies Four."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, status

from app.api.deps import get_current_active_user
from app.core.rate_limiter import global_rate_limiter
from app.models.schemas import (
    MLPredictRequest,
    MLPredictResponse,
    MLStatusResponse,
    MLTrainRequest,
    MLTrainResponse,
)
from app.services.ml_anomaly import anomaly_detector

logger = logging.getLogger("securiglass.api.ml")

router = APIRouter(prefix="/api/v1/ml", tags=["Machine Learning"])


@router.post(
    "/predict",
    response_model=MLPredictResponse,
    summary="Diagnostic temps réel d'un échantillon de télémétrie process",
    dependencies=[Depends(global_rate_limiter)],
)
async def predict_anomaly(
    request: MLPredictRequest,
    current_user: Annotated[Any, Depends(get_current_active_user)],
) -> MLPredictResponse:
    """Analyse un vecteur de télémétrie four pour détecter les dérives thermiques ou pannes."""
    result = anomaly_detector.predict(request.model_dump())
    return MLPredictResponse(
        is_anomaly=result.is_anomaly,
        anomaly_score=result.anomaly_score,
        severity=result.severity,
        diagnosis=result.diagnosis,
        affected_features=result.affected_features,
        detected_at=result.detected_at,
    )


@router.post(
    "/train",
    response_model=MLTrainResponse,
    summary="Réentraînement du modèle Isolation Forest sur un lot d'échantillons",
    dependencies=[Depends(global_rate_limiter)],
)
async def train_model(
    request: MLTrainRequest,
    current_user: Annotated[Any, Depends(get_current_active_user)],
) -> MLTrainResponse:
    """Réentraîne le détecteur d'anomalies (réservé aux Ingénieurs Qualité / Responsables usine)."""
    user_clearance = (
        current_user.clearance_level
        if hasattr(current_user, "clearance_level")
        else (
            current_user.get("clearance_level", 0)
            if isinstance(current_user, dict)
            else 0
        )
    )
    if user_clearance < 3:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Habilitation insuffisante (niveau {user_clearance} < requis 3)",
        )

    roles = (
        current_user.roles
        if hasattr(current_user, "roles")
        else (current_user.get("roles", []) if isinstance(current_user, dict) else [])
    )
    allowed_roles = {"QUALITY_ENGINEER", "PLANT_MANAGER", "SUPER_ADMIN"}
    if not any(r in allowed_roles for r in roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Seuls les rôles QUALITY_ENGINEER, PLANT_MANAGER et SUPER_ADMIN peuvent réentraîner le modèle ML.",
        )

    samples_data = [s.model_dump() for s in request.samples]
    try:
        anomaly_detector.fit(samples_data)
    except Exception as exc:
        logger.error("Erreur lors de l'entraînement du modèle ML : %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Échec de l'entraînement : {exc}",
        ) from exc

    return MLTrainResponse(
        success=True,
        samples_trained=len(samples_data),
        trained_at=datetime.now(timezone.utc),
        message=f"Modèle réentraîné avec succès sur {len(samples_data)} échantillons.",
    )


@router.get(
    "/status",
    response_model=MLStatusResponse,
    summary="Consulter l'état opérationnel du modèle ML",
    dependencies=[Depends(global_rate_limiter)],
)
async def get_model_status(
    current_user: Annotated[Any, Depends(get_current_active_user)],
) -> MLStatusResponse:
    """Retourne les métadonnées et statistiques du modèle de détection d'anomalies."""
    status_dict = anomaly_detector.get_status()
    return MLStatusResponse(
        model_type=status_dict["model_type"],
        backend=status_dict["backend"],
        is_trained=status_dict["is_trained"],
        trained_samples_count=status_dict["trained_samples_count"],
        last_trained_at=(
            datetime.fromisoformat(status_dict["last_trained_at"])
            if status_dict.get("last_trained_at")
            else None
        ),
        monitored_features=status_dict["monitored_features"],
        contamination_rate=status_dict["contamination_rate"],
    )
