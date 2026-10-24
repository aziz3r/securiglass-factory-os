"""Schémas Pydantic v2 stricts pour SecuriGlass Factory OS (IAM & Métier).

Validation stricte (rejet systématique des champs inconnus via extra='forbid'),
assurant la conformité OWASP ASVS v4 et IEC 62443.
"""

import re
import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field

# Les comptes d'une usine utilisent des domaines internes (`.local`, RFC 6762 /
# mDNS) que `EmailStr` rejette comme « special-use ». On valide donc la syntaxe
# pour les identités internes, tout en gardant `EmailStr` sur les données clients.
_INTERNAL_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)


def _validate_internal_email(value: str) -> str:
    if len(value) > 254 or not _INTERNAL_EMAIL_RE.fullmatch(value):
        raise ValueError("adresse e-mail interne invalide")
    return value


InternalEmail = Annotated[str, AfterValidator(_validate_internal_email)]


class StrictBaseModel(BaseModel):
    """Modèle de base strict interdisant tout champ parasite."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        populate_by_name=True,
    )


# ============================================================================
# 1. AUTHENTIFICATION & UTILISATEURS
# ============================================================================


class LoginRequest(StrictBaseModel):
    username: str = Field(
        ..., min_length=3, max_length=64, description="Nom d'utilisateur normalisé"
    )
    password: str = Field(
        ..., min_length=1, max_length=256, description="Mot de passe en clair"
    )


# Alias pour interopérabilité
Login = LoginRequest


class TokenResponse(StrictBaseModel):
    access_token: str = Field(..., description="Jeton JWT signé avec JTI unique")
    token_type: str = Field(default="bearer", description="Type de jeton (RFC 6750)")
    expires_in: int = Field(..., description="Durée de validité en secondes")


# Alias
Token = TokenResponse


class MeResponse(StrictBaseModel):
    id: uuid.UUID
    username: str
    email: InternalEmail
    roles: list[str]
    clearance_level: int = Field(
        ..., ge=1, le=5, description="Niveau d'habilitation (1 à 5)"
    )


class UserResponse(StrictBaseModel):
    id: uuid.UUID
    username: str
    email: InternalEmail
    roles: list[str] = Field(default_factory=list)
    clearance_level: int = Field(default=1, ge=1, le=5)
    is_active: bool = True
    is_mfa_enabled: bool = False
    created_at: datetime | None = None
    updated_at: datetime | None = None


# ============================================================================
# 2. CLIENTS B2B & CHIFFREMENT TDE RGPD
# ============================================================================


class CustomerCreate(StrictBaseModel):
    company_name: str = Field(
        ..., min_length=1, max_length=128, description="Raison sociale"
    )
    contact_name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Nom du contact (PII - chiffré TDE)",
    )
    email: EmailStr = Field(..., description="Email professionnel (PII - chiffré TDE)")
    phone: str | None = Field(
        default=None,
        max_length=32,
        pattern=r"^\+?[0-9 .\-()]{6,32}$",
        description="Numéro de téléphone (PII - chiffré TDE)",
    )
    vat_number: str | None = Field(
        default=None, max_length=32, description="Numéro de TVA intracommunautaire"
    )
    country_code: str = Field(
        default="FR", pattern=r"^[A-Z]{2}$", description="Code ISO 3166-1 alpha-2"
    )


class CustomerResponse(StrictBaseModel):
    """Données client avec déchiffrement TDE des champs RGPD sensibles."""

    id: uuid.UUID
    company_name: str
    contact_name: str = Field(..., description="Nom déchiffré à la volée")
    email: EmailStr = Field(..., description="Email déchiffré à la volée")
    phone: str | None = Field(default=None, description="Téléphone déchiffré")
    vat_number: str | None = None
    country_code: str
    is_active: bool = True
    created_at: datetime | None = None


class CustomerOut(StrictBaseModel):
    """Vue sommaire client (données non sensibles)."""

    id: uuid.UUID
    company_name: str
    country_code: str
    is_active: bool = True


# ============================================================================
# 3. POLITIQUES CONTEXTUELLES ABAC
# ============================================================================


class ABACPolicyCreate(StrictBaseModel):
    policy_name: str = Field(..., min_length=3, max_length=64)
    effect: str = Field(..., pattern=r"^(ALLOW|DENY)$")
    subject_role: str = Field(..., min_length=1, max_length=32)
    action_verb: str = Field(..., min_length=1, max_length=32)
    resource_urn: str = Field(..., min_length=1, max_length=128)
    rule_condition: dict[str, Any] = Field(
        ..., description="Expression JSONB de condition"
    )
    description: str | None = None


class ABACPolicyResponse(StrictBaseModel):
    id: uuid.UUID
    policy_name: str
    effect: str
    subject_role: str
    action_verb: str
    resource_urn: str
    rule_condition: dict[str, Any]
    description: str | None = None
    is_active: bool = True
    created_at: datetime | None = None


class ABACEvaluationRequest(StrictBaseModel):
    roles: list[str] = Field(..., min_length=1)
    action: str
    resource_urn: str
    context: dict[str, Any] = Field(default_factory=dict)


class ABACEvaluationResponse(StrictBaseModel):
    allowed: bool
    reason: str
    policy: str | None = None


# ============================================================================
# 4. JOURNAL D'AUDIT IMMUABLE & CONTRÔLE D'INTÉGRITÉ
# ============================================================================


class AuditLogCreate(StrictBaseModel):
    event_type: str = Field(..., min_length=1, max_length=64)
    actor_username: str = Field(..., min_length=1, max_length=64)
    actor_ip: str = Field(..., min_length=1, max_length=45)
    action: str = Field(..., min_length=1, max_length=32)
    resource: str = Field(..., min_length=1, max_length=128)
    outcome: str = Field(..., pattern=r"^(SUCCESS|DENIED|FAILURE)$")
    actor_id: uuid.UUID | None = None
    client_cert_fingerprint: str | None = None
    details: dict[str, Any] | None = None


class AuditLogOut(StrictBaseModel):
    id: uuid.UUID
    event_time: datetime
    event_type: str
    actor_username: str
    actor_ip: str
    action: str
    resource: str
    outcome: str
    details: dict[str, Any] | None = None
    prev_log_hash: str | None = None
    current_hash: str


# Alias
AuditLogResponse = AuditLogOut


class AuditVerifyOut(StrictBaseModel):
    chain_valid: bool
    first_broken_id: uuid.UUID | None = None
    total_records_checked: int = 0


# ============================================================================
# 5. TÉLÉMÉTRIE OT FOUR EN 12150 & DATA DIODE LOGIQUE
# ============================================================================


class FurnaceTelemetryData(StrictBaseModel):
    """Métriques physiques du four de trempe (EN 12150)."""

    temp_zone1_c: float = Field(
        ..., ge=0.0, le=850.0, description="Température Zone 1 (°C)"
    )
    temp_zone2_c: float = Field(
        ..., ge=0.0, le=850.0, description="Température Zone 2 (°C)"
    )
    temp_zone3_c: float = Field(
        ..., ge=0.0, le=850.0, description="Température Zone 3 (°C)"
    )
    temp_zone4_c: float = Field(
        ..., ge=0.0, le=850.0, description="Température Zone 4 (°C)"
    )
    glass_pyrometer_temp_c: float = Field(
        ..., ge=0.0, le=850.0, description="Pyromètre optique verre (°C)"
    )
    quench_pressure_bar: float = Field(
        ..., ge=0.0, le=12.0, description="Pression de trempe (bar)"
    )
    conveyor_speed_m_min: float = Field(
        ..., ge=0.0, le=50.0, description="Vitesse rouleaux (m/min)"
    )
    blower_current_amps: float = Field(
        default=0.0, ge=0.0, le=100.0, description="Courant soufflante (A)"
    )
    power_consumption_kw: float = Field(
        default=0.0, ge=0.0, le=500.0, description="Puissance instantanée (kW)"
    )
    emergency_stop_tripped: bool = Field(
        default=False, description="État bouton d'urgence NF"
    )
    plc_status_flags: int = Field(
        default=0, ge=0, le=65535, description="Masque de drapeaux automate"
    )


class FurnaceTelemetryPayload(StrictBaseModel):
    """Payload JSON canonique transmis dans le datagramme de la diode."""

    schema_version: int = Field(default=1, ge=1)
    line_id: str = Field(..., min_length=1, max_length=64)
    sequence: int = Field(..., ge=0)
    measured_at: datetime
    values: dict[str, Any]
    batch_id: str | None = None


class FurnaceTelemetryDB(StrictBaseModel):
    """Représentation persistée dans ot_data.furnace_telemetry."""

    id: int | None = None
    timestamp: datetime
    line_id: uuid.UUID
    batch_id: uuid.UUID | None = None
    temp_zone1_c: float
    temp_zone2_c: float
    temp_zone3_c: float
    temp_zone4_c: float
    glass_pyrometer_temp_c: float
    quench_pressure_bar: float
    conveyor_speed_m_min: float
    blower_current_amps: float = 0.0
    power_consumption_kw: float = 0.0
    emergency_stop_tripped: bool = False
    plc_status_flags: int = 0


class DiodeImportLogDB(StrictBaseModel):
    """Journal immuable d'ingestion Data Diode (ot_data.diode_import_log)."""

    id: uuid.UUID | None = None
    transmission_id: uuid.UUID
    source_gateway: str = Field(..., min_length=1, max_length=64)
    records_ingested: int = Field(..., ge=0)
    packet_sha256: str = Field(..., min_length=64, max_length=64)
    ed25519_signature: str = Field(..., min_length=64)
    verified_at: datetime | None = None


# ============================================================================
# 6. DÉTECTION D'ANOMALIES ML & SANDBOX RAG / LLM GUARD
# ============================================================================


class MLPredictRequest(StrictBaseModel):
    """Échantillon de télémétrie process pour diagnostic ML temps réel."""

    temp_zone1_c: float = Field(..., ge=0.0, le=850.0)
    temp_zone2_c: float = Field(..., ge=0.0, le=850.0)
    temp_zone3_c: float = Field(..., ge=0.0, le=850.0)
    temp_zone4_c: float = Field(..., ge=0.0, le=850.0)
    glass_pyrometer_temp_c: float = Field(..., ge=0.0, le=850.0)
    quench_pressure_bar: float = Field(..., ge=0.0, le=12.0)
    conveyor_speed_m_min: float = Field(..., ge=0.0, le=50.0)
    blower_current_amps: float = Field(default=0.0, ge=0.0, le=100.0)
    power_consumption_kw: float = Field(default=0.0, ge=0.0, le=500.0)


class MLPredictResponse(StrictBaseModel):
    """Diagnostic d'anomalie retourné par le modèle Isolation Forest."""

    is_anomaly: bool
    anomaly_score: float
    severity: str = Field(..., pattern=r"^(NORMAL|WARNING|CRITICAL)$")
    diagnosis: str | None = None
    affected_features: list[str] = Field(default_factory=list)
    detected_at: datetime


class MLTrainRequest(StrictBaseModel):
    """Lot d'échantillons process pour réentraînement du modèle."""

    samples: list[MLPredictRequest] = Field(..., min_length=10, max_length=10000)


class MLTrainResponse(StrictBaseModel):
    """Confirmation d'entraînement du modèle ML."""

    success: bool
    samples_trained: int
    trained_at: datetime
    message: str


class MLStatusResponse(StrictBaseModel):
    """Statut opérationnel du modèle de détection d'anomalies."""

    model_type: str
    backend: str
    is_trained: bool
    trained_samples_count: int
    last_trained_at: datetime | None = None
    monitored_features: list[str]
    contamination_rate: float


class RAGQueryIn(StrictBaseModel):
    """Requête utilisateur transmise à l'assistant RAG EN 12150."""

    prompt: str = Field(
        ...,
        min_length=3,
        max_length=2000,
        description="Question technique ou consigne procédé",
    )


class RAGQueryOut(StrictBaseModel):
    """Réponse générée et vérifiée par les 4 barrières de sûreté LLM Guard."""

    query: str
    answer: str
    retrieved_sources: list[str]
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    safety_checked: bool = True
    processing_time_ms: float
