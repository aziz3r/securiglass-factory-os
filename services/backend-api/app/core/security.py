"""Primitives cryptographiques durcies pour SecuriGlass Factory OS.

Conforme :
- OWASP ASVS v4.0 (Niveau 2+)
- RFC 9106 (Argon2id pour le hachage des mots de passe)
- NIST SP 800-38D (AES-256-GCM pour le TDE RGPD)
- RFC 7519 (JSON Web Token avec JTI unique)
"""

import base64
import hashlib
import hmac
import json
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.core.config import get_settings

logger = logging.getLogger("securiglass.security")

# Constantes AES-256-GCM
_AES_KEY_LEN = 32  # 256 bits
_GCM_NONCE_LEN = 12  # 96 bits
_GCM_TAG_LEN = 16  # 128 bits
_REQUIRED_JWT_CLAIMS = ["exp", "iat", "sub", "jti"]

_ARGON2_AVAILABLE = True


# ============================================================================
# 1. HACHAGE DE MOTS DE PASSE (ARGON2ID RFC 9106, SANS REPLI)
# ============================================================================


def _get_argon2_hasher() -> PasswordHasher:
    settings = get_settings()
    return PasswordHasher(
        time_cost=settings.argon2_time_cost,
        memory_cost=settings.argon2_memory_cost,
        parallelism=settings.argon2_parallelism,
        hash_len=32,
        salt_len=settings.argon2_salt_length,
        type=Type.ID,
    )


def hash_password(password: str) -> str:
    """Hache un mot de passe en Argon2id (m=64 MiB, t=3, p=4, sel 16 octets)."""
    return _get_argon2_hasher().hash(password)


def extract_salt(password_hash: str) -> str:
    """Sel (base64) du hash PHC Argon2id, pour la colonne sec_data.users.salt."""
    parts = password_hash.split("$")
    if len(parts) < 6 or parts[1] != "argon2id":
        raise ValueError("not an Argon2id PHC hash")
    return parts[4]


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Vérifie un mot de passe ; tout hash non Argon2id est refusé."""
    if not hashed_password.startswith("$argon2id$"):
        return False
    try:
        return _get_argon2_hasher().verify(hashed_password, plain_password)
    except (VerificationError, InvalidHashError):
        return False


# ============================================================================
# 2. CHIFFREMENT SYMÉTRIQUE TRANSPARENT (TDE RGPD - AES-256-GCM)
# ============================================================================


def encrypt_field(plaintext: str, key: bytes) -> bytes:
    """Chiffre une chaîne sensible (RGPD) en AES-256-GCM.

    Format retourné : Nonce (12 octets) || Ciphertext || Tag d'authentification (16 octets).
    """
    if len(key) != _AES_KEY_LEN:
        raise ValueError(
            f"AES-256-GCM requiert une clé de {_AES_KEY_LEN} octets (reçu: {len(key)})"
        )

    nonce = os.urandom(_GCM_NONCE_LEN)
    aesgcm = AESGCM(key)
    # Dans cryptography, encrypt() concatène automatiquement ciphertext + 16 bytes auth tag
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce + ciphertext_with_tag


def decrypt_field(ciphertext: bytes, key: bytes) -> str:
    """Déchiffre un champ chiffré en AES-256-GCM.

    Vérifie l'intégrité via le tag d'authentification GCM.
    Lève ValueError si le format est invalide ou cryptography.exceptions.InvalidTag si altéré.
    """
    if len(key) != _AES_KEY_LEN:
        raise ValueError(
            f"AES-256-GCM requiert une clé de {_AES_KEY_LEN} octets (reçu: {len(key)})"
        )

    min_length = _GCM_NONCE_LEN + _GCM_TAG_LEN
    if len(ciphertext) < min_length:
        raise ValueError(
            f"Ciphertext trop court : {len(ciphertext)} octets (minimum attendu : {min_length})"
        )

    nonce = ciphertext[:_GCM_NONCE_LEN]
    body = ciphertext[_GCM_NONCE_LEN:]
    aesgcm = AESGCM(key)
    decrypted_bytes = aesgcm.decrypt(nonce, body, None)
    return decrypted_bytes.decode("utf-8")


# ============================================================================
# 3. GESTION DES JETONS JWT (AVEC JTI UNIQUE ET CONTRÔLE DE RÉVOCATION)
# ============================================================================


def generate_jwt_token(
    payload: dict[str, Any], expires_delta: timedelta | None = None
) -> str:
    """Génère un jeton JWT signé avec identifiant unique (JTI) et expiration stricte."""
    settings = get_settings()
    if "sub" not in payload:
        raise ValueError(
            "Le payload du token JWT doit impérativement contenir le claim 'sub'"
        )

    now = datetime.now(timezone.utc)
    if expires_delta is not None:
        exp = now + expires_delta
    else:
        exp = now + timedelta(minutes=settings.access_token_expire_minutes)

    claims = {
        **payload,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": payload.get("jti") or str(uuid.uuid4()),
    }

    return jwt.encode(
        claims,
        settings.secret_key.get_secret_value(),
        algorithm=settings.jwt_algorithm,
    )


def verify_jwt_token(token: str) -> dict[str, Any]:
    """Vérifie la signature et la validité du token JWT.

    Lève jwt.PyJWTError ou ValueError si le token est falsifié, expiré ou sans JTI UUID.
    """
    settings = get_settings()
    claims: dict[str, Any] = jwt.decode(
        token,
        settings.secret_key.get_secret_value(),
        algorithms=[settings.jwt_algorithm],
        options={"require": _REQUIRED_JWT_CLAIMS},
    )

    # Valide que le JTI est un UUID valide
    jti_str = str(claims.get("jti", ""))
    uuid.UUID(jti_str)

    return claims


def get_jti_from_token(token: str) -> str:
    """Extrait le JTI du token après vérification cryptographique."""
    claims = verify_jwt_token(token)
    return str(claims["jti"])


# ============================================================================
# 4. CALCUL D'EMPREINTE CHAÎNÉE SHA-256 POUR LE JOURNAL D'AUDIT IMMUABLE
# ============================================================================


def _canonical_json(data: Any) -> str:
    """Génère une représentation JSON déterministe (tri des clés, séparateurs compacts)."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def compute_audit_hash(
    prev_hash: str | None,
    actor: str,
    event: str,
    timestamp: datetime | str,
    resource: str,
    action: str = "",
    outcome: str = "",
    details: dict[str, Any] | None = None,
    actor_ip: str = "",
) -> str:
    """Calcule l'empreinte SHA-256 chaînée pour un enregistrement du journal d'audit.

    Formule canonique conforme IEC 62443 :
    current_hash = SHA256(prev_hash + canonical_representation(actor, event, timestamp, resource, ...))
    """
    ts_str = (
        timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp)
    )
    record = {
        "action": action,
        "actor": actor,
        "actor_ip": actor_ip,
        "details": details,
        "event": event,
        "outcome": outcome,
        "resource": resource,
        "timestamp": ts_str,
    }
    prev_clean = prev_hash or ""
    serialized = prev_clean + _canonical_json(record)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def b64(data: bytes) -> str:
    """Encode des octets bruts en chaîne Base64 ASCII."""
    return base64.b64encode(data).decode("ascii")
