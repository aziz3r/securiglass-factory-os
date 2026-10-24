"""Tests des primitives cryptographiques (Argon2id, AES-256-GCM, JWT).

Cible : `app.core.security` - OWASP ASVS v4 V2 (Authentication) / V6 (Crypto).
"""

from __future__ import annotations

import base64
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.exceptions import InvalidTag

from app.core.config import get_settings
from app.core.security import (
    b64,
    decrypt_field,
    encrypt_field,
    extract_salt,
    generate_jwt_token,
    hash_password,
    verify_jwt_token,
    verify_password,
)

_PHC_RE = re.compile(r"^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$")


# ---------------------------------------------------------------------------
# Argon2id (RFC 9106)
# ---------------------------------------------------------------------------
def test_hash_uses_argon2id_with_rfc9106_cost_parameters() -> None:
    hashed = hash_password("Correct-Horse-Battery-Staple-2026")
    match = _PHC_RE.match(hashed)
    assert match is not None, f"hash PHC invalide: {hashed[:30]}"
    memory, time_cost, parallelism = (int(g) for g in match.groups())
    assert (memory, time_cost, parallelism) == (65536, 3, 4)


def test_hash_is_salted_and_non_deterministic() -> None:
    first = hash_password("same-password")
    second = hash_password("same-password")
    assert first != second
    assert extract_salt(first) != extract_salt(second)
    # Sel CSPRNG de 16 octets encodé en base64 sans padding par argon2-cffi.
    raw = base64.b64decode(extract_salt(first) + "==")
    assert len(raw) == 16


def test_verify_password_accepts_correct_and_rejects_wrong() -> None:
    hashed = hash_password("s3cr3t-Passphrase")
    assert verify_password("s3cr3t-Passphrase", hashed) is True
    assert verify_password("s3cr3t-passphrase", hashed) is False
    assert verify_password("", hashed) is False
    assert verify_password("s3cr3t-Passphrase ", hashed) is False


@pytest.mark.parametrize(
    "malformed",
    [
        "",
        "not-a-hash",
        "$argon2id$broken",
        "$argon2i$v=19$m=1,t=1,p=1$c2FsdA$aGFzaA",
        "x" * 200,
    ],
)
def test_verify_password_never_raises_on_malformed_hash(malformed: str) -> None:
    assert verify_password("whatever", malformed) is False


def test_verify_password_rejects_empty_against_real_hash() -> None:
    hashed = hash_password("real-password")
    assert verify_password("", hashed) is False


# ---------------------------------------------------------------------------
# AES-256-GCM (TDE applicatif)
# ---------------------------------------------------------------------------
def test_encrypt_decrypt_roundtrip_preserves_unicode() -> None:
    key = os.urandom(32)
    plaintext = "Béatrice Ünal — 12 rue de l'Étuve, 1000 Bruxelles ☎ +32"
    ciphertext = encrypt_field(plaintext, key)
    assert decrypt_field(ciphertext, key) == plaintext


def test_ciphertext_is_nonce_prefixed_and_randomised() -> None:
    key = os.urandom(32)
    first = encrypt_field("identical", key)
    second = encrypt_field("identical", key)
    assert first != second  # nonce aléatoire
    assert len(first) == 12 + len("identical") + 16
    assert first[:12] != second[:12]


def test_tampered_authentication_tag_is_rejected() -> None:
    key = os.urandom(32)
    ciphertext = bytearray(encrypt_field("integrity", key))
    ciphertext[-1] ^= 0x01
    with pytest.raises(InvalidTag):
        decrypt_field(bytes(ciphertext), key)


def test_tampered_ciphertext_body_is_rejected() -> None:
    key = os.urandom(32)
    ciphertext = bytearray(encrypt_field("données critiques", key))
    ciphertext[14] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt_field(bytes(ciphertext), key)


def test_tampered_nonce_is_rejected() -> None:
    key = os.urandom(32)
    ciphertext = bytearray(encrypt_field("nonce check", key))
    ciphertext[0] ^= 0xFF
    with pytest.raises(InvalidTag):
        decrypt_field(bytes(ciphertext), key)


def test_decrypt_with_wrong_key_fails() -> None:
    ciphertext = encrypt_field("secret", os.urandom(32))
    with pytest.raises(InvalidTag):
        decrypt_field(ciphertext, os.urandom(32))


@pytest.mark.parametrize("length", [0, 16, 31, 33, 64])
def test_key_must_be_exactly_256_bits(length: int) -> None:
    with pytest.raises(ValueError):
        encrypt_field("x", b"k" * length)
    with pytest.raises(ValueError):
        decrypt_field(b"y" * 64, b"k" * length)


def test_truncated_ciphertext_is_rejected() -> None:
    with pytest.raises(ValueError):
        decrypt_field(b"short", os.urandom(32))


def test_b64_helper_is_standard_base64() -> None:
    assert b64(b"\x00\x01\x02") == "AAEC"


# ---------------------------------------------------------------------------
# JWT
# ---------------------------------------------------------------------------
def _decode_raw(token: str) -> dict[str, Any]:
    raw: dict[str, Any] = pyjwt.decode(
        token,
        get_settings().secret_key.get_secret_value(),
        algorithms=["HS256"],
    )
    return raw


def test_generate_token_sets_mandatory_claims() -> None:
    token = generate_jwt_token({"sub": "user-123", "role": "OT_OPERATOR"})
    claims = _decode_raw(token)
    assert claims["sub"] == "user-123"
    assert claims["role"] == "OT_OPERATOR"
    uuid.UUID(claims["jti"])
    # RFC 7519 NumericDate : exp/iat sont des entiers (secondes epoch).
    assert isinstance(claims["exp"], int)
    assert (
        claims["exp"] - claims["iat"] == get_settings().access_token_expire_minutes * 60
    )


def test_generate_token_requires_subject() -> None:
    with pytest.raises(ValueError):
        generate_jwt_token({"role": "SUPER_ADMIN"})


def test_generate_token_keeps_provided_jti() -> None:
    jti = str(uuid.uuid4())
    claims = verify_jwt_token(generate_jwt_token({"sub": "u1", "jti": jti}))
    assert claims["jti"] == jti


def test_verify_roundtrip_returns_claims() -> None:
    claims = verify_jwt_token(generate_jwt_token({"sub": "u1", "clearance": 3}))
    assert claims["sub"] == "u1"
    assert claims["clearance"] == 3


def test_verify_rejects_tampered_signature() -> None:
    token = generate_jwt_token({"sub": "u1"})
    header, payload, signature = token.split(".")
    forged = f"{header}.{payload}.{signature[:-2]}AA"
    with pytest.raises(pyjwt.PyJWTError):
        verify_jwt_token(forged)


def test_verify_rejects_algorithm_none_confusion() -> None:
    unsigned = pyjwt.encode(
        {"sub": "attacker", "exp": 9999999999, "iat": 1, "jti": str(uuid.uuid4())},
        None,
        algorithm="none",
    )
    with pytest.raises(pyjwt.PyJWTError):
        verify_jwt_token(unsigned)


def test_verify_rejects_other_hmac_variant() -> None:
    claims = {
        "sub": "u1",
        "iat": datetime.now(timezone.utc),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=5),
        "jti": str(uuid.uuid4()),
    }
    hmac512 = pyjwt.encode(
        claims, get_settings().secret_key.get_secret_value(), algorithm="HS512"
    )
    with pytest.raises(pyjwt.InvalidAlgorithmError):
        verify_jwt_token(hmac512)


def test_verify_rejects_expired_token() -> None:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": "u1",
        "iat": now - timedelta(hours=2),
        "exp": now - timedelta(hours=1),
        "jti": str(uuid.uuid4()),
    }
    expired = pyjwt.encode(
        claims, get_settings().secret_key.get_secret_value(), algorithm="HS256"
    )
    with pytest.raises(pyjwt.ExpiredSignatureError):
        verify_jwt_token(expired)


@pytest.mark.parametrize("missing", ["sub", "exp", "iat", "jti"])
def test_verify_rejects_missing_required_claim(missing: str) -> None:
    now = datetime.now(timezone.utc)
    claims: dict[str, Any] = {
        "sub": "u1",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "jti": str(uuid.uuid4()),
    }
    del claims[missing]
    token = pyjwt.encode(
        claims, get_settings().secret_key.get_secret_value(), algorithm="HS256"
    )
    with pytest.raises(pyjwt.MissingRequiredClaimError):
        verify_jwt_token(token)


def test_verify_rejects_non_uuid_jti() -> None:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": "u1",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "jti": "not-a-uuid",
    }
    token = pyjwt.encode(
        claims, get_settings().secret_key.get_secret_value(), algorithm="HS256"
    )
    with pytest.raises(ValueError):
        verify_jwt_token(token)


def test_verify_rejects_token_signed_with_other_secret() -> None:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": "u1",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "jti": str(uuid.uuid4()),
    }
    token = pyjwt.encode(
        claims, "another-secret-key-of-32-bytes-min!!", algorithm="HS256"
    )
    with pytest.raises(pyjwt.InvalidSignatureError):
        verify_jwt_token(token)
