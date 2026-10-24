"""Tests de durcissement de la configuration (fail-fast, OWASP ASVS V14.1).

Aucun secret ne doit avoir de valeur par défaut ; les valeurs faibles ou les
combinaisons dangereuses doivent être refusées au démarrage.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings

_VALID = {
    "database_url": "postgresql://user:pass@localhost:5432/db",
    "secret_key": "a" * 64,
    "tde_encryption_key": "ab" * 32,
}


def settings_with(**overrides: object) -> Settings:
    kwargs = {**_VALID, **overrides}
    return Settings(_env_file=None, **kwargs)  # type: ignore[arg-type]


def test_valid_minimal_configuration_loads() -> None:
    settings = settings_with(environment="development")
    assert settings.environment == "development"
    assert settings.argon2_memory_cost == 65536
    assert settings.tde_key_bytes == bytes.fromhex("ab" * 32)


@pytest.mark.parametrize(
    "missing", ["database_url", "secret_key", "tde_encryption_key"]
)
def test_missing_secret_fails_fast(
    missing: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Sans variable d'environnement ni valeur explicite, le service refuse de démarrer."""
    monkeypatch.delenv(missing.upper(), raising=False)
    kwargs = {k: v for k, v in _VALID.items() if k != missing}
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "secret",
    [
        "short",
        "replace_with_64_bytes_secure_random_key_in_production",
        "change_me_please_change_me_please_123456",
        "your_secret_key_here_0123456789abcdef0123",
    ],
)
def test_weak_or_placeholder_secret_is_rejected(secret: str) -> None:
    with pytest.raises(ValidationError):
        settings_with(secret_key=secret)


@pytest.mark.parametrize(
    "tde_key",
    ["not-hex", "ab" * 16, "ab" * 33, ""],
)
def test_tde_key_must_be_256_bits_hex(tde_key: str) -> None:
    with pytest.raises(ValidationError):
        settings_with(tde_encryption_key=tde_key)


@pytest.mark.parametrize(
    "dsn", ["mysql://u:p@h/db", "sqlite:///db.sqlite", "not-a-dsn"]
)
def test_database_dsn_must_be_postgresql(dsn: str) -> None:
    with pytest.raises(ValidationError):
        settings_with(database_url=dsn)


def test_jwt_algorithm_is_pinned_to_hmac() -> None:
    assert settings_with(jwt_algorithm="HS512").jwt_algorithm == "HS512"
    for algorithm in ("none", "RS256", "ES256", "hs256"):
        with pytest.raises(ValidationError):
            settings_with(jwt_algorithm=algorithm)


def test_pool_sizes_must_be_coherent() -> None:
    with pytest.raises(ValidationError):
        settings_with(db_min_connections=10, db_max_connections=5)


@pytest.mark.parametrize(
    "overrides",
    [
        {"db_min_connections": 0},
        {"argon2_time_cost": 2},
        {"argon2_memory_cost": 1024},
        {"argon2_parallelism": 0},
        {"argon2_salt_length": 8},
        {"max_failed_logins": 0},
        {"access_token_expire_minutes": 0},
        {"access_token_expire_minutes": 61},
        {"refresh_token_expire_days": 0},
    ],
)
def test_security_floor_values_are_enforced(overrides: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        settings_with(**overrides)


def test_production_forbids_debug_logging() -> None:
    with pytest.raises(ValidationError):
        settings_with(environment="production", log_level="DEBUG")


def test_production_forbids_long_access_tokens() -> None:
    with pytest.raises(ValidationError):
        settings_with(environment="production", access_token_expire_minutes=45)


def test_production_accepts_hardened_configuration() -> None:
    settings = settings_with(
        environment="production", log_level="INFO", access_token_expire_minutes=15
    )
    assert settings.environment == "production"


def test_settings_are_cached() -> None:
    from app.core.config import get_settings

    assert get_settings() is get_settings()
