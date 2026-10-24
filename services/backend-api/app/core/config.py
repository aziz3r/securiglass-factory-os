"""Configuration stricte via Pydantic v2 BaseSettings.

Aucun secret n'a de valeur par défaut : l'application refuse de démarrer sans
`DATABASE_URL`, `SECRET_KEY` et `TDE_ENCRYPTION_KEY` (fail-fast, OWASP ASVS V14.1).
"""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_PLACEHOLDER_PREFIXES = ("replace_with", "change_me", "changeme", "your_", "example")
_MIN_SECRET_LEN = 32


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    environment: Literal["development", "test", "staging", "production"] = "development"
    log_level: str = "INFO"

    # --- Base de données (obligatoire) -------------------------------------
    database_url: SecretStr
    db_min_connections: int = Field(default=5, ge=1)
    db_max_connections: int = Field(default=20, ge=1)

    # --- Cryptographie & JWT (obligatoires) --------------------------------
    secret_key: SecretStr
    tde_encryption_key: SecretStr
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = Field(default=30, ge=1, le=60)
    refresh_token_expire_days: int = Field(default=7, ge=1, le=90)
    jwt_issuer: str = "https://iam.securiglass.local"
    jwt_audience: str = "securiglass-factory-os"

    # --- Argon2id RFC 9106 --------------------------------------------------
    argon2_time_cost: int = Field(default=3, ge=3, description="Nombre de passes (t)")
    argon2_memory_cost: int = Field(
        default=65536, ge=65536, description="Mémoire en KiB (64 MiB)"
    )
    argon2_parallelism: int = Field(
        default=4, ge=1, description="Parallélisme / threads (p)"
    )
    argon2_salt_length: int = Field(
        default=16, ge=16, description="Longueur du sel en octets"
    )

    # --- Anti-bruteforce ----------------------------------------------------
    max_failed_logins: int = Field(default=5, ge=1)
    lockout_minutes: int = Field(default=15, ge=1)

    # --- Réseaux OT (IEC 62443 / Purdue 1-3) --------------------------------
    ot_control_room_cidr: str = "10.10.20.0/24"
    ot_gateway_cidr: str = "10.10.30.0/24"

    @field_validator("jwt_algorithm")
    @classmethod
    def _symmetric_only(cls, value: str) -> str:
        # Algorithme épinglé : interdit 'none' et la confusion d'algorithme.
        if value not in {"HS256", "HS384", "HS512"}:
            raise ValueError("jwt_algorithm must be HS256, HS384, or HS512")
        return value

    @field_validator("secret_key")
    @classmethod
    def _validate_secret_key(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if len(raw) < _MIN_SECRET_LEN:
            raise ValueError(
                f"secret_key must be at least {_MIN_SECRET_LEN} characters"
            )
        if raw.lower().startswith(_PLACEHOLDER_PREFIXES):
            raise ValueError("secret_key must not be a placeholder value")
        return value

    @field_validator("tde_encryption_key")
    @classmethod
    def _valid_tde_key(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise ValueError("tde_encryption_key must be hexadecimal") from exc
        if len(key) != 32:
            raise ValueError(
                "tde_encryption_key must be 256 bits (64 hexadecimal characters)"
            )
        return value

    @field_validator("database_url")
    @classmethod
    def _postgres_only(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value()
        if not raw.startswith(("postgresql://", "postgres://")):
            raise ValueError("database_url must be a PostgreSQL DSN")
        return value

    @model_validator(mode="after")
    def _coherent_pool(self) -> "Settings":
        if self.db_min_connections > self.db_max_connections:
            raise ValueError("db_min_connections must be <= db_max_connections")
        return self

    @model_validator(mode="after")
    def _harden_production(self) -> "Settings":
        if self.environment in {"staging", "production"}:
            if self.log_level.upper() == "DEBUG":
                raise ValueError("DEBUG logging is forbidden outside development")
            if self.access_token_expire_minutes > 30:
                raise ValueError(
                    "access token TTL must be <= 30 minutes in staging/production"
                )
        return self

    @property
    def tde_key_bytes(self) -> bytes:
        """Retourne la clé TDE décodée sous forme de 32 octets bruts pour AES-256-GCM."""
        return bytes.fromhex(self.tde_encryption_key.get_secret_value())


@lru_cache
def get_settings() -> Settings:
    """Retourne l'instance unique de configuration mise en cache."""
    return Settings()
