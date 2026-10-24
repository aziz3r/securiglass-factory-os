"""Fixtures & environnement de test SecuriGlass.

Les variables d'environnement sont posées AVANT tout import de `app.*` car
`app.core.config.get_settings()` est mis en cache (`lru_cache`).
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

# Résolution automatique du chemin vers services/backend-api et services/ot-edge-gateway
_repo_root = Path(__file__).resolve().parent.parent
_backend_dir = str(_repo_root / "services" / "backend-api")
_gateway_dir = str(_repo_root / "services" / "ot-edge-gateway")
if _backend_dir not in sys.path:
    sys.path.insert(0, _backend_dir)
if _gateway_dir not in sys.path:
    sys.path.insert(0, _gateway_dir)

# --- Configuration minimale et déterministe pour toute la suite -------------
_TEST_SECRET = "unit-test-secret-key-0123456789abcdef0123456789abcdef"
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("SECRET_KEY", _TEST_SECRET)
os.environ.setdefault("TDE_ENCRYPTION_KEY", "ab" * 32)
os.environ.setdefault(
    "DATABASE_URL",
    os.environ.get(
        "SECURIGLASS_TEST_DATABASE_URL",
        "postgresql://securiglass_admin:SecuriGlass_Admin_2026!MasterKey@localhost:5432/securiglass_db",
    ),
)
os.environ.setdefault("DB_MIN_CONNECTIONS", "1")
os.environ.setdefault("DB_MAX_CONNECTIONS", "5")

from app.core.config import Settings, get_settings  # noqa: E402


@pytest.fixture(scope="session")
def settings() -> Settings:
    return get_settings()


@pytest.fixture
def reset_settings_cache() -> Iterator[None]:
    """Permet à un test de recharger la configuration depuis l'environnement."""
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def make_settings_only() -> Settings:
    """Settings isolés, sans fichier .env, pour tester les validateurs."""
    return Settings(
        _env_file=None,
        database_url="postgresql://test:test@localhost:5432/test",
        secret_key=_TEST_SECRET,
        tde_encryption_key="cd" * 32,
    )


@pytest.fixture
def base_settings_kwargs() -> dict[str, str]:
    return {
        "database_url": "postgresql://test:test@localhost:5432/test",
        "secret_key": _TEST_SECRET,
        "tde_encryption_key": "cd" * 32,
    }


# --- Base de données réelle (tests d'intégration) ---------------------------
DATABASE_URL = os.environ["DATABASE_URL"]


async def _can_connect() -> bool:
    try:
        import asyncpg

        conn = await asyncpg.connect(DATABASE_URL, timeout=3)
    except Exception:  # noqa: BLE001 - sonde de disponibilité
        return False
    await conn.close()
    return True


_DB_STATUS: bool | None = None


@pytest.fixture(scope="session")
def db_available() -> bool:
    """Sonde synchrone : évite tout conflit de boucle avec pytest-asyncio."""
    global _DB_STATUS
    if _DB_STATUS is None:
        _DB_STATUS = asyncio.run(_can_connect())
    return _DB_STATUS


@pytest.fixture
async def db_conn(db_available: bool) -> AsyncIterator[object]:
    """Connexion asyncpg réelle ; skip explicite si PostgreSQL est absent."""
    if not db_available:
        pytest.skip("PostgreSQL indisponible (docker compose infra/docker)")
    import asyncpg

    conn = await asyncpg.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        await conn.close()


@pytest.fixture
def unique_suffix() -> str:
    return uuid.uuid4().hex[:12]
