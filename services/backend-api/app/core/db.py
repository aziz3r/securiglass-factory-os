"""Gestionnaire du pool de connexions asynchrones PostgreSQL (asyncpg)."""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING, Any

import asyncpg

from app.core.config import get_settings

logger = logging.getLogger("securiglass.db")

if TYPE_CHECKING:
    DbConn = asyncpg.Connection[asyncpg.Record]
else:  # asyncpg.Connection n'est pas subscriptable à l'exécution
    DbConn = asyncpg.Connection

_pool: "asyncpg.Pool[asyncpg.Record] | None" = None


async def init_pool() -> None:
    """Initialise le pool de connexions vers la base PostgreSQL durcie."""
    global _pool
    settings = get_settings()
    dsn = settings.database_url.get_secret_value()
    try:
        _pool = await asyncpg.create_pool(
            dsn,
            min_size=settings.db_min_connections,
            max_size=settings.db_max_connections,
        )
        logger.info(
            "Pool PostgreSQL initialisé avec succès (min=%d, max=%d)",
            settings.db_min_connections,
            settings.db_max_connections,
        )
    except Exception as exc:
        logger.warning(
            "Connexion immédiate à PostgreSQL échouée (%s). Le pool reste non initialisé.",
            exc,
        )
        _pool = None


async def close_pool() -> None:
    """Ferme proprement toutes les connexions du pool lors de l'arrêt du service."""
    global _pool
    if _pool is not None:
        await _pool.close()
        _pool = None
        logger.info("Pool PostgreSQL fermé proprement.")


async def get_conn() -> AsyncIterator[DbConn]:
    """Dépendance FastAPI fournissant une connexion active issue du pool."""
    if _pool is None:
        raise RuntimeError(
            "Le pool de connexions de la base de données n'est pas initialisé ou la base est inaccessible."
        )
    async with _pool.acquire() as conn:
        yield conn  # type: ignore[misc]


@asynccontextmanager
async def acquire_conn() -> AsyncIterator[DbConn]:
    """Connexion courte hors dépendance FastAPI (ex. boucle WebSocket : une connexion par lecture)."""
    if _pool is None:
        raise RuntimeError(
            "Le pool de connexions de la base de données n'est pas initialisé."
        )
    async with _pool.acquire() as conn:
        yield conn  # type: ignore[misc]
