"""Tests du pool de connexions et des contrats de repli (fail-closed)."""

from __future__ import annotations

import pytest

from app.core import db


async def test_get_conn_without_pool_raises_runtime_error() -> None:
    """Aucune connexion implicite : sans pool initialisé, l'accès est refusé."""
    await db.close_pool()
    generator = db.get_conn()
    with pytest.raises(RuntimeError, match="n'est pas initialisé"):
        await generator.__anext__()


async def test_close_pool_is_idempotent() -> None:
    await db.close_pool()
    await db.close_pool()


async def test_pool_lifecycle(db_available: bool) -> None:
    if not db_available:
        pytest.skip("PostgreSQL indisponible")
    await db.init_pool()
    try:
        generator = db.get_conn()
        conn = await generator.__anext__()
        assert await conn.fetchval("SELECT 1") == 1
        with pytest.raises(StopAsyncIteration):
            await generator.__anext__()
    finally:
        await db.close_pool()
