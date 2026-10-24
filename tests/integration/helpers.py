"""Helpers des tests d'intégration PostgreSQL (aucun effet de bord persistant)."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import asyncpg


class RollbackSentinel(Exception):
    """Sortie de bloc `transaction()` annulant systématiquement les écritures."""


async def denied(conn: asyncpg.Connection, sql: str, *args: Any) -> bool:
    """Exécute `sql` dans un point de sauvegarde ; vrai si refusé pour privilèges."""
    try:
        async with conn.transaction():
            await conn.execute(sql, *args)
    except asyncpg.exceptions.InsufficientPrivilegeError:
        return True
    return False


@asynccontextmanager
async def scoped_role(conn: asyncpg.Connection, role: str) -> AsyncIterator[None]:
    """Exécute le bloc sous `role` dans une transaction annulée à la sortie."""
    try:
        async with conn.transaction():
            await conn.execute(f"SET LOCAL ROLE {role}")
            yield
            raise RollbackSentinel
    except RollbackSentinel:
        return
