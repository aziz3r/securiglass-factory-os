"""Fixtures d'intégration : base réelle, comptes QA, client ASGI FastAPI."""

from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Iterator

import asyncpg
import httpx
import pytest

from app.core.security import hash_password

DATABASE_URL = os.environ["DATABASE_URL"]

QA_PASSWORD = "Qa-SecuriGlass-Test-2026!"
QA_ACCOUNTS: dict[str, tuple[str, str, int]] = {
    # clé logique -> (username, rôle, clearance)
    "manager": ("qa_manager", "PLANT_MANAGER", 3),
    "operator": ("qa_operator", "OT_OPERATOR", 2),
    "auditor": ("qa_auditor", "SECURITY_AUDITOR", 4),
}


async def _reset_accounts() -> None:
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        for username, role_code, clearance in QA_ACCOUNTS.values():
            password_hash = hash_password(QA_PASSWORD)
            user_id = await conn.fetchval(
                """
                INSERT INTO sec_data.users (username, email, password_hash, salt, clearance_level)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (username) DO UPDATE SET
                    password_hash = EXCLUDED.password_hash,
                    salt = EXCLUDED.salt,
                    is_active = TRUE,
                    failed_login_attempts = 0,
                    locked_until = NULL,
                    clearance_level = EXCLUDED.clearance_level
                RETURNING id
                """,
                username,
                f"{username}@securiglass.local",
                password_hash,
                password_hash.split("$")[4],
                clearance,
            )
            await conn.execute(
                "DELETE FROM sec_data.user_roles WHERE user_id = $1", user_id
            )
            await conn.execute(
                """
                INSERT INTO sec_data.user_roles (user_id, role_id)
                SELECT $1, id FROM sec_data.roles WHERE role_code = $2
                """,
                user_id,
                role_code,
            )
    finally:
        await conn.close()


async def _drop_accounts() -> None:
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        await conn.execute("DELETE FROM sec_data.users WHERE username LIKE 'qa\\_%'")
    finally:
        await conn.close()


@pytest.fixture(scope="session")
def qa_accounts(db_available: bool) -> Iterator[dict[str, tuple[str, str, int]]]:
    """Comptes de test réels (créés une fois, supprimés en fin de session)."""
    if not db_available:
        pytest.skip("PostgreSQL indisponible")
    asyncio.run(_reset_accounts())
    yield QA_ACCOUNTS
    asyncio.run(_drop_accounts())


@pytest.fixture
async def api_client(db_available: bool) -> AsyncIterator[httpx.AsyncClient]:
    """Client HTTP ASGI branché sur l'application FastAPI réelle (pool PostgreSQL inclus)."""
    if not db_available:
        pytest.skip("PostgreSQL indisponible")
    from app.core import db as db_module
    from app.main import app

    await db_module.init_pool()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://securiglass.test"
    ) as client:
        yield client
    await db_module.close_pool()


async def login(
    client: httpx.AsyncClient, username: str, password: str = QA_PASSWORD
) -> httpx.Response:
    return await client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )


async def bearer(client: httpx.AsyncClient, username: str) -> dict[str, str]:
    response = await login(client, username)
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}
