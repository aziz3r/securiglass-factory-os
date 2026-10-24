#!/usr/bin/env python3
"""Crée un compte de démonstration par rôle dans une base de DÉVELOPPEMENT locale.

Usage (base migrée, ex. `alembic upgrade head`) :
    DATABASE_URL=postgresql://... services/backend-api/.venv/bin/python scripts/dev_seed_users.py

Les mots de passe sont aléatoires et écrits UNIQUEMENT dans `.dev-credentials.json`
(droits 0600, ignoré par git). Un compte déjà présent n'est pas modifié : son mot de
passe n'est donc pas réécrit. Ne jamais lancer ce script sur une base de production.
"""

import asyncio
import json
import os
import secrets
import sys
from pathlib import Path

import asyncpg
from argon2 import PasswordHasher, Type

ROLES = (
    "SUPER_ADMIN",
    "SECURITY_AUDITOR",
    "PLANT_MANAGER",
    "OT_OPERATOR",
    "QUALITY_INSPECTOR",
    "SERVICE_ACCOUNT_EDGE",
)
OUT = Path(__file__).resolve().parent.parent / ".dev-credentials.json"
HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


async def main() -> int:
    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL requis", file=sys.stderr)
        return 2
    if not any(h in dsn for h in ("localhost", "127.0.0.1", "[::1]")):
        print(
            "Refus : ce script n'écrit que sur une base locale (localhost).",
            file=sys.stderr,
        )
        return 2

    conn = await asyncpg.connect(dsn)
    created: dict[str, dict[str, str]] = {}
    known = json.loads(OUT.read_text()) if OUT.exists() else {}
    try:
        async with conn.transaction():
            for role in ROLES:
                username = f"demo_{role.lower()}"
                row = await conn.fetchrow(
                    "SELECT id, default_clearance FROM sec_data.roles WHERE role_code = $1",
                    role,
                )
                if row is None:
                    print(
                        f"rôle {role} absent : migrations non appliquées ?",
                        file=sys.stderr,
                    )
                    return 1
                exists = await conn.fetchval(
                    "SELECT id FROM sec_data.users WHERE username = $1", username
                )
                if exists and role in known:
                    print(f"{username} existe déjà : conservé tel quel")
                    continue
                password = secrets.token_urlsafe(18)
                phc = HASHER.hash(password)
                if (
                    exists
                ):  # compte présent mais mot de passe perdu : rotation (base de développement)
                    await conn.execute(
                        "UPDATE sec_data.users SET password_hash = $2, salt = $3, failed_login_attempts = 0,"
                        " locked_until = NULL, updated_at = now() WHERE id = $1",
                        exists,
                        phc,
                        phc.split("$")[4],
                    )
                    created[role] = {"username": username, "password": password}
                    print(
                        f"{username} : mot de passe régénéré (absent du fichier d'identifiants)"
                    )
                    continue
                user_id = await conn.fetchval(
                    "INSERT INTO sec_data.users (username, email, password_hash, salt, clearance_level)"
                    " VALUES ($1, $2, $3, $4, $5) RETURNING id",
                    username,
                    f"{username}@securiglass.local",
                    phc,
                    phc.split("$")[4],
                    row["default_clearance"],
                )
                await conn.execute(
                    "INSERT INTO sec_data.user_roles (user_id, role_id) VALUES ($1, $2)",
                    user_id,
                    row["id"],
                )
                created[role] = {"username": username, "password": password}
    finally:
        await conn.close()

    if created:
        existing = json.loads(OUT.read_text()) if OUT.exists() else {}
        existing.update(created)
        fd = os.open(OUT, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(existing, fh, indent=2, ensure_ascii=False)
        print(
            f"{len(created)} compte(s) créé(s). Identifiants dans {OUT.name} (0600, hors git)."
        )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
