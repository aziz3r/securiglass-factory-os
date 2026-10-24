#!/usr/bin/env python3
"""Jeu de données de démonstration (base de DÉVELOPPEMENT locale uniquement).

Crée via l'API (donc avec chiffrement TDE réel) un client, puis en base une recette
approuvée, une commande et un lot « IN_PROGRESS » : la console affiche alors l'épaisseur
du verre en cours de production. Idempotent. Prérequis : backend sur 127.0.0.1:8000,
comptes créés par `dev_seed_users.py` (fichier `.dev-credentials.json`).

    DATABASE_URL=postgresql://...@localhost/... services/backend-api/.venv/bin/python scripts/dev_seed_demo_data.py
"""

import asyncio
import json
import os
import sys
import urllib.request
from pathlib import Path

import asyncpg

API = os.environ.get("API_URL", "http://127.0.0.1:8000")
CREDS = Path(__file__).resolve().parent.parent / ".dev-credentials.json"


def call(
    method: str, path: str, body: dict | None = None, token: str | None = None
) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(API + path, method=method, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read() or b"null")


async def main() -> int:
    dsn = os.environ.get("DATABASE_URL", "")
    if not any(h in dsn for h in ("localhost", "127.0.0.1", "[::1]")):
        print("Refus : base locale (localhost) uniquement.", file=sys.stderr)
        return 2
    manager = json.loads(CREDS.read_text())["PLANT_MANAGER"]
    token = call(
        "POST",
        "/api/v1/auth/login",
        {"username": manager["username"], "password": manager["password"]},
    )["access_token"]

    conn = await asyncpg.connect(dsn)
    try:
        customer_id = await conn.fetchval(
            "SELECT id FROM it_data.customers WHERE company_name = 'Vitrages Atlantique SA'"
        )
        if customer_id is None:
            created = call(
                "POST",
                "/api/v1/customers",
                {
                    "company_name": "Vitrages Atlantique SA",
                    "contact_name": "Claire Martin",
                    "email": "claire.martin@vitrages-atlantique.example",
                    "phone": "+33 2 40 00 00 00",
                    "country_code": "FR",
                },
                token,
            )
            customer_id = created["id"]
        recipe_id = await conn.fetchval(
            "INSERT INTO it_data.recipes (recipe_code, name, glass_type, thickness_nominal_mm, target_furnace_temp_c,"
            " target_quench_pressure_bar, heating_duration_s, cooling_duration_s, is_approved, approved_at)"
            " VALUES ('RCP-FT-6MM','Float trempé 6 mm','FLOAT_TEMPERED',6.0,690.0,4.00,210,120,TRUE,now())"
            " ON CONFLICT (recipe_code) DO UPDATE SET name = EXCLUDED.name RETURNING id"
        )
        order_id = await conn.fetchval(
            "INSERT INTO it_data.glass_orders (order_ref, customer_id, recipe_id, width_mm, height_mm, quantity, status, target_delivery_date)"
            " VALUES ('CMD-DEMO-0001',$1,$2,1200,800,40,'IN_PRODUCTION', current_date + 7)"
            " ON CONFLICT (order_ref) DO UPDATE SET status = 'IN_PRODUCTION' RETURNING id",
            customer_id,
            recipe_id,
        )
        await conn.execute(
            "INSERT INTO it_data.production_batches (batch_code, order_id, line_code, planned_quantity, status, started_at)"
            " VALUES ('LOT-DEMO-0001',$1,'LINE-FOUR-01',40,'IN_PROGRESS', now())"
            " ON CONFLICT (batch_code) DO UPDATE SET status = 'IN_PROGRESS', started_at = now()",
            order_id,
        )
    finally:
        await conn.close()
    print(
        "Données de démonstration prêtes (client, recette 6 mm, commande, lot en cours)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
