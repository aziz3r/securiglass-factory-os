"""Tests d'API du service IAM (FastAPI réel + PostgreSQL réel).

Couvre : authentification, verrouillage anti-bruteforce, révocation JTI, gardes
RBAC, chiffrement TDE des PII clients, accès au journal d'audit et en-têtes HTTP.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

import asyncpg
import httpx
import pytest

from .conftest import QA_PASSWORD, bearer, login

DATABASE_URL = os.environ["DATABASE_URL"]


# ---------------------------------------------------------------------------
# Surface HTTP & durcissement
# ---------------------------------------------------------------------------
async def test_health_exposes_service_identity(api_client: httpx.AsyncClient) -> None:
    response = await api_client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "UP"
    assert body["service"] == "securiglass-backend-api"


async def test_security_headers_are_strict(api_client: httpx.AsyncClient) -> None:
    response = await api_client.get("/health")
    headers = response.headers
    assert (
        headers["content-security-policy"]
        == "default-src 'none'; frame-ancestors 'none'"
    )
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cache-control"].startswith("no-store")
    assert "max-age=63072000" in headers["strict-transport-security"]


async def test_security_headers_are_also_set_on_errors(
    api_client: httpx.AsyncClient,
) -> None:
    response = await api_client.get("/api/v1/does-not-exist")
    assert response.status_code == 404
    assert response.headers["content-security-policy"].startswith("default-src 'none'")


async def test_validation_errors_are_sanitized(api_client: httpx.AsyncClient) -> None:
    response = await api_client.post("/api/v1/auth/login", json={"username": "x"})
    assert response.status_code == 422
    payload = response.json()
    assert payload["detail"] == "Échec de validation des données d'entrée"
    assert {e["field"] for e in payload["errors"]} >= {"body -> password"}


# ---------------------------------------------------------------------------
# Authentification
# ---------------------------------------------------------------------------
async def test_login_returns_bearer_token(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    response = await login(api_client, "qa_manager")
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 1800
    assert body["access_token"].count(".") == 2


async def test_login_wrong_password_is_401(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    response = await login(api_client, "qa_manager", "wrong-password")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


async def test_login_unknown_user_is_indistinguishable(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    response = await login(api_client, "ghost_user_does_not_exist")
    assert response.status_code == 401
    assert response.json()["detail"] == "Identifiants de connexion invalides"


async def test_me_requires_authentication(api_client: httpx.AsyncClient) -> None:
    response = await api_client.get("/api/v1/auth/me")
    assert response.status_code == 401


async def test_me_returns_roles_and_clearance(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    headers = await bearer(api_client, "qa_auditor")
    response = await api_client.get("/api/v1/auth/me", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "qa_auditor"
    assert body["roles"] == ["SECURITY_AUDITOR"]
    assert body["clearance_level"] == 4


async def test_logout_revokes_the_token_immediately(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    headers = await bearer(api_client, "qa_operator")
    assert (await api_client.get("/api/v1/auth/me", headers=headers)).status_code == 200

    logout = await api_client.post("/api/v1/auth/logout", headers=headers)
    assert logout.status_code == 204

    assert (await api_client.get("/api/v1/auth/me", headers=headers)).status_code == 401


async def test_forged_token_is_rejected(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    forged = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9."
    response = await api_client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {forged}"}
    )
    assert response.status_code == 401


async def test_bruteforce_lockout_after_max_failures(
    api_client: httpx.AsyncClient,
) -> None:
    username = f"qa_lockout_{uuid.uuid4().hex[:8]}"
    conn = await asyncpg.connect(DATABASE_URL)
    try:
        from app.core.security import hash_password

        password_hash = hash_password(QA_PASSWORD)
        await conn.execute(
            """
            INSERT INTO sec_data.users (username, email, password_hash, salt, clearance_level)
            VALUES ($1, $2, $3, $4, 2)
            """,
            username,
            f"{username}@securiglass.local",
            password_hash,
            password_hash.split("$")[4],
        )

        for _ in range(5):
            response = await login(api_client, username, "bad-password")
            assert response.status_code == 401

        locked = await login(api_client, username, QA_PASSWORD)
        assert locked.status_code == 423
        assert "verrouillé" in locked.json()["detail"]

        row = await conn.fetchrow(
            "SELECT failed_login_attempts, locked_until FROM sec_data.users WHERE username = $1",
            username,
        )
        assert row is not None
        assert row["locked_until"] is not None
    finally:
        await conn.execute("DELETE FROM sec_data.users WHERE username = $1", username)
        await conn.close()


# ---------------------------------------------------------------------------
# Clients & TDE (RGPD)
# ---------------------------------------------------------------------------
def _customer_payload() -> dict[str, str]:
    return {
        "company_name": f"Verrier QA {uuid.uuid4().hex[:6]}",
        "contact_name": "Béatrice Ünal",
        "email": "beatrice.unal@verrier-qa.example",
        "phone": "+32 2 555 01 02",
        "vat_number": f"BE{uuid.uuid4().hex[:10].upper()}",
        "country_code": "BE",
    }


async def test_plant_manager_can_create_customer_with_encrypted_pii(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    headers = await bearer(api_client, "qa_manager")
    payload = _customer_payload()
    response = await api_client.post("/api/v1/customers", json=payload, headers=headers)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["company_name"] == payload["company_name"]
    # Le déchiffrement à la volée restitue les PII en clair pour l'utilisateur habilité.
    assert body["email"] == payload["email"]
    assert body["contact_name"] == payload["contact_name"]

    conn = await asyncpg.connect(DATABASE_URL)
    try:
        row = await conn.fetchrow(
            "SELECT contact_name_encrypted, email_encrypted, phone_encrypted"
            " FROM it_data.customers WHERE id = $1::uuid",
            body["id"],
        )
        assert row is not None
        ciphertext = bytes(row["contact_name_encrypted"])
        assert payload["contact_name"].encode() not in ciphertext
        assert bytes(row["email_encrypted"]) != payload["email"].encode()
        assert bytes(row["phone_encrypted"]) != payload["phone"].encode()
    finally:
        await conn.execute(
            "DELETE FROM it_data.customers WHERE id = $1::uuid", body["id"]
        )
        await conn.close()


async def test_operator_cannot_create_customer(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    headers = await bearer(api_client, "qa_operator")
    response = await api_client.post(
        "/api/v1/customers", json=_customer_payload(), headers=headers
    )
    assert response.status_code == 403
    assert "PLANT_MANAGER" in response.json()["detail"]


async def test_operator_cannot_list_customers(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    headers = await bearer(api_client, "qa_operator")
    response = await api_client.get("/api/v1/customers", headers=headers)
    assert response.status_code == 403


async def test_auditor_can_list_customers_but_cannot_create(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    headers = await bearer(api_client, "qa_auditor")
    listing = await api_client.get("/api/v1/customers", headers=headers)
    assert listing.status_code == 200
    assert isinstance(listing.json(), list)

    creation = await api_client.post(
        "/api/v1/customers", json=_customer_payload(), headers=headers
    )
    assert creation.status_code == 403


# ---------------------------------------------------------------------------
# Journal d'audit
# ---------------------------------------------------------------------------
async def test_audit_logs_are_restricted_to_auditor_and_admin(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    auditor = await bearer(api_client, "qa_auditor")
    response = await api_client.get("/api/v1/audit/logs", headers=auditor)
    assert response.status_code == 200
    entries = response.json()
    assert isinstance(entries, list)
    if entries:
        assert len(entries[0]["current_hash"]) == 64

    manager = await bearer(api_client, "qa_manager")
    forbidden = await api_client.get("/api/v1/audit/logs", headers=manager)
    assert forbidden.status_code == 403


async def test_audit_chain_verification_endpoint(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    headers = await bearer(api_client, "qa_auditor")
    response = await api_client.get("/api/v1/audit/verify", headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["chain_valid"] is True
    assert body["first_broken_id"] is None
    assert body["total_records_checked"] >= 1


async def test_audit_logs_pagination_is_bounded(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    headers = await bearer(api_client, "qa_auditor")
    too_large = await api_client.get("/api/v1/audit/logs?limit=100000", headers=headers)
    assert too_large.status_code == 422


@pytest.mark.parametrize(
    "path", ["/api/v1/auth/me", "/api/v1/audit/logs", "/api/v1/customers"]
)
async def test_protected_routes_reject_anonymous(
    api_client: httpx.AsyncClient, path: str
) -> None:
    response = await api_client.get(path)
    assert response.status_code == 401


# ---------------------------------------------------------------------------
# Consultation unitaire d'un client & filtres d'audit
# ---------------------------------------------------------------------------
async def test_get_customer_by_id_and_unknown_id(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    manager = await bearer(api_client, "qa_manager")
    payload = _customer_payload()
    created = await api_client.post("/api/v1/customers", json=payload, headers=manager)
    assert created.status_code == 201
    customer_id = created.json()["id"]

    conn = await asyncpg.connect(DATABASE_URL)
    try:
        fetched = await api_client.get(
            f"/api/v1/customers/{customer_id}", headers=manager
        )
        assert fetched.status_code == 200
        assert fetched.json()["id"] == customer_id
        assert fetched.json()["email"] == payload["email"]

        unknown = await api_client.get(
            f"/api/v1/customers/{uuid.uuid4()}", headers=manager
        )
        assert unknown.status_code == 404

        malformed = await api_client.get(
            "/api/v1/customers/not-a-uuid", headers=manager
        )
        assert malformed.status_code == 422
    finally:
        await conn.execute(
            "DELETE FROM it_data.customers WHERE id = $1::uuid", customer_id
        )
        await conn.close()


async def test_audit_logs_can_be_filtered_by_event_type(
    api_client: httpx.AsyncClient, qa_accounts: dict[str, Any]
) -> None:
    headers = await bearer(api_client, "qa_auditor")
    response = await api_client.get(
        "/api/v1/audit/logs?event_type=AUTH_LOGIN&limit=10", headers=headers
    )
    assert response.status_code == 200
    entries = response.json()
    assert all(entry["event_type"] == "AUTH_LOGIN" for entry in entries)
    # Les `details` JSONB doivent être désérialisés en objet, pas en chaîne (D8).
    if entries:
        assert isinstance(entries[0]["details"], dict)
        assert entries[0]["prev_log_hash"] is None or isinstance(
            entries[0]["prev_log_hash"], str
        )
