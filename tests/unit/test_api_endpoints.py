"""Tests unitaires des endpoints FastAPI IAM & Métier (avec TestClient & dependency_overrides).

Couvre l'authentification (/login, /logout, /me), les clients avec TDE AES-256-GCM (/customers),
les pistes d'audit immuables (/audit/logs, /audit/verify), et les en-têtes de sécurité HTTP.
"""

import json
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.api.deps import CurrentUser, get_conn, get_current_user
from app.core.security import generate_jwt_token, hash_password
from app.main import app
from app.services.tde_service import get_tde_service

client = TestClient(app, raise_server_exceptions=True)


class DummyTransaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        return None


def _create_mock_conn(user_row=None, customer_row=None):
    mock = MagicMock()
    mock.transaction = MagicMock(side_effect=lambda: DummyTransaction())

    async def _fetchrow_dispatch(query, *args):
        if "sec_data.audit_logs" in query:
            return None
        if "sec_data.users" in query:
            return user_row
        if "it_data.customers" in query:
            return customer_row
        return None

    mock.fetchrow = AsyncMock(side_effect=_fetchrow_dispatch)
    mock.fetch = AsyncMock(return_value=[])
    mock.fetchval = AsyncMock(return_value=None)
    mock.execute = AsyncMock(return_value="INSERT 0 1")
    return mock


# ============================================================================
# 1. TESTS DE SANTÉ & MIDDLEWARE DE SÉCURITÉ
# ============================================================================


def test_healthcheck_endpoint() -> None:
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UP"
    assert data["service"] == "securiglass-backend-api"


def test_security_headers_present() -> None:
    """Vérifie la présence des en-têtes HTTP de sécurité stricts (HSTS, CSP, X-Frame-Options)."""
    response = client.get("/health")
    headers = response.headers
    assert "strict-transport-security" in headers
    assert "content-security-policy" in headers
    assert "x-frame-options" in headers
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"


# ============================================================================
# 2. TESTS AUTHENTIFICATION (/login, /logout, /me)
# ============================================================================


def test_auth_me_requires_token() -> None:
    mock_conn = _create_mock_conn()

    async def override_conn() -> AsyncIterator[MagicMock]:
        yield mock_conn

    app.dependency_overrides[get_conn] = override_conn
    try:
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 401
    finally:
        app.dependency_overrides.pop(get_conn, None)


def test_auth_me_returns_profile_for_valid_user() -> None:
    user_id = uuid.uuid4()
    mock_user = CurrentUser(
        id=user_id,
        username="supervisor_alpha",
        email="supervisor@securiglass.fr",
        roles=["PLANT_MANAGER"],
        clearance_level=3,
        jti=str(uuid.uuid4()),
        token_exp=datetime.now(timezone.utc),
    )

    app.dependency_overrides[get_current_user] = lambda: mock_user
    try:
        response = client.get("/api/v1/auth/me")
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "supervisor_alpha"
        assert data["roles"] == ["PLANT_MANAGER"]
        assert data["clearance_level"] == 3
    finally:
        app.dependency_overrides.pop(get_current_user, None)


def test_login_success() -> None:
    """Test nominal de connexion réussie avec génération de token JWT."""
    raw_pass = "Industrial_Secret_2026!"
    hashed = hash_password(raw_pass)
    user_id = uuid.uuid4()

    user_row = {
        "id": user_id,
        "username": "plant_manager_bob",
        "email": "bob@securiglass.fr",
        "password_hash": hashed,
        "clearance_level": 3,
        "is_active": True,
        "failed_login_attempts": 0,
        "locked_until": None,
    }
    mock_conn = _create_mock_conn(user_row=user_row)
    mock_conn.fetch.return_value = [{"role_code": "PLANT_MANAGER"}]

    async def override_conn():
        yield mock_conn

    app.dependency_overrides[get_conn] = override_conn
    try:
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "plant_manager_bob", "password": raw_pass},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["expires_in"] > 0
    finally:
        app.dependency_overrides.pop(get_conn, None)


def test_login_unknown_user_constant_time() -> None:
    """Vérifie le rejet avec 401 et protection anti-énumération pour un utilisateur inconnu."""
    mock_conn = _create_mock_conn(user_row=None)

    async def override_conn():
        yield mock_conn

    app.dependency_overrides[get_conn] = override_conn
    try:
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "non_existent_user", "password": "RandomPassword!"},
        )
        assert resp.status_code == 401
    finally:
        app.dependency_overrides.pop(get_conn, None)


def test_login_locked_account() -> None:
    """Vérifie le blocage HTTP 423 si le compte est actuellement verrouillé."""
    raw_pass = "AnyPassword"
    future_time = datetime.now(timezone.utc) + timedelta(minutes=10)
    user_row = {
        "id": uuid.uuid4(),
        "username": "locked_operator",
        "email": "locked@securiglass.fr",
        "password_hash": hash_password("ValidPassword!"),
        "clearance_level": 2,
        "is_active": True,
        "failed_login_attempts": 5,
        "locked_until": future_time,
    }
    mock_conn = _create_mock_conn(user_row=user_row)

    async def override_conn():
        yield mock_conn

    app.dependency_overrides[get_conn] = override_conn
    try:
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "locked_operator", "password": raw_pass},
        )
        assert resp.status_code == 423
        assert "verrouillé" in resp.json()["detail"]
    finally:
        app.dependency_overrides.pop(get_conn, None)


def test_login_invalid_password_increments_attempts() -> None:
    """Vérifie l'incrémentation des tentatives et le rejet 401 en cas de mauvais mot de passe."""
    user_row = {
        "id": uuid.uuid4(),
        "username": "op_test",
        "email": "op@securiglass.fr",
        "password_hash": hash_password("RealPassword123!"),
        "clearance_level": 2,
        "is_active": True,
        "failed_login_attempts": 2,
        "locked_until": None,
    }
    mock_conn = _create_mock_conn(user_row=user_row)

    async def override_conn():
        yield mock_conn

    app.dependency_overrides[get_conn] = override_conn
    try:
        resp = client.post(
            "/api/v1/auth/login",
            json={"username": "op_test", "password": "WrongPassword!"},
        )
        assert resp.status_code == 401
        assert mock_conn.execute.called
    finally:
        app.dependency_overrides.pop(get_conn, None)


def test_logout_revokes_token() -> None:
    """Test de révocation de jeton JTI lors du logout (HTTP 204 No Content)."""
    mock_conn = _create_mock_conn()
    user_id = uuid.uuid4()
    mock_user = CurrentUser(
        id=user_id,
        username="user_logout",
        email="logout@securiglass.fr",
        roles=["OT_OPERATOR"],
        clearance_level=2,
        jti=str(uuid.uuid4()),
        token_exp=datetime.now(timezone.utc) + timedelta(hours=1),
    )

    app.dependency_overrides[get_current_user] = lambda: mock_user

    async def override_conn():
        yield mock_conn

    app.dependency_overrides[get_conn] = override_conn
    try:
        resp = client.post("/api/v1/auth/logout")
        assert resp.status_code == 204
        assert mock_conn.execute.called
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_conn, None)


# ============================================================================
# 3. TESTS CLIENTS B2B AVEC TDE AES-256-GCM (/customers)
# ============================================================================


def test_customer_creation_forbidden_for_security_auditor() -> None:
    mock_auditor = CurrentUser(
        id=uuid.uuid4(),
        username="sec_auditor_01",
        email="auditor@securiglass.fr",
        roles=["SECURITY_AUDITOR"],
        clearance_level=4,
        jti=str(uuid.uuid4()),
        token_exp=datetime.now(timezone.utc),
    )
    mock_conn = _create_mock_conn()

    async def override_conn() -> AsyncIterator[MagicMock]:
        yield mock_conn

    app.dependency_overrides[get_current_user] = lambda: mock_auditor
    app.dependency_overrides[get_conn] = override_conn
    try:
        payload = {
            "company_name": "Saint-Gobain",
            "contact_name": "Jean Dupont",
            "email": "j.dupont@saint-gobain.fr",
            "phone": "+33 1 23 45 67 89",
            "country_code": "FR",
        }
        response = client.post("/api/v1/customers", json=payload)
        assert response.status_code == 403
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_conn, None)


def test_create_customer_success_with_tde() -> None:
    """Test nominal de création client avec chiffrement TDE sous le rôle PLANT_MANAGER."""
    mock_manager = CurrentUser(
        id=uuid.uuid4(),
        username="plant_mgr_claire",
        email="claire@securiglass.fr",
        roles=["PLANT_MANAGER"],
        clearance_level=3,
        jti=str(uuid.uuid4()),
        token_exp=datetime.now(timezone.utc),
    )
    customer_id = uuid.uuid4()
    cust_row = {
        "id": customer_id,
        "company_name": "Automotive Glass Partners",
        "vat_number": "FR12345678901",
        "country_code": "FR",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
    }
    mock_conn = _create_mock_conn(customer_row=cust_row)

    app.dependency_overrides[get_current_user] = lambda: mock_manager

    async def override_conn():
        yield mock_conn

    app.dependency_overrides[get_conn] = override_conn
    try:
        payload = {
            "company_name": "Automotive Glass Partners",
            "contact_name": "Marc Lemoine",
            "email": "m.lemoine@autoglass.fr",
            "phone": "+33 6 12 34 56 78",
            "country_code": "FR",
        }
        resp = client.post("/api/v1/customers", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["id"] == str(customer_id)
        assert data["contact_name"] == "Marc Lemoine"
        assert data["email"] == "m.lemoine@autoglass.fr"
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_conn, None)


def test_get_customers_success_with_tde_decryption() -> None:
    """Test de listage de clients avec déchiffrement TDE transparent."""
    tde = get_tde_service()
    enc_pii = tde.encrypt_customer_pii("Alice V", "alice@glass.com", "+33699887766")
    cust_id = uuid.uuid4()

    mock_reader = CurrentUser(
        id=uuid.uuid4(),
        username="auditor_guy",
        email="guy@securiglass.fr",
        roles=["SECURITY_AUDITOR"],
        clearance_level=4,
        jti=str(uuid.uuid4()),
        token_exp=datetime.now(timezone.utc),
    )
    mock_conn = _create_mock_conn()
    mock_conn.fetch.return_value = [
        {
            "id": cust_id,
            "company_name": "Saint-Gobain Vitrage",
            "contact_name_encrypted": enc_pii.contact_name_encrypted,
            "email_encrypted": enc_pii.email_encrypted,
            "phone_encrypted": enc_pii.phone_encrypted,
            "vat_number": "FR999",
            "country_code": "FR",
            "is_active": True,
            "created_at": datetime.now(timezone.utc),
        }
    ]

    app.dependency_overrides[get_current_user] = lambda: mock_reader

    async def override_conn():
        yield mock_conn

    app.dependency_overrides[get_conn] = override_conn
    try:
        resp = client.get("/api/v1/customers")
        assert resp.status_code == 200
        items = resp.json()
        assert len(items) == 1
        assert items[0]["contact_name"] == "Alice V"
        assert items[0]["email"] == "alice@glass.com"
        assert items[0]["phone"] == "+33699887766"
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_conn, None)


def test_get_customer_by_id_found_and_not_found() -> None:
    """Test de récupération d'un client par ID (succès et 404)."""
    tde = get_tde_service()
    enc_pii = tde.encrypt_customer_pii("Bob V", "bob@glass.com", None)
    cust_id = uuid.uuid4()

    mock_mgr = CurrentUser(
        id=uuid.uuid4(),
        username="mgr_luc",
        email="luc@securiglass.fr",
        roles=["PLANT_MANAGER"],
        clearance_level=3,
        jti=str(uuid.uuid4()),
        token_exp=datetime.now(timezone.utc),
    )

    cust_row = {
        "id": cust_id,
        "company_name": "Vitrage Industriel",
        "contact_name_encrypted": enc_pii.contact_name_encrypted,
        "email_encrypted": enc_pii.email_encrypted,
        "phone_encrypted": None,
        "vat_number": "FR888",
        "country_code": "FR",
        "is_active": True,
        "created_at": datetime.now(timezone.utc),
    }
    mock_conn = _create_mock_conn(customer_row=cust_row)

    app.dependency_overrides[get_current_user] = lambda: mock_mgr

    async def override_conn():
        yield mock_conn

    app.dependency_overrides[get_conn] = override_conn
    try:
        # 1. Cas trouvé
        resp = client.get(f"/api/v1/customers/{cust_id}")
        assert resp.status_code == 200
        assert resp.json()["contact_name"] == "Bob V"

        # 2. Cas 404 Not Found
        mock_conn_404 = _create_mock_conn(customer_row=None)

        async def override_conn_404():
            yield mock_conn_404

        app.dependency_overrides[get_conn] = override_conn_404

        resp_404 = client.get(f"/api/v1/customers/{uuid.uuid4()}")
        assert resp_404.status_code == 404
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_conn, None)


# ============================================================================
# 4. TESTS PISTES D'AUDIT (/audit/logs, /audit/verify)
# ============================================================================


def test_audit_logs_forbidden_for_ot_operator() -> None:
    mock_operator = CurrentUser(
        id=uuid.uuid4(),
        username="operator_line1",
        email="operator@securiglass.fr",
        roles=["OT_OPERATOR"],
        clearance_level=2,
        jti=str(uuid.uuid4()),
        token_exp=datetime.now(timezone.utc),
    )
    mock_conn = _create_mock_conn()

    async def override_conn() -> AsyncIterator[MagicMock]:
        yield mock_conn

    app.dependency_overrides[get_current_user] = lambda: mock_operator
    app.dependency_overrides[get_conn] = override_conn
    try:
        response = client.get("/api/v1/audit/logs")
        assert response.status_code == 403
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_conn, None)


def test_audit_logs_success_for_super_admin() -> None:
    """Test de consultation des pistes d'audit pour SUPER_ADMIN."""
    mock_admin = CurrentUser(
        id=uuid.uuid4(),
        username="admin_sec",
        email="admin@securiglass.fr",
        roles=["SUPER_ADMIN"],
        clearance_level=5,
        jti=str(uuid.uuid4()),
        token_exp=datetime.now(timezone.utc),
    )
    log_id = uuid.uuid4()
    mock_conn = _create_mock_conn()
    mock_conn.fetch.return_value = [
        {
            "id": log_id,
            "event_time": datetime.now(timezone.utc),
            "event_type": "AUTH_LOGIN",
            "actor_username": "operator1",
            "actor_ip": "10.10.20.10",
            "action": "LOGIN",
            "resource": "/api/v1/auth/login",
            "outcome": "SUCCESS",
            "details": json.dumps({"agent": "SCADA"}),
            "prev_log_hash": None,
            "current_hash": "a" * 64,
        }
    ]

    app.dependency_overrides[get_current_user] = lambda: mock_admin

    async def override_conn():
        yield mock_conn

    app.dependency_overrides[get_conn] = override_conn
    try:
        resp = client.get("/api/v1/audit/logs?limit=50&offset=0")
        assert resp.status_code == 200
        logs = resp.json()
        assert len(logs) == 1
        assert logs[0]["actor_username"] == "operator1"
        assert logs[0]["current_hash"] == "a" * 64

        # Test avec filtre event_type
        resp_filtered = client.get("/api/v1/audit/logs?event_type=AUTH_LOGIN")
        assert resp_filtered.status_code == 200
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_conn, None)


def test_audit_verify_valid_and_broken_chain() -> None:
    """Test de vérification de l'intégrité globale de la chaîne d'audit."""
    mock_auditor = CurrentUser(
        id=uuid.uuid4(),
        username="auditor_ext",
        email="auditor@securiglass.fr",
        roles=["SECURITY_AUDITOR"],
        clearance_level=4,
        jti=str(uuid.uuid4()),
        token_exp=datetime.now(timezone.utc),
    )
    mock_conn = _create_mock_conn()

    app.dependency_overrides[get_current_user] = lambda: mock_auditor

    async def override_conn():
        yield mock_conn

    app.dependency_overrides[get_conn] = override_conn
    try:
        # 1. Cas intact : verify_stored_chain retourne (True, None)
        with patch(
            "app.services.audit_service.verify_stored_chain",
            AsyncMock(return_value=(True, None)),
        ):
            mock_conn.fetchval.return_value = 42
            resp = client.get("/api/v1/audit/verify")
            assert resp.status_code == 200
            data = resp.json()
            assert data["chain_valid"] is True
            assert data["total_records_checked"] == 42
            assert data["first_broken_id"] is None

        # 2. Cas altéré : verify_stored_chain retourne (False, broken_uuid_str)
        broken_uuid = uuid.uuid4()
        with patch(
            "app.services.audit_service.verify_stored_chain",
            AsyncMock(return_value=(False, str(broken_uuid))),
        ):
            mock_conn.fetchval.return_value = 42
            resp = client.get("/api/v1/audit/verify")
            assert resp.status_code == 200
            data = resp.json()
            assert data["chain_valid"] is False
            assert data["first_broken_id"] == str(broken_uuid)
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_conn, None)
