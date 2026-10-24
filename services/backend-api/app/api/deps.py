"""Dépendances FastAPI : injection de connexion DB, authentification JWT, RBAC & ABAC."""

import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Any

import asyncpg
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.db import DbConn, get_conn
from app.core.security import verify_jwt_token
from app.services import audit_service

_bearer_security = HTTPBearer(auto_error=False)
Conn = Annotated[DbConn, Depends(get_conn)]


@dataclass(frozen=True)
class CurrentUser:
    """Représentation immuable de l'utilisateur authentifié en session de requête."""

    id: uuid.UUID
    username: str
    email: str
    roles: list[str]
    clearance_level: int
    jti: str
    token_exp: datetime


def client_ip(request: Request) -> str:
    """Extrait l'adresse IP source du client.

    Conformément aux directives IEC 62443, la priorité est accordée à l'IP de socket directe
    pour les contrôles d'accès critiques (ABAC).
    """
    if request.client and request.client.host:
        host = request.client.host
        if host == "testclient":
            return "127.0.0.1"
        return host
    return "127.0.0.1"


def client_cert_fingerprint(request: Request) -> str | None:
    """Extrait l'empreinte SHA-256 du certificat client mTLS si fourni."""
    return request.headers.get("X-SSL-Client-SHA256") or request.headers.get(
        "X-Client-Cert-Fingerprint"
    )


def _unauthorized_error(
    detail: str = "Invalid or expired credentials",
) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def authenticate_token(conn: DbConn, token: str) -> CurrentUser:
    """Valide un JWT (signature, expiration, révocation JTI, compte actif) -> utilisateur.

    Partagé par les routes HTTP (en-tête Bearer) et le canal WebSocket (premier message).
    """
    try:
        claims = verify_jwt_token(token)
    except (jwt.PyJWTError, ValueError) as exc:
        raise _unauthorized_error("Token JWT invalide ou expiré") from exc

    jti = str(claims["jti"])
    sub_user_id = str(claims["sub"])

    # Vérification de la liste de révocation (JTI Blocklist)
    is_revoked = await conn.fetchval(
        "SELECT 1 FROM sec_data.token_revocations WHERE jti = $1::uuid",
        jti,
    )
    if is_revoked:
        raise _unauthorized_error("Ce jeton a été révoqué")

    # Récupération de l'utilisateur
    user_row = await conn.fetchrow(
        """
        SELECT id, username, email, clearance_level, is_active, locked_until
        FROM sec_data.users
        WHERE id = $1::uuid
        """,
        sub_user_id,
    )

    now = datetime.now(timezone.utc)
    if user_row is None:
        raise _unauthorized_error("Utilisateur introuvable")

    if not user_row["is_active"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte utilisateur désactivé",
        )

    if user_row["locked_until"] is not None and user_row["locked_until"] > now:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte temporairement verrouillé pour sécurité",
        )

    # Récupération des rôles associés
    role_rows = await conn.fetch(
        """
        SELECT r.role_code
        FROM sec_data.user_roles ur
        JOIN sec_data.roles r ON r.id = ur.role_id
        WHERE ur.user_id = $1
        """,
        user_row["id"],
    )

    roles = [r["role_code"] for r in role_rows]
    exp_ts = int(claims.get("exp", now.timestamp()))

    return CurrentUser(
        id=user_row["id"],
        username=user_row["username"],
        email=user_row["email"],
        roles=roles,
        clearance_level=int(user_row["clearance_level"]),
        jti=jti,
        token_exp=datetime.fromtimestamp(exp_ts, tz=timezone.utc),
    )


async def get_current_user(
    request: Request,
    conn: Conn,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_security)],
) -> CurrentUser:
    """Authentifie la requête via JWT et contrôle la validité et révocation du JTI."""
    if creds is None:
        raise _unauthorized_error("Token d'authentification manquant")
    return await authenticate_token(conn, creds.credentials)


CurrentUserDep = Annotated[CurrentUser, Depends(get_current_user)]
get_current_active_user = get_current_user


def require_roles(
    *allowed_roles: str,
) -> Callable[[Request, Conn, CurrentUserDep], Coroutine[Any, Any, CurrentUser]]:
    """Garde RBAC stricte : requiert au moins un des rôles spécifiés.

    Enregistre automatiquement une violation dans le journal d'audit en cas de refus.
    """

    async def role_checker(
        request: Request, conn: Conn, user: CurrentUserDep
    ) -> CurrentUser:
        user_role_set = set(user.roles)
        required_role_set = set(allowed_roles)

        if not (user_role_set & required_role_set):
            await audit_service.record_event(
                conn,
                event_type="ACCESS_DENIED_RBAC",
                actor_id=str(user.id),
                actor_username=user.username,
                actor_ip=client_ip(request),
                action=request.method,
                resource=request.url.path,
                outcome="DENIED",
                details={
                    "user_roles": user.roles,
                    "required_roles": list(allowed_roles),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Privilèges insuffisants. Rôles requis : {', '.join(allowed_roles)}",
            )
        return user

    return role_checker


def require_clearance(
    min_clearance: int,
) -> Callable[[Request, Conn, CurrentUserDep], Coroutine[Any, Any, CurrentUser]]:
    """Garde basée sur le niveau d'accréditation de sécurité (Clearance Level)."""

    async def clearance_checker(
        request: Request, conn: Conn, user: CurrentUserDep
    ) -> CurrentUser:
        if user.clearance_level < min_clearance:
            await audit_service.record_event(
                conn,
                event_type="ACCESS_DENIED_CLEARANCE",
                actor_id=str(user.id),
                actor_username=user.username,
                actor_ip=client_ip(request),
                action=request.method,
                resource=request.url.path,
                outcome="DENIED",
                details={
                    "user_clearance": user.clearance_level,
                    "required_clearance": min_clearance,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Habilitation insuffisante (niveau {user.clearance_level} < requis {min_clearance})",
            )
        return user

    return clearance_checker
