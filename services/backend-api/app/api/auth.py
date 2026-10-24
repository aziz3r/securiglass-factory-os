"""Endpoints d'authentification et de gestion de session (OWASP ASVS & IEC 62443).

Comprend :
- Protection anti-bruteforce (verrouillage temporaire après 5 échecs).
- Égalisation temporelle contre l'énumération de comptes.
- Révocation immédiate de session (JTI blocklist) lors de la déconnexion.
- Consultation de profil avec niveau d'accréditation (Clearance).
"""

from datetime import datetime, timedelta, timezone
from functools import lru_cache

from fastapi import APIRouter, HTTPException, Request, status

from app.api.deps import Conn, CurrentUserDep, client_ip
from app.core.config import get_settings
from app.core.security import generate_jwt_token, hash_password, verify_password
from app.models.schemas import LoginRequest, MeResponse, TokenResponse
from app.services import audit_service

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@lru_cache(maxsize=1)
def _get_dummy_argon2_hash() -> str:
    """Empreinte factice précalculée pour égaliser le temps de réponse (anti-timing attacks)."""
    return hash_password("SecuriGlass_Dummy_Timing_Equalizer_2026!")


def _credentials_exception(
    detail: str = "Identifiants de connexion invalides",
) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Authentification opérateur ou superviseur",
)
async def login(
    body: LoginRequest,
    request: Request,
    conn: Conn,
) -> TokenResponse:
    """Authentifie un utilisateur avec contrôle anti-bruteforce et émet un jeton JWT."""
    settings = get_settings()
    ip = client_ip(request)
    now = datetime.now(timezone.utc)

    user = await conn.fetchrow(
        """
        SELECT id, username, email, password_hash, clearance_level, is_active,
               failed_login_attempts, locked_until
        FROM sec_data.users
        WHERE username = $1
        """,
        body.username,
    )

    # 1. Protection contre l'énumération si l'utilisateur n'existe pas
    if user is None:
        verify_password(body.password, _get_dummy_argon2_hash())
        await audit_service.record_event(
            conn,
            event_type="AUTH_LOGIN",
            actor_username=body.username,
            actor_ip=ip,
            action="LOGIN",
            resource="/api/v1/auth/login",
            outcome="FAILURE",
            details={"reason": "unknown_user"},
        )
        raise _credentials_exception()

    user_id_str = str(user["id"])

    # 2. Vérification du verrouillage actif pour bruteforce
    if user["locked_until"] is not None:
        locked_until_dt: datetime = user["locked_until"]
        if locked_until_dt > now:
            remaining_seconds = int((locked_until_dt - now).total_seconds())
            await audit_service.record_event(
                conn,
                event_type="AUTH_LOGIN",
                actor_id=user_id_str,
                actor_username=body.username,
                actor_ip=ip,
                action="LOGIN",
                resource="/api/v1/auth/login",
                outcome="DENIED",
                details={
                    "reason": "account_locked",
                    "remaining_seconds": remaining_seconds,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Compte temporairement verrouillé pour sécurité. Réessayez dans {remaining_seconds} secondes.",
            )

    # 3. Validation du mot de passe et de l'état actif
    is_valid_password = verify_password(body.password, user["password_hash"])
    is_active = user["is_active"]

    if not is_valid_password or not is_active:
        current_fails = user["failed_login_attempts"] + 1
        is_now_locked = current_fails >= settings.max_failed_logins
        new_locked_until = (
            now + timedelta(minutes=settings.lockout_minutes) if is_now_locked else None
        )

        await conn.execute(
            """
            UPDATE sec_data.users
            SET failed_login_attempts = $2,
                locked_until = $3,
                updated_at = now()
            WHERE id = $1
            """,
            user["id"],
            0 if is_now_locked else current_fails,
            new_locked_until,
        )

        await audit_service.record_event(
            conn,
            event_type="AUTH_LOGIN",
            actor_id=user_id_str,
            actor_username=body.username,
            actor_ip=ip,
            action="LOGIN",
            resource="/api/v1/auth/login",
            outcome="FAILURE",
            details={
                "reason": (
                    "account_locked_max_failures"
                    if is_now_locked
                    else "invalid_password"
                ),
                "attempt_count": current_fails,
                "locked": is_now_locked,
            },
        )
        raise _credentials_exception()

    # 4. Succès : réinitialisation du compteur d'échecs
    await conn.execute(
        """
        UPDATE sec_data.users
        SET failed_login_attempts = 0,
            locked_until = NULL,
            updated_at = now()
        WHERE id = $1
        """,
        user["id"],
    )

    # Récupération des rôles
    role_rows = await conn.fetch(
        """
        SELECT r.role_code
        FROM sec_data.user_roles ur
        JOIN sec_data.roles r ON r.id = ur.role_id
        WHERE ur.user_id = $1
        """,
        user["id"],
    )
    user_roles = [r["role_code"] for r in role_rows]

    # Génération du jeton JWT avec claims stricts
    token_claims = {
        "sub": user_id_str,
        "username": user["username"],
        "roles": user_roles,
        "clearance_level": user["clearance_level"],
    }
    access_token = generate_jwt_token(token_claims)

    await audit_service.record_event(
        conn,
        event_type="AUTH_LOGIN",
        actor_id=user_id_str,
        actor_username=body.username,
        actor_ip=ip,
        action="LOGIN",
        resource="/api/v1/auth/login",
        outcome="SUCCESS",
        details={"roles": user_roles, "clearance": user["clearance_level"]},
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",  # nosec: B106
        expires_in=settings.access_token_expire_minutes * 60,
    )


@router.post(
    "/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Déconnexion et révocation immédiate du jeton JWT (JTI)",
)
async def logout(
    request: Request,
    conn: Conn,
    current_user: CurrentUserDep,
) -> None:
    """Révoque le jeton courant en inscrivant son JTI dans la table sec_data.token_revocations."""
    await conn.execute(
        """
        INSERT INTO sec_data.token_revocations (jti, user_id, expires_at, reason)
        VALUES ($1::uuid, $2, $3, 'user_logout')
        ON CONFLICT (jti) DO NOTHING
        """,
        current_user.jti,
        current_user.id,
        current_user.token_exp,
    )

    await audit_service.record_event(
        conn,
        event_type="AUTH_LOGOUT",
        actor_id=str(current_user.id),
        actor_username=current_user.username,
        actor_ip=client_ip(request),
        action="LOGOUT",
        resource="/api/v1/auth/logout",
        outcome="SUCCESS",
        details={"jti": current_user.jti},
    )


@router.get(
    "/me",
    response_model=MeResponse,
    status_code=status.HTTP_200_OK,
    summary="Profil de l'utilisateur connecté",
)
async def get_my_profile(
    current_user: CurrentUserDep,
) -> MeResponse:
    """Retourne les attributs d'identité, rôles et niveau de clearance du compte connecté."""
    return MeResponse(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        roles=current_user.roles,
        clearance_level=current_user.clearance_level,
    )
