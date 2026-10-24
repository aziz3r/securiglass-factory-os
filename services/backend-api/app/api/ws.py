"""Canal WebSocket de télémétrie temps réel : /ws/telemetry.

Protocole (client : services/frontend-ui/src/realtime/telemetrySocket.ts) :
  1. le client ouvre la connexion ;
  2. PREMIER message : {"type": "auth", "token": "<JWT>"} dans un délai de 5 s
     (le jeton ne transite jamais dans l'URL) ;
  3. serveur : {"type": "auth_ok"} ou {"type": "auth_error"} puis fermeture 1008 ;
  4. client : {"type": "subscribe", "channels": ["telemetry"]} ;
  5. serveur : une trame {"type": "telemetry", "payload": {...}} à chaque nouvelle mesure
     écrite par la Data Diode dans ot_data.furnace_telemetry.

Contrôles : rôle (RBAC de la matrice : lecture télémétrie), taille et forme des messages,
nombre de connexions simultanées plafonné, révocation du jeton revérifiée périodiquement.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Any, Final

from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

from app.api.deps import CurrentUser, authenticate_token
from app.core import db
from app.services.telemetry_view import SELECT_LATEST, diagnose, to_payload

logger = logging.getLogger("securiglass.ws")
router = APIRouter()

READ_ROLES: Final = frozenset(
    {
        "SUPER_ADMIN",
        "PLANT_MANAGER",
        "OT_OPERATOR",
        "QUALITY_INSPECTOR",
    }
)
AUTH_TIMEOUT_S: Final = 5.0
SUBSCRIBE_TIMEOUT_S: Final = 10.0
POLL_INTERVAL_S: Final = 1.0
REVALIDATE_EVERY_S: Final = 30.0
MAX_MESSAGE_BYTES: Final = 4096
MAX_CONNECTIONS: Final = 50

CLOSE_POLICY: Final = 1008
_active = 0


async def _recv_json(ws: WebSocket, timeout: float) -> dict[str, Any] | None:
    try:
        raw = await asyncio.wait_for(ws.receive_text(), timeout)
    except (asyncio.TimeoutError, WebSocketDisconnect):
        return None
    if len(raw) > MAX_MESSAGE_BYTES:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


async def _authenticate(ws: WebSocket) -> CurrentUser | None:
    message = await _recv_json(ws, AUTH_TIMEOUT_S)
    token = message.get("token") if message and message.get("type") == "auth" else None
    if not isinstance(token, str) or not 0 < len(token) <= 2048:
        return None
    try:
        async with db.acquire_conn() as conn:
            user = await authenticate_token(conn, token)
    except HTTPException:
        return None
    return user if READ_ROLES & set(user.roles) else None


async def _latest_sample(
    previous: dict[str, float] | None,
) -> tuple[int, dict[str, Any], dict[str, float]] | None:
    """Dernière mesure du four + diagnostic ML + épaisseur nominale du lot en cours."""
    async with db.acquire_conn() as conn:
        row = await conn.fetchrow(SELECT_LATEST)
        if row is None:
            return None
        thickness = await conn.fetchval(
            "SELECT r.thickness_nominal_mm FROM it_data.production_batches b"
            " JOIN it_data.glass_orders o ON o.id = b.order_id"
            " JOIN it_data.recipes r ON r.id = o.recipe_id"
            " WHERE b.status = 'IN_PROGRESS' ORDER BY b.started_at DESC NULLS LAST LIMIT 1"
        )
    anomaly, features = diagnose(row, previous)
    payload = to_payload(
        row, float(thickness) if thickness is not None else None, anomaly
    )
    return int(row["id"]), payload, features


async def _still_authorised(user: CurrentUser, token_exp: datetime) -> bool:
    if datetime.now(timezone.utc) >= token_exp:
        return False
    async with db.acquire_conn() as conn:
        revoked = await conn.fetchval(
            "SELECT 1 FROM sec_data.token_revocations WHERE jti = $1::uuid", user.jti
        )
        active = await conn.fetchval(
            "SELECT is_active FROM sec_data.users WHERE id = $1", user.id
        )
    return not revoked and bool(active)


@router.websocket("/ws/telemetry")
async def telemetry_socket(ws: WebSocket) -> None:
    global _active
    await ws.accept()
    if _active >= MAX_CONNECTIONS:
        await ws.close(code=1013)
        return
    _active += 1
    try:
        user = await _authenticate(ws)
        if user is None:
            await ws.send_json({"type": "auth_error"})
            await ws.close(code=CLOSE_POLICY)
            return
        await ws.send_json({"type": "auth_ok"})

        sub = await _recv_json(ws, SUBSCRIBE_TIMEOUT_S)
        if (
            not sub
            or sub.get("type") != "subscribe"
            or "telemetry" not in (sub.get("channels") or [])
        ):
            await ws.close(code=CLOSE_POLICY)
            return

        last_id = -1
        waited = 0.0
        previous: dict[str, float] | None = None
        while True:
            latest = await _latest_sample(previous)
            if latest is not None and latest[0] != last_id:
                last_id = latest[0]
                previous = latest[2]
                await ws.send_json({"type": "telemetry", "payload": latest[1]})
            await asyncio.sleep(POLL_INTERVAL_S)
            waited += POLL_INTERVAL_S
            if waited >= REVALIDATE_EVERY_S:
                waited = 0.0
                if not await _still_authorised(user, user.token_exp):
                    await ws.close(code=CLOSE_POLICY)
                    return
    except WebSocketDisconnect:
        return
    except Exception:
        logger.exception("ws/telemetry : erreur inattendue")
        try:
            await ws.close(code=1011)
        except RuntimeError:
            pass
    finally:
        _active -= 1
