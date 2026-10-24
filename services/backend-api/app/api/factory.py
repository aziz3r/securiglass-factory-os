"""API « usine » : vue d'ensemble, historique télémétrie, commandes, alertes SOC.

Alimente la console de supervision (stocks, ventes, production + diagnostic ML,
cartographie OT/IT, flux d'alertes qualifiées MITRE, métriques de conformité).
Chaque bloc est filtré par rôle côté serveur : un opérateur ne reçoit ni les
données commerciales ni les métriques de conformité.
"""

import asyncio
import json
import logging
import re
import secrets
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Annotated, Any, Final

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import Field

from app.api.deps import Conn, CurrentUser, CurrentUserDep, client_ip, require_roles
from app.core.rate_limiter import enforcement_enabled, global_rate_limiter
from app.models.schemas import StrictBaseModel
from app.services import audit_service
from app.services.ml_anomaly import anomaly_detector
from app.services.telemetry_view import (
    SELECT_LATEST,
    SELECT_RECENT,
    diagnose,
    to_payload,
)

logger = logging.getLogger("securiglass.api.factory")
router = APIRouter(
    prefix="/api/v1", tags=["factory"], dependencies=[Depends(global_rate_limiter)]
)

VIEW_ROLES: Final = (
    "SUPER_ADMIN",
    "SECURITY_AUDITOR",
    "PLANT_MANAGER",
    "OT_OPERATOR",
    "QUALITY_INSPECTOR",
)
# Principe du besoin d'en connaître : chaque bloc n'est renvoyé qu'aux rôles concernés.
PRODUCTION_ROLES: Final = frozenset(
    {"SUPER_ADMIN", "PLANT_MANAGER", "OT_OPERATOR", "QUALITY_INSPECTOR"}
)
STOCK_ROLES: Final = frozenset({"SUPER_ADMIN", "PLANT_MANAGER", "OT_OPERATOR"})
SALES_ROLES: Final = frozenset({"SUPER_ADMIN", "PLANT_MANAGER"})
SOC_ROLES: Final = frozenset({"SUPER_ADMIN", "SECURITY_AUDITOR"})
LIVE_MAX_AGE_S: Final = 15.0
CI_WORKFLOW: Final = Path(__file__).resolve().parents[4] / ".github/workflows/ci.yml"

Viewer = Annotated[CurrentUser, Depends(require_roles(*VIEW_ROLES))]
Seller = Annotated[CurrentUser, Depends(require_roles("PLANT_MANAGER"))]

# Qualification MITRE : ATT&CK Enterprise / ICS, ATLAS pour les attaques sur le LLM.
_MITRE: Final[dict[str, dict[str, str]]] = {
    "OT_SETPOINT_WRITE_BLOCKED": {
        "id": "T0836",
        "name": "Modify Parameter",
        "tactic": "Impair Process Control",
        "framework": "ATT&CK ICS",
        "severity": "CRITICAL",
    },
    "PROMPT_INJECTION_BLOCKED": {
        "id": "AML.T0051",
        "name": "LLM Prompt Injection",
        "tactic": "Initial Access",
        "framework": "MITRE ATLAS",
        "severity": "HIGH",
    },
    "UNSAFE_RECIPE_BLOCKED": {
        "id": "T0831",
        "name": "Manipulation of Control",
        "tactic": "Impact",
        "framework": "ATT&CK ICS",
        "severity": "HIGH",
    },
    "SENSITIVE_DATA_REQUEST_REFUSED": {
        "id": "AML.T0057",
        "name": "LLM Data Leakage",
        "tactic": "Exfiltration",
        "framework": "MITRE ATLAS",
        "severity": "HIGH",
    },
    "ACCESS_DENIED_RBAC": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Privilege Escalation",
        "framework": "ATT&CK",
        "severity": "MEDIUM",
    },
    "ACCESS_DENIED_CLEARANCE": {
        "id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Privilege Escalation",
        "framework": "ATT&CK",
        "severity": "MEDIUM",
    },
    "AUTH_LOGIN": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "framework": "ATT&CK",
        "severity": "MEDIUM",
    },
}
_DEFAULT_MITRE: Final = {
    "id": "T1562",
    "name": "Impair Defenses",
    "tactic": "Defense Evasion",
    "framework": "ATT&CK",
    "severity": "LOW",
}


# ---------------------------------------------------------------------------
# Lecture
# ---------------------------------------------------------------------------
async def _inventory(conn: Any) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        "SELECT material_code, name, unit, stock_qty, capacity_qty, reorder_level"
        " FROM it_data.raw_materials ORDER BY material_code"
    )
    return [
        {
            "code": r["material_code"],
            "name": r["name"],
            "unit": r["unit"],
            "stock": float(r["stock_qty"]),
            "capacity": float(r["capacity_qty"]),
            "reorder_level": float(r["reorder_level"]),
            "level_pct": round(float(r["stock_qty"]) / float(r["capacity_qty"]) * 100),
            "low": r["stock_qty"] <= r["reorder_level"],
        }
        for r in rows
    ]


async def _sales(conn: Any) -> dict[str, Any]:
    totals = await conn.fetchrow(
        "SELECT count(*) AS n,"
        " count(*) FILTER (WHERE status NOT IN ('DELIVERED','CANCELLED')) AS open_n,"
        " COALESCE(sum(quantity),0) AS panes FROM it_data.glass_orders"
    )
    recent = await conn.fetch(
        "SELECT o.order_ref, c.company_name, o.quantity, o.status, o.created_at,"
        " r.name AS recipe FROM it_data.glass_orders o"
        " JOIN it_data.customers c ON c.id = o.customer_id"
        " JOIN it_data.recipes r ON r.id = o.recipe_id"
        " ORDER BY o.created_at DESC LIMIT 6"
    )
    recipes = await conn.fetch(
        "SELECT recipe_code, name, thickness_nominal_mm FROM it_data.recipes"
        " WHERE is_approved ORDER BY recipe_code"
    )
    return {
        "recipes": [
            {
                "code": r["recipe_code"],
                "name": r["name"],
                "thickness_mm": float(r["thickness_nominal_mm"]),
            }
            for r in recipes
        ],
        "orders_total": int(totals["n"]),
        "orders_open": int(totals["open_n"]),
        "panes_ordered": int(totals["panes"]),
        "recent": [
            {
                "order_ref": r["order_ref"],
                "customer": r["company_name"],
                "recipe": r["recipe"],
                "quantity": int(r["quantity"]),
                "status": r["status"],
                "created_at": r["created_at"].astimezone(timezone.utc).isoformat(),
            }
            for r in recent
        ],
    }


async def _production(conn: Any) -> dict[str, Any]:
    line = await conn.fetchval(
        "SELECT status FROM ot_data.production_lines ORDER BY line_code LIMIT 1"
    )
    batch = await conn.fetchrow(
        "SELECT batch_code, planned_quantity, produced_quantity, scrapped_quantity, status"
        " FROM it_data.production_batches WHERE status = 'IN_PROGRESS'"
        " ORDER BY started_at DESC NULLS LAST LIMIT 1"
    )
    row = await conn.fetchrow(SELECT_LATEST)
    anomaly = None
    age = None
    if row is not None:
        anomaly, _ = diagnose(row, None)
        age = round((datetime.now(timezone.utc) - row["timestamp"]).total_seconds(), 1)
    anomalies_1h = await conn.fetchval(
        "SELECT count(*) FROM ot_data.furnace_telemetry"
        " WHERE timestamp > now() - interval '1 hour' AND emergency_stop_tripped"
    )
    return {
        "line_status": line,
        "batch": (
            {
                "code": batch["batch_code"],
                "planned": int(batch["planned_quantity"]),
                "produced": int(batch["produced_quantity"]),
                "scrapped": int(batch["scrapped_quantity"]),
                "status": batch["status"],
            }
            if batch
            else None
        ),
        "telemetry_age_s": age,
        "emergency_stops_1h": int(anomalies_1h or 0),
        "ml": {
            "trained": anomaly_detector.is_trained,
            "backend": anomaly_detector.backend,
            "current": anomaly,
        },
    }


_NODES: Final = (
    ("plc", "Automate four", "OT", 1),
    ("gateway", "Passerelle Edge", "OT", 3),
    ("diode", "Data Diode", "DMZ", 3),
    ("backend", "API FastAPI", "IT", 4),
    ("db", "PostgreSQL", "IT", 4),
    ("llm", "Assistant IA", "IT", 4),
    ("soc", "SOC · Audit", "IT", 4),
    ("web", "Portail web React", "IT", 5),
)
_LINKS: Final = (
    ("plc", "gateway", "Modbus TCP (lecture seule)"),
    ("gateway", "diode", "UDP simplex signé Ed25519"),
    ("diode", "backend", "Ingestion + anti-rejeu"),
    ("backend", "db", "asyncpg"),
    ("backend", "llm", "RAG EN 12150"),
    ("backend", "soc", "Journal SHA-256"),
    ("web", "backend", "HTTPS · WSS"),
)


def _network(telemetry_age: float | None) -> dict[str, Any]:
    ot_live = telemetry_age is not None and telemetry_age < LIVE_MAX_AGE_S
    status_of = {"plc": ot_live, "gateway": ot_live, "diode": ot_live}
    return {
        "nodes": [
            {
                "id": nid,
                "label": label,
                "zone": zone,
                "purdue_level": level,
                "up": status_of.get(nid, True),
            }
            for nid, label, zone, level in _NODES
        ],
        "links": [{"source": s, "target": t, "label": label} for s, t, label in _LINKS],
    }


def _ci_jobs() -> list[str]:
    try:
        text = CI_WORKFLOW.read_text(encoding="utf-8")
    except OSError:
        return []
    block = text.split("\njobs:", 1)[-1]
    return re.findall(r"^  ([a-z][a-z0-9_-]*):\s*$", block, flags=re.MULTILINE)


_compliance_cache: tuple[float, dict[str, Any]] | None = None
COMPLIANCE_TTL_S: Final = 30.0


async def _compliance(conn: Any) -> dict[str, Any]:
    global _compliance_cache
    if _compliance_cache and time.monotonic() - _compliance_cache[0] < COMPLIANCE_TTL_S:
        return _compliance_cache[1]
    chain_ok, _broken = await audit_service.verify_stored_chain(conn)
    total = await conn.fetchval("SELECT count(*) FROM sec_data.audit_logs")
    blocked = await conn.fetchval(
        "SELECT count(*) FROM sec_data.audit_logs"
        " WHERE outcome IN ('DENIED','FAILURE') AND event_time > now() - interval '24 hours'"
    )
    jobs = await asyncio.to_thread(_ci_jobs)
    controls = [
        {
            "name": "Chaîne d'audit intègre",
            "ok": bool(chain_ok),
            "detail": f"{total} entrées",
        },
        {
            "name": "Limitation de débit active",
            "ok": enforcement_enabled(),
            "detail": "login 5/min · API 60/min · RAG 10/min",
        },
        {
            "name": "Détecteur d'anomalies entraîné",
            "ok": anomaly_detector.is_trained,
            "detail": anomaly_detector.backend,
        },
        {"name": "Garde LLM (4 barrières)", "ok": True, "detail": "EN 12150"},
    ]
    if jobs:
        controls.append(
            {
                "name": "Pipeline CI/CD défini",
                "ok": True,
                "detail": " · ".join(jobs),
            }
        )
    score = round(100 * sum(1 for c in controls if c["ok"]) / len(controls))
    result = {
        "score": score,
        "controls": controls,
        "threats_blocked_24h": int(blocked or 0),
        "ci_jobs": jobs,
    }
    _compliance_cache = (time.monotonic(), result)
    return result


def _qualify(row: Any) -> dict[str, Any]:
    event_type = row["event_type"]
    mitre = _MITRE.get(event_type, _DEFAULT_MITRE)
    details = row["details"]
    return {
        "id": str(row["id"]),
        "time": row["event_time"].astimezone(timezone.utc).isoformat(),
        "event_type": event_type,
        "actor": row["actor_username"],
        "source_ip": str(row["actor_ip"]),
        "resource": row["resource"],
        "outcome": row["outcome"],
        "severity": mitre["severity"],
        "mitre": {k: mitre[k] for k in ("id", "name", "tactic", "framework")},
        "blocked": row["outcome"] in ("DENIED", "FAILURE"),
        "details": details if isinstance(details, dict) else None,
    }


async def _alerts(conn: Any, limit: int) -> list[dict[str, Any]]:
    rows = await conn.fetch(
        "SELECT id, event_time, event_type, actor_username, actor_ip, resource, outcome,"
        " details FROM sec_data.audit_logs WHERE outcome IN ('DENIED','FAILURE')"
        " ORDER BY event_time DESC, id DESC LIMIT $1",
        limit,
    )
    out = []
    for r in rows:
        item = dict(r)
        raw = item["details"]
        if isinstance(raw, str):
            try:
                item["details"] = json.loads(raw)
            except ValueError:
                item["details"] = None
        out.append(_qualify(item))
    return out


async def production_report(conn: Any) -> str:
    """Rapport de production en texte : mesures, lot, stocks, sécurité. Aucune donnée client."""
    production = await _production(conn)
    inventory = await _inventory(conn)
    sales = await _sales(conn)
    blocked = await conn.fetchval(
        "SELECT count(*) FROM sec_data.audit_logs"
        " WHERE outcome IN ('DENIED','FAILURE') AND event_time > now() - interval '24 hours'"
    )
    batch = production["batch"]
    ml = production["ml"]["current"]
    low = [i["name"] for i in inventory if i["low"]]
    lines = [
        f"RAPPORT DE PRODUCTION · {datetime.now(timezone.utc):%d/%m/%Y %H:%M} UTC",
        f"• Ligne : {production['line_status'] or 'inconnue'}",
        (
            f"• Lot {batch['code']} : {batch['produced']}/{batch['planned']} vitres"
            f" produites, {batch['scrapped']} rebuts"
            if batch
            else "• Aucun lot en cours"
        ),
        (
            f"• Diagnostic ML du four : {ml['severity']}"
            + (f" ({ml['diagnosis']})" if ml["diagnosis"] else "")
            if ml
            else "• Diagnostic ML du four : indisponible"
        ),
        f"• Commandes ouvertes : {sales['orders_open']} ({sales['panes_ordered']} vitres au total)",
        "• Stocks sous le seuil de réapprovisionnement : "
        + (", ".join(low) if low else "aucun"),
        f"• Événements de sécurité bloqués (24 h) : {int(blocked or 0)}",
        "Les données commerciales et personnelles des clients ne figurent pas dans ce rapport.",
    ]
    return "\n".join(lines)


@router.get(
    "/factory/overview", summary="Vue d'ensemble de la console (filtrée par rôle)"
)
async def overview(conn: Conn, user: Viewer) -> dict[str, Any]:
    roles = set(user.roles)
    production = await _production(conn) if roles & PRODUCTION_ROLES else None
    soc = bool(roles & SOC_ROLES)
    age = None
    if soc:
        age = await conn.fetchval(
            "SELECT extract(epoch FROM now() - max(timestamp)) FROM ot_data.furnace_telemetry"
        )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inventory": await _inventory(conn) if roles & STOCK_ROLES else None,
        "production": production,
        "network": _network(None if age is None else float(age)) if soc else None,
        "sales": await _sales(conn) if roles & SALES_ROLES else None,
        "compliance": await _compliance(conn) if soc else None,
        "alerts": await _alerts(conn, 12) if soc else None,
    }


@router.get(
    "/factory/telemetry/history", summary="Historique récent avec diagnostic ML"
)
async def telemetry_history(
    conn: Conn,
    user: Annotated[CurrentUser, Depends(require_roles(*PRODUCTION_ROLES))],
    limit: Annotated[int, Query(ge=10, le=300)] = 120,
) -> list[dict[str, Any]]:
    rows = await conn.fetch(SELECT_RECENT, limit)
    points: list[dict[str, Any]] = []
    previous: dict[str, float] | None = None
    for row in reversed(rows):
        anomaly, previous = diagnose(row, previous)
        points.append(to_payload(row, None, anomaly))
    return points


@router.get("/soc/alerts", summary="Flux d'alertes qualifiées MITRE")
async def soc_alerts(
    conn: Conn,
    user: Annotated[CurrentUser, Depends(require_roles(*SOC_ROLES))],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> list[dict[str, Any]]:
    return await _alerts(conn, limit)


# ---------------------------------------------------------------------------
# Ventes : une commande décrémente les stocks de matières premières
# ---------------------------------------------------------------------------
class OrderCreate(StrictBaseModel):
    customer_id: str = Field(..., min_length=36, max_length=36)
    recipe_code: str = Field(..., min_length=3, max_length=32)
    quantity: int = Field(..., ge=1, le=10_000)
    width_mm: float = Field(1200.0, ge=100.0, le=6000.0)
    height_mm: float = Field(800.0, ge=100.0, le=3300.0)


@router.post(
    "/orders", status_code=status.HTTP_201_CREATED, summary="Enregistre une commande"
)
async def create_order(
    body: OrderCreate, request: Request, conn: Conn, user: Seller
) -> dict[str, Any]:
    async with conn.transaction():
        recipe = await conn.fetchrow(
            "SELECT id, thickness_nominal_mm, is_approved FROM it_data.recipes"
            " WHERE recipe_code = $1",
            body.recipe_code,
        )
        if recipe is None or not recipe["is_approved"]:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND, "Recette inconnue ou non approuvée"
            )
        customer = await conn.fetchval(
            "SELECT 1 FROM it_data.customers WHERE id = $1::uuid AND is_active",
            body.customer_id,
        )
        if not customer:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Client inconnu")

        area_m2 = body.quantity * body.width_mm * body.height_mm / 1_000_000
        thickness = float(recipe["thickness_nominal_mm"])
        materials = await conn.fetch(
            "SELECT material_code, stock_qty, consumption_per_m2_mm"
            " FROM it_data.raw_materials ORDER BY material_code FOR UPDATE"
        )
        needs = {
            m["material_code"]: round(
                area_m2 * thickness * float(m["consumption_per_m2_mm"]), 2
            )
            for m in materials
        }
        short = [
            code
            for m in materials
            if (code := m["material_code"]) and float(m["stock_qty"]) < needs[code]
        ]
        if short:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"Stock insuffisant : {', '.join(short)}",
            )
        for code, qty in needs.items():
            await conn.execute(
                "UPDATE it_data.raw_materials SET stock_qty = stock_qty - $2::numeric,"
                " updated_at = now() WHERE material_code = $1",
                code,
                qty,
            )
        order_ref = f"CMD-{date.today():%Y%m%d}-{secrets.token_hex(2).upper()}"
        await conn.execute(
            "INSERT INTO it_data.glass_orders (order_ref, customer_id, recipe_id, width_mm,"
            " height_mm, quantity, status, target_delivery_date)"
            " VALUES ($1, $2::uuid, $3, $4, $5, $6, 'SUBMITTED', $7)",
            order_ref,
            body.customer_id,
            recipe["id"],
            body.width_mm,
            body.height_mm,
            body.quantity,
            date.today() + timedelta(days=14),
        )
    await audit_service.record_event(
        conn,
        event_type="ORDER_CREATE",
        actor_id=str(user.id),
        actor_username=user.username,
        actor_ip=client_ip(request),
        action="POST",
        resource=f"it_data.glass_orders/{order_ref}",
        outcome="SUCCESS",
        details={"quantity": body.quantity, "materials_consumed": needs},
    )
    return {
        "order_ref": order_ref,
        "quantity": body.quantity,
        "area_m2": round(area_m2, 2),
        "materials_consumed": needs,
        "inventory": await _inventory(conn),
    }


# ---------------------------------------------------------------------------
# Simulation d'attaque : le portail web n'a AUCUN chemin d'écriture vers le four
# ---------------------------------------------------------------------------
class SetpointRequest(StrictBaseModel):
    furnace_temp_c: float = Field(..., ge=0.0, le=2000.0)


@router.post(
    "/factory/furnace/setpoint",
    summary="Consigne four depuis le portail web : toujours bloquée et qualifiée MITRE",
)
async def attempt_setpoint(
    body: SetpointRequest, request: Request, conn: Conn, user: CurrentUserDep
) -> None:
    await audit_service.record_event(
        conn,
        event_type="OT_SETPOINT_WRITE_BLOCKED",
        actor_id=str(user.id),
        actor_username=user.username,
        actor_ip=client_ip(request),
        action="POST",
        resource="urn:securiglass:ot:furnace:setpoint",
        outcome="DENIED",
        details={"requested_temp_c": body.furnace_temp_c, "path": "IT->OT"},
    )
    raise HTTPException(
        status.HTTP_403_FORBIDDEN,
        "Écriture OT interdite depuis le domaine IT (segmentation Purdue, Data Diode unidirectionnelle).",
    )
