"""Validation de la matrice RBAC réelle (privilèges PostgreSQL).

Source de vérité : `database/schemas/05_rbac_abac_grants.sql` confronté à
`docs/specifications/RBAC_ABAC_MATRIX.md`. Contrôle déclaratif (catalogues
`has_*_privilege`) + contrôles comportementaux (SET ROLE / requête refusée).
"""

from __future__ import annotations

import uuid

import asyncpg
import pytest

from .helpers import RollbackSentinel, denied, scoped_role

# (rôle PostgreSQL, objet, privilège, attendu)
_TABLE_MATRIX: tuple[tuple[str, str, str, bool], ...] = (
    # --- SUPER_ADMIN : administration IAM, jamais d'altération d'audit -------
    ("role_super_admin", "sec_data.users", "SELECT", True),
    ("role_super_admin", "sec_data.users", "INSERT", True),
    ("role_super_admin", "sec_data.users", "DELETE", True),
    ("role_super_admin", "sec_data.audit_logs", "SELECT", True),
    ("role_super_admin", "sec_data.audit_logs", "INSERT", True),
    ("role_super_admin", "sec_data.audit_logs", "UPDATE", False),
    ("role_super_admin", "sec_data.audit_logs", "DELETE", False),
    # --- SECURITY_AUDITOR : lecture seule -----------------------------------
    ("role_security_auditor", "sec_data.audit_logs", "SELECT", True),
    ("role_security_auditor", "sec_data.abac_policies", "SELECT", True),
    ("role_security_auditor", "sec_data.users", "INSERT", False),
    ("role_security_auditor", "sec_data.users", "UPDATE", False),
    ("role_security_auditor", "it_data.glass_orders", "SELECT", False),
    # --- PLANT_MANAGER : métier IT ------------------------------------------
    ("role_plant_manager", "it_data.customers", "SELECT", True),
    ("role_plant_manager", "it_data.customers", "INSERT", True),
    ("role_plant_manager", "it_data.customers", "DELETE", False),
    ("role_plant_manager", "it_data.glass_orders", "DELETE", True),
    ("role_plant_manager", "it_data.recipes", "UPDATE", True),
    # D7 (constat) : la matrice annonce « R (filtré usine) » sur sec_data.users,
    # mais aucun GRANT n'est émis -> refus effectif. Le test fige le comportement réel.
    ("role_plant_manager", "sec_data.users", "SELECT", False),
    # --- OT_OPERATOR : conduite de ligne ------------------------------------
    ("role_ot_operator", "ot_data.furnace_telemetry", "SELECT", True),
    ("role_ot_operator", "ot_data.furnace_telemetry", "INSERT", False),
    ("role_ot_operator", "ot_data.furnace_telemetry", "UPDATE", False),
    ("role_ot_operator", "it_data.production_batches", "SELECT", True),
    # Le GRANT est colonne par colonne (status, started_at, finished_at) :
    # PostgreSQL n'implique donc PAS de privilège UPDATE au niveau table.
    ("role_ot_operator", "it_data.production_batches", "UPDATE", False),
    ("role_ot_operator", "it_data.glass_orders", "DELETE", False),
    ("role_ot_operator", "sec_data.users", "SELECT", False),
    # --- QUALITY_INSPECTOR ---------------------------------------------------
    ("role_quality_inspector", "ot_data.quality_defects", "INSERT", True),
    ("role_quality_inspector", "ot_data.quality_defects", "UPDATE", True),
    ("role_quality_inspector", "ot_data.autoclave_telemetry", "SELECT", True),
    ("role_quality_inspector", "sec_data.audit_logs", "SELECT", False),
    # --- SERVICE_ACCOUNT_EDGE : insertion unidirectionnelle ------------------
    ("role_edge_service", "ot_data.furnace_telemetry", "INSERT", True),
    ("role_edge_service", "ot_data.autoclave_telemetry", "INSERT", True),
    ("role_edge_service", "ot_data.diode_import_log", "INSERT", True),
    ("role_edge_service", "ot_data.furnace_telemetry", "SELECT", False),
    ("role_edge_service", "ot_data.furnace_telemetry", "UPDATE", False),
    ("role_edge_service", "ot_data.furnace_telemetry", "DELETE", False),
    ("role_edge_service", "sec_data.users", "SELECT", False),
)

_SCHEMA_MATRIX: tuple[tuple[str, str, bool], ...] = (
    ("role_super_admin", "sec_data", True),
    ("role_security_auditor", "sec_data", True),
    ("role_ot_operator", "sec_data", False),
    ("role_quality_inspector", "sec_data", False),
    ("role_edge_service", "sec_data", False),
    ("role_edge_service", "ot_data", True),
)


@pytest.mark.parametrize(("role", "obj", "privilege", "expected"), _TABLE_MATRIX)
async def test_table_privileges_match_rbac_matrix(
    db_conn: asyncpg.Connection, role: str, obj: str, privilege: str, expected: bool
) -> None:
    got = await db_conn.fetchval(
        "SELECT has_table_privilege($1, $2, $3)", role, obj, privilege
    )
    assert (
        got is expected
    ), f"{role} {privilege} sur {obj} : attendu {expected}, obtenu {got}"


async def test_column_level_update_is_restricted(db_conn: asyncpg.Connection) -> None:
    """L'opérateur OT ne peut modifier que le statut/les horodatages des lots."""
    allowed = await db_conn.fetchval(
        "SELECT has_column_privilege('role_ot_operator','it_data.production_batches','status','UPDATE')"
    )
    forbidden = await db_conn.fetchval(
        "SELECT has_column_privilege('role_ot_operator','it_data.production_batches',"
        "'planned_quantity','UPDATE')"
    )
    assert allowed is True
    assert forbidden is False


async def test_security_auditor_cannot_insert_audit_rows(
    db_conn: asyncpg.Connection,
) -> None:
    got = await db_conn.fetchval(
        "SELECT has_table_privilege('role_security_auditor','sec_data.audit_logs','INSERT')"
    )
    assert got is False


async def test_edge_service_can_insert_telemetry(db_conn: asyncpg.Connection) -> None:
    try:
        async with db_conn.transaction():
            line_id = await db_conn.fetchval(
                """
                INSERT INTO ot_data.production_lines (line_code, line_name, ip_gateway, status)
                VALUES ($1, 'Ligne de test RBAC', '10.10.30.10', 'RUNNING')
                RETURNING id
                """,
                f"RBAC-{uuid.uuid4().hex[:8]}",
            )
            await db_conn.execute("SET LOCAL ROLE role_edge_service")
            # Pas de RETURNING : celui-ci exigerait le privilège SELECT, que
            # l'Edge Gateway (data diode) ne possède volontairement pas.
            status = await db_conn.execute(
                """
                INSERT INTO ot_data.furnace_telemetry
                    (line_id, temp_zone1_c, temp_zone2_c, temp_zone3_c, temp_zone4_c,
                     glass_pyrometer_temp_c, quench_pressure_bar, conveyor_speed_m_min)
                VALUES ($1, 700.0, 710.0, 720.0, 730.0, 640.0, 5.50, 12.00)
                """,
                line_id,
            )
            assert status == "INSERT 0 1"
            raise RollbackSentinel
    except RollbackSentinel:
        pass


async def test_edge_service_select_is_denied_at_runtime(
    db_conn: asyncpg.Connection,
) -> None:
    async with scoped_role(db_conn, "role_edge_service"):
        assert (
            await denied(db_conn, "SELECT id FROM ot_data.furnace_telemetry LIMIT 1")
            is True
        )


async def test_ot_operator_cannot_insert_telemetry_at_runtime(
    db_conn: asyncpg.Connection,
) -> None:
    async with scoped_role(db_conn, "role_ot_operator"):
        assert (
            await denied(
                db_conn,
                "INSERT INTO ot_data.furnace_telemetry (line_id, temp_zone1_c, temp_zone2_c,"
                " temp_zone3_c, temp_zone4_c, glass_pyrometer_temp_c, quench_pressure_bar,"
                " conveyor_speed_m_min) VALUES ($1,700,700,700,700,600,5,10)",
                uuid.uuid4(),
            )
            is True
        )


async def test_plant_manager_cannot_escalate_to_sec_data(
    db_conn: asyncpg.Connection,
) -> None:
    async with scoped_role(db_conn, "role_plant_manager"):
        assert (
            await denied(db_conn, "SELECT username FROM sec_data.users LIMIT 1") is True
        )


@pytest.mark.parametrize(("role", "schema", "expected"), _SCHEMA_MATRIX)
async def test_schema_usage_is_least_privilege(
    db_conn: asyncpg.Connection, role: str, schema: str, expected: bool
) -> None:
    got = await db_conn.fetchval(
        "SELECT has_schema_privilege($1, $2, 'USAGE')", role, schema
    )
    assert got is expected


async def test_public_schema_is_locked_down(db_conn: asyncpg.Connection) -> None:
    """CIS Benchmark / IEC 62443 : PUBLIC ne doit plus créer d'objets."""
    can_create = await db_conn.fetchval(
        "SELECT has_schema_privilege('public', 'public', 'CREATE')"
    )
    assert can_create is False
