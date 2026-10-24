"""Validation de conformité et syntaxe de la configuration pgAudit.

Normes de référence :
- IEC 62443-3-3 (SR 2.8 Audit generation, SR 2.9 Audit record content, SR 2.11 Non-repudiation)
- OWASP ASVS v4.0 - V8 Data Protection & Audit Architecture
- CIS PostgreSQL 16 Benchmark v1.0
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PGAUDIT_CONF = _REPO_ROOT / "database" / "pgaudit" / "pgaudit_config.conf"
_DOCKERFILE = _REPO_ROOT / "infra" / "docker" / "postgres" / "Dockerfile"


def _parse_conf_file(path: Path) -> dict[str, str]:
    """Parse un fichier de configuration style postgresql.conf."""
    assert path.is_file(), f"Fichier de configuration introuvable : {path}"
    data: dict[str, str] = {}
    pattern = re.compile(
        r"^\s*([a-zA-Z0-9_.]+)\s*=\s*(?:'([^']*)'|\"([^\"]*)\"|([^\s#]+))"
    )
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = pattern.match(line)
        if match:
            key = match.group(1)
            val = match.group(2) or match.group(3) or match.group(4)
            data[key] = val.strip()
    return data


def test_pgaudit_config_file_exists_and_readable() -> None:
    """Vérifie l'existence et l'accès au fichier database/pgaudit/pgaudit_config.conf."""
    assert _PGAUDIT_CONF.exists(), f"Le fichier {_PGAUDIT_CONF} doit exister"
    assert (
        _PGAUDIT_CONF.stat().st_size > 0
    ), "Le fichier pgaudit_config.conf ne doit pas être vide"


def test_pgaudit_config_syntax_and_directives() -> None:
    """Valide les paramètres obligatoires pgAudit selon les spécifications industrielles."""
    conf = _parse_conf_file(_PGAUDIT_CONF)

    # 1. Vérification des classes d'événements auditées (IEC 62443 SR 2.8)
    assert "pgaudit.log" in conf, "pgaudit.log est obligatoire"
    log_classes = [c.strip().lower() for c in conf["pgaudit.log"].split(",")]
    assert (
        "role" in log_classes
    ), "La classe 'role' doit être auditée (création/modification de rôles)"
    assert (
        "ddl" in log_classes
    ), "La classe 'ddl' doit être auditée (schémas, tables, triggers)"
    assert (
        "write" in log_classes
    ), "La classe 'write' doit être auditée (modifications de données)"
    assert (
        "function" in log_classes
    ), "La classe 'function' doit être auditée (exécution de procédures stockées)"

    # 2. Paramètres de requête (IEC 62443 SR 2.9 - traçabilité complète des arguments)
    assert "pgaudit.log_parameter" in conf
    assert conf["pgaudit.log_parameter"].lower() in (
        "on",
        "true",
        "1",
    ), "pgaudit.log_parameter doit être 'on'"

    # 3. Masquage des catalogues système pour éviter le DoS des logs
    assert "pgaudit.log_catalog" in conf
    assert conf["pgaudit.log_catalog"].lower() in (
        "off",
        "false",
        "0",
    ), "pgaudit.log_catalog doit être 'off'"

    # 4. Niveau de log standard PostgreSQL
    assert "pgaudit.log_level" in conf
    assert conf["pgaudit.log_level"].lower() in ("log", "info", "notice")

    # 5. Ciblage du rôle d'administration à hauts privilèges
    assert "pgaudit.role" in conf
    assert (
        conf["pgaudit.role"] == "role_super_admin"
    ), "pgaudit.role doit cibler 'role_super_admin'"


def test_postgres_dockerfile_embeds_pgaudit_preload() -> None:
    """Vérifie que l'image Docker PostgreSQL Debian officielle précharge l'extension pgaudit."""
    assert _DOCKERFILE.is_file(), f"Dockerfile introuvable : {_DOCKERFILE}"
    content = _DOCKERFILE.read_text(encoding="utf-8")

    assert (
        "postgresql-16-pgaudit" in content
    ), "Le paquet binaire postgresql-16-pgaudit doit être installé"
    assert (
        "shared_preload_libraries = 'pgaudit'" in content
    ), "shared_preload_libraries doit contenir 'pgaudit'"
    assert "pgaudit.log" in content, "pgaudit.log doit être configuré dans le template"
    assert (
        "pgaudit.log_parameter = on" in content
    ), "pgaudit.log_parameter doit être activé"


# ============================================================================
# Tests dynamiques avec la base réelle (si conteneur démarré)
# ============================================================================


async def test_live_postgres_pgaudit_settings(db_conn: Any) -> None:
    """Si PostgreSQL est connecté, vérifie les variables d'exécution effectives."""
    preload = await db_conn.fetchval("SHOW shared_preload_libraries")
    assert (
        "pgaudit" in preload
    ), f"pgaudit absent de shared_preload_libraries: {preload}"

    pgaudit_log = await db_conn.fetchval("SHOW pgaudit.log")
    assert "ddl" in pgaudit_log
    assert "role" in pgaudit_log

    pgaudit_param = await db_conn.fetchval("SHOW pgaudit.log_parameter")
    assert pgaudit_param.lower() in ("on", "true")
