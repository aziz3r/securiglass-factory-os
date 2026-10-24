"""Arguments et initialisation communes aux trois outils Red Team."""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path
from typing import Any

from .guardrails import (
    ALLOWED_PORTS,
    ALLOWED_TARGETS,
    GuardrailError,
    Session,
    build_session,
)


def add_common_args(
    parser: argparse.ArgumentParser,
    *,
    require_authorization: bool = False,
) -> None:
    parser.add_argument(
        "--target",
        required=True,
        help="Adresse IPv4 cible : 127.0.0.1 ou une adresse de 10.10.30.0/24 (obligatoire).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5020,
        help=f"Port Modbus/TCP (seul {sorted(ALLOWED_PORTS)} est autorise, defaut 5020).",
    )
    parser.add_argument("--unit-id", type=int, default=1, help="Identifiant d'unite Modbus (0-255).")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout reseau en secondes (max 30).")
    parser.add_argument(
        "--rate",
        type=float,
        default=5.0,
        help="Debit maximal en operations/seconde (0.1 a 20, defaut 5).",
    )
    parser.add_argument(
        "--max-operations",
        type=int,
        default=50,
        help="Nombre maximal de trames envoyees dans l'execution (1 a 1000, defaut 50).",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=None,
        help="Repertoire du journal JSONL (defaut : redteam/logs ou $REDTEAM_LOG_DIR).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Construit et affiche la trame sans l'envoyer sur le reseau.",
    )
    if require_authorization:
        parser.add_argument(
            "--i-have-authorization",
            action="store_true",
            help="OBLIGATOIRE pour toute ecriture ou tout rejeu : confirme l'autorisation ecrite du proprietaire.",
        )
        parser.add_argument(
            "--authorization-ref",
            default="",
            help="Reference de l'autorisation (bon de commande, ticket, date) journalisee avec l'action.",
        )


def new_transaction_id() -> int:
    return secrets.randbelow(0xFFFF + 1)


def session_from_args(
    args: argparse.Namespace,
    *,
    tool: str,
    action: str,
    require_authorization: bool = False,
) -> Session:
    return build_session(
        tool=tool,
        action=action,
        target=args.target,
        port=args.port,
        unit_id=args.unit_id,
        timeout=args.timeout,
        rate=args.rate,
        max_operations=args.max_operations,
        authorized=bool(getattr(args, "i_have_authorization", False)),
        authorization_ref=getattr(args, "authorization_ref", "") or "",
        log_dir=args.log_dir,
        need_authorization=require_authorization,
    )


def fail(message: str, code: int = 2) -> int:
    print(f"ERREUR : {message}", file=sys.stderr)
    return code


def print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))


def describe_scope() -> str:
    return (
        "Perimetre autorise : "
        + ", ".join(str(network) for network in ALLOWED_TARGETS)
        + f" ; port {sorted(ALLOWED_PORTS)} uniquement."
    )
