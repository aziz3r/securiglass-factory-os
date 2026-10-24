#!/usr/bin/env python3
"""Reconnaissance Modbus/TCP en lecture seule (FC1 a FC4).

Exemples :
  python redteam/modbus_recon.py --target 127.0.0.1 --function 3 --start 0 --count 10
  python redteam/modbus_recon.py --target 10.10.30.10 --function 4 --dry-run

Garde-fous : cible 127.0.0.1 ou 10.10.30.0/24, port 5020, debit limite,
journalisation JSONL. Aucune ecriture possible dans cet outil.
"""

from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

# Permet l'execution directe : python redteam/<script>.py
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from redteam.cli_common import (
    add_common_args,
    describe_scope,
    fail,
    new_transaction_id,
    print_json,
    session_from_args,
)
from redteam.guardrails import GuardrailError
from redteam.modbus_proto import (
    ModbusProtocolError,
    build_read_pdu,
    build_request,
    parse_response,
)
from redteam.modbus_scapy import (
    SCAPY_AVAILABLE,
    ScapyNotInstalledError,
    build_tcp_packet,
    open_tcp_session,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Reconnaissance Modbus/TCP (lecture de registres) - SecuriGlass Red Team.",
        epilog=describe_scope(),
    )
    add_common_args(parser, require_authorization=False)
    parser.add_argument(
        "--function",
        type=int,
        choices=(1, 2, 3, 4),
        default=3,
        help="Fonction de lecture : 1 bobines, 2 entrees discretes, 3 registres holding, 4 registres input.",
    )
    parser.add_argument("--start", type=int, default=0, help="Adresse de depart (0-65535).")
    parser.add_argument("--count", type=int, default=10, help="Nombre de valeurs (max 125 registres / 2000 bits).")
    parser.add_argument("--output", type=Path, default=None, help="Fichier JSON de sortie (optionnel).")
    return parser


def run(args: argparse.Namespace) -> int:
    # Validation stricte avant tout acces reseau (leve GuardrailError).
    build_read_pdu(args.function, args.start, args.count)
    session = session_from_args(
        args,
        tool="modbus_recon",
        action="read_registers",
        require_authorization=False,
    )
    try:
        transaction_id = new_transaction_id()
        payload = build_request(
            transaction_id=transaction_id,
            unit_id=args.unit_id,
            function_code=args.function,
            start=args.start,
            count=args.count,
        )
        result: dict = {
            "tool": "modbus_recon",
            "target": str(session.target),
            "port": session.port,
            "unit_id": args.unit_id,
            "function": args.function,
            "start": args.start,
            "count": args.count,
            "transaction_id": transaction_id,
            "request_hex": payload.hex(),
            "dry_run": bool(args.dry_run),
        }

        if args.dry_run:
            if SCAPY_AVAILABLE:
                packet = build_tcp_packet(str(session.target), session.port, payload)
                result["scapy_summary"] = packet.summary()
            result["status"] = "DRY_RUN"
            session.log_result(status="DRY_RUN", request_hex=payload.hex())
        else:
            session.before_operation(f"read FC{args.function} start={args.start} count={args.count}")
            tcp_session = open_tcp_session(str(session.target), session.port, session.timeout)
            try:
                raw_response = tcp_session.send_payload(payload)
            finally:
                tcp_session.close()
            if not raw_response:
                result["status"] = "NO_RESPONSE"
                session.log_result(status="NO_RESPONSE", request_hex=payload.hex())
                print_json(result)
                return 4
            result["response_hex"] = raw_response.hex()
            result["response"] = parse_response(raw_response)
            result["status"] = "OK"
            session.log_result(status="OK", response_hex=raw_response.hex(), decoded=result["response"])

        print_json(result)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(
                __import__("json").dumps(result, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        return 0
    finally:
        session.logger.close()


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except GuardrailError as exc:
        return fail(str(exc), 2)
    except ScapyNotInstalledError as exc:
        return fail(str(exc), 3)
    except ModbusProtocolError as exc:
        return fail(f"trame Modbus invalide : {exc}", 2)
    except (socket.timeout, TimeoutError):
        return fail("timeout reseau : automate injoignable", 4)
    except OSError as exc:
        return fail(f"erreur reseau : {exc}", 4)


if __name__ == "__main__":
    sys.exit(main())
