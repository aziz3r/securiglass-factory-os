#!/usr/bin/env python3
"""Rejeu de trames Modbus/TCP capturees (pcap).

ATTENTION : le rejeu peut declencher des ecritures sur l'automate. Il exige
donc `--i-have-authorization`, une cible dans le perimetre, le port 5020 et
un debit limite. Par defaut, seules les requetes (destination 5020) sont
rejouees.

Exemples :
  # Inspection d'un pcap sans emission
  python redteam/modbus_replay.py --target 127.0.0.1 --pcap capture.pcap \
      --dry-run --i-have-authorization

  # Rejeu des ecritures FC6/FC16 vers le simulateur local
  python redteam/modbus_replay.py --target 127.0.0.1 --pcap capture.pcap \
      --filter-function 6 --limit 3 --i-have-authorization \
      --authorization-ref "LAB-2026-001"
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
    print_json,
    session_from_args,
)
from redteam.guardrails import GuardrailError
from redteam.modbus_proto import ModbusProtocolError, frame_summary, parse_response
from redteam.modbus_scapy import (
    SCAPY_AVAILABLE,
    ScapyNotInstalledError,
    build_tcp_packet,
    extract_modbus_payloads,
    open_tcp_session,
    send_raw_packet,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Rejeu de trames Modbus/TCP capturees - SecuriGlass Red Team. "
            "Outil strictement reserve aux tests autorises."
        ),
        epilog=describe_scope(),
    )
    add_common_args(parser, require_authorization=True)
    parser.set_defaults(max_operations=10, rate=2.0)
    parser.add_argument("--pcap", type=Path, required=True, help="Fichier pcap/pcapng source.")
    parser.add_argument(
        "--filter-function",
        type=int,
        choices=(1, 2, 3, 4, 5, 6, 15, 16),
        default=None,
        help="Ne rejouer qu'une fonction Modbus (optionnel).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=10,
        help="Nombre maximal de trames extraites du pcap (1 a 100, defaut 10).",
    )
    parser.add_argument(
        "--mode",
        choices=("stream", "raw"),
        default="stream",
        help="stream : nouvelle session TCP Scapy ; raw : emission L3 brute (racine requise).",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    if not 1 <= args.limit <= 100:
        raise GuardrailError("--limit doit etre compris entre 1 et 100")
    if not SCAPY_AVAILABLE:
        raise ScapyNotInstalledError("Scapy est requis pour lire un pcap et rejouer des trames")

    # Autorisation obligatoire AVANT lecture du pcap et emission.
    session = session_from_args(
        args,
        tool="modbus_replay",
        action="replay_frames",
        require_authorization=True,
    )
    try:
        frames = extract_modbus_payloads(
            args.pcap,
            port=session.port,
            only_requests=True,
            function_filter=args.filter_function,
            limit=args.limit,
        )
        if not frames:
            print_json(
                {
                    "tool": "modbus_replay",
                    "status": "NO_FRAMES",
                    "pcap": str(args.pcap),
                    "message": "Aucune requete Modbus/TCP 5020 correspondante dans le pcap.",
                }
            )
            session.log_result(status="NO_FRAMES", pcap=str(args.pcap))
            return 4

        results: list[dict] = []
        stream = None
        if not args.dry_run and args.mode == "stream":
            stream = open_tcp_session(str(session.target), session.port, session.timeout)

        try:
            for index, item in enumerate(frames, start=1):
                payload: bytes = item["payload"]
                summary = frame_summary(payload)
                record: dict = {
                    "index": index,
                    "original_src": item["src_ip"],
                    "original_dst": item["dst_ip"],
                    "original_sport": item["sport"],
                    "original_dport": item["dport"],
                    "frame": summary,
                    "payload_hex": payload.hex(),
                }
                if args.dry_run:
                    record["status"] = "DRY_RUN"
                    results.append(record)
                    session.logger.log(
                        "replay_frame",
                        status="DRY_RUN",
                        index=index,
                        frame=summary,
                        original_src=item["src_ip"],
                        original_dst=item["dst_ip"],
                        authorized=session.authorized,
                        authorization_ref=session.authorization_ref,
                    )
                    continue

                session.before_operation(
                    f"replay frame {index} FC{summary.get('function_code')} to {session.target}:{session.port}"
                )
                if args.mode == "raw":
                    packet = build_tcp_packet(str(session.target), session.port, payload)
                    raw_response = send_raw_packet(packet, session.timeout)
                else:
                    assert stream is not None
                    raw_response = stream.send_payload(payload)

                if not raw_response:
                    record["status"] = "NO_RESPONSE"
                else:
                    record["status"] = "OK"
                    record["response_hex"] = raw_response.hex()
                    record["response"] = parse_response(raw_response)
                results.append(record)
                session.log_result(
                    status=record["status"],
                    index=index,
                    request_hex=payload.hex(),
                    response_hex=record.get("response_hex", ""),
                )
        finally:
            if stream is not None:
                stream.close()

        print_json(
            {
                "tool": "modbus_replay",
                "target": str(session.target),
                "port": session.port,
                "pcap": str(args.pcap),
                "mode": args.mode,
                "dry_run": bool(args.dry_run),
                "frames": results,
                "status": "OK",
            }
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
    except FileNotFoundError as exc:
        return fail(str(exc), 4)
    except ModbusProtocolError as exc:
        return fail(f"trame Modbus invalide : {exc}", 2)
    except (socket.timeout, TimeoutError):
        return fail("timeout reseau : automate injoignable", 4)
    except OSError as exc:
        return fail(f"erreur reseau : {exc}", 4)


if __name__ == "__main__":
    sys.exit(main())
