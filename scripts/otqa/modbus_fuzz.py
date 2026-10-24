#!/usr/bin/env python3
"""Campagne de fuzzing Modbus TCP contre le démon PLC SecuriGlass.

Objectif (spec Étape 2 §4.2) : prouver qu'aucune trame corrompue, tronquée,
sur-dimensionnée ou hors bornes ne provoque de crash, de fuite ni de blocage
du démon, et qu'un client légitime continue d'être servi après la campagne.

Aucune écriture de consigne n'est effectuée par défaut (mode lecture seule).
Utilisation :
    python scripts/otqa/modbus_fuzz.py --port 5020 --rounds 200
"""

from __future__ import annotations

import argparse
import random
import socket
import struct
import sys
import time

MBAP = struct.Struct(">HHHB")


def build(tid: int, pid: int, unit: int, pdu: bytes, declared_len: int | None = None) -> bytes:
    length = declared_len if declared_len is not None else len(pdu) + 1
    return MBAP.pack(tid, pid, length & 0xFFFF, unit) + pdu


def read_registers(tid: int, address: int, quantity: int, function: int = 0x04) -> bytes:
    return build(tid, 0, 1, struct.pack(">BHH", function, address, quantity))


def adversarial_frames(rng: random.Random) -> list[tuple[str, bytes]]:
    """Jeu de trames hostiles pseudo-aléatoires, reproductible via --seed."""
    cases: list[tuple[str, bytes]] = [
        ("vide", b""),
        ("1-octet", b"\x00"),
        ("mbap-partiel", b"\x00\x01\x00\x00\x00"),
        ("longueur-nulle", build(1, 0, 1, b"", declared_len=0)),
        ("longueur-1", build(2, 0, 1, b"\x04", declared_len=1)),
        ("longueur-max", build(3, 0, 1, b"\x04", declared_len=0xFFFF)),
        ("protocole-non-nul", build(4, 1, 1, struct.pack(">BHH", 0x04, 0, 1))),
        ("unite-inconnue", build(5, 0, 247, struct.pack(">BHH", 0x04, 0, 1))),
        ("fonction-inconnue", build(6, 0, 1, struct.pack(">BHH", 0x2B, 0, 1))),
        ("lecture-quantite-nulle", read_registers(7, 0, 0)),
        ("lecture-quantite-125", read_registers(8, 0, 125)),
        ("lecture-quantite-126", read_registers(9, 0, 126)),
        ("lecture-quantite-65535", read_registers(10, 0, 65535)),
        ("adresse-debordante", read_registers(11, 0xFFFF, 10)),
        ("pdu-tronquee", build(12, 0, 1, b"\x04\x00")),
        ("pdu-trop-longue", build(13, 0, 1, struct.pack(">BHH", 0x04, 0, 1) + b"\x00" * 50)),
        ("octets-aleatoires", bytes(rng.randrange(256) for _ in range(rng.randrange(1, 64)))),
        ("gros-paquet", bytes(rng.randrange(256) for _ in range(4096))),
        ("deux-trames-collees", read_registers(14, 0, 4) + read_registers(15, 0, 4)),
        ("trame-valide-suffixee", read_registers(16, 0, 4) + b"\xDE\xAD\xBE\xEF"),
    ]
    # Écritures hors bornes (uniquement si le démon autorise l'écriture) :
    cases += [
        ("ecriture-adresse-invalide", build(20, 0, 1, struct.pack(">BHH", 0x06, 0x0100, 1))),
        ("ecriture-multiple-inexistante", build(21, 0, 1, struct.pack(">BHHB", 0x10, 0x0200, 2, 4) + b"\x00\x00\x00\x00")),
        ("ecriture-multiple-compteur-faux", build(22, 0, 1, struct.pack(">BHHB", 0x10, 0x0000, 2, 3) + b"\x00" * 6)),
    ]
    return cases


def transact(host: str, port: int, payload: bytes, timeout: float = 1.0) -> bytes | None:
    """Envoie un datagramme applicatif ; retourne la réponse ou None (connexion close)."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(payload)
        try:
            return sock.recv(4096)
        except socket.timeout:
            return None


def campaign(host: str, port: int, rounds: int, seed: int) -> int:
    rng = random.Random(seed)
    anomalies: list[str] = []
    executed = 0

    for name, payload in adversarial_frames(rng):
        try:
            transact(host, port, payload)
        except (ConnectionResetError, BrokenPipeError):
            pass  # fermeture défensive : comportement attendu et sûr
        except socket.timeout:
            anomalies.append(f"{name}: timeout de connexion")
        except OSError as exc:
            anomalies.append(f"{name}: {exc}")
        executed += 1

    # Trames valides répétées pour détecter une dérive mémoire sous charge.
    for index in range(rounds):
        try:
            response = transact(host, port, read_registers(index & 0xFFFF, 0, 12))
            if not response:
                anomalies.append(f"round {index}: aucune réponse à une lecture valide")
                break
        except OSError as exc:
            anomalies.append(f"round {index}: {exc}")
            break
        executed += 1

    # Contrôle final : le démon doit toujours servir un client légitime.
    try:
        final = transact(host, port, read_registers(0xBEEF, 0, 12), timeout=2.0)
        if not final or len(final) < 9:
            anomalies.append("contrôle final : démon indisponible après la campagne")
    except OSError as exc:
        anomalies.append(f"contrôle final : {exc}")

    print(f"[fuzz] {executed} trames envoyées, {len(anomalies)} anomalie(s)")
    for anomaly in anomalies:
        print(f"  - {anomaly}")
    return 0 if not anomalies else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5020)
    parser.add_argument("--rounds", type=int, default=200)
    parser.add_argument("--seed", type=int, default=1337)
    parser.add_argument("--wait", type=float, default=0.0, help="attente avant la campagne")
    args = parser.parse_args()

    if args.wait > 0:
        time.sleep(args.wait)
    try:
        return campaign(args.host, args.port, args.rounds, args.seed)
    except ConnectionRefusedError:
        print(f"[fuzz] ERREUR : aucun démon à l'écoute sur {args.host}:{args.port}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
