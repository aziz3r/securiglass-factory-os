"""Point d'entrée CLI pour la Passerelle OT SecuriGlass Edge Gateway."""

from __future__ import annotations

import argparse
import logging
import sys
import time
import uuid
from pathlib import Path

from .crypto import (
    generate_ed25519_keypair,
    load_private_key_from_raw_bytes,
    private_key_to_raw_bytes,
)
from .diode import DiodePacketBuilder, UDPSimplexEmitter
from .modbus_client import ModbusReadOnlyClient
from .poller import FurnacePoller


def main() -> int:
    parser = argparse.ArgumentParser(
        description="SecuriGlass OT Edge Gateway (Purdue 2-3)"
    )
    parser.add_argument(
        "--plc-host", default="127.0.0.1", help="Adresse IP du PLC Modbus TCP"
    )
    parser.add_argument(
        "--plc-port", type=int, default=5020, help="Port Modbus TCP du PLC"
    )
    parser.add_argument(
        "--diode-host", default="127.0.0.1", help="Adresse IP de la Data Diode / iDMZ"
    )
    parser.add_argument(
        "--diode-port",
        type=int,
        default=50005,
        help="Port UDP Simplex de la Data Diode",
    )
    parser.add_argument(
        "--line-id",
        default="LINE-FOUR-01",
        help="Identifiant de la ligne de production",
    )
    parser.add_argument(
        "--emitter-uuid",
        default="00000000-0000-0000-0000-000000000001",
        help="UUIDv4 de l'émetteur Edge Gateway",
    )
    parser.add_argument(
        "--key-file",
        type=Path,
        default=None,
        help="Chemin vers le fichier de clé privée Ed25519 (raw 32 octets)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Intervalle d'acquisition en secondes",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Exécute un seul cycle de scrutation et quitte",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Active les logs verbeux"
    )

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    logger = logging.getLogger("securiglass.ot.gateway.main")

    emitter_uuid = uuid.UUID(args.emitter_uuid)

    if args.key_file and args.key_file.is_file():
        raw_key = args.key_file.read_bytes()
        priv_key = load_private_key_from_raw_bytes(raw_key)
        logger.info("Clé Ed25519 chargée depuis %s", args.key_file)
    else:
        priv_key, pub_key = generate_ed25519_keypair()
        logger.info("Clé Ed25519 éphémère générée pour cette session")

    modbus_client = ModbusReadOnlyClient(host=args.plc_host, port=args.plc_port)
    builder = DiodePacketBuilder(emitter_id=emitter_uuid, private_key=priv_key)
    emitter = UDPSimplexEmitter(dest_host=args.diode_host, dest_port=args.diode_port)

    poller = FurnacePoller(
        modbus_client=modbus_client,
        packet_builder=builder,
        emitter=emitter,
        line_id=args.line_id,
    )

    logger.info(
        "Passerelle Edge OT démarrée : PLC %s:%d -> Diode %s:%d (Ligne: %s)",
        args.plc_host,
        args.plc_port,
        args.diode_host,
        args.diode_port,
        args.line_id,
    )

    try:
        if args.once:
            frame = poller.poll_once()
            logger.info("Cycle unique terminé : séquence %d", frame.sequence)
            return 0

        while True:
            try:
                frame = poller.poll_once()
                logger.info(
                    "Télémétrie émise : séquence %d, temps %s",
                    frame.sequence,
                    frame.measured_at,
                )
            except Exception as exc:
                logger.error("Erreur de cycle d'acquisition : %s", exc)
            time.sleep(args.interval)

    except KeyboardInterrupt:
        logger.info("Arrêt de la passerelle demandé par l'opérateur")
    finally:
        emitter.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
