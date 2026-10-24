"""Encapsulation et émetteur UDP Simplex pour SecuriGlass Data Diode.

Spécification : DATA_DIODE_SPEC.md (IEC 62443 / iDMZ Niveau 3.5).
Format binaire :
  - En-tête fixe 64 octets (Magic SGDD, Version 2, Type, Seq, Timestamp, UUID, Len, Pad)
  - Corps de télémétrie (JSON canonique UTF-8)
  - Sceau cryptographique 96 octets : SHA-256 (32 octets) + Signature Ed25519 (64 octets)
Garantie Simplex : Zéro canal de retour, aucun ACK vers la zone OT.
"""

from __future__ import annotations

import hashlib
import socket
import struct
import time
import uuid
from typing import Final

from cryptography.hazmat.primitives.asymmetric import ed25519

from .crypto import sign_data
from .frames import TelemetryFrame

# Constantes protocole Data Diode v2.0
DIODE_MAGIC: Final[bytes] = b"SGDD"  # 0x53474444
PROTOCOL_VERSION: Final[int] = 0x0002
HEADER_FORMAT: Final[str] = "!4sHHQQ16sI20s"
HEADER_SIZE_BYTES: Final[int] = struct.calcsize(HEADER_FORMAT)  # 64 octets
HEADER_HASHABLE_BYTES: Final[int] = 44  # Header[0..43]
SHA256_SIZE_BYTES: Final[int] = 32
SIGNATURE_SIZE_BYTES: Final[int] = 64
SEAL_SIZE_BYTES: Final[int] = SHA256_SIZE_BYTES + SIGNATURE_SIZE_BYTES  # 96 octets
MIN_PACKET_SIZE_BYTES: Final[int] = HEADER_SIZE_BYTES + SEAL_SIZE_BYTES  # 160 octets

# Types de messages
MSG_TYPE_FURNACE_TELEMETRY: Final[int] = 0x0001
MSG_TYPE_AUTOCLAVE_TELEMETRY: Final[int] = 0x0002


class DiodeError(RuntimeError):
    """Erreur de validation ou d'émission de la diode."""


class DiodePacketBuilder:
    """Construit et scelle cryptographiquement les paquets Data Diode."""

    def __init__(
        self,
        emitter_id: uuid.UUID,
        private_key: ed25519.Ed25519PrivateKey,
    ) -> None:
        self.emitter_id = emitter_id
        self._private_key = private_key
        self._last_sequence = 0

    def build_packet(
        self,
        frame: TelemetryFrame,
        msg_type: int = MSG_TYPE_FURNACE_TELEMETRY,
    ) -> bytes:
        """Encapsule une trame de télémétrie dans un datagramme binaire scellé."""
        # 1. Vérification de la séquence strictement croissante
        if frame.sequence <= self._last_sequence:
            raise DiodeError(
                f"Séquence non croissante détectée ({frame.sequence} <= {self._last_sequence})"
            )
        self._last_sequence = frame.sequence

        # 2. Payload canonique
        payload_bytes = frame.canonical_bytes()
        payload_len = len(payload_bytes)

        # 3. Horodatage en microsecondes depuis l'époque Unix
        timestamp_us = int(time.time() * 1_000_000)

        # 4. En-tête binaire 64 octets
        padding = b"\x00" * 20
        header = struct.pack(
            HEADER_FORMAT,
            DIODE_MAGIC,
            PROTOCOL_VERSION,
            msg_type,
            frame.sequence,
            timestamp_us,
            self.emitter_id.bytes,
            payload_len,
            padding,
        )

        # 5. Calcul de l'empreinte SHA-256 sur Header[0..43] + Payload
        hash_input = header[:HEADER_HASHABLE_BYTES] + payload_bytes
        sha256_digest = hashlib.sha256(hash_input).digest()

        # 6. Signature Ed25519 sur le hash SHA-256
        signature = sign_data(self._private_key, sha256_digest)

        # 7. Assemblage : Header (64) + Payload (N) + SHA-256 (32) + Signature (64)
        return header + payload_bytes + sha256_digest + signature


class UDPSimplexEmitter:
    """Émetteur Simplex UDP Unidirectionnel (TX strict, aucun canal de retour)."""

    def __init__(
        self,
        dest_host: str = "127.0.0.1",
        dest_port: int = 50005,
        *,
        redundancy: int = 1,
    ) -> None:
        if not 1 <= dest_port <= 65535:
            raise ValueError(f"Port UDP de destination invalide : {dest_port}")
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.redundancy = max(1, min(redundancy, 3))
        # Socket UDP non relié en réception (aucun bind, aucun recv)
        self._sock: socket.socket | None = socket.socket(
            socket.AF_INET, socket.SOCK_DGRAM
        )
        self._emitted_count = 0

    @property
    def emitted_count(self) -> int:
        return self._emitted_count

    def emit(self, packet: bytes) -> None:
        """Émet le paquet UDP sans attendre d'acquittement (aveugle/simplex)."""
        if self._sock is None:
            raise DiodeError("Émetteur diode fermé")

        # Émission redondante si demandée pour compenser l'absence d'ACK sur canal simplex
        for _ in range(self.redundancy):
            self._sock.sendto(packet, (self.dest_host, self.dest_port))
        self._emitted_count += 1

    def close(self) -> None:
        """Ferme la socket d'émission."""
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def __enter__(self) -> UDPSimplexEmitter:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
