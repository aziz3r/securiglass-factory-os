"""Tests unitaires pour le Récepteur Data Diode IT et le protocole Simplex unidirectionnel.

Conforme IEC 62443 / iDMZ Niveau 3.5 et spécification DATA_DIODE_SPEC.md.
"""

from __future__ import annotations

import hashlib
import json
import struct
import time
import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.services.diode_receiver import (
    DIODE_MAGIC,
    HEADER_FORMAT,
    HEADER_SIZE_BYTES,
    MSG_TYPE_FURNACE_TELEMETRY,
    PROTOCOL_VERSION,
    DiodeIngestResult,
    DiodeReceiverService,
    DiodeRejected,
    DiodeReplayError,
    DiodeSecurityError,
    ParsedDiodePacket,
)


def _create_signed_packet(
    emitter_id: uuid.UUID,
    private_key: ed25519.Ed25519PrivateKey,
    sequence: int = 1,
    payload_dict: dict | None = None,
    msg_type: int = MSG_TYPE_FURNACE_TELEMETRY,
    timestamp_us: int | None = None,
) -> bytes:
    """Helper pour construire un paquet binaire Data Diode valide."""
    if payload_dict is None:
        payload_dict = {
            "schema_version": 1,
            "line_id": "LINE-01",
            "sequence": sequence,
            "measured_at": datetime.now(timezone.utc).isoformat(),
            "values": {
                "temp_zone1_c": 680.0,
                "temp_zone2_c": 690.0,
                "temp_zone3_c": 695.0,
                "temp_zone4_c": 700.0,
                "glass_pyrometer_temp_c": 640.0,
                "quench_pressure_bar": 4.2,
                "conveyor_speed_m_min": 15.0,
                "blower_current_amps": 42.0,
                "power_consumption_kw": 165.0,
                "emergency_stop_tripped": False,
                "plc_status_flags": 1,
            },
        }

    payload_bytes = json.dumps(
        payload_dict, sort_keys=True, separators=(",", ":")
    ).encode("ascii")

    if timestamp_us is None:
        timestamp_us = int(time.time() * 1_000_000)

    header = struct.pack(
        HEADER_FORMAT,
        DIODE_MAGIC,
        PROTOCOL_VERSION,
        msg_type,
        sequence,
        timestamp_us,
        emitter_id.bytes,
        len(payload_bytes),
        b"\x00" * 20,
    )

    hash_input = header[:44] + payload_bytes
    sha256_digest = hashlib.sha256(hash_input).digest()
    sig = private_key.sign(sha256_digest)

    return header + payload_bytes + sha256_digest + sig


def test_diode_receiver_nominal_verification() -> None:
    """Vérifie le décodage et la validation réussie d'un paquet nominal."""
    emitter_id = uuid.uuid4()
    priv = ed25519.Ed25519PrivateKey.generate()
    pub = priv.public_key()

    service = DiodeReceiverService()
    service.register_gateway(emitter_id, pub)

    packet = _create_signed_packet(emitter_id, priv, sequence=1)
    parsed = service.verify_and_parse(packet)

    assert isinstance(parsed, ParsedDiodePacket)
    assert parsed.sequence == 1
    assert parsed.emitter_id == emitter_id
    assert parsed.msg_type == MSG_TYPE_FURNACE_TELEMETRY
    assert parsed.payload["line_id"] == "LINE-01"
    assert parsed.payload["values"]["temp_zone1_c"] == 680.0
    assert len(parsed.packet_sha256_hex) == 64
    assert len(parsed.ed25519_signature_hex) == 128
    assert service.get_last_seen_sequence(emitter_id) == 1


def test_diode_receiver_rejects_unauthorized_gateway() -> None:
    """Rejette les paquets émis par une passerelle non enregistrée."""
    emitter_id = uuid.uuid4()
    priv = ed25519.Ed25519PrivateKey.generate()

    service = DiodeReceiverService()  # Aucune passerelle enregistrée
    packet = _create_signed_packet(emitter_id, priv, sequence=1)

    with pytest.raises(DiodeRejected, match="untrusted_emitter"):
        service.verify_and_parse(packet)


def test_diode_receiver_rejects_corrupted_payload_checksum() -> None:
    """Détecte toute altération du payload même minime (rejet SHA-256)."""
    emitter_id = uuid.uuid4()
    priv = ed25519.Ed25519PrivateKey.generate()
    service = DiodeReceiverService({emitter_id: priv.public_key()})

    packet = bytearray(_create_signed_packet(emitter_id, priv, sequence=1))
    # Altération d'un octet au milieu du payload
    packet[HEADER_SIZE_BYTES + 5] ^= 0xFF

    with pytest.raises(DiodeRejected, match="bad_hash"):
        service.verify_and_parse(bytes(packet))


def test_diode_receiver_rejects_forged_signature() -> None:
    """Rejette une signature Ed25519 invalide ou produite par une autre clé."""
    emitter_id = uuid.uuid4()
    priv = ed25519.Ed25519PrivateKey.generate()
    forger_priv = ed25519.Ed25519PrivateKey.generate()

    # Le service attend la clé de priv, mais le paquet est signé avec forger_priv
    service = DiodeReceiverService({emitter_id: priv.public_key()})
    packet = _create_signed_packet(emitter_id, forger_priv, sequence=1)

    with pytest.raises(DiodeRejected, match="bad_signature"):
        service.verify_and_parse(packet)


def test_diode_receiver_rejects_invalid_magic() -> None:
    """Rejette immédiatement un paquet ayant un nombre magique non conforme."""
    emitter_id = uuid.uuid4()
    priv = ed25519.Ed25519PrivateKey.generate()
    service = DiodeReceiverService({emitter_id: priv.public_key()})

    packet = bytearray(_create_signed_packet(emitter_id, priv, sequence=1))
    packet[0:4] = b"XXXX"

    with pytest.raises(DiodeRejected, match="bad_magic"):
        service.verify_and_parse(bytes(packet))


def test_diode_receiver_replay_protection_sequence() -> None:
    """Vérifie la protection anti-rejeu par séquence strictement croissante."""
    emitter_id = uuid.uuid4()
    priv = ed25519.Ed25519PrivateKey.generate()
    service = DiodeReceiverService({emitter_id: priv.public_key()})

    # Paquet 1 : séquence 10 -> OK
    p1 = _create_signed_packet(emitter_id, priv, sequence=10)
    service.verify_and_parse(p1)

    # Paquet 2 : même séquence 10 -> REJET REJEU
    p2 = _create_signed_packet(emitter_id, priv, sequence=10)
    with pytest.raises(DiodeRejected, match="replay_or_stale_sequence"):
        service.verify_and_parse(p2)

    # Paquet 3 : séquence antérieure 9 -> REJET REJEU
    p3 = _create_signed_packet(emitter_id, priv, sequence=9)
    with pytest.raises(DiodeRejected, match="replay_or_stale_sequence"):
        service.verify_and_parse(p3)

    # Paquet 4 : séquence postérieure 11 -> OK
    p4 = _create_signed_packet(emitter_id, priv, sequence=11)
    res = service.verify_and_parse(p4)
    assert res.sequence == 11


def test_diode_receiver_clock_skew_tolerance() -> None:
    """Rejette les paquets dont le timestamp dérive de plus de 30 secondes."""
    emitter_id = uuid.uuid4()
    priv = ed25519.Ed25519PrivateKey.generate()
    service = DiodeReceiverService(
        {emitter_id: priv.public_key()}, clock_skew_tolerance_s=30.0
    )

    now_epoch = time.time()

    # Paquet avec 10s de retard -> OK
    p_ok = _create_signed_packet(
        emitter_id, priv, sequence=1, timestamp_us=int((now_epoch - 10.0) * 1_000_000)
    )
    service.verify_and_parse(p_ok, current_time_epoch=now_epoch)

    # Paquet avec 45s de retard -> REJET
    p_too_old = _create_signed_packet(
        emitter_id, priv, sequence=2, timestamp_us=int((now_epoch - 45.0) * 1_000_000)
    )
    with pytest.raises(DiodeRejected, match="clock_skew"):
        service.verify_and_parse(p_too_old, current_time_epoch=now_epoch)

    # Paquet avec 35s dans le futur -> REJET
    p_future = _create_signed_packet(
        emitter_id, priv, sequence=3, timestamp_us=int((now_epoch + 35.0) * 1_000_000)
    )
    with pytest.raises(DiodeRejected, match="clock_skew"):
        service.verify_and_parse(p_future, current_time_epoch=now_epoch)


@pytest.mark.asyncio
async def test_diode_receiver_ingest_db_integration() -> None:
    """Valide l'ingestion de la télémétrie et du journal d'import dans la session SQLAlchemy / asyncpg."""
    emitter_id = uuid.uuid4()
    priv = ed25519.Ed25519PrivateKey.generate()
    service = DiodeReceiverService({emitter_id: priv.public_key()})

    packet = _create_signed_packet(emitter_id, priv, sequence=1)

    # Mock conforme DbConn asyncpg
    mock_conn = MagicMock()
    mock_conn.transaction = MagicMock()
    mock_conn.transaction.return_value.__aenter__ = AsyncMock()
    mock_conn.transaction.return_value.__aexit__ = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value={"id": uuid.uuid4()})
    mock_conn.execute = AsyncMock(return_value="INSERT 0 1")

    result = await service.ingest_packet(packet, mock_conn)

    assert isinstance(result, DiodeIngestResult)
    assert result.success is True
    assert result.sequence == 1
    assert result.emitter_id == emitter_id
    assert result.records_count == 1

    # Vérification des appels transactionnels asyncpg
    mock_conn.fetchrow.assert_awaited_once()
    mock_conn.execute.assert_awaited_once()


def test_end_to_end_edge_gateway_to_diode_receiver() -> None:
    """Valide la chaîne complète : Edge Gateway OT (frames + builder) -> Récepteur IT (parse + verify)."""
    import sys
    from pathlib import Path

    gateway_path = str(Path(__file__).parents[2] / "services" / "ot-edge-gateway")
    if gateway_path not in sys.path:
        sys.path.insert(0, gateway_path)

    from gateway.crypto import generate_ed25519_keypair
    from gateway.diode import DiodePacketBuilder
    from gateway.frames import TelemetryFrame, utc_now_iso

    # 1. OT : Création des clés et de l'émetteur
    emitter_id = uuid.uuid4()
    priv_ot, pub_ot = generate_ed25519_keypair()
    builder = DiodePacketBuilder(emitter_id=emitter_id, private_key=priv_ot)

    # 2. IT : Enregistrement de la clé publique de la Gateway
    rx_service = DiodeReceiverService({emitter_id: pub_ot})

    # 3. OT : Capture Modbus simulée et génération trame
    frame = TelemetryFrame(
        line_id="FURNACE-L01",
        sequence=101,
        measured_at=utc_now_iso(),
        values={
            "temp_zone1_c": 690.0,
            "temp_zone2_c": 705.5,
            "temp_zone3_c": 702.0,
            "temp_zone4_c": 698.0,
            "glass_pyrometer_temp_c": 655.0,
            "quench_pressure_bar": 5.2,
            "conveyor_speed_m_min": 14.5,
            "blower_current_amps": 52.0,
            "power_consumption_kw": 195.0,
            "emergency_stop_tripped": False,
            "plc_status_flags": 3,
        },
    )
    raw_datagram = builder.build_packet(frame)

    # 4. IT : Réception et vérification de conformité
    verified = rx_service.verify_and_parse(raw_datagram)
    assert verified.sequence == 101
    assert verified.emitter_id == emitter_id
    assert verified.line_code == "FURNACE-L01"
    assert verified.values["temp_zone2_c"] == 705.5
    assert verified.values["quench_pressure_bar"] == 5.2
    assert rx_service.get_last_seen_sequence(emitter_id) == 101

    # 5. Tentative de rejeu de la même trame -> Rejet
    with pytest.raises(DiodeRejected, match="replay_or_stale_sequence"):
        rx_service.verify_and_parse(raw_datagram)
