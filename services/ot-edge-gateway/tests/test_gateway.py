"""Tests unitaires et de conformité pour l'Edge Gateway OT et la Data Diode Simplex."""

from __future__ import annotations

import hashlib
import json
import struct
import uuid
from datetime import datetime, timezone
import pytest

from gateway.crypto import (
    generate_ed25519_keypair,
    load_private_key_from_raw_bytes,
    load_public_key_from_raw_bytes,
    private_key_to_raw_bytes,
    public_key_to_raw_bytes,
    sign_data,
    verify_signature,
)
from gateway.diode import (
    DIODE_MAGIC,
    HEADER_FORMAT,
    HEADER_SIZE_BYTES,
    PROTOCOL_VERSION,
    SEAL_SIZE_BYTES,
    DiodeError,
    DiodePacketBuilder,
    UDPSimplexEmitter,
)
from gateway.frames import (
    FrameValidationError,
    TelemetryFrame,
    canonical_json,
    utc_now_iso,
)
from gateway.poller import (
    ProcessSnapshot,
    decode_modbus_registers,
)


def test_ed25519_keypair_generation_and_export() -> None:
    """Valide la génération et la sérialisation des clés Ed25519 RFC 8032."""
    priv, pub = generate_ed25519_keypair()
    priv_bytes = private_key_to_raw_bytes(priv)
    pub_bytes = public_key_to_raw_bytes(pub)

    assert len(priv_bytes) == 32
    assert len(pub_bytes) == 32

    reloaded_priv = load_private_key_from_raw_bytes(priv_bytes)
    reloaded_pub = load_public_key_from_raw_bytes(pub_bytes)

    test_data = b"SecuriGlass Industrial Security Payload"
    sig = sign_data(reloaded_priv, test_data)
    assert len(sig) == 64
    assert verify_signature(reloaded_pub, test_data, sig) is True

    # Altération d'un octet : la signature doit être rejetée
    corrupted_data = test_data + b"!"
    assert verify_signature(reloaded_pub, corrupted_data, sig) is False


def test_telemetry_frame_validation_nominal() -> None:
    """Valide une trame de télémétrie conforme EN 12150."""
    frame = TelemetryFrame(
        line_id="FURNACE-LINE-01",
        sequence=42,
        measured_at=utc_now_iso(),
        values={
            "temp_zone1_c": 680.5,
            "temp_zone2_c": 700.0,
            "temp_zone3_c": 705.2,
            "temp_zone4_c": 690.0,
            "glass_pyrometer_temp_c": 645.0,
            "quench_pressure_bar": 4.5,
            "conveyor_speed_m_min": 12.0,
            "blower_current_amps": 45.0,
            "power_consumption_kw": 180.5,
            "emergency_stop_tripped": False,
            "plc_status_flags": 0x0001,
        },
    )
    data = frame.to_dict()
    assert data["line_id"] == "FURNACE-LINE-01"
    assert data["sequence"] == 42
    assert len(frame.canonical_bytes()) > 0


def test_telemetry_frame_validation_out_of_bounds() -> None:
    """Rejette les grandeurs physiques en dehors des plages autorisées."""
    # Température trop haute (> 850°C)
    with pytest.raises(FrameValidationError, match="hors tolérance EN 12150"):
        TelemetryFrame(
            line_id="LINE-01",
            sequence=1,
            measured_at=utc_now_iso(),
            values={"temp_zone1_c": 920.0},
        )

    # Pression trop haute (> 12.0 bar)
    with pytest.raises(FrameValidationError, match="quench_pressure_bar"):
        TelemetryFrame(
            line_id="LINE-01",
            sequence=1,
            measured_at=utc_now_iso(),
            values={"quench_pressure_bar": 15.0},
        )

    # Clé inconnue
    with pytest.raises(FrameValidationError, match="clés de métriques non autorisées"):
        TelemetryFrame(
            line_id="LINE-01",
            sequence=1,
            measured_at=utc_now_iso(),
            values={"malicious_key": 123.0},
        )


def test_canonical_json_determinism() -> None:
    """Garantit le déterminisme strict de la sérialisation JSON."""
    d1 = {"b": 2, "a": 1, "z": 9}
    d2 = {"z": 9, "a": 1, "b": 2}
    assert canonical_json(d1) == canonical_json(d2)
    assert canonical_json(d1) == b'{"a":1,"b":2,"z":9}'


def test_diode_packet_encapsulation_format() -> None:
    """Valide le format de trame binaire 64 octets + payload + 96 octets sceau."""
    emitter_uuid = uuid.uuid4()
    priv, pub = generate_ed25519_keypair()
    builder = DiodePacketBuilder(emitter_id=emitter_uuid, private_key=priv)

    frame = TelemetryFrame(
        line_id="LINE-01",
        sequence=100,
        measured_at=utc_now_iso(),
        values={"temp_zone1_c": 690.0, "emergency_stop_tripped": False},
    )

    packet = builder.build_packet(frame)

    # Vérification des tailles
    assert len(packet) >= 160
    header = packet[:HEADER_SIZE_BYTES]
    assert len(header) == 64

    # Dépaquetage en-tête
    magic, version, msg_type, seq, ts_us, emitter_bytes, payload_len, pad = (
        struct.unpack(HEADER_FORMAT, header)
    )
    assert magic == DIODE_MAGIC
    assert version == PROTOCOL_VERSION
    assert msg_type == 1
    assert seq == 100
    assert ts_us > 0
    assert emitter_bytes == emitter_uuid.bytes
    assert pad == b"\x00" * 20

    # Vérification de l'intégrité du corps et du sceau
    payload = packet[HEADER_SIZE_BYTES : HEADER_SIZE_BYTES + payload_len]
    assert len(payload) == payload_len
    seal = packet[HEADER_SIZE_BYTES + payload_len :]
    assert len(seal) == SEAL_SIZE_BYTES

    sha256_recv = seal[:32]
    sig_recv = seal[32:]

    # Recalcul de l'empreinte SHA-256
    expected_hash = hashlib.sha256(header[:44] + payload).digest()
    assert sha256_recv == expected_hash

    # Vérification de la signature Ed25519 sur le SHA-256
    assert verify_signature(pub, sha256_recv, sig_recv) is True


def test_diode_replay_protection_sequence() -> None:
    """Vérifie que l'émetteur diode rejette toute séquence non strictement croissante."""
    emitter_uuid = uuid.uuid4()
    priv, _ = generate_ed25519_keypair()
    builder = DiodePacketBuilder(emitter_id=emitter_uuid, private_key=priv)

    frame1 = TelemetryFrame(
        line_id="LINE-01",
        sequence=10,
        measured_at=utc_now_iso(),
        values={"temp_zone1_c": 600.0},
    )
    builder.build_packet(frame1)

    # Même séquence => Rejet
    frame_same = TelemetryFrame(
        line_id="LINE-01",
        sequence=10,
        measured_at=utc_now_iso(),
        values={"temp_zone1_c": 605.0},
    )
    with pytest.raises(DiodeError, match="Séquence non croissante"):
        builder.build_packet(frame_same)

    # Séquence antérieure => Rejet
    frame_lower = TelemetryFrame(
        line_id="LINE-01",
        sequence=9,
        measured_at=utc_now_iso(),
        values={"temp_zone1_c": 605.0},
    )
    with pytest.raises(DiodeError, match="Séquence non croissante"):
        builder.build_packet(frame_lower)


def test_modbus_register_decoding() -> None:
    """Valide la conversion des 12 Input Registers de l'automate four."""
    registers = [
        6850,  # Zone 1: 685.0 °C
        6900,  # Zone 2: 690.0 °C
        6950,  # Zone 3: 695.0 °C
        7000,  # Zone 4: 700.0 °C
        6500,  # Pyro: 650.0 °C
        450,  # Quench: 4.50 bar (x100)
        1200,  # Vitesse: 12.00 m/min (x100)
        2500,  # Blower: 2500 RPM
        1750,  # Puissance: 175.0 kW (x10)
        0b0101,  # Flags (Chauffe ON + E-STOP)
        2,  # Cycle HEATING
        0,  # Erreur 0
    ]
    snapshot = decode_modbus_registers(registers)
    assert snapshot.temp_zone1_c == 685.0
    assert snapshot.temp_zone4_c == 700.0
    assert snapshot.quench_pressure_bar == 4.5
    assert snapshot.conveyor_speed_m_min == 12.0
    assert snapshot.power_consumption_kw == 175.0
    assert snapshot.status_flags == 5
    assert snapshot.cycle_state == 2
