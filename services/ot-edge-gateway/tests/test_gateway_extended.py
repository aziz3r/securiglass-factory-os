"""Tests exhaustifs étendus pour la passerelle SecuriGlass OT Edge Gateway.

Couvre :
- modbus_client.py : Mock TCP sockets, MBAP header checks, exception frames, PDU errors.
- poller.py : FurnacePoller, decode_modbus_registers erreurs et valeurs limites, E-stop flags.
- diode.py : UDPSimplexEmitter, context managers, redondance, erreurs de socket fermée.
- frames.py : validation des champs, dates naïves, caractères interdits, oversize JSON.
- __main__.py : arguments CLI, chargement de clé sur disque vs éphémère, option --once.
"""

from __future__ import annotations

import io
import json
import socket
import struct
import sys
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from gateway.__main__ import main as gateway_main
from gateway.crypto import (
    generate_ed25519_keypair,
    private_key_to_raw_bytes,
)
from gateway.diode import (
    DIODE_MAGIC,
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
from gateway.modbus_client import (
    MBAP_HEADER_FORMAT,
    ModbusExceptionResponse,
    ModbusProtocolError,
    ModbusReadOnlyClient,
    _recv_exact,
)
from gateway.poller import (
    INPUT_REGISTER_COUNT,
    STATUS_FLAG_E_STOP_ACTIVE,
    FurnacePoller,
    decode_modbus_registers,
)


# ==============================================================================
# 1. TESTS MODBUS CLIENT (MOCK SOCKET TCP)
# ==============================================================================


def test_recv_exact_premature_close() -> None:
    """_recv_exact lève ModbusProtocolError si la connexion se ferme avant la taille requise."""
    mock_sock = MagicMock()
    mock_sock.recv.side_effect = [
        b"123",
        b"",
    ]  # Fini après 3 octets alors qu'on en attend 5
    with pytest.raises(ModbusProtocolError, match="Connexion TCP fermée"):
        _recv_exact(mock_sock, 5)


def test_modbus_client_invalid_init_parameters() -> None:
    """Validation des paramètres d'initialisation du client Modbus."""
    with pytest.raises(ValueError, match="unit_id Modbus invalide"):
        ModbusReadOnlyClient(unit_id=0)
    with pytest.raises(ValueError, match="unit_id Modbus invalide"):
        ModbusReadOnlyClient(unit_id=250)
    with pytest.raises(ValueError, match="Port Modbus invalide"):
        ModbusReadOnlyClient(port=0)
    with pytest.raises(ValueError, match="Port Modbus invalide"):
        ModbusReadOnlyClient(port=70000)


def test_modbus_client_invalid_read_parameters() -> None:
    """Validation des adresses et compteurs de registres."""
    client = ModbusReadOnlyClient()
    with pytest.raises(ValueError, match="Adresse de registre hors bornes"):
        client._execute_read(0x04, -1, 10)
    with pytest.raises(ValueError, match="Adresse de registre hors bornes"):
        client._execute_read(0x04, 0x10000, 10)
    with pytest.raises(ValueError, match="Quantité de registres invalide"):
        client._execute_read(0x04, 0, 0)
    with pytest.raises(ValueError, match="Quantité de registres invalide"):
        client._execute_read(0x04, 0, 126)


def test_modbus_client_read_input_and_holding_nominal() -> None:
    """Test nominal de lecture de registres d'entrée et de maintien avec socket mocké."""
    client = ModbusReadOnlyClient(unit_id=1)

    # Réponse simulée : TID=1, PID=0, LEN=7, UID=1, FC=0x04, ByteCount=4, Val1=6800, Val2=6900
    mbap_resp = struct.pack(MBAP_HEADER_FORMAT, 1, 0, 7, 1)
    body_resp = bytes([0x04, 4]) + struct.pack(">HH", 6800, 6900)

    with patch("socket.create_connection") as mock_connect:
        mock_sock = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.side_effect = [mbap_resp, body_resp]

        registers = client.read_input_registers(address=0, count=2)
        assert registers == [6800, 6900]

    # Test holding registers
    mbap_resp_hold = struct.pack(MBAP_HEADER_FORMAT, 2, 0, 7, 1)
    body_resp_hold = bytes([0x03, 4]) + struct.pack(">HH", 500, 1200)
    with patch("socket.create_connection") as mock_connect:
        mock_sock = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.side_effect = [mbap_resp_hold, body_resp_hold]

        holding = client.read_holding_registers(address=0, count=2)
        assert holding == [500, 1200]


def test_modbus_client_context_manager() -> None:
    """Vérifie le fonctionnement du context manager."""
    with ModbusReadOnlyClient() as client:
        assert client.host == "127.0.0.1"


def test_modbus_client_protocol_errors() -> None:
    """Test des détections d'erreurs de protocole Modbus (TID, PID, UID, LEN, etc.)."""
    client = ModbusReadOnlyClient(unit_id=1)

    # 1. TID mismatch
    with patch("socket.create_connection") as mock_connect:
        mock_sock = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.side_effect = [
            struct.pack(MBAP_HEADER_FORMAT, 999, 0, 5, 1),
            b"\x04\x02\x00\x00",
        ]
        with pytest.raises(
            ModbusProtocolError, match="Désynchronisation de transaction TID"
        ):
            client.read_input_registers(0, 1)

    # 2. Protocol ID != 0
    with patch("socket.create_connection") as mock_connect:
        mock_sock = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.side_effect = [
            struct.pack(MBAP_HEADER_FORMAT, client._transaction_id + 1, 1, 5, 1),
            b"\x04\x02\x00\x00",
        ]
        with pytest.raises(ModbusProtocolError, match="Protocole ID Modbus invalide"):
            client.read_input_registers(0, 1)

    # 3. Unit ID mismatch
    with patch("socket.create_connection") as mock_connect:
        mock_sock = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.side_effect = [
            struct.pack(MBAP_HEADER_FORMAT, client._transaction_id + 1, 0, 5, 2),
            b"\x04\x02\x00\x00",
        ]
        with pytest.raises(ModbusProtocolError, match="Unit ID invalide"):
            client.read_input_registers(0, 1)

    # 4. Length field invalid (< 2 ou > 256)
    with patch("socket.create_connection") as mock_connect:
        mock_sock = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.side_effect = [
            struct.pack(MBAP_HEADER_FORMAT, client._transaction_id + 1, 0, 1, 1),
            b"",
        ]
        with pytest.raises(ModbusProtocolError, match="Champ Longueur MBAP invalide"):
            client.read_input_registers(0, 1)

    # 5. FC mismatch (reçu 0x01 au lieu de 0x04)
    with patch("socket.create_connection") as mock_connect:
        mock_sock = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.side_effect = [
            struct.pack(MBAP_HEADER_FORMAT, client._transaction_id + 1, 0, 5, 1),
            b"\x01\x02\x00\x00",
        ]
        with pytest.raises(ModbusProtocolError, match="Code fonction inattendu"):
            client.read_input_registers(0, 1)

    # 6. Byte count mismatch
    with patch("socket.create_connection") as mock_connect:
        mock_sock = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.side_effect = [
            struct.pack(MBAP_HEADER_FORMAT, client._transaction_id + 1, 0, 5, 1),
            b"\x04\x04\x00\x00",  # count attendu 1 reg = 2 octets, reçu byte_count = 4
        ]
        with pytest.raises(
            ModbusProtocolError, match="Nombre d'octets retournés invalide"
        ):
            client.read_input_registers(0, 1)

    # 7. Data bytes length mismatch
    with patch("socket.create_connection") as mock_connect:
        mock_sock = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_sock
        mock_sock.recv.side_effect = [
            struct.pack(MBAP_HEADER_FORMAT, client._transaction_id + 1, 0, 4, 1),
            b"\x04\x02\x00",  # byte_count dit 2, mais 1 seul octet suit
        ]
        with pytest.raises(
            ModbusProtocolError, match="Taille des données de registres incohérente"
        ):
            client.read_input_registers(0, 1)


def test_modbus_client_exception_response() -> None:
    """L'automate renvoie un code d'exception Modbus (ex: 0x84, code 0x02 ILLEGAL DATA ADDR)."""
    client = ModbusReadOnlyClient(unit_id=1)

    with patch("socket.create_connection") as mock_connect:
        mock_sock = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_sock
        # MBAP: TID, PID=0, LEN=3 (UID + FC + EXC), UID=1
        mbap = struct.pack(MBAP_HEADER_FORMAT, client._transaction_id + 1, 0, 3, 1)
        body = bytes([0x84, 0x02])  # FC 0x04 | 0x80 = 0x84, exception 0x02
        mock_sock.recv.side_effect = [mbap, body]

        with pytest.raises(ModbusExceptionResponse) as exc_info:
            client.read_input_registers(0, 10)
        assert exc_info.value.function_code == 0x04
        assert exc_info.value.exception_code == 0x02

    # Exception tronquée
    with patch("socket.create_connection") as mock_connect:
        mock_sock = MagicMock()
        mock_connect.return_value.__enter__.return_value = mock_sock
        mbap = struct.pack(MBAP_HEADER_FORMAT, client._transaction_id + 1, 0, 2, 1)
        body = bytes([0x84])  # Pas d'octet de code exception
        mock_sock.recv.side_effect = [mbap, body]

        with pytest.raises(
            ModbusProtocolError, match="PDU d'exception Modbus tronquée"
        ):
            client.read_input_registers(0, 10)


# ==============================================================================
# 2. TESTS POLLER ET DECODEUR
# ==============================================================================


def test_decode_modbus_registers_insufficient_length() -> None:
    """Taille inférieure aux 12 registres obligatoires lève ValueError."""
    with pytest.raises(ValueError, match="Taille de registres insuffisante"):
        decode_modbus_registers([0] * 11)


def test_furnace_poller_poll_once_nominal_and_estop() -> None:
    """Exécution complète de poll_once() avec validation des grandeurs et émission."""
    mock_modbus = MagicMock(spec=ModbusReadOnlyClient)
    # 12 registres : z1, z2, z3, z4, pyro, quench, speed, rpm, power, flags, state, err
    # z1: 6850 (685.0°C), z2: 6900, z3: 6950, z4: 7000, pyro: 6400 (640.0°C)
    # quench: 450 (4.50 bar), speed: 1500 (15.00 m/min), rpm: 2100 (42.0 A), power: 1650 (165.0 kW)
    # flags: STATUS_FLAG_E_STOP_ACTIVE (1 << 2) = 4
    registers_estop = [6850, 6900, 6950, 7000, 6400, 450, 1500, 2100, 1650, 4, 1, 0]
    mock_modbus.read_input_registers.return_value = registers_estop

    priv, _ = generate_ed25519_keypair()
    builder = DiodePacketBuilder(emitter_id=uuid.uuid4(), private_key=priv)
    mock_emitter = MagicMock(spec=UDPSimplexEmitter)

    poller = FurnacePoller(
        modbus_client=mock_modbus,
        packet_builder=builder,
        emitter=mock_emitter,
        line_id="FURNACE-01",
        initial_sequence=1,
    )

    frame = poller.poll_once()
    assert frame.line_id == "FURNACE-01"
    assert frame.sequence == 1
    assert frame.values["temp_zone1_c"] == 685.0
    assert frame.values["quench_pressure_bar"] == 4.5
    assert frame.values["emergency_stop_tripped"] is True

    # Vérification que l'émetteur a reçu le paquet binaire
    mock_emitter.emit.assert_called_once()
    packet = mock_emitter.emit.call_args[0][0]
    assert packet.startswith(DIODE_MAGIC)


# ==============================================================================
# 3. TESTS DIODE ET UDP SIMPLEX EMITTER
# ==============================================================================


def test_udp_simplex_emitter_parameters_and_lifecycle() -> None:
    """Cycle de vie et redondance de l'émetteur Simplex UDP."""
    with pytest.raises(ValueError, match="Port UDP de destination invalide"):
        UDPSimplexEmitter(dest_port=0)
    with pytest.raises(ValueError, match="Port UDP de destination invalide"):
        UDPSimplexEmitter(dest_port=70000)

    # Redondance bornée entre 1 et 3
    emitter = UDPSimplexEmitter(redundancy=5)
    assert emitter.redundancy == 3
    emitter_low = UDPSimplexEmitter(redundancy=0)
    assert emitter_low.redundancy == 1

    # Émission et fermeture
    with patch("socket.socket.sendto") as mock_sendto:
        with UDPSimplexEmitter(
            dest_host="127.0.0.1", dest_port=50005, redundancy=2
        ) as em:
            em.emit(b"TEST_PACKET")
            assert em.emitted_count == 1
            assert mock_sendto.call_count == 2

    # Émission après fermeture -> DiodeError
    em_closed = UDPSimplexEmitter()
    em_closed.close()
    with pytest.raises(DiodeError, match="Émetteur diode fermé"):
        em_closed.emit(b"FAIL")


# ==============================================================================
# 4. TESTS FRAMES ET VALIDATION DE SCHÉMA
# ==============================================================================


def test_telemetry_frame_validation_edge_cases() -> None:
    """Cas limites et validations approfondies de TelemetryFrame."""
    valid_values = {
        "temp_zone1_c": 680.0,
        "temp_zone2_c": 680.0,
        "temp_zone3_c": 680.0,
        "temp_zone4_c": 680.0,
        "glass_pyrometer_temp_c": 640.0,
        "quench_pressure_bar": 4.0,
        "conveyor_speed_m_min": 10.0,
    }

    # 1. line_id invalide
    with pytest.raises(FrameValidationError, match="line_id invalide"):
        TelemetryFrame(
            line_id="", sequence=1, measured_at=utc_now_iso(), values=valid_values
        )
    with pytest.raises(
        FrameValidationError, match="line_id contient des caractères interdits"
    ):
        TelemetryFrame(
            line_id="LINE@01",
            sequence=1,
            measured_at=utc_now_iso(),
            values=valid_values,
        )

    # 2. sequence booléenne ou hors bornes
    with pytest.raises(
        FrameValidationError, match="sequence doit être un entier non-booléen"
    ):
        TelemetryFrame(line_id="L1", sequence=True, measured_at=utc_now_iso(), values=valid_values)  # type: ignore[arg-type]
    with pytest.raises(FrameValidationError, match="sequence hors bornes uint64"):
        TelemetryFrame(
            line_id="L1", sequence=-1, measured_at=utc_now_iso(), values=valid_values
        )

    # 3. measured_at invalide ou sans timezone (naïf)
    with pytest.raises(
        FrameValidationError, match="measured_at n'est pas une date ISO-8601"
    ):
        TelemetryFrame(
            line_id="L1", sequence=1, measured_at="non-date", values=valid_values
        )
    with pytest.raises(
        FrameValidationError, match="measured_at doit être timezone-aware"
    ):
        TelemetryFrame(
            line_id="L1",
            sequence=1,
            measured_at="2026-10-24T18:00:00",
            values=valid_values,
        )

    # 4. batch_id invalide
    with pytest.raises(FrameValidationError, match="batch_id invalide"):
        TelemetryFrame(
            line_id="L1",
            sequence=1,
            measured_at=utc_now_iso(),
            values=valid_values,
            batch_id="",
        )

    # 5. Métriques vides
    with pytest.raises(FrameValidationError, match="trame de métriques vide"):
        TelemetryFrame(line_id="L1", sequence=1, measured_at=utc_now_iso(), values={})

    # 6. NaN ou Infinity
    with pytest.raises(
        FrameValidationError, match="temp_zone1_c doit être un nombre fini"
    ):
        TelemetryFrame(
            line_id="L1",
            sequence=1,
            measured_at=utc_now_iso(),
            values={**valid_values, "temp_zone1_c": float("nan")},
        )

    # 7. Type booléen au lieu de float pour une mesure
    with pytest.raises(
        FrameValidationError, match="temp_zone1_c doit être une valeur numérique"
    ):
        TelemetryFrame(line_id="L1", sequence=1, measured_at=utc_now_iso(), values={**valid_values, "temp_zone1_c": False})  # type: ignore[dict-item]

    # 8. emergency_stop_tripped mauvais type
    with pytest.raises(
        FrameValidationError, match="emergency_stop_tripped doit être un booléen"
    ):
        TelemetryFrame(line_id="L1", sequence=1, measured_at=utc_now_iso(), values={**valid_values, "emergency_stop_tripped": "yes"})  # type: ignore[dict-item]

    # 9. plc_status_flags mauvais type ou hors bornes
    with pytest.raises(
        FrameValidationError, match="plc_status_flags doit être un entier"
    ):
        TelemetryFrame(line_id="L1", sequence=1, measured_at=utc_now_iso(), values={**valid_values, "plc_status_flags": True})  # type: ignore[dict-item]
    with pytest.raises(
        FrameValidationError, match="plc_status_flags hors bornes uint16"
    ):
        TelemetryFrame(
            line_id="L1",
            sequence=1,
            measured_at=utc_now_iso(),
            values={**valid_values, "plc_status_flags": 0x10000},
        )


# ==============================================================================
# 5. TESTS CLI GATEWAY (__main__.py)
# ==============================================================================


def test_gateway_cli_once_mode(tmp_path: Path) -> None:
    """Test de la commande CLI en mode --once."""
    # Création d'une clé privée sur disque
    key_file = tmp_path / "ed25519.key"
    priv, _ = generate_ed25519_keypair()
    key_file.write_bytes(private_key_to_raw_bytes(priv))

    mock_modbus = MagicMock()
    mock_modbus.read_input_registers.return_value = [
        6850,
        6900,
        6950,
        7000,
        6400,
        450,
        1500,
        2100,
        1650,
        1,
        1,
        0,
    ]

    with patch(
        "gateway.__main__.ModbusReadOnlyClient", return_value=mock_modbus
    ), patch("gateway.__main__.UDPSimplexEmitter") as mock_emitter_cls, patch(
        "sys.argv", ["gateway", "--once", "--key-file", str(key_file), "-v"]
    ):

        mock_emitter = MagicMock()
        mock_emitter_cls.return_value = mock_emitter

        ret = gateway_main()
        assert ret == 0
        mock_emitter.close.assert_called_once()


def test_gateway_cli_keyboard_interrupt() -> None:
    """Gestion propre de KeyboardInterrupt lors de la boucle continue."""
    with patch("gateway.__main__.FurnacePoller") as mock_poller_cls, patch(
        "gateway.__main__.UDPSimplexEmitter"
    ) as mock_emitter_cls, patch("sys.argv", ["gateway", "--interval", "0.01"]):

        mock_poller = MagicMock()
        mock_poller.poll_once.side_effect = KeyboardInterrupt
        mock_poller_cls.return_value = mock_poller
        mock_emitter = MagicMock()
        mock_emitter_cls.return_value = mock_emitter

        ret = gateway_main()
        assert ret == 0
        mock_emitter.close.assert_called_once()
