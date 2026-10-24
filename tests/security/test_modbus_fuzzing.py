"""Tests de sécurité offensifs & Fuzzing intensif du serveur Modbus TCP (Automate C).

Conformité : IEC 62443-3-3, IEC 62443-4-2 (Communication integrity), Modbus V1.1b3.
Vérifie la robustesse de l'implémentation C :
- Codes de fonctions illégaux -> Exception 0x01
- Adresses de registres hors limites -> Exception 0x02
- Compteurs de registres invalides -> Exception 0x03
- Trames tronquées et en-têtes MBAP corrompues
- Résilience absolue (0 crash, 0 overflow) face à 5 000 trames de fuzzing aléatoire
"""

from __future__ import annotations

import ctypes
import os
import random
import struct
from pathlib import Path
from typing import Generator

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_LIB_PATH = _REPO_ROOT / "services" / "ot-plc-daemon" / "bin" / "libplc.dylib"

if not _LIB_PATH.is_file():
    # Compilation dynamique automatique si la lib n'existe pas
    import subprocess

    subprocess.run(
        [
            "clang",
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-pedantic",
            "-D_POSIX_C_SOURCE=200809L",
            "-Iinclude",
            "-pthread",
            "-O2",
            "-fPIC",
            "-shared",
            "-o",
            "bin/libplc.dylib",
            "src/plc_simulator.c",
            "src/plc_modbus.c",
            "-lm",
        ],
        cwd=str(_REPO_ROOT / "services" / "ot-plc-daemon"),
        check=True,
    )

_lib = ctypes.CDLL(str(_LIB_PATH))


@pytest.fixture
def plc_ctx() -> Generator[ctypes.Array[ctypes.c_char], None, None]:
    """Alloue et initialise un contexte automate C pour chaque test."""
    ctx = ctypes.create_string_buffer(2048)
    _lib.plc_simulator_init(ctx)
    yield ctx
    _lib.plc_simulator_destroy(ctx)


def _process_frame(ctx: ctypes.Array[ctypes.c_char], req_bytes: bytes) -> bytes:
    """Passe une trame brute à l'automate C et retourne la réponse binaire."""
    resp_buf = ctypes.create_string_buffer(512)
    resp_len = _lib.plc_modbus_process_frame(
        ctx, req_bytes, len(req_bytes), resp_buf, 512
    )
    if resp_len > 0:
        return bytes(resp_buf[:resp_len])
    return b""


def _build_mbap(tx_id: int, pdu_len: int, unit_id: int = 1, proto_id: int = 0) -> bytes:
    return struct.pack("!HHHB", tx_id, proto_id, pdu_len, unit_id)


# ============================================================================
# 1. TESTS NOMINAUX MODBUS EN C
# ============================================================================


def test_modbus_c_nominal_read_input_registers(
    plc_ctx: ctypes.Array[ctypes.c_char],
) -> None:
    """Lecture des Input Registers 30001..30004 (FC 0x04)."""
    pdu = struct.pack("!BHH", 0x04, 0, 4)
    req = _build_mbap(tx_id=1, pdu_len=len(pdu) + 1) + pdu

    resp = _process_frame(plc_ctx, req)
    assert len(resp) == 7 + 1 + 1 + 8  # MBAP (7) + FC (1) + ByteCount (1) + 8B (4 reg)
    assert resp[7] == 0x04
    assert resp[8] == 8


def test_modbus_c_nominal_read_discrete_inputs(
    plc_ctx: ctypes.Array[ctypes.c_char],
) -> None:
    """Lecture des Discrete Inputs 10001..10004 (FC 0x02)."""
    pdu = struct.pack("!BHH", 0x02, 0, 4)
    req = _build_mbap(tx_id=2, pdu_len=len(pdu) + 1) + pdu

    resp = _process_frame(plc_ctx, req)
    assert len(resp) == 10
    assert resp[7] == 0x02
    assert resp[8] == 1  # 1 octet pour 4 bits


def test_modbus_c_write_holding_register_setpoint(
    plc_ctx: ctypes.Array[ctypes.c_char],
) -> None:
    """Écriture d'une consigne thermique autorisée (FC 0x06, 710.0 °C = 7100)."""
    pdu = struct.pack("!BHH", 0x06, 0, 7100)
    req = _build_mbap(tx_id=3, pdu_len=len(pdu) + 1) + pdu

    resp = _process_frame(plc_ctx, req)
    assert len(resp) == 12  # Écho de la requête en cas de succès
    assert resp[7] == 0x06


# ============================================================================
# 2. FUZZING : CODES DE FONCTION ILLÉGAUX (EXCEPTION 0x01)
# ============================================================================


@pytest.mark.parametrize(
    "illegal_fc", [0x00, 0x07, 0x08, 0x0B, 0x11, 0x14, 0x17, 0x2A, 0x7F, 0xFF]
)
def test_modbus_c_illegal_function_codes(
    plc_ctx: ctypes.Array[ctypes.c_char], illegal_fc: int
) -> None:
    """Vérifie le retour strict de l'exception 0x01 (ILLEGAL FUNCTION)."""
    pdu = struct.pack("!BHH", illegal_fc, 0, 1)
    req = _build_mbap(tx_id=42, pdu_len=len(pdu) + 1) + pdu

    resp = _process_frame(plc_ctx, req)
    assert len(resp) == 9
    assert resp[7] == (illegal_fc | 0x80)
    assert resp[8] == 0x01  # MB_EXC_ILLEGAL_FUNCTION


# ============================================================================
# 3. FUZZING : ADRESSES ET VALEURS HORS LIMITES (EXCEPTIONS 0x02 ET 0x03)
# ============================================================================


def test_modbus_c_illegal_register_address(
    plc_ctx: ctypes.Array[ctypes.c_char],
) -> None:
    """Accès à une adresse hors limites -> Exception 0x02 (ILLEGAL DATA ADDRESS)."""
    # Input register 0xFFFF
    pdu = struct.pack("!BHH", 0x04, 0xFFFF, 1)
    req = _build_mbap(tx_id=10, pdu_len=len(pdu) + 1) + pdu

    resp = _process_frame(plc_ctx, req)
    assert len(resp) == 9
    assert resp[7] == (0x04 | 0x80)
    assert resp[8] == 0x02


def test_modbus_c_illegal_register_count(plc_ctx: ctypes.Array[ctypes.c_char]) -> None:
    """Compteur nul ou en dépassement de PDU -> Exception Modbus (0x02 ou 0x03)."""
    # 1. Count = 0
    pdu_zero = struct.pack("!BHH", 0x04, 0, 0)
    resp_zero = _process_frame(
        plc_ctx, _build_mbap(tx_id=11, pdu_len=len(pdu_zero) + 1) + pdu_zero
    )
    assert len(resp_zero) == 9
    assert resp_zero[7] == (0x04 | 0x80)
    assert resp_zero[8] in (0x02, 0x03)

    # 2. Count = 126 (dépassement max PDU Modbus 125)
    pdu_max = struct.pack("!BHH", 0x04, 0, 126)
    resp_max = _process_frame(
        plc_ctx, _build_mbap(tx_id=12, pdu_len=len(pdu_max) + 1) + pdu_max
    )
    assert len(resp_max) == 9
    assert resp_max[7] == (0x04 | 0x80)
    assert resp_max[8] in (0x02, 0x03)


def test_modbus_c_write_out_of_bounds_setpoint_rejected(
    plc_ctx: ctypes.Array[ctypes.c_char],
) -> None:
    """Tentative de surchauffe destructrice : consigne T° à 1200°C (12000) -> Exception 0x03."""
    pdu = struct.pack("!BHH", 0x06, 0, 12000)
    req = _build_mbap(tx_id=13, pdu_len=len(pdu) + 1) + pdu

    resp = _process_frame(plc_ctx, req)
    assert len(resp) == 9
    assert resp[7] == (0x06 | 0x80)
    assert resp[8] == 0x03  # Valeur illégale


# ============================================================================
# 4. FUZZING : TRAMES TRONQUÉES & PROTOCOLE NON CONFORME
# ============================================================================


def test_modbus_c_truncated_frames_rejected(
    plc_ctx: ctypes.Array[ctypes.c_char],
) -> None:
    """Trames tronquées (< 7 octets MBAP) doivent être ignorées sans réponse."""
    sample = b"\x00\x01\x00\x00\x00\x06\x01\x04\x00\x00\x00\x04"
    for length in range(7):
        resp = _process_frame(plc_ctx, sample[:length])
        assert resp == b"", f"Une trame de {length} octets doit être rejetée"


def test_modbus_c_invalid_protocol_id_ignored(
    plc_ctx: ctypes.Array[ctypes.c_char],
) -> None:
    """Protocol ID non nul (ex: 0x1234) -> Trame ignorée."""
    pdu = struct.pack("!BHH", 0x04, 0, 4)
    req = _build_mbap(tx_id=14, pdu_len=len(pdu) + 1, proto_id=0x1234) + pdu
    resp = _process_frame(plc_ctx, req)
    assert resp == b""


# ============================================================================
# 5. FUZZING MASSIF ALÉATOIRE (RED TEAM STRESS TEST)
# ============================================================================


def test_modbus_c_massive_random_payloads_fuzzing(
    plc_ctx: ctypes.Array[ctypes.c_char],
) -> None:
    """Envoi de 5 000 trames d'octets pseudo-aléatoires : 0 crash toléré."""
    random.seed(1337)
    for _ in range(5000):
        length = random.randint(1, 350)
        garbage = random.randbytes(length)
        _process_frame(plc_ctx, garbage)

    # Vérification que le moteur fonctionne toujours après les 5000 trames
    pdu = struct.pack("!BHH", 0x04, 0, 4)
    req = _build_mbap(tx_id=999, pdu_len=len(pdu) + 1) + pdu
    resp = _process_frame(plc_ctx, req)
    assert len(resp) > 0
    assert resp[7] == 0x04
