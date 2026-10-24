"""Construction et analyse de trames Modbus/TCP (sans dependance Scapy).

Le format MBAP est implemente a la main pour rester testable sur toute
plateforme, y compris sans droits root et sans Scapy. La couche IP/TCP est
fournie par `modbus_scapy.py`.

References :
  - Modbus Application Protocol Specification V1.1b3 (Modbus Organization)
  - Modbus Messaging on TCP/IP Implementation Guide V1.0b
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Sequence

MAX_REGISTERS_PER_READ = 125
MAX_COILS_PER_READ = 2000
MAX_REGISTERS_PER_WRITE = 123
MAX_COILS_PER_WRITE = 1968

READ_FUNCTIONS = frozenset({1, 2, 3, 4})
WRITE_FUNCTIONS = frozenset({5, 6, 15, 16})

FUNCTION_NAMES = {
    1: "READ_COILS",
    2: "READ_DISCRETE_INPUTS",
    3: "READ_HOLDING_REGISTERS",
    4: "READ_INPUT_REGISTERS",
    5: "WRITE_SINGLE_COIL",
    6: "WRITE_SINGLE_REGISTER",
    15: "WRITE_MULTIPLE_COILS",
    16: "WRITE_MULTIPLE_REGISTERS",
}

EXCEPTION_NAMES = {
    1: "ILLEGAL_FUNCTION",
    2: "ILLEGAL_DATA_ADDRESS",
    3: "ILLEGAL_DATA_VALUE",
    4: "SERVER_DEVICE_FAILURE",
    5: "ACKNOWLEDGE",
    6: "SERVER_DEVICE_BUSY",
    8: "MEMORY_PARITY_ERROR",
    10: "GATEWAY_PATH_UNAVAILABLE",
    11: "GATEWAY_TARGET_FAILED_TO_RESPOND",
}


class ModbusProtocolError(ValueError):
    """Trame Modbus invalide ou tronquee."""


@dataclass(frozen=True)
class ModbusFrame:
    transaction_id: int
    protocol_id: int
    unit_id: int
    function_code: int
    pdu: bytes
    raw: bytes

    @property
    def is_exception(self) -> bool:
        return bool(self.function_code & 0x80)

    @property
    def function_name(self) -> str:
        base = self.function_code & 0x7F
        return FUNCTION_NAMES.get(base, f"UNKNOWN_{base}")


def _u16(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF:
        raise ModbusProtocolError(f"{name} invalide : entier 0 a 65535 attendu")
    return value


def build_mbap(transaction_id: int, unit_id: int, pdu: bytes) -> bytes:
    """Construit l'en-tete MBAP (7 octets) suivi du PDU."""
    _u16(transaction_id, "transaction_id")
    if not 0 <= unit_id <= 255:
        raise ModbusProtocolError("unit_id invalide : 0 a 255 attendu")
    if not pdu:
        raise ModbusProtocolError("PDU vide interdit")
    length = 1 + len(pdu)
    if length > 0xFFFF:
        raise ModbusProtocolError("PDU trop long pour MBAP")
    return struct.pack(">HHHB", transaction_id, 0, length, unit_id) + pdu


def parse_mbap(data: bytes) -> ModbusFrame:
    """Valide et decode une trame MBAP complete (en-tete + PDU)."""
    if len(data) < 8:
        raise ModbusProtocolError(f"trame trop courte ({len(data)} octets)")
    transaction_id, protocol_id, length, unit_id = struct.unpack(">HHHB", data[:7])
    if protocol_id != 0:
        raise ModbusProtocolError(f"protocol_id {protocol_id} invalide (attendu 0)")
    expected = 6 + length
    if len(data) != expected:
        raise ModbusProtocolError(
            f"longueur MBAP incoherente : annonce {length}, trame {len(data)} (attendu {expected})"
        )
    if length < 2:
        raise ModbusProtocolError("longueur MBAP trop petite pour un PDU")
    pdu = data[7 : 7 + length - 1]
    if not pdu:
        raise ModbusProtocolError("PDU absent")
    return ModbusFrame(
        transaction_id=transaction_id,
        protocol_id=protocol_id,
        unit_id=unit_id,
        function_code=pdu[0],
        pdu=pdu,
        raw=bytes(data),
    )


def build_read_pdu(function_code: int, start: int, count: int) -> bytes:
    if function_code not in READ_FUNCTIONS:
        raise ModbusProtocolError(f"FC {function_code} n'est pas une lecture (1-4)")
    _u16(start, "start")
    if count < 1:
        raise ModbusProtocolError("count doit etre >= 1")
    limit = MAX_COILS_PER_READ if function_code in (1, 2) else MAX_REGISTERS_PER_READ
    if count > limit:
        raise ModbusProtocolError(f"count {count} > limite {limit} pour FC {function_code}")
    return struct.pack(">BHH", function_code, start, count)


def build_write_single_pdu(function_code: int, address: int, value: int) -> bytes:
    if function_code not in (5, 6):
        raise ModbusProtocolError("FC5 ou FC6 attendu pour une ecriture unique")
    _u16(address, "address")
    if function_code == 5:
        if value not in (0, 1, 0xFF00, 0x0000):
            raise ModbusProtocolError("FC5 : valeur 0/1 (ou 0x0000/0xFF00)")
        wire = 0xFF00 if value in (1, 0xFF00) else 0x0000
        return struct.pack(">BHH", 5, address, wire)
    _u16(value, "value")
    return struct.pack(">BHH", 6, address, value)


def _pack_bits(values: Sequence[int]) -> bytes:
    packed = bytearray((len(values) + 7) // 8)
    for index, bit in enumerate(values):
        if bit not in (0, 1):
            raise ModbusProtocolError("FC15 : chaque valeur doit etre 0 ou 1")
        if bit:
            packed[index // 8] |= 1 << (index % 8)
    return bytes(packed)


def build_write_multiple_pdu(function_code: int, start: int, values: Sequence[int]) -> bytes:
    if function_code not in (15, 16):
        raise ModbusProtocolError("FC15 ou FC16 attendu pour une ecriture multiple")
    if not values:
        raise ModbusProtocolError("liste de valeurs vide")
    _u16(start, "start")
    if function_code == 15:
        if len(values) > MAX_COILS_PER_WRITE:
            raise ModbusProtocolError(f"trop de bobines ({len(values)} > {MAX_COILS_PER_WRITE})")
        payload = _pack_bits(values)
        return struct.pack(">BHHB", 15, start, len(values), len(payload)) + payload

    if len(values) > MAX_REGISTERS_PER_WRITE:
        raise ModbusProtocolError(
            f"trop de registres ({len(values)} > {MAX_REGISTERS_PER_WRITE})"
        )
    for value in values:
        _u16(value, "value")
    payload = struct.pack(">" + "H" * len(values), *values)
    return struct.pack(">BHHB", 16, start, len(values), len(payload)) + payload


def build_request(
    *,
    transaction_id: int,
    unit_id: int,
    function_code: int,
    start: int,
    count: int = 1,
    values: Sequence[int] | None = None,
) -> bytes:
    """Construit une trame Modbus/TCP complete (MBAP + PDU)."""
    if function_code in READ_FUNCTIONS:
        pdu = build_read_pdu(function_code, start, count)
    elif function_code in (5, 6):
        if values is None or len(values) != 1:
            raise ModbusProtocolError("FC5/FC6 : une seule valeur attendue")
        pdu = build_write_single_pdu(function_code, start, values[0])
    elif function_code in (15, 16):
        if values is None:
            raise ModbusProtocolError("FC15/FC16 : liste de valeurs requise")
        pdu = build_write_multiple_pdu(function_code, start, values)
    else:
        raise ModbusProtocolError(f"fonction Modbus non supportee : {function_code}")
    return build_mbap(transaction_id, unit_id, pdu)


def parse_response(data: bytes) -> dict[str, Any]:
    """Decode une reponse Modbus (valeurs, exception ou echo d'ecriture)."""
    frame = parse_mbap(data)
    pdu = frame.pdu
    fc = frame.function_code
    base_fc = fc & 0x7F

    result: dict[str, Any] = {
        "transaction_id": frame.transaction_id,
        "unit_id": frame.unit_id,
        "function_code": base_fc,
        "function_name": frame.function_name,
        "raw_pdu_hex": pdu.hex(),
        "is_exception": frame.is_exception,
    }

    if frame.is_exception:
        code = pdu[1] if len(pdu) > 1 else None
        result["exception_code"] = code
        result["exception_name"] = EXCEPTION_NAMES.get(code, "UNKNOWN_EXCEPTION")
        return result

    if base_fc in (1, 2):
        if len(pdu) < 2:
            raise ModbusProtocolError("reponse FC1/FC2 tronquee")
        byte_count = pdu[1]
        payload = pdu[2 : 2 + byte_count]
        if len(payload) != byte_count:
            raise ModbusProtocolError("byte_count incoherent (FC1/FC2)")
        bits = [(payload[i // 8] >> (i % 8)) & 1 for i in range(byte_count * 8)]
        result["bits"] = bits
        result["values"] = bits
        return result

    if base_fc in (3, 4):
        if len(pdu) < 2:
            raise ModbusProtocolError("reponse FC3/FC4 tronquee")
        byte_count = pdu[1]
        payload = pdu[2 : 2 + byte_count]
        if byte_count % 2 or len(payload) != byte_count:
            raise ModbusProtocolError("byte_count incoherent (FC3/FC4)")
        result["values"] = list(struct.unpack(">" + "H" * (byte_count // 2), payload))
        return result

    if base_fc in (5, 6):
        if len(pdu) < 5:
            raise ModbusProtocolError("reponse FC5/FC6 tronquee")
        address, value = struct.unpack(">HH", pdu[1:5])
        result.update({"address": address, "value": value, "echo": True})
        return result

    if base_fc in (15, 16):
        if len(pdu) < 5:
            raise ModbusProtocolError("reponse FC15/FC16 tronquee")
        address, value = struct.unpack(">HH", pdu[1:5])
        result.update({"address": address, "value": value, "echo": True})
        return result

    result["unparsed"] = True
    return result


def frame_summary(data: bytes) -> dict[str, Any]:
    """Resume non intrusif d'une trame (utilise par le rejeu et les logs)."""
    try:
        frame = parse_mbap(data)
    except ModbusProtocolError as exc:
        return {"valid": False, "error": str(exc), "length": len(data)}
    return {
        "valid": True,
        "transaction_id": frame.transaction_id,
        "unit_id": frame.unit_id,
        "function_code": frame.function_code & 0x7F,
        "function_name": frame.function_name,
        "is_exception": frame.is_exception,
        "length": len(data),
    }
