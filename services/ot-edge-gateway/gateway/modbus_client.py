"""Client Modbus TCP sécurisé en lecture seule stricte (Least Privilege).

Interroge les Input Registers (FC 0x04) et Holding Registers (FC 0x03) de
l'automate PLC de trempe. Aucune primitive d'écriture n'est implémentée afin
d'interdire physiquement toute compromission descendante vers le procédé.
"""

from __future__ import annotations

import socket
import struct
from types import TracebackType
from typing import Final

MBAP_HEADER_FORMAT: Final[str] = ">HHHB"
MBAP_HEADER_SIZE: Final[int] = struct.calcsize(MBAP_HEADER_FORMAT)  # 7 octets
_FC_READ_HOLDING: Final[int] = 0x03
_FC_READ_INPUT: Final[int] = 0x04
_MAX_READ_REGISTERS: Final[int] = 125


class ModbusError(Exception):
    """Erreur de communication ou de transport Modbus."""


class ModbusProtocolError(ModbusError):
    """Violation du protocole Modbus TCP ou PDU malformée."""


class ModbusExceptionResponse(ModbusError):
    """L'automate a retourné une trame d'exception Modbus (FC | 0x80)."""

    def __init__(self, function_code: int, exception_code: int) -> None:
        super().__init__(
            f"Exception Modbus code {exception_code} pour la fonction {function_code:#04x}"
        )
        self.function_code = function_code
        self.exception_code = exception_code


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    """Lit exactement `length` octets sur la socket ou lève une exception."""
    buffer = bytearray()
    while len(buffer) < length:
        chunk = sock.recv(length - len(buffer))
        if not chunk:
            raise ModbusProtocolError(
                "Connexion TCP fermée prématurément par l'automate"
            )
        buffer.extend(chunk)
    return bytes(buffer)


class ModbusReadOnlyClient:
    """Client Modbus TCP dédié aux passerelles d'acquisition (Niveau Purdue 2-3)."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5020,
        unit_id: int = 1,
        timeout: float = 2.0,
    ) -> None:
        if not (1 <= unit_id <= 247):
            raise ValueError(f"unit_id Modbus invalide : {unit_id} (plage 1..247)")
        if not (1 <= port <= 65535):
            raise ValueError(f"Port Modbus invalide : {port}")
        self.host = host
        self.port = port
        self.unit_id = unit_id
        self.timeout = timeout
        self._transaction_id = 0

    def _next_transaction_id(self) -> int:
        self._transaction_id = (self._transaction_id + 1) & 0xFFFF
        return self._transaction_id

    def _execute_read(self, function_code: int, address: int, count: int) -> list[int]:
        if not (0 <= address <= 0xFFFF):
            raise ValueError(f"Adresse de registre hors bornes 16 bits : {address}")
        if not (1 <= count <= _MAX_READ_REGISTERS):
            raise ValueError(
                f"Quantité de registres invalide : {count} (max {_MAX_READ_REGISTERS})"
            )

        tid = self._next_transaction_id()
        # Requête MBAP : TID (2), PID=0 (2), LEN=6 (2), UID (1) + FC (1) + ADDR (2) + COUNT (2)
        request = struct.pack(
            MBAP_HEADER_FORMAT, tid, 0, 6, self.unit_id
        ) + struct.pack(">BHH", function_code, address, count)

        with socket.create_connection(
            (self.host, self.port), timeout=self.timeout
        ) as sock:
            sock.settimeout(self.timeout)
            sock.sendall(request)

            header = _recv_exact(sock, MBAP_HEADER_SIZE)
            resp_tid, protocol_id, length_field, resp_uid = struct.unpack(
                MBAP_HEADER_FORMAT, header
            )

            if resp_tid != tid:
                raise ModbusProtocolError(
                    f"Désynchronisation de transaction TID ({resp_tid} != {tid})"
                )
            if protocol_id != 0:
                raise ModbusProtocolError(
                    f"Protocole ID Modbus invalide : {protocol_id} != 0"
                )
            if resp_uid != self.unit_id:
                raise ModbusProtocolError(
                    f"Unit ID invalide : {resp_uid} != {self.unit_id}"
                )
            if not (2 <= length_field <= 256):
                raise ModbusProtocolError(
                    f"Champ Longueur MBAP invalide : {length_field}"
                )

            # Le corps PDU fait `length_field - 1` octets (le champ UID comptant pour 1 octet)
            body = _recv_exact(sock, length_field - 1)
            resp_fc = body[0]

            # Vérification d'exception Modbus
            if resp_fc == (function_code | 0x80):
                if len(body) < 2:
                    raise ModbusProtocolError("PDU d'exception Modbus tronquée")
                raise ModbusExceptionResponse(function_code, body[1])

            if resp_fc != function_code:
                raise ModbusProtocolError(
                    f"Code fonction inattendu dans la réponse : {resp_fc:#04x} != {function_code:#04x}"
                )

            byte_count = body[1]
            expected_byte_count = count * 2
            if byte_count != expected_byte_count:
                raise ModbusProtocolError(
                    f"Nombre d'octets retournés invalide ({byte_count} != {expected_byte_count})"
                )

            data_bytes = body[2:]
            if len(data_bytes) != expected_byte_count:
                raise ModbusProtocolError("Taille des données de registres incohérente")

            return list(struct.unpack(f">{count}H", data_bytes))

    def read_input_registers(self, address: int, count: int) -> list[int]:
        """Lit `count` registres d'entrée analogiques (FC 0x04, plage 30001+)."""
        return self._execute_read(_FC_READ_INPUT, address, count)

    def read_holding_registers(self, address: int, count: int) -> list[int]:
        """Lit `count` registres de maintien (FC 0x03, plage 40001+)."""
        return self._execute_read(_FC_READ_HOLDING, address, count)

    def __enter__(self) -> ModbusReadOnlyClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        pass
