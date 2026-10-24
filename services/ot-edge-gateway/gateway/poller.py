"""Boucle d'acquisition OT : Registres Modbus -> Validation Physique -> Sceau Diode -> Simplex UDP.

Conforme IEC 62443 et norme de trempe thermique EN 12150.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Callable, Final

from .diode import DiodePacketBuilder, UDPSimplexEmitter
from .frames import TelemetryFrame, utc_now_iso
from .modbus_client import ModbusReadOnlyClient

logger = logging.getLogger("securiglass.ot.gateway")

INPUT_REGISTER_COUNT: Final[int] = 12
INPUT_REG_START_ADDR: Final[int] = 0x0000

STATUS_FLAG_HEATERS_ON: Final[int] = 1 << 0
STATUS_FLAG_BLOWER_ON: Final[int] = 1 << 1
STATUS_FLAG_E_STOP_ACTIVE: Final[int] = 1 << 2
STATUS_FLAG_GLASS_BROKEN: Final[int] = 1 << 3


@dataclass(frozen=True, slots=True)
class ProcessSnapshot:
    """Grandeur physique normalisée extraite des registres de l'automate."""

    temp_zone1_c: float
    temp_zone2_c: float
    temp_zone3_c: float
    temp_zone4_c: float
    glass_pyrometer_temp_c: float
    quench_pressure_bar: float
    conveyor_speed_m_min: float
    blower_current_amps: float
    power_consumption_kw: float
    status_flags: int
    cycle_state: int
    error_code: int


def decode_modbus_registers(registers: list[int]) -> ProcessSnapshot:
    """Décode les 12 Input Registers de l'automate four EN 12150."""
    if len(registers) < INPUT_REGISTER_COUNT:
        raise ValueError(
            f"Taille de registres insuffisante : reçu {len(registers)}, attendu au moins {INPUT_REGISTER_COUNT}"
        )

    z1 = round(registers[0] * 0.1, 1)
    z2 = round(registers[1] * 0.1, 1)
    z3 = round(registers[2] * 0.1, 1)
    z4 = round(registers[3] * 0.1, 1)
    pyro = round(registers[4] * 0.1, 1)
    quench = round(registers[5] * 0.01, 2)
    speed = round(registers[6] * 0.01, 2)
    rpm = float(registers[7])
    # Estimation du courant soufflante : 0 à 60 A proportionnel aux RPM
    blower_amps = round(min(100.0, rpm / 50.0), 1)
    power_kw = round(registers[8] * 0.1, 2)
    flags = registers[9] & 0xFFFF
    state = registers[10] & 0xFFFF
    err = registers[11] & 0xFFFF

    return ProcessSnapshot(
        temp_zone1_c=z1,
        temp_zone2_c=z2,
        temp_zone3_c=z3,
        temp_zone4_c=z4,
        glass_pyrometer_temp_c=pyro,
        quench_pressure_bar=quench,
        conveyor_speed_m_min=speed,
        blower_current_amps=blower_amps,
        power_consumption_kw=power_kw,
        status_flags=flags,
        cycle_state=state,
        error_code=err,
    )


class FurnacePoller:
    """Interroge l'automate Modbus, valide les grandeurs et émet les trames via la Data Diode."""

    def __init__(
        self,
        modbus_client: ModbusReadOnlyClient,
        packet_builder: DiodePacketBuilder,
        emitter: UDPSimplexEmitter,
        line_id: str,
        *,
        clock: Callable[[], str] = utc_now_iso,
        initial_sequence: int | None = None,
    ) -> None:
        self.modbus_client = modbus_client
        self.packet_builder = packet_builder
        self.emitter = emitter
        self.line_id = line_id
        self._clock = clock
        # Départ sur l'horloge (µs depuis l'époque) : la séquence reste strictement
        # croissante après un redémarrage de la passerelle (le récepteur rejette tout rejeu).
        self._sequence = (
            time.time_ns() // 1000 if initial_sequence is None else initial_sequence
        )

    def poll_once(self) -> TelemetryFrame:
        """Acquiert un échantillon Modbus, construit la trame scellée et l'émet en UDP simplex."""
        # 1. Lecture Modbus FC 0x04
        registers = self.modbus_client.read_input_registers(
            address=INPUT_REG_START_ADDR,
            count=INPUT_REGISTER_COUNT,
        )

        # 2. Décodage grandeurs physiques
        snapshot = decode_modbus_registers(registers)

        # 3. Préparation des valeurs de télémétrie
        values: dict[str, float | int | bool] = {
            "temp_zone1_c": snapshot.temp_zone1_c,
            "temp_zone2_c": snapshot.temp_zone2_c,
            "temp_zone3_c": snapshot.temp_zone3_c,
            "temp_zone4_c": snapshot.temp_zone4_c,
            "glass_pyrometer_temp_c": snapshot.glass_pyrometer_temp_c,
            "quench_pressure_bar": snapshot.quench_pressure_bar,
            "conveyor_speed_m_min": snapshot.conveyor_speed_m_min,
            "blower_current_amps": snapshot.blower_current_amps,
            "power_consumption_kw": snapshot.power_consumption_kw,
            "emergency_stop_tripped": bool(
                snapshot.status_flags & STATUS_FLAG_E_STOP_ACTIVE
            ),
            "plc_status_flags": snapshot.status_flags,
        }

        # 4. Construction de la trame validée
        seq = self._sequence
        self._sequence += 1
        frame = TelemetryFrame(
            line_id=self.line_id,
            sequence=seq,
            measured_at=self._clock(),
            values=values,
        )

        # 5. Encapsulation binaire et signature Ed25519
        packet = self.packet_builder.build_packet(frame)

        # 6. Émission aveugle simplex vers la Data Diode
        self.emitter.emit(packet)
        logger.debug(
            "Trame émise vers Diode: line=%s, seq=%d, size=%d bytes",
            self.line_id,
            frame.sequence,
            len(packet),
        )
        return frame
