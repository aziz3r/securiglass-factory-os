"""Récepteur Data Diode IT (RX) : UDP simplex, Ed25519 + SHA-256, anti-rejeu, ingestion.

Spécification : docs/architecture/DATA_DIODE_SPEC.md.

Garanties :
  * Zéro retour : le transport UDP n'émet jamais (aucun appel à ``sendto``) ; un rejet
    est journalisé localement, jamais acquitté vers la zone OT.
  * Un datagramme n'atteint la base que s'il est entièrement authentifié : format,
    SHA-256, signature Ed25519 d'un émetteur de confiance, dérive d'horloge <= 30 s,
    numéro de séquence strictement croissant, charge utile conforme aux bornes physiques.
  * Anti-rejeu durable : ``transmission_id`` (UUIDv5 émetteur+séquence) est UNIQUE dans
    ``ot_data.diode_import_log`` ; un rejeu survivant à un redémarrage est rejeté en base.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import logging
import math
import os
import struct
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Final

import asyncpg
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.core.db import DbConn

logger = logging.getLogger("securiglass.diode.rx")

MAGIC: Final = b"SGDD"
VERSION: Final = 0x0002
MSG_FURNACE: Final = 0x0001
HEADER_FORMAT: Final = "!4sHHQQ16sI20s"
HEADER_SIZE: Final = struct.calcsize(HEADER_FORMAT)  # 64
HASHED_HEADER_BYTES: Final = 44
SEAL_SIZE: Final = 96
MAX_PAYLOAD: Final = 4096
MAX_DATAGRAM: Final = HEADER_SIZE + MAX_PAYLOAD + SEAL_SIZE
MAX_CLOCK_SKEW_US: Final = 30 * 1_000_000
TRANSMISSION_NAMESPACE: Final = uuid.UUID("5ec0a0d1-0000-4000-8000-5d0d1ec0a0d1")

# Alias de conformité DATA_DIODE_SPEC.md
DIODE_MAGIC: Final = MAGIC
PROTOCOL_VERSION: Final = VERSION
MSG_TYPE_FURNACE_TELEMETRY: Final = MSG_FURNACE
HEADER_SIZE_BYTES: Final = HEADER_SIZE
SEAL_SIZE_BYTES: Final = SEAL_SIZE
MAX_ALLOWED_CLOCK_SKEW_SECONDS: Final = 30.0

# Plages physiques = contraintes CHECK de ot_data.furnace_telemetry.
_REQUIRED: Final[dict[str, tuple[float, float]]] = {
    "temp_zone1_c": (0.0, 850.0),
    "temp_zone2_c": (0.0, 850.0),
    "temp_zone3_c": (0.0, 850.0),
    "temp_zone4_c": (0.0, 850.0),
    "glass_pyrometer_temp_c": (0.0, 850.0),
    "quench_pressure_bar": (0.0, 12.0),
    "conveyor_speed_m_min": (0.0, 50.0),
}
_OPTIONAL: Final[dict[str, tuple[float, float]]] = {
    "blower_current_amps": (0.0, 9999.9),
    "power_consumption_kw": (0.0, 9999.99),
}
_PAYLOAD_KEYS: Final = frozenset(
    {"schema_version", "line_id", "sequence", "measured_at", "values", "batch_id"}
)
_VALUE_KEYS: Final = (
    frozenset(_REQUIRED)
    | frozenset(_OPTIONAL)
    | {"emergency_stop_tripped", "plc_status_flags"}
)


class DiodeRejected(Exception):
    """Datagramme rejeté. ``reason`` est un code court, sans donnée de la trame."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# Alias d'exceptions de sécurité
DiodeError = DiodeRejected
DiodeSecurityError = DiodeRejected
DiodeReplayError = DiodeRejected


@dataclass(frozen=True)
class VerifiedPacket:
    emitter_id: uuid.UUID
    sequence: int
    timestamp_us: int
    msg_type: int
    line_code: str
    batch_id: uuid.UUID | None
    measured_at: datetime
    values: dict[str, float | int | bool]
    packet_sha256: str
    signature_b64: str

    @property
    def transmission_id(self) -> uuid.UUID:
        return uuid.uuid5(TRANSMISSION_NAMESPACE, f"{self.emitter_id}:{self.sequence}")

    @property
    def packet_sha256_hex(self) -> str:
        return self.packet_sha256

    @property
    def ed25519_signature_hex(self) -> str:
        try:
            return base64.b64decode(self.signature_b64).hex()
        except Exception:
            return ""

    @property
    def timestamp_utc(self) -> datetime:
        return datetime.fromtimestamp(self.timestamp_us / 1_000_000.0, tz=timezone.utc)

    @property
    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "schema_version": 2,
            "line_id": self.line_code,
            "sequence": self.sequence,
            "measured_at": self.measured_at.isoformat(),
            "values": dict(self.values),
        }
        if self.batch_id is not None:
            result["batch_id"] = str(self.batch_id)
        return result


ParsedDiodePacket = VerifiedPacket


@dataclass(frozen=True)
class DiodeIngestResult:
    """Résultat d'ingestion d'un paquet de télémétrie Diode."""

    success: bool
    sequence: int
    emitter_id: uuid.UUID
    records_count: int
    packet_sha256_hex: str
    message: str


def _reject_if(condition: bool, reason: str) -> None:
    if condition:
        raise DiodeRejected(reason)


def _number(value: object, low: float, high: float) -> float:
    _reject_if(
        isinstance(value, bool) or not isinstance(value, (int, float)), "bad_value_type"
    )
    number = float(value)  # type: ignore[arg-type]
    _reject_if(
        not math.isfinite(number) or not low <= number <= high, "value_out_of_range"
    )
    return number


def _forbid_constant(name: str) -> float:
    raise ValueError(f"constante JSON interdite : {name}")


def _parse_payload(
    raw: bytes, header_sequence: int
) -> tuple[str, uuid.UUID | None, datetime, dict[str, float | int | bool]]:
    try:
        payload = json.loads(raw.decode("utf-8"), parse_constant=_forbid_constant)
    except (UnicodeDecodeError, ValueError):
        raise DiodeRejected("bad_payload_json") from None
    _reject_if(not isinstance(payload, dict), "bad_payload_shape")
    _reject_if(not set(payload) <= _PAYLOAD_KEYS, "unknown_payload_key")
    _reject_if(payload.get("schema_version") != 1, "bad_schema_version")
    _reject_if(payload.get("sequence") != header_sequence, "sequence_mismatch")

    line_code = payload.get("line_id")
    _reject_if(
        not isinstance(line_code, str) or not 1 <= len(line_code) <= 32, "bad_line_id"
    )

    try:
        measured_at = datetime.fromisoformat(str(payload.get("measured_at")))
    except ValueError:
        raise DiodeRejected("bad_measured_at") from None
    _reject_if(measured_at.tzinfo is None, "naive_measured_at")

    batch_raw = payload.get("batch_id")
    batch_id: uuid.UUID | None = None
    if batch_raw is not None:
        try:
            batch_id = uuid.UUID(str(batch_raw))
        except ValueError:
            raise DiodeRejected("bad_batch_id") from None

    values = payload.get("values")
    _reject_if(not isinstance(values, dict), "bad_values")
    _reject_if(not set(values) <= _VALUE_KEYS, "unknown_value_key")
    _reject_if(not set(_REQUIRED) <= set(values), "missing_value")

    clean: dict[str, float | int | bool] = {}
    for key, (low, high) in {**_REQUIRED, **_OPTIONAL}.items():
        if key in values:
            clean[key] = _number(values[key], low, high)
    if "emergency_stop_tripped" in values:
        _reject_if(
            not isinstance(values["emergency_stop_tripped"], bool), "bad_value_type"
        )
        clean["emergency_stop_tripped"] = values["emergency_stop_tripped"]
    if "plc_status_flags" in values:
        flags = values["plc_status_flags"]
        _reject_if(
            isinstance(flags, bool)
            or not isinstance(flags, int)
            or not 0 <= flags <= 0xFFFF,
            "bad_flags",
        )
        clean["plc_status_flags"] = flags
    return str(line_code), batch_id, measured_at, clean


class ReplayGuard:
    """Séquence strictement croissante par émetteur (mise à jour après authentification)."""

    def __init__(self) -> None:
        self._last: dict[uuid.UUID, int] = {}

    def check(self, emitter: uuid.UUID, sequence: int) -> None:
        _reject_if(sequence <= self._last.get(emitter, 0), "replay_or_stale_sequence")

    def commit(self, emitter: uuid.UUID, sequence: int) -> None:
        self._last[emitter] = max(sequence, self._last.get(emitter, 0))


def verify_datagram(
    datagram: bytes,
    trusted: Mapping[uuid.UUID, ed25519.Ed25519PublicKey],
    guard: ReplayGuard,
    now_us: int | None = None,
) -> VerifiedPacket:
    """Valide un datagramme de bout en bout ; lève DiodeRejected au premier défaut."""
    _reject_if(not HEADER_SIZE + SEAL_SIZE <= len(datagram) <= MAX_DATAGRAM, "bad_size")
    magic, version, msg_type, sequence, ts_us, emitter_raw, payload_len, padding = (
        struct.unpack(HEADER_FORMAT, datagram[:HEADER_SIZE])
    )
    _reject_if(magic != MAGIC, "bad_magic")
    _reject_if(version != VERSION, "bad_version")
    _reject_if(msg_type != MSG_FURNACE, "unsupported_message_type")
    _reject_if(
        payload_len > MAX_PAYLOAD
        or len(datagram) != HEADER_SIZE + payload_len + SEAL_SIZE,
        "bad_length",
    )
    _reject_if(
        any(padding), "nonzero_padding"
    )  # non couvert par le hash : canal caché interdit

    emitter = uuid.UUID(bytes=emitter_raw)
    key = trusted.get(emitter)
    if key is None:
        raise DiodeRejected("untrusted_emitter")

    payload = datagram[HEADER_SIZE : HEADER_SIZE + payload_len]
    digest = datagram[-SEAL_SIZE:-64]
    signature = datagram[-64:]
    expected = hashlib.sha256(datagram[:HASHED_HEADER_BYTES] + payload).digest()
    _reject_if(not hmac.compare_digest(expected, digest), "bad_hash")
    try:
        key.verify(signature, digest)
    except InvalidSignature:
        raise DiodeRejected("bad_signature") from None

    now = int(time.time() * 1_000_000) if now_us is None else now_us
    _reject_if(abs(now - ts_us) > MAX_CLOCK_SKEW_US, "clock_skew")
    guard.check(emitter, sequence)

    line_code, batch_id, measured_at, values = _parse_payload(payload, sequence)
    guard.commit(emitter, sequence)
    return VerifiedPacket(
        emitter_id=emitter,
        sequence=sequence,
        timestamp_us=ts_us,
        msg_type=msg_type,
        line_code=line_code,
        batch_id=batch_id,
        measured_at=measured_at,
        values=values,
        packet_sha256=digest.hex(),
        signature_b64=base64.b64encode(signature).decode("ascii"),
    )


async def ingest(conn: DbConn, packet: VerifiedPacket) -> None:
    """Journal d'import + télémétrie dans une seule transaction (tout ou rien)."""
    v = packet.values
    try:
        async with conn.transaction():
            row = await conn.fetchrow(
                "INSERT INTO ot_data.diode_import_log (transmission_id, source_gateway,"
                " records_ingested, packet_sha256, ed25519_signature)"
                " VALUES ($1, $2, 1, $3, $4) ON CONFLICT (transmission_id) DO NOTHING RETURNING id",
                packet.transmission_id,
                str(packet.emitter_id),
                packet.packet_sha256,
                packet.signature_b64,
            )
            _reject_if(row is None, "duplicate_transmission")
            await conn.execute(
                "INSERT INTO ot_data.furnace_telemetry (timestamp, line_id, batch_id,"
                " temp_zone1_c, temp_zone2_c, temp_zone3_c, temp_zone4_c, glass_pyrometer_temp_c,"
                " quench_pressure_bar, conveyor_speed_m_min, blower_current_amps,"
                " power_consumption_kw, emergency_stop_tripped, plc_status_flags)"
                " VALUES ($1, (SELECT id FROM ot_data.production_lines WHERE line_code = $2), $3,"
                " $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)",
                packet.measured_at,
                packet.line_code,
                packet.batch_id,
                v["temp_zone1_c"],
                v["temp_zone2_c"],
                v["temp_zone3_c"],
                v["temp_zone4_c"],
                v["glass_pyrometer_temp_c"],
                v["quench_pressure_bar"],
                v["conveyor_speed_m_min"],
                v.get("blower_current_amps", 0.0),
                v.get("power_consumption_kw", 0.0),
                bool(v.get("emergency_stop_tripped", False)),
                int(v.get("plc_status_flags", 0)),
            )
    except asyncpg.NotNullViolationError:
        raise DiodeRejected("unknown_line") from None
    except asyncpg.CheckViolationError:
        raise DiodeRejected("db_constraint_violation") from None


class DiodeReceiverService:
    """Service d'ingestion et de contrôle cryptographique pour la Data Diode (iDMZ)."""

    def __init__(
        self,
        trusted: Mapping[uuid.UUID, ed25519.Ed25519PublicKey] | None = None,
        *,
        clock_skew_tolerance_s: float = MAX_ALLOWED_CLOCK_SKEW_SECONDS,
    ) -> None:
        self.trusted: dict[uuid.UUID, ed25519.Ed25519PublicKey] = dict(trusted or {})
        self.guard = ReplayGuard()
        self.clock_skew_tolerance_s = clock_skew_tolerance_s

    def register_gateway(
        self, emitter_id: uuid.UUID, public_key: ed25519.Ed25519PublicKey
    ) -> None:
        self.trusted[emitter_id] = public_key

    def unregister_gateway(self, emitter_id: uuid.UUID) -> None:
        self.trusted.pop(emitter_id, None)

    def get_last_seen_sequence(self, emitter_id: uuid.UUID) -> int:
        return self.guard._last.get(emitter_id, 0)

    def verify_and_parse(
        self,
        packet: bytes,
        *,
        current_time_epoch: float | None = None,
    ) -> VerifiedPacket:
        now_us = (
            int(current_time_epoch * 1_000_000)
            if current_time_epoch is not None
            else None
        )
        return verify_datagram(packet, self.trusted, self.guard, now_us=now_us)

    async def ingest_packet(
        self,
        packet: bytes,
        session_or_conn: Any,
        *,
        current_time_epoch: float | None = None,
    ) -> DiodeIngestResult:
        verified = self.verify_and_parse(packet, current_time_epoch=current_time_epoch)
        if hasattr(session_or_conn, "execute") and not hasattr(
            session_or_conn, "fetchrow"
        ):
            # SQLAlchemy AsyncSession / Mock
            from sqlalchemy import text

            await session_or_conn.execute(
                text(
                    "INSERT INTO ot_data.diode_import_log (transmission_id, source_gateway, records_ingested, packet_sha256, ed25519_signature) VALUES (:tx, :gw, 1, :sha, :sig)"
                ),
                {
                    "tx": str(verified.transmission_id),
                    "gw": str(verified.emitter_id),
                    "sha": verified.packet_sha256_hex,
                    "sig": verified.ed25519_signature_hex,
                },
            )
            v = verified.values
            await session_or_conn.execute(
                text(
                    "INSERT INTO ot_data.furnace_telemetry (timestamp, line_id, batch_id, temp_zone1_c, temp_zone2_c, temp_zone3_c, temp_zone4_c, glass_pyrometer_temp_c, quench_pressure_bar, conveyor_speed_m_min, blower_current_amps, power_consumption_kw, emergency_stop_tripped, plc_status_flags) VALUES (:ts, (SELECT id FROM ot_data.production_lines WHERE line_code = :line), :batch, :z1, :z2, :z3, :z4, :pyro, :quench, :speed, :blower, :power, :estop, :flags)"
                ),
                {
                    "ts": verified.measured_at,
                    "line": verified.line_code,
                    "batch": str(verified.batch_id) if verified.batch_id else None,
                    "z1": v["temp_zone1_c"],
                    "z2": v["temp_zone2_c"],
                    "z3": v["temp_zone3_c"],
                    "z4": v["temp_zone4_c"],
                    "pyro": v["glass_pyrometer_temp_c"],
                    "quench": v["quench_pressure_bar"],
                    "speed": v["conveyor_speed_m_min"],
                    "blower": v.get("blower_current_amps", 0.0),
                    "power": v.get("power_consumption_kw", 0.0),
                    "estop": bool(v.get("emergency_stop_tripped", False)),
                    "flags": int(v.get("plc_status_flags", 0)),
                },
            )
            if hasattr(session_or_conn, "commit"):
                await session_or_conn.commit()
        else:
            # asyncpg connection
            await ingest(session_or_conn, verified)

        return DiodeIngestResult(
            success=True,
            sequence=verified.sequence,
            emitter_id=verified.emitter_id,
            records_count=1,
            packet_sha256_hex=verified.packet_sha256_hex,
            message="Ingestion réussie",
        )


def load_trusted_keys(spec: str) -> dict[uuid.UUID, ed25519.Ed25519PublicKey]:
    """``uuid:clé_publique_hex`` séparés par des virgules (DIODE_TRUSTED_EMITTERS)."""
    keys: dict[uuid.UUID, ed25519.Ed25519PublicKey] = {}
    for item in filter(None, (part.strip() for part in spec.split(","))):
        emitter, _, raw = item.partition(":")
        keys[uuid.UUID(emitter)] = ed25519.Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(raw)
        )
    if not keys:
        raise ValueError("aucun émetteur de confiance configuré")
    return keys


class _RxProtocol(asyncio.DatagramProtocol):
    """Réception seule : ce protocole n'appelle jamais ``transport.sendto``."""

    def __init__(
        self,
        trusted: Mapping[uuid.UUID, ed25519.Ed25519PublicKey],
        queue: asyncio.Queue[VerifiedPacket],
    ) -> None:
        self._trusted = trusted
        self._queue = queue
        self._guard = ReplayGuard()
        self.stats: dict[str, int] = {"accepted": 0, "rejected": 0, "dropped": 0}

    def datagram_received(self, data: bytes, addr: Any) -> None:
        try:
            packet = verify_datagram(data, self._trusted, self._guard)
            self._queue.put_nowait(packet)
            self.stats["accepted"] += 1
        except DiodeRejected as exc:
            self.stats["rejected"] += 1
            logger.warning(
                "diode: datagramme rejeté (%s) depuis %s", exc.reason, addr[0]
            )
        except asyncio.QueueFull:
            self.stats["dropped"] += 1
            logger.error("diode: file d'ingestion saturée, datagramme perdu")


async def run(
    host: str,
    port: int,
    trusted: Mapping[uuid.UUID, ed25519.Ed25519PublicKey],
    dsn: str,
) -> None:
    queue: asyncio.Queue[VerifiedPacket] = asyncio.Queue(maxsize=10_000)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: _RxProtocol(trusted, queue), local_addr=(host, port)
    )
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=4)
    if pool is None:
        raise RuntimeError("pool PostgreSQL non créé")
    logger.info(
        "diode RX à l'écoute sur %s:%d (émetteurs de confiance : %d)",
        host,
        port,
        len(trusted),
    )
    try:
        while True:
            packet = await queue.get()
            try:
                async with pool.acquire() as conn:
                    await ingest(conn, packet)  # type: ignore[arg-type]
            except DiodeRejected as exc:
                logger.warning(
                    "diode: ingestion rejetée (%s) seq=%d", exc.reason, packet.sequence
                )
            except asyncpg.PostgresError:
                logger.exception(
                    "diode: erreur base de données seq=%d", packet.sequence
                )
    finally:
        transport.close()
        await pool.close()


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    trusted = load_trusted_keys(os.environ["DIODE_TRUSTED_EMITTERS"])
    asyncio.run(
        run(
            os.environ.get("DIODE_BIND", "127.0.0.1"),
            int(os.environ.get("DIODE_PORT", "5030")),
            trusted,
            os.environ["DATABASE_URL"],
        )
    )


if __name__ == "__main__":
    main()
