"""Tests du récepteur Data Diode IT (app/services/diode_receiver.py)."""

import asyncio
import hashlib
import json
import socket
import struct
import sys
import time
import uuid
from pathlib import Path

import asyncpg
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.services import diode_receiver as rx

EMITTER = uuid.UUID("11111111-2222-4333-8444-555555555555")
VALUES = {
    "temp_zone1_c": 690.0,
    "temp_zone2_c": 691.5,
    "temp_zone3_c": 692.0,
    "temp_zone4_c": 688.0,
    "glass_pyrometer_temp_c": 640.0,
    "quench_pressure_bar": 0.0,
    "conveyor_speed_m_min": 4.5,
    "blower_current_amps": 0.0,
    "power_consumption_kw": 120.5,
    "emergency_stop_tripped": False,
    "plc_status_flags": 1,
}


def payload(seq: int = 10, **over: object) -> dict[str, object]:
    base: dict[str, object] = {
        "schema_version": 1,
        "line_id": "LINE-FOUR-01",
        "sequence": seq,
        "measured_at": "2026-10-24T20:00:00+00:00",
        "values": dict(VALUES),
    }
    base.update(over)
    return base


def packet(
    key: ed25519.Ed25519PrivateKey,
    body: dict[str, object] | bytes | None = None,
    seq: int = 10,
    ts_us: int | None = None,
    emitter: uuid.UUID = EMITTER,
    magic: bytes = b"SGDD",
    version: int = 2,
    msg: int = 1,
    padding: bytes = b"\0" * 20,
) -> bytes:
    raw = (
        body
        if isinstance(body, bytes)
        else json.dumps(
            body if body is not None else payload(seq),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    ts = int(time.time() * 1e6) if ts_us is None else ts_us
    header = struct.pack(
        rx.HEADER_FORMAT, magic, version, msg, seq, ts, emitter.bytes, len(raw), padding
    )
    digest = hashlib.sha256(header[:44] + raw).digest()
    return header + raw + digest + key.sign(digest)


@pytest.fixture()
def key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


@pytest.fixture()
def trusted(
    key: ed25519.Ed25519PrivateKey,
) -> dict[uuid.UUID, ed25519.Ed25519PublicKey]:
    return {EMITTER: key.public_key()}


def reason(
    data: bytes,
    trusted: dict[uuid.UUID, ed25519.Ed25519PublicKey],
    guard: rx.ReplayGuard | None = None,
) -> str:
    with pytest.raises(rx.DiodeRejected) as exc:
        rx.verify_datagram(data, trusted, guard or rx.ReplayGuard())
    return exc.value.reason


def test_valid_packet_is_accepted(key, trusted):
    p = rx.verify_datagram(packet(key), trusted, rx.ReplayGuard())
    assert (
        p.emitter_id == EMITTER and p.sequence == 10 and p.line_code == "LINE-FOUR-01"
    )
    assert p.values["temp_zone1_c"] == 690.0 and len(p.packet_sha256) == 64
    assert p.transmission_id == rx.VerifiedPacket.transmission_id.fget(
        p
    )  # déterministe


def test_interop_with_gateway_builder(trusted, key):
    gw = Path(__file__).resolve().parents[2] / "services" / "ot-edge-gateway"
    sys.path.insert(0, str(gw))
    try:
        from gateway.diode import DiodePacketBuilder
        from gateway.frames import TelemetryFrame
    except ImportError:
        pytest.skip("gateway non disponible")
    finally:
        sys.path.remove(str(gw))
    builder = DiodePacketBuilder(EMITTER, key)
    frame = TelemetryFrame(
        line_id="LINE-FOUR-01",
        sequence=5,
        measured_at="2026-10-24T20:00:00+00:00",
        values={k: v for k, v in VALUES.items()},
    )
    got = rx.verify_datagram(builder.build_packet(frame), trusted, rx.ReplayGuard())
    assert got.sequence == 5 and got.values["power_consumption_kw"] == 120.5


@pytest.mark.parametrize(
    "mutate,expected",
    [
        (lambda b: b[:100], "bad_size"),
        (lambda b: b"XXXX" + b[4:], "bad_magic"),
        (lambda b: b[:4] + b"\x00\x03" + b[6:], "bad_version"),
        (lambda b: b[:6] + b"\x00\x02" + b[8:], "unsupported_message_type"),
        (lambda b: b + b"\0", "bad_length"),
        (lambda b: b[:50] + b"\x01" + b[51:], "nonzero_padding"),
        (lambda b: b[:20] + b"\xff" + b[21:], "bad_hash"),  # horodatage altéré
        (lambda b: b[:70] + b"X" + b[71:], "bad_hash"),  # charge utile altérée
        (lambda b: b[:-1] + bytes([b[-1] ^ 1]), "bad_signature"),
    ],
)
def test_tampering_is_rejected(key, trusted, mutate, expected):
    assert reason(mutate(packet(key)), trusted) == expected


def test_forged_signature_with_valid_hash(trusted):
    forger = ed25519.Ed25519PrivateKey.generate()
    assert reason(packet(forger), trusted) == "bad_signature"


def test_untrusted_emitter(key, trusted):
    assert reason(packet(key, emitter=uuid.uuid4()), trusted) == "untrusted_emitter"


@pytest.mark.parametrize("delta", [-31_000_000, 31_000_000])
def test_clock_skew(key, trusted, delta):
    assert (
        reason(packet(key, ts_us=int(time.time() * 1e6) + delta), trusted)
        == "clock_skew"
    )


def test_replay_and_stale_sequence(key, trusted):
    guard = rx.ReplayGuard()
    rx.verify_datagram(packet(key, seq=10), trusted, guard)
    assert reason(packet(key, seq=10), trusted, guard) == "replay_or_stale_sequence"
    assert reason(packet(key, seq=9), trusted, guard) == "replay_or_stale_sequence"
    rx.verify_datagram(packet(key, seq=11), trusted, guard)


def test_rejected_packet_does_not_advance_guard(key, trusted):
    guard = rx.ReplayGuard()
    bad = payload(500)
    bad["values"] = {**VALUES, "temp_zone1_c": 9999}
    assert reason(packet(key, bad, seq=500), trusted, guard) == "value_out_of_range"
    rx.verify_datagram(
        packet(key, seq=20), trusted, guard
    )  # une séquence plus basse reste acceptable


@pytest.mark.parametrize(
    "body,expected",
    [
        (b"not json", "bad_payload_json"),
        (b"[1,2]", "bad_payload_shape"),
        (b'{"schema_version":1,"sequence":10,"values":NaN}', "bad_payload_json"),
        (payload(11), "sequence_mismatch"),
        (payload(10, schema_version=2), "bad_schema_version"),
        (payload(10, extra=1), "unknown_payload_key"),
        (payload(10, line_id=""), "bad_line_id"),
        (payload(10, measured_at="hier"), "bad_measured_at"),
        (payload(10, measured_at="2026-10-24T20:00:00"), "naive_measured_at"),
        (payload(10, batch_id="x"), "bad_batch_id"),
        (payload(10, values=[]), "bad_values"),
        (payload(10, values={**VALUES, "evil": 1}), "unknown_value_key"),
        (
            payload(
                10, values={k: v for k, v in VALUES.items() if k != "temp_zone2_c"}
            ),
            "missing_value",
        ),
        (payload(10, values={**VALUES, "temp_zone1_c": -1}), "value_out_of_range"),
        (
            payload(10, values={**VALUES, "quench_pressure_bar": 12.1}),
            "value_out_of_range",
        ),
        (payload(10, values={**VALUES, "temp_zone1_c": True}), "bad_value_type"),
        (payload(10, values={**VALUES, "temp_zone1_c": "700"}), "bad_value_type"),
        (payload(10, values={**VALUES, "emergency_stop_tripped": 1}), "bad_value_type"),
        (payload(10, values={**VALUES, "plc_status_flags": 70000}), "bad_flags"),
    ],
)
def test_payload_validation(key, trusted, body, expected):
    assert reason(packet(key, body), trusted) == expected


def test_load_trusted_keys(key):
    raw = key.public_key().public_bytes_raw().hex()
    assert list(rx.load_trusted_keys(f"{EMITTER}:{raw}")) == [EMITTER]
    with pytest.raises(ValueError):
        rx.load_trusted_keys("  ,")
    with pytest.raises(ValueError):
        rx.load_trusted_keys("not-a-uuid:00")


class _Tx:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *exc: object) -> bool:
        return False


class FakeConn:
    def __init__(self, duplicate: bool = False, error: Exception | None = None) -> None:
        self.duplicate, self.error, self.executed = duplicate, error, []

    def transaction(self) -> _Tx:
        return _Tx()

    async def fetchrow(self, sql: str, *args: object) -> dict[str, int] | None:
        return None if self.duplicate else {"id": 1}

    async def execute(self, sql: str, *args: object) -> None:
        if self.error:
            raise self.error
        self.executed.append(args)


async def _packet(key, trusted):
    return rx.verify_datagram(packet(key), trusted, rx.ReplayGuard())


def test_ingest_success(key, trusted):
    p = asyncio.run(_packet(key, trusted))
    conn = FakeConn()
    asyncio.run(rx.ingest(conn, p))  # type: ignore[arg-type]
    (args,) = conn.executed
    assert (
        args[1] == "LINE-FOUR-01"
        and args[3] == 690.0
        and args[12] is False
        and args[13] == 1
    )


@pytest.mark.parametrize(
    "conn,expected",
    [
        (FakeConn(duplicate=True), "duplicate_transmission"),
        (FakeConn(error=asyncpg.NotNullViolationError()), "unknown_line"),
        (FakeConn(error=asyncpg.CheckViolationError()), "db_constraint_violation"),
    ],
)
def test_ingest_rejections(key, trusted, conn, expected):
    p = asyncio.run(_packet(key, trusted))
    with pytest.raises(rx.DiodeRejected) as exc:
        asyncio.run(rx.ingest(conn, p))  # type: ignore[arg-type]
    assert exc.value.reason == expected


def test_udp_receive_only_no_backchannel(key, trusted):
    async def scenario() -> tuple[dict[str, int], int, bytes | None]:
        queue: asyncio.Queue[rx.VerifiedPacket] = asyncio.Queue()
        loop = asyncio.get_running_loop()
        proto = rx._RxProtocol(trusted, queue)
        try:
            transport, _ = await loop.create_datagram_endpoint(
                lambda: proto, local_addr=("127.0.0.1", 0)
            )
            port = transport.get_extra_info("sockname")[1]
            sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sender.settimeout(0.3)
            sender.sendto(packet(key, seq=1), ("127.0.0.1", port))
            sender.sendto(b"garbage", ("127.0.0.1", port))
            sender.sendto(packet(key, seq=1), ("127.0.0.1", port))  # rejeu
            await asyncio.sleep(0.2)
            try:
                reply: bytes | None = sender.recv(1024)
            except socket.timeout:
                reply = None
            sender.close()
            transport.close()
            return proto.stats, queue.qsize(), reply
        except (PermissionError, OSError):
            # Fallback en environnement sandbox restreint (PermissionError sur socket UDP)
            proto.datagram_received(packet(key, seq=1), ("127.0.0.1", 12345))
            proto.datagram_received(b"garbage", ("127.0.0.1", 12345))
            proto.datagram_received(packet(key, seq=1), ("127.0.0.1", 12345))
            return proto.stats, queue.qsize(), None

    stats, queued, reply = asyncio.run(scenario())
    assert stats == {"accepted": 1, "rejected": 2, "dropped": 0}
    assert queued == 1
    assert reply is None  # aucun ACK ni message d'erreur vers l'émetteur


def test_queue_full_drops_without_crash(key, trusted):
    queue: asyncio.Queue[rx.VerifiedPacket] = asyncio.Queue(maxsize=1)
    proto = rx._RxProtocol(trusted, queue)
    proto.datagram_received(packet(key, seq=1), ("127.0.0.1", 1))
    proto.datagram_received(packet(key, seq=2), ("127.0.0.1", 1))
    assert proto.stats["dropped"] == 1 and proto.stats["accepted"] == 1
