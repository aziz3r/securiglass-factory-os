"""Démon PLC réel : rafales de connexions Modbus courtes (régression du bug de sondage)."""

import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

import pytest

BINARY = (
    Path(__file__).resolve().parents[2]
    / "services"
    / "ot-plc-daemon"
    / "bin"
    / "plc_daemon"
)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture(scope="module")
def port() -> int:
    if not BINARY.exists():
        pytest.skip("démon C non compilé (make -C services/ot-plc-daemon)")
    p = _free_port()
    proc = subprocess.Popen(
        [str(BINARY), "--bind", "127.0.0.1", "--port", str(p)],
        stdout=subprocess.DEVNULL,
    )
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", p), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    yield p
    proc.terminate()
    proc.wait(timeout=5)


def _read_input_registers(port: int, tid: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=2) as s:
            s.sendall(struct.pack(">HHHBBHH", tid, 0, 6, 1, 4, 0, 12))
            data = s.recv(260)
        return len(data) == 33 and struct.unpack(">H", data[:2])[0] == tid
    except OSError:
        return False


def test_sequential_short_connections_all_answered(port: int) -> None:
    assert all(_read_input_registers(port, i) for i in range(150))


def test_concurrent_short_connections_all_answered(port: int) -> None:
    results: list[bool] = []
    threads = [
        threading.Thread(
            target=lambda i=i: results.append(_read_input_registers(port, i))
        )
        for i in range(60)
    ]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert results.count(True) == 60
