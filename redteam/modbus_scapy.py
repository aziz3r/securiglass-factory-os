"""Couche Scapy des outils Red Team Modbus/TCP.

Scapy est importe de facon optionnelle : les modules de construction de trames
(`modbus_proto`) restent utilisables sans Scapy. Les tests de paquets sont
explicitement ignores si Scapy n'est pas installe.

Deux modes de transport sont fournis :
  * `stream` (defaut) : vraie session TCP via `StreamSocket` Scapy, sans root.
  * `raw` : emission L3/L4 brute via `send()`/`sr1()` (necessite les droits
    reseau, utile pour un rejeu fidele sur un banc isole).
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, Sequence

from .modbus_proto import ModbusFrame, ModbusProtocolError, parse_mbap

try:  # pragma: no cover - depend de l'environnement d'execution
    from scapy.all import IP, TCP, Raw, conf, rdpcap, send, sr1
    from scapy.supersocket import StreamSocket

    SCAPY_AVAILABLE = True
    SCAPY_IMPORT_ERROR: str | None = None
except Exception as exc:  # pragma: no cover
    IP = TCP = Raw = conf = rdpcap = send = sr1 = None  # type: ignore[assignment]
    StreamSocket = None  # type: ignore[assignment]
    SCAPY_AVAILABLE = False
    SCAPY_IMPORT_ERROR = str(exc)


class ScapyNotInstalledError(RuntimeError):
    """Scapy absent : installer `siem/.venv` ou desactiver les tests reseau."""


def require_scapy() -> None:
    if not SCAPY_AVAILABLE:
        raise ScapyNotInstalledError(
            "Scapy n'est pas installe dans cet environnement "
            f"({SCAPY_IMPORT_ERROR}). Utiliser siem/.venv."
        )


@dataclass
class TcpSession:
    """Session TCP Scapy minimale, fermee explicitement par l'appelant."""

    stream: Any
    socket: socket.socket

    def send_payload(self, payload: bytes) -> bytes | None:
        self.stream.send(Raw(load=payload))
        response = self.stream.recv()
        if response is None:
            return None
        return bytes(response.load)

    def close(self) -> None:
        try:
            self.stream.close()
        finally:
            try:
                self.socket.close()
            except OSError:
                pass


def open_tcp_session(target: str, port: int, timeout: float) -> TcpSession:
    """Ouvre une vraie connexion TCP et l'enveloppe dans un StreamSocket Scapy."""
    require_scapy()
    sock = socket.create_connection((target, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        stream = StreamSocket(sock, Raw)
    except Exception:
        sock.close()
        raise
    return TcpSession(stream=stream, socket=sock)


def build_tcp_packet(
    target: str,
    port: int,
    payload: bytes,
    *,
    sport: int | None = None,
) -> Any:
    """Construit IP/TCP/Raw (pour affichage, dry-run ou emission brute)."""
    require_scapy()
    layer = IP(dst=target) / TCP(sport=sport, dport=port, flags="PA") / Raw(load=payload)
    return layer


def send_raw_packet(packet: Any, timeout: float) -> bytes | None:
    """Emission L3 brute ; retourne la charge utile de la reponse TCP."""
    require_scapy()
    answered = sr1(packet, timeout=timeout, verbose=False)
    if answered is None:
        return None
    if answered.haslayer(Raw):
        return bytes(answered[Raw].load)
    return None


def send_raw_no_wait(packet: Any) -> None:
    require_scapy()
    send(packet, verbose=False)


def extract_modbus_payloads(
    pcap_path: str | Path,
    *,
    port: int = 5020,
    only_requests: bool = True,
    function_filter: int | None = None,
    limit: int = 100,
) -> list[dict[str, Any]]:
    """Extrait les trames Modbus/TCP d'un pcap, sans les envoyer."""
    require_scapy()
    path = Path(pcap_path)
    if not path.is_file():
        raise FileNotFoundError(f"pcap introuvable : {path}")

    frames: list[dict[str, Any]] = []
    for packet in rdpcap(str(path)):
        if not (packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw)):
            continue
        tcp = packet[TCP]
        if int(tcp.dport) != port:
            continue
        payload = bytes(packet[Raw].load)
        try:
            frame = parse_mbap(payload)
        except ModbusProtocolError:
            continue
        if only_requests and frame.is_exception:
            continue
        if function_filter is not None and (frame.function_code & 0x7F) != function_filter:
            continue
        frames.append(
            {
                "payload": payload,
                "src_ip": packet[IP].src,
                "dst_ip": packet[IP].dst,
                "sport": int(tcp.sport),
                "dport": int(tcp.dport),
                "frame": frame,
            }
        )
        if len(frames) >= limit:
            break
    return frames


def iter_pcap_frames(
    pcap_path: str | Path,
    *,
    port: int = 5020,
    only_requests: bool = True,
    function_filter: int | None = None,
    limit: int = 100,
) -> Iterator[dict[str, Any]]:
    yield from extract_modbus_payloads(
        pcap_path,
        port=port,
        only_requests=only_requests,
        function_filter=function_filter,
        limit=limit,
    )
