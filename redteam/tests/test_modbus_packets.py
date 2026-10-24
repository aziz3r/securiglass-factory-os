"""Tests de construction/analyse Modbus et de lecture pcap avec Scapy."""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("scapy", reason="Scapy absent : tests de paquets explicitement ignores")

from scapy.all import Ether, IP, Raw, TCP, wrpcap  # noqa: E402

from redteam.modbus_proto import (  # noqa: E402
    ModbusProtocolError,
    build_request,
    build_write_multiple_pdu,
    build_write_single_pdu,
    frame_summary,
    parse_mbap,
    parse_response,
)
from redteam.modbus_scapy import build_tcp_packet, extract_modbus_payloads  # noqa: E402


def test_fc3_requete_hex() -> None:
    payload = build_request(
        transaction_id=0x0001, unit_id=1, function_code=3, start=0, count=10
    )
    assert payload.hex() == "00010000000601030000000a"
    frame = parse_mbap(payload)
    assert frame.transaction_id == 1
    assert frame.unit_id == 1
    assert frame.function_code == 3
    assert frame.function_name == "READ_HOLDING_REGISTERS"


def test_fc6_requete_hex() -> None:
    payload = build_request(
        transaction_id=0x1234, unit_id=1, function_code=6, start=0, values=[1]
    )
    assert payload.hex() == "123400000006010600000001"


def test_fc16_requete_hex() -> None:
    payload = build_request(
        transaction_id=1,
        unit_id=2,
        function_code=16,
        start=5,
        values=[10, 20],
    )
    assert payload.hex() == "00010000000b02100005000204000a0014"


def test_fc15_requete_hex() -> None:
    payload = build_request(
        transaction_id=1,
        unit_id=1,
        function_code=15,
        start=0,
        values=[1, 0, 1],
    )
    assert payload.hex() == "000100000008010f000000030105"


def test_fc5_valeurs_acceptees_et_refusees() -> None:
    assert build_write_single_pdu(5, 0, 1).hex() == "050000ff00"
    assert build_write_single_pdu(5, 0, 0).hex() == "0500000000"
    with pytest.raises(ModbusProtocolError):
        build_write_single_pdu(5, 0, 2)


def test_fc6_valeur_hors_limite() -> None:
    with pytest.raises(ModbusProtocolError):
        build_write_single_pdu(6, 0, 70000)


def test_fc16_trop_de_registres() -> None:
    with pytest.raises(ModbusProtocolError):
        build_write_multiple_pdu(16, 0, [1] * 124)


def test_reponse_fc3() -> None:
    raw = bytes.fromhex("000100000007010304000a0014")
    decoded = parse_response(raw)
    assert decoded["function_code"] == 3
    assert decoded["values"] == [10, 20]
    assert decoded["is_exception"] is False


def test_reponse_exception() -> None:
    raw = bytes.fromhex("000100000003018302")
    decoded = parse_response(raw)
    assert decoded["is_exception"] is True
    assert decoded["exception_code"] == 2
    assert decoded["exception_name"] == "ILLEGAL_DATA_ADDRESS"


def test_mbap_invalide() -> None:
    with pytest.raises(ModbusProtocolError):
        parse_mbap(bytes.fromhex("0001000100060103"))
    with pytest.raises(ModbusProtocolError):
        parse_mbap(b"\x00\x01")


def test_frame_summary() -> None:
    summary = frame_summary(bytes.fromhex("000100000006010600000001"))
    assert summary["valid"] is True
    assert summary["function_code"] == 6
    assert frame_summary(b"nope")["valid"] is False


def test_paquet_scapy() -> None:
    payload = build_request(
        transaction_id=7, unit_id=1, function_code=3, start=0, count=2
    )
    packet = build_tcp_packet("127.0.0.1", 5020, payload)
    assert packet.haslayer(IP)
    assert packet.haslayer(TCP)
    assert packet[TCP].dport == 5020
    assert bytes(packet[Raw].load) == payload


def test_extraction_pcap(tmp_path: Path) -> None:
    payload = build_request(
        transaction_id=42, unit_id=1, function_code=6, start=0, values=[1]
    )
    packet = Ether() / IP(src="10.10.20.10", dst="10.10.30.10") / TCP(
        sport=40123, dport=5020
    ) / Raw(load=payload)
    pcap = tmp_path / "capture.pcap"
    wrpcap(str(pcap), [packet])

    frames = extract_modbus_payloads(pcap, limit=10)
    assert len(frames) == 1
    assert frames[0]["payload"] == payload
    assert frames[0]["src_ip"] == "10.10.20.10"
    assert frames[0]["frame"].function_code == 6


def test_extraction_pcap_filtre_fonction(tmp_path: Path) -> None:
    write_frame = build_request(
        transaction_id=1, unit_id=1, function_code=6, start=0, values=[1]
    )
    read_frame = build_request(
        transaction_id=2, unit_id=1, function_code=3, start=0, count=2
    )
    packets = [
        Ether() / IP(src="10.10.20.10", dst="10.10.30.10") / TCP(sport=40000, dport=5020) / Raw(load=write_frame),
        Ether() / IP(src="10.10.20.10", dst="10.10.30.10") / TCP(sport=40001, dport=5020) / Raw(load=read_frame),
    ]
    pcap = tmp_path / "capture2.pcap"
    wrpcap(str(pcap), packets)

    assert len(extract_modbus_payloads(pcap)) == 2
    assert len(extract_modbus_payloads(pcap, function_filter=6)) == 1
    assert len(extract_modbus_payloads(pcap, limit=1)) == 1


def test_pcap_absent() -> None:
    with pytest.raises(FileNotFoundError):
        extract_modbus_payloads("/tmp/inexistant-securiglass.pcap")
