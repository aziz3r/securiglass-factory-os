"""Tests du rejeu de trames capturees (pcap synthetique, sans reseau)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("scapy", reason="Scapy absent : tests de rejeu explicitement ignores")

from scapy.all import Ether, IP, Raw, TCP, wrpcap  # noqa: E402

from redteam import modbus_replay  # noqa: E402
from redteam.modbus_proto import build_request  # noqa: E402


def _make_pcap(tmp_path: Path) -> Path:
    write_frame = build_request(
        transaction_id=10, unit_id=1, function_code=6, start=0, values=[1]
    )
    read_frame = build_request(
        transaction_id=11, unit_id=1, function_code=3, start=0, count=2
    )
    packets = [
        Ether()
        / IP(src="10.10.20.10", dst="10.10.30.10")
        / TCP(sport=40000, dport=5020)
        / Raw(load=write_frame),
        Ether()
        / IP(src="10.10.20.10", dst="10.10.30.10")
        / TCP(sport=40001, dport=5020)
        / Raw(load=read_frame),
    ]
    path = tmp_path / "capture.pcap"
    wrpcap(str(path), packets)
    return path


def test_replay_sans_autorisation_refuse(tmp_path: Path) -> None:
    pcap = _make_pcap(tmp_path)
    code = modbus_replay.main(
        [
            "--target",
            "127.0.0.1",
            "--pcap",
            str(pcap),
            "--dry-run",
            "--i-have-authorization",
            "--log-dir",
            str(tmp_path),
        ]
    )
    assert code == 0


def test_replay_exige_autorisation_meme_en_dry_run(tmp_path: Path) -> None:
    pcap = _make_pcap(tmp_path)
    code = modbus_replay.main(
        ["--target", "127.0.0.1", "--pcap", str(pcap), "--dry-run", "--log-dir", str(tmp_path)]
    )
    assert code == 2


def test_replay_cible_non_autorisee(tmp_path: Path) -> None:
    pcap = _make_pcap(tmp_path)
    code = modbus_replay.main(
        [
            "--target",
            "10.10.20.10",
            "--pcap",
            str(pcap),
            "--dry-run",
            "--i-have-authorization",
            "--log-dir",
            str(tmp_path),
        ]
    )
    assert code == 2


def test_replay_dry_run_ne_touche_pas_le_reseau(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    pcap = _make_pcap(tmp_path)

    def interdit(*args: object, **kwargs: object) -> None:
        raise AssertionError("aucune connexion en dry-run")

    monkeypatch.setattr(modbus_replay, "open_tcp_session", interdit)

    code = modbus_replay.main(
        [
            "--target",
            "127.0.0.1",
            "--pcap",
            str(pcap),
            "--dry-run",
            "--limit",
            "2",
            "--i-have-authorization",
            "--authorization-ref",
            "LAB-REPLAY-1",
            "--log-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "OK"
    assert len(payload["frames"]) == 2
    assert all(frame["status"] == "DRY_RUN" for frame in payload["frames"])


def test_replay_filtre_fonction(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pcap = _make_pcap(tmp_path)
    code = modbus_replay.main(
        [
            "--target",
            "127.0.0.1",
            "--pcap",
            str(pcap),
            "--dry-run",
            "--filter-function",
            "6",
            "--i-have-authorization",
            "--log-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["frames"]) == 1
    assert payload["frames"][0]["frame"]["function_code"] == 6


def test_replay_pcap_absent(tmp_path: Path) -> None:
    code = modbus_replay.main(
        [
            "--target",
            "127.0.0.1",
            "--pcap",
            str(tmp_path / "absent.pcap"),
            "--dry-run",
            "--i-have-authorization",
            "--log-dir",
            str(tmp_path),
        ]
    )
    assert code == 4
