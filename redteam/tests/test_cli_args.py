"""Tests d'interface des trois outils Red Team, sans emission reseau."""

from __future__ import annotations

from pathlib import Path

import pytest

from redteam import modbus_recon, modbus_write


def _common(tmp_path: Path) -> list[str]:
    return ["--log-dir", str(tmp_path)]


def test_recon_refuse_cible_publique(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = modbus_recon.main(
        ["--target", "8.8.8.8", "--function", "3", "--dry-run", *_common(tmp_path)]
    )
    assert code == 2
    assert "hors perimetre" in capsys.readouterr().err


def test_recon_dry_run_ok(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
    def interdit(*args: object, **kwargs: object) -> None:
        raise AssertionError("aucune connexion ne doit etre ouverte en dry-run")

    monkeypatch.setattr(modbus_recon, "open_tcp_session", interdit)
    code = modbus_recon.main(
        [
            "--target",
            "127.0.0.1",
            "--function",
            "3",
            "--start",
            "0",
            "--count",
            "2",
            "--dry-run",
            *_common(tmp_path),
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert '"status": "DRY_RUN"' in out
    assert '"request_hex"' in out


def test_write_refuse_sans_autorisation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = modbus_write.main(
        [
            "--target",
            "127.0.0.1",
            "--function",
            "6",
            "--address",
            "0",
            "--value",
            "1",
            "--dry-run",
            *_common(tmp_path),
        ]
    )
    assert code == 2
    assert "i-have-authorization" in capsys.readouterr().err


def test_write_refuse_cible_salle_controle(tmp_path: Path) -> None:
    code = modbus_write.main(
        [
            "--target",
            "10.10.20.10",
            "--function",
            "6",
            "--address",
            "0",
            "--value",
            "1",
            "--i-have-authorization",
            "--dry-run",
            *_common(tmp_path),
        ]
    )
    assert code == 2


def test_write_refuse_port_502(tmp_path: Path) -> None:
    code = modbus_write.main(
        [
            "--target",
            "127.0.0.1",
            "--port",
            "502",
            "--function",
            "6",
            "--address",
            "0",
            "--value",
            "1",
            "--i-have-authorization",
            "--dry-run",
            *_common(tmp_path),
        ]
    )
    assert code == 2


def test_write_dry_run_avec_autorisation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    code = modbus_write.main(
        [
            "--target",
            "10.10.30.10",
            "--function",
            "16",
            "--address",
            "10",
            "--values",
            "700,701,702",
            "--i-have-authorization",
            "--authorization-ref",
            "LAB-2026-001",
            "--dry-run",
            *_common(tmp_path),
        ]
    )
    assert code == 0
    out = capsys.readouterr().out
    assert '"authorized": true' in out
    assert '"values": [' in out
    assert "LAB-2026-001" in out


@pytest.mark.parametrize(
    "extra",
    [
        ["--function", "5", "--address", "0", "--value", "2"],  # FC5 : bit invalide
        ["--function", "6", "--address", "0"],  # valeur manquante
        ["--function", "16", "--address", "0", "--values", "1,,2"],
        ["--function", "16", "--address", "0", "--values", "70000"],
        ["--function", "6", "--address", "0", "--value", "1", "--values", "1,2"],
    ],
)
def test_write_rejette_arguments_invalides(
    tmp_path: Path, extra: list[str]
) -> None:
    code = modbus_write.main(
        [
            "--target",
            "127.0.0.1",
            "--i-have-authorization",
            "--dry-run",
            *extra,
            *_common(tmp_path),
        ]
    )
    assert code == 2


def test_recon_rejette_count_hors_limite(tmp_path: Path) -> None:
    code = modbus_recon.main(
        [
            "--target",
            "127.0.0.1",
            "--function",
            "3",
            "--count",
            "126",
            "--dry-run",
            *_common(tmp_path),
        ]
    )
    assert code == 2
