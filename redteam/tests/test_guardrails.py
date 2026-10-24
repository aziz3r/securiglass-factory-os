"""Tests des garde-fous Red Team (aucun reseau, aucune infrastructure)."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from redteam.guardrails import (
    ALLOWED_TARGETS,
    AuditLogger,
    GuardrailError,
    RateLimiter,
    build_session,
    parse_int_list,
    require_authorization,
    validate_address,
    validate_max_operations,
    validate_port,
    validate_rate,
    validate_target,
    validate_timeout,
    validate_unit_id,
)


@pytest.mark.parametrize("value", ["127.0.0.1", "10.10.30.1", "10.10.30.254", "10.10.30.0"])
def test_targets_autorisees(value: str) -> None:
    assert str(validate_target(value)) == value


@pytest.mark.parametrize(
    "value",
    [
        "8.8.8.8",
        "1.1.1.1",
        "10.10.20.5",
        "192.168.1.10",
        "127.0.0.2",
        "0.0.0.0",
        "224.0.0.1",
        "169.254.1.1",
        "::1",
        "localhost",
        "example.com",
        "10.10.30.0/24",
        "",
        " ",
    ],
)
def test_cibles_refusees(value: str) -> None:
    with pytest.raises(GuardrailError):
        validate_target(value)


def test_perimetre_est_bien_limite() -> None:
    assert [str(n) for n in ALLOWED_TARGETS] == ["127.0.0.1/32", "10.10.30.0/24"]


@pytest.mark.parametrize("port", [502, 80, 443, 0, 65535])
def test_ports_refuses(port: int) -> None:
    with pytest.raises(GuardrailError):
        validate_port(port)


def test_port_5020_accepte() -> None:
    assert validate_port(5020) == 5020


@pytest.mark.parametrize("rate", [0.0, -1.0, 0.05, 20.01, 100.0])
def test_debit_refuse(rate: float) -> None:
    with pytest.raises(GuardrailError):
        validate_rate(rate)


@pytest.mark.parametrize("rate", [0.1, 1.0, 5.0, 20.0])
def test_debit_accepte(rate: float) -> None:
    assert validate_rate(rate) == rate


@pytest.mark.parametrize("value", [0, -1, 1001, 10_000])
def test_max_operations_refuse(value: int) -> None:
    with pytest.raises(GuardrailError):
        validate_max_operations(value)


@pytest.mark.parametrize("value", [0.0, -1.0, 30.01, 100.0])
def test_timeout_refuse(value: float) -> None:
    with pytest.raises(GuardrailError):
        validate_timeout(value)


@pytest.mark.parametrize("value", [-1, 256, 999])
def test_unit_id_refuse(value: int) -> None:
    with pytest.raises(GuardrailError):
        validate_unit_id(value)


@pytest.mark.parametrize("value", [0, 1, 65535])
def test_addresses_acceptees(value: int) -> None:
    assert validate_address(value) == value


def test_autorisation_obligatoire() -> None:
    with pytest.raises(GuardrailError, match="i-have-authorization"):
        require_authorization(False, "write")
    require_authorization(True, "write")  # ne leve pas


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0,1,1", [0, 1, 1]),
        (" 10 , 20 ", [10, 20]),
        ("65535", [65535]),
    ],
)
def test_parse_int_list_valide(raw: str, expected: list[int]) -> None:
    assert parse_int_list(raw) == expected


@pytest.mark.parametrize("raw", ["", " ", "1,,2", "a,b", "1,70000", "-1"])
def test_parse_int_list_invalide(raw: str) -> None:
    with pytest.raises(GuardrailError):
        parse_int_list(raw)


def test_rate_limiter_token_bucket() -> None:
    clock = [0.0]
    sleeps: list[float] = []

    def now() -> float:
        return clock[0]

    def sleeper(delay: float) -> None:
        sleeps.append(delay)
        clock[0] += delay

    limiter = RateLimiter(2.0, burst=1, clock=now, sleeper=sleeper)
    assert limiter.acquire() == 0.0
    assert limiter.acquire() == pytest.approx(0.5)
    assert sleeps == [pytest.approx(0.5)]


def test_rate_limiter_refill() -> None:
    clock = [0.0]
    limiter = RateLimiter(2.0, burst=1, clock=lambda: clock[0], sleeper=lambda d: None)
    assert limiter.acquire() == 0.0
    clock[0] = 10.0  # 20 jetons gagnes, plafonnes a 1
    assert limiter.acquire() == 0.0


def test_build_session_refuse_cible_hors_perimetre(tmp_path: Path) -> None:
    with pytest.raises(GuardrailError):
        build_session(
            tool="test",
            action="read",
            target="10.10.20.10",
            port=5020,
            unit_id=1,
            timeout=1.0,
            rate=1.0,
            max_operations=1,
            authorized=False,
            log_dir=tmp_path,
            stream=io.StringIO(),
        )
    assert not list(tmp_path.glob("*.jsonl"))


def test_build_session_refuse_ecriture_sans_autorisation(tmp_path: Path) -> None:
    with pytest.raises(GuardrailError):
        build_session(
            tool="test",
            action="write",
            target="127.0.0.1",
            port=5020,
            unit_id=1,
            timeout=1.0,
            rate=1.0,
            max_operations=1,
            authorized=False,
            need_authorization=True,
            log_dir=tmp_path,
            stream=io.StringIO(),
        )


def test_build_session_journalise_et_limite(tmp_path: Path) -> None:
    stream = io.StringIO()
    session = build_session(
        tool="test",
        action="write",
        target="127.0.0.1",
        port=5020,
        unit_id=1,
        timeout=1.0,
        rate=20.0,
        max_operations=1,
        authorized=True,
        authorization_ref="LAB-TEST-42",
        log_dir=tmp_path,
        need_authorization=True,
        stream=stream,
    )
    session.before_operation("test")
    with pytest.raises(GuardrailError, match="limite"):
        session.before_operation("test-2")
    session.logger.close()

    log_file = next(tmp_path.glob("redteam-*.jsonl"))
    content = log_file.read_text(encoding="utf-8")
    assert '"event": "start"' in content
    assert '"authorization_ref": "LAB-TEST-42"' in content
    assert '"event": "request"' in content
    assert "LAB-TEST-42" in stream.getvalue()


def test_audit_logger_ne_contient_pas_de_mot_de_passe(tmp_path: Path) -> None:
    logger = AuditLogger(tool="test", log_dir=tmp_path, stream=io.StringIO())
    logger.log("test", note="aucun secret")
    logger.close()
    content = next(tmp_path.glob("redteam-*.jsonl")).read_text(encoding="utf-8")
    assert "password" not in content.lower()
    assert "aucun secret" in content
