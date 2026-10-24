"""Garde-fous communs aux outils Red Team Modbus/TCP SecuriGlass.

Principes non negociables :
  * Cible limitee a 127.0.0.1/32 ou 10.10.30.0/24 (reseau gateway OT).
  * Port limite a 5020 (port du simulateur d'automate de l'Etape 2).
  * Toute operation d'ecriture ou de rejeu exige `--i-have-authorization`.
  * Debit limite (token bucket) et nombre d'operations plafonne.
  * Chaque action est journalisee en JSON Lines (append-only cote outil).
  * Aucune resolution DNS : la cible doit etre une adresse IP litterale, ce
    qui interdit les scans de plages publiques et les cibles ambigues.

Ce module ne depend pas de Scapy : il est testable sans infrastructure.
"""

from __future__ import annotations

import getpass
import ipaddress
import json
import os
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TextIO

# --- Perimetre autorise -----------------------------------------------------
ALLOWED_TARGETS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("127.0.0.1/32"),
    ipaddress.ip_network("10.10.30.0/24"),
)
ALLOWED_PORTS: frozenset[int] = frozenset({5020})
OT_NETWORK = ipaddress.ip_network("10.10.30.0/24")
CONTROL_ROOM_NETWORK = ipaddress.ip_network("10.10.20.0/24")

MIN_RATE = 0.1
MAX_RATE = 20.0
MAX_OPERATIONS = 1000
MAX_TIMEOUT = 30.0

DEFAULT_LOG_DIR = Path(__file__).resolve().parent / "logs"


class GuardrailError(ValueError):
    """Levee lorsqu'une demande sort du perimetre ou des limites autorisees."""


def validate_target(value: str) -> ipaddress.IPv4Address:
    """Valide une cible IPv4 litterale et la contraint au perimetre du labo.

    Une nom d'hote est volontairement refuse : il pourrait resoudre vers une
    adresse publique ou changer apres validation (DNS rebinding).
    """
    if not isinstance(value, str) or not value.strip():
        raise GuardrailError("cible vide : fournir une adresse IPv4 litterale autorisee")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise GuardrailError(
            f"cible invalide '{value}' : adresse IPv4 litterale requise "
            "(aucun nom d'hote, aucune plage)"
        ) from exc

    if not isinstance(address, ipaddress.IPv4Address):
        raise GuardrailError("IPv6 refuse : le perimetre du PoC est IPv4 uniquement")

    if not any(address in network for network in ALLOWED_TARGETS):
        raise GuardrailError(
            f"cible {address} hors perimetre : seules 127.0.0.1 et 10.10.30.0/24 "
            "sont autorisees (aucun scan de plage publique)"
        )
    return address


def validate_port(value: int) -> int:
    """Le port est fige a 5020 (simulateur d'automate SecuriGlass)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise GuardrailError("port invalide : entier 5020 attendu")
    if value not in ALLOWED_PORTS:
        raise GuardrailError(
            f"port {value} interdit : seul le port 5020 du simulateur OT est autorise"
        )
    return value


def validate_rate(value: float) -> float:
    if value < MIN_RATE or value > MAX_RATE:
        raise GuardrailError(
            f"debit {value} hors limites : {MIN_RATE} a {MAX_RATE} operations/seconde"
        )
    return float(value)


def validate_max_operations(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise GuardrailError("max-operations invalide : entier attendu")
    if value < 1 or value > MAX_OPERATIONS:
        raise GuardrailError(
            f"max-operations hors limites : 1 a {MAX_OPERATIONS}"
        )
    return value


def validate_timeout(value: float) -> float:
    if value <= 0 or value > MAX_TIMEOUT:
        raise GuardrailError(f"timeout hors limites : > 0 et <= {MAX_TIMEOUT} secondes")
    return float(value)


def validate_unit_id(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 255:
        raise GuardrailError("unit-id invalide : entier 0 a 255")
    return value


def validate_address(value: int, *, max_value: int = 65535) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= max_value:
        raise GuardrailError(f"adresse invalide : entier 0 a {max_value}")
    return value


def require_authorization(authorized: bool, action: str) -> None:
    """Refuse toute ecriture/rejeu sans preuve d'autorisation explicite."""
    if authorized is not True:
        raise GuardrailError(
            f"operation '{action}' refusee : --i-have-authorization est obligatoire "
            "pour toute ecriture ou tout rejeu de trame"
        )


def parse_int_list(raw: str, *, minimum: int = 0, maximum: int = 65535) -> list[int]:
    """Parse '1,2,3' en liste d'entiers bornes (pour FC15/FC16)."""
    if not raw or not raw.strip():
        raise GuardrailError("liste de valeurs vide")
    values: list[int] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            raise GuardrailError(f"liste de valeurs invalide : '{raw}'")
        try:
            value = int(token, 10)
        except ValueError as exc:
            raise GuardrailError(f"valeur non entiere : '{token}'") from exc
        if value < minimum or value > maximum:
            raise GuardrailError(
                f"valeur {value} hors limites : {minimum} a {maximum}"
            )
        values.append(value)
    return values


class RateLimiter:
    """Token bucket simple, injectable pour les tests (horloge et sleep)."""

    def __init__(
        self,
        rate: float,
        *,
        burst: float | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.rate = validate_rate(rate)
        self.capacity = float(burst if burst is not None else max(1.0, self.rate))
        self._tokens = self.capacity
        self._clock = clock
        self._sleep = sleeper
        self._last = clock()

    def acquire(self) -> float:
        """Consomme un jeton ; retourne le temps d'attente effectif (secondes)."""
        waited = 0.0
        now = self._clock()
        elapsed = max(0.0, now - self._last)
        self._last = now
        self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)

        if self._tokens < 1.0:
            missing = 1.0 - self._tokens
            delay = missing / self.rate
            self._sleep(delay)
            waited += delay
            self._tokens = 0.0
            self._last = self._clock()
        else:
            self._tokens -= 1.0
        return waited


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class AuditLogger:
    """Journal JSON Lines local, horodate en UTC, sans secret."""

    tool: str
    log_dir: Path = DEFAULT_LOG_DIR
    stream: TextIO = sys.stderr
    path: Path = field(init=False)
    _fh: TextIO = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.log_dir = Path(self.log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        self.path = self.log_dir / f"redteam-{day}.jsonl"
        self._fh = self.path.open("a", encoding="utf-8")

    def log(self, event: str, **fields: Any) -> dict[str, Any]:
        record: dict[str, Any] = {
            "ts": _utc_now(),
            "tool": self.tool,
            "event": event,
            "user": getpass.getuser(),
            "pid": os.getpid(),
        }
        record.update(fields)
        line = json.dumps(record, ensure_ascii=False, sort_keys=True)
        self._fh.write(line + "\n")
        self._fh.flush()
        self.stream.write(f"[redteam] {line}\n")
        self.stream.flush()
        return record

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:  # pragma: no cover - fermeture best effort
            pass


@dataclass
class Session:
    """Contexte d'execution valide : cible, limites, journal, compteur."""

    tool: str
    action: str
    target: ipaddress.IPv4Address
    port: int
    unit_id: int
    timeout: float
    limiter: RateLimiter
    logger: AuditLogger
    max_operations: int
    authorized: bool
    authorization_ref: str = ""
    operations: int = 0

    def before_operation(self, description: str) -> None:
        if self.operations >= self.max_operations:
            raise GuardrailError(
                f"limite de {self.max_operations} operations atteinte : arret preventif"
            )
        waited = self.limiter.acquire()
        self.operations += 1
        self.logger.log(
            "request",
            target=str(self.target),
            port=self.port,
            unit_id=self.unit_id,
            operation=self.operations,
            description=description,
            authorized=self.authorized,
            authorization_ref=self.authorization_ref,
            rate_wait_s=round(waited, 4),
        )

    def log_result(self, **fields: Any) -> None:
        self.logger.log(
            "result",
            target=str(self.target),
            port=self.port,
            authorized=self.authorized,
            authorization_ref=self.authorization_ref,
            **fields,
        )


def build_session(
    *,
    tool: str,
    action: str,
    target: str,
    port: int,
    unit_id: int,
    timeout: float,
    rate: float,
    max_operations: int,
    authorized: bool,
    authorization_ref: str = "",
    log_dir: Path | str | None = None,
    need_authorization: bool = False,
    stream: TextIO = sys.stderr,
) -> Session:
    """Valide tous les parametres, applique les garde-fous et ouvre le journal."""
    address = validate_target(target)
    validated_port = validate_port(port)
    validated_unit = validate_unit_id(unit_id)
    validated_timeout = validate_timeout(timeout)
    validated_rate = validate_rate(rate)
    validated_max = validate_max_operations(max_operations)

    if need_authorization:
        require_authorization(authorized, action)

    log_path = Path(log_dir) if log_dir else Path(
        os.environ.get("REDTEAM_LOG_DIR", str(DEFAULT_LOG_DIR))
    )
    logger = AuditLogger(tool=tool, log_dir=log_path, stream=stream)
    logger.log(
        "start",
        action=action,
        target=str(address),
        port=validated_port,
        unit_id=validated_unit,
        rate=validated_rate,
        max_operations=validated_max,
        authorized=authorized,
        authorization_ref=authorization_ref,
        allowed_targets=[str(n) for n in ALLOWED_TARGETS],
    )
    return Session(
        tool=tool,
        action=action,
        target=address,
        port=validated_port,
        unit_id=validated_unit,
        timeout=validated_timeout,
        limiter=RateLimiter(validated_rate),
        logger=logger,
        max_operations=validated_max,
        authorized=authorized,
        authorization_ref=authorization_ref,
    )
