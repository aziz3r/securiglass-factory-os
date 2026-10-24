"""Trames de télémétrie four EN 12150 : validation physique et sérialisation canonique.

Conforme IEC 62443 et spécification de sécurité OT SecuriGlass Factory OS.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final

SCHEMA_VERSION: Final[int] = 1

# Plages physiques autorisées (unités SI après mise à l'échelle)
LIMITS: Final[dict[str, tuple[float, float]]] = {
    "temp_zone1_c": (0.0, 850.0),
    "temp_zone2_c": (0.0, 850.0),
    "temp_zone3_c": (0.0, 850.0),
    "temp_zone4_c": (0.0, 850.0),
    "glass_pyrometer_temp_c": (0.0, 850.0),
    "quench_pressure_bar": (0.0, 12.0),
    "conveyor_speed_m_min": (0.0, 50.0),
    "blower_current_amps": (0.0, 100.0),
    "power_consumption_kw": (0.0, 500.0),
}

ALLOWED_METRIC_KEYS: Final[frozenset[str]] = frozenset(LIMITS) | {
    "emergency_stop_tripped",
    "plc_status_flags",
}

MAX_PAYLOAD_BYTES: Final[int] = 8192


class FrameValidationError(ValueError):
    """Trame rejetée : violation de validité physique ou syntaxique."""


def utc_now_iso() -> str:
    """Retourne la date/heure courante UTC au format ISO 8601 strict."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def canonical_json(payload: dict[str, Any]) -> bytes:
    """Sérialisation déterministe canonique (RFC 8785 subset) :
    clés triées, séparateurs compacts sans espaces, ASCII strict, NaN rejetés.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


@dataclass(frozen=True, slots=True)
class TelemetryFrame:
    """Mesure de télémétrie process four EN 12150."""

    line_id: str
    sequence: int
    measured_at: str
    values: dict[str, float | int | bool] = field(default_factory=dict)
    batch_id: str | None = None
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        self._validate()

    def _validate(self) -> None:
        if not isinstance(self.line_id, str) or not (1 <= len(self.line_id) <= 64):
            raise FrameValidationError(
                "line_id invalide : attendu chaîne de 1 à 64 caractères"
            )
        if not all(c.isalnum() or c in "-_" for c in self.line_id):
            raise FrameValidationError(
                "line_id contient des caractères interdits (alphanumérique, tiret, underscore)"
            )

        if isinstance(self.sequence, bool) or not isinstance(self.sequence, int):
            raise FrameValidationError("sequence doit être un entier non-booléen")
        if not (0 <= self.sequence <= 0xFFFFFFFFFFFFFFFF):
            raise FrameValidationError("sequence hors bornes uint64 (0 .. 2^64-1)")

        if self.schema_version != SCHEMA_VERSION:
            raise FrameValidationError(
                f"version de schéma non supportée : {self.schema_version}"
            )

        try:
            parsed = datetime.fromisoformat(self.measured_at)
        except (TypeError, ValueError) as exc:
            raise FrameValidationError(
                "measured_at n'est pas une date ISO-8601 valide"
            ) from exc
        if parsed.tzinfo is None:
            raise FrameValidationError("measured_at doit être timezone-aware (ex: UTC)")

        if self.batch_id is not None:
            if not isinstance(self.batch_id, str) or not (
                1 <= len(self.batch_id) <= 64
            ):
                raise FrameValidationError("batch_id invalide")

        unknown = set(self.values) - ALLOWED_METRIC_KEYS
        if unknown:
            raise FrameValidationError(
                f"clés de métriques non autorisées : {sorted(unknown)}"
            )
        if not self.values:
            raise FrameValidationError("trame de métriques vide")

        for key, value in self.values.items():
            if key in LIMITS:
                if isinstance(value, bool) or not isinstance(value, (int, float)):
                    raise FrameValidationError(f"{key} doit être une valeur numérique")
                numeric = float(value)
                if not math.isfinite(numeric):
                    raise FrameValidationError(
                        f"{key} doit être un nombre fini (pas de NaN/Inf)"
                    )
                low, high = LIMITS[key]
                if not (low <= numeric <= high):
                    raise FrameValidationError(
                        f"Grandeur physique hors tolérance EN 12150 pour {key}: "
                        f"{numeric} n'est pas dans [{low}, {high}]"
                    )
            elif key == "emergency_stop_tripped":
                if not isinstance(value, bool):
                    raise FrameValidationError(
                        "emergency_stop_tripped doit être un booléen"
                    )
            elif key == "plc_status_flags":
                if isinstance(value, bool) or not isinstance(value, int):
                    raise FrameValidationError("plc_status_flags doit être un entier")
                if not (0 <= value <= 0xFFFF):
                    raise FrameValidationError(
                        "plc_status_flags hors bornes uint16 (0..65535)"
                    )

    def to_dict(self) -> dict[str, Any]:
        """Convertit la trame en dictionnaire prêt pour le JSON canonique."""
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "line_id": self.line_id,
            "sequence": self.sequence,
            "measured_at": self.measured_at,
            "values": dict(self.values),
        }
        if self.batch_id is not None:
            data["batch_id"] = self.batch_id
        return data

    def canonical_bytes(self) -> bytes:
        """Produit la représentation canonique binaire du payload."""
        encoded = canonical_json(self.to_dict())
        if len(encoded) > MAX_PAYLOAD_BYTES:
            raise FrameValidationError(
                f"Payload trop volumineux : {len(encoded)} octets > max {MAX_PAYLOAD_BYTES}"
            )
        return encoded
