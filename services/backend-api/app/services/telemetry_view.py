"""Projection d'une ligne `ot_data.furnace_telemetry` pour la console + diagnostic ML.

Partagé par le canal WebSocket (`/ws/telemetry`) et l'historique REST
(`/api/v1/factory/telemetry/history`). Le diagnostic est celui du détecteur
d'anomalies (Isolation Forest + signatures de pannes) : une trame sans diagnostic
(`anomaly: None`) n'est jamais présentée comme « normale ».
"""

import logging
from datetime import timezone
from typing import Any, Final

from app.services.ml_anomaly import FEATURES, InvalidSample, anomaly_detector

logger = logging.getLogger("securiglass.telemetry_view")

# Requêtes littérales (aucune construction dynamique de SQL).
SELECT_LATEST: Final = (
    "SELECT id, timestamp, temp_zone1_c, temp_zone2_c, temp_zone3_c, temp_zone4_c,"
    " glass_pyrometer_temp_c, quench_pressure_bar, conveyor_speed_m_min,"
    " blower_current_amps, power_consumption_kw, plc_status_flags"
    " FROM ot_data.furnace_telemetry ORDER BY timestamp DESC, id DESC LIMIT 1"
)
SELECT_RECENT: Final = (
    "SELECT id, timestamp, temp_zone1_c, temp_zone2_c, temp_zone3_c, temp_zone4_c,"
    " glass_pyrometer_temp_c, quench_pressure_bar, conveyor_speed_m_min,"
    " blower_current_amps, power_consumption_kw, plc_status_flags"
    " FROM ot_data.furnace_telemetry ORDER BY timestamp DESC, id DESC LIMIT $1"
)


def _features(row: Any) -> dict[str, float]:
    return {name: float(row[name]) for name in FEATURES}


def diagnose(
    row: Any, previous: dict[str, float] | None
) -> tuple[dict[str, Any] | None, dict[str, float]]:
    """(diagnostic | None, vecteur à passer comme `previous` à la mesure suivante)."""
    features = _features(row)
    try:
        result = anomaly_detector.predict(
            {**features, "plc_status_flags": int(row["plc_status_flags"])},
            previous=previous,
        )
    except (InvalidSample, RuntimeError):
        logger.warning("diagnostic ML indisponible pour une mesure", exc_info=True)
        return None, features
    return (
        {
            "is_anomaly": result.is_anomaly,
            "severity": result.severity,
            "score": round(result.anomaly_score, 3),
            "diagnosis": result.diagnosis,
        },
        features,
    )


def to_payload(
    row: Any,
    thickness_mm: float | None,
    anomaly: dict[str, Any] | None,
) -> dict[str, Any]:
    zones = [float(row[f"temp_zone{i}_c"]) for i in range(1, 5)]
    return {
        "furnace_temp_c": round(sum(zones) / len(zones), 1),
        "zones_c": zones,
        "glass_temp_c": float(row["glass_pyrometer_temp_c"]),
        "quench_pressure_bar": float(row["quench_pressure_bar"]),
        "power_kw": float(row["power_consumption_kw"]),
        "glass_thickness_mm": thickness_mm,
        "line_speed_mps": round(float(row["conveyor_speed_m_min"]) / 60.0, 3),
        "timestamp": row["timestamp"].astimezone(timezone.utc).isoformat(),
        "anomaly": anomaly,
    }
