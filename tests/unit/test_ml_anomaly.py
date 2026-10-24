"""Tests unitaires pour le moteur ML de détection d'anomalies four (app/services/ml_anomaly.py)."""

from __future__ import annotations

import pytest

from app.services.ml_anomaly import (
    SEVERITY_CRITICAL,
    SEVERITY_NORMAL,
    AnomalyResult,
    FurnaceAnomalyDetector,
    anomaly_detector,
)


@pytest.fixture
def detector() -> FurnaceAnomalyDetector:
    return FurnaceAnomalyDetector(contamination=0.03, random_state=42)


def test_nominal_sample_prediction(detector: FurnaceAnomalyDetector) -> None:
    """Valide qu'un échantillon nominal standard est classifié comme normal."""
    nominal_sample = {
        "temp_zone1_c": 685.0,
        "temp_zone2_c": 690.0,
        "temp_zone3_c": 692.0,
        "temp_zone4_c": 688.0,
        "glass_pyrometer_temp_c": 660.0,
        "quench_pressure_bar": 4.5,
        "conveyor_speed_m_min": 12.0,
        "blower_current_amps": 40.0,
        "power_consumption_kw": 150.0,
    }
    result = detector.predict(nominal_sample)
    assert isinstance(result, AnomalyResult)
    assert result.is_anomaly is False
    assert result.severity == SEVERITY_NORMAL
    assert result.diagnosis is None


def test_rule_overheat_critical(detector: FurnaceAnomalyDetector) -> None:
    """Règle 1 : Surchauffe critique (> 750°C)."""
    overheat_sample = {
        "temp_zone1_c": 765.0,  # > 750°C
        "temp_zone2_c": 690.0,
        "temp_zone3_c": 690.0,
        "temp_zone4_c": 690.0,
        "glass_pyrometer_temp_c": 670.0,
        "quench_pressure_bar": 4.0,
        "conveyor_speed_m_min": 12.0,
        "blower_current_amps": 40.0,
        "power_consumption_kw": 180.0,
    }
    result = detector.predict(overheat_sample)
    assert result.is_anomaly is True
    assert result.severity == SEVERITY_CRITICAL
    assert "OVERHEAT_CRITICAL" in (result.diagnosis or "")
    assert "temp_zone1_c" in result.affected_features


def test_rule_heater_element_failure(detector: FurnaceAnomalyDetector) -> None:
    """Règle 2 : Défaillance élément chauffant (Zone 2 chute de > 50°C sous forte puissance)."""
    failure_sample = {
        "temp_zone1_c": 690.0,
        "temp_zone2_c": 580.0,  # Chute de plus de 100°C
        "temp_zone3_c": 695.0,
        "temp_zone4_c": 690.0,
        "glass_pyrometer_temp_c": 640.0,
        "quench_pressure_bar": 4.0,
        "conveyor_speed_m_min": 12.0,
        "blower_current_amps": 35.0,
        "power_consumption_kw": 170.0,  # Puissance élevée
    }
    result = detector.predict(failure_sample)
    assert result.is_anomaly is True
    assert result.severity == SEVERITY_CRITICAL
    assert "HEATER_ELEMENT_FAILURE" in (result.diagnosis or "")
    assert "temp_zone2_c" in result.affected_features


def test_rule_quench_pressure_loss(detector: FurnaceAnomalyDetector) -> None:
    """Règle 3 : Perte de pression caisson de trempe (< 1.8 bar alors que soufflante active)."""
    quench_loss_sample = {
        "temp_zone1_c": 690.0,
        "temp_zone2_c": 695.0,
        "temp_zone3_c": 695.0,
        "temp_zone4_c": 690.0,
        "glass_pyrometer_temp_c": 650.0,
        "quench_pressure_bar": 1.1,  # < 1.8 bar
        "conveyor_speed_m_min": 12.0,
        "blower_current_amps": 45.0,  # Soufflante tourne à plein régime
        "power_consumption_kw": 160.0,
    }
    result = detector.predict(quench_loss_sample)
    assert result.is_anomaly is True
    assert result.severity == SEVERITY_CRITICAL
    assert "QUENCH_PRESSURE_LOSS" in (result.diagnosis or "")


def test_rule_conveyor_stall(detector: FurnaceAnomalyDetector) -> None:
    """Règle 4 : Blocage convoyeur (< 0.5 m/min en four chaud)."""
    stall_sample = {
        "temp_zone1_c": 680.0,
        "temp_zone2_c": 690.0,
        "temp_zone3_c": 690.0,
        "temp_zone4_c": 685.0,
        "glass_pyrometer_temp_c": 650.0,
        "quench_pressure_bar": 0.0,
        "conveyor_speed_m_min": 0.1,  # Vitesse quasi nulle
        "blower_current_amps": 0.0,
        "power_consumption_kw": 130.0,
    }
    result = detector.predict(stall_sample)
    assert result.is_anomaly is True
    assert result.severity == SEVERITY_CRITICAL
    assert "CONVEYOR_STALL" in (result.diagnosis or "")


def test_rule_thermal_shock_risk(detector: FurnaceAnomalyDetector) -> None:
    """Règle 5 : Risque de casse thermique (verre < 620°C sous soufflage trempe)."""
    thermal_shock_sample = {
        "temp_zone1_c": 650.0,
        "temp_zone2_c": 660.0,
        "temp_zone3_c": 660.0,
        "temp_zone4_c": 650.0,
        "glass_pyrometer_temp_c": 595.0,  # Verre trop froid (< 620°C)
        "quench_pressure_bar": 4.5,  # Soufflage actif
        "conveyor_speed_m_min": 15.0,
        "blower_current_amps": 45.0,
        "power_consumption_kw": 150.0,
    }
    result = detector.predict(thermal_shock_sample)
    assert result.is_anomaly is True
    assert result.severity == SEVERITY_CRITICAL
    assert "THERMAL_SHOCK_RISK" in (result.diagnosis or "")


def test_model_status_and_metadata(detector: FurnaceAnomalyDetector) -> None:
    """Valide les informations retournées par get_status."""
    status = detector.get_status()
    assert status["is_trained"] is True
    assert status["trained_samples_count"] >= 100
    assert "monitored_features" in status
    assert len(status["monitored_features"]) == 9
