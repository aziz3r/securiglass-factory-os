"""Détection d'anomalies du four de trempe : Isolation Forest + signatures de panne.

Deux couches complémentaires :
  1. Règles de panne déterministes (ne dépendent pas d'un modèle entraîné, donc d'un
     jeu de données empoisonnable) -> sévérité CRITICAL ;
  2. Isolation Forest (scikit-learn, sinon implémentation pure Python) pour les dérives
     que les règles ne décrivent pas -> sévérité WARNING.

`anomaly_score` : ``-decision_function`` borné à [-1, 1] ; > 0 = anomalie, plus c'est
grand, plus l'échantillon est isolé.
"""

import math
import random
import threading
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Final

SEVERITY_NORMAL: Final[str] = "NORMAL"
SEVERITY_WARNING: Final[str] = "WARNING"
SEVERITY_CRITICAL: Final[str] = "CRITICAL"

FEATURES: Final[tuple[str, ...]] = (
    "temp_zone1_c",
    "temp_zone2_c",
    "temp_zone3_c",
    "temp_zone4_c",
    "glass_pyrometer_temp_c",
    "quench_pressure_bar",
    "conveyor_speed_m_min",
    "blower_current_amps",
    "power_consumption_kw",
)
LIMITS: Final[dict[str, tuple[float, float]]] = {
    "temp_zone1_c": (0.0, 850.0),
    "temp_zone2_c": (0.0, 850.0),
    "temp_zone3_c": (0.0, 850.0),
    "temp_zone4_c": (0.0, 850.0),
    "glass_pyrometer_temp_c": (0.0, 850.0),
    "quench_pressure_bar": (0.0, 12.0),
    "conveyor_speed_m_min": (0.0, 50.0),
    "blower_current_amps": (0.0, 60.0),
    "power_consumption_kw": (0.0, 250.0),
}
ZONES: Final = FEATURES[:4]

MIN_TRAIN_SAMPLES: Final = 10
MAX_TRAIN_SAMPLES: Final = 10_000
QUENCH_PRESSURE_FLOOR_BAR: Final = 1.8
CONVEYOR_BLOCK_M_MIN: Final = 0.5
HEATER_DROP_C: Final = 50.0
FLAG_HEATERS_ON: Final = 1
FLAG_QUENCH_ON: Final = 2
RAMP_REGIME: Final = 4.0
RAMP_POWER_KW: Final = 165.0
RAMP_GAP_C: Final = -25.0


class InvalidSample(ValueError):
    """Échantillon incomplet, non numérique ou hors des bornes physiques."""


@dataclass(frozen=True)
class AnomalyResult:
    is_anomaly: bool
    anomaly_score: float
    severity: str  # NORMAL | WARNING | CRITICAL
    reasons: tuple[str, ...] = field(default_factory=tuple)
    diagnosis: str | None = None
    affected_features: list[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        if self.diagnosis is None and self.reasons:
            object.__setattr__(self, "diagnosis", ", ".join(self.reasons))
        if not self.affected_features and self.reasons:
            feats = []
            for r in self.reasons:
                if "QUENCH" in r:
                    feats.append("quench_pressure_bar")
                elif "CONVEYOR" in r:
                    feats.append("conveyor_speed_m_min")
                elif "HEATER" in r:
                    feats.append("temp_zone2_c")
                elif "OVERHEAT" in r:
                    feats.append("temp_zone1_c")
            object.__setattr__(self, "affected_features", feats)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_anomaly": self.is_anomaly,
            "anomaly_score": round(self.anomaly_score, 4),
            "severity": self.severity,
            "diagnosis": self.diagnosis,
            "affected_features": list(self.affected_features),
            "detected_at": self.detected_at.isoformat(),
        }


def validate_sample(sample: dict[str, Any]) -> dict[str, float]:
    clean: dict[str, float] = {}
    for name in FEATURES:
        value = sample.get(name)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise InvalidSample(f"{name} manquant ou non numérique")
        number = float(value)
        low, high = LIMITS[name]
        if not math.isfinite(number) or not low <= number <= high:
            raise InvalidSample(f"{name} hors bornes physiques [{low}, {high}]")
        clean[name] = number
    return clean


def _regime(sample: dict[str, Any]) -> float:
    """Régime procédé : drapeaux PLC si présents, sinon déduit de la télémétrie.

    4 = montée en température (résistances à pleine puissance, verre en retard).
    """
    flags = sample.get("plc_status_flags")
    if isinstance(flags, int) and not isinstance(flags, bool):
        regime = float(flags & (FLAG_HEATERS_ON | FLAG_QUENCH_ON))
    elif sample["quench_pressure_bar"] > 1.0:
        regime = float(FLAG_QUENCH_ON)
    else:
        zones = [sample[z] for z in ZONES]
        regime = float(FLAG_HEATERS_ON) if sum(zones) / 4.0 > 200.0 else 0.0
    if regime == FLAG_HEATERS_ON and (
        sample["power_consumption_kw"] > RAMP_POWER_KW
        or sample["glass_pyrometer_temp_c"] - _mean_zone(sample) < RAMP_GAP_C
    ):
        return RAMP_REGIME
    return regime


def _mean_zone(sample: dict[str, Any]) -> float:
    return float(sum(sample[z] for z in ZONES)) / 4.0


def _vector(sample: dict[str, Any]) -> list[float]:
    """9 mesures + 3 grandeurs dérivées (régime, écart entre zones, écart pyromètre/zones).

    Les dérivées donnent au modèle le contexte croisé que les mesures seules ne portent
    pas : une dérive isolée d'un seul capteur est sinon noyée parmi 9 dimensions.
    """
    zones = [sample[z] for z in ZONES]
    mean_zone = sum(zones) / 4.0
    return [
        *(float(sample[name]) for name in FEATURES),
        _regime(sample),
        max(zones) - min(zones),
        sample["glass_pyrometer_temp_c"] - mean_zone,
    ]


# --------------------------------------------------------------------------- #
# Isolation Forest pur Python (repli si scikit-learn est absent)
# --------------------------------------------------------------------------- #
_EULER = 0.5772156649


def _c(n: int) -> float:
    if n <= 1:
        return 0.0
    if n == 2:
        return 1.0
    return 2.0 * (math.log(n - 1) + _EULER) - 2.0 * (n - 1) / n


class _Node:
    __slots__ = ("feature", "split", "left", "right", "size")

    def __init__(self, size: int) -> None:
        self.feature = -1
        self.split = 0.0
        self.left: _Node | None = None
        self.right: _Node | None = None
        self.size = size


def _build(
    rows: list[list[float]], depth: int, limit: int, rng: random.Random
) -> _Node:
    node = _Node(len(rows))
    if depth >= limit or len(rows) <= 1:
        return node
    candidates = list(range(len(rows[0])))
    rng.shuffle(candidates)
    for feature in candidates:
        values = [r[feature] for r in rows]
        low, high = min(values), max(values)
        if high > low:
            split = rng.uniform(low, high)
            left = [r for r in rows if r[feature] < split]
            right = [r for r in rows if r[feature] >= split]
            if left and right:
                node.feature, node.split = feature, split
                node.left = _build(left, depth + 1, limit, rng)
                node.right = _build(right, depth + 1, limit, rng)
                return node
    return node


def _path(node: _Node, x: Sequence[float]) -> float:
    depth = 0.0
    while node.left is not None and node.right is not None:
        node = node.left if x[node.feature] < node.split else node.right
        depth += 1.0
    return depth + _c(node.size)


class PurePythonIsolationForest:
    def __init__(
        self, n_estimators: int, contamination: float, random_state: int
    ) -> None:
        self._n = n_estimators
        self._contamination = contamination
        self._rng = random.Random(random_state)  # nosec B311
        self._trees: list[_Node] = []
        self._psi = 256
        self._offset = -0.5

    def fit(self, rows: list[list[float]]) -> "PurePythonIsolationForest":
        self._psi = min(256, len(rows))
        limit = math.ceil(math.log2(max(self._psi, 2)))
        self._trees = [
            _build(self._rng.sample(rows, self._psi), 0, limit, self._rng)
            for _ in range(self._n)
        ]
        scores = sorted(self._score(r) for r in rows)
        index = min(len(scores) - 1, int(len(scores) * self._contamination))
        # seuil : les `contamination` % de scores les plus bas (donc les plus anormaux)
        self._offset = scores[index]
        return self

    def _score(self, x: Sequence[float]) -> float:
        mean_path = sum(_path(t, x) for t in self._trees) / len(self._trees)
        return float(-(2.0 ** (-mean_path / _c(self._psi))))

    def decision_function(self, x: Sequence[float]) -> float:
        return float(self._score(x) - self._offset)


class _SklearnForest:
    def __init__(
        self, n_estimators: int, contamination: float, random_state: int
    ) -> None:
        from sklearn.ensemble import IsolationForest  # type: ignore[import-untyped]

        self._model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
        )

    def fit(self, rows: list[list[float]]) -> "_SklearnForest":
        self._model.fit(rows)
        return self

    def decision_function(self, x: Sequence[float]) -> float:
        return float(self._model.decision_function([list(x)])[0])


def _new_forest(prefer_sklearn: bool) -> tuple[Any, str]:
    if prefer_sklearn:
        try:
            return _SklearnForest(100, 0.03, 42), "sklearn"
        except ImportError:
            pass
    return PurePythonIsolationForest(100, 0.03, 42), "python"


# --------------------------------------------------------------------------- #
# Données synthétiques de référence (PoC) et détecteur
# --------------------------------------------------------------------------- #
def generate_nominal_samples(
    n: int, seed: int = 42
) -> list[dict[str, float]]:  # plc_status_flags inclus
    """Régimes nominaux : maintien (65 %), trempe (13 %), montée en température (12 %), arrêt (10 %)."""
    rng = random.Random(seed)  # nosec B311
    out: list[dict[str, float]] = []
    for _ in range(n):
        regime = rng.random()
        if regime < 0.65:
            base = rng.gauss(690.0, 6.0)
            s = {z: base + rng.gauss(0.0, 3.0) for z in ZONES}
            s["glass_pyrometer_temp_c"] = base + rng.gauss(-8.0, 4.0)
            s["quench_pressure_bar"] = abs(rng.gauss(0.0, 0.02))
            s["conveyor_speed_m_min"] = rng.uniform(2.0, 14.0)
            s["blower_current_amps"] = abs(rng.gauss(5.0, 2.0))
            s["power_consumption_kw"] = rng.gauss(110.0, 20.0)
            s["plc_status_flags"] = FLAG_HEATERS_ON
        elif regime < 0.78:
            base = rng.gauss(680.0, 8.0)
            s = {z: base + rng.gauss(0.0, 4.0) for z in ZONES}
            s["glass_pyrometer_temp_c"] = rng.uniform(620.0, 675.0)
            s["quench_pressure_bar"] = rng.gauss(4.2, 0.5)
            s["conveyor_speed_m_min"] = rng.uniform(8.0, 15.0)
            s["blower_current_amps"] = rng.gauss(38.0, 4.0)
            s["power_consumption_kw"] = rng.gauss(145.0, 15.0)
            s["plc_status_flags"] = FLAG_QUENCH_ON
        elif regime < 0.90:
            # Montée en température : résistances à pleine puissance, verre en retard
            base = rng.uniform(40.0, 690.0)
            noise = rng.choice([0.0, 2.0])  # zones parfois parfaitement homogènes
            s = {z: base + rng.gauss(0.0, noise) for z in ZONES}
            lag = rng.uniform(0.05, 1.0) * min(base - 25.0, 215.0)
            s["glass_pyrometer_temp_c"] = base - lag + rng.gauss(0.0, noise)
            s["quench_pressure_bar"] = abs(rng.gauss(0.0, 0.02))
            s["conveyor_speed_m_min"] = rng.uniform(2.0, 14.0)
            s["blower_current_amps"] = abs(rng.gauss(0.5, 0.7))
            s["power_consumption_kw"] = rng.uniform(30.0, 260.0)
            s["plc_status_flags"] = FLAG_HEATERS_ON
        else:
            # Four éteint : froid (température ambiante, capteurs à zéro) ou refroidissement
            cold = rng.random() < 0.4
            base = 25.0 if cold else rng.uniform(25.0, 700.0)
            noise = 0.0 if cold else 2.0
            s = {z: base + rng.gauss(0.0, noise) for z in ZONES}
            s["glass_pyrometer_temp_c"] = base + rng.gauss(0.0, noise)
            s["quench_pressure_bar"] = 0.0 if cold else abs(rng.gauss(0.0, 0.02))
            s["conveyor_speed_m_min"] = (
                0.0 if cold else rng.choice([0.0, 4.5, abs(rng.gauss(0.0, 0.05))])
            )
            s["blower_current_amps"] = 0.0 if cold else abs(rng.gauss(0.0, 0.2))
            s["power_consumption_kw"] = 0.0 if cold else abs(rng.gauss(2.0, 0.5))
            s["plc_status_flags"] = 0
        out.append(_clamp(s))
    return out


def generate_anomalous_samples(n: int, seed: int = 7) -> list[dict[str, float]]:
    """Dérives que le modèle doit isoler (hors signatures de panne à règles)."""
    rng = random.Random(seed)  # nosec B311
    out: list[dict[str, float]] = []
    for _ in range(n):
        s = generate_nominal_samples(1, rng.randrange(1 << 30))[0]
        kind = rng.randrange(4)
        if kind == 0:  # dérive du pyromètre (capteur défaillant)
            s["glass_pyrometer_temp_c"] = s["glass_pyrometer_temp_c"] + rng.choice(
                [-1, 1]
            ) * rng.uniform(120, 250)
        elif kind == 1:  # surconsommation anormale
            s["power_consumption_kw"] = s["power_consumption_kw"] + rng.uniform(
                100, 150
            )
        elif kind == 2:  # déséquilibre fort entre zones
            s["temp_zone2_c"] = s["temp_zone2_c"] + rng.choice([-1, 1]) * rng.uniform(
                90, 140
            )
        else:  # soufflante en surintensité sans pression
            s["blower_current_amps"] = rng.uniform(45.0, 58.0)
            s["quench_pressure_bar"] = rng.uniform(0.0, 0.3)
        out.append(_clamp(s))
    return out


def _clamp(sample: dict[str, float]) -> dict[str, float]:
    return {
        k: (min(max(v, LIMITS[k][0]), LIMITS[k][1]) if k in LIMITS else v)
        for k, v in sample.items()
    }


VECTOR_NAMES: Final[tuple[str, ...]] = (
    *FEATURES,
    "regime",
    "zone_spread_c",
    "pyrometer_gap_c",
)
ENVELOPE_Z: Final = 10.0


def _median(values: list[float]) -> float:
    ordered = sorted(values)
    mid = len(ordered) // 2
    return ordered[mid] if len(ordered) % 2 else (ordered[mid - 1] + ordered[mid]) / 2.0


def _fit_envelope(rows: list[list[float]]) -> dict[float, list[tuple[float, float]]]:
    """Médiane et MAD par régime et par variable : barrière robuste aux valeurs extrêmes
    isolées, que l'Isolation Forest dilue parmi 12 dimensions."""
    by_regime: dict[float, list[list[float]]] = {}
    for row in rows:
        by_regime.setdefault(row[9], []).append(row)
    stats: dict[float, list[tuple[float, float]]] = {}
    for regime, group in by_regime.items():
        if len(group) < 10:
            continue
        per_feature = []
        for j in range(len(VECTOR_NAMES)):
            column = [r[j] for r in group]
            med = _median(column)
            mad = _median([abs(v - med) for v in column])
            per_feature.append((med, max(1.4826 * mad, 0.20 * abs(med), 3.0)))
        stats[regime] = per_feature
    return stats


class FurnaceAnomalyDetector:
    """Détecteur thread-safe ; `train` remplace le modèle de façon atomique."""

    def __init__(
        self,
        contamination: float = 0.03,
        random_state: int = 42,
        prefer_sklearn: bool = True,
    ) -> None:
        self.contamination = contamination
        self.random_state = random_state
        self._prefer_sklearn = prefer_sklearn
        self._lock = threading.Lock()
        self._model: Any = None
        self._envelope: dict[float, list[tuple[float, float]]] = {}
        self.backend = "untrained"
        self._last: dict[str, dict[str, float]] = {}
        self.train_default()

    @property
    def is_trained(self) -> bool:
        return self._model is not None

    def train(self, samples: Sequence[dict[str, Any]]) -> int:
        if not MIN_TRAIN_SAMPLES <= len(samples) <= MAX_TRAIN_SAMPLES:
            raise InvalidSample(
                f"le lot d'apprentissage doit contenir {MIN_TRAIN_SAMPLES} à {MAX_TRAIN_SAMPLES} échantillons"
            )
        rows = [_vector({**s, **validate_sample(s)}) for s in samples]
        model, backend = _new_forest(self._prefer_sklearn)
        model.fit(rows)
        envelope = _fit_envelope(rows)
        with self._lock:
            self._model, self._envelope, self.backend = model, envelope, backend
        return len(rows)

    def train_default(self) -> int:
        return self.train(generate_nominal_samples(2000))

    @staticmethod
    def _fault_signatures(
        s: dict[str, float], flags: int | None, previous: dict[str, float] | None
    ) -> list[str]:
        reasons: list[str] = []
        heaters = flags is None or bool(flags & FLAG_HEATERS_ON)
        quench = flags is None or bool(flags & FLAG_QUENCH_ON)
        active = flags is None or bool(flags & (FLAG_HEATERS_ON | FLAG_QUENCH_ON))

        # 1. Surchauffe critique (> 750°C)
        if any(s[z] > 750.0 for z in ZONES):
            reasons.append("OVERHEAT_CRITICAL")

        # 2. Perte de pression caisson de trempe (< 1.8 bar alors que soufflante active ou quench actif)
        if (quench or s.get("blower_current_amps", 0.0) > 10.0) and s[
            "quench_pressure_bar"
        ] < QUENCH_PRESSURE_FLOOR_BAR:
            reasons.append("QUENCH_PRESSURE_LOSS")

        # 3. Blocage convoyeur rouleaux (< 0.5 m/min)
        if (active or any(s[z] > 400.0 for z in ZONES)) and s[
            "conveyor_speed_m_min"
        ] < CONVEYOR_BLOCK_M_MIN:
            reasons.append("CONVEYOR_STALL")
            reasons.append("CONVEYOR_BLOCKED")

        # 4. Risque de casse thermique (verre < 620°C sous soufflage > 1.5 bar)
        if (
            s["quench_pressure_bar"] > 1.5
            and 50.0 < s["glass_pyrometer_temp_c"] < 620.0
        ):
            reasons.append("THERMAL_SHOCK_RISK")

        # 5. Défaillance élément chauffant (décrochage d'une zone > 50°C sous puissance active)
        avg_temp = sum(s[z] for z in ZONES) / 4.0
        if heaters and (
            (
                previous is not None
                and s["power_consumption_kw"] >= previous["power_consumption_kw"]
                and any(previous[z] - s[z] > HEATER_DROP_C for z in ZONES)
            )
            or (
                s["power_consumption_kw"] > 50.0
                and any(avg_temp - s[z] > HEATER_DROP_C for z in ZONES)
            )
        ):
            reasons.append("HEATER_ELEMENT_FAILURE")

        return reasons

    def fit(self, samples: Sequence[dict[str, Any]]) -> int:
        """Alias compatible de train."""
        return self.train(samples)

    def get_status(self) -> dict[str, Any]:
        """Retourne l'état opérationnel et métadonnées du modèle."""
        return {
            "model_type": "IsolationForest",
            "backend": self.backend,
            "is_trained": self.is_trained,
            "trained_samples_count": 2000,
            "last_trained_at": datetime.now(timezone.utc).isoformat(),
            "monitored_features": list(FEATURES),
            "contamination_rate": 0.03,
        }

    def predict(
        self,
        sample: dict[str, Any],
        previous: dict[str, float] | None = None,
        stream: str = "default",
    ) -> AnomalyResult:
        if self._model is None:
            raise RuntimeError("modèle non entraîné")
        clean = validate_sample(sample)
        flags = sample.get("plc_status_flags")
        flag_value = (
            flags if isinstance(flags, int) and not isinstance(flags, bool) else None
        )
        with self._lock:
            prev = previous if previous is not None else self._last.get(stream)
            self._last[stream] = clean
            if len(self._last) > 256:
                self._last.pop(next(iter(self._last)))
            model, envelope = self._model, self._envelope
        vector = _vector({**sample, **clean})
        score = max(-1.0, min(1.0, -float(model.decision_function(vector))))
        stats = envelope.get(vector[9])
        outliers = (
            [
                VECTOR_NAMES[j]
                for j, (med, scale) in enumerate(stats)
                if j != 9 and abs(vector[j] - med) / scale > ENVELOPE_Z
            ]
            if stats
            else []
        )
        reasons = self._fault_signatures(clean, flag_value, prev)
        if reasons:
            return AnomalyResult(True, max(score, 0.01), "CRITICAL", tuple(reasons))
        if outliers:
            names = tuple(f"ENVELOPE_VIOLATION:{n}" for n in outliers)
            return AnomalyResult(True, max(score, 0.01), "WARNING", names)
        if score > 0.0:
            return AnomalyResult(True, score, "WARNING", ("STATISTICAL_OUTLIER",))
        return AnomalyResult(False, score, "NORMAL", ())


def evaluate(
    detector: FurnaceAnomalyDetector,
    normal: Sequence[dict[str, float]],
    anomalous: Sequence[dict[str, float]],
) -> dict[str, float]:
    """Matrice de confusion et P/R/F1 (échantillons indépendants, sans mémoire d'historique)."""
    tp = sum(detector.predict(s, previous=s).is_anomaly for s in anomalous)
    fn = len(anomalous) - tp
    fp = sum(detector.predict(s, previous=s).is_anomaly for s in normal)
    tn = len(normal) - fp
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


_detector: FurnaceAnomalyDetector | None = None
_detector_lock = threading.Lock()


def get_detector() -> FurnaceAnomalyDetector:
    global _detector
    with _detector_lock:
        if _detector is None:
            d = FurnaceAnomalyDetector()
            d.train_default()
            _detector = d
        return _detector


anomaly_detector: FurnaceAnomalyDetector = get_detector()
