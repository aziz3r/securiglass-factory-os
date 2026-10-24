"""Normalisation et enrichissement du flux d'audit SecuriGlass pour le SOC.

Le backend ecrit `sec_data.audit_logs` (une ligne par evenement). Wazuh attend
un flux JSON Lines normalise. Ce module fournit la transformation pure Python,
sans dependance externe, utilisee par l'exportateur PostgreSQL :

  * ajoute `source = securiglass.audit` et `srcip` (alias de `actor_ip`) ;
  * calcule `details.prior_failures` (echecs avant un succes, fenetre 15 min) ;
  * calcule `details.denied_count` (refus RBAC du meme acteur, fenetre 10 min) ;
  * conserve les hashes `prev_log_hash` / `current_hash` pour l'audit ;
  * ne modifie jamais l'enregistrement source.

Le champ `details.attempt_count` est deja produit par le backend ; il est
conserve s'il existe, sinon il est deduit du compteur normalise.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping

FAILURE_WINDOW = timedelta(minutes=15)
DENY_WINDOW = timedelta(minutes=10)

_OUTPUT_FIELDS = (
    "event_time",
    "event_type",
    "actor_username",
    "actor_ip",
    "action",
    "resource",
    "outcome",
    "prev_log_hash",
    "current_hash",
)


def parse_timestamp(value: Any) -> datetime:
    """Accepte datetime, chaine ISO-8601 ou epoch ; retourne un datetime UTC."""
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
    elif isinstance(value, str) and value.strip():
        text = value.strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(text)
    else:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass
class AuditNormalizer:
    """Etat glissant par acteur pour enrichir les evenements d'audit."""

    failure_window: timedelta = FAILURE_WINDOW
    deny_window: timedelta = DENY_WINDOW
    _failures: dict[str, list[datetime]] = field(default_factory=dict, repr=False)
    _denials: dict[str, list[datetime]] = field(default_factory=dict, repr=False)

    @staticmethod
    def _prune(entries: list[datetime], now: datetime, window: timedelta) -> list[datetime]:
        cutoff = now - window
        return [entry for entry in entries if entry > cutoff]

    def _record_failure(self, actor: str, now: datetime) -> int:
        entries = self._prune(self._failures.get(actor, []), now, self.failure_window)
        prior = len(entries)
        entries.append(now)
        self._failures[actor] = entries
        return prior

    def _record_denial(self, actor: str, now: datetime) -> int:
        entries = self._prune(self._denials.get(actor, []), now, self.deny_window)
        entries.append(now)
        self._denials[actor] = entries
        return len(entries)

    def normalize(self, row: Mapping[str, Any]) -> dict[str, Any]:
        """Transforme une ligne d'audit en evenement JSON serialisable."""
        event = {key: row[key] for key in _OUTPUT_FIELDS if key in row}
        now = parse_timestamp(event.get("event_time"))
        event["event_time"] = now.isoformat()
        event["source"] = "securiglass.audit"

        actor = str(row.get("actor_username", ""))
        actor_ip = str(row.get("actor_ip", ""))
        if actor_ip:
            # Wazuh utilise srcip pour les correlations same_srcip / srcip.
            event["srcip"] = actor_ip

        details: dict[str, Any] = dict(row.get("details") or {})
        event_type = str(row.get("event_type", ""))
        outcome = str(row.get("outcome", ""))

        if event_type == "AUTH_LOGIN":
            if outcome == "FAILURE":
                prior = self._record_failure(actor, now)
                details["prior_failures"] = prior
                details.setdefault("attempt_count", prior + 1)
            elif outcome == "SUCCESS":
                entries = self._prune(self._failures.get(actor, []), now, self.failure_window)
                details["prior_failures"] = len(entries)
                self._failures[actor] = []
        elif event_type == "ACCESS_DENIED_RBAC":
            details["denied_count"] = self._record_denial(actor, now)

        event["details"] = details
        return event


def to_jsonl(event: Mapping[str, Any]) -> str:
    """Serialise un evenement normalise en une ligne JSON (UTF-8, sans ASCII force)."""
    return json.dumps(event, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def normalize_batch(rows: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Normalise une sequence de lignes d'audit dans l'ordre chronologique."""
    normalizer = AuditNormalizer()
    return [normalizer.normalize(row) for row in rows]
