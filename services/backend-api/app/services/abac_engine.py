"""Moteur de décision de contrôle d'accès basé sur les attributs (ABAC - PDP/PEP).

Conforme aux spécifications IEC 62443 et NIST SP 800-162 :
- Principe du Default-Deny absolu.
- Algorithme de résolution Deny-Overrides (un DENY explicite l'emporte sur tout ALLOW).
- Évaluation en Python pur des expressions JSONB (`in_cidr`, `time_between`, `equals`, `greater_or_equal`, `clearance_level`).
- Fail-closed : Toute anomalie d'évaluation (attribut manquant, erreur de typage) neutralise la règle.
"""

import fnmatch
import ipaddress
import logging
from dataclasses import dataclass
from datetime import datetime, time, timezone
from typing import Any

logger = logging.getLogger("securiglass.abac")

Context = dict[str, Any]
_REF_PREFIXES = ("subject.", "resource.", "environment.", "client_cert.")


@dataclass(frozen=True)
class Policy:
    name: str
    effect: str  # 'ALLOW' ou 'DENY'
    subject_role: str  # Code rôle spécifique ou '*'
    action_verb: str  # Ex: 'ot:control:write', 'it:recipe:approve'
    resource_urn: str  # Motif fnmatch (ex: 'urn:securiglass:ot:furnace:*')
    condition: dict[str, Any]
    description: str | None = None
    is_active: bool = True


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    policy: str | None = None


def _lookup_path(ctx: Context, path: str) -> Any:
    """Résout un chemin pointé dans le dictionnaire de contexte.

    Supporte également les clés directes à la racine (ex: 'client_ip').
    """
    if path in ctx:
        return ctx[path]

    # Alias fréquents
    if path == "client_ip":
        if "environment" in ctx and "client_ip" in ctx["environment"]:
            return ctx["environment"]["client_ip"]
        if "subject" in ctx and "client_ip" in ctx["subject"]:
            return ctx["subject"]["client_ip"]

    cur: Any = ctx
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise KeyError(f"Attribut ABAC introuvable dans le contexte : '{path}'")
        cur = cur[part]
    return cur


def _resolve_value(ctx: Context, val: Any) -> Any:
    """Résout les références dynamiques d'attributs ou les listes nommées."""
    if isinstance(val, str):
        if val.startswith(_REF_PREFIXES):
            return _lookup_path(ctx, val)
        lists = ctx.get("lists", {})
        if isinstance(lists, dict) and val in lists:
            return lists[val]
    return val


def _parse_time(val: Any) -> time:
    """Parse une chaîne ou objet time."""
    if isinstance(val, time):
        return val
    if isinstance(val, str):
        return time.fromisoformat(val)
    raise ValueError(f"Format d'heure invalide : {val}")


def _evaluate_node(node: Any, ctx: Context) -> bool:
    """Évalue récursivement un nœud de l'arbre conditionnel JSONB."""
    if not isinstance(node, dict) or len(node) != 1:
        raise ValueError(f"Nœud de condition ABAC malformé : {node}")

    ((op, operand),) = node.items()

    # 1. Opérateurs logiques booléens
    if op == "and":
        if not isinstance(operand, list):
            raise ValueError("L'opérateur 'and' requiert une liste de conditions")
        return bool(operand) and all(_evaluate_node(child, ctx) for child in operand)

    if op == "or":
        if not isinstance(operand, list):
            raise ValueError("L'opérateur 'or' requiert une liste de conditions")
        return any(_evaluate_node(child, ctx) for child in operand)

    if op == "not":
        return not _evaluate_node(operand, ctx)

    # 2. Prédicats d'évaluation
    if not isinstance(operand, dict):
        raise ValueError(f"L'opérande de '{op}' doit être un dictionnaire")

    # Plage horaire contextuelle (ex: quart d'équipe 05:45 - 22:15)
    if op == "time_between":
        start = _parse_time(operand["start"])
        end = _parse_time(operand["end"])
        # Fail-closed (D6) : sans `environment.time`, KeyError -> condition fausse.
        current_time = _lookup_path(ctx, "environment.time")
        if not isinstance(current_time, time):
            current_time = _parse_time(current_time)

        if start <= end:
            return bool(start <= current_time <= end)
        # Cas de dépassement de minuit (ex: 22:00 -> 06:00)
        return bool(current_time >= start or current_time <= end)

    # Opérateur direct de clearance level
    if op == "clearance_level":
        min_clearance = operand.get("min", operand.get("greater_or_equal", 1))
        user_clearance = _lookup_path(ctx, "subject.clearance_level")
        return int(user_clearance) >= int(min_clearance)

    if len(operand) != 1:
        raise ValueError(
            f"L'opérande de '{op}' doit contenir exactement une paire clé/valeur"
        )

    ((key, expected_raw),) = operand.items()
    actual_value = _lookup_path(ctx, key)
    expected_value = _resolve_value(ctx, expected_raw)

    # Filtrage CIDR réseau (IEC 62443 zone de confiance)
    if op == "in_cidr":
        ip_obj = ipaddress.ip_address(actual_value)
        network_obj = ipaddress.ip_network(expected_value, strict=False)
        return ip_obj in network_obj

    if op == "equals":
        return bool(actual_value == expected_value)

    if op == "not_equals":
        return bool(actual_value != expected_value)

    if op == "greater_or_equal":
        return bool(actual_value >= expected_value)

    if op == "less_or_equal":
        return bool(actual_value <= expected_value)

    if op == "in":
        return bool(actual_value in expected_value)

    if op == "not_in":
        return bool(actual_value not in expected_value)

    raise ValueError(f"Opérateur ABAC non reconnu : '{op}'")


def evaluate_condition(condition: dict[str, Any], ctx: Context) -> bool:
    """Évalue une condition JSONB dans le contexte donné.

    Applique le principe du Fail-Closed : renvoie False en cas d'erreur.
    """
    try:
        return _evaluate_node(condition, ctx)
    except Exception as exc:
        logger.debug("Échec de l'évaluation de condition ABAC (fail-closed) : %s", exc)
        return False


def decide(
    policies: list[Policy],
    roles: list[str],
    action: str,
    resource_urn: str,
    ctx: Context,
) -> Decision:
    """Moteur PDP principal appliquant le principe Deny-Overrides et Default-Deny.

    1. Filtre les politiques applicables au sujet, à l'action et à la ressource.
    2. Si une politique DENY applicable a sa condition vérifiée -> Refus immédiat.
    3. Si une politique ALLOW applicable a sa condition vérifiée -> Autorisé (sauf si DENY ultérieur).
    4. Si aucune politique ALLOW n'a été validée -> Default Deny.
    """
    allow_policy: Policy | None = None

    for p in policies:
        if not p.is_active:
            continue

        # Correspondance de rôle (* ou appartenance au jeu de rôles)
        if p.subject_role != "*" and p.subject_role not in roles:
            continue

        # Correspondance de verbe d'action
        if p.action_verb != "*" and p.action_verb != action:
            continue

        # Correspondance URN de ressource (avec jokers fnmatch)
        if not fnmatch.fnmatchcase(resource_urn, p.resource_urn):
            continue

        # Évaluation de la condition contextuelle
        if not evaluate_condition(p.condition, ctx):
            continue

        # Deny-Overrides : le refus explicite est prioritaire
        if p.effect == "DENY":
            logger.info("ABAC: Accès refusé par politique explicite DENY '%s'", p.name)
            return Decision(
                allowed=False,
                reason=f"Refus explicite par la politique ABAC '{p.name}'",
                policy=p.name,
            )

        if p.effect == "ALLOW" and allow_policy is None:
            allow_policy = p

    if allow_policy is not None:
        logger.info(
            "ABAC: Accès accordé par la politique ALLOW '%s'", allow_policy.name
        )
        return Decision(
            allowed=True,
            reason=f"Autorisé par la politique ABAC '{allow_policy.name}'",
            policy=allow_policy.name,
        )

    logger.warning(
        "ABAC: Accès refusé par Default-Deny pour rôle=%s action=%s urn=%s",
        roles,
        action,
        resource_urn,
    )
    return Decision(
        allowed=False,
        reason="Accès refusé par le principe Default-Deny (aucune règle ALLOW correspondante)",
    )
