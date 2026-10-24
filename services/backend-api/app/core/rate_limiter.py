"""Limiteur de débit Token Bucket (stockage mémoire thread-safe, remplaçable par Redis).

Règles (STEP3 spec) : login 5/min/IP, RAG 10/min/utilisateur, API générale 60/min/IP.
Dépassement : HTTP 429 + Retry-After, X-RateLimit-Limit, X-RateLimit-Remaining.

L'IP est celle de la socket (X-Forwarded-For ignoré : falsifiable). Derrière un reverse
proxy de confiance, il faut une configuration explicite du proxy, pas un en-tête libre.
"""

import math
import os
import threading
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Protocol

from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse

from app.core.config import get_settings

MAX_BUCKETS = 100_000


@dataclass(frozen=True)
class Rule:
    name: str
    capacity: int  # jetons max = rafale autorisée
    window_s: float  # temps pour recharger `capacity` jetons

    @property
    def refill_per_s(self) -> float:
        return self.capacity / self.window_s


LOGIN_RULE = Rule("login", 5, 60.0)
RAG_RULE = Rule("rag", 10, 60.0)
GENERAL_RULE = Rule("general", 60, 60.0)


@dataclass(frozen=True)
class Decision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_s: int

    def headers(self) -> dict[str, str]:
        h = {
            "X-RateLimit-Limit": str(self.limit),
            "X-RateLimit-Remaining": str(self.remaining),
        }
        if not self.allowed:
            h["Retry-After"] = str(self.retry_after_s)
        return h


class RateLimitStore(Protocol):
    def consume(self, rule: Rule, key: str) -> Decision: ...


class InMemoryTokenBucketStore:
    """Un seau par (règle, clé) ; verrou unique, éviction des seaux pleins et inactifs."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: dict[tuple[str, str], tuple[float, float]] = {}

    def consume(self, rule: Rule, key: str) -> Decision:
        now = self._clock()
        with self._lock:
            tokens, last = self._buckets.get(
                (rule.name, key), (float(rule.capacity), now)
            )
            tokens = min(
                float(rule.capacity), tokens + max(0.0, now - last) * rule.refill_per_s
            )
            allowed = tokens >= 1.0
            if allowed:
                tokens -= 1.0
            self._buckets[(rule.name, key)] = (tokens, now)
            if len(self._buckets) > MAX_BUCKETS:
                self._evict(now)
            retry = (
                0 if allowed else max(1, math.ceil((1.0 - tokens) / rule.refill_per_s))
            )
            return Decision(allowed, rule.capacity, int(tokens), retry)

    def _evict(self, now: float) -> None:
        # Un seau inactif depuis plus que sa fenêtre est forcément plein : sans perte d'état.
        stale = [k for k, (_t, last) in self._buckets.items() if now - last > 3600.0]
        for k in stale:
            del self._buckets[k]
        if (
            len(self._buckets) > MAX_BUCKETS
        ):  # sous attaque : refuse d'allouer davantage
            self._buckets.clear()


_store: RateLimitStore = InMemoryTokenBucketStore()


def set_store(store: RateLimitStore) -> None:
    """Remplace le stockage (ex. Redis partagé entre répliques) ; utile aux tests."""
    global _store
    _store = store


def get_store() -> RateLimitStore:
    return _store


def enforcement_enabled() -> bool:
    if os.environ.get("RATE_LIMIT_ENFORCE") == "1":
        return True
    return get_settings().environment != "test"


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _too_many(decision: Decision) -> HTTPException:
    return HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        "Too Many Requests",
        headers=decision.headers(),
    )


def limit_by_ip(rule: Rule) -> Callable[[Request], None]:
    """Dépendance FastAPI : une requête consomme un jeton du seau de l'IP appelante."""

    def dependency(request: Request) -> None:
        if not enforcement_enabled():
            return
        decision = get_store().consume(rule, _client_ip(request))
        if not decision.allowed:
            raise _too_many(decision)

    return dependency


def limit_by_user(
    rule: Rule, user_dependency: Callable[..., object]
) -> Callable[..., None]:
    """Dépendance FastAPI par utilisateur authentifié (identifiant stable, pas l'IP)."""

    def dependency(request: Request, user: object = Depends(user_dependency)) -> None:
        if not enforcement_enabled():
            return
        user_id = getattr(user, "id", None)
        if user_id is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unauthorized")
        decision = get_store().consume(rule, str(user_id))
        if not decision.allowed:
            raise _too_many(decision)

    return dependency


EXEMPT_PATHS = frozenset({"/health"})


async def general_rate_limit_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    """Plafond global par IP, avec en-têtes X-RateLimit-* sur chaque réponse."""
    if not enforcement_enabled() or request.url.path in EXEMPT_PATHS:
        return await call_next(request)
    decision = get_store().consume(GENERAL_RULE, _client_ip(request))
    if not decision.allowed:
        return JSONResponse(
            {"detail": "Too Many Requests"},
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            headers=decision.headers(),
        )
    response = await call_next(request)
    for name, value in decision.headers().items():
        response.headers[name] = value
    return response


# ============================================================================
# COMPATIBILITÉ & INTERFACES AVANCÉES
# ============================================================================


class TokenBucket:
    """Seau à jetons individuel (pour tests et granularités personnalisées)."""

    __slots__ = ("capacity", "refill_rate", "tokens", "last_update", "_lock")

    def __init__(self, capacity: int, window_seconds: float) -> None:
        if capacity <= 0 or window_seconds <= 0:
            raise ValueError("capacity et window_seconds doivent être positifs")
        self.capacity: float = float(capacity)
        self.refill_rate: float = float(capacity) / float(window_seconds)
        self.tokens: float = float(capacity)
        self.last_update: float = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, tokens_needed: float = 1.0) -> tuple[bool, float, int]:
        with self._lock:
            now = time.monotonic()
            dt = now - self.last_update
            self.last_update = now
            self.tokens = min(self.capacity, self.tokens + dt * self.refill_rate)
            if self.tokens >= tokens_needed:
                self.tokens -= tokens_needed
                return True, 0.0, int(self.tokens)
            deficit = tokens_needed - self.tokens
            retry_after = deficit / self.refill_rate if self.refill_rate > 0 else 60.0
            return False, math.ceil(retry_after), int(self.tokens)

    def reset(self) -> None:
        with self._lock:
            self.tokens = self.capacity
            self.last_update = time.monotonic()


InMemoryRateLimiterStorage = InMemoryTokenBucketStore
get_client_ip = _client_ip


def reset_rate_limiters() -> None:
    """Réinitialise tous les seaux en mémoire (pour les tests)."""
    set_store(InMemoryTokenBucketStore())


class RateLimiter:
    """Dépendance FastAPI appliquant une limitation Token Bucket."""

    def __init__(
        self,
        requests: int = 60,
        window_seconds: int = 60,
        key_func: Callable[[Request], str] = _client_ip,
        prefix: str = "custom",
    ) -> None:
        self.rule = Rule(prefix, requests, float(window_seconds))
        self.key_func = key_func

    async def __call__(
        self, request: Request, response: Response | None = None
    ) -> None:
        if not enforcement_enabled():
            return
        key = self.key_func(request)
        decision = get_store().consume(self.rule, key)
        if response is not None:
            for k, v in decision.headers().items():
                response.headers[k] = v
        if not decision.allowed:
            raise _too_many(decision)


# Dépendances prêtes à l'emploi
global_rate_limiter = limit_by_ip(GENERAL_RULE)
auth_rate_limiter = limit_by_ip(LOGIN_RULE)
rag_rate_limiter = limit_by_ip(RAG_RULE)
