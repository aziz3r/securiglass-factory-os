"""Tests unitaires pour le limiteur de débit Token Bucket (app/core/rate_limiter.py)."""

from __future__ import annotations

import time
import pytest
from starlette.requests import Request
from starlette.responses import Response
from fastapi import HTTPException

from app.core.rate_limiter import (
    InMemoryRateLimiterStorage,
    RateLimiter,
    TokenBucket,
    get_client_ip,
    reset_rate_limiters,
)


def test_token_bucket_initial_state_and_acquisition() -> None:
    """Valide l'état initial et la consommation unitaire des jetons."""
    bucket = TokenBucket(capacity=5, window_seconds=10.0)
    assert bucket.capacity == 5.0
    assert bucket.tokens == 5.0

    # Consommation de 3 jetons
    for expected_remaining in [4, 3, 2]:
        allowed, retry_after, remaining = bucket.acquire(1.0)
        assert allowed is True
        assert retry_after == 0.0
        assert remaining == expected_remaining


def test_token_bucket_exhaustion_and_retry_after() -> None:
    """Valide le refus d'acquisition et le calcul du temps de recharge (Retry-After)."""
    bucket = TokenBucket(capacity=2, window_seconds=2.0)
    # Taux de recharge = 1 jeton / seconde

    ok1, _, _ = bucket.acquire(1.0)
    ok2, _, _ = bucket.acquire(1.0)
    assert ok1 is True and ok2 is True

    # Troisième requête : refus immédiat
    allowed, retry_after, remaining = bucket.acquire(1.0)
    assert allowed is False
    assert remaining == 0
    assert retry_after >= 1.0  # Au moins 1 seconde requise pour recharger 1 jeton


def test_token_bucket_continuous_refill() -> None:
    """Valide la recharge continue proportionnelle au temps écoulé."""
    bucket = TokenBucket(capacity=2, window_seconds=0.2)
    # Recharge = 10 jetons / seconde
    bucket.acquire(2.0)
    assert int(bucket.tokens) == 0

    # Attente de 100ms (recharge d'1 jeton)
    time.sleep(0.12)
    allowed, _, remaining = bucket.acquire(1.0)
    assert allowed is True
    assert remaining == 0


def test_token_bucket_reset() -> None:
    """Valide la remise à niveau manuelle du seau."""
    bucket = TokenBucket(capacity=10, window_seconds=60.0)
    bucket.acquire(8.0)
    assert int(bucket.tokens) == 2
    bucket.reset()
    assert int(bucket.tokens) == 10


@pytest.mark.asyncio
async def test_rate_limiter_dependency_enforcement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vérifie la levée de HTTP 429 et la présence des en-têtes RFC 6585."""
    monkeypatch.setenv("RATE_LIMIT_ENFORCE", "1")
    reset_rate_limiters()
    limiter = RateLimiter(requests=2, window_seconds=60, prefix="test_dep")

    scope = {
        "type": "http",
        "client": ("192.168.1.50", 12345),
        "headers": [],
    }
    request = Request(scope)
    response = Response()

    # Requêtes 1 et 2 autorisées
    await limiter(request, response)
    assert response.headers["X-RateLimit-Limit"] == "2"
    assert response.headers["X-RateLimit-Remaining"] == "1"

    await limiter(request, response)
    assert response.headers["X-RateLimit-Remaining"] == "0"

    # Requête 3 : doit lever HTTP 429
    with pytest.raises(HTTPException) as exc_info:
        await limiter(request, response)

    assert exc_info.value.status_code == 429
    assert "Retry-After" in exc_info.value.headers
    assert exc_info.value.headers["X-RateLimit-Remaining"] == "0"
