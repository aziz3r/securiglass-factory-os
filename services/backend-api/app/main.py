"""Point d'entrée principal de SecuriGlass Factory OS - Service IAM & Fondations Data.

Conformité :
- OWASP ASVS v4.0 (Niveau 2+)
- IEC 62443-3-3 (Sécurité industrielle & intégrité)
- En-têtes HTTP de sécurité stricts (HSTS, CSP, Anti-Sniff, Anti-Clickjacking)
"""

import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api import audit, auth, customers, factory, ml, rag, ws
from app.core import db
from app.core.config import get_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("securiglass.main")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Cycle de vie de l'application : initialisation et libération du pool DB."""
    logger.info("Démarrage du service IAM SecuriGlass Factory OS...")
    await db.init_pool()
    try:
        yield
    finally:
        logger.info("Arrêt du service IAM SecuriGlass Factory OS...")
        await db.close_pool()


app = FastAPI(
    title="SecuriGlass Factory OS - Service IAM",
    description="Socle de sécurité cryptographique, IAM et gestion industrielle (IEC 62443 & RGPD)",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if get_settings().environment != "production" else None,
    redoc_url=None,
)


# ============================================================================
# MIDDLEWARES DE SÉCURITÉ INDUSTRIELLE
# ============================================================================


@app.middleware("http")
async def security_headers_middleware(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    """Injecte des en-têtes HTTP de sécurité stricts (OWASP ASVS / IEC 62443)."""
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains; preload"
    )
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-XSS-Protection"] = "0"
    return response


# ============================================================================
# GESTIONNAIRES D'EXCEPTIONS CENTRALISÉS (ANTI-LEAK)
# ============================================================================


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Intercepte les erreurs de validation Pydantic en masquant les détails sensibles."""
    errors = []
    for err in exc.errors():
        field_loc = " -> ".join(str(loc) for loc in err.get("loc", []))
        errors.append(
            {
                "field": field_loc,
                "message": err.get("msg", "Invalid value"),
                "type": err.get("type", "value_error"),
            }
        )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "detail": "Échec de validation des données d'entrée",
            "errors": errors,
        },
    )


# ============================================================================
# ROUTEURS & ENDPOINTS SYSTÈME
# ============================================================================


@app.get("/health", tags=["system"], summary="Contrôle de santé du service IAM")
async def healthcheck() -> dict[str, str]:
    """Endpoint de liveness / readiness pour orchestrateurs et sondes Purdue L3."""
    return {
        "status": "UP",
        "service": "securiglass-backend-api",
        "version": "1.0.0",
        "environment": get_settings().environment,
    }


# Inclusion des sous-routeurs d'API
app.include_router(auth.router)
app.include_router(customers.router)
app.include_router(audit.router)
app.include_router(ml.router)
app.include_router(rag.router)
app.include_router(factory.router)
app.include_router(ws.router)
