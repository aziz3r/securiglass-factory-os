# =============================================================================
# SecuriGlass Factory OS - Backend API (FastAPI / uvicorn)
# =============================================================================
# Durcissement :
#   - build multi-etapes : aucun compilateur, en-tete ni cache pip dans l'image
#     finale ;
#   - image finale DISTROLESS (aucun shell, aucun gestionnaire de paquets) ;
#   - execution non-root : USER 65532:65532 (utilisateur "nonroot" distroless) ;
#   - PYTHONDONTWRITEBYTECODE=1 : compatible racine en lecture seule (read-only) ;
#   - dependances installees dans un venv puis copiees telles quelles ;
#   - healthcheck sans shell, via l'interpreteur Python (exec form).
#
# Construction (contexte = racine du depot) :
#   docker build -f security/docker/backend.Dockerfile -t securiglass/backend-api:1.0.0 .
#
# Note Python 3.12 : gcr.io/distroless/python3-debian12 embarque Python 3.11
# (version de Debian 12). Pour conserver le runtime Python 3.12 du projet, le
# runtime 3.12 est copie depuis l'etage builder (meme base Debian bookworm) ;
# il est place dans /usr/local, sans collision avec le Python 3.11 distroless
# (/usr/bin/python3.11, /usr/lib/python3.11).
# =============================================================================

ARG PYTHON_VERSION=3.12
ARG DISTROLESS_IMAGE=gcr.io/distroless/python3-debian12:nonroot

# -----------------------------------------------------------------------------
# Etage 1 - Builder : venv isole + code applicatif
# -----------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}"

WORKDIR /build

# Le venv est cree avant l'installation : les dependances sont isolees du Python
# systeme et l'arborescence /opt/venv est copiee en bloc dans l'image finale.
RUN python -m venv "${VIRTUAL_ENV}"

# Les dependances sont copiees seules pour maximiser le cache de couche Docker.
COPY services/backend-api/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Dependance runtime absente de requirements.txt (defaut remonte dans
# security/REPORT.md) : app/core/db.py importe asyncpg au chargement.
# Elle est epinglee ici pour que l'image reste constructible et fonctionnelle.
RUN pip install --no-cache-dir "asyncpg==0.30.0"

# Code applicatif uniquement (pas de tests, pas de .env, pas de .venv local).
COPY services/backend-api/app ./app

# Verification d'import au build : echoue tot si une dependance manque ou si
# l'application n'est pas importable. Aucune connexion reseau/DB n'est ouverte
# (init_pool n'est appele qu'au lifespan uvicorn).
RUN ENVIRONMENT=test \
    SECRET_KEY="build-time-only-secret-key-0123456789abcdef" \
    TDE_ENCRYPTION_KEY="0000000000000000000000000000000000000000000000000000000000000000" \
    python -c "import app.main; print('backend import OK')"

# -----------------------------------------------------------------------------
# Etage 2 - Runtime distroless, non-root, sans shell
# -----------------------------------------------------------------------------
FROM ${DISTROLESS_IMAGE}

ARG PYTHON_VERSION=3.12

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    LD_LIBRARY_PATH="/usr/local/lib" \
    APP_PORT=8000

# Runtime Python 3.12 (binaire + bibliotheque partagee + bibliotheque standard).
# python3 et python sont copies car le venv cree par "python -m venv" pointe vers
# /usr/local/bin/python (symlink), pas directement vers python3.12.
COPY --from=builder --chown=65532:65532 /usr/local/bin/python${PYTHON_VERSION} /usr/local/bin/python${PYTHON_VERSION}
COPY --from=builder --chown=65532:65532 /usr/local/bin/python3 /usr/local/bin/python3
COPY --from=builder --chown=65532:65532 /usr/local/bin/python /usr/local/bin/python
COPY --from=builder --chown=65532:65532 /usr/local/lib/libpython${PYTHON_VERSION}.so.1.0 /usr/local/lib/
COPY --from=builder --chown=65532:65532 /usr/local/lib/python${PYTHON_VERSION} /usr/local/lib/python${PYTHON_VERSION}

# Venv complet : interpreteur, paquets, points d'entree.
COPY --from=builder --chown=65532:65532 /opt/venv /opt/venv

WORKDIR /app
COPY --from=builder --chown=65532:65532 /build/app /app/app

# Utilisateur "nonroot" de distroless (UID/GID 65532), explicite meme si le tag
# :nonroot le configure deja (defense en profondeur / lisibilite).
USER 65532:65532

# Documentation uniquement : l'exposition reelle est pilotee par Terraform.
EXPOSE 8000

# Healthcheck exec form (pas de shell) : GET /health sur le port interne.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["/opt/venv/bin/python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).getcode() == 200 else 1)"]

# Pas de shell : uvicorn est lance directement par l'interpreteur du venv.
# --no-server-header : retire l'en-tete "Server: uvicorn".
ENTRYPOINT ["/opt/venv/bin/python", "-m", "uvicorn", "app.main:app", \
            "--host", "0.0.0.0", "--port", "8000", \
            "--proxy-headers", "--no-server-header"]
