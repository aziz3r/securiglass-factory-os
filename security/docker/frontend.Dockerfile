# =============================================================================
# SecuriGlass Factory OS - Frontend SPA (Vite / React / TypeScript)
# =============================================================================
# Durcissement :
#   - build multi-etapes : node:22-alpine (builder) -> nginx unprivileged alpine ;
#   - image finale non-root : USER 101:101 (uid/gid "nginx" de l'image) ;
#   - ecoute sur le port 8080 non privilegie (jamais 80) ;
#   - racine en lecture seule : PID et repertoires temporaires sous /tmp
#     (monter /tmp en tmpfs, cf. security/docker/nginx.conf) ;
#   - en-tetes CSP / HSTS / nosniff / frame-ancestors / Permissions-Policy ;
#   - routage SPA par try_files, assets caches, index.html non cache.
#
# Construction (contexte = racine du depot) :
#   docker build -f security/docker/frontend.Dockerfile -t securiglass/frontend-ui:1.0.0 .
#
# Le dossier services/frontend-ui est developpe en parallele : la CI ne lance
# ce build que si services/frontend-ui/package.json existe (hashFiles).
# =============================================================================

ARG NODE_IMAGE=node:22-alpine
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.27-alpine

# -----------------------------------------------------------------------------
# Etage 1 - Build Vite (TypeScript strict)
# -----------------------------------------------------------------------------
FROM ${NODE_IMAGE} AS build

WORKDIR /build

ENV CI=true \
    NODE_ENV=development \
    NPM_CONFIG_FUND=false \
    NPM_CONFIG_AUDIT=false

# Cache de couche : manifestes seuls d'abord.
# Le glob package-lock.json* tolere l'absence du lock (npm install en repli).
COPY services/frontend-ui/package.json services/frontend-ui/package-lock.json* ./

RUN if [ -f package-lock.json ]; then \
        npm ci --no-audit --no-fund; \
    else \
        npm install --no-audit --no-fund; \
    fi

# Sources de l'application (node_modules de l'hote exclu par .dockerignore).
COPY services/frontend-ui/ ./

# URL d'API injectee au build par Vite (aucun secret : valeur publique).
ARG VITE_API_BASE_URL=/api/v1
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

RUN npm run build

# -----------------------------------------------------------------------------
# Etage 2 - Runtime nginx non privilegie
# -----------------------------------------------------------------------------
FROM ${NGINX_IMAGE}

# Configuration maitresse durcie (CSP/HSTS, try_files, chemins /tmp).
COPY security/docker/nginx.conf /etc/nginx/nginx.conf

# Artefacts statiques produits par Vite.
COPY --from=build --chown=101:101 /build/dist /usr/share/nginx/html

# UID/GID 101 = utilisateur "nginx" de l'image nginx-unprivileged.
USER 101:101

EXPOSE 8080

# Healthcheck sans shell : wget BusyBox present dans l'image alpine.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["wget", "-q", "-O", "/dev/null", "http://127.0.0.1:8080/healthz"]

# On court-circuite le script d'entrypoint de l'image (qui peut ecrire dans
# /etc/nginx) pour rester compatible avec une racine en lecture seule.
# Aucune fonctionnalite d'envsubst n'est utilisee par cette configuration.
ENTRYPOINT ["nginx", "-g", "daemon off;"]
