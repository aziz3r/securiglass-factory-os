#!/usr/bin/env bash
# ============================================================================
# SecuriGlass Factory OS - Bootstrap de la pile SOC Wazuh
# ----------------------------------------------------------------------------
# 1. Cree siem/.env avec des mots de passe aleatoires (si absent).
# 2. Genere la PKI interne (CA + certificats).
# 3. Genere internal_users.yml (hashes bcrypt) et wazuh.yml.
# 4. Valide la configuration Compose.
#
# Aucun secret n'est affiche. Le fichier .env est en chmod 600 et ignore par git.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIEM_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${SIEM_DIR}/.env"
ENV_EXAMPLE="${SIEM_DIR}/.env.example"

cd "${SIEM_DIR}"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "ERREUR : commande requise introuvable : $1" >&2
    exit 1
  }
}
need_cmd openssl

# --- 1. Fichier .env --------------------------------------------------------
if [[ ! -f "${ENV_FILE}" ]]; then
  echo "[bootstrap] Creation de siem/.env (mots de passe aleatoires)."
  umask 077
  local_indexer="$(openssl rand -hex 24)"
  local_dashboard="$(openssl rand -hex 24)"
  local_api="$(openssl rand -hex 24)"
  # Remplacement litteral via awk pour ne pas interpreter les caracteres speciaux
  awk -v i="${local_indexer}" -v d="${local_dashboard}" -v a="${local_api}" '
    /^INDEXER_PASSWORD=/   { print "INDEXER_PASSWORD=" i; next }
    /^DASHBOARD_PASSWORD=/ { print "DASHBOARD_PASSWORD=" d; next }
    /^API_PASSWORD=/       { print "API_PASSWORD=" a; next }
    { print }
  ' "${ENV_EXAMPLE}" >"${ENV_FILE}"
  chmod 600 "${ENV_FILE}"
else
  echo "[bootstrap] siem/.env deja present (conserve)."
fi

env_value() {
  # Lit une cle sans sourcer le fichier (evite l'evaluation de shell).
  local key="$1"
  grep -E "^${key}=" "${ENV_FILE}" | head -n1 | cut -d'=' -f2- | sed -e 's/^"//' -e 's/"$//'
}

INDEXER_PASSWORD="$(env_value INDEXER_PASSWORD)"
DASHBOARD_PASSWORD="$(env_value DASHBOARD_PASSWORD)"
API_PASSWORD="$(env_value API_PASSWORD)"

for pair in "INDEXER_PASSWORD:${INDEXER_PASSWORD}" "DASHBOARD_PASSWORD:${DASHBOARD_PASSWORD}" "API_PASSWORD:${API_PASSWORD}"; do
  value="${pair#*:}"
  if [[ -z "${value}" || "${value}" == CHANGEME* ]]; then
    echo "ERREUR : ${pair%%:*} non defini dans siem/.env (valeur par defaut)." >&2
    exit 1
  fi
done

# --- 2. PKI ----------------------------------------------------------------
"${SCRIPT_DIR}/generate-certs.sh"

# --- 3. Hash bcrypt --------------------------------------------------------
hash_password() {
  local password="$1"
  if command -v htpasswd >/dev/null 2>&1; then
    # -B : bcrypt, -C 12 : cout, -n : stdout, -b : mot de passe en argument.
    htpasswd -bnBC 12 "" "${password}" | cut -d: -f2 | tr -d '\r\n'
  elif [[ -x "${SIEM_DIR}/.venv/bin/python" ]] && \
       "${SIEM_DIR}/.venv/bin/python" -c "import bcrypt" >/dev/null 2>&1; then
    "${SIEM_DIR}/.venv/bin/python" - "${password}" <<'PY'
import sys
import bcrypt

pw = sys.argv[1].encode("utf-8")
print(bcrypt.hashpw(pw, bcrypt.gensalt(rounds=12)).decode("ascii").replace("$2b$", "$2y$"))
PY
  else
    echo "ERREUR : htpasswd (apache2-utils) ou bcrypt (venv siem/.venv) requis." >&2
    exit 1
  fi
}

ADMIN_HASH="$(hash_password "${INDEXER_PASSWORD}")"
DASHBOARD_HASH="$(hash_password "${DASHBOARD_PASSWORD}")"

if [[ "${ADMIN_HASH}" != \$2* || "${DASHBOARD_HASH}" != \$2* ]]; then
  echo "ERREUR : hash bcrypt invalide genere." >&2
  exit 1
fi

# --- 4. Fichiers derives ----------------------------------------------------
python3 - "${SIEM_DIR}" "${ADMIN_HASH}" "${DASHBOARD_HASH}" "${API_PASSWORD}" <<'PY'
import os
import sys

siem_dir, admin_hash, dashboard_hash, api_password = sys.argv[1:5]

def render(template: str, output: str, replacements: dict[str, str]) -> None:
    with open(template, encoding="utf-8") as fh:
        content = fh.read()
    for key, value in replacements.items():
        if key not in content:
            raise SystemExit(f"placeholder absent du modele {template}: {key}")
        content = content.replace(key, value)
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(output, 0o600)

render(
    os.path.join(siem_dir, "wazuh/config/indexer/internal_users.yml.template"),
    os.path.join(siem_dir, "wazuh/config/indexer/internal_users.yml"),
    {"__ADMIN_PASSWORD_HASH__": admin_hash, "__DASHBOARD_PASSWORD_HASH__": dashboard_hash},
)
render(
    os.path.join(siem_dir, "wazuh/config/dashboard/wazuh.yml.template"),
    os.path.join(siem_dir, "wazuh/config/dashboard/wazuh.yml"),
    {"__API_PASSWORD__": api_password},
)
print("[bootstrap] internal_users.yml et wazuh.yml generes (chmod 600).")
PY

chmod 600 "${ENV_FILE}" \
  "${SIEM_DIR}/wazuh/config/indexer/internal_users.yml" \
  "${SIEM_DIR}/wazuh/config/dashboard/wazuh.yml"

# --- 5. Validation Compose --------------------------------------------------
if command -v docker >/dev/null 2>&1; then
  echo "[bootstrap] Validation de la configuration Compose..."
  docker compose --env-file "${ENV_FILE}" -f "${SIEM_DIR}/docker-compose.yml" config --quiet
  echo "[bootstrap] Compose valide."
else
  echo "[bootstrap] Docker absent : validation Compose ignoree."
fi

cat <<'EOF'

[bootstrap] Termine.
  - Verifier les limites memoire dans docker-compose.yml (2g/1g/768m).
  - Demarrer : docker compose up -d
  - Dashboard : https://127.0.0.1:8443 (certificat interne auto-signe)
  - Ne jamais commiter siem/.env ni les cles de siem/wazuh/certs/.
EOF
