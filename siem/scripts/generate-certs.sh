#!/usr/bin/env bash
# ============================================================================
# SecuriGlass Factory OS - Generation de la PKI interne du SOC (Wazuh)
# ----------------------------------------------------------------------------
# Cree une CA racine locale et 4 certificats (indexeur, manager, dashboard,
# client admin) avec les SAN et les DN attendus par wazuh.indexer.yml.
# Les cles privees sont generees avec umask 077 et ne doivent jamais etre
# commitees (voir siem/.gitignore).
#
# Usage : ./scripts/generate-certs.sh [--force]
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SIEM_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERT_DIR="${SIEM_DIR}/wazuh/certs"
OPENSSL="${OPENSSL:-openssl}"
DAYS_CA=3650
DAYS_LEAF=825
SUBJ_BASE="/OU=SecuriGlass-SOC/O=SecuriGlass/L=Paris/C=FR"

FORCE=0
if [[ "${1:-}" == "--force" ]]; then
  FORCE=1
fi

if ! command -v "${OPENSSL}" >/dev/null 2>&1; then
  echo "ERREUR : openssl introuvable." >&2
  exit 1
fi

if [[ -f "${CERT_DIR}/root-ca.pem" && "${FORCE}" -ne 1 ]]; then
  echo "[certs] PKI deja presente dans ${CERT_DIR} (utiliser --force pour regenerer)."
  exit 0
fi

if [[ "${FORCE}" -eq 1 ]]; then
  echo "[certs] Regeneration forcee : suppression des anciens certificats."
  rm -f "${CERT_DIR}"/*.pem "${CERT_DIR}"/*.key "${CERT_DIR}"/*.csr "${CERT_DIR}"/*.srl
fi

umask 077
mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

gen_key() {
  local name="$1"
  "${OPENSSL}" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
    -out "${name}-key.pem" 2>/dev/null
  chmod 600 "${name}-key.pem"
}

# --- 1. CA racine -----------------------------------------------------------
echo "[certs] CA racine (${DAYS_CA} jours)..."
gen_key "root-ca"
"${OPENSSL}" req -new -x509 -sha256 -days "${DAYS_CA}" \
  -key "root-ca-key.pem" \
  -out "root-ca.pem" \
  -subj "/CN=SecuriGlass-SOC-Root-CA${SUBJ_BASE}" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash"
chmod 644 "root-ca.pem"

# --- 2. Fonction de signature ----------------------------------------------
sign_leaf() {
  local name="$1" cn="$2" san="$3" eku="$4"
  echo "[certs] ${name} (CN=${cn})..."
  gen_key "${name}"
  "${OPENSSL}" req -new -sha256 \
    -key "${name}-key.pem" \
    -out "${name}.csr" \
    -subj "/CN=${cn}${SUBJ_BASE}"

  local ext
  ext="$(mktemp)"
  cat >"${ext}" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=${eku}
subjectAltName=${san}
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF

  "${OPENSSL}" x509 -req -sha256 -days "${DAYS_LEAF}" \
    -in "${name}.csr" \
    -CA "root-ca.pem" -CAkey "root-ca-key.pem" \
    -set_serial "0x$(openssl rand -hex 16)" \
    -extfile "${ext}" \
    -out "${name}.pem" 2>/dev/null
  rm -f "${ext}" "${name}.csr"
  chmod 644 "${name}.pem"
}

# --- 3. Certificats feuilles ------------------------------------------------
# Indexeur : serveur TLS + transport (verification de nom activee)
sign_leaf "wazuh.indexer" \
  "wazuh.indexer" \
  "DNS:wazuh.indexer,DNS:localhost,IP:127.0.0.1" \
  "serverAuth,clientAuth"

# Manager : client mTLS Filebeat vers l'indexeur
sign_leaf "wazuh.manager" \
  "wazuh.manager" \
  "DNS:wazuh.manager,DNS:localhost" \
  "serverAuth,clientAuth"

# Dashboard : serveur HTTPS navigateur + client vers l'indexeur
sign_leaf "wazuh.dashboard" \
  "wazuh.dashboard" \
  "DNS:wazuh.dashboard,DNS:localhost,IP:127.0.0.1" \
  "serverAuth,clientAuth"

# Admin : client de maintenance (securityadmin, API indexeur)
sign_leaf "admin" \
  "admin" \
  "DNS:localhost,IP:127.0.0.1" \
  "clientAuth"

echo "[certs] Verification de la chaine :"
"${OPENSSL}" verify -CAfile "root-ca.pem" \
  "wazuh.indexer.pem" "wazuh.manager.pem" "wazuh.dashboard.pem" "admin.pem"

echo "[certs] OK - certificats dans ${CERT_DIR}"
