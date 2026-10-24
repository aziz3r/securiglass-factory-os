#!/usr/bin/env bash
# Campagne Valgrind + fuzzing Modbus (hôte macOS -> conteneur Linux).
# Valgrind n'existe pas sur macOS : installation à la volée dans gcc:13-bookworm
# (image locale), copie des sources dans /tmp pour ne rien écrire côté hôte.
#
# Usage : ./scripts/otqa/valgrind_campaign.sh [rondes] [binaire]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROUNDS="${1:-3}"
BIN="${2:-bin/plc_daemon}"

exec docker run --rm \
    -v "$ROOT/services/ot-plc-daemon:/src:ro" \
    -v "$ROOT/scripts/otqa:/qa:ro" \
    -v "$ROOT/scripts/otqa/out:/out" \
    gcc:13-bookworm \
    bash -lc "set -e; mkdir -p /out; apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq valgrind >/dev/null 2>&1; cp -r /src /tmp/build; cd /tmp/build; bash /qa/valgrind_inner.sh '$ROUNDS' '$BIN' '/out'"
