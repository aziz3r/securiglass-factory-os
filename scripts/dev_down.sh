#!/usr/bin/env bash
# Arrête la chaîne démarrée par dev_up.sh (la base PostgreSQL est conservée : --db pour l'arrêter aussi).
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
for name in frontend gateway receiver plc backend; do
  f="$ROOT/.dev-run/$name.pid"
  [ -f "$f" ] && { pkill -P "$(cat "$f")" 2>/dev/null; kill "$(cat "$f")" 2>/dev/null; rm -f "$f"; echo "arrêté : $name"; }
done
[ "${1:-}" = "--db" ] && ( cd "$ROOT/infra/docker" && docker compose stop ) || true
