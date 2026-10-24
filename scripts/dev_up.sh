#!/usr/bin/env bash
# Démarre TOUTE la chaîne SecuriGlass en local (développement uniquement) :
#   PostgreSQL (Docker) -> backend FastAPI -> démon PLC (C) -> passerelle OT -> diode -> récepteur IT
#   -> base -> WebSocket /ws/telemetry -> console React (http://localhost:5173)
# Usage : scripts/dev_up.sh        puis        scripts/dev_down.sh
# Secrets de développement générés au premier lancement dans .dev-env (0600, ignoré par git).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$ROOT/.dev-run"; ENVF="$ROOT/.dev-env"
PY="$ROOT/services/backend-api/.venv/bin/python"
mkdir -p "$RUN"

[ -x "$PY" ] || { echo "venv absent : python3.12 -m venv services/backend-api/.venv && pip install -r services/backend-api/requirements-dev.txt" >&2; exit 1; }
command -v docker >/dev/null || { echo "docker requis" >&2; exit 1; }
docker info >/dev/null 2>&1 || { command -v colima >/dev/null && colima start --cpu 2 --memory 4 --disk 20; }

FRESH=0
if [ ! -f "$ENVF" ]; then
  FRESH=1
  umask 077
  {
    echo "DB_ADMIN_PASSWORD=dev_$(openssl rand -hex 10)"
    echo "SECRET_KEY=$(openssl rand -hex 32)"
    echo "TDE_ENCRYPTION_KEY=$(openssl rand -hex 32)"
  } > "$ENVF"
fi
set -a; . "$ENVF"; set +a
export DATABASE_URL="postgresql://securiglass_admin:${DB_ADMIN_PASSWORD}@localhost:5432/securiglass_db"
export ENVIRONMENT=development

echo "[1/7] PostgreSQL"
( cd "$ROOT/infra/docker" && docker compose up -d --build ) >/dev/null
for _ in $(seq 1 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' securiglass-postgres 2>/dev/null)" = healthy ] && break; sleep 2
done
# Volume existant créé avec un autre mot de passe : on aligne (sans effacer les données).
docker exec securiglass-postgres psql -U securiglass_admin -d securiglass_db -qc "ALTER USER securiglass_admin PASSWORD '${DB_ADMIN_PASSWORD}'" >/dev/null
if [ "$FRESH" = 1 ]; then  # nouvelles clés TDE : les anciens clients chiffrés seraient illisibles
  docker exec securiglass-postgres psql -U securiglass_admin -d securiglass_db -qc "TRUNCATE it_data.production_batches, it_data.glass_orders, it_data.customers CASCADE" >/dev/null
fi
# Extension idempotente (volume créé avant l'ajout du fichier 06 dans initdb.d)
docker exec -i securiglass-postgres psql -U securiglass_admin -d securiglass_db -q < "$ROOT/database/schemas/06_factory_extension.sql" >/dev/null
docker exec securiglass-postgres psql -U securiglass_admin -d securiglass_db -qc \
  "INSERT INTO ot_data.production_lines (line_code, line_name, ip_gateway, status) VALUES ('LINE-FOUR-01','Four de trempe 1','127.0.0.1','RUNNING') ON CONFLICT (line_code) DO NOTHING" >/dev/null

echo "[2/7] Clé Ed25519 de la passerelle"
if [ ! -f "$RUN/edge.key" ]; then
  "$PY" - "$RUN" <<'PYEOF'
import sys, os
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization as s
d = sys.argv[1]; k = ed25519.Ed25519PrivateKey.generate()
open(f"{d}/edge.key", "wb").write(k.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption()))
os.chmod(f"{d}/edge.key", 0o600)
open(f"{d}/edge.pub", "w").write(k.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw).hex())
PYEOF
fi

start() { # nom, répertoire, commande...
  local name="$1" dir="$2"; shift 2
  [ -f "$RUN/$name.pid" ] && kill -0 "$(cat "$RUN/$name.pid")" 2>/dev/null && return 0
  ( cd "$dir" || exit 1
    nohup "$@" > "$RUN/$name.log" 2>&1 < /dev/null &
    echo $! > "$RUN/$name.pid" )
}

echo "[3/7] Backend API :8000"
start backend "$ROOT/services/backend-api" .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
for _ in $(seq 1 30); do curl -fs http://127.0.0.1:8000/health >/dev/null && break; sleep 1; done

echo "[4/7] Comptes et données de démonstration"
"$PY" "$ROOT/scripts/dev_seed_users.py"
"$PY" "$ROOT/scripts/dev_seed_demo_data.py"

echo "[5/7] Démon PLC :5020 + cycle de trempe"
make -C "$ROOT/services/ot-plc-daemon" >/dev/null
start plc "$ROOT/services/ot-plc-daemon" ./bin/plc_daemon --bind 127.0.0.1 --port 5020
sleep 1
"$PY" - <<'PYEOF'
import socket, struct
s = socket.create_connection(("127.0.0.1", 5020), timeout=3)
s.sendall(struct.pack(">HHHBBHH", 1, 0, 6, 1, 6, 6, 1)); s.recv(260); s.close()  # START_CYCLE
PYEOF

echo "[6/7] Récepteur diode IT :50005 + passerelle OT"
export DIODE_TRUSTED_EMITTERS="00000000-0000-0000-0000-000000000001:$(cat "$RUN/edge.pub")" DIODE_BIND=127.0.0.1 DIODE_PORT=50005
start receiver "$ROOT/services/backend-api" .venv/bin/python -m app.services.diode_receiver
start gateway "$ROOT/services/ot-edge-gateway" "$PY" -u -m gateway --key-file "$RUN/edge.key" --interval 1

echo "[7/7] Console React :5173"
[ -d "$ROOT/services/frontend-ui/node_modules" ] || ( cd "$ROOT/services/frontend-ui" && npm ci >/dev/null )
start frontend "$ROOT/services/frontend-ui" npm run dev

echo; echo "Prêt : http://localhost:5173  (identifiants : .dev-credentials.json)"
echo "Logs : $RUN/*.log   Arrêt : scripts/dev_down.sh"
