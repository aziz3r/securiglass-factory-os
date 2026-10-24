#!/usr/bin/env bash
# Campagne Valgrind + fuzzing Modbus pour le démon PLC SecuriGlass.
#
# Exécuté DANS le conteneur Linux (voir valgrind_campaign.sh) :
#   1. compilation stricte (-Werror) ;
#   2. N rondes [démon sous Valgrind -> fuzzing Modbus -> SIGTERM] ;
#   3. vérification stricte : 0 erreur, 0 octet perdu, 0 fuite de descripteur.
set -uo pipefail

ROUNDS="${1:-3}"
BIN="${2:-bin/plc_daemon}"
OUT="${3:-/out}"
mkdir -p "$OUT"
FAILURES=0

echo "== compilation =="
if ! make clean >/dev/null 2>&1; then :; fi
if ! make 2>&1 | tail -5; then
    echo "ECHEC : compilation"
    exit 1
fi
if [[ ! -x "$BIN" ]]; then
    echo "ECHEC : binaire introuvable : $BIN"
    exit 1
fi

for round in $(seq 1 "$ROUNDS"); do
    seed=$((1337 + round))
    port=$((15020 + round))
    vg_log="/tmp/valgrind.${round}.log"
    daemon_log="/tmp/daemon.${round}.log"

    echo "== ronde ${round}/${ROUNDS} (port ${port}, seed ${seed}) =="

    valgrind \
        --error-exitcode=42 \
        --leak-check=full \
        --show-leak-kinds=all \
        --errors-for-leak-kinds=all \
        --track-origins=yes \
        --track-fds=yes \
        --log-file="$vg_log" \
        "./$BIN" -p "$port" >"$daemon_log" 2>&1 &
    vg_pid=$!

    # Attente d'ouverture du port (max 10 s)
    ready=0
    for _ in $(seq 1 100); do
        if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
            exec 3>&- 2>/dev/null
            ready=1
            break
        fi
        sleep 0.1
    done
    if [[ "$ready" -ne 1 ]]; then
        echo "ECHEC : le démon n'écoute pas sur ${port}"
        cat "$daemon_log"
        kill -TERM "$vg_pid" 2>/dev/null
        FAILURES=$((FAILURES + 1))
        continue
    fi

    if ! python3 /qa/modbus_fuzz.py --port "$port" --rounds 120 --seed "$seed"; then
        echo "ECHEC : anomalies de fuzzing à la ronde ${round}"
        FAILURES=$((FAILURES + 1))
    fi

    kill -TERM "$vg_pid" 2>/dev/null
    wait "$vg_pid"
    daemon_rc=$?

    if [[ "$daemon_rc" -ne 0 ]]; then
        echo "ECHEC : code de sortie du démon = ${daemon_rc} (Valgrind renvoie 42 sur erreur)"
        FAILURES=$((FAILURES + 1))
    fi

    if ! grep -q "ERROR SUMMARY: 0 errors" "$vg_log"; then
        echo "ECHEC : erreurs mémoire détectées"
        grep -A6 "ERROR SUMMARY" "$vg_log" || true
        echo "--- détail Valgrind (extrait) ---"
        grep -E "Invalid (read|write)|Jump|uninitialised|at 0x|by 0x|Thread|Address 0x" "$vg_log" | head -40 || true
        FAILURES=$((FAILURES + 1))
    fi
    for kind in "definitely lost" "indirectly lost" "possibly lost"; do
        if ! grep -q "${kind}: 0 bytes" "$vg_log"; then
            echo "ECHEC : fuite mémoire (${kind})"
            grep -E "${kind}:" "$vg_log" || true
            FAILURES=$((FAILURES + 1))
        fi
    done
    if grep -qE "FILE DESCRIPTORS: [0-9]+ open \(([3-9]|[1-9][0-9]+) std" "$vg_log"; then
        echo "ECHEC : descripteurs de fichier non fermés"
        grep "FILE DESCRIPTORS" "$vg_log"
        FAILURES=$((FAILURES + 1))
    fi

    cp "$vg_log" "$OUT/round${round}.valgrind.log" 2>/dev/null || true
    cp "$daemon_log" "$OUT/round${round}.daemon.log" 2>/dev/null || true
    echo "  -> $(grep -m1 'ERROR SUMMARY' "$vg_log")"
    echo "  -> $(grep -m1 'definitely lost' "$vg_log" | sed 's/^ *//')"
done

if [[ "$FAILURES" -ne 0 ]]; then
    echo "RESULTAT : ECHEC (${FAILURES} anomalie(s))"
    exit 1
fi
echo "RESULTAT : OK — 0 erreur mémoire, 0 fuite sur ${ROUNDS} rondes"
