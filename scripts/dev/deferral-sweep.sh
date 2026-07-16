#!/bin/bash
# Deferral N-sweep: for each N, submit ONE proof_type=evm verify-stark-multi
# proof that makes N verify_stark calls, and record STARK vs halo2 proving time
# from the manager's /proof_state. Emits a CSV for plot-deferral-sweep.py.
#
# Prereqs:
#   1. A deferral deployment is UP with proof_type=evm capability (halo2), i.e.
#      start-provers.py --halo2 full --with-deferral --halo2-pk-path <deferral halo2 key>
#      --persist-final-proofs-dir ... --programs programs.json, where programs.json
#      points verify-stark v1 at fixtures-deferral/verify-stark-multi.elf.
#   2. Per-N fixtures derived under <fixture-dir>/N<n>/ (see the
#      derive_deferral_multi_fixtures test):
#        DEFERRAL_NUM_VERIFIES=1,2,4,8,16,32 DEFERRAL_FIXTURE_DIR=<fixture-dir> \
#        cargo test -p edge-integration-tests --test deferral_stark_e2e_test \
#          --features real-deferral-integration,cuda --release \
#          derive_deferral_multi_fixtures -- --ignored --nocapture
#
# Usage:
#   ./deferral-sweep.sh --fixture-dir /tmp/def-sweep --n-values 1,2,4,8,16,32 \
#       --worker-port-base 18001 --tag halo2-defsweep
#
# Output (under $LOG_DIR, default ~/deferral-sweep-logs):
#   <tag>.csv   — N,status,e2e_ms,proving_ms,app_ms,leaf_ms,internal_ms,compression_ms,root_ms,halo2_ms
#   <tag>.log   — full run log

set -euo pipefail

MANAGER_URL="${MANAGER_URL:-http://localhost:3000}"
FIXTURE_DIR="${FIXTURE_DIR:-/tmp/def-sweep}"
N_VALUES="1,2,4,8,16,32"
WORKER_PORT_BASE="${WORKER_PORT_BASE:-8001}"
START_PROOF="${START_PROOF:-}"
LOG_DIR="${LOG_DIR:-$HOME/deferral-sweep-logs}"
TAG=""
PROGRAM="verify-stark"
VERSION=1
TIMEOUT=3600
POLL_INTERVAL=5

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fixture-dir)      FIXTURE_DIR="$2"; shift 2 ;;
        --n-values)         N_VALUES="$2"; shift 2 ;;
        --manager)          MANAGER_URL="$2"; shift 2 ;;
        --worker-port-base) WORKER_PORT_BASE="$2"; shift 2 ;;
        --start-proof)      START_PROOF="$2"; shift 2 ;;
        --program)          PROGRAM="$2"; shift 2 ;;
        --version)          VERSION="$2"; shift 2 ;;
        --tag)              TAG="$2"; shift 2 ;;
        --timeout)          TIMEOUT="$2"; shift 2 ;;
        --poll-interval)    POLL_INTERVAL="$2"; shift 2 ;;
        -h|--help)          sed -n '2,/^$/p' "$0" | sed 's/^# \?//'; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Locate start-proof.sh (same search as benchmark-range.sh).
if [[ -z "$START_PROOF" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    for cand in \
        "$SCRIPT_DIR/../ops/start-proof.sh" \
        "${AXIOM_EDGE_DIR:-}/scripts/ops/start-proof.sh" \
        "$HOME/axiom-edge/scripts/ops/start-proof.sh"; do
        [[ -n "$cand" && -f "$cand" ]] && { START_PROOF="$cand"; break; }
    done
fi
[[ -f "${START_PROOF:-}" ]] || { echo "ERROR: start-proof.sh not found; pass --start-proof" >&2; exit 1; }

DATE=$(date +%Y%m%d-%H%M%S)
RUN_TAG="${TAG:-defsweep-${DATE}}"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/${RUN_TAG}.log"
CSV_FILE="$LOG_DIR/${RUN_TAG}.csv"
exec > >(tee -a "$LOG_FILE") 2>&1

# json_field <key> : reads /proof_state JSON on stdin, prints int or 0.
json_field() {
    python3 -c "import json,sys
try:
    print(json.load(sys.stdin).get('$1', 0) or 0)
except Exception:
    print(0)"
}

IFS=',' read -ra NS <<< "$N_VALUES"

echo "============================================================"
echo "  Deferral N-sweep: $RUN_TAG"
echo "  Manager:     $MANAGER_URL"
echo "  Fixtures:    $FIXTURE_DIR/N<n>/"
echo "  N values:    ${NS[*]}"
echo "  Worker base: $WORKER_PORT_BASE"
echo "============================================================"

curl -sf "$MANAGER_URL/healthz" >/dev/null 2>&1 || { echo "ERROR: manager not healthy at $MANAGER_URL" >&2; exit 1; }

echo "N,status,e2e_ms,proving_ms,app_ms,leaf_ms,internal_ms,compression_ms,root_ms,halo2_ms" > "$CSV_FILE"

for N in "${NS[@]}"; do
    DIR="$FIXTURE_DIR/N${N}"
    IN="$DIR/outer_stdin.bin"
    ST="$DIR/deferral_state_0.bin"
    DI="$DIR/deferral_input_0.bin"
    if [[ ! -f "$IN" || ! -f "$ST" || ! -f "$DI" ]]; then
        echo "  N=$N SKIP: missing fixtures under $DIR"
        echo "$N,missing_fixtures,0,0,0,0,0,0,0,0" >> "$CSV_FILE"
        continue
    fi

    UUID="${RUN_TAG}-N${N}"
    echo ""
    echo "--- N=$N  (proof_uuid: $UUID) ---"
    SP_EXIT=0
    "$START_PROOF" \
        --input "$IN" \
        --program "$PROGRAM" --version "$VERSION" \
        --proof-type evm \
        --deferral-state "$ST" \
        --deferral-input "$DI" \
        --proof-uuid "$UUID" \
        --manager "$MANAGER_URL" --worker-port-base "$WORKER_PORT_BASE" \
        --timeout "$TIMEOUT" --poll-interval "$POLL_INTERVAL" || SP_EXIT=$?

    STATE="$(curl -sf "$MANAGER_URL/proof_state/$UUID" 2>/dev/null || echo '{}')"
    STATUS="$(echo "$STATE" | python3 -c "import json,sys
try:
    s=json.load(sys.stdin).get('status','unknown'); print(s if isinstance(s,str) else next(iter(s.keys())))
except Exception: print('unknown')")"
    E2E="$(echo "$STATE" | json_field e2e_latency_ms)"
    PROV="$(echo "$STATE" | json_field proving_latency_ms)"
    APP="$(echo "$STATE" | json_field total_app_prove_ms)"
    LEAF="$(echo "$STATE" | json_field total_leaf_prove_ms)"
    INT="$(echo "$STATE" | json_field total_internal_prove_ms)"
    COMP="$(echo "$STATE" | json_field compression_time_ms)"
    ROOT="$(echo "$STATE" | json_field total_root_prove_ms)"
    HALO2="$(echo "$STATE" | json_field total_halo2_prove_ms)"

    [[ "$SP_EXIT" -ne 0 && "$STATUS" == "completed" ]] && STATUS="failed(exit=$SP_EXIT)"
    echo "  status=$STATUS  e2e=${E2E}ms  root=${ROOT}ms  halo2=${HALO2}ms  (evm tail=$((ROOT+HALO2))ms)"
    echo "$N,$STATUS,$E2E,$PROV,$APP,$LEAF,$INT,$COMP,$ROOT,$HALO2" >> "$CSV_FILE"
done

echo ""
echo "============================================================"
echo "  CSV:  $CSV_FILE"
echo "  Plot: python3 $(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/plot-deferral-sweep.py $CSV_FILE"
echo "============================================================"
column -t -s, "$CSV_FILE"
