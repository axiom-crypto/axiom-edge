#!/bin/bash
# Submit a single proof to the manager and poll until it reaches a terminal
# state. Minimal by design — no manifest, no stats; just one proof, one
# program, one input.
#
# Input handling (two transports):
#
#   Direct (default): the script uploads the input straight to every worker in
#   parallel, then submits with input_already_uploaded=true so the manager
#   skips its own fan-out. Workers are reached on the host-published ports
#   localhost:(WORKER_PORT_BASE + i) — these must match the --worker-port-base
#   passed to start-provers.py. For single-element inputs the raw "compact"
#   bytes are uploaded (~4x smaller than the bincode StdIn) and each worker
#   rebuilds the StdIn locally. Multi-element inputs upload the full StdIn
#   bincode instead (the compact endpoint can only represent one element).
#   Deferral is NOT supported on this transport.
#
#   Manager (--via-manager, or auto-selected when the worker ports aren't
#   reachable from the host, and always used for deferral): the script uploads
#   the bincode StdIn to the manager (POST /upload_input/{uuid}); the manager
#   fans it out to the workers. This is the general path and the only one that
#   supports deferral (the manager retains each DeferralInput and pushes it
#   just-in-time to the tail worker). Slower for the main input (extra hop + 4x
#   payload), but assumption-free (no shared filesystem needed).
#
# Accepts .json, .bin (bincode StdIn), or .compact (raw single-element bytes,
# direct transport only). JSON is converted on the fly; temps are deleted on
# exit.
#
# Usage:
#   ./start-proof.sh --input ~/input/example.json \
#                    --program my-program \
#                    --version 0
#
# `--program` and `--version` are optional when the manager has exactly
# one program in its loadout; the manager resolves the missing field
# server-side. If you omit one you must omit the other (the pair is
# treated as a single hint). Multi-program loadouts still require both.
#
# Options:
#   --input,    -i  PATH    Host-side path to input file (.json/.bin/.compact).
#   --program,  -p  NAME    Program name (must be in /loadout). Optional
#                           when only one program is loaded.
#   --version,  -v  N       Program version. Optional, paired with --program.
#   --proof-uuid    UUID    Custom proof_uuid (default: auto).
#   --manager       URL     Manager URL (default: http://localhost:3000).
#   --artifacts     DIR     Host-side artifacts dir (default: $ARTIFACTS_PATH
#                           or /tmp/edge-test-artifacts).
#   --worker-port-base PORT Base host port for workers; worker i is reached at
#                           localhost:(PORT+i) (default: 8001). Must match
#                           start-provers.py --worker-port-base.
#   --via-manager           Force the manager transport (upload input to the
#                           manager, which fans out). Auto-selected for deferral
#                           and when workers aren't directly reachable.
#   --timeout       SECS    Watchdog timeout (default: 3600).
#   --poll-interval SECS    Polling cadence (default: 5).
#   --no-wait               Submit and exit immediately, print proof_uuid.
#   --segment-memory N      Optional override for OPENVM_MAX_SEGMENT_MEMORY.
#   --proof-type TYPE       "stark" (default) or "evm". Stark deployments stop
#                           at the final internal proof; evm runs root → halo2.
#   --deferral-state PATH   (Repeatable) Path to a serialized DeferralState
#                           (the caller-derived per-circuit execution input
#                           consumed by app workers). One per deferral
#                           circuit, in def-idx order. Must be paired with a
#                           matching number of --deferral-input flags.
#                           Uploaded to the manager (forces the manager
#                           transport); .bin only.
#   --deferral-input PATH   (Repeatable) Path to a serialized DeferralInput
#                           (the inner proof bytes consumed by the tail
#                           worker's `prove_def`). One per deferral circuit,
#                           same order as --deferral-state. .bin only. Uploaded
#                           to the manager, which retains it and pushes it to
#                           the tail worker just before the final internal prove.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${REPO_ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
MANAGER_URL="${MANAGER_URL:-http://localhost:3000}"
ARTIFACTS="${ARTIFACTS_PATH:-/tmp/edge-test-artifacts}"
CONVERT_BIN="$REPO_ROOT/target/release/convert_fixtures"
INPUT_PATH=""
PROGRAM_NAME=""
PROGRAM_VERSION=""
PROOF_UUID=""
PROOF_TIMEOUT=3600
POLL_INTERVAL=5
NO_WAIT=false
SEGMENT_MEMORY=""
WORKER_PORT_BASE=8001
VIA_MANAGER=false
PROOF_TYPE="stark"
DEFERRAL_STATE_PATHS=()
DEFERRAL_INPUT_PATHS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --input|-i)         INPUT_PATH="$2"; shift 2 ;;
        --program|-p)       PROGRAM_NAME="$2"; shift 2 ;;
        --version|-v)       PROGRAM_VERSION="$2"; shift 2 ;;
        --proof-uuid)       PROOF_UUID="$2"; shift 2 ;;
        --manager)          MANAGER_URL="$2"; shift 2 ;;
        --artifacts)        ARTIFACTS="$2"; shift 2 ;;
        --worker-port-base) WORKER_PORT_BASE="$2"; shift 2 ;;
        --via-manager)      VIA_MANAGER=true; shift ;;
        --timeout)          PROOF_TIMEOUT="$2"; shift 2 ;;
        --poll-interval)    POLL_INTERVAL="$2"; shift 2 ;;
        --no-wait)          NO_WAIT=true; shift ;;
        --segment-memory)   SEGMENT_MEMORY="$2"; shift 2 ;;
        --proof-type)       PROOF_TYPE="$2"; shift 2 ;;
        --deferral-state)   DEFERRAL_STATE_PATHS+=("$2"); shift 2 ;;
        --deferral-input)   DEFERRAL_INPUT_PATHS+=("$2"); shift 2 ;;
        --help|-h)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$INPUT_PATH" ]]; then
    echo "ERROR: --input is required" >&2
    echo "Usage: $0 --input PATH [--program NAME --version N]" >&2
    exit 1
fi

# `--program` + `--version` are paired: either both set or both omitted.
# Both omitted is OK only when the manager has exactly one program loaded;
# the manager resolves and returns 400 if the loadout has >= 2 programs.
if [[ -n "$PROGRAM_NAME" && -z "$PROGRAM_VERSION" ]] \
   || [[ -z "$PROGRAM_NAME" && -n "$PROGRAM_VERSION" ]]; then
    echo "ERROR: --program and --version must be set together (or both omitted)" >&2
    exit 1
fi

# Expand ~ in the input path.
INPUT_PATH="${INPUT_PATH/#\~/$HOME}"
if [[ ! -f "$INPUT_PATH" ]]; then
    echo "ERROR: input file not found: $INPUT_PATH" >&2
    exit 1
fi

if [[ -z "$PROOF_UUID" ]]; then
    PROOF_UUID="oneoff-$(date +%s)-$$"
fi

# ─── Manager pre-flight ─────────────────────────────────────────────────────

if ! curl -sf "$MANAGER_URL/healthz" > /dev/null 2>&1; then
    echo "ERROR: Manager not healthy at $MANAGER_URL/healthz" >&2
    exit 1
fi

# ─── Temp cleanup ───────────────────────────────────────────────────────────
# Every temp (converted payload, upload body, status dir) is registered here
# and removed on exit so a benchmark loop doesn't leak files.

TEMP_FILES=()
cleanup_temp() {
    local f
    for f in "${TEMP_FILES[@]:-}"; do
        [[ -n "$f" && -e "$f" ]] && rm -rf "$f"
    done
    # Always succeed: this runs from the EXIT trap, and under `set -e` a
    # non-zero last command here (e.g. the `[[ ]]` when the array is empty)
    # would override the script's real exit code.
    return 0
}
trap cleanup_temp EXIT INT TERM

ensure_convert_bin() {
    if [[ ! -f "$CONVERT_BIN" ]]; then
        echo "Building convert_fixtures..." >&2
        (cd "$REPO_ROOT" && cargo build --release --bin convert_fixtures) 2>&1 | tail -5
    fi
}

# ─── Choose transport: direct worker upload vs manager fan-out ──────────────
# Direct is the default and the fast path: upload straight to each worker using
# the URL it registered with the manager (/readyz). Two cases:
#   - Internal docker DNS (edge-worker-N:8001) — not reachable from the host;
#     rewritten to the locally published port localhost:(WORKER_PORT_BASE + N).
#   - A real host:port (e.g. a second machine started with --worker-host) — used
#     verbatim; the port is already in the URL, so WORKER_PORT_BASE is ignored.
# We fall back to the manager only when forced (--via-manager) or when the
# derived endpoints aren't reachable (and the input can be a StdIn .bin).

TRANSPORT="direct"
[[ "$VIA_MANAGER" == "true" ]] && TRANSPORT="manager"

# Deferral is manager-staged only: the manager retains each DeferralInput and
# pushes it just-in-time to the worker that runs the tail merge. So any deferral
# request forces the manager transport regardless of the default/--via-manager.
if [[ ${#DEFERRAL_STATE_PATHS[@]} -gt 0 ]]; then
    if [[ "$INPUT_PATH" == *.compact ]]; then
        echo "ERROR: a .compact input cannot be combined with deferral; deferral requires" >&2
        echo "       the manager transport, which takes a bincode StdIn (.json/.bin)." >&2
        exit 1
    fi
    TRANSPORT="manager"
fi

WORKER_TARGETS=()
if [[ "$TRANSPORT" == "direct" ]]; then
    READY_BODY="$(curl -s -m 10 "$MANAGER_URL/readyz" || true)"
    # Script is fed via -c (not stdin) so the /readyz body can be piped in on
    # stdin — feeding both the program and the data through stdin would clash.
    DERIVE_TARGETS_PY=$(cat <<'PY'
import json, sys
from urllib.parse import urlparse
base = int(sys.argv[1])
try:
    data = json.load(sys.stdin)
except Exception:
    sys.exit(0)
for entry in data.get("workers", []):
    # entry is [worker_id, {"worker_url": ...}]
    wid = entry[0]
    url = entry[1].get("worker_url", "")
    host = urlparse(url).hostname or ""
    if host.startswith("edge-worker"):
        # Internal docker hostname: reach it on the locally published port.
        try:
            idx = int(host.rsplit("-", 1)[-1])
        except ValueError:
            idx = wid
        print(f"http://localhost:{base + idx}")
    elif url:
        print(url.rstrip("/"))
PY
)
    while IFS= read -r line; do
        [[ -n "$line" ]] && WORKER_TARGETS+=("$line")
    done < <(printf '%s' "$READY_BODY" | python3 -c "$DERIVE_TARGETS_PY" "$WORKER_PORT_BASE")

    if [[ "${#WORKER_TARGETS[@]}" -lt 1 ]]; then
        if [[ "$INPUT_PATH" == *.compact ]]; then
            echo "ERROR: no worker endpoints from /readyz, and a .compact input cannot" >&2
            echo "       use the manager fan-out path. Is the manager up with workers?" >&2
            echo "$READY_BODY" >&2
            exit 1
        fi
        echo "WARN: could not derive worker endpoints from /readyz; falling back to" >&2
        echo "      manager fan-out (slower)." >&2
        TRANSPORT="manager"
    elif ! curl -sf -m 3 "${WORKER_TARGETS[0]}/healthz" > /dev/null 2>&1; then
        if [[ "$INPUT_PATH" == *.compact ]]; then
            echo "ERROR: worker ${WORKER_TARGETS[0]} not reachable, and a .compact input" >&2
            echo "       cannot use the manager fan-out path. Check --worker-port-base" >&2
            echo "       and that worker host ports are published/reachable." >&2
            exit 1
        fi
        echo "WARN: worker ${WORKER_TARGETS[0]} not reachable; falling back to manager" >&2
        echo "      fan-out (slower). Check --worker-port-base, or pass --via-manager." >&2
        TRANSPORT="manager"
    fi
fi

if [[ "$TRANSPORT" == "direct" ]]; then
    # ─── Direct path: upload to every worker in parallel ────────────────────
    #
    # Single-element inputs ride /upload_input_compact (raw bytes, ~4x smaller;
    # the worker rebuilds the StdIn). Everything else uploads the full bincode
    # StdIn verbatim via /upload_input. Then start_proof is submitted with
    # input_already_uploaded=true and the on-worker /dev/shm path, so the
    # manager skips its own read + fan-out entirely.

    NUM_WORKERS="${#WORKER_TARGETS[@]}"

    UPLOAD_ENDPOINT=""
    PAYLOAD_FILE=""
    case "$INPUT_PATH" in
        *.json)
            ensure_convert_bin
            NELEM="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["input"]))' "$INPUT_PATH")"
            PAYLOAD_FILE="$(mktemp "${TMPDIR:-/tmp}/start-proof-${PROOF_UUID}-XXXXXX")"
            TEMP_FILES+=("$PAYLOAD_FILE")
            if [[ "$NELEM" == "1" ]]; then
                echo "Converting $INPUT_PATH -> compact bytes (1 element)..."
                "$CONVERT_BIN" json-to-compact --json "$INPUT_PATH" --output "$PAYLOAD_FILE" 2>&1 | sed 's/^/  /'
                UPLOAD_ENDPOINT="upload_input_compact"
            else
                echo "Converting $INPUT_PATH -> bincode StdIn ($NELEM elements)..."
                "$CONVERT_BIN" json-to-stdin --json "$INPUT_PATH" --output "$PAYLOAD_FILE" 2>&1 | sed 's/^/  /'
                UPLOAD_ENDPOINT="upload_input"
            fi
            ;;
        *.compact)
            PAYLOAD_FILE="$INPUT_PATH"
            UPLOAD_ENDPOINT="upload_input_compact"
            ;;
        *.bin)
            PAYLOAD_FILE="$INPUT_PATH"
            UPLOAD_ENDPOINT="upload_input"
            ;;
        *)
            echo "ERROR: unsupported input extension (expected .json/.bin/.compact): $INPUT_PATH" >&2
            exit 1
            ;;
    esac

    # Body is the raw payload; proof_uuid rides in the URL path.
    PAYLOAD_BYTES="$(wc -c < "$PAYLOAD_FILE" | tr -d ' ')"

    STATUS_DIR="$(mktemp -d "${TMPDIR:-/tmp}/start-proof-up-${PROOF_UUID}-XXXXXX")"
    TEMP_FILES+=("$STATUS_DIR")

    echo "Uploading ${PAYLOAD_BYTES} bytes to ${NUM_WORKERS} worker(s) in parallel via /${UPLOAD_ENDPOINT}/${PROOF_UUID}..."
    UP_START=$SECONDS
    for ((i = 0; i < NUM_WORKERS; i++)); do
        target="${WORKER_TARGETS[$i]}"
        (
            # -w captures per-worker timing: time_total includes the worker's
            # receive + StdIn expand + /dev/shm write (the POST only returns
            # once the file is written), while speed_upload reflects the wire
            # transfer. High speed_upload + high time_total => worker-side cost;
            # low speed_upload => network-bound.
            if m=$(curl -fsS -m 300 \
                -H 'Content-Type: application/octet-stream' \
                --data-binary "@$PAYLOAD_FILE" \
                -o /dev/null -w '%{time_total} %{speed_upload}' \
                "${target}/${UPLOAD_ENDPOINT}/${PROOF_UUID}" 2>"$STATUS_DIR/err.$i"); then
                echo "ok $m" > "$STATUS_DIR/status.$i"
            else
                echo "fail(curl=$?)" > "$STATUS_DIR/status.$i"
            fi
        ) &
    done
    wait

    UPLOAD_FAILED=0
    for ((i = 0; i < NUM_WORKERS; i++)); do
        s="$(cat "$STATUS_DIR/status.$i" 2>/dev/null || echo "fail(no-status)")"
        case "$s" in
            ok\ *)
                # "ok <time_total_s> <speed_upload_Bps>"
                t="$(awk '{print $2}' <<<"$s")"
                mbps="$(awk '{printf "%.1f", $3/1048576}' <<<"$s")"
                printf '  worker %d (%s): %ss @ %s MB/s\n' "$i" "${WORKER_TARGETS[$i]}" "$t" "$mbps"
                ;;
            *)
                UPLOAD_FAILED=1
                echo "  worker $i (${WORKER_TARGETS[$i]}): $s" >&2
                [[ -s "$STATUS_DIR/err.$i" ]] && sed 's/^/    /' "$STATUS_DIR/err.$i" >&2
                ;;
        esac
    done
    if [[ "$UPLOAD_FAILED" == "1" ]]; then
        echo "ERROR: input upload failed to one or more workers (see above)." >&2
        exit 1
    fi
    echo "  uploaded to ${NUM_WORKERS} worker(s) in $((SECONDS - UP_START))s"

    CONTAINER_INPUT_PATH="/dev/shm/edge_${PROOF_UUID}/input.bin"
    INPUT_ALREADY_UPLOADED=True
    SUBMIT_SEES_LABEL="workers see:"
else
    # ─── Manager-staged path (Flow 2) ───────────────────────────────────────
    # Resolve the bincode StdIn. It, plus any deferral parts (below), is
    # uploaded to the manager in ONE multipart request; the manager then fans
    # it out to the workers. Accepts .json (converted) or .bin.

    case "$INPUT_PATH" in
        *.json)
            ensure_convert_bin
            STAGE_BIN="$(mktemp "${TMPDIR:-/tmp}/start-proof-${PROOF_UUID}-XXXXXX")"
            TEMP_FILES+=("$STAGE_BIN")
            echo "Converting $INPUT_PATH -> bincode StdIn..."
            "$CONVERT_BIN" json-to-stdin --json "$INPUT_PATH" --output "$STAGE_BIN" 2>&1 | sed 's/^/  /'
            MANAGER_PAYLOAD_FILE="$STAGE_BIN"
            ;;
        *.bin)
            MANAGER_PAYLOAD_FILE="$INPUT_PATH"
            ;;
        *.compact)
            echo "ERROR: .compact input requires the direct path; not supported via the manager." >&2
            exit 1
            ;;
        *)
            echo "ERROR: unsupported input extension (expected .json/.bin): $INPUT_PATH" >&2
            exit 1
            ;;
    esac

    CONTAINER_INPUT_PATH="/dev/shm/edge_${PROOF_UUID}/input.bin"
    INPUT_ALREADY_UPLOADED=False
    SUBMIT_SEES_LABEL="manager staged, workers see:"
fi

# ─── Upload everything to the manager in ONE multipart request (Flow 2) ─────
#
# One `POST /upload_input/{uuid}` carries the main input plus, for a deferral
# proof, each circuit's DeferralState/DeferralInput — so the caller makes a
# single upload call regardless of circuit count. The manager fans the input +
# each DeferralState out to app workers and retains each DeferralInput for the
# just-in-time push to the tail worker. It infers the circuit count from the
# parts (contiguous indices 0..N). Deferral forced the manager transport above.

if [[ ${#DEFERRAL_STATE_PATHS[@]} -ne ${#DEFERRAL_INPUT_PATHS[@]} ]]; then
    echo "ERROR: --deferral-state and --deferral-input must be paired \
(${#DEFERRAL_STATE_PATHS[@]} state files vs ${#DEFERRAL_INPUT_PATHS[@]} input files)" >&2
    exit 1
fi

# Validate a caller-supplied deferral host path (tilde, existence, .bin) and
# echo the resolved local path.
resolve_deferral_host_file() {
    # $1 = host path to .bin, $2 = tag (state|input)
    local host_path="${1/#\~/$HOME}"
    local tag="$2"
    if [[ ! -f "$host_path" ]]; then
        echo "ERROR: deferral $tag file not found: $host_path" >&2
        exit 1
    fi
    case "$host_path" in
        *.bin) ;;
        *)
            echo "ERROR: deferral $tag must be .bin (serialized $tag): $host_path" >&2
            exit 1
            ;;
    esac
    echo "$host_path"
}

if [[ "$TRANSPORT" == "manager" ]]; then
    # Build the multipart form: `input`, then one deferral_state_{i} /
    # deferral_input_{i} pair per circuit.
    UPLOAD_FORM=(-F "input=@${MANAGER_PAYLOAD_FILE}")
    for i in "${!DEFERRAL_STATE_PATHS[@]}"; do
        sh_state="$(resolve_deferral_host_file "${DEFERRAL_STATE_PATHS[$i]}" "state")"
        sh_input="$(resolve_deferral_host_file "${DEFERRAL_INPUT_PATHS[$i]}" "input")"
        UPLOAD_FORM+=(-F "deferral_state_${i}=@${sh_state}")
        UPLOAD_FORM+=(-F "deferral_input_${i}=@${sh_input}")
        echo "  deferral [$i] state=$sh_state"
        echo "           input=$sh_input"
    done

    if [[ ${#DEFERRAL_STATE_PATHS[@]} -gt 0 ]]; then
        echo "Uploading input + ${#DEFERRAL_STATE_PATHS[@]} deferral circuit(s) to manager via /upload_input/${PROOF_UUID}..."
    else
        echo "Uploading input to manager via /upload_input/${PROOF_UUID}..."
    fi
    if ! curl -fsS -m 300 -o /dev/null "${UPLOAD_FORM[@]}" \
        "$MANAGER_URL/upload_input/$PROOF_UUID"; then
        echo "ERROR: input upload to manager failed." >&2
        exit 1
    fi
fi

# ─── Build request body ─────────────────────────────────────────────────────

REQUEST_JSON=$(python3 - <<PY
import json
req = {
    "proof_uuid": "$PROOF_UUID",
    "input_already_uploaded": $INPUT_ALREADY_UPLOADED,
    "proof_type": "$PROOF_TYPE",
}
# Omit "program" when neither --program nor --version was supplied; the
# manager will resolve it from its loadout if exactly one program is
# loaded, or reject with 400 if multiple are loaded.
if "$PROGRAM_NAME":
    req["program"] = {"name": "$PROGRAM_NAME", "version": int("$PROGRAM_VERSION")}
if "$SEGMENT_MEMORY":
    req["segment_memory"] = int("$SEGMENT_MEMORY")
print(json.dumps(req))
PY
)

echo ""
echo "Submitting proof:"
echo "  proof_uuid:    $PROOF_UUID"
if [[ -n "$PROGRAM_NAME" ]]; then
    echo "  program:       $PROGRAM_NAME v$PROGRAM_VERSION"
else
    echo "  program:       (omitted — manager will use sole loaded program)"
fi
echo "  host input:    $INPUT_PATH"
echo "  transport:     $TRANSPORT"
echo "  $SUBMIT_SEES_LABEL $CONTAINER_INPUT_PATH"
echo "  manager:       $MANAGER_URL"
echo "  proof_type:    $PROOF_TYPE"
if [[ ${#DEFERRAL_STATE_PATHS[@]} -gt 0 ]]; then
    echo "  deferrals:     ${#DEFERRAL_STATE_PATHS[@]} circuit(s)"
fi
echo ""

# ─── Submit ─────────────────────────────────────────────────────────────────

RESPONSE_FILE="$(mktemp "${TMPDIR:-/tmp}/start-proof-resp-${PROOF_UUID}-XXXXXX")"
TEMP_FILES+=("$RESPONSE_FILE")
HTTP_CODE=$(curl -s -o "$RESPONSE_FILE" -w '%{http_code}' \
    -X POST "$MANAGER_URL/start_proof" \
    -H 'Content-Type: application/json' \
    -d "$REQUEST_JSON")
BODY=$(cat "$RESPONSE_FILE")

if [[ "$HTTP_CODE" != "200" ]]; then
    echo "FAIL  HTTP $HTTP_CODE" >&2
    echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY" >&2
    exit 1
fi

echo "Submitted. Manager response:"
echo "$BODY" | python3 -m json.tool 2>/dev/null || echo "$BODY"
echo ""

if [[ "$NO_WAIT" == "true" ]]; then
    echo "Proof submitted; not waiting (--no-wait). Poll with:"
    echo "  curl $MANAGER_URL/proof_state/$PROOF_UUID"
    # The input is fully uploaded to the manager/workers by now, so local temps
    # can be cleaned normally by the EXIT trap.
    exit 0
fi

# ─── Poll until terminal ────────────────────────────────────────────────────

START_TS=$(date +%s)
while true; do
    NOW=$(date +%s)
    ELAPSED=$((NOW - START_TS))
    if [[ $ELAPSED -ge $PROOF_TIMEOUT ]]; then
        echo "" >&2
        echo "TIMEOUT after ${PROOF_TIMEOUT}s" >&2
        exit 1
    fi

    STATE=$(curl -sf "$MANAGER_URL/proof_state/$PROOF_UUID" 2>/dev/null || echo "")
    if [[ -z "$STATE" ]]; then
        printf "\r  [%4ds] waiting for manager state" "$ELAPSED" >&2
        sleep "$POLL_INTERVAL"
        continue
    fi

    STATUS=$(echo "$STATE" | python3 -c '
import json, sys
try:
    s = json.load(sys.stdin).get("status", "unknown")
    print(s if isinstance(s, str) else next(iter(s.keys())))
except Exception:
    print("unknown")
')

    case "$STATUS" in
        completed|failed|canceled)
            echo "" >&2
            echo ""
            echo "Final status: $STATUS"
            echo "$STATE" | python3 -m json.tool
            [[ "$STATUS" == "completed" ]] && exit 0 || exit 1
            ;;
        *)
            APP=$(echo "$STATE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("app_proofs_count",0))' 2>/dev/null || echo "?")
            LEAF=$(echo "$STATE" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("leaf_proofs_count",0))' 2>/dev/null || echo "?")
            SEGS=$(echo "$STATE" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("num_segments") or "?")' 2>/dev/null || echo "?")
            printf "\r  [%4ds] status=%s app=%s/%s leaf=%s" "$ELAPSED" "$STATUS" "$APP" "$SEGS" "$LEAF" >&2
            sleep "$POLL_INTERVAL"
            ;;
    esac
done
