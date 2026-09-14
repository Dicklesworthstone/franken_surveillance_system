#!/usr/bin/env bash
# scripts/e2e/cap_ingest_mjpeg.sh
# End-to-end integration test runner for CAP- INGEST MJPEG frame splitter (fss-2h5zq.22).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# Parse arguments: support --only <step> or --only=<step>
ONLY_STEP=""
PASS_THROUGH_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --only)
            if [[ $# -lt 2 ]]; then
                echo "Error: --only requires a step argument" >&2
                exit 1
            fi
            ONLY_STEP="$2"
            PASS_THROUGH_ARGS+=("$1" "$2")
            shift 2
            ;;
        --only=*)
            ONLY_STEP="${1#--only=}"
            PASS_THROUGH_ARGS+=("$1")
            shift
            ;;
        *)
            PASS_THROUGH_ARGS+=("$1")
            shift
            ;;
    esac
done

# If scripts/e2e/lib.sh is present (fss-2h5zq.1 harness), use the shared runner.
if [[ -f "${SCRIPT_DIR}/lib.sh" ]]; then
    source "${SCRIPT_DIR}/lib.sh"
    e2e_init "ingest_mjpeg" "fss-2h5zq.22" "${PASS_THROUGH_ARGS[@]}"
    e2e_cargo_test "fss-reference" "mjpeg_split_contract"
    e2e_summary
else
    # Standalone harness conforming to CAP- structured JSON-lines logging specification.
    SUITE_NAME="ingest_mjpeg"
    BEAD_ID="fss-2h5zq.22"
    LOG_DIR="${FSS_E2E_LOG_DIR:-${REPO_ROOT}/target/e2e-logs}/${SUITE_NAME}"
    mkdir -p "$LOG_DIR"

    # Find next monotonic run log index
    MAX_IDX=0
    if [[ -d "$LOG_DIR" ]]; then
        for f in "${LOG_DIR}"/run_*.log; do
            if [[ -f "$f" ]]; then
                BN=$(basename "$f" .log)
                IDX_STR="${BN#run_}"
                if [[ "$IDX_STR" =~ ^[0-9]+$ ]]; then
                    IDX=$((10#$IDX_STR))
                    if (( IDX > MAX_IDX )); then
                        MAX_IDX=$IDX
                    fi
                fi
            fi
        done
    fi
    NEXT_IDX=$(( MAX_IDX + 1 ))
    LOG_FILE=$(printf "%s/run_%04d.log" "$LOG_DIR" "$NEXT_IDX")

    START_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
    GIT_SHA=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")
    HOST_TRIPLE="$(uname -m)-$(uname -s)"
    DIRTY="false"
    if [[ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]]; then
        DIRTY="true"
    fi

    # 1. Write environment record
    python3 -c '
import json, os, sys
log_file, script, bead, git_sha, dirty_str, host, bin_dir, log_dir = sys.argv[1:9]
dirty = (dirty_str.lower() == "true")
bins = []
if bin_dir and os.path.isdir(bin_dir):
    for name in sorted(os.listdir(bin_dir)):
        p = os.path.join(bin_dir, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            bins.append(name)
rec = {
    "step": "env",
    "script": script,
    "bead": bead,
    "git_sha": git_sha,
    "dirty": dirty,
    "host": host,
    "bins": bins,
    "fss_env": {
        "FSS_BIN_DIR": bin_dir,
        "FSS_E2E_LOG_DIR": log_dir
    }
}
with open(log_file, "w", encoding="utf-8") as f:
    f.write(json.dumps(rec) + "\n")
' "$LOG_FILE" "cap_ingest_mjpeg.sh" "$BEAD_ID" "$GIT_SHA" "$DIRTY" "$HOST_TRIPLE" "${FSS_BIN_DIR:-}" "${FSS_E2E_LOG_DIR:-}"

    # 2. Execute test companion via RCH with --nocapture (retrying on 103 up to 3 times)
    STDOUT_TMP=$(mktemp)
    TEST_EXIT=0
    RETRY_COUNT=0

    CARGO_TEST_ARGS=()
    if [[ -n "$ONLY_STEP" ]]; then
        CARGO_TEST_ARGS+=("$ONLY_STEP")
    fi
    CARGO_TEST_ARGS+=("--nocapture")

    while true; do
        TEST_EXIT=0
        RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p fss-reference --test mjpeg_split_contract --locked --offline -- "${CARGO_TEST_ARGS[@]}" > "$STDOUT_TMP" 2>&1 || TEST_EXIT=$?
        if [[ $TEST_EXIT -eq 103 && $RETRY_COUNT -lt 3 ]]; then
            RETRY_COUNT=$(( RETRY_COUNT + 1 ))
            sleep $(( RETRY_COUNT * 5 ))
            continue
        fi
        break
    done

    # Parse CAPLOG records from test output with ANSI stripping and robust error detection
    SUMMARY_JSON=$(python3 -c '
import datetime, json, re, sys
stdout_file, log_file, script, bead, test_exit_str = sys.argv[1:6]
test_exit = int(test_exit_str)
ansi_strip = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

step_count = 0
fail_count = 0
failures = []
skipped = []

with open(stdout_file, "r", encoding="utf-8", errors="replace") as sf, \
     open(log_file, "a", encoding="utf-8") as lf:
    for raw_line in sf:
        line = ansi_strip.sub("", raw_line).strip()
        if "CAPLOG " in line:
            idx = line.find("CAPLOG ")
            json_part = line[idx + 7:].strip()
            try:
                data = json.loads(json_part)
                if not isinstance(data, dict):
                    raise ValueError("CAPLOG payload is not a JSON object")
            except Exception as exc:
                fail_count += 1
                step_count += 1
                step_name = "malformed_caplog"
                failures.append(step_name)
                rec = {
                    "ts": now_iso(),
                    "script": script,
                    "bead": bead,
                    "step": step_name,
                    "cmd": "cargo test -p fss-reference --test mjpeg_split_contract",
                    "exit": 1,
                    "duration_ms": 1,
                    "expected": "valid json object",
                    "observed": f"unparseable json: {json_part[:200]}",
                    "digest": None,
                    "stdout_sha256": "",
                    "stdout_excerpt": line[:200],
                    "stderr_excerpt": "",
                    "verdict": "fail",
                    "repro": "scripts/e2e/cap_ingest_mjpeg.sh"
                }
                lf.write(json.dumps(rec) + "\n")
                continue

            step = data.get("step", "unknown")
            verdict = data.get("verdict", "pass")
            step_count += 1
            if verdict == "fail":
                fail_count += 1
                failures.append(step)
            elif verdict == "skip":
                skipped.append(step)
            elif verdict != "pass":
                fail_count += 1
                failures.append(step)

            rec = {
                "ts": now_iso(),
                "script": script,
                "bead": bead,
                "step": step,
                "cmd": f"cargo test -p fss-reference --test mjpeg_split_contract -- {step}",
                "exit": data.get("exit", 0),
                "duration_ms": data.get("duration_ms", 1),
                "expected": data.get("expected"),
                "observed": data.get("observed"),
                "digest": None,
                "stdout_sha256": "",
                "stdout_excerpt": "",
                "stderr_excerpt": "",
                "verdict": verdict,
                "repro": f"scripts/e2e/cap_ingest_mjpeg.sh --only {step}"
            }
            lf.write(json.dumps(rec) + "\n")

if test_exit != 0 and "cargo_test_failed" not in failures:
    failures.append("cargo_test_failed")
if step_count == 0 and "no_caplog_emitted" not in failures:
    failures.append("no_caplog_emitted")

print(json.dumps({
    "step_count": step_count,
    "fail_count": fail_count,
    "failures": failures,
    "skipped": skipped
}))
' "$STDOUT_TMP" "$LOG_FILE" "cap_ingest_mjpeg.sh" "$BEAD_ID" "$TEST_EXIT")

    rm -f "$STDOUT_TMP"

    END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
    DURATION_MS=$(( END_MS - START_MS ))

    REPRO="scripts/e2e/cap_ingest_mjpeg.sh"
    if [[ -n "$ONLY_STEP" ]]; then
        REPRO="scripts/e2e/cap_ingest_mjpeg.sh --only ${ONLY_STEP}"
    fi

    # 3. Write summary record and determine script verdict
    VERDICT=$(python3 -c '
import json, sys
log_file, summary_json_str, duration_ms, repro, test_exit_str = sys.argv[1:6]
test_exit = int(test_exit_str)
info = json.loads(summary_json_str)
step_count = info["step_count"]
fail_count = info["fail_count"]
failures = info["failures"]
skipped = info["skipped"]

verdict = "pass"
if test_exit != 0 or fail_count > 0 or step_count == 0:
    verdict = "fail"

rec = {
    "step": "summary",
    "verdict": verdict,
    "steps": step_count,
    "failures": failures,
    "skipped": skipped,
    "duration_ms": max(0, int(duration_ms)),
    "log_path": log_file,
    "repro": repro
}
with open(log_file, "a", encoding="utf-8") as f:
    f.write(json.dumps(rec) + "\n")
print(verdict)
' "$LOG_FILE" "$SUMMARY_JSON" "$DURATION_MS" "$REPRO" "$TEST_EXIT")

    echo "E2E Log: ${LOG_FILE}"

    STEP_COUNT=$(python3 -c 'import json, sys; print(json.loads(sys.argv[1])["step_count"])' "$SUMMARY_JSON")
    FAIL_COUNT=$(python3 -c 'import json, sys; print(json.loads(sys.argv[1])["fail_count"])' "$SUMMARY_JSON")

    if [[ "$VERDICT" == "pass" ]]; then
        echo "pass summary: ${STEP_COUNT} steps passed, 0 failures"
        exit 0
    else
        echo "fail summary: ${FAIL_COUNT} steps failed (cargo exit ${TEST_EXIT})"
        exit 1
    fi
fi
