#!/usr/bin/env bash
# scripts/e2e/cap_ingest_mjpeg.sh
# End-to-end integration test runner for CAP- INGEST MJPEG frame splitter (fss-2h5zq.22).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

# If scripts/e2e/lib.sh is present (fss-2h5zq.1 harness), use the shared runner.
if [[ -f "${SCRIPT_DIR}/lib.sh" ]]; then
    source "${SCRIPT_DIR}/lib.sh"
    e2e_init "ingest_mjpeg" "fss-2h5zq.22" "$@"
    e2e_cargo_test "fss-reference" "mjpeg_split_contract"
    e2e_summary
else
    # Standalone harness conforming to CAP- structured JSON-lines logging specification.
    # Operates reliably in isolation before fss-2h5zq.1 merges into this branch.
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
    TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    GIT_SHA=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")
    HOST_TRIPLE="$(uname -m)-$(uname -s)"

    # 1. Write environment record
    python3 -c '
import json, sys
log_file, ts, script, bead, git_sha, host, bin_dir, log_dir = sys.argv[1:9]
rec = {
    "step": "env",
    "script": script,
    "bead": bead,
    "git_sha": git_sha,
    "dirty": False,
    "host": host,
    "bins": [],
    "fss_env": {
        "FSS_BIN_DIR": bin_dir,
        "FSS_E2E_LOG_DIR": log_dir
    }
}
with open(log_file, "w", encoding="utf-8") as f:
    f.write(json.dumps(rec) + "\n")
' "$LOG_FILE" "$TS" "cap_ingest_mjpeg.sh" "$BEAD_ID" "$GIT_SHA" "$HOST_TRIPLE" "${FSS_BIN_DIR:-}" "${FSS_E2E_LOG_DIR:-}"

    # 2. Execute test companion via RCH with --nocapture (retrying on 103 up to 3 times)
    STDOUT_TMP=$(mktemp)
    TEST_EXIT=0
    RETRY_COUNT=0
    while true; do
        TEST_EXIT=0
        RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p fss-reference --test mjpeg_split_contract -- --nocapture > "$STDOUT_TMP" 2>&1 || TEST_EXIT=$?
        if [[ $TEST_EXIT -eq 103 && $RETRY_COUNT -lt 3 ]]; then
            RETRY_COUNT=$(( RETRY_COUNT + 1 ))
            sleep 5
            continue
        fi
        break
    done

    # Parse CAPLOG records from test output with ANSI stripping
    COUNTS=$(python3 -c '
import json, re, sys
stdout_file, log_file, ts, script, bead = sys.argv[1:6]
ansi_strip = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
caplog_pat = re.compile(r"CAPLOG\s+(\{.*\})")
step_count = 0
fail_count = 0
with open(stdout_file, "r", encoding="utf-8", errors="replace") as sf, \
     open(log_file, "a", encoding="utf-8") as lf:
    for raw_line in sf:
        line = ansi_strip.sub("", raw_line).strip()
        m = caplog_pat.search(line)
        if m:
            try:
                data = json.loads(m.group(1))
            except Exception:
                continue
            step = data.get("step", "unknown")
            verdict = data.get("verdict", "pass")
            step_count += 1
            if verdict != "pass":
                fail_count += 1
            rec = {
                "ts": ts,
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
print(f"{step_count} {fail_count}")
' "$STDOUT_TMP" "$LOG_FILE" "$TS" "cap_ingest_mjpeg.sh" "$BEAD_ID")

    read -r STEP_COUNT FAIL_COUNT <<< "$COUNTS"
    rm -f "$STDOUT_TMP"

    END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
    DURATION_MS=$(( END_MS - START_MS ))

    VERDICT="pass"
    if [[ $TEST_EXIT -ne 0 || $FAIL_COUNT -gt 0 || $STEP_COUNT -eq 0 ]]; then
        VERDICT="fail"
    fi

    # 3. Write summary record
    python3 -c '
import json, sys
log_file, verdict, steps, duration_ms, repro = sys.argv[1:6]
rec = {
    "step": "summary",
    "verdict": verdict,
    "steps": int(steps),
    "failures": [],
    "skipped": [],
    "duration_ms": max(0, int(duration_ms)),
    "log_path": log_file,
    "repro": repro
}
with open(log_file, "a", encoding="utf-8") as f:
    f.write(json.dumps(rec) + "\n")
' "$LOG_FILE" "$VERDICT" "$STEP_COUNT" "$DURATION_MS" "scripts/e2e/cap_ingest_mjpeg.sh"

    echo "E2E Log: ${LOG_FILE}"

    if [[ "$VERDICT" == "pass" ]]; then
        echo "pass summary: ${STEP_COUNT} steps passed, 0 failures"
        exit 0
    else
        echo "fail summary: ${FAIL_COUNT} steps failed (cargo exit ${TEST_EXIT})"
        exit 1
    fi
fi
