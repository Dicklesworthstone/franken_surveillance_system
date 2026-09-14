#!/usr/bin/env bash
# scripts/e2e/cap_inspect.sh
# End-to-end integration test runner for CAP- DOCTOR0 inspection (fss-2h5zq.67).
# Conforms to CAP- structured JSON-lines logging specification.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SUITE_NAME="cap_inspect"
BEAD_ID="fss-2h5zq.67"

# Parse arguments: support --list, --only <step>, --only=<step>
PASS_THROUGH_ARGS=()
LIST_MODE=0
ONLY_STEP=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --list)
            LIST_MODE=1
            PASS_THROUGH_ARGS+=("$1")
            shift
            ;;
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

TARGETS=(
    "fss-object:spool_inspect_contract"
    "fss-publication:local_inspect_contract"
    "fss-ledger:durable_inspect_contract"
    "fss-reference:effect_journal_inspect_contract"
)

if [[ $LIST_MODE -eq 1 ]]; then
    for item in "${TARGETS[@]}"; do
        echo "${item##*:}"
    done
    exit 0
fi

# If scripts/e2e/lib.sh is present (fss-2h5zq.1 harness), use the shared runner.
if [[ -f "${SCRIPT_DIR}/lib.sh" ]]; then
    # shellcheck source=/dev/null
    source "${SCRIPT_DIR}/lib.sh"
    e2e_init "$SUITE_NAME" "$BEAD_ID" "${PASS_THROUGH_ARGS[@]}"
    for item in "${TARGETS[@]}"; do
        crate="${item%%:*}"
        target="${item##*:}"
        e2e_cargo_test "$crate" "$target"
    done
    e2e_summary
    exit 0
fi

# Standalone runner conforming to CAP- structured JSON-lines logging specification
LOG_DIR="${FSS_E2E_LOG_DIR:-${REPO_ROOT}/target/e2e-logs}/${SUITE_NAME}"
mkdir -p "$LOG_DIR"

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

# Write environment record
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
        "FSS_E2E_LOG_DIR": log_dir,
    }
}
with open(log_file, "w", encoding="utf-8") as f:
    f.write(json.dumps(rec) + "\n")
' "$LOG_FILE" "cap_inspect.sh" "$BEAD_ID" "$GIT_SHA" "$DIRTY" "$HOST_TRIPLE" "${FSS_BIN_DIR:-}" "$LOG_DIR"

ACCUM_FILE=$(mktemp "${LOG_DIR}/accum_XXXXXX.json")
echo '{"step_count":0,"fail_count":0,"failures":[],"skipped":[],"seen_steps":[]}' > "$ACCUM_FILE"

for item in "${TARGETS[@]}"; do
    crate="${item%%:*}"
    target="${item##*:}"

    if [[ -n "$ONLY_STEP" && "$ONLY_STEP" != "$target" ]]; then
        continue
    fi

    STDOUT_TMP=$(mktemp "${LOG_DIR}/stdout_XXXXXX")
    STDERR_TMP=$(mktemp "${LOG_DIR}/stderr_XXXXXX")

    TEST_EXIT=0
    RETRIES=0
    while true; do
        TEST_EXIT=0
        (
            cd "$REPO_ROOT"
            RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p "$crate" --test "$target" --locked --offline -- --nocapture
        ) > "$STDOUT_TMP" 2> "$STDERR_TMP" || TEST_EXIT=$?

        if [[ $TEST_EXIT -eq 103 && $RETRIES -lt 3 ]]; then
            RETRIES=$((RETRIES + 1))
            python3 -c 'import time; time.sleep(0.1)' 2>/dev/null || true
            continue
        fi
        break
    done

    python3 -c '
import datetime, json, re, sys
stdout_file, log_file, script, bead, test_exit_str, crate, target, accum_file = sys.argv[1:9]
test_exit = int(test_exit_str)
ansi_strip = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

with open(accum_file, "r", encoding="utf-8") as af:
    accum = json.load(af)

step_count = accum["step_count"]
fail_count = accum["fail_count"]
failures = accum["failures"]
skipped = accum["skipped"]
seen_steps = set(accum.get("seen_steps", []))

target_caplog_count = 0

with open(stdout_file, "r", encoding="utf-8", errors="replace") as sf, \
     open(log_file, "a", encoding="utf-8") as lf:
    for raw_line in sf:
        line = ansi_strip.sub("", raw_line).strip()
        if "CAPLOG " in line:
            idx = line.find("CAPLOG ")
            json_part = line[idx + 7:].strip()
            target_caplog_count += 1
            try:
                data = json.loads(json_part)
                if not isinstance(data, dict):
                    raise ValueError("CAPLOG payload is not a JSON object")
            except Exception as exc:
                fail_count += 1
                step_count += 1
                step_name = f"{target}:malformed_caplog"
                failures.append(step_name)
                rec = {
                    "ts": now_iso(),
                    "script": script,
                    "bead": bead,
                    "step": step_name,
                    "cmd": f"cargo test -p {crate} --test {target}",
                    "exit": 1,
                    "duration_ms": 1,
                    "expected": "valid json object",
                    "observed": f"unparseable json: {json_part[:200]}",
                    "digest": None,
                    "stdout_sha256": "",
                    "stdout_excerpt": line[:200],
                    "stderr_excerpt": "",
                    "verdict": "fail",
                    "repro": f"scripts/e2e/cap_inspect.sh --only {target}",
                }
                lf.write(json.dumps(rec) + "\n")
                continue

            if "step" not in data or data["step"] is None or not str(data["step"]).strip():
                fail_count += 1
                step_count += 1
                failures.append(f"{target}:missing_step")
                rec = {
                    "ts": now_iso(),
                    "script": script,
                    "bead": bead,
                    "step": f"{target}:missing_step",
                    "cmd": f"cargo test -p {crate} --test {target}",
                    "exit": 1,
                    "duration_ms": data.get("duration_ms", 1) if isinstance(data, dict) else 1,
                    "expected": "step key present",
                    "observed": "missing step key",
                    "digest": None,
                    "stdout_sha256": "",
                    "stdout_excerpt": line[:200],
                    "stderr_excerpt": "",
                    "verdict": "fail",
                    "repro": f"scripts/e2e/cap_inspect.sh --only {target}",
                }
                lf.write(json.dumps(rec) + "\n")
                continue

            step = str(data["step"]).strip()
            if step in seen_steps:
                fail_count += 1
                step_count += 1
                failures.append(f"{step}:duplicate_step")
                rec = {
                    "ts": now_iso(),
                    "script": script,
                    "bead": bead,
                    "step": step,
                    "cmd": f"cargo test -p {crate} --test {target} -- {step}",
                    "exit": 1,
                    "duration_ms": 1,
                    "expected": "unique step name",
                    "observed": f"duplicate step name: {step}",
                    "digest": None,
                    "stdout_sha256": "",
                    "stdout_excerpt": line[:200],
                    "stderr_excerpt": "",
                    "verdict": "fail",
                    "repro": f"scripts/e2e/cap_inspect.sh --only {target}",
                }
                lf.write(json.dumps(rec) + "\n")
                continue

            seen_steps.add(step)

            if "verdict" not in data or data["verdict"] is None:
                fail_count += 1
                step_count += 1
                failures.append(f"{step}:missing_verdict")
                rec = {
                    "ts": now_iso(),
                    "script": script,
                    "bead": bead,
                    "step": step,
                    "cmd": f"cargo test -p {crate} --test {target} -- {step}",
                    "exit": 1,
                    "duration_ms": data.get("duration_ms", 1),
                    "expected": "verdict key present",
                    "observed": "missing verdict key",
                    "digest": None,
                    "stdout_sha256": "",
                    "stdout_excerpt": line[:200],
                    "stderr_excerpt": "",
                    "verdict": "fail",
                    "repro": f"scripts/e2e/cap_inspect.sh --only {target}",
                }
                lf.write(json.dumps(rec) + "\n")
                continue

            verdict = data["verdict"]
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
                "cmd": f"cargo test -p {crate} --test {target} -- {step}",
                "exit": data.get("exit", 0),
                "duration_ms": data.get("duration_ms", 1),
                "expected": data.get("expected"),
                "observed": data.get("observed"),
                "digest": data.get("digest"),
                "stdout_sha256": "",
                "stdout_excerpt": "",
                "stderr_excerpt": "",
                "verdict": verdict,
                "repro": f"scripts/e2e/cap_inspect.sh --only {target}",
            }
            lf.write(json.dumps(rec) + "\n")

if test_exit != 0 and f"{target}:cargo_test_failed" not in failures:
    failures.append(f"{target}:cargo_test_failed")
if target_caplog_count == 0 and f"{target}:no_caplog_emitted" not in failures:
    failures.append(f"{target}:no_caplog_emitted")
    fail_count += 1

with open(accum_file, "w", encoding="utf-8") as af:
    json.dump({
        "step_count": step_count,
        "fail_count": fail_count,
        "failures": failures,
        "skipped": skipped,
        "seen_steps": list(seen_steps),
    }, af)
' "$STDOUT_TMP" "$LOG_FILE" "cap_inspect.sh" "$BEAD_ID" "$TEST_EXIT" "$crate" "$target" "$ACCUM_FILE"

    rm -f "$STDOUT_TMP" "$STDERR_TMP"
done

END_MS=$(python3 -c 'import time; print(int(time.time()*1000))')
DURATION_MS=$(( END_MS - START_MS ))

REPRO="scripts/e2e/cap_inspect.sh"
if [[ -n "$ONLY_STEP" ]]; then
    REPRO="scripts/e2e/cap_inspect.sh --only ${ONLY_STEP}"
fi

SUMMARY_VERDICT=$(python3 -c '
import json, sys
log_file, accum_file, duration_ms, repro = sys.argv[1:5]
with open(accum_file, "r", encoding="utf-8") as af:
    accum = json.load(af)

step_count = accum["step_count"]
fail_count = accum["fail_count"]
failures = accum["failures"]
skipped = accum["skipped"]

verdict = "pass"
if fail_count > 0 or step_count == 0 or (len(skipped) == step_count and step_count > 0):
    verdict = "fail"
if len(skipped) == step_count and step_count > 0 and "all_steps_skipped" not in failures:
    failures.append("all_steps_skipped")

summary = {
    "step": "summary",
    "verdict": verdict,
    "steps": step_count,
    "failures": failures,
    "skipped": skipped,
    "duration_ms": max(0, int(duration_ms)),
    "log_path": log_file,
    "repro": repro,
}
with open(log_file, "a", encoding="utf-8") as lf:
    lf.write(json.dumps(summary) + "\n")

print(verdict)
' "$LOG_FILE" "$ACCUM_FILE" "$DURATION_MS" "$REPRO")

TOTAL_STEPS=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["step_count"])' "$ACCUM_FILE")
FAIL_COUNT=$(python3 -c 'import json, sys; print(len(json.load(open(sys.argv[1]))["failures"]))' "$ACCUM_FILE")
rm -f "$ACCUM_FILE"

if [[ "$SUMMARY_VERDICT" == "pass" ]]; then
    echo "pass summary: ${TOTAL_STEPS} steps passed, 0 failures"
    exit 0
else
    echo "fail summary: ${FAIL_COUNT} failures in ${TOTAL_STEPS} steps" >&2
    exit 1
fi
