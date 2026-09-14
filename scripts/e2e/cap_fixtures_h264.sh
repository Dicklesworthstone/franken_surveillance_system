#!/usr/bin/env bash
# scripts/e2e/cap_fixtures_h264.sh
# End-to-end verification for CAP- fixtures H.264/rtpdump (fss-2h5zq.4).
# Strictly conforms to the CAP- E2E harness specification and scripts/e2e/lib.sh.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null || pwd)"

SUITE_NAME="cap_fixtures_h264"
BEAD_ID="fss-2h5zq.4"

# Base fixture steps
FIXTURE_STEPS=(
    "clean_264"
    "clean_rtp"
    "loss_rtp"
    "reorder_rtp"
    "duplicate_rtp"
    "ssrc_reset_rtp"
    "truncated_last_record_rtp"
    "large_gap_rtp"
)

# Relative file paths for fixtures
declare -A FIXTURE_PATHS=(
    ["clean_264"]="tests/fixtures/media/h264/clean.264"
    ["clean_rtp"]="tests/fixtures/media/rtp/clean.rtp"
    ["loss_rtp"]="tests/fixtures/media/rtp/loss.rtp"
    ["reorder_rtp"]="tests/fixtures/media/rtp/reorder.rtp"
    ["duplicate_rtp"]="tests/fixtures/media/rtp/duplicate.rtp"
    ["ssrc_reset_rtp"]="tests/fixtures/media/rtp/ssrc_reset.rtp"
    ["truncated_last_record_rtp"]="tests/fixtures/media/rtp/truncated_last_record.rtp"
    ["large_gap_rtp"]="tests/fixtures/media/rtp/large_gap.rtp"
)

# All known valid steps (fixtures, ffprobe observations, and cargo test target)
ALL_VALID_STEPS=(
    "clean_264"
    "clean_rtp"
    "loss_rtp"
    "reorder_rtp"
    "duplicate_rtp"
    "ssrc_reset_rtp"
    "truncated_last_record_rtp"
    "large_gap_rtp"
    "ffprobe_clean_264"
    "ffprobe_clean_rtp"
    "ffprobe_loss_rtp"
    "ffprobe_reorder_rtp"
    "ffprobe_duplicate_rtp"
    "ffprobe_ssrc_reset_rtp"
    "ffprobe_truncated_last_record_rtp"
    "ffprobe_large_gap_rtp"
    "media_fixture_h264_contract"
)

verify_fixture() {
    local step="$1"
    python3 -B -c '
import sys, os, json, hashlib

repo_root = sys.argv[1]
step = sys.argv[2]

step_map = {
    "clean_264": ("tests/fixtures/media/h264/fixture_manifest.json", "tests/fixtures/media/h264/clean.264", "clean.264"),
    "clean_rtp": ("tests/fixtures/media/rtp/fixture_manifest.json", "tests/fixtures/media/rtp/clean.rtp", "clean.rtp"),
    "loss_rtp": ("tests/fixtures/media/rtp/fixture_manifest.json", "tests/fixtures/media/rtp/loss.rtp", "loss.rtp"),
    "reorder_rtp": ("tests/fixtures/media/rtp/fixture_manifest.json", "tests/fixtures/media/rtp/reorder.rtp", "reorder.rtp"),
    "duplicate_rtp": ("tests/fixtures/media/rtp/fixture_manifest.json", "tests/fixtures/media/rtp/duplicate.rtp", "duplicate.rtp"),
    "ssrc_reset_rtp": ("tests/fixtures/media/rtp/fixture_manifest.json", "tests/fixtures/media/rtp/ssrc_reset.rtp", "ssrc_reset.rtp"),
    "truncated_last_record_rtp": ("tests/fixtures/media/rtp/fixture_manifest.json", "tests/fixtures/media/rtp/truncated_last_record.rtp", "truncated_last_record.rtp"),
    "large_gap_rtp": ("tests/fixtures/media/rtp/fixture_manifest.json", "tests/fixtures/media/rtp/large_gap.rtp", "large_gap.rtp"),
}

if step not in step_map:
    sys.stderr.write(f"Error: unknown fixture step: {step}\n")
    sys.exit(1)

rel_man, rel_path, fname = step_map[step]
man_path = os.path.join(repo_root, rel_man)
fix_path = os.path.join(repo_root, rel_path)

if not os.path.isfile(man_path):
    sys.stderr.write(f"Error: manifest file not found: {rel_man}\n")
    sys.exit(1)

try:
    with open(man_path, "r", encoding="utf-8") as f:
        man = json.load(f)
except Exception as e:
    sys.stderr.write(f"Error: failed to parse manifest {rel_man}: {e}\n")
    sys.exit(1)

fixtures = man.get("fixtures", [])
man_dir = os.path.dirname(man_path)

# Verify every fixture listed in manifest exists on disk
for fix_entry in fixtures:
    name = fix_entry.get("name")
    if not name:
        sys.stderr.write(f"Error: fixture entry without name in {rel_man}\n")
        sys.exit(1)
    target = os.path.join(man_dir, name)
    if not os.path.isfile(target):
        sys.stderr.write(f"Error: manifest {rel_man} lists absent file: {name}\n")
        sys.exit(1)

# Find entry for this fixture
entry = next((item for item in fixtures if item.get("name") == fname), None)
if entry is None:
    sys.stderr.write(f"Error: fixture {fname} missing from manifest {rel_man}\n")
    sys.exit(1)

expected_sha = entry.get("sha256")
if not expected_sha:
    sys.stderr.write(f"Error: missing sha256 for {fname} in manifest\n")
    sys.exit(1)

if not os.path.isfile(fix_path):
    sys.stderr.write(f"Error: fixture file not found: {rel_path}\n")
    sys.exit(1)

if os.path.getsize(fix_path) == 0:
    sys.stderr.write(f"Error: fixture file is empty: {rel_path}\n")
    sys.exit(1)

with open(fix_path, "rb") as f:
    data = f.read()

actual_sha = hashlib.sha256(data).hexdigest()
if actual_sha != expected_sha:
    sys.stderr.write(f"Error: SHA-256 mismatch for {rel_path}: expected {expected_sha}, got {actual_sha}\n")
    sys.exit(1)

print(f"OK: {step} ({rel_path}) sha256={actual_sha}")
sys.exit(0)
' "$REPO_ROOT" "$step"
}

run_ffprobe() {
    local step="$1"
    local rel_path="${FIXTURE_PATHS[$step]:-}"
    if [[ -z "$rel_path" ]]; then
        echo "Error: unknown fixture step: $step" >&2
        return 1
    fi
    local full_path="${REPO_ROOT}/${rel_path}"
    if [[ ! -f "$full_path" ]]; then
        echo "Error: fixture file not found: $rel_path" >&2
        return 1
    fi
    ffprobe -v error -count_packets -show_packets -show_format -show_streams "$full_path"
}

# CLI Argument parsing
ONLY=""
LIST=0
args=("$@")
idx=0
while [[ $idx -lt ${#args[@]} ]]; do
    arg="${args[$idx]}"
    case "$arg" in
        --list)
            LIST=1
            idx=$((idx + 1))
            ;;
        --only=*)
            ONLY="${arg#*=}"
            idx=$((idx + 1))
            ;;
        --only)
            idx=$((idx + 1))
            if [[ $idx -ge ${#args[@]} ]]; then
                echo "Error: --only requires an argument" >&2
                exit 2
            fi
            ONLY="${args[$idx]}"
            idx=$((idx + 1))
            ;;
        *)
            idx=$((idx + 1))
            ;;
    esac
done

# If --only was specified, validate step name
if [[ -n "$ONLY" ]]; then
    found_valid=0
    for s in "${ALL_VALID_STEPS[@]}"; do
        if [[ "$s" == "$ONLY" ]]; then
            found_valid=1
            break
        fi
    done
    if [[ $found_valid -eq 0 ]]; then
        echo "Error: unknown step name: $ONLY" >&2
        exit 2
    fi
fi

if [[ "$LIST" -eq 1 ]]; then
    for s in "${ALL_VALID_STEPS[@]}"; do
        echo "$s"
    done
    exit 0
fi

# If shared lib.sh is present, use it
if [[ -f "${SCRIPT_DIR}/lib.sh" ]]; then
    source "${SCRIPT_DIR}/lib.sh"

    if [[ -n "$ONLY" && "$ONLY" == ffprobe_* ]]; then
        fixture_step="${ONLY#ffprobe_}"
        e2e_args=()
        for a in "$@"; do
            if [[ "$a" == "--only=$ONLY" ]]; then
                e2e_args+=("--only=${fixture_step},${ONLY}")
            elif [[ "$a" == "$ONLY" ]]; then
                e2e_args+=("${fixture_step},${ONLY}")
            else
                e2e_args+=("$a")
            fi
        done
        e2e_init "$SUITE_NAME" "$BEAD_ID" "${e2e_args[@]}"
    else
        e2e_init "$SUITE_NAME" "$BEAD_ID" "$@"
    fi

    for step in "${FIXTURE_STEPS[@]}"; do
        e2e_step "$step" -- verify_fixture "$step"
        e2e_expect_exit "$step" 0

        if command -v ffprobe >/dev/null 2>&1; then
            e2e_step "ffprobe_${step}" -- run_ffprobe "$step"
        else
            if type e2e_skip >/dev/null 2>&1; then
                e2e_skip "ffprobe_${step}" "ffprobe not found on PATH"
            fi
        fi
    done

    if type e2e_cargo_test >/dev/null 2>&1; then
        e2e_cargo_test "fss-reference" "media_fixture_h264_contract"
    fi

    e2e_summary
    exit $?
fi

# Standalone runner conforming strictly to CAP- E2E JSON-lines schema
# when lib.sh has not yet been merged onto HEAD.
if [[ "$ONLY" == "media_fixture_h264_contract" ]]; then
    echo "Error: lib.sh is required for e2e_cargo_test of media_fixture_h264_contract" >&2
    exit 1
fi

LOG_DIR="${FSS_E2E_LOG_DIR:-${REPO_ROOT}/target/e2e-logs}/${SUITE_NAME}"
mkdir -p "$LOG_DIR"

max_idx=0
for f in "${LOG_DIR}"/run_*.log; do
    if [[ -f "$f" ]]; then
        base="$(basename "$f" .log)"
        idx_str="${base#run_}"
        if [[ "$idx_str" =~ ^[0-9]+$ ]]; then
            num=$((10#$idx_str))
            if (( num > max_idx )); then max_idx=$num; fi
        fi
    fi
done
next_idx=$((max_idx + 1))
LOG_FILE="${LOG_DIR}/$(printf "run_%04d.log" "$next_idx")"

now_iso() { date -u +"%Y-%m-%dT%H:%M:%SZ"; }
now_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }

git_sha="$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")"
dirty="false"
if [[ -n "$(git -C "$REPO_ROOT" status --porcelain 2>/dev/null)" ]]; then dirty="true"; fi
host_triple="$(rustc -vV 2>/dev/null | grep "^host:" | cut -d" " -f2 || uname -m)"

# Write env record
python3 -c '
import json, sys
print(json.dumps({
    "step": "env",
    "script": "cap_fixtures_h264.sh",
    "bead": sys.argv[1],
    "git_sha": sys.argv[2],
    "dirty": sys.argv[3] == "true",
    "host": sys.argv[4],
    "bins": [],
    "fss_env": {"FSS_BIN_DIR": "", "FSS_E2E_LOG_DIR": sys.argv[5]}
}))
' "$BEAD_ID" "$git_sha" "$dirty" "$host_triple" "$LOG_DIR" > "$LOG_FILE"

failures=()
step_count=0
verification_step_count=0

for step in "${FIXTURE_STEPS[@]}"; do
    rel_path="${FIXTURE_PATHS[$step]}"
    full_path="${REPO_ROOT}/${rel_path}"

    # 1. Base fixture verification step
    run_this=0
    if [[ -z "$ONLY" || "$step" == "$ONLY" || "$ONLY" == "ffprobe_${step}" ]]; then
        run_this=1
    fi

    if [[ $run_this -eq 1 ]]; then
        step_count=$((step_count + 1))
        verification_step_count=$((verification_step_count + 1))
        t0=$(now_ms)
        ts=$(now_iso)

        stdout_tmp="$(mktemp)"
        stderr_tmp="$(mktemp)"
        rc=0
        verify_fixture "$step" > "$stdout_tmp" 2> "$stderr_tmp" || rc=$?
        t1=$(now_ms)
        dur=$(( t1 - t0 ))

        verdict="pass"
        if [[ $rc -ne 0 ]]; then
            verdict="fail"
            failures+=("$step")
        fi

        python3 -c '
import json, sys, os, hashlib

ts, script, bead, step, rc, dur, out_path, err_path, verdict, fix_path = sys.argv[1:11]
with open(out_path, "r", errors="ignore") as f:
    out_txt = f.read()[:4096]
with open(err_path, "r", errors="ignore") as f:
    err_txt = f.read()[:4096]

digest_val = None
if os.path.isfile(fix_path):
    with open(fix_path, "rb") as f:
        digest_val = hashlib.sha256(f.read()).hexdigest()

out_bytes = out_txt.encode("utf-8")
stdout_sha = hashlib.sha256(out_bytes).hexdigest()

rec = {
    "ts": ts,
    "script": script,
    "bead": bead,
    "step": step,
    "cmd": ["verify_fixture", step],
    "exit": int(rc),
    "duration_ms": int(dur),
    "expected": 0,
    "observed": int(rc),
    "digest": digest_val,
    "stdout_sha256": stdout_sha,
    "stdout_excerpt": out_txt,
    "stderr_excerpt": err_txt,
    "verdict": verdict,
    "repro": f"scripts/e2e/cap_fixtures_h264.sh --only {step}"
}
print(json.dumps(rec))
' "$ts" "cap_fixtures_h264.sh" "$BEAD_ID" "$step" "$rc" "$dur" "$stdout_tmp" "$stderr_tmp" "$verdict" "$full_path" >> "$LOG_FILE"

        rm -f "$stdout_tmp" "$stderr_tmp"
    fi

    # 2. ffprobe observation step
    ffprobe_step="ffprobe_${step}"
    run_ffprobe_this=0
    if [[ -z "$ONLY" || "$ONLY" == "$ffprobe_step" || "$ONLY" == "$step" ]]; then
        run_ffprobe_this=1
    fi

    if [[ $run_ffprobe_this -eq 1 ]]; then
        step_count=$((step_count + 1))
        t0=$(now_ms)
        ts=$(now_iso)

        if command -v ffprobe >/dev/null 2>&1; then
            stdout_tmp="$(mktemp)"
            stderr_tmp="$(mktemp)"
            rc=0
            run_ffprobe "$step" > "$stdout_tmp" 2> "$stderr_tmp" || rc=$?
            t1=$(now_ms)
            dur=$(( t1 - t0 ))

            python3 -c '
import json, sys, os, hashlib

ts, script, bead, step, rc, dur, out_path, err_path, fix_path = sys.argv[1:10]
with open(out_path, "r", errors="ignore") as f:
    out_txt = f.read()[:4096]
with open(err_path, "r", errors="ignore") as f:
    err_txt = f.read()[:4096]

digest_val = None
if os.path.isfile(fix_path):
    with open(fix_path, "rb") as f:
        digest_val = hashlib.sha256(f.read()).hexdigest()

out_bytes = out_txt.encode("utf-8")
stdout_sha = hashlib.sha256(out_bytes).hexdigest()

rc_int = int(rc)
verdict = "pass" if rc_int == 0 else "ran"

rec = {
    "ts": ts,
    "script": script,
    "bead": bead,
    "step": step,
    "cmd": ["ffprobe", "-v", "error", "-count_packets", "-show_packets", "-show_format", "-show_streams", fix_path],
    "exit": rc_int,
    "duration_ms": int(dur),
    "expected": 0,
    "observed": rc_int,
    "digest": digest_val,
    "stdout_sha256": stdout_sha,
    "stdout_excerpt": out_txt,
    "stderr_excerpt": err_txt,
    "verdict": verdict,
    "repro": f"scripts/e2e/cap_fixtures_h264.sh --only {step}"
}
print(json.dumps(rec))
' "$ts" "cap_fixtures_h264.sh" "$BEAD_ID" "$ffprobe_step" "$rc" "$dur" "$stdout_tmp" "$stderr_tmp" "$full_path" >> "$LOG_FILE"
            rm -f "$stdout_tmp" "$stderr_tmp"
        else
            python3 -c '
import json, sys

ts, script, bead, step = sys.argv[1:5]
rec = {
    "ts": ts,
    "script": script,
    "bead": bead,
    "step": step,
    "cmd": ["skip", "ffprobe not found on PATH"],
    "exit": 0,
    "duration_ms": 0,
    "expected": None,
    "observed": "ffprobe not found on PATH",
    "digest": None,
    "stdout_sha256": "",
    "stdout_excerpt": "",
    "stderr_excerpt": "",
    "verdict": "skip",
    "repro": f"scripts/e2e/cap_fixtures_h264.sh --only {step}"
}
print(json.dumps(rec))
' "$ts" "cap_fixtures_h264.sh" "$BEAD_ID" "$ffprobe_step" >> "$LOG_FILE"
        fi
    fi
done

# Write summary record
overall_verdict="pass"
if [[ ${#failures[@]} -gt 0 || $verification_step_count -eq 0 ]]; then
    overall_verdict="fail"
fi

failures_json="$(python3 -c "import json, sys; print(json.dumps(sys.argv[1:]))" "${failures[@]+"${failures[@]}"}")"

python3 -c '
import json, sys
print(json.dumps({
    "step": "summary",
    "verdict": sys.argv[1],
    "steps": int(sys.argv[2]),
    "failures": json.loads(sys.argv[3])
}))
' "$overall_verdict" "$step_count" "$failures_json" >> "$LOG_FILE"

cat "$LOG_FILE"

if [[ "$overall_verdict" == "pass" && $verification_step_count -gt 0 ]]; then
    exit 0
else
    exit 1
fi
