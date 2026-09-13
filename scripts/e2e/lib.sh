#!/usr/bin/env bash
# scripts/e2e/lib.sh
# Deterministic E2E test harness and structured JSON-lines logging library.
# Strictly conforms to the CAP- E2E harness specification (fss-2h5zq.1).

set -euo pipefail

# Determine library and repo directory
_E2E_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_E2E_REPO_ROOT="$(git -C "$_E2E_LIB_DIR" rev-parse --show-toplevel 2>/dev/null || pwd)"

# Global state
_E2E_INITIALIZED=0
_E2E_NAME=""
_E2E_BEAD=""
_E2E_SCRIPT_NAME="$(basename "$0")"
_E2E_SCRIPT_PATH="$0"
_E2E_START_MS=0
_E2E_LOG_DIR=""
_E2E_RUN_DIR=""
_E2E_LOG_FILE=""
_E2E_STEP_COUNT=0
_E2E_FAILURES=()
_E2E_SKIPPED=()
_E2E_TMPDIRS=()
_E2E_LIST=0
_E2E_ONLY=""
_E2E_SUMMARY_WRITTEN=0
_E2E_CAP_EXCEEDED=0

declare -A _E2E_STEP_EXIT=()
declare -A _E2E_STEP_STDOUT=()
declare -A _E2E_STEP_STDERR=()

# Max log file size: 10 MiB (10485760 bytes)
_E2E_MAX_LOG_BYTES=10485760
# Max excerpt size: 4 KiB (4096 bytes)
_E2E_MAX_EXCERPT_BYTES=4096

_e2e_now_ms() {
    local n
    n=$(date +%s%N 2>/dev/null) || true
    if [[ -n "$n" && "$n" =~ ^[0-9]+$ ]]; then
        echo $(( n / 1000000 ))
    else
        python3 -c 'import time; print(int(time.time() * 1000))'
    fi
}

_e2e_iso8601() {
    date -u +"%Y-%m-%dT%H:%M:%SZ"
}

_e2e_parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --list)
                _E2E_LIST=1
                shift
                ;;
            --only)
                if [[ $# -lt 2 ]]; then
                    echo "Error: --only requires a step pattern argument" >&2
                    exit 1
                fi
                _E2E_ONLY="$2"
                shift 2
                ;;
            --only=*)
                _E2E_ONLY="${1#*=}"
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
}

# Parse any args passed at source time
_e2e_parse_args "$@"

_e2e_step_matches_only() {
    local step="$1"
    if [[ -z "${_E2E_ONLY:-}" ]]; then
        return 0
    fi
    local IFS=','
    for pat in $_E2E_ONLY; do
        pat="$(echo "$pat" | xargs)"
        if [[ -n "$pat" && "$step" == $pat ]]; then
            return 0
        fi
    done
    return 1
}

# Append a line to the run log with 10 MiB cap enforcement
_e2e_append_log() {
    local line="$1"
    if [[ -z "${_E2E_LOG_FILE:-}" ]]; then
        return 0
    fi

    local cur_size=0
    if [[ -f "$_E2E_LOG_FILE" ]]; then
        cur_size=$(wc -c < "$_E2E_LOG_FILE" 2>/dev/null || echo 0)
    fi

    local line_bytes
    line_bytes=$(printf "%s\n" "$line" | wc -c)

    # Reserve 4096 bytes buffer for the closing summary record
    if (( cur_size + line_bytes > _E2E_MAX_LOG_BYTES - 4096 )); then
        if [[ "$_E2E_CAP_EXCEEDED" -eq 0 ]]; then
            _E2E_CAP_EXCEEDED=1
            _E2E_FAILURES+=("10 MiB log cap exceeded")
            echo "Error: 10 MiB log cap exceeded" >&2
            _e2e_write_summary_record "fail"
            exit 1
        fi
        return 1
    fi

    printf "%s\n" "$line" >> "$_E2E_LOG_FILE"
}

_e2e_redact_file() {
    local input_file="$1"
    python3 -c '
import sys, re

input_path = sys.argv[1]
secret_pat = re.compile(r"authorization|password|token|secret|cookie", re.IGNORECASE)
hex_pat = re.compile(r"[0-9a-fA-F]{65,}")
max_bytes = 4096

out_lines = []
total_bytes = 0
try:
    with open(input_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            if secret_pat.search(line):
                continue
            line = hex_pat.sub(lambda m: f"<{len(m.group(0))} hex chars>", line)
            out_lines.append(line)
            total_bytes += len(line.encode("utf-8"))
            if total_bytes >= max_bytes * 2:
                break
except Exception:
    pass

result = "".join(out_lines)
res_bytes = result.encode("utf-8")
if len(res_bytes) > max_bytes:
    result = res_bytes[:max_bytes].decode("utf-8", errors="ignore")

sys.stdout.write(result)
' "$input_file"
}

_e2e_sha256_file() {
    local input_file="$1"
    if [[ -f "$input_file" ]]; then
        sha256sum "$input_file" | cut -d' ' -f1
    else
        echo ""
    fi
}

e2e_init() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: e2e_init <name> <bead-id> [options...]" >&2
        exit 1
    fi

    _E2E_NAME="$1"
    _E2E_BEAD="$2"
    shift 2

    # Parse any additional arguments passed to e2e_init
    _e2e_parse_args "$@"

    _E2E_START_MS=$(_e2e_now_ms)
    _E2E_INITIALIZED=1
    _E2E_SUMMARY_WRITTEN=0
    _E2E_CAP_EXCEEDED=0
    _E2E_STEP_COUNT=0
    _E2E_FAILURES=()
    _E2E_SKIPPED=()
    _E2E_TMPDIRS=()

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        return 0
    fi

    _E2E_LOG_DIR="${FSS_E2E_LOG_DIR:-${_E2E_REPO_ROOT}/target/e2e-logs}"
    _E2E_RUN_DIR="${_E2E_LOG_DIR}/${_E2E_NAME}"
    mkdir -p "$_E2E_RUN_DIR"

    # Find next monotonic run_NNNN.log index
    local max_idx=0
    for f in "${_E2E_RUN_DIR}"/run_*.log; do
        if [[ -f "$f" ]]; then
            local base
            base="$(basename "$f" .log)"
            local idx_str="${base#run_}"
            idx_str="$((10#$idx_str))" 2>/dev/null || true
            if [[ "$idx_str" =~ ^[0-9]+$ ]] && (( idx_str > max_idx )); then
                max_idx=$idx_str
            fi
        fi
    done
    local next_idx=$((max_idx + 1))
    _E2E_LOG_FILE="${_E2E_RUN_DIR}/$(printf "run_%04d.log" "$next_idx")"

    # Gather environment details
    local git_sha
    git_sha="$(git -C "$_E2E_REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")"
    local dirty="false"
    if [[ -n "$(git -C "$_E2E_REPO_ROOT" status --porcelain 2>/dev/null)" ]]; then
        dirty="true"
    fi

    local host_triple
    host_triple="$(rustc -vV 2>/dev/null | grep '^host:' | cut -d' ' -f2 || true)"
    if [[ -z "$host_triple" ]]; then
        host_triple="$(uname -m)-unknown-linux-gnu"
    fi

    # Check for binaries in FSS_BIN_DIR or target/debug
    local bins_json="[]"
    if [[ -n "${FSS_BIN_DIR:-}" && -d "$FSS_BIN_DIR" ]]; then
        bins_json=$(python3 -c '
import os, sys, hashlib, json

bin_dir = sys.argv[1]
bins = []
if os.path.isdir(bin_dir):
    for fname in sorted(os.listdir(bin_dir)):
        p = os.path.join(bin_dir, fname)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            h = hashlib.sha256()
            with open(p, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            bins.append({"name": fname, "path": os.path.abspath(p), "sha256": h.hexdigest()})
print(json.dumps(bins))
' "$FSS_BIN_DIR")
    fi

    local env_json
    env_json=$(python3 -c '
import json, sys

script, bead, git_sha, dirty_str, host, bins_raw, bin_dir, log_dir = sys.argv[1:9]
rec = {
    "step": "env",
    "script": script,
    "bead": bead,
    "git_sha": git_sha,
    "dirty": dirty_str == "true",
    "host": host,
    "bins": json.loads(bins_raw),
    "fss_env": {
        "FSS_BIN_DIR": bin_dir,
        "FSS_E2E_LOG_DIR": log_dir
    }
}
print(json.dumps(rec))
' "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$git_sha" "$dirty" "$host_triple" "$bins_json" "${FSS_BIN_DIR:-}" "${FSS_E2E_LOG_DIR:-}")

    printf "%s\n" "$env_json" > "$_E2E_LOG_FILE"

    trap _e2e_trap_exit EXIT
}

_e2e_trap_exit() {
    local rc=$?
    if [[ "${_E2E_SUMMARY_WRITTEN:-0}" -eq 1 || "${_E2E_LIST:-0}" -eq 1 ]]; then
        return
    fi
    if [[ $rc -ne 0 ]]; then
        _E2E_FAILURES+=("unexpected_exit_${rc}")
    fi
    e2e_summary
}

e2e_step() {
    local step="$1"
    shift
    if [[ $# -gt 0 && "$1" == "--" ]]; then
        shift
    fi

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        echo "$step"
        return 0
    fi

    if ! _e2e_step_matches_only "$step"; then
        return 0
    fi

    _E2E_STEP_COUNT=$((_E2E_STEP_COUNT + 1))
    _E2E_LAST_STEP="$step"

    local stdout_file
    stdout_file=$(mktemp "${_E2E_RUN_DIR}/stdout_XXXXXX")
    local stderr_file
    stderr_file=$(mktemp "${_E2E_RUN_DIR}/stderr_XXXXXX")

    local start_ms
    start_ms=$(_e2e_now_ms)

    local cmd_exit=0
    "$@" > "$stdout_file" 2> "$stderr_file" || cmd_exit=$?

    local end_ms
    end_ms=$(_e2e_now_ms)
    local duration_ms=$(( end_ms - start_ms ))

    _E2E_STEP_EXIT["$step"]=$cmd_exit
    _E2E_STEP_STDOUT["$step"]="$stdout_file"
    _E2E_STEP_STDERR["$step"]="$stderr_file"

    local stdout_sha256
    stdout_sha256=$(_e2e_sha256_file "$stdout_file")
    local stdout_excerpt
    stdout_excerpt=$(_e2e_redact_file "$stdout_file")
    local stderr_excerpt
    stderr_excerpt=$(_e2e_redact_file "$stderr_file")

    local cmd_str="$*"
    local repro_cmd="${_E2E_SCRIPT_PATH} --only ${step}"
    local ts
    ts=$(_e2e_iso8601)

    local rec_json
    rec_json=$(python3 -c '
import json, sys

ts, script, bead, step, cmd, exit_code, duration_ms, stdout_sha256, stdout_excerpt, stderr_excerpt, repro = sys.argv[1:12]

rec = {
    "ts": ts,
    "script": script,
    "bead": bead,
    "step": step,
    "cmd": cmd,
    "exit": int(exit_code),
    "duration_ms": int(duration_ms),
    "expected": None,
    "observed": None,
    "digest": stdout_sha256 if stdout_sha256 else None,
    "stdout_sha256": stdout_sha256,
    "stdout_excerpt": stdout_excerpt,
    "stderr_excerpt": stderr_excerpt,
    "verdict": "ran",
    "repro": repro
}
print(json.dumps(rec))
' "$ts" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$step" "$cmd_str" "$cmd_exit" "$duration_ms" "$stdout_sha256" "$stdout_excerpt" "$stderr_excerpt" "$repro_cmd")

    _e2e_append_log "$rec_json"
    rm -f "$stdout_file" "$stderr_file"
}

e2e_expect_eq() {
    local step="$1"
    local expected="$2"
    local observed="$3"

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        return 0
    fi

    if ! _e2e_step_matches_only "$step"; then
        return 0
    fi

    local verdict="pass"
    if [[ "$expected" != "$observed" ]]; then
        verdict="fail"
        _E2E_FAILURES+=("$step")
    fi

    local ts
    ts=$(_e2e_iso8601)
    local repro_cmd="${_E2E_SCRIPT_PATH} --only ${step}"

    local rec_json
    rec_json=$(python3 -c '
import json, sys

ts, script, bead, step, expected_str, observed_str, verdict, repro = sys.argv[1:9]

def parse_val(s):
    try:
        return json.loads(s)
    except Exception:
        return s

rec = {
    "ts": ts,
    "script": script,
    "bead": bead,
    "step": step,
    "cmd": ["e2e_expect_eq", step, expected_str, observed_str],
    "exit": 0 if verdict == "pass" else 1,
    "duration_ms": 0,
    "expected": parse_val(expected_str),
    "observed": parse_val(observed_str),
    "digest": None,
    "stdout_sha256": "",
    "stdout_excerpt": "",
    "stderr_excerpt": "",
    "verdict": verdict,
    "repro": repro
}
print(json.dumps(rec))
' "$ts" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$step" "$expected" "$observed" "$verdict" "$repro_cmd")

    _e2e_append_log "$rec_json"
}

e2e_expect_exit() {
    local step="$1"
    local expected_code="$2"

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        return 0
    fi

    if ! _e2e_step_matches_only "$step"; then
        return 0
    fi

    local observed_code="${_E2E_STEP_EXIT["$step"]:-unknown}"
    local verdict="pass"
    if [[ "$observed_code" != "$expected_code" ]]; then
        verdict="fail"
        _E2E_FAILURES+=("$step")
    fi

    local ts
    ts=$(_e2e_iso8601)
    local repro_cmd="${_E2E_SCRIPT_PATH} --only ${step}"

    local rec_json
    rec_json=$(python3 -c '
import json, sys

ts, script, bead, step, expected_str, observed_str, verdict, repro = sys.argv[1:9]

try:
    expected_val = int(expected_str)
except Exception:
    expected_val = expected_str

try:
    observed_val = int(observed_str)
except Exception:
    observed_val = observed_str

rec = {
    "ts": ts,
    "script": script,
    "bead": bead,
    "step": step,
    "cmd": ["e2e_expect_exit", step, expected_str],
    "exit": 0 if verdict == "pass" else 1,
    "duration_ms": 0,
    "expected": expected_val,
    "observed": observed_val,
    "digest": None,
    "stdout_sha256": "",
    "stdout_excerpt": "",
    "stderr_excerpt": "",
    "verdict": verdict,
    "repro": repro
}
print(json.dumps(rec))
' "$ts" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$step" "$expected_code" "$observed_code" "$verdict" "$repro_cmd")

    _e2e_append_log "$rec_json"
}

e2e_expect_json_field() {
    local step="$1"
    local file_or_var="$2"
    local path="$3"
    local expected="$4"

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        return 0
    fi

    if ! _e2e_step_matches_only "$step"; then
        return 0
    fi

    local mode="var"
    if [[ -f "$file_or_var" ]]; then
        mode="file"
    fi

    local py_output
    local match_status=0
    py_output=$(python3 -c '
import json, sys, re

input_data = sys.argv[1]
path = sys.argv[2]
expected_str = sys.argv[3]
mode = sys.argv[4]

try:
    if mode == "file":
        with open(input_data, "r", encoding="utf-8") as f:
            data = json.load(f)
    else:
        data = json.loads(input_data)

    if path.startswith("."):
        path = path[1:]

    cur = data
    if path:
        parts = re.split(r"\.|(?=\[)", path)
        for p in parts:
            if not p:
                continue
            if p.startswith("[") and p.endswith("]"):
                idx = int(p[1:-1])
                cur = cur[idx]
            else:
                cur = cur[p]

    try:
        expected_val = json.loads(expected_str)
    except Exception:
        expected_val = expected_str

    matched = (cur == expected_val or str(cur) == expected_str)
    out = {
        "matched": matched,
        "observed": cur,
        "expected": expected_val
    }
    print(json.dumps(out))
    sys.exit(0 if matched else 1)
except Exception as e:
    out = {
        "matched": False,
        "observed": f"Error: {e}",
        "expected": expected_str
    }
    print(json.dumps(out))
    sys.exit(1)
' "$file_or_var" "$path" "$expected" "$mode") || match_status=$?

    local verdict="pass"
    if [[ $match_status -ne 0 ]]; then
        verdict="fail"
        _E2E_FAILURES+=("$step")
    fi

    local ts
    ts=$(_e2e_iso8601)
    local repro_cmd="${_E2E_SCRIPT_PATH} --only ${step}"

    local rec_json
    rec_json=$(python3 -c '
import json, sys

ts, script, bead, step, py_json_str, path, verdict, repro = sys.argv[1:9]
info = json.loads(py_json_str)

rec = {
    "ts": ts,
    "script": script,
    "bead": bead,
    "step": step,
    "cmd": ["e2e_expect_json_field", step, path],
    "exit": 0 if verdict == "pass" else 1,
    "duration_ms": 0,
    "expected": info.get("expected"),
    "observed": info.get("observed"),
    "digest": None,
    "stdout_sha256": "",
    "stdout_excerpt": "",
    "stderr_excerpt": "",
    "verdict": verdict,
    "repro": repro
}
print(json.dumps(rec))
' "$ts" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$step" "$py_output" "$path" "$verdict" "$repro_cmd")

    _e2e_append_log "$rec_json"
}

e2e_skip() {
    local step="$1"
    local reason="$2"

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        echo "$step"
        return 0
    fi

    if ! _e2e_step_matches_only "$step"; then
        return 0
    fi

    _E2E_STEP_COUNT=$((_E2E_STEP_COUNT + 1))
    local skip_entry
    skip_entry=$(python3 -c 'import json, sys; print(json.dumps({"step": sys.argv[1], "reason": sys.argv[2]}))' "$step" "$reason")
    _E2E_SKIPPED+=("$skip_entry")

    local ts
    ts=$(_e2e_iso8601)
    local repro_cmd="${_E2E_SCRIPT_PATH} --only ${step}"

    local rec_json
    rec_json=$(python3 -c '
import json, sys

ts, script, bead, step, reason, repro = sys.argv[1:7]
rec = {
    "ts": ts,
    "script": script,
    "bead": bead,
    "step": step,
    "cmd": ["skip", reason],
    "exit": 0,
    "duration_ms": 0,
    "expected": None,
    "observed": reason,
    "digest": None,
    "stdout_sha256": "",
    "stdout_excerpt": "",
    "stderr_excerpt": "",
    "verdict": "skip",
    "repro": repro
}
print(json.dumps(rec))
' "$ts" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$step" "$reason" "$repro_cmd")

    _e2e_append_log "$rec_json"
}

e2e_bin() {
    local name="$1"
    if [[ -n "${FSS_BIN_DIR:-}" && -x "${FSS_BIN_DIR}/${name}" ]]; then
        echo "${FSS_BIN_DIR}/${name}"
        return 0
    elif [[ -x "${_E2E_REPO_ROOT}/target/debug/${name}" ]]; then
        echo "${_E2E_REPO_ROOT}/target/debug/${name}"
        return 0
    elif [[ -x "${_E2E_REPO_ROOT}/target/release/${name}" ]]; then
        echo "${_E2E_REPO_ROOT}/target/release/${name}"
        return 0
    else
        echo "Binary '${name}' not found. Build it first via: RCH_REQUIRE_REMOTE=1 rch exec -- cargo build -p fss-cli --bins --locked --offline and set FSS_BIN_DIR" >&2
        return 1
    fi
}

e2e_tmpdir() {
    local base_dir="${_E2E_RUN_DIR:-${FSS_E2E_LOG_DIR:-${_E2E_REPO_ROOT}/target/e2e-logs}}"
    mkdir -p "$base_dir"
    local tmp
    tmp=$(mktemp -d "${base_dir}/tmp_XXXXXX")
    if [[ -n "${_E2E_RUN_DIR:-}" && -d "${_E2E_RUN_DIR}" ]]; then
        echo "$tmp" >> "${_E2E_RUN_DIR}/.tmpdirs"
    fi
    _E2E_TMPDIRS+=("$tmp")
    echo "$tmp"
}

e2e_cargo_test() {
    local crate="$1"
    local target="$2"
    local filter="${3:-}"

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        echo "$target"
        return 0
    fi

    if ! _e2e_step_matches_only "$target"; then
        return 0
    fi

    _E2E_STEP_COUNT=$((_E2E_STEP_COUNT + 1))
    local stdout_file
    stdout_file=$(mktemp "${_E2E_RUN_DIR:-/tmp}/cargo_test_stdout_XXXXXX")
    local stderr_file
    stderr_file=$(mktemp "${_E2E_RUN_DIR:-/tmp}/cargo_test_stderr_XXXXXX")

    local start_ms
    start_ms=$(_e2e_now_ms)

    local test_exit=0
    local cmd_args=(rch exec -- cargo test -p "$crate" --test "$target" --locked --offline -- --nocapture)
    if [[ -n "$filter" ]]; then
        cmd_args+=("$filter")
    fi

    (
        cd "$_E2E_REPO_ROOT"
        RCH_REQUIRE_REMOTE=1 "${cmd_args[@]}"
    ) > "$stdout_file" 2> "$stderr_file" || test_exit=$?

    local end_ms
    end_ms=$(_e2e_now_ms)
    local duration_ms=$(( end_ms - start_ms ))

    local repro_cmd="${_E2E_SCRIPT_PATH} --only ${target}"

    # Process stdout with python: strip ANSI, find CAPLOG lines, fail closed if missing or malformed
    local proc_res
    proc_res=$(python3 -c '
import sys, re, json

stdout_path, stderr_path, crate, target, test_exit, script, bead, duration_ms, repro = sys.argv[1:10]

ansi_re = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

with open(stdout_path, "r", encoding="utf-8", errors="replace") as f:
    raw_stdout = f.read()

clean_stdout = ansi_re.sub("", raw_stdout)
lines = clean_stdout.splitlines()

caplog_records = []
has_malformed = False

for line in lines:
    sline = line.strip()
    if not sline.startswith("CAPLOG "):
        continue
    payload = sline[7:].strip()
    try:
        data = json.loads(payload)
        if not isinstance(data, dict) or "step" not in data or "verdict" not in data:
            has_malformed = True
            break
        caplog_records.append(data)
    except Exception:
        has_malformed = True
        break

res = {
    "caplog_count": len(caplog_records),
    "has_malformed": has_malformed,
    "records": caplog_records
}
print(json.dumps(res))
' "$stdout_file" "$stderr_file" "$crate" "$target" "$test_exit" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$duration_ms" "$repro_cmd")

    local caplog_count
    caplog_count=$(python3 -c 'import json, sys; print(json.loads(sys.argv[1])["caplog_count"])' "$proc_res")
    local has_malformed
    has_malformed=$(python3 -c 'import json, sys; print("true" if json.loads(sys.argv[1])["has_malformed"] else "false")' "$proc_res")

    local stdout_sha256
    stdout_sha256=$(_e2e_sha256_file "$stdout_file")
    local stdout_excerpt
    stdout_excerpt=$(_e2e_redact_file "$stdout_file")
    local stderr_excerpt
    stderr_excerpt=$(_e2e_redact_file "$stderr_file")
    local ts
    ts=$(_e2e_iso8601)

    if [[ "$test_exit" -ne 0 || "$caplog_count" -eq 0 || "$has_malformed" == "true" ]]; then
        _E2E_FAILURES+=("$target")
        local fail_reason="cargo test failed (exit ${test_exit})"
        if [[ "$has_malformed" == "true" ]]; then
            fail_reason="malformed CAPLOG line observed"
        elif [[ "$caplog_count" -eq 0 ]]; then
            fail_reason="no CAPLOG line observed"
        fi

        local rec_json
        rec_json=$(python3 -c '
import json, sys

ts, script, bead, target, fail_reason, test_exit, duration_ms, stdout_sha256, stdout_excerpt, stderr_excerpt, repro = sys.argv[1:12]

rec = {
    "ts": ts,
    "script": script,
    "bead": bead,
    "step": target,
    "cmd": f"cargo test -p {target}",
    "exit": int(test_exit),
    "duration_ms": int(duration_ms),
    "expected": "valid CAPLOG line and exit 0",
    "observed": fail_reason,
    "digest": stdout_sha256 if stdout_sha256 else None,
    "stdout_sha256": stdout_sha256,
    "stdout_excerpt": stdout_excerpt,
    "stderr_excerpt": stderr_excerpt,
    "verdict": "fail",
    "repro": repro
}
print(json.dumps(rec))
' "$ts" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$target" "$fail_reason" "$test_exit" "$duration_ms" "$stdout_sha256" "$stdout_excerpt" "$stderr_excerpt" "$repro_cmd")
        _e2e_append_log "$rec_json"
    else
        # Ingest each CAPLOG record
        python3 -c '
import json, sys

proc_res = json.loads(sys.argv[1])
ts, script, bead, target, duration_ms, stdout_sha256, stdout_excerpt, stderr_excerpt, repro = sys.argv[2:11]

for item in proc_res["records"]:
    step_name = item.get("step", target)
    rec = {
        "ts": item.get("ts", ts),
        "script": item.get("script", script),
        "bead": item.get("bead", bead),
        "step": step_name,
        "cmd": item.get("cmd", f"cargo test -p {target}"),
        "exit": int(item.get("exit", 0)),
        "duration_ms": int(item.get("duration_ms", duration_ms)),
        "expected": item.get("expected", None),
        "observed": item.get("observed", None),
        "digest": item.get("digest", stdout_sha256 if stdout_sha256 else None),
        "stdout_sha256": item.get("stdout_sha256", stdout_sha256),
        "stdout_excerpt": item.get("stdout_excerpt", stdout_excerpt),
        "stderr_excerpt": item.get("stderr_excerpt", stderr_excerpt),
        "verdict": item.get("verdict", "pass"),
        "repro": item.get("repro", repro)
    }
    print(json.dumps(rec))
' "$proc_res" "$ts" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$target" "$duration_ms" "$stdout_sha256" "$stdout_excerpt" "$stderr_excerpt" "$repro_cmd" | while read -r line; do
            _e2e_append_log "$line"
            local v
            v=$(python3 -c 'import json, sys; print(json.loads(sys.argv[1])["verdict"])' "$line")
            if [[ "$v" == "fail" ]]; then
                local st
                st=$(python3 -c 'import json, sys; print(json.loads(sys.argv[1])["step"])' "$line")
                _E2E_FAILURES+=("$st")
            fi
        done
    fi

    rm -f "$stdout_file" "$stderr_file"
}

_e2e_write_summary_record() {
    local verdict="$1"
    local end_ms
    end_ms=$(_e2e_now_ms)
    local total_ms=$(( end_ms - _E2E_START_MS ))

    local failures_json="[]"
    if [[ ${#_E2E_FAILURES[@]} -gt 0 ]]; then
        failures_json=$(python3 -c 'import json, sys; print(json.dumps(sys.argv[1:]))' "${_E2E_FAILURES[@]}")
    fi

    local skipped_json="[]"
    if [[ ${#_E2E_SKIPPED[@]} -gt 0 ]]; then
        skipped_json=$(python3 -c 'import json, sys; print(json.dumps([json.loads(x) for x in sys.argv[1:]]))' "${_E2E_SKIPPED[@]}")
    fi

    local repro_cmd="${_E2E_SCRIPT_PATH}"
    if [[ "$verdict" == "fail" && ${#_E2E_FAILURES[@]} -gt 0 ]]; then
        local fail_list
        fail_list=$(IFS=','; echo "${_E2E_FAILURES[*]}")
        repro_cmd="${_E2E_SCRIPT_PATH} --only \"${fail_list}\""
    fi

    local summary_json
    summary_json=$(python3 -c '
import json, sys

verdict, steps, failures_raw, skipped_raw, total_ms, log_path, repro = sys.argv[1:8]
rec = {
    "step": "summary",
    "verdict": verdict,
    "steps": int(steps),
    "failures": json.loads(failures_raw),
    "skipped": json.loads(skipped_raw),
    "duration_ms": int(total_ms),
    "log_path": log_path,
    "repro": repro
}
print(json.dumps(rec))
' "$verdict" "$_E2E_STEP_COUNT" "$failures_json" "$skipped_json" "$total_ms" "${_E2E_LOG_FILE:-}" "$repro_cmd")

    if [[ -n "${_E2E_LOG_FILE:-}" ]]; then
        printf "%s\n" "$summary_json" >> "$_E2E_LOG_FILE"
    fi
}

e2e_summary() {
    if [[ "${_E2E_LIST:-0}" -eq 1 ]]; then
        exit 0
    fi

    if [[ "${_E2E_SUMMARY_WRITTEN:-0}" -eq 1 ]]; then
        return 0
    fi
    _E2E_SUMMARY_WRITTEN=1

    local verdict="pass"
    if [[ ${#_E2E_FAILURES[@]} -gt 0 || "${_E2E_CAP_EXCEEDED:-0}" -eq 1 ]]; then
        verdict="fail"
    fi

    _e2e_write_summary_record "$verdict"

    # Validate log file using validate_log.py
    if [[ -f "${_E2E_LOG_FILE:-}" ]]; then
        python3 "${_E2E_LIB_DIR}/validate_log.py" "$_E2E_LOG_FILE"
    fi

    # Handle temporary directories
    local all_tmpdirs=("${_E2E_TMPDIRS[@]}")
    if [[ -f "${_E2E_RUN_DIR:-}/.tmpdirs" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && all_tmpdirs+=("$line")
        done < "${_E2E_RUN_DIR}/.tmpdirs"
    fi

    if [[ "$verdict" == "pass" ]]; then
        for tmp in "${all_tmpdirs[@]}"; do
            rm -rf "$tmp"
        done
        rm -f "${_E2E_RUN_DIR:-}/.tmpdirs"
    else
        for tmp in "${all_tmpdirs[@]}"; do
            echo "Forensics: preserved temporary directory: $tmp" >&2
        done
    fi

    if [[ -n "${_E2E_LOG_FILE:-}" ]]; then
        echo "E2E Log: ${_E2E_LOG_FILE}"
    fi

    if [[ "$verdict" == "pass" ]]; then
        exit 0
    else
        exit 1
    fi
}
