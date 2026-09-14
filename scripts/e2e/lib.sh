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
_E2E_LAST_STEP=""
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
declare -A _E2E_SEEN_STEPS=()

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
            -h|--help)
                echo "Usage: $0 [--list] [--only <pattern>]"
                exit 0
                ;;
            "")
                shift
                ;;
            *)
                echo "Error: unrecognized argument: $1" >&2
                exit 1
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
        pat="$(echo "$pat" | tr -d '\"'\'' ')"
        if [[ -n "$pat" ]]; then
            if [[ "$step" == $pat ]]; then
                return 0
            fi
            local base_pat="${pat%_exit*}"
            base_pat="${base_pat%_[0-9]*}"
            if [[ "$base_pat" != "$pat" && "$step" == "$base_pat" ]]; then
                return 0
            fi
            local base_step="${step%_exit*}"
            base_step="${base_step%_[0-9]*}"
            if [[ "$base_step" != "$step" && "$base_step" == "$pat" ]]; then
                return 0
            fi
            if [[ "$pat" == "${step}_"* ]]; then
                return 0
            fi
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
            local cap_step="${_E2E_LAST_STEP:-log_cap_exceeded}"
            _E2E_FAILURES+=("$cap_step")
            echo "Error: 10 MiB log cap exceeded" >&2
            e2e_summary
        fi
        return 1
    fi

    printf "%s\n" "$line" >> "$_E2E_LOG_FILE"
}

_e2e_redact_file() {
    local input_file="$1"
    python3 -c '
import os, sys, re

input_path = sys.argv[1]

# Collect known secret variable values from environment
secret_var_pat = re.compile(r"authorization|password|token|secret|cookie|pass|key", re.IGNORECASE)
env_secrets = []
for k, v in os.environ.items():
    if secret_var_pat.search(k):
        sv = v.strip()
        if len(sv) >= 4:
            env_secrets.append(sv)
env_secrets.sort(key=len, reverse=True)

# Known token shape patterns
token_patterns = [
    re.compile(r"ghp_[A-Za-z0-9_]{16,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"xox[bpa]-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.+/=]+", re.IGNORECASE),
    re.compile(r"""(?i)\b([A-Za-z0-9_]*(?:authorization|password|passwd|token|secret|cookie|api_key|apikey|mypass|privkey|secret_key|(?:(?<![a-zA-Z])pass)|(?:(?<![a-zA-Z])key))[A-Za-z0-9_]*)\s*[:=]\s*(?:\"[^\"]*\"|\x27[^\x27]*\x27|[^\s,;\x22\x27]+)"""),
]
hex_pat = re.compile(r"[0-9a-fA-F]{65,}")
max_bytes = 4096

out_lines = []
total_bytes = 0
try:
    with open(input_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            for s in env_secrets:
                if s in line:
                    line = line.replace(s, "<redacted>")
            for pat in token_patterns:
                line = pat.sub("<redacted>", line)
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

    # Validate suite name and bead id (no path traversal, alphanumeric/dashes/underscores)
    if [[ ! "$_E2E_NAME" =~ ^[A-Za-z0-9_.-]+$ ]] || [[ "$_E2E_NAME" == *".."* ]]; then
        echo "Error: invalid suite name '${_E2E_NAME}'" >&2
        exit 1
    fi
    if [[ ! "$_E2E_BEAD" =~ ^[A-Za-z0-9_.-]+$ ]] || [[ "$_E2E_BEAD" == *".."* ]]; then
        echo "Error: invalid bead id '${_E2E_BEAD}'" >&2
        exit 1
    fi

    # Parse any additional arguments passed to e2e_init
    _e2e_parse_args "$@"

    _E2E_START_MS=$(_e2e_now_ms)
    _E2E_INITIALIZED=1
    _E2E_SUMMARY_WRITTEN=0
    _E2E_CAP_EXCEEDED=0
    _E2E_STEP_COUNT=0
    _E2E_LAST_STEP=""
    _E2E_FAILURES=()
    _E2E_SKIPPED=()
    _E2E_TMPDIRS=()
    _E2E_SEEN_STEPS=()

    # Install early EXIT trap so any abort before log file creation fails closed
    trap _e2e_trap_exit EXIT

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        return 0
    fi

    _E2E_LOG_DIR="${FSS_E2E_LOG_DIR:-${_E2E_REPO_ROOT}/target/e2e-logs}"
    _E2E_RUN_DIR="${_E2E_LOG_DIR}/${_E2E_NAME}"
    mkdir -p "$_E2E_RUN_DIR"

    # Find next monotonic run_NNNN.log index, ignoring non-numeric names
    local max_idx=0
    if [[ -d "$_E2E_RUN_DIR" ]]; then
        for f in "${_E2E_RUN_DIR}"/run_*.log; do
            if [[ -f "$f" ]]; then
                local base
                base="$(basename "$f" .log)"
                local idx_str="${base#run_}"
                if [[ "$idx_str" =~ ^[0-9]+$ ]]; then
                    local num=$((10#$idx_str))
                    if (( num > max_idx )); then
                        max_idx=$num
                    fi
                fi
            fi
        done
    fi
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

    if [[ -z "${_E2E_LOG_FILE:-}" || ! -f "$_E2E_LOG_FILE" ]]; then
        echo "Error: failed to initialize E2E log file" >&2
        exit 1
    fi

    trap _e2e_trap_exit EXIT
}

_e2e_trap_exit() {
    local rc=$?
    if [[ "${_E2E_LIST:-0}" -eq 1 ]]; then
        return
    fi
    if [[ -z "${_E2E_LOG_FILE:-}" || ! -f "${_E2E_LOG_FILE:-}" ]]; then
        echo "Error: E2E uninitialized or log file not set (failing closed)" >&2
        exit 1
    fi
    if [[ "${_E2E_SUMMARY_WRITTEN:-0}" -eq 1 ]]; then
        return
    fi
    if [[ $rc -ne 0 ]]; then
        _E2E_FAILURES+=("${_E2E_LAST_STEP:-unexpected_exit}")
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

    local record_step="$step"
    local idx=1
    while [[ -n "${_E2E_SEEN_STEPS["$record_step"]:-}" ]]; do
        record_step="${step}_${idx}"
        idx=$((idx + 1))
    done
    _E2E_SEEN_STEPS["$record_step"]=1
    _E2E_STEP_COUNT=$((_E2E_STEP_COUNT + 1))
    _E2E_LAST_STEP="$record_step"

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
    _E2E_STEP_EXIT["$record_step"]=$cmd_exit
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
import os, json, sys, re

ts, script, bead, step, cmd, exit_code, duration_ms, stdout_sha256, stdout_excerpt, stderr_excerpt, repro = sys.argv[1:12]

secret_var_pat = re.compile(r"authorization|password|token|secret|cookie|pass|key", re.IGNORECASE)
env_secrets = []
for k, v in os.environ.items():
    if secret_var_pat.search(k):
        sv = v.strip()
        if len(sv) >= 4:
            env_secrets.append(sv)
env_secrets.sort(key=len, reverse=True)

token_patterns = [
    re.compile(r"ghp_[A-Za-z0-9_]{16,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"xox[bpa]-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.+/=]+", re.IGNORECASE),
    re.compile(r"""(?i)\b([A-Za-z0-9_]*(?:authorization|password|passwd|token|secret|cookie|api_key|apikey|mypass|privkey|secret_key|(?:(?<![a-zA-Z])pass)|(?:(?<![a-zA-Z])key))[A-Za-z0-9_]*)\s*[:=]\s*(?:\"[^\"]*\"|\x27[^\x27]*\x27|[^\s,;\x22\x27]+)"""),
]
hex_pat = re.compile(r"[0-9a-fA-F]{65,}")

def sanitize(s):
    if not isinstance(s, str):
        return s
    for sec in env_secrets:
        if sec in s:
            s = s.replace(sec, "<redacted>")
    for pat in token_patterns:
        s = pat.sub("<redacted>", s)
    s = hex_pat.sub(lambda m: f"<{len(m.group(0))} hex chars>", s)
    b = s.encode("utf-8")
    if len(b) > 4096:
        s = b[:4096].decode("utf-8", errors="ignore")
    return s

rec = {
    "ts": ts,
    "script": script,
    "bead": bead,
    "step": step,
    "cmd": sanitize(cmd),
    "exit": int(exit_code),
    "duration_ms": max(0, int(duration_ms)),
    "expected": None,
    "observed": None,
    "digest": stdout_sha256 if stdout_sha256 else None,
    "stdout_sha256": stdout_sha256,
    "stdout_excerpt": sanitize(stdout_excerpt),
    "stderr_excerpt": sanitize(stderr_excerpt),
    "verdict": "ran",
    "repro": sanitize(repro)
}
print(json.dumps(rec))
' "$ts" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$record_step" "$cmd_str" "$cmd_exit" "$duration_ms" "$stdout_sha256" "$stdout_excerpt" "$stderr_excerpt" "$repro_cmd")

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

    local record_step="$step"
    local idx=1
    while [[ -n "${_E2E_SEEN_STEPS["$record_step"]:-}" ]]; do
        record_step="${step}_${idx}"
        idx=$((idx + 1))
    done
    _E2E_SEEN_STEPS["$record_step"]=1
    _E2E_STEP_COUNT=$((_E2E_STEP_COUNT + 1))
    _E2E_LAST_STEP="$record_step"

    local verdict="pass"
    if [[ "$expected" != "$observed" ]]; then
        verdict="fail"
        _E2E_FAILURES+=("$record_step")
    fi

    local ts
    ts=$(_e2e_iso8601)
    local repro_cmd="${_E2E_SCRIPT_PATH} --only ${step}"

    local rec_json
    rec_json=$(python3 -c '
import os, json, sys, re

ts, script, bead, step, expected_str, observed_str, verdict, repro = sys.argv[1:9]

secret_var_pat = re.compile(r"authorization|password|token|secret|cookie|pass|key", re.IGNORECASE)
env_secrets = []
for k, v in os.environ.items():
    if secret_var_pat.search(k):
        sv = v.strip()
        if len(sv) >= 4:
            env_secrets.append(sv)
env_secrets.sort(key=len, reverse=True)

token_patterns = [
    re.compile(r"ghp_[A-Za-z0-9_]{16,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"xox[bpa]-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.+/=]+", re.IGNORECASE),
    re.compile(r"""(?i)\b([A-Za-z0-9_]*(?:authorization|password|passwd|token|secret|cookie|api_key|apikey|mypass|privkey|secret_key|(?:(?<![a-zA-Z])pass)|(?:(?<![a-zA-Z])key))[A-Za-z0-9_]*)\s*[:=]\s*(?:\"[^\"]*\"|\x27[^\x27]*\x27|[^\s,;\x22\x27]+)"""),
]
hex_pat = re.compile(r"[0-9a-fA-F]{65,}")

def sanitize(s):
    if not isinstance(s, str):
        return s
    for sec in env_secrets:
        if sec in s:
            s = s.replace(sec, "<redacted>")
    for pat in token_patterns:
        s = pat.sub("<redacted>", s)
    s = hex_pat.sub(lambda m: f"<{len(m.group(0))} hex chars>", s)
    b = s.encode("utf-8")
    if len(b) > 4096:
        s = b[:4096].decode("utf-8", errors="ignore")
    return s

def sanitize_data(data):
    if isinstance(data, str):
        return sanitize(data)
    elif isinstance(data, dict):
        return {sanitize(str(k)): sanitize_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_data(x) for x in data]
    return data

def parse_val(s):
    try:
        val = json.loads(s)
        return sanitize_data(val)
    except Exception:
        return sanitize(s)

rec = {
    "ts": ts,
    "script": script,
    "bead": bead,
    "step": step,
    "cmd": ["e2e_expect_eq", step, sanitize(expected_str), sanitize(observed_str)],
    "exit": 0 if verdict == "pass" else 1,
    "duration_ms": 0,
    "expected": parse_val(expected_str),
    "observed": parse_val(observed_str),
    "digest": None,
    "stdout_sha256": "",
    "stdout_excerpt": "",
    "stderr_excerpt": "",
    "verdict": verdict,
    "repro": sanitize(repro)
}
print(json.dumps(rec))
' "$ts" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$record_step" "$expected" "$observed" "$verdict" "$repro_cmd")

    _e2e_append_log "$rec_json"
}

e2e_expect_exit() {
    local step="$1"
    local expected_code="$2"

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        echo "$step"
        return 0
    fi

    if ! _e2e_step_matches_only "$step"; then
        return 0
    fi

    local observed_code="${_E2E_STEP_EXIT["$step"]:-}"
    local target_step="$step"
    if [[ -z "$observed_code" && "$step" == *_exit ]]; then
        target_step="${step%_exit}"
        observed_code="${_E2E_STEP_EXIT["$target_step"]:-unknown}"
    elif [[ -z "$observed_code" ]]; then
        observed_code="unknown"
    fi

    local record_step="$step"
    if [[ -n "${_E2E_SEEN_STEPS["$step"]:-}" ]]; then
        record_step="${step}_exit"
    fi
    local idx=1
    while [[ -n "${_E2E_SEEN_STEPS["$record_step"]:-}" ]]; do
        record_step="${step}_exit_${idx}"
        idx=$((idx + 1))
    done
    _E2E_SEEN_STEPS["$record_step"]=1
    _E2E_STEP_COUNT=$((_E2E_STEP_COUNT + 1))
    _E2E_LAST_STEP="$record_step"

    local verdict="pass"
    if [[ "$observed_code" != "$expected_code" ]]; then
        verdict="fail"
        _E2E_FAILURES+=("$record_step")
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
' "$ts" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$record_step" "$expected_code" "$observed_code" "$verdict" "$repro_cmd")

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
import os, json, sys, re

input_data = sys.argv[1]
path = sys.argv[2]
expected_str = sys.argv[3]
mode = sys.argv[4]

secret_var_pat = re.compile(r"authorization|password|token|secret|cookie|pass|key", re.IGNORECASE)
env_secrets = []
for k, v in os.environ.items():
    if secret_var_pat.search(k):
        sv = v.strip()
        if len(sv) >= 4:
            env_secrets.append(sv)
env_secrets.sort(key=len, reverse=True)

token_patterns = [
    re.compile(r"ghp_[A-Za-z0-9_]{16,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"xox[bpa]-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.+/=]+", re.IGNORECASE),
    re.compile(r"""(?i)\b([A-Za-z0-9_]*(?:authorization|password|passwd|token|secret|cookie|api_key|apikey|mypass|privkey|secret_key|(?:(?<![a-zA-Z])pass)|(?:(?<![a-zA-Z])key))[A-Za-z0-9_]*)\s*[:=]\s*(?:\"[^\"]*\"|\x27[^\x27]*\x27|[^\s,;\x22\x27]+)"""),
]
hex_pat = re.compile(r"[0-9a-fA-F]{65,}")

def sanitize(s):
    if not isinstance(s, str):
        return s
    for sec in env_secrets:
        if sec in s:
            s = s.replace(sec, "<redacted>")
    for pat in token_patterns:
        s = pat.sub("<redacted>", s)
    s = hex_pat.sub(lambda m: f"<{len(m.group(0))} hex chars>", s)
    b = s.encode("utf-8")
    if len(b) > 4096:
        s = b[:4096].decode("utf-8", errors="ignore")
    return s

def sanitize_data(data):
    if isinstance(data, str):
        return sanitize(data)
    elif isinstance(data, dict):
        return {sanitize(str(k)): sanitize_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_data(x) for x in data]
    return data

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

    # Strict type equality: "1" != 1, True != 1
    matched = (cur == expected_val and type(cur) is type(expected_val))
    out = {
        "matched": matched,
        "observed": sanitize_data(cur),
        "expected": sanitize_data(expected_val)
    }
    print(json.dumps(out))
    sys.exit(0 if matched else 1)
except Exception as e:
    out = {
        "matched": False,
        "observed": f"Error: {e}",
        "expected": sanitize(expected_str)
    }
    print(json.dumps(out))
    sys.exit(1)
' "$file_or_var" "$path" "$expected" "$mode") || match_status=$?

    local record_step="$step"
    local idx=1
    while [[ -n "${_E2E_SEEN_STEPS["$record_step"]:-}" ]]; do
        record_step="${step}_${idx}"
        idx=$((idx + 1))
    done
    _E2E_SEEN_STEPS["$record_step"]=1
    _E2E_STEP_COUNT=$((_E2E_STEP_COUNT + 1))
    _E2E_LAST_STEP="$record_step"

    local verdict="pass"
    if [[ $match_status -ne 0 ]]; then
        verdict="fail"
        _E2E_FAILURES+=("$record_step")
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
' "$ts" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$record_step" "$py_output" "$path" "$verdict" "$repro_cmd")

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

    local record_step="$step"
    local idx=1
    while [[ -n "${_E2E_SEEN_STEPS["$record_step"]:-}" ]]; do
        record_step="${step}_${idx}"
        idx=$((idx + 1))
    done
    _E2E_SEEN_STEPS["$record_step"]=1
    _E2E_STEP_COUNT=$((_E2E_STEP_COUNT + 1))
    _E2E_LAST_STEP="$record_step"

    local skip_entry
    skip_entry=$(python3 -c '
import os, sys, re, json

step, reason = sys.argv[1:3]
secret_var_pat = re.compile(r"authorization|password|token|secret|cookie|pass|key", re.IGNORECASE)
env_secrets = []
for k, v in os.environ.items():
    if secret_var_pat.search(k):
        sv = v.strip()
        if len(sv) >= 4:
            env_secrets.append(sv)
env_secrets.sort(key=len, reverse=True)

token_patterns = [
    re.compile(r"ghp_[A-Za-z0-9_]{16,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"xox[bpa]-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.+/=]+", re.IGNORECASE),
    re.compile(r"""(?i)\b([A-Za-z0-9_]*(?:authorization|password|passwd|token|secret|cookie|api_key|apikey|mypass|privkey|secret_key|(?:(?<![a-zA-Z])pass)|(?:(?<![a-zA-Z])key))[A-Za-z0-9_]*)\s*[:=]\s*(?:\"[^\"]*\"|\x27[^\x27]*\x27|[^\s,;\x22\x27]+)"""),
]
hex_pat = re.compile(r"[0-9a-fA-F]{65,}")

def sanitize(s):
    if not isinstance(s, str):
        return s
    for sec in env_secrets:
        if sec in s:
            s = s.replace(sec, "<redacted>")
    for pat in token_patterns:
        s = pat.sub("<redacted>", s)
    s = hex_pat.sub(lambda m: f"<{len(m.group(0))} hex chars>", s)
    b = s.encode("utf-8")
    if len(b) > 4096:
        s = b[:4096].decode("utf-8", errors="ignore")
    return s

print(json.dumps({"step": step, "reason": sanitize(reason)}))
' "$step" "$reason")
    _E2E_SKIPPED+=("$skip_entry")

    local ts
    ts=$(_e2e_iso8601)
    local repro_cmd="${_E2E_SCRIPT_PATH} --only ${step}"

    local rec_json
    rec_json=$(python3 -c '
import os, json, sys, re

ts, script, bead, step, reason, repro = sys.argv[1:7]
secret_var_pat = re.compile(r"authorization|password|token|secret|cookie|pass|key", re.IGNORECASE)
env_secrets = []
for k, v in os.environ.items():
    if secret_var_pat.search(k):
        sv = v.strip()
        if len(sv) >= 4:
            env_secrets.append(sv)
env_secrets.sort(key=len, reverse=True)

token_patterns = [
    re.compile(r"ghp_[A-Za-z0-9_]{16,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"xox[bpa]-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.+/=]+", re.IGNORECASE),
    re.compile(r"""(?i)\b([A-Za-z0-9_]*(?:authorization|password|passwd|token|secret|cookie|api_key|apikey|mypass|privkey|secret_key|(?:(?<![a-zA-Z])pass)|(?:(?<![a-zA-Z])key))[A-Za-z0-9_]*)\s*[:=]\s*(?:\"[^\"]*\"|\x27[^\x27]*\x27|[^\s,;\x22\x27]+)"""),
]
hex_pat = re.compile(r"[0-9a-fA-F]{65,}")

def sanitize(s):
    if not isinstance(s, str):
        return s
    for sec in env_secrets:
        if sec in s:
            s = s.replace(sec, "<redacted>")
    for pat in token_patterns:
        s = pat.sub("<redacted>", s)
    s = hex_pat.sub(lambda m: f"<{len(m.group(0))} hex chars>", s)
    b = s.encode("utf-8")
    if len(b) > 4096:
        s = b[:4096].decode("utf-8", errors="ignore")
    return s

rec = {
    "ts": ts,
    "script": script,
    "bead": bead,
    "step": step,
    "cmd": ["skip", sanitize(reason)],
    "exit": 0,
    "duration_ms": 0,
    "expected": None,
    "observed": sanitize(reason),
    "digest": None,
    "stdout_sha256": "",
    "stdout_excerpt": "",
    "stderr_excerpt": "",
    "verdict": "skip",
    "repro": sanitize(repro)
}
print(json.dumps(rec))
' "$ts" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$record_step" "$reason" "$repro_cmd")

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
    if [[ -n "${_E2E_LOG_FILE:-}" ]]; then
        echo "$tmp" >> "${_E2E_LOG_FILE}.tmpdirs"
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

    _E2E_LAST_STEP="$target"
    _E2E_SEEN_STEPS["$target"]=1

    if [[ -z "${_E2E_RUN_DIR:-}" || ! -d "$_E2E_RUN_DIR" ]]; then
        echo "Error: E2E uninitialized; _E2E_RUN_DIR is not set" >&2
        exit 1
    fi

    local stdout_file
    stdout_file=$(mktemp "${_E2E_RUN_DIR}/cargo_test_stdout_XXXXXX")
    local stderr_file
    stderr_file=$(mktemp "${_E2E_RUN_DIR}/cargo_test_stderr_XXXXXX")

    local start_ms
    start_ms=$(_e2e_now_ms)

    local test_exit=0
    local cmd_args=(rch exec -- cargo test -p "$crate" --test "$target" --locked --offline -- --nocapture)
    if [[ -n "$filter" ]]; then
        cmd_args+=("$filter")
    fi

    local cmd_display="RCH_REQUIRE_REMOTE=1 ${cmd_args[*]}"

    (
        cd "$_E2E_REPO_ROOT"
        RCH_REQUIRE_REMOTE=1 "${cmd_args[@]}"
    ) > "$stdout_file" 2> "$stderr_file" || test_exit=$?

    local end_ms
    end_ms=$(_e2e_now_ms)
    local duration_ms=$(( end_ms - start_ms ))

    local repro_cmd="${_E2E_SCRIPT_PATH} --only ${target}"
    local stdout_sha256
    stdout_sha256=$(_e2e_sha256_file "$stdout_file")
    local stdout_excerpt
    stdout_excerpt=$(_e2e_redact_file "$stdout_file")
    local stderr_excerpt
    stderr_excerpt=$(_e2e_redact_file "$stderr_file")
    local ts
    ts=$(_e2e_iso8601)

    # Ingest CAPLOG lines in current shell via process substitution
    while IFS= read -r line; do
        if [[ "$line" =~ ^__FAIL__:\ (.*)$ ]]; then
            _E2E_FAILURES+=("${BASH_REMATCH[1]}")
        elif [[ -n "$line" ]]; then
            _E2E_STEP_COUNT=$((_E2E_STEP_COUNT + 1))
            _e2e_append_log "$line"
        fi
    done < <(python3 -c '
import os, sys, re, json

stdout_path, stderr_path, crate, target, test_exit_str, script, bead, duration_ms_str, repro, cmd_display, stdout_sha256, stdout_excerpt, stderr_excerpt, ts = sys.argv[1:15]
test_exit = int(test_exit_str)
duration_ms = max(0, int(duration_ms_str))

secret_var_pat = re.compile(r"authorization|password|token|secret|cookie|pass|key", re.IGNORECASE)
env_secrets = []
for k, v in os.environ.items():
    if secret_var_pat.search(k):
        sv = v.strip()
        if len(sv) >= 4:
            env_secrets.append(sv)
env_secrets.sort(key=len, reverse=True)

token_patterns = [
    re.compile(r"ghp_[A-Za-z0-9_]{16,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"xox[bpa]-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.+/=]+", re.IGNORECASE),
    re.compile(r"""(?i)\b([A-Za-z0-9_]*(?:authorization|password|passwd|token|secret|cookie|api_key|apikey|mypass|privkey|secret_key|(?:(?<![a-zA-Z])pass)|(?:(?<![a-zA-Z])key))[A-Za-z0-9_]*)\s*[:=]\s*(?:\"[^\"]*\"|\x27[^\x27]*\x27|[^\s,;\x22\x27]+)"""),
]
hex_pat = re.compile(r"[0-9a-fA-F]{65,}")

def sanitize(s):
    if not isinstance(s, str):
        return s
    for sec in env_secrets:
        if sec in s:
            s = s.replace(sec, "<redacted>")
    for pat in token_patterns:
        s = pat.sub("<redacted>", s)
    s = hex_pat.sub(lambda m: f"<{len(m.group(0))} hex chars>", s)
    b = s.encode("utf-8")
    if len(b) > 4096:
        s = b[:4096].decode("utf-8", errors="ignore")
    return s

def sanitize_data(data):
    if isinstance(data, str):
        return sanitize(data)
    elif isinstance(data, dict):
        return {sanitize(str(k)): sanitize_data(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_data(x) for x in data]
    return data

ansi_re = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

with open(stdout_path, "r", encoding="utf-8", errors="replace") as f:
    raw_stdout = f.read()

clean_stdout = ansi_re.sub("", raw_stdout)
lines = clean_stdout.splitlines()

caplog_records = []
has_malformed = False

VALID_STEP_VERDICTS = {"ran", "pass", "fail", "skip"}

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
        if data["verdict"] not in VALID_STEP_VERDICTS:
            has_malformed = True
            break
        caplog_records.append(data)
    except Exception:
        has_malformed = True
        break

if test_exit != 0 or len(caplog_records) == 0 or has_malformed:
    fail_reason = f"cargo test failed (exit {test_exit})"
    if has_malformed:
        fail_reason = "malformed CAPLOG line observed"
    elif len(caplog_records) == 0:
        fail_reason = "no CAPLOG line observed"

    rec = {
        "ts": ts,
        "script": script,
        "bead": bead,
        "step": target,
        "cmd": sanitize(cmd_display),
        "exit": test_exit,
        "duration_ms": duration_ms,
        "expected": "valid CAPLOG line and exit 0",
        "observed": fail_reason,
        "digest": stdout_sha256 if stdout_sha256 else None,
        "stdout_sha256": stdout_sha256,
        "stdout_excerpt": sanitize(stdout_excerpt),
        "stderr_excerpt": sanitize(stderr_excerpt),
        "verdict": "fail",
        "repro": sanitize(repro)
    }
    print(json.dumps(rec))
    print(f"__FAIL__: {target}")
else:
    for item in caplog_records:
        st_name = item.get("step", target)
        v = item.get("verdict", "pass")
        rec = {
            "ts": item.get("ts", ts),
            "script": item.get("script", script),
            "bead": item.get("bead", bead),
            "step": st_name,
            "cmd": sanitize(item.get("cmd", cmd_display)),
            "exit": int(item.get("exit", 0)),
            "duration_ms": max(0, int(item.get("duration_ms", duration_ms))),
            "expected": sanitize_data(item.get("expected", None)),
            "observed": sanitize_data(item.get("observed", None)),
            "digest": item.get("digest", stdout_sha256 if stdout_sha256 else None),
            "stdout_sha256": item.get("stdout_sha256", stdout_sha256),
            "stdout_excerpt": sanitize(item.get("stdout_excerpt", stdout_excerpt)),
            "stderr_excerpt": sanitize(item.get("stderr_excerpt", stderr_excerpt)),
            "verdict": v,
            "repro": sanitize(item.get("repro", repro))
        }
        print(json.dumps(rec))
        if v == "fail":
            print(f"__FAIL__: {st_name}")
' "$stdout_file" "$stderr_file" "$crate" "$target" "$test_exit" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$duration_ms" "$repro_cmd" "$cmd_display" "$stdout_sha256" "$stdout_excerpt" "$stderr_excerpt" "$ts")

    rm -f "$stdout_file" "$stderr_file"
}

_e2e_write_summary_record() {
    _E2E_SUMMARY_WRITTEN=1
    local verdict="$1"
    local end_ms
    end_ms=$(_e2e_now_ms)
    local total_ms=$(( end_ms - _E2E_START_MS ))

    local unique_failures=()
    for f in "${_E2E_FAILURES[@]}"; do
        if [[ -n "$f" && ! " ${unique_failures[*]:-} " =~ " ${f} " ]]; then
            unique_failures+=("$f")
        fi
    done
    _E2E_FAILURES=("${unique_failures[@]}")

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
        local real_steps=()
        for f in "${_E2E_FAILURES[@]}"; do
            local rf="${f%_exit*}"
            rf="${rf%_[0-9]*}"
            if [[ -n "$rf" && ! " ${real_steps[*]:-} " =~ " ${rf} " ]]; then
                real_steps+=("$rf")
            fi
        done
        if [[ ${#real_steps[@]} -gt 0 ]]; then
            local fail_list
            fail_list=$(IFS=','; echo "${real_steps[*]}")
            repro_cmd="${_E2E_SCRIPT_PATH} --only ${fail_list}"
        fi
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
    "duration_ms": max(0, int(total_ms)),
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

    local verdict="pass"
    if [[ ${#_E2E_FAILURES[@]} -gt 0 || "${_E2E_CAP_EXCEEDED:-0}" -eq 1 ]]; then
        verdict="fail"
    fi

    # Handle temporary directories keyed per run file
    local raw_tmpdirs=("${_E2E_TMPDIRS[@]}")
    local tmpdirs_file="${_E2E_LOG_FILE:-}.tmpdirs"
    if [[ -n "${_E2E_LOG_FILE:-}" && -f "$tmpdirs_file" ]]; then
        while IFS= read -r line; do
            [[ -n "$line" ]] && raw_tmpdirs+=("$line")
        done < "$tmpdirs_file"
    fi
    local all_tmpdirs=()
    for tmp in "${raw_tmpdirs[@]}"; do
        if [[ -n "$tmp" && ! " ${all_tmpdirs[*]:-} " =~ " ${tmp} " ]]; then
            all_tmpdirs+=("$tmp")
        fi
    done

    if [[ "$verdict" == "fail" ]]; then
        for tmp in "${all_tmpdirs[@]}"; do
            echo "{\"event\":\"forensics_preserved\",\"tmpdir\":\"$tmp\"}" >&2
        done
    fi

    _e2e_write_summary_record "$verdict"

    # Validate log file using validate_log.py
    if [[ -f "${_E2E_LOG_FILE:-}" ]]; then
        python3 "${_E2E_LIB_DIR}/validate_log.py" "$_E2E_LOG_FILE"
    fi

    if [[ "$verdict" == "pass" ]]; then
        for tmp in "${all_tmpdirs[@]}"; do
            rm -rf "$tmp"
        done
        [[ -n "${_E2E_LOG_FILE:-}" ]] && rm -f "$tmpdirs_file"
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
