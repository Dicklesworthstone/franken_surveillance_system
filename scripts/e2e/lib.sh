#!/usr/bin/env bash
# scripts/e2e/lib.sh
# Shared E2E harness and structured JSON-lines logger for scripts/e2e/cap_*.sh (fss-2h5zq.1).
#
# Public API (sourced by cap_*.sh; names and semantics are a compatibility contract):
#   e2e_init <name> <bead-id> [--list] [--only <glob>[,<glob>...]]
#   e2e_step <step> [--] <cmd...>            records {verdict:"ran", exit, digests, excerpts}
#   e2e_expect_eq <step> <expected> <observed>
#   e2e_expect_exit <step> <code>            checks the exit code of an earlier e2e_step
#   e2e_expect_json_field <step> <file-or-json> <.path> <expected>
#   e2e_skip <step> <reason>                 verdict "skip"; listed in summary.skipped
#   e2e_cargo_test <crate> <test-target> [filter]
#                                            RCH_REQUIRE_REMOTE=1 rch exec -- cargo test ... --nocapture;
#                                            every stdout line `CAPLOG {json}` (ANSI stripped, at least
#                                            "step" and "verdict") becomes one step record
#   e2e_bin <name>, e2e_tmpdir, e2e_summary
#
# Log: ${FSS_E2E_LOG_DIR:-<repo>/target/e2e-logs}/<name>/run_NNNN.log, one JSON object per line:
# the env record first, then step records, then exactly one summary record. The summary is written
# only after the whole log, summary included, passes scripts/e2e/validate_log.py; a log that fails
# validation never carries a "pass" summary, and e2e_summary exits non-zero for it.
#
# Every string that reaches the log passes the same sanitize(): lines naming
# authorization|password|token|secret|cookie (any case) are dropped, then values of secret-named
# environment variables, token shapes, --password/-p arguments and URL credentials are redacted,
# hex blobs over 64 characters are replaced by their length, and the result is capped at 4 KiB.
# A step id that sanitize() would change is replaced by a salted redacted_<hash> id.
#
# --only selects steps by glob on the step name; CAPLOG steps are selected by their cargo test
# target name. The summary repro reruns exactly the failing steps (a failing CAPLOG step reruns its
# cargo target) and is written relative to the repository root.
#
# FSS_E2E_MAX_LOG_BYTES may LOWER the 10 MiB per-run cap (tests use it); it can never raise it.

set -euo pipefail

_E2E_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_E2E_REPO_ROOT="$(cd "${_E2E_LIB_DIR}/../.." && pwd)"

# Global state
_E2E_INITIALIZED=0
_E2E_NAME=""
_E2E_BEAD=""
_E2E_SCRIPT_NAME="$(basename "$0")"
_E2E_SCRIPT_PATH="$0"
_E2E_REPRO_BASE=""
_E2E_START_MS=0
_E2E_LOG_DIR=""
_E2E_RUN_DIR=""
_E2E_LOG_FILE=""
_E2E_STEP_COUNT=0
# Last record written; informational only. The EXIT trap never blames it.
_E2E_LAST_STEP=""
_E2E_FAILURES=()
_E2E_SKIPPED=()
_E2E_TMPDIRS=()
_E2E_LIST=0
_E2E_ONLY=""
_E2E_SUMMARY_WRITTEN=0
_E2E_CAP_EXCEEDED=0
_E2E_SUMMARY_BYTES=0
# Record name of the step running right now, and the step name that reruns it.
_E2E_CURRENT_RUNNING_STEP=""
_E2E_CURRENT_RUNNING_ORIGIN=""
_E2E_CLAIMED=""
_E2E_REC_VERDICT=""
_E2E_REC_ID=""
_E2E_REC_JSON=""
_E2E_REC_EXTRA=""

declare -A _E2E_STEP_EXIT=()
declare -A _E2E_SEEN_STEPS=()
declare -A _E2E_WRITTEN_IDS=()
declare -A _E2E_RECORD_ORIGIN=()
declare -A _E2E_STEP_TARGET=()

# Max log file size: 10 MiB (10485760 bytes)
_E2E_HARD_MAX_LOG_BYTES=10485760
_E2E_MAX_LOG_BYTES=$_E2E_HARD_MAX_LOG_BYTES
if [[ -n "${FSS_E2E_MAX_LOG_BYTES:-}" ]]; then
    if [[ ! "$FSS_E2E_MAX_LOG_BYTES" =~ ^[0-9]{1,9}$ ]] \
        || (( 10#$FSS_E2E_MAX_LOG_BYTES < 131072 || 10#$FSS_E2E_MAX_LOG_BYTES > _E2E_HARD_MAX_LOG_BYTES )); then
        echo "Error: FSS_E2E_MAX_LOG_BYTES must be an integer in [131072, ${_E2E_HARD_MAX_LOG_BYTES}]" >&2
        exit 1
    fi
    _E2E_MAX_LOG_BYTES=$((10#$FSS_E2E_MAX_LOG_BYTES))
fi
# Max excerpt size: 4 KiB (4096 bytes)
_E2E_MAX_EXCERPT_BYTES=4096
# Bytes always kept free for the summary record, plus a budget for what failures and skips add
# to it; together they keep the summary line under the validator's 64 KiB line cap.
_E2E_SUMMARY_RESERVE_BYTES=32768
_E2E_SUMMARY_BUDGET_BYTES=24576
_E2E_MAX_TMPDIRS=32

# The one Python engine behind every record. Record modes print "<verdict>\t<id>" and then the
# record JSON on one line (skip_record adds the summary.skipped entry as a third line).
IFS= read -r -d '' _E2E_PY <<'PYEOF' || true
import hashlib
import json
import math
import os
import re
import sys

max_bytes = 4096
LINE_LIMIT = 65536
CAPLOG_LINE_LIMIT = 1048576
MAX_RECORD_LINE_BYTES = 60000
SKIP_REASON_SUMMARY_BYTES = 256
VALID_STEP_VERDICTS = {"ran", "pass", "fail", "skip"}
RESERVED_STEPS = {"env", "summary"}

secret_var_pat = re.compile(r"authorization|password|token|secret|cookie|pass|key", re.IGNORECASE)
env_secrets = []
for k, v in os.environ.items():
    if secret_var_pat.search(k):
        sv = v.strip()
        if len(sv) >= 4:
            env_secrets.append(sv)
env_secrets.sort(key=len, reverse=True)

token_patterns = [
    re.compile(r"ghp_[A-Za-z0-9_]{12,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    re.compile(r"sk-[A-Za-z0-9_\-]{16,}"),
    re.compile(r"xox[bpa]-[A-Za-z0-9_\-]{4,}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"(?i)\b(?:Basic|Bearer)\s+[A-Za-z0-9_\-\.+/=]+"),
    re.compile(r"""(?i)\b([A-Za-z0-9_]*(?:authorization|password|passwd|token|secret|cookie|api_key|apikey|mypass|privkey|secret_key|(?:(?<![a-zA-Z])pass)|(?:(?<![a-zA-Z])key))[A-Za-z0-9_]*)\s*[:=]\s*(?:\"[^\"]*\"|\x27[^\x27]*\x27|[^\s,;\x22\x27]+)"""),
]
drop_line_pat = re.compile(r"authorization|password|token|secret|cookie", re.IGNORECASE)
hex_pat = re.compile(r"[0-9a-fA-F]{65,}")
secret_key_pat = re.compile(r"authorization|password|token|secret|cookie|api_key|apikey", re.IGNORECASE)
hex64 = re.compile(r"^[0-9a-fA-F]{64}$")
ansi_re = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def sanitize(s):
    if not isinstance(s, str):
        return s
    kept = []
    if s:
        for line in s.split("\n"):
            if drop_line_pat.search(line):
                continue
            kept.append(line)
    s = "\n".join(kept)
    for sec in env_secrets:
        if sec in s:
            s = s.replace(sec, "<redacted>")
    for pat in token_patterns:
        s = pat.sub("<redacted>", s)
    s = re.sub(r"(--password(?:=|\s+))\S+", r"\g<1><redacted>", s)
    s = re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:)[^/\s:@]+(@)", r"\g<1><redacted>\g<2>", s)
    s = re.sub(r"(?<!\S)-p\S+", "-p<redacted>", s)
    s = hex_pat.sub(lambda m: f"<{len(m.group(0))} hex chars>", s)
    b = s.encode("utf-8")
    if len(b) > 4096:
        s = b[:4096].decode("utf-8", errors="ignore")
    return s


def sanitize_data(data):
    if isinstance(data, str):
        return sanitize(data)
    elif isinstance(data, dict):
        out = {}
        for k, v in data.items():
            key = sanitize(str(k))
            if key != str(k) or not key or secret_key_pat.search(key) or key in out:
                key = f"<redacted key {len(out)}>"
                v = "<redacted>"
            out[key] = sanitize_data(v)
        return out
    elif isinstance(data, list):
        return [sanitize_data(x) for x in data]
    elif isinstance(data, float) and not math.isfinite(data):
        return "NaN" if math.isnan(data) else ("Infinity" if data > 0 else "-Infinity")
    return data


def read_bounded_line(f, limit):
    """One line of at most `limit` characters; an over-long line is consumed and returned as None."""
    line = f.readline(limit)
    if line and len(line) >= limit and not line.endswith("\n"):
        while True:
            rest = f.readline(limit)
            if not rest or rest.endswith("\n"):
                break
        return None
    return line


def redact_file(input_path):
    out_lines = []
    total_bytes = 0
    with open(input_path, "r", encoding="utf-8", errors="replace", newline="\n") as f:
        while total_bytes < max_bytes * 2:
            line = read_bounded_line(f, LINE_LIMIT)
            if line is None:
                line = "<over-long line omitted>\n"
            if not line:
                break
            if drop_line_pat.search(line):
                continue
            for s in env_secrets:
                if s in line:
                    line = line.replace(s, "<redacted>")
            for pat in token_patterns:
                line = pat.sub("<redacted>", line)
            line = re.sub(r"(--password(?:=|\s+))\S+", r"\g<1><redacted>", line)
            line = re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:)[^/\s:@]+(@)", r"\g<1><redacted>\g<2>", line)
            line = re.sub(r"(?<!\S)-p\S+", "-p<redacted>", line)
            line = hex_pat.sub(lambda m: f"<{len(m.group(0))} hex chars>", line)
            out_lines.append(line)
            total_bytes += len(line.encode("utf-8"))
    result = "".join(out_lines)
    res_bytes = result.encode("utf-8")
    if len(res_bytes) > max_bytes:
        result = res_bytes[:max_bytes].decode("utf-8", errors="ignore")
    return result


def excerpt_of(path):
    try:
        return redact_file(path)
    except OSError:
        return ""


def safe_int(val, default=0):
    if val is None or isinstance(val, bool):
        return default
    try:
        return int(val)
    except (ValueError, TypeError, OverflowError):
        return default


def plain_id(s):
    return (isinstance(s, str) and s not in RESERVED_STEPS and 0 < len(s.encode("utf-8")) <= 200
            and not any(ord(c) < 32 or ord(c) == 127 for c in s))


def redacted_id(raw):
    salt = os.environ.get("_E2E_ID_SALT", "")
    digest = hashlib.sha256((salt + "\0" + str(raw)).encode("utf-8", "replace")).hexdigest()
    return "redacted_" + digest[:16]


def sanitize_id(raw):
    raw = str(raw)
    s = sanitize(raw)
    if s != raw or not plain_id(s):
        return redacted_id(raw)
    return s


def unique_id(rid, taken):
    base, n = rid, 1
    while rid in taken:
        rid = f"{base}_{n}"
        n += 1
    taken.add(rid)
    return rid


def dumps(obj):
    return json.dumps(obj, allow_nan=False)


def fit_record(rec):
    """Serialize a record; oversized fields become a size marker so the line stays under the
    validator's 64 KiB per-line cap."""
    line = dumps(rec)
    for key in ("expected", "observed", "cmd", "stdout_excerpt", "stderr_excerpt", "repro", "ts",
                "script", "bead"):
        if len(line.encode("utf-8")) <= MAX_RECORD_LINE_BYTES:
            break
        if rec.get(key) not in (None, ""):
            size = len(dumps(rec[key]).encode("utf-8"))
            rec[key] = f"<omitted: {size} bytes over the record line cap>"
            line = dumps(rec)
    return line


def emit(verdict, rec, extra=None):
    sys.stdout.write(f"{verdict}\t{rec['step']}\n{fit_record(rec)}\n")
    if extra is not None:
        sys.stdout.write(dumps(extra) + "\n")


def emit_stream(verdict, rec, extra=None):
    """Streamed record for the CAPLOG ingester: "<verdict>\t<id>[\t<summary.skipped entry>]", then
    the record JSON. JSON escapes tabs and newlines, so the header stays one tab-separated line."""
    header = f"{verdict}\t{rec['step']}"
    if extra is not None:
        header += "\t" + dumps(extra)
    sys.stdout.write(f"{header}\n{fit_record(rec)}\n")


def skip_entry(rid, observed):
    reason = observed if isinstance(observed, str) else ("" if observed is None else dumps(observed))
    reason = reason.encode("utf-8")[:SKIP_REASON_SUMMARY_BYTES].decode("utf-8", errors="ignore")
    return {"step": rid, "reason": reason}


def base_record(ts, script, bead, rid):
    return {"ts": ts, "script": sanitize(script), "bead": sanitize(bead), "step": rid}


def check_fields(verdict, cmd, expected, observed, repro, exit_code=None):
    return {
        "cmd": cmd,
        "exit": (0 if verdict == "pass" else 1) if exit_code is None else exit_code,
        "duration_ms": 0,
        "expected": expected,
        "observed": observed,
        "digest": None,
        "stdout_sha256": "",
        "stdout_excerpt": "",
        "stderr_excerpt": "",
        "verdict": verdict,
        "repro": sanitize(repro),
    }


def mode_redact_file(a):
    sys.stdout.write(excerpt_of(a[0]))


def mode_env_record(a):
    script, bead, git_sha, dirty_str, host, bin_dir, log_dir = a
    bins = []
    if bin_dir and os.path.isdir(bin_dir):
        for fname in sorted(os.listdir(bin_dir)):
            p = os.path.join(bin_dir, fname)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                h = hashlib.sha256()
                with open(p, "rb") as f:
                    while chunk := f.read(65536):
                        h.update(chunk)
                bins.append({"name": sanitize(fname), "path": sanitize(os.path.abspath(p)),
                             "sha256": h.hexdigest()})
    rec = {
        "step": "env",
        "script": sanitize(script),
        "bead": sanitize(bead),
        "git_sha": git_sha,
        "dirty": dirty_str == "true",
        "host": host,
        "bins": bins,
        "fss_env": {"FSS_BIN_DIR": sanitize(bin_dir), "FSS_E2E_LOG_DIR": sanitize(log_dir)},
    }
    sys.stdout.write(dumps(rec) + "\n")


def mode_step_record(a):
    ts, script, bead, step, cmd, exit_code, duration_ms, sha, stdout_path, stderr_path, repro = a
    rid = sanitize_id(step)
    good_sha = sha if hex64.match(sha or "") else ""
    rec = base_record(ts, script, bead, rid)
    rec.update({
        "cmd": sanitize(cmd),
        "exit": safe_int(exit_code, 1),
        "duration_ms": max(0, safe_int(duration_ms, 0)),
        "expected": None,
        "observed": None,
        "digest": good_sha or None,
        "stdout_sha256": good_sha,
        "stdout_excerpt": excerpt_of(stdout_path),
        "stderr_excerpt": excerpt_of(stderr_path),
        "verdict": "ran",
        "repro": sanitize(repro),
    })
    emit("ran", rec)


def parse_val(s):
    try:
        val = json.loads(s)
    except ValueError:
        return sanitize(s)
    return sanitize_data(val)


def mode_eq_record(a):
    ts, script, bead, step, expected_str, observed_str, verdict, repro = a
    rid = sanitize_id(step)
    rec = base_record(ts, script, bead, rid)
    rec.update(check_fields(verdict, ["e2e_expect_eq", rid, sanitize(expected_str), sanitize(observed_str)],
                            parse_val(expected_str), parse_val(observed_str), repro))
    emit(verdict, rec)


def mode_exit_record(a):
    ts, script, bead, step, expected_str, observed_str, verdict, repro = a
    rid = sanitize_id(step)
    try:
        expected_val = int(expected_str)
    except ValueError:
        expected_val = sanitize(expected_str)
    try:
        observed_val = int(observed_str)
    except ValueError:
        observed_val = sanitize(observed_str)
    rec = base_record(ts, script, bead, rid)
    rec.update({
        "cmd": [sanitize(x) for x in ["e2e_expect_exit", step, str(expected_str)]],
        "exit": 0 if verdict == "pass" else 1,
        "duration_ms": 0,
        "expected": sanitize_data(expected_val),
        "observed": sanitize_data(observed_val),
        "digest": None,
        "stdout_sha256": "",
        "stdout_excerpt": "",
        "stderr_excerpt": "",
        "verdict": verdict,
        "repro": sanitize(repro),
    })
    emit(verdict, rec)


def mode_json_field_record(a):
    ts, script, bead, step, input_data, path, expected_str, input_mode, repro = a
    rid = sanitize_id(step)
    try:
        if input_mode == "file":
            with open(input_data, "r", encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = json.loads(input_data)
        walk = path[1:] if path.startswith(".") else path
        cur = data
        if walk:
            for p in re.split(r"\.|(?=\[)", walk):
                if not p:
                    continue
                if p.startswith("[") and p.endswith("]"):
                    cur = cur[int(p[1:-1])]
                else:
                    cur = cur[p]
        try:
            expected_val = json.loads(expected_str)
        except ValueError:
            expected_val = expected_str
        # Strict type equality: "1" != 1, True != 1, 1.0 != 1
        matched = (cur == expected_val and type(cur) is type(expected_val))
        observed = sanitize_data(cur)
        expected = sanitize_data(expected_val)
    except Exception as e:  # an evaluation error is a fail verdict, never a crash
        matched = False
        observed = sanitize(f"Error: {type(e).__name__}: {e}")
        expected = sanitize(expected_str)
    verdict = "pass" if matched else "fail"
    rec = base_record(ts, script, bead, rid)
    rec.update(check_fields(verdict, [sanitize(x) for x in ["e2e_expect_json_field", step, path]],
                            expected, observed, repro))
    emit(verdict, rec)


def mode_skip_record(a):
    ts, script, bead, step, reason, repro = a
    rid = sanitize_id(step)
    r = sanitize(reason)
    rec = base_record(ts, script, bead, rid)
    rec.update(check_fields("skip", ["skip", r], None, r, repro, exit_code=0))
    short = r.encode("utf-8")[:SKIP_REASON_SUMMARY_BYTES].decode("utf-8", errors="ignore")
    emit("skip", rec, extra={"step": rid, "reason": short})


def mode_fail_record(a):
    ts, script, bead, step, exit_code, expected, observed, repro = a
    rid = sanitize_id(step)
    code = safe_int(exit_code, 1)
    rec = base_record(ts, script, bead, rid)
    rec.update(check_fields("fail", "e2e_harness", sanitize(expected), sanitize(observed), repro,
                            exit_code=code if code != 0 else 1))
    emit("fail", rec)


def collect_caplog_payloads(stdout_path):
    """CAPLOG payloads of the captured cargo stdout. An unreadable capture raises: the ingester then
    exits non-zero and e2e_cargo_test fails the target through py_rc."""
    payloads = []
    with open(stdout_path, "r", encoding="utf-8", errors="replace", newline="\n") as f:
        while True:
            raw = f.readline(CAPLOG_LINE_LIMIT)
            if not raw:
                break
            overlong = len(raw) >= CAPLOG_LINE_LIMIT and not raw.endswith("\n")
            sline = ansi_re.sub("", raw).strip()
            if overlong:
                while True:
                    rest = f.readline(CAPLOG_LINE_LIMIT)
                    if not rest or rest.endswith("\n"):
                        break
                if "CAPLOG " in sline[:64]:
                    return payloads, "CAPLOG line over 1 MiB"
                continue
            if not sline.startswith("CAPLOG "):
                continue
            payloads.append(sline[7:].strip())
    return payloads, None


def _no_duplicate_keys(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError(f"duplicate key {k!r}")
        d[k] = v
    return d


def _str_or_str_list(v):
    return isinstance(v, str) or (isinstance(v, list) and all(isinstance(x, str) for x in v))


def parse_caplog(stdout_path):
    payloads, why = collect_caplog_payloads(stdout_path)
    has_malformed = why is not None
    caplog_records = []
    seen_caplog_steps = set()
    for payload in payloads:
        if has_malformed:
            break
        try:
            data = json.loads(payload, object_pairs_hook=_no_duplicate_keys)
        except ValueError:
            has_malformed, why = True, "invalid JSON"
            break
        if not isinstance(data, dict) or "step" not in data or "verdict" not in data:
            has_malformed, why = True, "not an object with step and verdict"
            break
        if not isinstance(data["verdict"], str):
            has_malformed, why = True, "non-string verdict"
            break
        if data["verdict"] not in VALID_STEP_VERDICTS:
            has_malformed = True
            why = "verdict outside ran|pass|fail|skip"
            break
        st = data["step"]
        if not isinstance(st, str) or not st or st in seen_caplog_steps or st in RESERVED_STEPS:
            has_malformed, why = True, "missing, duplicate or reserved step"
            break
        for key in ("ts", "script", "bead", "repro"):
            if key in data and not isinstance(data[key], str):
                has_malformed, why = True, f"non-string {key}"
        for key in ("stdout_excerpt", "stderr_excerpt"):
            if key in data and not _str_or_str_list(data[key]):
                has_malformed, why = True, f"{key} is not a string or a list of strings"
        if "cmd" in data and not isinstance(data["cmd"], (str, list)):
            has_malformed, why = True, "cmd is not a string or a list"
        sha = data.get("stdout_sha256", "")
        if not isinstance(sha, str) or (sha and not hex64.match(sha)):
            has_malformed, why = True, "stdout_sha256 is not 64 hex characters"
        if has_malformed:
            break
        seen_caplog_steps.add(st)
        caplog_records.append(data)
    return caplog_records, has_malformed, why


def mode_cargo_ingest(a):
    (stdout_path, stderr_path, crate, target, test_exit_str, script, bead, duration_ms_str,
     repro, cmd_display, ids_file, stdout_sha256, stdout_excerpt, stderr_excerpt, ts) = a
    test_exit = safe_int(test_exit_str, 1)
    duration_ms = max(0, safe_int(duration_ms_str, 0))
    with open(ids_file, "r", encoding="utf-8", errors="replace") as f:
        taken = {line.rstrip("\n") for line in f if line.strip()}
    good_sha = stdout_sha256 if hex64.match(stdout_sha256 or "") else ""
    stdout_excerpt = ansi_re.sub("", stdout_excerpt)
    stderr_excerpt = ansi_re.sub("", stderr_excerpt)
    caplog_records, has_malformed, why = parse_caplog(stdout_path)

    if not has_malformed:
        for item in caplog_records:
            raw_step = item["step"]
            st_name = sanitize(item.get("step", target))
            if st_name != raw_step or not plain_id(st_name):
                st_name = redacted_id(raw_step)
            st_name = unique_id(st_name, taken)
            v = item["verdict"]
            def_exit = 1 if v == "fail" else 0
            item_exit = safe_int(item.get("exit", def_exit), default=def_exit)
            item_duration = max(0, safe_int(item.get("duration_ms", duration_ms), default=duration_ms))

            raw_cmd = item.get("cmd", cmd_display)
            if isinstance(raw_cmd, list):
                cmd_val = [sanitize_data(x) for x in raw_cmd]
            else:
                cmd_val = sanitize(raw_cmd)

            raw_se = item.get("stdout_excerpt", stdout_excerpt)
            if isinstance(raw_se, list):
                raw_se = "\n".join(raw_se)
            raw_sde = item.get("stderr_excerpt", stderr_excerpt)
            if isinstance(raw_sde, list):
                raw_sde = "\n".join(raw_sde)

            raw_digest = item.get("digest")
            digest_val = None
            if isinstance(raw_digest, str) and hex64.match(raw_digest):
                digest_val = raw_digest
            if digest_val is None and good_sha:
                digest_val = good_sha

            rec = {
                "ts": sanitize(item.get("ts", ts)),
                "script": sanitize(item.get("script", script)),
                "bead": sanitize(item.get("bead", bead)),
                "step": st_name,
                "cmd": cmd_val,
                "exit": item_exit,
                "duration_ms": item_duration,
                "expected": sanitize_data(item.get("expected", None)),
                "observed": sanitize_data(item.get("observed", None)),
                "digest": digest_val,
                "stdout_sha256": item.get("stdout_sha256", good_sha) or good_sha,
                "stdout_excerpt": sanitize(raw_se),
                "stderr_excerpt": sanitize(raw_sde),
                "verdict": v,
                "repro": sanitize(item.get("repro", repro)),
            }
            emit_stream(v, rec, skip_entry(st_name, rec["observed"]) if v == "skip" else None)

    if test_exit != 0 or len(caplog_records) == 0 or has_malformed:
        reasons = []
        if has_malformed:
            reasons.append(f"malformed CAPLOG line observed: {why}")
        if test_exit != 0:
            reasons.append(f"cargo test failed (exit {test_exit})")
        if len(caplog_records) == 0 and not has_malformed:
            reasons.append("no CAPLOG line observed")
        fail_reason = "; ".join(reasons)
        rid = unique_id(sanitize_id(target), taken)
        rec = {
            "ts": ts,
            "script": sanitize(script),
            "bead": sanitize(bead),
            "step": rid,
            "cmd": sanitize(cmd_display),
            "exit": test_exit if test_exit != 0 else 1,
            "duration_ms": duration_ms,
            "expected": "valid CAPLOG line and exit 0",
            "observed": fail_reason,
            "digest": good_sha or None,
            "stdout_sha256": good_sha,
            "stdout_excerpt": sanitize(stdout_excerpt),
            "stderr_excerpt": sanitize(stderr_excerpt),
            "verdict": "fail",
            "repro": sanitize(repro),
        }
        emit_stream("fail", rec)


def mode_summary_record(a):
    verdict, steps, total_ms, log_path, repro = a[:5]
    rest = a[5:]
    lists = []
    for _ in range(3):
        n = int(rest[0])
        lists.append(rest[1:1 + n])
        rest = rest[1 + n:]
    failures, skipped_raw, kept = lists
    kept_tmpdirs_raw = dumps(kept if verdict == "fail" else [])
    rec = {
        "step": "summary",
        "verdict": verdict,
        "steps": int(steps),
        "failures": failures,
        "skipped": [json.loads(x) for x in skipped_raw],
        "duration_ms": max(0, int(total_ms)),
        "log_path": log_path,
        "repro": sanitize(repro),
        "preserved_tmpdirs": json.loads(kept_tmpdirs_raw)
    }
    sys.stdout.write(dumps(rec) + "\n")


MODES = {
    "redact_file": mode_redact_file,
    "env_record": mode_env_record,
    "step_record": mode_step_record,
    "eq_record": mode_eq_record,
    "exit_record": mode_exit_record,
    "json_field_record": mode_json_field_record,
    "skip_record": mode_skip_record,
    "fail_record": mode_fail_record,
    "cargo_ingest": mode_cargo_ingest,
    "summary_record": mode_summary_record,
}

if __name__ == "__main__":
    MODES[sys.argv[1]](sys.argv[2:])
PYEOF

_e2e_py() {
    python3 -c "$_E2E_PY" "$@"
}

_e2e_internal_error() {
    echo "Error: e2e harness internal failure: $*" >&2
    exit 70
}

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
                echo "Usage: $0 [--list] [--only <glob>[,<glob>...]]"
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

# --only: comma-separated globs matched against the step name (CAPLOG steps: the cargo target).
_e2e_step_matches_only() {
    local step="$1"
    if [[ -z "${_E2E_ONLY:-}" ]]; then
        return 0
    fi
    local pats=() pat
    IFS=',' read -r -a pats <<< "$_E2E_ONLY"
    for pat in "${pats[@]}"; do
        pat="${pat#"${pat%%[![:space:]]*}"}"
        pat="${pat%"${pat##*[![:space:]]}"}"
        # shellcheck disable=SC2053  # pat is a glob on purpose
        if [[ -n "$pat" && "$step" == $pat ]]; then
            return 0
        fi
    done
    return 1
}

_e2e_require_init() {
    if [[ "${_E2E_INITIALIZED:-0}" -ne 1 || -z "${_E2E_LOG_FILE:-}" || ! -f "${_E2E_LOG_FILE:-}" ]]; then
        echo "Error: call e2e_init <name> <bead-id> before ${1:-this function}" >&2
        exit 1
    fi
}

# True when the log already ends with a summary record (for instance one written by e2e_summary
# running in a subshell, whose flag never reaches this shell).
_e2e_log_has_summary() {
    [[ -n "${_E2E_LOG_FILE:-}" && -f "${_E2E_LOG_FILE:-}" ]] || return 1
    local last
    last=$(tail -n 1 "$_E2E_LOG_FILE" 2>/dev/null) || return 1
    [[ "$last" == '{"step": "summary"'* ]]
}

# Exit for a log that already carries its summary: never write a second one.
_e2e_exit_on_existing_summary() {
    local rc="$1"
    echo "Note: ${_E2E_LOG_FILE} already ends with a summary record (e2e_summary ran in a subshell); not writing a second summary" >&2
    if [[ "$rc" -ne 0 ]]; then
        exit "$rc"
    fi
    if [[ "$(tail -n 1 "$_E2E_LOG_FILE")" == '{"step": "summary", "verdict": "pass"'* ]]; then
        exit 0
    fi
    exit 1
}

# Append a line to the run log with 10 MiB cap enforcement
_e2e_append_log() {
    local line="$1"
    local step_id="${2:-}"
    local summary_extra="${3:-0}"
    if [[ -z "${_E2E_LOG_FILE:-}" ]]; then
        echo "Error: E2E log file not set; call e2e_init first" >&2
        exit 1
    fi
    if [[ "${_E2E_SUMMARY_WRITTEN:-0}" -eq 1 ]] || _e2e_log_has_summary; then
        echo "Error: refusing to append record '${step_id}' after the summary record of ${_E2E_LOG_FILE}" >&2
        exit 1
    fi

    local cur_size=0
    if [[ -f "$_E2E_LOG_FILE" ]]; then
        cur_size=$(wc -c < "$_E2E_LOG_FILE" 2>/dev/null || echo 0)
    fi

    local line_bytes
    line_bytes=$(printf "%s\n" "$line" | wc -c)

    # Keep room for the closing summary record, including what failures and skips add to it
    local projected=$(( cur_size + line_bytes + _E2E_SUMMARY_RESERVE_BYTES + _E2E_SUMMARY_BYTES + summary_extra ))
    if (( projected > _E2E_MAX_LOG_BYTES || _E2E_SUMMARY_BYTES + summary_extra > _E2E_SUMMARY_BUDGET_BYTES )); then
        if [[ "$_E2E_CAP_EXCEEDED" -eq 0 ]]; then
            _E2E_CAP_EXCEEDED=1
            echo "Error: E2E log cap reached (${_E2E_MAX_LOG_BYTES} bytes per run); record '${step_id}' was not written" >&2
            e2e_summary
        fi
        return 1
    fi

    printf "%s\n" "$line" >> "$_E2E_LOG_FILE"
    if [[ -n "$step_id" ]]; then
        _E2E_STEP_COUNT=$((_E2E_STEP_COUNT + 1))
        _E2E_LAST_STEP="$step_id"
        _E2E_WRITTEN_IDS["$step_id"]=1
        _E2E_SUMMARY_BYTES=$(( _E2E_SUMMARY_BYTES + summary_extra ))
    fi
}

# Split one engine output ("<verdict>\t<id>", record JSON, optional extra line).
_e2e_take_record() {
    local out="$1"
    local header="${out%%$'\n'*}"
    local rest="${out#*$'\n'}"
    if [[ "$header" != *$'\t'* || "$rest" == "$out" ]]; then
        _e2e_internal_error "malformed record output"
    fi
    _E2E_REC_VERDICT="${header%%$'\t'*}"
    _E2E_REC_ID="${header#*$'\t'}"
    _E2E_REC_JSON="${rest%%$'\n'*}"
    _E2E_REC_EXTRA=""
    if [[ "$rest" == *$'\n'* ]]; then
        _E2E_REC_EXTRA="${rest#*$'\n'}"
    fi
    if [[ -z "$_E2E_REC_ID" || "$_E2E_REC_JSON" != "{"* ]]; then
        _e2e_internal_error "malformed record output"
    fi
}

# Write the taken record; only once it is in the log, count its failure or skip.
_e2e_commit_record() {
    local origin="$1"
    local claimed="$2"
    local rid="$_E2E_REC_ID"
    local verdict="$_E2E_REC_VERDICT"
    local extra=0
    case "$verdict" in
        fail) extra=$(( 2 * (${#rid} + 8) )) ;;
        skip)
            if [[ "$_E2E_REC_EXTRA" != "{"* ]]; then
                _e2e_internal_error "skip record '${rid}' without its summary.skipped entry"
            fi
            extra=$(( ${#_E2E_REC_EXTRA} + 4 ))
            ;;
    esac
    _e2e_append_log "$_E2E_REC_JSON" "$rid" "$extra" || return 1
    if [[ -n "$origin" && "$rid" == "$claimed" ]]; then
        _E2E_RECORD_ORIGIN["$rid"]="$origin"
    fi
    case "$verdict" in
        fail) _E2E_FAILURES+=("$rid") ;;
        skip) _E2E_SKIPPED+=("$_E2E_REC_EXTRA") ;;
    esac
    return 0
}

# Claim a unique record name for <step> in _E2E_CLAIMED: <step>, <step>_1, ... or, for
# e2e_expect_exit on an already-used name, <step>_exit, <step>_exit_1, ...
_e2e_claim_name() {
    local step="$1"
    local exit_style="${2:-0}"
    case "$step" in
        ""|env|summary)
            echo "Error: invalid or reserved step name '${step}'" >&2
            exit 1
            ;;
    esac
    local record_step="$step"
    local idx=1
    if [[ "$exit_style" -eq 1 && -n "${_E2E_SEEN_STEPS["$step"]:-}${_E2E_WRITTEN_IDS["$step"]:-}" ]]; then
        record_step="${step}_exit"
    fi
    while [[ -n "${_E2E_SEEN_STEPS["$record_step"]:-}${_E2E_WRITTEN_IDS["$record_step"]:-}" ]]; do
        if [[ "$exit_style" -eq 1 ]]; then
            record_step="${step}_exit_${idx}"
        else
            record_step="${step}_${idx}"
        fi
        idx=$((idx + 1))
    done
    _E2E_SEEN_STEPS["$record_step"]=1
    _E2E_CLAIMED="$record_step"
}

_e2e_repro_for() {
    local step="$1"
    if [[ -z "$step" ]]; then
        printf '%s' "$_E2E_REPRO_BASE"
    else
        printf '%s --only %q' "$_E2E_REPRO_BASE" "$step"
    fi
}

_e2e_redact_file() {
    _e2e_py redact_file "$1"
}

_e2e_sha256_file() {
    local input_file="$1"
    if [[ -f "$input_file" ]]; then
        sha256sum "$input_file" | cut -d' ' -f1
    else
        echo ""
    fi
}

_e2e_host_triple() {
    local arch os
    arch="$(uname -m)"
    os="$(uname -s)"
    case "$os" in
        Linux) echo "${arch}-unknown-linux-gnu" ;;
        Darwin) echo "${arch}-apple-darwin" ;;
        *) echo "${arch}-unknown-$(printf '%s' "$os" | tr '[:upper:]' '[:lower:]')" ;;
    esac
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
    if [[ "$_E2E_NAME" == "." ]]; then
        echo "Error: invalid suite name '${_E2E_NAME}'" >&2
        exit 1
    fi
    if [[ ! "$_E2E_BEAD" =~ ^[A-Za-z0-9_.-]+$ ]] || [[ "$_E2E_BEAD" == *".."* ]] || [[ "$_E2E_BEAD" == "." ]]; then
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
    _E2E_SUMMARY_BYTES=0
    _E2E_LAST_STEP=""
    _E2E_CURRENT_RUNNING_STEP=""
    _E2E_CURRENT_RUNNING_ORIGIN=""
    _E2E_FAILURES=()
    _E2E_SKIPPED=()
    _E2E_TMPDIRS=()
    _E2E_STEP_EXIT=()
    _E2E_SEEN_STEPS=()
    _E2E_WRITTEN_IDS=()
    _E2E_RECORD_ORIGIN=()
    _E2E_STEP_TARGET=()
    # Per-run salt for redacted step ids (never logged)
    _E2E_ID_SALT="${SRANDOM:-$RANDOM}${SRANDOM:-$RANDOM}${SRANDOM:-$RANDOM}${SRANDOM:-$RANDOM}"
    export _E2E_ID_SALT

    # The repro command is relative to the repository root when the script lives in it.
    local script_abs
    script_abs="$(cd "$(dirname "$_E2E_SCRIPT_PATH")" 2>/dev/null && pwd)/$(basename "$_E2E_SCRIPT_PATH")" \
        || script_abs="$_E2E_SCRIPT_PATH"
    if [[ "$script_abs" == "$_E2E_REPO_ROOT"/* ]]; then
        script_abs="${script_abs#"$_E2E_REPO_ROOT"/}"
    fi
    _E2E_REPRO_BASE="$(printf '%q' "$script_abs")"

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
    # Create the run file exclusively, so two concurrent runs never share one log
    local next_idx=$((max_idx + 1))
    local attempts=0
    while :; do
        _E2E_LOG_FILE="${_E2E_RUN_DIR}/$(printf "run_%04d.log" "$next_idx")"
        if ( set -o noclobber; : > "$_E2E_LOG_FILE" ) 2>/dev/null; then
            break
        fi
        next_idx=$((next_idx + 1))
        attempts=$((attempts + 1))
        if (( attempts > 1000 )); then
            _E2E_LOG_FILE=""
            echo "Error: could not create a run log under ${_E2E_RUN_DIR}" >&2
            exit 1
        fi
    done

    # Gather environment details
    local git_sha
    git_sha="$(git -C "$_E2E_REPO_ROOT" rev-parse HEAD 2>/dev/null || echo "unknown")"
    local dirty="false"
    if [[ -n "$(git -C "$_E2E_REPO_ROOT" status --porcelain 2>/dev/null)" ]]; then
        dirty="true"
    fi

    local env_json
    env_json=$(_e2e_py env_record "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$git_sha" "$dirty" "$(_e2e_host_triple)" \
        "${FSS_BIN_DIR:-}" "${FSS_E2E_LOG_DIR:-}") || _e2e_internal_error "env record"
    printf "%s\n" "$env_json" > "$_E2E_LOG_FILE"

    if [[ -z "${_E2E_LOG_FILE:-}" || ! -s "$_E2E_LOG_FILE" ]]; then
        echo "Error: failed to initialize E2E log file" >&2
        exit 1
    fi

    trap _e2e_trap_exit EXIT
}

# Write a failing record for a step that could not finish (abnormal exit, ingester crash). The
# failure is counted only once the record is in the log.
_e2e_record_synthetic_fail() {
    local name="$1"
    local origin="$2"
    local code="$3"
    local expected="$4"
    local observed="$5"
    local base="$name"
    local n=1
    while [[ -n "${_E2E_WRITTEN_IDS["$name"]:-}" ]]; do
        name="${base}_${n}"
        n=$((n + 1))
    done
    local out
    out=$(_e2e_py fail_record "$(_e2e_iso8601)" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$name" "$code" \
        "$expected" "$observed" "$(_e2e_repro_for "$origin")") || return 1
    _e2e_take_record "$out"
    _E2E_SEEN_STEPS["$name"]=1
    _e2e_commit_record "$origin" "$name"
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
    if _e2e_log_has_summary; then
        _e2e_exit_on_existing_summary "$rc"
    fi
    if [[ $rc -ne 0 ]]; then
        local blamed_step="${_E2E_CURRENT_RUNNING_STEP:-${_E2E_SCRIPT_NAME}:exit}"
        local blamed_origin="${_E2E_CURRENT_RUNNING_ORIGIN:-}"
        local name="$blamed_step"
        if [[ -n "${_E2E_WRITTEN_IDS["$name"]:-}" ]]; then
            name="${blamed_step}:exit"
        fi
        _e2e_record_synthetic_fail "$name" "$blamed_origin" "$rc" "script completes and runs e2e_summary" \
            "script exited with status ${rc} while '${blamed_step}' was running" \
            || echo "Error: could not record the abnormal exit of '${blamed_step}'" >&2
    fi
    e2e_summary
}

_e2e_on_signal() {
    exit "$1"
}

# Install EXIT trap so any uninitialized exit fails closed; signals finalize through it.
trap _e2e_trap_exit EXIT
trap '_e2e_on_signal 129' HUP
trap '_e2e_on_signal 130' INT
trap '_e2e_on_signal 143' TERM

e2e_step() {
    if [[ $# -lt 1 ]]; then
        echo "Usage: e2e_step <step> [--] <cmd...>" >&2
        exit 1
    fi
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
    _e2e_require_init e2e_step
    if [[ $# -eq 0 ]]; then
        echo "Error: e2e_step '${step}' needs a command" >&2
        exit 1
    fi

    _e2e_claim_name "$step" 0
    local record_step="$_E2E_CLAIMED"
    _E2E_CURRENT_RUNNING_STEP="$record_step"
    _E2E_CURRENT_RUNNING_ORIGIN="$step"

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

    local stdout_sha256
    stdout_sha256=$(_e2e_sha256_file "$stdout_file")
    local cmd_str="$*"
    local out
    out=$(_e2e_py step_record "$(_e2e_iso8601)" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$record_step" "$cmd_str" \
        "$cmd_exit" "$duration_ms" "$stdout_sha256" "$stdout_file" "$stderr_file" "$(_e2e_repro_for "$step")") \
        || _e2e_internal_error "step record for '${record_step}'"
    rm -f "$stdout_file" "$stderr_file"

    _e2e_take_record "$out"
    _e2e_commit_record "$step" "$record_step" || true
    _E2E_CURRENT_RUNNING_STEP=""
    _E2E_CURRENT_RUNNING_ORIGIN=""
}

e2e_expect_eq() {
    if [[ $# -lt 3 ]]; then
        echo "Usage: e2e_expect_eq <step> <expected> <observed>" >&2
        exit 1
    fi
    local step="$1"
    local expected="$2"
    local observed="$3"

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        return 0
    fi

    if ! _e2e_step_matches_only "$step"; then
        return 0
    fi
    _e2e_require_init e2e_expect_eq

    _e2e_claim_name "$step" 0
    local record_step="$_E2E_CLAIMED"
    _E2E_CURRENT_RUNNING_STEP="$record_step"
    _E2E_CURRENT_RUNNING_ORIGIN="$step"

    local verdict="pass"
    if [[ "$expected" != "$observed" ]]; then
        verdict="fail"
    fi

    local out
    out=$(_e2e_py eq_record "$(_e2e_iso8601)" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$record_step" "$expected" \
        "$observed" "$verdict" "$(_e2e_repro_for "$step")") || _e2e_internal_error "expect_eq record for '${record_step}'"
    _e2e_take_record "$out"
    _e2e_commit_record "$step" "$record_step" || true
    _E2E_CURRENT_RUNNING_STEP=""
    _E2E_CURRENT_RUNNING_ORIGIN=""
}

e2e_expect_exit() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: e2e_expect_exit <step> <code>" >&2
        exit 1
    fi
    local step="$1"
    local expected_code="$2"

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        echo "$step"
        return 0
    fi

    if ! _e2e_step_matches_only "$step"; then
        return 0
    fi
    _e2e_require_init e2e_expect_exit

    local observed_code="${_E2E_STEP_EXIT["$step"]:-}"
    local target_step="$step"
    if [[ -z "$observed_code" && "$step" == *_exit ]]; then
        target_step="${step%_exit}"
        observed_code="${_E2E_STEP_EXIT["$target_step"]:-unknown}"
    elif [[ -z "$observed_code" ]]; then
        observed_code="unknown"
    fi

    _e2e_claim_name "$step" 1
    local record_step="$_E2E_CLAIMED"
    _E2E_CURRENT_RUNNING_STEP="$record_step"
    _E2E_CURRENT_RUNNING_ORIGIN="$step"

    local verdict="pass"
    if [[ "$observed_code" != "$expected_code" ]]; then
        verdict="fail"
    fi

    local out
    out=$(_e2e_py exit_record "$(_e2e_iso8601)" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$record_step" "$expected_code" \
        "$observed_code" "$verdict" "$(_e2e_repro_for "$step")") || _e2e_internal_error "expect_exit record for '${record_step}'"
    _e2e_take_record "$out"
    _e2e_commit_record "$step" "$record_step" || true
    _E2E_CURRENT_RUNNING_STEP=""
    _E2E_CURRENT_RUNNING_ORIGIN=""
}

e2e_expect_json_field() {
    if [[ $# -lt 4 ]]; then
        echo "Usage: e2e_expect_json_field <step> <file-or-json> <.path> <expected>" >&2
        exit 1
    fi
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
    _e2e_require_init e2e_expect_json_field

    local mode="var"
    if [[ -f "$file_or_var" ]]; then
        mode="file"
    fi

    _e2e_claim_name "$step" 0
    local record_step="$_E2E_CLAIMED"
    _E2E_CURRENT_RUNNING_STEP="$record_step"
    _E2E_CURRENT_RUNNING_ORIGIN="$step"

    local out
    out=$(_e2e_py json_field_record "$(_e2e_iso8601)" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$record_step" \
        "$file_or_var" "$path" "$expected" "$mode" "$(_e2e_repro_for "$step")") \
        || _e2e_internal_error "expect_json_field record for '${record_step}'"
    _e2e_take_record "$out"
    _e2e_commit_record "$step" "$record_step" || true
    _E2E_CURRENT_RUNNING_STEP=""
    _E2E_CURRENT_RUNNING_ORIGIN=""
}

e2e_skip() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: e2e_skip <step> <reason>" >&2
        exit 1
    fi
    local step="$1"
    local reason="$2"

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        echo "$step"
        return 0
    fi

    if ! _e2e_step_matches_only "$step"; then
        return 0
    fi
    _e2e_require_init e2e_skip

    _e2e_claim_name "$step" 0
    local record_step="$_E2E_CLAIMED"
    _E2E_CURRENT_RUNNING_STEP="$record_step"
    _E2E_CURRENT_RUNNING_ORIGIN="$step"

    local out
    out=$(_e2e_py skip_record "$(_e2e_iso8601)" "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$record_step" "$reason" \
        "$(_e2e_repro_for "$step")") || _e2e_internal_error "skip record for '${record_step}'"
    _e2e_take_record "$out"
    _e2e_commit_record "$step" "$record_step" || true
    _E2E_CURRENT_RUNNING_STEP=""
    _E2E_CURRENT_RUNNING_ORIGIN=""
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

# Scoped temp root under the run dir: removed when the run passes, kept (and listed in
# summary.preserved_tmpdirs) when it fails. Usually called as T=$(e2e_tmpdir), so the path is
# tracked in "<run log>.tmpdirs", which survives the command substitution.
e2e_tmpdir() {
    _e2e_require_init e2e_tmpdir
    local tracked=0
    if [[ -f "${_E2E_LOG_FILE}.tmpdirs" ]]; then
        tracked=$(wc -l < "${_E2E_LOG_FILE}.tmpdirs")
    fi
    if (( tracked >= _E2E_MAX_TMPDIRS )); then
        echo "Error: at most ${_E2E_MAX_TMPDIRS} e2e_tmpdir directories per run" >&2
        return 1
    fi
    local tmp
    tmp=$(mktemp -d "${_E2E_RUN_DIR}/tmp_XXXXXX")
    echo "$tmp" >> "${_E2E_LOG_FILE}.tmpdirs"
    _E2E_TMPDIRS+=("$tmp")
    echo "$tmp"
}

e2e_cargo_test() {
    if [[ $# -lt 2 ]]; then
        echo "Usage: e2e_cargo_test <crate> <test-target> [filter]" >&2
        exit 1
    fi
    local crate="$1"
    local target="$2"
    local filter="${3:-}"

    if [[ "$_E2E_LIST" -eq 1 ]]; then
        echo "$target"
        return 0
    fi

    # CAPLOG steps are selected through their cargo target; the summary repro names the target.
    if ! _e2e_step_matches_only "$target"; then
        return 0
    fi
    _e2e_require_init e2e_cargo_test

    _E2E_CURRENT_RUNNING_STEP="$target"
    _E2E_CURRENT_RUNNING_ORIGIN="$target"

    local stdout_file
    stdout_file=$(mktemp "${_E2E_RUN_DIR}/cargo_test_stdout_XXXXXX")
    local stderr_file
    stderr_file=$(mktemp "${_E2E_RUN_DIR}/cargo_test_stderr_XXXXXX")
    local ids_file
    ids_file=$(mktemp "${_E2E_RUN_DIR}/cargo_test_ids_XXXXXX")

    local start_ms
    start_ms=$(_e2e_now_ms)

    local test_exit=0
    local cmd_args=(rch exec -- cargo test -p "$crate" --test "$target" --locked --offline -- --nocapture)
    if [[ -n "$filter" ]]; then
        cmd_args+=("$filter")
    fi

    local cmd_display="RCH_REQUIRE_REMOTE=1 ${cmd_args[*]}"

    local retries=0
    while true; do
        test_exit=0
        (
            cd "$_E2E_REPO_ROOT"
            RCH_REQUIRE_REMOTE=1 "${cmd_args[@]}"
        ) > "$stdout_file" 2> "$stderr_file" || test_exit=$?

        if [[ $test_exit -eq 103 && $retries -lt 3 ]]; then
            retries=$((retries + 1))
            python3 -c 'import time; time.sleep(0.1)' 2>/dev/null || true
            continue
        fi
        break
    done

    local end_ms
    end_ms=$(_e2e_now_ms)
    local duration_ms=$(( end_ms - start_ms ))

    local repro_cmd
    repro_cmd="$(_e2e_repro_for "$target")"
    local stdout_sha256
    stdout_sha256=$(_e2e_sha256_file "$stdout_file")
    local stdout_excerpt
    stdout_excerpt=$(_e2e_redact_file "$stdout_file")
    local stderr_excerpt
    stderr_excerpt=$(_e2e_redact_file "$stderr_file")
    local ts
    ts=$(_e2e_iso8601)
    if [[ ${#_E2E_WRITTEN_IDS[@]} -gt 0 ]]; then
        printf '%s\n' "${!_E2E_WRITTEN_IDS[@]}" > "$ids_file"
    fi

    local pending_verdict=""
    local pending_id=""
    local pending_extra=""
    # Ingest CAPLOG lines in current shell via process substitution
    while IFS= read -r line; do
        if [[ "$line" == "{"* ]]; then
            if [[ -n "$pending_id" ]]; then
                _E2E_REC_VERDICT="$pending_verdict"
                _E2E_REC_ID="$pending_id"
                _E2E_REC_JSON="$line"
                _E2E_REC_EXTRA="$pending_extra"
                if _e2e_commit_record "" ""; then
                    _E2E_STEP_TARGET["$pending_id"]="$target"
                fi
            fi
            pending_id=""
        elif [[ "$line" == *$'\t'* ]]; then
            pending_verdict="${line%%$'\t'*}"
            pending_id="${line#*$'\t'}"
            pending_extra=""
            if [[ "$pending_id" == *$'\t'* ]]; then
                pending_extra="${pending_id#*$'\t'}"
                pending_id="${pending_id%%$'\t'*}"
            fi
        fi
    done < <(_e2e_py cargo_ingest "$stdout_file" "$stderr_file" "$crate" "$target" "$test_exit" \
        "$_E2E_SCRIPT_NAME" "$_E2E_BEAD" "$duration_ms" "$repro_cmd" "$cmd_display" "$ids_file" \
        "$stdout_sha256" "$stdout_excerpt" "$stderr_excerpt" "$ts")

    rm -f "$stdout_file" "$stderr_file" "$ids_file"

    local py_rc=0
    wait $! || py_rc=$?
    if [[ $py_rc -ne 0 ]]; then
        # The ingester crashed: fail the target through a record of its own.
        local name="$target"
        if [[ -n "${_E2E_WRITTEN_IDS["$name"]:-}" ]]; then
            name="${target}:ingest"
        fi
        _e2e_record_synthetic_fail "$name" "$target" "$py_rc" "CAPLOG ingestion completes" \
            "CAPLOG ingester exited with status ${py_rc}; the cargo test output was not fully ingested" \
            || _e2e_internal_error "ingester failure record for '${target}'"
        _E2E_STEP_TARGET["$_E2E_REC_ID"]="$target"
    fi
    _E2E_CURRENT_RUNNING_STEP=""
    _E2E_CURRENT_RUNNING_ORIGIN=""
}

# Repro for the summary: rerun exactly the failing steps. A failing CAPLOG step (or its cargo
# target) maps to the target through _E2E_STEP_TARGET; a failure no step name reproduces (a
# script-level exit, a redacted step id) reruns the whole script.
_e2e_summary_repro() {
    local verdict="$1"
    if [[ "$verdict" != "fail" || ${#_E2E_FAILURES[@]} -eq 0 ]]; then
        if [[ -n "${_E2E_ONLY:-}" ]]; then
            printf '%s --only %q' "$_E2E_REPRO_BASE" "$_E2E_ONLY"
        else
            printf '%s' "$_E2E_REPRO_BASE"
        fi
        return 0
    fi
    local names=()
    local -A picked=()
    local f n
    for f in "${_E2E_FAILURES[@]}"; do
        if [[ -n "${_E2E_STEP_TARGET["$f"]:-}" ]]; then
            n="${_E2E_STEP_TARGET["$f"]}"
        elif [[ -n "${_E2E_RECORD_ORIGIN["$f"]:-}" ]]; then
            n="${_E2E_RECORD_ORIGIN["$f"]}"
        else
            printf '%s' "$_E2E_REPRO_BASE"
            return 0
        fi
        if [[ -z "${picked["$n"]:-}" ]]; then
            picked["$n"]=1
            names+=("$(printf '%q' "$n")")
        fi
    done
    local joined
    joined=$(IFS=','; echo "${names[*]}")
    printf '%s --only %s' "$_E2E_REPRO_BASE" "$joined"
}

_e2e_summary_json() {
    local verdict="$1"
    shift || true
    local kept_tmpdirs=("$@")
    local end_ms
    end_ms=$(_e2e_now_ms)
    local total_ms=$(( end_ms - _E2E_START_MS ))

    local unique_failures=()
    local -A seen_failure=()
    local f
    for f in "${_E2E_FAILURES[@]}"; do
        if [[ -n "$f" && -z "${seen_failure["$f"]:-}" ]]; then
            seen_failure["$f"]=1
            unique_failures+=("$f")
        fi
    done
    _E2E_FAILURES=("${unique_failures[@]}")

    local keep=()
    if [[ "$verdict" == "fail" ]]; then
        keep=("${kept_tmpdirs[@]}")
    fi

    _e2e_py summary_record "$verdict" "$_E2E_STEP_COUNT" "$total_ms" "${_E2E_LOG_FILE:-}" \
        "$(_e2e_summary_repro "$verdict")" \
        "${#_E2E_FAILURES[@]}" "${_E2E_FAILURES[@]}" \
        "${#_E2E_SKIPPED[@]}" "${_E2E_SKIPPED[@]}" \
        "${#keep[@]}" "${keep[@]}"
}

_e2e_write_summary_record() {
    _E2E_SUMMARY_WRITTEN=1
    local summary_json="$1"
    printf "%s\n" "$summary_json" >> "$_E2E_LOG_FILE"
}

e2e_summary() {
    if [[ "${_E2E_LIST:-0}" -eq 1 ]]; then
        exit 0
    fi

    if [[ "${_E2E_INITIALIZED:-0}" -ne 1 || -z "${_E2E_LOG_FILE:-}" ]]; then
        echo "Error: E2E uninitialized or log file not set (failing closed)" >&2
        exit 1
    fi

    if [[ "${_E2E_SUMMARY_WRITTEN:-0}" -eq 1 ]]; then
        return 0
    fi
    if _e2e_log_has_summary; then
        _e2e_exit_on_existing_summary 0
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
    local -A seen_tmp=()
    local tmp
    for tmp in "${raw_tmpdirs[@]}"; do
        # Only directories this run created (<run dir>/tmp_*) are listed or ever removed.
        if [[ "$tmp" == "${_E2E_RUN_DIR}"/tmp_* && "$tmp" != *..* && -z "${seen_tmp["$tmp"]:-}" ]]; then
            seen_tmp["$tmp"]=1
            all_tmpdirs+=("$tmp")
        fi
    done

    if [[ -n "${_E2E_ONLY:-}" && "$_E2E_STEP_COUNT" -eq 0 ]]; then
        echo "Error: no step matched --only '${_E2E_ONLY}' (CAPLOG steps are selected by their cargo test target name)" >&2
    fi

    local summary_json
    summary_json=$(_e2e_summary_json "$verdict" "${all_tmpdirs[@]}") || _e2e_internal_error "summary record"

    # Validate the log plus its candidate summary BEFORE writing: a log that fails validation never
    # receives a pass summary.
    local candidate
    local val_rc=0
    candidate=$(mktemp "${_E2E_RUN_DIR}/summary_candidate_XXXXXX")
    { cat "$_E2E_LOG_FILE"; printf "%s\n" "$summary_json"; } > "$candidate"
    python3 "${_E2E_LIB_DIR}/validate_log.py" "$candidate" > /dev/null 2> "${candidate}.err" || val_rc=$?
    if [[ $val_rc -ne 0 ]]; then
        echo "Error: ${_E2E_LOG_FILE} failed validation (validator exit ${val_rc}); the run verdict is fail:" >&2
        grep -v '^Offending line:' "${candidate}.err" >&2 || true
        if [[ "$verdict" == "pass" ]]; then
            verdict="fail"
            summary_json=$(_e2e_summary_json "$verdict" "${all_tmpdirs[@]}") || _e2e_internal_error "summary record"
        fi
    fi
    rm -f "$candidate" "${candidate}.err"

    _e2e_write_summary_record "$summary_json"

    # Validate log file using validate_log.py
    local final_rc=0
    python3 "${_E2E_LIB_DIR}/validate_log.py" "$_E2E_LOG_FILE" || final_rc=$?
    if [[ $final_rc -ne 0 || $val_rc -ne 0 ]]; then
        verdict="fail"
    fi

    if [[ "$verdict" == "fail" ]]; then
        for tmp in "${all_tmpdirs[@]}"; do
            python3 -c 'import json, sys; print(json.dumps({"event": "forensics_preserved", "tmpdir": sys.argv[1]}))' "$tmp" >&2
        done
    else
        for tmp in "${all_tmpdirs[@]}"; do
            rm -rf "$tmp"
        done
        rm -f "$tmpdirs_file"
    fi

    if [[ -n "${_E2E_RUN_DIR:-}" && -d "${_E2E_RUN_DIR:-}" ]]; then
        rm -f "${_E2E_RUN_DIR}"/stdout_* "${_E2E_RUN_DIR}"/stderr_* "${_E2E_RUN_DIR}"/cargo_test_* \
            "${_E2E_RUN_DIR}"/summary_candidate_* 2>/dev/null || true
    fi

    echo "E2E Log: ${_E2E_LOG_FILE}"
    if [[ "$verdict" == "pass" ]]; then
        exit 0
    else
        echo "E2E Repro (from ${_E2E_REPO_ROOT}): $(_e2e_summary_repro fail)"
        exit 1
    fi
}
