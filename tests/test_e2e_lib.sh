#!/usr/bin/env bash
# tests/test_e2e_lib.sh
# Self-test for scripts/e2e/lib.sh (fss-2h5zq.1).
# The only rch on PATH is the stub written below; a cargo tripwire fails the suite if anything
# tries local cargo. Every write (TMPDIR included) stays under target/test_sandboxes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Run in a clean environment: secret-named host variables would otherwise be redacted from every
# record and make the expectations below depend on the host.
if [[ -z "${_E2E_LIB_TEST_CLEAN_ENV:-}" ]]; then
    exec env -i PATH="$PATH" HOME="${HOME:-/nonexistent}" LANG=C.UTF-8 _E2E_LIB_TEST_CLEAN_ENV=1 \
        bash "${BASH_SOURCE[0]}" "$@"
fi

LIB="${REPO_ROOT}/scripts/e2e/lib.sh"
VALIDATOR="${REPO_ROOT}/scripts/e2e/validate_log.py"
TEST_SANDBOX="${REPO_ROOT}/target/test_sandboxes/e2e_lib_test_$$"
rm -rf "$TEST_SANDBOX"
mkdir -p "$TEST_SANDBOX"

cleanup() {
    local rc=$?
    # Keep the sandbox of a failing run for forensics.
    if [[ $rc -eq 0 ]]; then
        rm -rf "$TEST_SANDBOX"
    else
        echo "sandbox kept: $TEST_SANDBOX" >&2
    fi
}
trap cleanup EXIT

export TMPDIR="${TEST_SANDBOX}/tmpdir"
mkdir -p "$TMPDIR"
REAL_PYTHON="$(command -v python3)"

STUB_BIN_DIR="${TEST_SANDBOX}/bin"
mkdir -p "$STUB_BIN_DIR"
export STUB_RCH_CALLS="${TEST_SANDBOX}/rch_calls.log"
export CARGO_TRIPWIRE="${TEST_SANDBOX}/cargo_tripwire.log"

# Stub rch
cat <<'STUB' > "${STUB_BIN_DIR}/rch"
#!/usr/bin/env bash
# Stub rch for the e2e harness self-test. Never touches real rch, cargo or the network.
set -uo pipefail
echo "RCH_REQUIRE_REMOTE=${RCH_REQUIRE_REMOTE:-unset} ARGS=$*" >> "${STUB_RCH_CALLS}"
mode="${STUB_RCH_MODE:-pass}"
target="${STUB_RCH_TARGET:-test_target}"
cap() { printf 'CAPLOG %s\n' "$1"; }

case "$mode" in
    pass)
        echo "running 1 test"
        cap "{\"step\": \"${target}\", \"verdict\": \"pass\", \"exit\": 0, \"duration_ms\": 10, \"expected\": 1, \"observed\": 1}"
        echo "test result: ok. 1 passed; 0 failed"
        exit 0
        ;;
    fail)
        echo "running 1 test"
        cap "{\"step\": \"${target}_fail\", \"verdict\": \"fail\", \"exit\": 1, \"duration_ms\": 12, \"expected\": 1, \"observed\": 2}"
        echo "test result: FAILED. 0 passed; 1 failed"
        exit 0  # cargo exits 0 here on purpose: a CAPLOG fail verdict alone must fail the run
        ;;
    zero_caplog)
        echo "running 1 test"
        echo "test result: ok. 1 passed; 0 failed"
        exit 0
        ;;
    malformed)
        echo "CAPLOG not a valid json line"
        exit 0
        ;;
    bad_verdict)
        cap "{\"step\": \"${target}\", \"verdict\": \"bogus\", \"exit\": 0, \"duration_ms\": 10}"
        exit 0
        ;;
    secret_caplog)
        cap "{\"step\": \"${target}\", \"verdict\": \"pass\", \"exit\": 0, \"duration_ms\": 10, \"expected\": \"ghp_EXPECTEDSECRET1234567890\", \"observed\": {\"k\": \"ghp_OBSERVEDSECRET1234567890\"}}"
        exit 0
        ;;
    inf)
        cap '{"step": "inf_step", "verdict": "fail", "duration_ms": 1e400}'
        cap '{"step": "str_exit", "verdict": "pass", "exit": "boom", "duration_ms": "abc"}'
        exit 0
        ;;
    r103)
        echo "remote unavailable"
        exit 103
        ;;
    vanish)
        # The capture file disappears under the ingester: it must fail the target, not pass it.
        capture="$(readlink "/proc/$$/fd/1")"
        cap '{"step": "v1", "verdict": "pass"}'
        rm -f "$capture"
        exit 0
        ;;
    term)
        kill -TERM "${E2E_TEST_SCRIPT_PID}"
        exit 0
        ;;
    badts)
        cap '{"step": "t1", "verdict": "pass", "ts": 5}'
        exit 0
        ;;
    badtype)
        cap '{"step": "t1", "verdict": "pass", "stdout_excerpt": {"a": 1}}'
        exit 0
        ;;
    secretkey)
        cap '{"step": "t1", "verdict": "pass", "observed": {"token": "SKVAL1", "ok": 2}}'
        exit 0
        ;;
    huge)
        python3 -c 'import json; print("CAPLOG " + json.dumps({"step": "t1", "verdict": "pass", "expected": ["y" * 4000] * 40}))'
        exit 0
        ;;
    caplog_skip)
        cap '{"step": "a", "verdict": "pass"}'
        cap '{"step": "b", "verdict": "skip", "observed": {"r": "oracle absent"}}'
        exit 0
        ;;
    caplog_allskip)
        cap '{"step": "b", "verdict": "skip", "observed": "oracle absent"}'
        exit 0
        ;;
    leakname)
        cap '{"step": "ghp_STEPLEAK1234567890abcd", "verdict": "pass", "bead": "xoxb-BEADLEAK1234"}'
        cap "{\"step\": \"plain_step\", \"verdict\": \"pass\", \"bead\": \"${DEPLOY_TOKEN_T23:-unset}\"}"
        exit 0
        ;;
    cred_list)
        cap '{"step": "capcred", "verdict": "pass", "cmd": ["curl", "-u", "admin:L1CAPU"], "observed": "git clone deploy:L1CAPSCP@git.invalid:r.git"}'
        exit 0
        ;;
    leak345)
        echo "borrow marker L5BORROW"
        cap '{"step": "dictstep", "verdict": "pass", "observed": {"pass": "L4PASS", "passwd": "L4PASSWD", "pwd": "L4PWD", "private_key": "L4PK", "credentials": "L4CRED", "ok": 1}}'
        cap '{"step": "noexcerpt", "verdict": "pass"}'
        cap '{"step": "cmdstep", "verdict": "pass", "cmd": ["curl", "-u", "admin:L3CMDU", "https://h.invalid/"], "observed": "--password L3CMDPW"}'
        cap '{"step": "forcefail", "verdict": "fail"}'
        exit 0
        ;;
    kwcaplog)
        python3 - <<'PY'
import json, os
rec = {
    "step": "kw", "verdict": "pass",
    "stdout_excerpt": "Authorization: Basic KWCAA\nkeep_caplog_line\npassword hunter KWCBB\nX-Auth-Token KWCCC\nsecret is KWCDD\nCookie: KWCEE",
    "stderr_excerpt": ["password hunter KWCKK", "keep_caplog_err"],
    "expected": ["password hunter KWCFF", "https://u:KWCHH@h.invalid/x", "mysql -pKWCII"],
    "observed": "--password KWCGG",
    "cmd": ["mysql", "-pKWCJJ", "--password=KWCLL"],
    "bead": os.environ.get("MYPASS", "unset"),
    "script": "https://u:KWCMM@h.invalid/",
    "repro": "secret is KWCNN",
}
print("CAPLOG " + json.dumps(rec))
PY
        exit 0
        ;;
    stderr_only)
        # Real rch forwards the remote test output on stderr.
        cap '{"step": "e1", "verdict": "pass", "expected": 1, "observed": 1}' >&2
        cap '{"step": "e2", "verdict": "pass"}' >&2
        exit 0
        ;;
    split_pass_fail)
        cap '{"step": "s_ok", "verdict": "pass"}'
        cap '{"step": "s_bad", "verdict": "fail", "expected": 1, "observed": 2}' >&2
        exit 0
        ;;
    dup_cross)
        cap '{"step": "d1", "verdict": "pass"}'
        cap '{"step": "d1", "verdict": "pass"}' >&2
        exit 0
        ;;
    malformed_stderr)
        cap '{"step": "m_ok", "verdict": "pass"}'
        echo 'CAPLOG {"step": "m_bad", broken' >&2
        exit 0
        ;;
    overlong_stderr)
        cap '{"step": "o_ok", "verdict": "pass"}'
        python3 -c 'import json, sys; sys.stderr.write("CAPLOG " + json.dumps({"step": "o_big", "verdict": "pass", "observed": "z" * 1100000}) + "\n")'
        exit 0
        ;;
    pw_caplog)
        cap '{"step": "pwcap", "verdict": "pass", "stdout_excerpt": "Password:\nL7CAPVAL\nkept caplog line"}'
        exit 0
        ;;
    libtest_interleave)
        # Real rch shapes: libtest's "test <name> ... " (once, twice, ANSI-wrapped) before a CAPLOG line.
        {
            printf 'test test_02_synthetic_standard_stream ... CAPLOG {"step": "li1", "verdict": "pass"}\n'
            printf 'ok\n'
            printf 'test t_one ... test mod::t_two ... CAPLOG {"step": "li5", "verdict": "pass"}\n'
            printf '\033[1mtest t_one ... \033[0mCAPLOG {"step": "li6", "verdict": "pass"}\n'
            cap '{"step": "li2", "verdict": "pass"}'
        } >&2
        exit 0
        ;;
    hide_*)
        # A pass on stdout, and a record behind leading text on stderr: never a hidden record.
        cap '{"step": "h_ok", "verdict": "pass"}'
        case "$mode" in
            hide_double) printf 'test t_one ... test t_two ... CAPLOG {"step": "hd", "verdict": "fail"}\n' ;;
            hide_midline) printf 'running 2 tests CAPLOG {"step": "hm", "verdict": "fail"}\n' ;;
            hide_tab) printf 'test t_one ...\tCAPLOG {"step": "ht", "verdict": "fail"}\n' ;;
            hide_noise) printf 'noise CAPLOG {"step": "li3", "verdict": "pass"}\n' ;;
            hide_badname) printf 'test a b ... CAPLOG {"step": "li4", "verdict": "pass"}\n' ;;
            hide_smuggle) printf 'test not-a-test-line ... CAPLOG {"step": "sm", "verdict": "pass"}\n' ;;
            hide_overlong) python3 -c 'import json; print("test " + "t" * 80 + " ... CAPLOG " + json.dumps({"step": "ho", "verdict": "fail", "observed": "x" * 1100000}))' ;;
            hide_overlong_tail) python3 -c 'print("x" * 1100000 + " CAPLOG {\"step\": \"hot\", \"verdict\": \"fail\"}")' ;;
            hide_overlong_mid) python3 -c 'import json; print("running 2 tests " * 10 + "CAPLOG " + json.dumps({"step": "hom", "verdict": "fail", "observed": "x" * 1100000}))' ;;
        esac >&2
        exit 0
        ;;
    *)
        echo "Unknown stub mode $mode" >&2
        exit 1
        ;;
esac
STUB
chmod +x "${STUB_BIN_DIR}/rch"

# Tripwire: local cargo must never run.
cat <<'STUB' > "${STUB_BIN_DIR}/cargo"
#!/usr/bin/env bash
echo "local cargo called: $*" >> "${CARGO_TRIPWIRE}"
exit 99
STUB
chmod +x "${STUB_BIN_DIR}/cargo"

# python3 wrapper that fails one engine mode (fault injection for the running-step marker).
PYFAIL_DIR="${TEST_SANDBOX}/pyfail"
mkdir -p "$PYFAIL_DIR"
cat <<STUB > "${PYFAIL_DIR}/python3"
#!/usr/bin/env bash
if [[ -n "\${E2E_TEST_FAIL_PY_MODE:-}" && "\${3:-}" == "\${E2E_TEST_FAIL_PY_MODE}" ]]; then
    echo "injected failure of engine mode \$3" >&2
    exit 1
fi
# Fault injection for the FINAL validation of the written log (never the pre-write candidate).
if [[ -n "\${E2E_TEST_FAIL_FINAL_VALIDATE:-}" && "\${1:-}" == */validate_log.py && "\${2:-}" != *summary_candidate_* ]]; then
    echo "injected failure of the final validation of \$2" >&2
    exit 1
fi
exec "${REAL_PYTHON}" "\$@"
STUB
chmod +x "${PYFAIL_DIR}/python3"

export PATH="${STUB_BIN_DIR}:${PATH}"
export FSS_E2E_LOG_DIR="${TEST_SANDBOX}/logs"

# HARD GUARD against reaching real rch or local cargo
if [[ "$(command -v rch)" != "${STUB_BIN_DIR}/rch" ]]; then
    echo "HARD GUARD FAIL: rch resolved to $(command -v rch), not ${STUB_BIN_DIR}/rch" >&2
    exit 97
fi
if [[ "$(command -v cargo)" != "${STUB_BIN_DIR}/cargo" ]]; then
    echo "HARD GUARD FAIL: cargo resolved to $(command -v cargo), not the tripwire" >&2
    exit 97
fi

# Log inspection helper
cat <<'PY' > "${TEST_SANDBOX}/logtool.py"
import json
import sys


def recs(p):
    return [json.loads(line) for line in open(p, encoding="utf-8")]


cmd, path, *rest = sys.argv[1:]
if cmd == "summary":
    print(json.dumps(recs(path)[-1].get(rest[0])))
elif cmd == "summary_str":
    print(recs(path)[-1].get(rest[0]))
elif cmd == "steps":
    print(json.dumps([r["step"] for r in recs(path)[1:-1]]))
elif cmd == "record":
    for r in recs(path):
        if r.get("step") == rest[0]:
            print(json.dumps(r.get(rest[1])))
            break
    else:
        print("<no record>")
elif cmd == "summaries":
    print(sum(1 for r in recs(path) if r.get("step") == "summary"))
elif cmd == "pass_summaries":
    print(sum(1 for r in recs(path) if r.get("step") == "summary" and r.get("verdict") == "pass"))
elif cmd == "consistent":
    rs = recs(path)
    s = rs[-1]
    ids = [r["step"] for r in rs[1:-1]]
    ok = (s.get("step") == "summary" and s["steps"] == len(ids)
          and all(f in ids for f in s["failures"]) and all(k["step"] in ids for k in s["skipped"]))
    print("ok" if ok else f"inconsistent: steps={s.get('steps')} records={len(ids)} failures={s.get('failures')}")
elif cmd == "leaks":
    text = open(path, encoding="utf-8", errors="replace").read()
    found = [n for n in rest if n in text]
    print(f"{len(found)} {' '.join(found)}".strip())
elif cmd == "max_line":
    print(max(len(line) for line in open(path, "rb")))
elif cmd == "json":
    print(json.dumps(rest))
PY

lt() { python3 "${TEST_SANDBOX}/logtool.py" "$@"; }
fail() { echo "FAIL: $*" >&2; exit 1; }
check_eq() { [[ "$2" == "$3" ]] || fail "$1: expected <$2>, got <$3>"; }
check_ne() { [[ "$2" != "$3" ]] || fail "$1: did not expect <$3>"; }
check_valid() { python3 "$VALIDATOR" "$1" > /dev/null || fail "validator rejected $1"; }
check_contains() { grep -qF -- "$2" "$3" || fail "$1: <$2> not found in $3"; }
check_absent() { if grep -qF -- "$2" "$3"; then fail "$1: <$2> unexpectedly found in $3"; fi; }
check_no_leaks() {
    local file="$1"
    shift
    local r
    r=$(lt leaks "$file" "$@")
    [[ "$r" == "0" ]] || fail "leaked into ${file}: ${r}"
}
new_script() {
    local path="$1"
    mkdir -p "$(dirname "$path")"
    { printf '#!/usr/bin/env bash\nsource %q\n' "$LIB"; cat; } > "$path"
    chmod +x "$path"
}
run() {
    local tag="$1"
    shift
    OUT="${TEST_SANDBOX}/${tag}.out"
    set +e
    "$@" > "$OUT" 2>&1
    RC=$?
    set -e
}
calls() { if [[ -f "$STUB_RCH_CALLS" ]]; then wc -l < "$STUB_RCH_CALLS" | tr -d ' '; else echo 0; fi; }
reset_calls() { : > "$STUB_RCH_CALLS"; }
logdir() { echo "${FSS_E2E_LOG_DIR}/$1"; }
rel() { echo "${1#"$REPO_ROOT"/}"; }

echo "=== Test 1: Happy path e2e execution ==="
S="${TEST_SANDBOX}/suite1/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite1" "fss-2h5zq.1"
e2e_step "step_echo" echo "hello world"
e2e_expect_eq "step_eq" "val1" "val1"
e2e_expect_exit "step_echo" 0
e2e_cargo_test "fss-cli" "test_target"
e2e_summary
EOF
reset_calls
run t1 env STUB_RCH_MODE=pass "$S"
check_eq "T1 rc" 0 "$RC"
LOG1="$(logdir suite1)/run_0001.log"
if [[ ! -f "$LOG1" ]]; then
    echo "FAIL: Expected log file $LOG1 does not exist" >&2
    exit 1
fi
check_valid "$LOG1"
check_eq "T1 summary verdict" '"pass"' "$(lt summary "$LOG1" verdict)"
check_eq "T1 steps" '["step_echo", "step_eq", "step_echo_exit", "test_target"]' "$(lt steps "$LOG1")"
check_eq "T1 consistent" ok "$(lt consistent "$LOG1")"
check_eq "T1 rch calls" 1 "$(calls)"
check_eq "T1 rch argv" "RCH_REQUIRE_REMOTE=1 ARGS=exec -- cargo test -p fss-cli --test test_target --locked --offline -- --nocapture" "$(cat "$STUB_RCH_CALLS")"
# The normal path writes one summary and the EXIT trap stays silent.
check_absent "T1 second-summary note" "Note:" "$OUT"
check_eq "T1 run dir holds only the log" "run_0001.log" "$(ls -A "$(logdir suite1)")"
echo "PASS: Test 1"

echo "=== Test 2: F1 & Mutant 6 - CAPLOG verdict fail with exit 0 fails summary ==="
S="${TEST_SANDBOX}/suite2/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite2" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_fail_target"
e2e_summary
EOF
run t2 env STUB_RCH_MODE=fail "$S"
if [[ $RC -eq 0 ]]; then
    echo "FAIL: F1 mutant survived! CAPLOG fail verdict gave exit 0!" >&2
    exit 1
fi
LOG2="$(logdir suite2)/run_0001.log"
check_valid "$LOG2"
# The SUMMARY record (last line) must carry the fail verdict, not just any record.
check_eq "T2 summary verdict" '"fail"' "$(lt summary "$LOG2" verdict)"
check_eq "T2 failures" '["test_target_fail"]' "$(lt summary "$LOG2" failures)"
echo "PASS: Test 2"

echo "=== Test 3: Mutant 6 - Zero-CAPLOG failure ==="
S="${TEST_SANDBOX}/suite3/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite3" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_no_caplog"
e2e_summary
EOF
run t3 env STUB_RCH_MODE=zero_caplog "$S"
if [[ $RC -eq 0 ]]; then
    echo "FAIL: Zero-CAPLOG test survived with exit 0!" >&2
    exit 1
fi
LOG3="$(logdir suite3)/run_0001.log"
check_valid "$LOG3"
check_eq "T3 observed" '"no CAPLOG line observed"' "$(lt record "$LOG3" test_no_caplog observed)"
check_eq "T3 summary verdict" '"fail"' "$(lt summary "$LOG3" verdict)"
echo "PASS: Test 3"

echo "=== Test 4: F2 - Non-numeric run_abc.log skipped and fail closed ==="
SUITE4_DIR="$(logdir suite4)"
mkdir -p "$SUITE4_DIR"
touch "${SUITE4_DIR}/run_stray_abc.log"
S="${TEST_SANDBOX}/suite4/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite4" "fss-2h5zq.1"
e2e_step "step1" echo "ok"
e2e_summary
EOF
run t4 "$S"
check_eq "T4 rc" 0 "$RC"
LOG4="${SUITE4_DIR}/run_0001.log"
if [[ ! -f "$LOG4" ]]; then
    echo "FAIL: Expected $LOG4 created despite stray run_stray_abc.log" >&2
    exit 1
fi
check_valid "$LOG4"
echo "PASS: Test 4"

echo "=== Test 5: F3 & Mutant 5/17 - Secret redaction of planted secrets and token shapes ==="
S="${TEST_SANDBOX}/suite5/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite5" "fss-2h5zq.1"
e2e_step "leak_step" echo "$GITHUB_TOKEN $AWS_SECRET_ACCESS_KEY $MYPASS sk-ant-api03-faketoken123456 Bearer faketoken123456"
e2e_step "plain_env_value" echo "$DEPLOY_KEY_T5"
e2e_expect_eq "leak_expect" "Authorization: Bearer $GITHUB_TOKEN" "Authorization: Bearer $GITHUB_TOKEN"
e2e_skip "leak_skip" "Skipping because $MYPASS is secret"
e2e_summary
EOF
run t5 env GITHUB_TOKEN="ghp_superfaketoken1234567890" AWS_SECRET_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE" \
    MYPASS="supersecretpassword123" DEPLOY_KEY_T5="hunterPLAINVAL0005" "$S"
check_eq "T5 rc" 0 "$RC"
LOG5="$(logdir suite5)/run_0001.log"
check_valid "$LOG5"
for secret in "ghp_superfaketoken1234567890" "AKIAIOSFODNN7EXAMPLE" "supersecretpassword123" "sk-ant-api03-faketoken123456" "faketoken123456" "hunterPLAINVAL0005"; do
    if grep -q "$secret" "$LOG5" "$OUT"; then
        echo "FAIL: Secret '$secret' leaked into log file $LOG5 or the run output!" >&2
        exit 1
    fi
done
# A plain value line (no keyword) is redacted in place by the step-output path, not dropped.
check_eq "T5 env value redacted in the excerpt" '"<redacted>\n"' "$(lt record "$LOG5" plain_env_value stdout_excerpt)"
echo "PASS: Test 5"

echo "=== Test 6: Mutant 4 & Mutant 4b - Excerpt cap <= 4096 bytes with non-hex filler ==="
S="${TEST_SANDBOX}/suite6/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite6" "fss-2h5zq.1"
e2e_step "large_output" python3 -c 'print("Z" * 12000)'
e2e_step "overlong_line" python3 -c 'print("Q" * 70000, end="")'
e2e_summary
EOF
run t6 "$S"
check_eq "T6 rc" 0 "$RC"
LOG6="$(logdir suite6)/run_0001.log"
check_valid "$LOG6"
# Verify excerpt size strictly capped at 4096 bytes (kills M4b)
python3 - "$LOG6" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    rec = json.loads(line)
    if rec.get("step") == "large_output":
        b = rec["stdout_excerpt"].encode("utf-8")
        assert len(b) == 4096, f"Expected exactly 4096 bytes, got {len(b)}"
    if rec.get("step") == "overlong_line":
        assert rec["stdout_excerpt"] == "<over-long line omitted>\n", rec["stdout_excerpt"][:80]
PY
echo "PASS: Test 6"

echo "=== Test 7: Mutant 12 & F7 & F8 - Path traversal rejection & no escaped dirs ==="
set +e
ESCAPED_TARGET="${FSS_E2E_LOG_DIR}/../../escaped_dir_m12_test_$$"
T7_OUT=$(
    source "$LIB"
    e2e_init "../../escaped_dir_m12_test_$$" "fss-2h5zq.1" 2>&1
)
T7_EXIT=$?
set -e
if [[ $T7_EXIT -eq 0 ]]; then
    echo "FAIL: Path traversal suite name was accepted!" >&2
    exit 1
fi
if [[ ! "$T7_OUT" =~ "invalid suite name" ]]; then
    echo "FAIL: M12 mutant survived: e2e_init did not output invalid suite name error (got: $T7_OUT)" >&2
    exit 1
fi
if [[ -d "$ESCAPED_TARGET" || -d "${REPO_ROOT}/escaped" || -d "${TEST_SANDBOX}/escaped" ]]; then
    echo "FAIL: M12 mutant survived: escaped directory exists outside log root!" >&2
    exit 1
fi
echo "PASS: Test 7"

echo "=== Test 8: Mutant 14 / N40 / N29 - Forensics tmpdir preserved on fail, listed, kept across a passing run ==="
SUITE8_DIR="${TEST_SANDBOX}/suite8"
new_script "${SUITE8_DIR}/run_fail.sh" <<'EOF'
e2e_init "suite8_tmp" "fss-2h5zq.1"
TMP=$(e2e_tmpdir)
echo "data1" > "${TMP}/data.txt"
echo "$TMP" > "${T8_DIR}/tmp_fail.txt"
e2e_expect_eq "must_fail" "expected_val" "observed_val"
e2e_summary
EOF
run t8fail env T8_DIR="$SUITE8_DIR" "${SUITE8_DIR}/run_fail.sh"
if [[ $RC -eq 0 ]]; then
    echo "FAIL: run_fail.sh should have exited non-zero" >&2
    exit 1
fi
TMP_FAIL=$(cat "${SUITE8_DIR}/tmp_fail.txt")
if [[ ! -d "$TMP_FAIL" ]]; then
    echo "FAIL: Forensics tmpdir $TMP_FAIL was not preserved on failure!" >&2
    exit 1
fi
check_contains "T8 forensics event" "forensics_preserved" "$OUT"
LOG8="$(logdir suite8_tmp)/run_0001.log"
check_valid "$LOG8"
check_eq "T8 preserved_tmpdirs" "$(lt json - "$TMP_FAIL")" "$(lt summary "$LOG8" preserved_tmpdirs)"
[[ -f "${LOG8}.tmpdirs" ]] || fail "T8: ${LOG8}.tmpdirs missing"
# Directory mode skips the .tmpdirs side file (its name starts with run_) and the tmp_ dirs.
python3 "$VALIDATOR" "$(logdir suite8_tmp)" > /dev/null || fail "T8: validator dir mode rejected $(logdir suite8_tmp)"

new_script "${SUITE8_DIR}/run_pass.sh" <<'EOF'
e2e_init "suite8_tmp" "fss-2h5zq.1"
TMP=$(e2e_tmpdir)
echo "data2" > "${TMP}/data2.txt"
echo "$TMP" > "${T8_DIR}/tmp_pass.txt"
e2e_step "step_pass" echo "ok"
e2e_summary
EOF
run t8pass env T8_DIR="$SUITE8_DIR" "${SUITE8_DIR}/run_pass.sh"
check_eq "T8 pass rc" 0 "$RC"
TMP_PASS=$(cat "${SUITE8_DIR}/tmp_pass.txt")
# Kills M14: Run 1's tmpdir must STILL exist, while Run 2's tmpdir must be deleted!
if [[ ! -d "$TMP_FAIL" ]]; then
    echo "FAIL: M14 mutant survived: Run 1 tmpdir was deleted after Run 2 passed!" >&2
    exit 1
fi
if [[ -d "$TMP_PASS" ]]; then
    echo "FAIL: Run 2 tmpdir was not cleaned up on pass!" >&2
    exit 1
fi
check_eq "T8 pass preserved_tmpdirs" '[]' "$(lt summary "$(logdir suite8_tmp)/run_0002.log" preserved_tmpdirs)"
python3 "$VALIDATOR" "$(logdir suite8_tmp)" > /dev/null || fail "T8: validator dir mode rejected the suite dir after run 2"
echo "PASS: Test 8"

echo "=== Test 9: Mutant 15 & F9 - Strict JSON type comparison (1 vs '1', 1 vs true, 1 vs 1.0) ==="
S="${TEST_SANDBOX}/suite9/run.sh"
mkdir -p "$(dirname "$S")"
{
    printf '#!/usr/bin/env bash\nMODE="${1:-}"\nset --\nsource %q\n' "$LIB"
    cat <<'EOF'
e2e_init "suite9" "fss-2h5zq.1"
case "$MODE" in
    str)   e2e_expect_json_field "s" '{"a":1}' .a '"1"' ;;
    bool)  e2e_expect_json_field "b" '{"a":1}' .a true ;;
    float) e2e_expect_json_field "f" '{"a":1}' .a 1.0 ;;
    pass)  e2e_expect_json_field "p" '{"a":1}' .a 1 ;;
esac
e2e_summary
EOF
} > "$S"
chmod +x "$S"
run t9s "$S" str
RC_STR=$RC
run t9b "$S" bool
RC_BOOL=$RC
run t9f "$S" float
RC_FLOAT=$RC
run t9p "$S" pass
RC_PASS=$RC
if [[ $RC_STR -eq 0 || $RC_BOOL -eq 0 || $RC_FLOAT -eq 0 || $RC_PASS -ne 0 ]]; then
    echo "FAIL: M15 mutant survived! Strict types not enforced: str=$RC_STR bool=$RC_BOOL float=$RC_FLOAT pass=$RC_PASS" >&2
    exit 1
fi
echo "PASS: Test 9"

echo "=== Test 10: Mutant 16 - Unknown argument rejection ==="
S="${TEST_SANDBOX}/suite10/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite10" "fss-2h5zq.1" "$@"
e2e_step "s" echo hi
e2e_summary
EOF
run t10 "$S" --bogus-unknown-flag
if [[ $RC -eq 0 ]]; then
    echo "FAIL: Unknown argument was accepted without error!" >&2
    exit 1
fi
check_contains "T10 (M16) unrecognized argument message" "unrecognized argument: --bogus-unknown-flag" "$OUT"
echo "PASS: Test 10"

echo "=== Test 11: Mutant 8 - CAPLOG verdict enum validation ==="
S="${TEST_SANDBOX}/suite11/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite11" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_bad_verdict"
e2e_summary
EOF
run t11 env STUB_RCH_MODE=bad_verdict "$S"
if [[ $RC -eq 0 ]]; then
    echo "FAIL: M8 mutant survived: CAPLOG with verdict 'bogus' was accepted with exit 0!" >&2
    exit 1
fi
LOG11="$(logdir suite11)/run_0001.log"
check_valid "$LOG11"
check_contains "T11 (M8) malformed CAPLOG" "malformed CAPLOG line observed" "$LOG11"
check_eq "T11 failures" '["test_bad_verdict"]' "$(lt summary "$LOG11" failures)"
echo "PASS: Test 11"

echo "=== Test 12: Mutant 9 - Trap fails closed on uninitialized abort ==="
set +e
ERR_M9=$(bash -c 'source "'"${LIB}"'"; exit 42' 2>&1)
EXIT_M9=$?
set -e
if [[ $EXIT_M9 -ne 1 ]]; then
    echo "FAIL: M9 mutant survived: uninitialized EXIT trap did not exit 1 (got $EXIT_M9)!" >&2
    exit 1
fi
if [[ ! "$ERR_M9" =~ "failing closed" ]]; then
    echo "FAIL: M9 mutant survived: expected 'failing closed' in stderr, got: $ERR_M9" >&2
    exit 1
fi
echo "PASS: Test 12"

echo "=== Test 13: Mutant 11 - Plant secret in CAPLOG expected and observed ==="
S="${TEST_SANDBOX}/suite13/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite13" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_secret_caplog"
e2e_summary
EOF
run t13 env STUB_RCH_MODE=secret_caplog STUB_RCH_TARGET=test_secret_caplog "$S"
check_eq "T13 rc" 0 "$RC"
LOG13="$(logdir suite13)/run_0001.log"
check_valid "$LOG13"
if grep -q "ghp_EXPECTEDSECRET" "$LOG13" || grep -q "ghp_OBSERVEDSECRET" "$LOG13"; then
    echo "FAIL: M11 mutant survived: secret in CAPLOG line was not sanitized!" >&2
    exit 1
fi
echo "PASS: Test 13"

echo "=== Test 14: the summary repro string is executed and reruns exactly the failing steps ==="
S="${TEST_SANDBOX}/suite14/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite14" "fss-2h5zq.1" "$@"
e2e_step "step_a" echo "A"
e2e_expect_eq "step_b" "expected_val" "${T14_OBSERVED:-expected_val}"
e2e_cargo_test "fss-cli" "test_target"
e2e_summary
EOF
REL14="$(rel "$S")"
LOG14_DIR="$(logdir suite14)"
run_repro() {  # run_repro <tag> <repro> <env...>: execute the repro string from the repo root
    local tag="$1" repro="$2"
    shift 2
    reset_calls
    run "$tag" env "$@" bash -c 'cd "$1" && eval "$2"' _ "$REPO_ROOT" "$repro"
}
# (a) mixed: a regular failure plus a failing CAPLOG step
run t14a env STUB_RCH_MODE=fail T14_OBSERVED=actual_val "$S"
check_ne "T14a rc" 0 "$RC"
check_valid "${LOG14_DIR}/run_0001.log"
REPRO14=$(lt summary_str "${LOG14_DIR}/run_0001.log" repro)
check_eq "T14a repro" "${REL14} --only step_b,test_target" "$REPRO14"
run_repro t14a_rerun "$REPRO14" STUB_RCH_MODE=fail T14_OBSERVED=actual_val
check_ne "T14a rerun rc" 0 "$RC"
check_valid "${LOG14_DIR}/run_0002.log"
check_eq "T14a rerun steps" '["step_b", "test_target_fail"]' "$(lt steps "${LOG14_DIR}/run_0002.log")"
check_eq "T14a rerun reran the cargo target" 1 "$(calls)"
# ... and once both are fixed the same repro passes
run_repro t14a_fixed "$REPRO14" STUB_RCH_MODE=pass T14_OBSERVED=expected_val
check_eq "T14a fixed rerun rc" 0 "$RC"
check_eq "T14a fixed rerun steps" '["step_b", "test_target"]' "$(lt steps "${LOG14_DIR}/run_0003.log")"
# (b) regular-only failure: the repro does not rerun the cargo target
run t14b env STUB_RCH_MODE=pass T14_OBSERVED=actual_val "$S"
REPRO14B=$(lt summary_str "${LOG14_DIR}/run_0004.log" repro)
check_eq "T14b repro" "${REL14} --only step_b" "$REPRO14B"
run_repro t14b_rerun "$REPRO14B" STUB_RCH_MODE=pass T14_OBSERVED=actual_val
check_eq "T14b rerun steps" '["step_b"]' "$(lt steps "${LOG14_DIR}/run_0005.log")"
check_eq "T14b rerun rch calls" 0 "$(calls)"
if grep -q '"step": "step_a"' "${LOG14_DIR}/run_0005.log"; then
    echo "FAIL: step_a was run during repro execution when only step_b should run!" >&2
    exit 1
fi
# (c) CAPLOG-only failure: the repro names the cargo target, which reruns
run t14c env STUB_RCH_MODE=fail T14_OBSERVED=expected_val "$S"
REPRO14C=$(lt summary_str "${LOG14_DIR}/run_0006.log" repro)
check_eq "T14c repro" "${REL14} --only test_target" "$REPRO14C"
run_repro t14c_rerun "$REPRO14C" STUB_RCH_MODE=fail T14_OBSERVED=expected_val
check_eq "T14c rerun steps" '["test_target_fail"]' "$(lt steps "${LOG14_DIR}/run_0007.log")"
check_eq "T14c rerun rch calls" 1 "$(calls)"
echo "PASS: Test 14"

echo "=== Test 15: N31 - Ingester safe_int: duration_ms 1e400 and exit \"boom\" are coerced to ints ==="
S="${TEST_SANDBOX}/suite15/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite15" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_inf"
set +e
e2e_summary
EOF
run t15 env STUB_RCH_MODE=inf "$S"
check_eq "T15 rc" 1 "$RC"
LOG15="$(logdir suite15)/run_0001.log"
check_valid "$LOG15"
check_eq "T15 summary verdict" '"fail"' "$(lt summary "$LOG15" verdict)"
check_eq "T15 failures" '["inf_step"]' "$(lt summary "$LOG15" failures)"
check_eq "T15 inf_step verdict" '"fail"' "$(lt record "$LOG15" inf_step verdict)"
[[ "$(lt record "$LOG15" inf_step duration_ms)" =~ ^[0-9]+$ ]] || fail "T15: inf_step duration_ms is not an int"
check_eq "T15 str_exit exit" 0 "$(lt record "$LOG15" str_exit exit)"
[[ "$(lt record "$LOG15" str_exit duration_ms)" =~ ^[0-9]+$ ]] || fail "T15: str_exit duration_ms is not an int"
echo "PASS: Test 15"

echo "=== Test 16: N31 - a crashed CAPLOG ingester (py_rc) fails the target through its own record ==="
S="${TEST_SANDBOX}/suite16/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite16" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_vanish"
e2e_summary
EOF
run t16 env STUB_RCH_MODE=vanish "$S"
check_eq "T16 rc" 1 "$RC"
LOG16="$(logdir suite16)/run_0001.log"
check_valid "$LOG16"
check_eq "T16 failures" '["test_vanish"]' "$(lt summary "$LOG16" failures)"
check_contains "T16 ingester failure recorded" "CAPLOG ingester exited with status" "$LOG16"
check_eq "T16 repro" "$(rel "$S") --only test_vanish" "$(lt summary_str "$LOG16" repro)"
echo "PASS: Test 16"

echo "=== Test 17: N32-N35 - keyword-line drop in every field; URL, --password and mysql -p redaction ==="
S="${TEST_SANDBOX}/suite17/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite17" "fss-2h5zq.1"
e2e_step cmd_kw -- echo "password hunter S3CMDAA"
e2e_step out_kw -- printf '%s\n' "Authorization: Basic S3KWEE" "keep_this_line" "password hunter S3KWFF" "X-Auth-Token S3KWGG" "secret is S3KWHH" "Cookie: S3KWII" "https://user:S3URLAA@example.invalid/x" "mysql -pS3MYDD" "--password S3PWBB"
e2e_step err_kw -- bash -c 'echo "password hunter S3KWJJ" >&2; echo "keep_err_line" >&2'
e2e_expect_eq eq_kw "password hunter S3EQKK" "secret is S3EQLL"
e2e_expect_eq eq_url "https://u:S3EQMM@h.invalid/x" "mysql -pS3EQNN"
e2e_step for_exit -- true
e2e_expect_exit for_exit "password hunter S3EXOO"
e2e_expect_json_field jf_doc '{"a":"password hunter S3JFQQ","b":"https://u:S3JFUU@h.invalid/"}' .a "x"
e2e_expect_json_field jf_whole '{"a":"password hunter S3JFVV","b":"https://u:S3JFWW@h.invalid/"}' . '{}'
e2e_expect_json_field jf_exp '{"a":1}' .a "secret is S3JFRR"
e2e_expect_json_field jf_keyerr '{"a":1}' ".$MYPASS" 1
e2e_skip skip_kw "Authorization: Basic S3SKSS"
e2e_skip skip_url "see https://u:S3SKTT@h.invalid/ and mysql -pS3SKUU"
e2e_cargo_test fss-cli test_kw
e2e_summary
EOF
run t17 env STUB_RCH_MODE=kwcaplog MYPASS=hunterS3ENVVAL0003 "$S"
check_eq "T17 rc (failing expectations)" 1 "$RC"
LOG17="$(logdir suite17)/run_0001.log"
check_valid "$LOG17"
T17_NEEDLES=(S3CMDAA S3KWEE S3KWFF S3KWGG S3KWHH S3KWII S3URLAA S3MYDD S3PWBB S3KWJJ S3EQKK S3EQLL S3EQMM
    S3EQNN S3EXOO S3JFQQ S3JFUU S3JFVV S3JFWW S3JFRR hunterS3ENVVAL0003 S3SKSS S3SKTT S3SKUU KWCAA KWCBB KWCCC
    KWCDD KWCEE KWCFF KWCGG KWCHH KWCII KWCJJ KWCKK KWCLL KWCMM KWCNN)
check_no_leaks "$LOG17" "${T17_NEEDLES[@]}"
check_no_leaks "$OUT" "${T17_NEEDLES[@]}"
# The drop is line-scoped, and the in-line rules redact rather than drop.
check_eq "T17 step output" '"keep_this_line\nhttps://user:<redacted>@example.invalid/x\nmysql -p<redacted>\n"' "$(lt record "$LOG17" out_kw stdout_excerpt)"
check_eq "T17 step stderr" '"keep_err_line\n"' "$(lt record "$LOG17" err_kw stderr_excerpt)"
check_eq "T17 step cmd" '""' "$(lt record "$LOG17" cmd_kw cmd)"
check_eq "T17 expect_eq values" '["e2e_expect_eq", "eq_kw", "", ""]' "$(lt record "$LOG17" eq_kw cmd)"
check_eq "T17 expect_eq url/mysql" '"https://u:<redacted>@h.invalid/x"' "$(lt record "$LOG17" eq_url expected)"
check_eq "T17 expect_exit expected" '""' "$(lt record "$LOG17" for_exit_exit expected)"
check_eq "T17 json whole doc" '{"a": "", "b": "https://u:<redacted>@h.invalid/"}' "$(lt record "$LOG17" jf_whole observed)"
check_eq "T17 summary.skipped" '[{"step": "skip_kw", "reason": ""}, {"step": "skip_url", "reason": "see https://u:<redacted>@h.invalid/ and mysql -p<redacted>"}]' "$(lt summary "$LOG17" skipped)"
check_eq "T17 CAPLOG excerpt" '"keep_caplog_line"' "$(lt record "$LOG17" kw stdout_excerpt)"
# The CAPLOG expected list is ["password hunter KWCFF", "https://u:KWCHH@h.invalid/x", "mysql -pKWCII"]:
# element 0 is dropped as a keyword line, so its "password ..." label wholesale-redacts element 1.
check_eq "T17 CAPLOG expected" '["", "<redacted>", "mysql -p<redacted>"]' "$(lt record "$LOG17" kw expected)"
# The list-form CAPLOG cmd ["mysql","-pKWCJJ","--password=KWCLL"] is sanitized as one joined string;
# it names --password, so the whole cmd line is dropped (L3, no per-element leak).
check_eq "T17 CAPLOG cmd" '""' "$(lt record "$LOG17" kw cmd)"
# The CAPLOG record's repro is rebuilt from the trusted script path plus the sanitized step id,
# never from the CAPLOG's own (untrusted) repro field, so no needle can reach it.
check_eq "T17 CAPLOG repro" "\"$(rel "$S") --only kw\"" "$(lt record "$LOG17" kw repro)"
echo "PASS: Test 17"

echo "=== Test 18: N36 - the rch exit-103 retry is bounded (1 attempt + 3 retries) ==="
S="${TEST_SANDBOX}/suite18/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite18" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_r103"
e2e_summary
EOF
reset_calls
run t18 env STUB_RCH_MODE=r103 timeout 60 "$S"
check_ne "T18 rc (timeout means the retry is unbounded)" 124 "$RC"
check_eq "T18 rc" 1 "$RC"
check_eq "T18 attempts" 4 "$(calls)"
LOG18="$(logdir suite18)/run_0001.log"
check_valid "$LOG18"
check_eq "T18 observed" '"cargo test failed (exit 103); no CAPLOG line observed"' "$(lt record "$LOG18" test_r103 observed)"
echo "PASS: Test 18"

echo "=== Test 19: N37 - the EXIT trap blames the running step or <script>:exit, never the last passing step ==="
# (a) the script dies after a passing step
S="${TEST_SANDBOX}/suite19a/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite19a" "fss-2h5zq.1"
e2e_step "good" echo "fine"
false
e2e_summary
EOF
run t19a "$S"
check_eq "T19a rc" 1 "$RC"
LOG19A="$(logdir suite19a)/run_0001.log"
check_valid "$LOG19A"
check_eq "T19a failures" '["run.sh:exit"]' "$(lt summary "$LOG19A" failures)"
check_eq "T19a passing step untouched" '"ran"' "$(lt record "$LOG19A" good verdict)"
check_eq "T19a exit record" '"fail"' "$(lt record "$LOG19A" run.sh:exit verdict)"
check_eq "T19a repro reruns the script" "$(rel "$S")" "$(lt summary_str "$LOG19A" repro)"
# (b) the script exits while a step runs; the blame names that step's record (boom_1), not the
#     raw step name, which an earlier passing record already uses
S="${TEST_SANDBOX}/suite19b/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite19b" "fss-2h5zq.1"
e2e_step "boom" echo "fine"
e2e_step "boom" exit 7
e2e_summary
EOF
run t19b "$S"
check_eq "T19b rc" 1 "$RC"
LOG19B="$(logdir suite19b)/run_0001.log"
check_valid "$LOG19B"
check_eq "T19b failures" '["boom_1"]' "$(lt summary "$LOG19B" failures)"
check_eq "T19b passing record untouched" '"ran"' "$(lt record "$LOG19B" boom verdict)"
check_eq "T19b exit code" 7 "$(lt record "$LOG19B" boom_1 exit)"
check_eq "T19b repro" "$(rel "$S") --only boom" "$(lt summary_str "$LOG19B" repro)"
# (c) SIGTERM while e2e_cargo_test runs: the cargo target is the running step
S="${TEST_SANDBOX}/suite19c/run.sh"
new_script "$S" <<'EOF'
export E2E_TEST_SCRIPT_PID=$$
e2e_init "suite19c" "fss-2h5zq.1"
e2e_step "before" echo "fine"
e2e_cargo_test "fss-cli" "test_term"
e2e_summary
EOF
run t19c env STUB_RCH_MODE=term timeout 60 "$S"
check_eq "T19c rc" 1 "$RC"
LOG19C="$(logdir suite19c)/run_0001.log"
check_valid "$LOG19C"
check_eq "T19c failures" '["test_term"]' "$(lt summary "$LOG19C" failures)"
check_eq "T19c repro" "$(rel "$S") --only test_term" "$(lt summary_str "$LOG19C" repro)"
# (d) e2e_skip dies (injected engine failure): the skip is the running step
S="${TEST_SANDBOX}/suite19d/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite19d" "fss-2h5zq.1"
e2e_step "before" echo "fine"
e2e_skip "skip_me" "oracle absent"
e2e_summary
EOF
run t19d env PATH="${PYFAIL_DIR}:${PATH}" E2E_TEST_FAIL_PY_MODE=skip_record "$S"
check_eq "T19d rc" 1 "$RC"
LOG19D="$(logdir suite19d)/run_0001.log"
check_valid "$LOG19D"
check_eq "T19d failures" '["skip_me"]' "$(lt summary "$LOG19D" failures)"
echo "PASS: Test 19"

echo "=== Test 20: N38 - suite names '.' and '..' are refused ==="
for bad in "." ".."; do
    T20_LOGS="${TEST_SANDBOX}/t20logs"
    rm -rf "$T20_LOGS"
    run t20 env FSS_E2E_LOG_DIR="$T20_LOGS" bash -c 'lib=$1 name=$2; set --; source "$lib"; e2e_init "$name" "fss-2h5zq.1"' _ "$LIB" "$bad"
    check_ne "T20 rc for '$bad'" 0 "$RC"
    check_contains "T20 message for '$bad'" "invalid suite name '${bad}'" "$OUT"
    if [[ -e "${T20_LOGS}/run_0001.log" ]]; then
        fail "T20: suite name '$bad' created ${T20_LOGS}/run_0001.log"
    fi
done
echo "PASS: Test 20"

echo "=== Test 21: N39 - e2e_summary without e2e_init fails closed ==="
run t21a env FSS_E2E_LOG_DIR="${TEST_SANDBOX}/t21logs" bash -c 'lib=$1; set --; source "$lib"; trap - EXIT; e2e_summary; echo "after summary rc=$?"' _ "$LIB"
check_eq "T21a rc" 1 "$RC"
check_contains "T21a message" "E2E uninitialized or log file not set (failing closed)" "$OUT"
check_absent "T21a returned" "after summary" "$OUT"
run t21b env FSS_E2E_LOG_DIR="${TEST_SANDBOX}/t21logs" bash -c 'lib=$1; set --; source "$lib"; e2e_summary' _ "$LIB"
check_eq "T21b rc" 1 "$RC"
[[ ! -e "${TEST_SANDBOX}/t21logs" ]] || fail "T21: e2e_summary without init created a log dir"
echo "PASS: Test 21"

echo "=== Test 22: N41 - the log cap never counts an unwritten record ==="
S="${TEST_SANDBOX}/suite22/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite22" "fss-2h5zq.1"
big=$(python3 -c 'print("q" * 4000)')
big2=$(python3 -c 'print("w" * 4000)')
i=0
while (( i < 200 )); do
    i=$((i + 1))
    e2e_expect_eq "f$i" "$big" "$big2"
done
echo "cap never reached" >&2
e2e_summary
EOF
run t22 env FSS_E2E_MAX_LOG_BYTES=262144 timeout 300 "$S"
check_eq "T22 rc" 1 "$RC"
check_contains "T22 cap message" "log cap exceeded" "$OUT"
check_absent "T22 cap reached" "cap never reached" "$OUT"
LOG22="$(logdir suite22)/run_0001.log"
check_valid "$LOG22"
check_eq "T22 consistent" ok "$(lt consistent "$LOG22")"
check_eq "T22 one summary" 1 "$(lt summaries "$LOG22")"
check_eq "T22 summary verdict" '"fail"' "$(lt summary "$LOG22" verdict)"
(( $(wc -c < "$LOG22") <= 262144 )) || fail "T22: log exceeds the cap"
echo "PASS: Test 22"

echo "=== Test 23: N43/N44 - CAPLOG step names and bead ids are sanitized ==="
S="${TEST_SANDBOX}/suite23/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite23" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_leakname"
e2e_summary
EOF
run t23 env STUB_RCH_MODE=leakname DEPLOY_TOKEN_T23=hunterBEADVAL0004 "$S"
check_eq "T23 rc" 0 "$RC"
LOG23="$(logdir suite23)/run_0001.log"
check_valid "$LOG23"
check_no_leaks "$LOG23" STEPLEAK BEADLEAK hunterBEADVAL0004
[[ "$(lt steps "$LOG23")" =~ ^\[\"redacted_[0-9a-f]{16}\",\ \"plain_step\"\]$ ]] || fail "T23: unexpected step ids $(lt steps "$LOG23")"
check_eq "T23 bead" '"<redacted>"' "$(lt record "$LOG23" plain_step bead)"
echo "PASS: Test 23"

echo "=== Test 24: N45 - the e2e_expect_exit cmd is sanitized ==="
S="${TEST_SANDBOX}/suite24/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite24" "fss-2h5zq.1"
e2e_step "s" true
e2e_expect_exit "s" "$DEPLOY_KEY_T24"
e2e_summary
EOF
run t24 env DEPLOY_KEY_T24=hunterEXITVAL0005 "$S"
check_eq "T24 rc" 1 "$RC"
LOG24="$(logdir suite24)/run_0001.log"
check_valid "$LOG24"
check_no_leaks "$LOG24" hunterEXITVAL0005
check_eq "T24 cmd" '["e2e_expect_exit", "s_exit", "<redacted>"]' "$(lt record "$LOG24" s_exit cmd)"
echo "PASS: Test 24"

echo "=== Test 25: e2e_summary in a subshell never leads to a second summary ==="
S="${TEST_SANDBOX}/suite25/run_a.sh"
new_script "$S" <<'EOF'
e2e_init "suite25a" "fss-2h5zq.1"
e2e_step "ok" true
( e2e_summary )
echo "parent continues"
EOF
run t25a "$S"
check_eq "T25a rc" 0 "$RC"
LOG25A="$(logdir suite25a)/run_0001.log"
check_valid "$LOG25A"
check_eq "T25a summaries" 1 "$(lt summaries "$LOG25A")"
check_contains "T25a parent ran on" "parent continues" "$OUT"
check_contains "T25a note" "not writing a second summary" "$OUT"
S="${TEST_SANDBOX}/suite25/run_b.sh"
new_script "$S" <<'EOF'
e2e_init "suite25b" "fss-2h5zq.1"
e2e_step "ok" true
captured=$(e2e_summary)
e2e_step "late" true
EOF
run t25b "$S"
check_ne "T25b rc" 0 "$RC"
LOG25B="$(logdir suite25b)/run_0001.log"
check_valid "$LOG25B"
check_eq "T25b summaries" 1 "$(lt summaries "$LOG25B")"
check_eq "T25b steps" '["ok"]' "$(lt steps "$LOG25B")"
check_contains "T25b refusal" "after the summary record" "$OUT"
S="${TEST_SANDBOX}/suite25/run_c.sh"
new_script "$S" <<'EOF'
e2e_init "suite25c" "fss-2h5zq.1"
e2e_expect_eq "bad" "a" "b"
( e2e_summary ) || true
exit 0
EOF
run t25c "$S"
check_eq "T25c rc follows the fail verdict" 1 "$RC"
check_eq "T25c summaries" 1 "$(lt summaries "$(logdir suite25c)/run_0001.log")"
echo "PASS: Test 25"

echo "=== Test 26: e2e_summary checks the validator: never a pass summary over an invalid log ==="
S="${TEST_SANDBOX}/suite26/run_a.sh"
new_script "$S" <<'EOF'
e2e_init "suite26a" "fss-2h5zq.1"
e2e_step "ok" true
printf '%s\n' '{"step": "bogus"}' >> "$_E2E_LOG_FILE"
set +e
e2e_summary
echo "unreachable"
EOF
run t26a "$S"
check_eq "T26a rc" 1 "$RC"
LOG26A="$(logdir suite26a)/run_0001.log"
check_eq "T26a summary verdict" '"fail"' "$(lt summary "$LOG26A" verdict)"
check_eq "T26a no pass summary" 0 "$(lt pass_summaries "$LOG26A")"
check_contains "T26a validator message" "failed validation" "$OUT"
check_absent "T26a returned" "unreachable" "$OUT"
S="${TEST_SANDBOX}/suite26/run_b.sh"
new_script "$S" <<'EOF'
e2e_init "suite26_${STUB_RCH_MODE}" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_caplog_shape"
set +e
e2e_summary
EOF
for mode in badts badtype; do
    run "t26_$mode" env STUB_RCH_MODE="$mode" "$S"
    check_eq "T26 $mode rc" 1 "$RC"
    LOG26="$(logdir "suite26_$mode")/run_0001.log"
    check_valid "$LOG26"
    check_eq "T26 $mode verdict" '"fail"' "$(lt summary "$LOG26" verdict)"
    check_contains "T26 $mode malformed" "malformed CAPLOG line observed" "$LOG26"
done
run t26_secretkey env STUB_RCH_MODE=secretkey "$S"
check_eq "T26 secretkey rc" 0 "$RC"
LOG26="$(logdir suite26_secretkey)/run_0001.log"
check_valid "$LOG26"
check_no_leaks "$LOG26" SKVAL1 '"token"'
check_eq "T26 secretkey observed" '{"<redacted key 0>": "<redacted>", "ok": 2}' "$(lt record "$LOG26" t1 observed)"
run t26_huge env STUB_RCH_MODE=huge "$S"
check_eq "T26 huge rc" 0 "$RC"
LOG26="$(logdir suite26_huge)/run_0001.log"
check_valid "$LOG26"
(( $(lt max_line "$LOG26") <= 65536 )) || fail "T26: a record line exceeds 64 KiB"
[[ "$(lt record "$LOG26" t1 expected)" == '"<omitted: '* ]] || fail "T26: oversized expected was not replaced"
echo "PASS: Test 26"

echo "=== Test 27: short ghp_ tokens (12 characters) are redacted ==="
S="${TEST_SANDBOX}/suite27/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite27" "fss-2h5zq.1"
e2e_step "short_token" echo "ghp_ABCDEFGHIJKL"
e2e_summary
EOF
run t27 "$S"
check_eq "T27 rc" 0 "$RC"
LOG27="$(logdir suite27)/run_0001.log"
check_valid "$LOG27"
check_no_leaks "$LOG27" ghp_ABCDEFGHIJKL
echo "PASS: Test 27"

echo "=== Test 28: --list prints the steps and writes no log ==="
S="${TEST_SANDBOX}/suite28/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite28" "fss-2h5zq.1" "$@"
e2e_step "first" true
e2e_cargo_test "fss-cli" "test_target"
e2e_summary
EOF
reset_calls
run t28 "$S" --list
check_eq "T28 rc" 0 "$RC"
check_eq "T28 listing" "$(printf 'first\ntest_target')" "$(cat "$OUT")"
[[ ! -e "$(logdir suite28)" ]] || fail "T28: --list wrote a log"
check_eq "T28 rch calls" 0 "$(calls)"
echo "PASS: Test 28"

echo "=== Test 29: redaction layers each hold on their own; safe_int and key redaction ==="
python3 - "$LIB" "${TEST_SANDBOX}/t29.txt" <<'PY'
import os, re, sys
src = open(sys.argv[1], encoding="utf-8").read()
engine = src.split("<<'PYEOF' || true\n", 1)[1].split("\nPYEOF\n", 1)[0]
os.environ["T29_DEPLOY_KEY"] = "hunterLAYERVAL0006"
ns = {"__name__": "e2e_engine"}
exec(compile(engine, "lib.sh engine", "exec"), ns)


def check(cond, msg):
    if not cond:
        print("FAIL: T29:", msg)
        sys.exit(1)


S = ns["sanitize"]
check(S("keep1\npassword hunter X1\nTOKEN=x\nkeep2") == "keep1\nkeep2", "keyword lines are not dropped line by line")
# With the keyword drop switched off, every in-line rule still redacts (defense in depth).
ns["drop_line_pat"] = re.compile(r"(?!x)x")
line = "--password LAY1 --password=LAY2 https://u:LAY3@h.invalid/ mysql -pLAY4 hunterLAYERVAL0006 ghp_ABCDEFGHIJKL"
out = S(line)
for n in ("LAY1", "LAY2", "LAY3", "LAY4", "hunterLAYERVAL0006", "ghp_ABCDEFGHIJKL"):
    check(n not in out, f"sanitize() leaks {n}: {out!r}")
with open(sys.argv[2], "w") as f:
    f.write(line + "\n")
out = ns["redact_file"](sys.argv[2])
for n in ("LAY1", "LAY2", "LAY3", "LAY4", "hunterLAYERVAL0006", "ghp_ABCDEFGHIJKL"):
    check(n not in out, f"redact_file() leaks {n}: {out!r}")
si = ns["safe_int"]
check(si(float("inf"), 7) == 7 and si(1e400, 7) == 7, "safe_int does not coerce an overflowing float")
check(si(float("nan"), 7) == 7 and si("boom", 7) == 7 and si(None, 7) == 7 and si(True, 7) == 7, "safe_int coercion")
check(si("12", 7) == 12 and si(3, 7) == 3, "safe_int keeps ints")
check(ns["sanitize_data"]({"token": "v", "ok": 1}) == {"<redacted key 0>": "<redacted>", "ok": 1}, "secret-like keys")
print("T29 layer checks ok")
PY
echo "PASS: Test 29"

echo "=== Test 30: CAPLOG skip records reach summary.skipped; skips never count as passes ==="
S="${TEST_SANDBOX}/suite30/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite30_${STUB_RCH_MODE}" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_skips"
e2e_summary
EOF
run t30a env STUB_RCH_MODE=caplog_skip "$S"
check_eq "T30a rc" 0 "$RC"
LOG30="$(logdir suite30_caplog_skip)/run_0001.log"
check_valid "$LOG30"
check_eq "T30a skipped" '[{"step": "b", "reason": "{\"r\": \"oracle absent\"}"}]' "$(lt summary "$LOG30" skipped)"
check_eq "T30a verdict" '"pass"' "$(lt summary "$LOG30" verdict)"
run t30b env STUB_RCH_MODE=caplog_allskip "$S"
check_eq "T30b rc" 1 "$RC"
LOG30="$(logdir suite30_caplog_allskip)/run_0001.log"
check_eq "T30b verdict" '"fail"' "$(lt summary "$LOG30" verdict)"
check_eq "T30b no pass summary" 0 "$(lt pass_summaries "$LOG30")"
check_eq "T30b skipped" '[{"step": "b", "reason": "oracle absent"}]' "$(lt summary "$LOG30" skipped)"
echo "PASS: Test 30"

echo "=== Test 31: F1 - exit 0 without an explicit e2e_summary is a FAIL, never a pass ==="
S="${TEST_SANDBOX}/suite31/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite31" "fss-2h5zq.1"
e2e_step "a" true
exit 0
EOF
run t31 "$S"
check_eq "T31 rc" 1 "$RC"
LOG31="$(logdir suite31)/run_0001.log"
check_valid "$LOG31"
check_eq "T31 verdict" '"fail"' "$(lt summary "$LOG31" verdict)"
check_eq "T31 no pass summary" 0 "$(lt pass_summaries "$LOG31")"
check_eq "T31 failures" '["run.sh:exit"]' "$(lt summary "$LOG31" failures)"
check_eq "T31 passing step untouched" '"ran"' "$(lt record "$LOG31" a verdict)"
echo "PASS: Test 31"

echo "=== Test 32: F2 - a replaced EXIT trap fails closed; e2e_on_exit runs cleanups instead ==="
# (a) the script installs its own EXIT trap, then an API call must refuse to continue
S="${TEST_SANDBOX}/suite32a/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite32a" "fss-2h5zq.1"
trap 'echo my-own-cleanup >&2' EXIT
e2e_step "after_trap" true
e2e_summary
EOF
run t32a "$S"
check_eq "T32a rc" 1 "$RC"
check_contains "T32a message" "EXIT trap has been replaced" "$OUT"
# (b) e2e_on_exit registers a cleanup that the harness trap runs, and the summary is still written
S="${TEST_SANDBOX}/suite32b/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite32b" "fss-2h5zq.1"
e2e_on_exit 'echo registered-cleanup-ran >&2'
e2e_step "ok" true
e2e_summary
EOF
run t32b "$S"
check_eq "T32b rc" 0 "$RC"
check_contains "T32b cleanup ran" "registered-cleanup-ran" "$OUT"
check_eq "T32b verdict" '"pass"' "$(lt summary "$(logdir suite32b)/run_0001.log" verdict)"
echo "PASS: Test 32"

echo "=== Test 33: F4 - a forged summary prefix on disk does not yield exit 0 ==="
S="${TEST_SANDBOX}/suite33/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite33" "fss-2h5zq.1"
e2e_step "a" true
printf '%s\n' '{"step": "summary", "verdict": "pass", garbage not json' >> "$_E2E_LOG_FILE"
exit 0
EOF
run t33 "$S"
check_eq "T33 rc (forged pass prefix must not pass)" 1 "$RC"
echo "PASS: Test 33"

echo "=== Test 34: L1 - credential redaction (-u, scp-like user:pass@host, URL passwords with : or @) ==="
S="${TEST_SANDBOX}/suite34/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite34" "fss-2h5zq.1"
e2e_step "curl_u" -- echo "curl -u admin:L1USERPASS https://h.invalid/"
e2e_step "scp" -- echo "git clone deploy:L1SCPPW@git.invalid:r.git"
e2e_step "url_colon" -- echo "https://u:L1COLA:L1COLB@h.invalid/"
e2e_step "url_at" -- echo "https://u:p@L1ATX@h.invalid/"
e2e_expect_eq "eq_u" "curl -u admin:L1EQPASS" "x"
e2e_cargo_test "fss-cli" "leak1_contract"
e2e_summary
EOF
run t34 env STUB_RCH_MODE=cred_list "$S"
check_ne "T34 rc" 0 "$RC"
LOG34="$(logdir suite34)/run_0001.log"
check_valid "$LOG34"
check_no_leaks "$LOG34" L1USERPASS L1SCPPW L1COLA L1COLB L1ATX L1EQPASS L1CAPU L1CAPSCP
check_no_leaks "$OUT" L1USERPASS L1SCPPW L1COLA L1COLB L1ATX L1EQPASS L1CAPU L1CAPSCP
check_eq "T34 -u redacted" '"curl -u <redacted> https://h.invalid/\n"' "$(lt record "$LOG34" curl_u stdout_excerpt)"
check_eq "T34 scp redacted" '"git clone deploy:<redacted>@git.invalid:r.git\n"' "$(lt record "$LOG34" scp stdout_excerpt)"
check_eq "T34 url colon redacted" '"https://u:<redacted>@h.invalid/\n"' "$(lt record "$LOG34" url_colon stdout_excerpt)"
echo "PASS: Test 34"

echo "=== Test 35: L2 - PEM private-key blocks are dropped, body lines included ==="
S="${TEST_SANDBOX}/suite35/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite35" "fss-2h5zq.1"
e2e_step "pem" -- printf '%s\n' "before line" "-----BEGIN RSA PRIVATE KEY-----" "MIIBODYL2PEMSECRET" "abcdefL2MORE" "-----END RSA PRIVATE KEY-----" "after line"
e2e_summary
EOF
run t35 "$S"
check_eq "T35 rc" 0 "$RC"
LOG35="$(logdir suite35)/run_0001.log"
check_valid "$LOG35"
check_no_leaks "$LOG35" L2PEMSECRET L2MORE "BEGIN RSA PRIVATE KEY"
check_eq "T35 excerpt" '"before line\n<redacted PEM block>\nafter line\n"' "$(lt record "$LOG35" pem stdout_excerpt)"
echo "PASS: Test 35"

echo "=== Test 36: L3/L4/L5/L6 - CAPLOG cmd join, dict keys, no borrowed excerpt, next-line drop ==="
S="${TEST_SANDBOX}/suite36/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite36" "fss-2h5zq.1"
e2e_step "nl" -- printf '%s\n' "Password:" "L6NEXTVAL" "kept line"
e2e_cargo_test "fss-cli" "leak3_contract"
e2e_summary
EOF
run t36 env STUB_RCH_MODE=leak345 "$S"
check_ne "T36 rc" 0 "$RC"
LOG36="$(logdir suite36)/run_0001.log"
check_valid "$LOG36"
check_no_leaks "$LOG36" L6NEXTVAL L3CMDU L3CMDPW L4PASS L4PASSWD L4PWD L4PK L4CRED L5BORROW
# L6: the value line after "Password:" is dropped, later lines kept
check_eq "T36 nextline drop" '"kept line\n"' "$(lt record "$LOG36" nl stdout_excerpt)"
# L4: dict keys pass/passwd/pwd/private_key/credentials redact their values
check_eq "T36 dict keys" '{"<redacted key 0>": "<redacted>", "<redacted key 1>": "<redacted>", "<redacted key 2>": "<redacted>", "<redacted key 3>": "<redacted>", "<redacted key 4>": "<redacted>", "ok": 1}' "$(lt record "$LOG36" dictstep observed)"
# L5: a CAPLOG record with no excerpt of its own does not borrow the cargo stdout excerpt
check_eq "T36 no borrowed excerpt" '""' "$(lt record "$LOG36" noexcerpt stdout_excerpt)"
# L3: a list-form CAPLOG cmd is joined and sanitized as one string (its -u user:pass redacted)
check_eq "T36 list cmd joined" '"curl -u <redacted> https://h.invalid/"' "$(lt record "$LOG36" cmdstep cmd)"
echo "PASS: Test 36"

echo "=== Test 37: item 6 - repro/script under a keyword-named script; a keyword-named step is kept ==="
SEC_DIR="${TEST_SANDBOX}/suite37"
mkdir -p "$SEC_DIR"
SEC="${SEC_DIR}/cap_secret2.sh"
{ printf '#!/usr/bin/env bash\nsource %q\n' "$LIB"; cat <<'EOF'
e2e_init "secretsuite" "fss-2h5zq.1"
e2e_step "token_bucket_refill" true
e2e_expect_eq "bad" a b
e2e_summary
EOF
} > "$SEC"
chmod +x "$SEC"
run t37 "$SEC"
check_eq "T37 rc" 1 "$RC"
LOG37="$(logdir secretsuite)/run_0001.log"
check_valid "$LOG37"
check_eq "T37 env.script kept" '"cap_secret2.sh"' "$(lt record "$LOG37" env script)"
# The keyword-named step keeps its real name (identifier sanitizer, no keyword-line drop).
check_eq "T37 token step kept" '"ran"' "$(lt record "$LOG37" token_bucket_refill verdict)"
REPRO37=$(lt summary_str "$LOG37" repro)
check_ne "T37 repro non-empty" "" "$REPRO37"
check_contains "T37 repro names the script" "cap_secret2.sh" "$LOG37"
# The failing step's own repro and the summary repro both carry the script path.
check_eq "T37 record repro" "\"$(rel "$SEC") --only bad\"" "$(lt record "$LOG37" bad repro)"
echo "PASS: Test 37"

echo "=== Test 38: CAPLOG is read from stdout AND stderr (real rch forwards remote output on stderr) ==="
S="${TEST_SANDBOX}/suite38/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite38_${STUB_RCH_MODE}" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_stderr"
e2e_summary
EOF
run t38a env STUB_RCH_MODE=stderr_only "$S"
check_eq "T38a rc" 0 "$RC"
LOG38="$(logdir suite38_stderr_only)/run_0001.log"
check_valid "$LOG38"
check_eq "T38a steps" '["e1", "e2"]' "$(lt steps "$LOG38")"
check_eq "T38a verdict" '"pass"' "$(lt summary "$LOG38" verdict)"
run t38b env STUB_RCH_MODE=split_pass_fail "$S"
check_eq "T38b rc" 1 "$RC"
LOG38="$(logdir suite38_split_pass_fail)/run_0001.log"
check_valid "$LOG38"
check_eq "T38b steps" '["s_ok", "s_bad"]' "$(lt steps "$LOG38")"
check_eq "T38b failures" '["s_bad"]' "$(lt summary "$LOG38" failures)"
check_absent "T38b no pass line" "pass summary" "$OUT"
for m in "dup_cross:duplicate step across stdout and stderr" "malformed_stderr:invalid JSON" \
        "overlong_stderr:CAPLOG line over 1 MiB"; do
    mode="${m%%:*}"
    why="${m#*:}"
    run "t38_${mode}" env STUB_RCH_MODE="$mode" "$S"
    check_eq "T38 ${mode} rc" 1 "$RC"
    LOG38="$(logdir "suite38_${mode}")/run_0001.log"
    check_valid "$LOG38"
    # A malformed stream is not trusted: none of its records survive, only the target's failure.
    check_eq "T38 ${mode} steps" '["test_stderr"]' "$(lt steps "$LOG38")"
    check_eq "T38 ${mode} failures" '["test_stderr"]' "$(lt summary "$LOG38" failures)"
    check_eq "T38 ${mode} observed" "\"malformed CAPLOG line observed: ${why}\"" "$(lt record "$LOG38" test_stderr observed)"
    check_absent "T38 ${mode} no pass line" "pass summary" "$OUT"
done
echo "PASS: Test 38"

echo "=== Test 39: an exit inside an e2e_on_exit hook never turns a failed run into exit 0 ==="
S="${TEST_SANDBOX}/suite39/run.sh"
new_script "$S" <<'EOF'
cleanup() { echo ran >> "$HOOK_MARK"; exit 0; }
e2e_init "suite39_${MODE39}" "fss-2h5zq.1"
e2e_on_exit cleanup
e2e_step a -- true
case "$MODE39" in
    hook_exit0_fail) e2e_expect_eq bad a b ;;
    hook_exit0_die) false ;;
esac
e2e_summary
EOF
for mode in hook_exit0_fail hook_exit0_die; do
    mark="${TEST_SANDBOX}/suite39/${mode}.mark"
    run "t39_${mode}" env MODE39="$mode" HOOK_MARK="$mark" "$S"
    check_eq "T39 ${mode} rc" 1 "$RC"
    LOG39="$(logdir "suite39_${mode}")/run_0001.log"
    check_valid "$LOG39"
    check_eq "T39 ${mode} verdict" '"fail"' "$(lt summary "$LOG39" verdict)"
    check_eq "T39 ${mode} one summary" 1 "$(lt summaries "$LOG39")"
    check_eq "T39 ${mode} hook ran once" 1 "$(wc -l < "$mark" | tr -d ' ')"
    check_absent "T39 ${mode} no pass line" "pass summary" "$OUT"
done
check_eq "T39 fail failures" '["bad"]' "$(lt summary "$(logdir suite39_hook_exit0_fail)/run_0001.log" failures)"
echo "PASS: Test 39"

echo "=== Test 40: lint - no scripts/e2e/cap_*.sh installs its own trap (cleanups use e2e_on_exit) ==="
LINT="${TEST_SANDBOX}/trap_lint.py"
cat <<'PY' > "$LINT"
import re
import sys

# `trap` in command position: line start, after a separator or keyword, or behind builtin/command.
CMD = re.compile(r"(?:^|[;&|({!]|\b(?:then|do|else|builtin|command)\b)\s*trap\b")
bad = []
for path in sys.argv[1:]:
    for n, line in enumerate(open(path, encoding="utf-8", errors="replace"), 1):
        if line.lstrip().startswith("#"):
            continue
        code = re.sub(r"\s#.*$", "", line.rstrip("\n"))
        if CMD.search(code):
            bad.append(f"{path}:{n}: {line.strip()}")
for b in bad:
    print(b)
sys.exit(1 if bad else 0)
PY
CAPS=()
for f in "$REPO_ROOT"/scripts/e2e/cap_*.sh; do
    [[ -f "$f" ]] && CAPS+=("$f")
done
# Every cap_*.sh present is linted (a tree without any has nothing to lint; the plants below still run).
if [[ ${#CAPS[@]} -gt 0 ]]; then
    python3 "$LINT" "${CAPS[@]}" || fail "T40: a cap_*.sh installs its own trap; register cleanups with e2e_on_exit"
fi
PLANT="${TEST_SANDBOX}/suite40"
mkdir -p "$PLANT"
# The r1e own_trap_late shape: a late trap that no later harness call can notice.
printf '%s\n' 'e2e_step a -- true' 'e2e_expect_eq bad a b' "trap 'echo own >&2' EXIT" 'exit 0' > "$PLANT/cap_late.sh"
printf '%s\n' 'e2e_step a -- true; trap -- cleanup EXIT' > "$PLANT/cap_inline.sh"
printf '%s\n' 'if true; then trap cleanup 0; fi' > "$PLANT/cap_then.sh"
printf '%s\n' 'builtin trap cleanup EXIT' > "$PLANT/cap_builtin.sh"
printf '%s\n' '  trap "rm -f x" INT TERM' > "$PLANT/cap_signal.sh"
printf '%s\n' '# trap cleanup EXIT is forbidden here' 'echo "no traps"  # trap x EXIT' > "$PLANT/cap_comment.sh"
for f in cap_late cap_inline cap_then cap_builtin cap_signal; do
    if python3 "$LINT" "$PLANT/$f.sh" > /dev/null; then
        fail "T40 lint missed ${f}"
    fi
done
python3 "$LINT" "$PLANT/cap_comment.sh" > /dev/null || fail "T40 lint flagged a comment"
echo "PASS: Test 40"

echo "=== Test 41: L6 next-line drop inside sanitize(): a skip reason and a CAPLOG excerpt ==="
S="${TEST_SANDBOX}/suite41/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite41" "fss-2h5zq.1"
e2e_step "a" -- true
e2e_skip "s" $'Password:\nL7SKIPVAL\nkept reason'
e2e_cargo_test "fss-cli" "test_pw"
e2e_summary
EOF
run t41 env STUB_RCH_MODE=pw_caplog "$S"
check_eq "T41 rc" 0 "$RC"
LOG41="$(logdir suite41)/run_0001.log"
check_valid "$LOG41"
check_no_leaks "$LOG41" L7SKIPVAL L7CAPVAL
check_contains "T41 later reason line kept" "kept reason" "$LOG41"
check_contains "T41 later excerpt line kept" "kept caplog line" "$LOG41"
echo "PASS: Test 41"

echo "=== Test 42: a background job that re-arms the harness EXIT handler never finalizes the log ==="
# Plain bash subshells reset the EXIT trap; one that (re)installs _e2e_trap_exit - directly, or by
# sourcing a helper that does - must still leave the summary to the e2e_init shell.
S="${TEST_SANDBOX}/suite42/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite42" "fss-2h5zq.1"
e2e_step "a" -- true
( trap _e2e_trap_exit EXIT; exit 0 ) &
wait $!
e2e_step "b" -- true
e2e_summary
EOF
run t42 "$S"
check_eq "T42 rc" 0 "$RC"
LOG42="$(logdir suite42)/run_0001.log"
check_valid "$LOG42"
check_eq "T42 one summary" 1 "$(lt summaries "$LOG42")"
check_eq "T42 steps" '["a", "b"]' "$(lt steps "$LOG42")"
check_eq "T42 verdict" '"pass"' "$(lt summary "$LOG42" verdict)"
echo "PASS: Test 42"

echo "=== Test 43: a failed FINAL validation of the written log fails the run (rc 1, no pass line) ==="
S="${TEST_SANDBOX}/suite43/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite43" "fss-2h5zq.1"
e2e_step "a" -- true
e2e_summary
EOF
run t43 env PATH="${PYFAIL_DIR}:${PATH}" E2E_TEST_FAIL_FINAL_VALIDATE=1 "$S"
check_eq "T43 rc" 1 "$RC"
check_contains "T43 injected" "injected failure of the final validation" "$OUT"
check_absent "T43 no pass line" "pass summary" "$OUT"
check_contains "T43 fail line" "fail summary" "$OUT"
echo "PASS: Test 43"

echo "=== Test 44: e2e_step --selector follows another step under --only and reruns it ==="
S="${TEST_SANDBOX}/suite44/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite44" "fss-2h5zq.1" "$@"
e2e_step "producer" -- true
e2e_step --selector producer "audit" -- false
e2e_summary
EOF
REPRO44="$(rel "$S") --only producer"
run t44a "$S" --only producer
check_eq "T44a rc" 1 "$RC"
LOG44="$(logdir suite44)/run_0001.log"
check_valid "$LOG44"
check_eq "T44a steps" '["producer", "audit"]' "$(lt steps "$LOG44")"
check_eq "T44a record repro" "\"${REPRO44}\"" "$(lt record "$LOG44" audit repro)"
check_eq "T44a summary repro" "${REPRO44}" "$(lt summary_str "$LOG44" repro)"
run t44b "$S" --only audit
check_eq "T44b rc" 1 "$RC"
LOG44="$(logdir suite44)/run_0002.log"
check_eq "T44b steps" '["audit"]' "$(lt steps "$LOG44")"
check_eq "T44b summary repro" "${REPRO44}" "$(lt summary_str "$LOG44" repro)"
run t44c "$S"
check_eq "T44c rc" 1 "$RC"
check_eq "T44c summary repro" "${REPRO44}" "$(lt summary_str "$(logdir suite44)/run_0003.log" repro)"
S="${TEST_SANDBOX}/suite44/empty.sh"
new_script "$S" <<'EOF'
e2e_init "suite44e" "fss-2h5zq.1"
e2e_step --selector "" "x" -- true
e2e_summary
EOF
run t44d "$S"
check_eq "T44d rc" 1 "$RC"
check_contains "T44d error" "e2e_step --selector needs a non-empty selector" "$OUT"
echo "PASS: Test 44"

echo "=== Test 45: FSS_E2E_CARGO_JOBS adds -j N; a non-integer fails closed before rch runs ==="
S="${TEST_SANDBOX}/suite45/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite45" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_target"
e2e_summary
EOF
reset_calls
run t45a env STUB_RCH_MODE=pass FSS_E2E_CARGO_JOBS=1 "$S"
check_eq "T45a rc" 0 "$RC"
check_contains "T45a -j 1" "RCH_REQUIRE_REMOTE=1 ARGS=exec -- cargo test -j 1 -p fss-cli --test test_target --locked --offline -- --nocapture" "$STUB_RCH_CALLS"
reset_calls
run t45b env STUB_RCH_MODE=pass 'FSS_E2E_CARGO_JOBS=1;x' "$S"
check_eq "T45b rc" 1 "$RC"
check_eq "T45b no rch call" 0 "$(calls)"
check_valid "$(logdir suite45)/run_0002.log"
echo "PASS: Test 45"

echo "=== Test 46: libtest 'test <name> ... ' prefixes are removed; other text before a record fails closed ==="
S="${TEST_SANDBOX}/suite46/run.sh"
new_script "$S" <<'EOF'
e2e_init "suite46_${STUB_RCH_MODE}" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_interleave"
e2e_summary
EOF
run t46a env STUB_RCH_MODE=libtest_interleave "$S"
check_eq "T46a rc" 0 "$RC"
LOG46="$(logdir suite46_libtest_interleave)/run_0001.log"
check_valid "$LOG46"
check_eq "T46a steps" '["li1", "li5", "li6", "li2"]' "$(lt steps "$LOG46")"
# Two libtest prefixes before a FAIL record: the record is kept and fails the run.
run t46b env STUB_RCH_MODE=hide_double "$S"
check_eq "T46b rc" 1 "$RC"
LOG46="$(logdir suite46_hide_double)/run_0001.log"
check_valid "$LOG46"
check_eq "T46b failures" '["hd"]' "$(lt summary "$LOG46" failures)"
check_absent "T46b no pass line" "pass summary" "$OUT"
# Any other leading text (mid-line, tab, noise, a non-test name) is malformed, and so is an over-long
# line with a record at its start, in the middle of its first chunk, or deep in its tail: fail closed.
NOTSTART="CAPLOG record not at the start of its line"
for m in "hide_midline:${NOTSTART}" "hide_tab:${NOTSTART}" "hide_noise:${NOTSTART}" "hide_badname:${NOTSTART}" \
        "hide_smuggle:${NOTSTART}" "hide_overlong:CAPLOG line over 1 MiB" "hide_overlong_tail:CAPLOG line over 1 MiB" \
        "hide_overlong_mid:CAPLOG line over 1 MiB"; do
    mode="${m%%:*}"
    why="${m#*:}"
    run "t46_${mode}" env STUB_RCH_MODE="$mode" "$S"
    check_eq "T46 ${mode} rc" 1 "$RC"
    LOG46="$(logdir "suite46_${mode}")/run_0001.log"
    check_valid "$LOG46"
    check_eq "T46 ${mode} steps" '["test_interleave"]' "$(lt steps "$LOG46")"
    check_eq "T46 ${mode} observed" "\"malformed CAPLOG line observed: ${why}\"" "$(lt record "$LOG46" test_interleave observed)"
    check_absent "T46 ${mode} no pass line" "pass summary" "$OUT"
done
echo "PASS: Test 46"

echo "=== Final guards ==="
if [[ -e "$CARGO_TRIPWIRE" ]]; then
    fail "local cargo was called: $(cat "$CARGO_TRIPWIRE")"
fi
if [[ -n "$(ls -A "$TMPDIR")" ]]; then
    fail "files were written to TMPDIR: $(ls -A "$TMPDIR")"
fi
STRAY=$(find "$FSS_E2E_LOG_DIR" \( -name 'stdout_*' -o -name 'stderr_*' -o -name 'cargo_test_*' -o -name 'summary_candidate_*' \) | head -5)
[[ -z "$STRAY" ]] || fail "stray harness temp files: $STRAY"
echo "PASS: final guards"

echo "ALL E2E LIB TESTS PASSED SUCCESSFULLY."
