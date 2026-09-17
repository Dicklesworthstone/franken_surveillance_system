#!/usr/bin/env bash
# tests/test_e2e_lib.sh
# Comprehensive self-test for scripts/e2e/lib.sh.
# Runs with a stub rch on PATH (never touches real rch or cargo).
# Kills all mutants and validates F1-F9 fixes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_SANDBOX="${REPO_ROOT}/target/test_sandboxes/e2e_lib_test_$$"
mkdir -p "$TEST_SANDBOX"

cleanup() {
    rm -rf "$TEST_SANDBOX"
}
trap cleanup EXIT

STUB_BIN_DIR="${TEST_SANDBOX}/bin"
mkdir -p "$STUB_BIN_DIR"

# Create stub rch
cat <<'STUB' > "${STUB_BIN_DIR}/rch"
#!/usr/bin/env bash
# Stub rch for e2e test harness tests. Never touches real rch or network.
set -euo pipefail

mode="${STUB_RCH_MODE:-pass}"
target="${STUB_RCH_TARGET:-test_target}"

case "$mode" in
    pass)
        echo "running 1 test"
        echo "CAPLOG {\"step\": \"${target}\", \"verdict\": \"pass\", \"exit\": 0, \"duration_ms\": 10, \"expected\": 1, \"observed\": 1}"
        echo "test result: ok. 1 passed; 0 failed"
        exit 0
        ;;
    fail)
        echo "running 1 test"
        echo "CAPLOG {\"step\": \"${target}_fail\", \"verdict\": \"fail\", \"exit\": 1, \"duration_ms\": 12, \"expected\": 1, \"observed\": 2}"
        echo "test result: FAILED. 0 passed; 1 failed"
        exit 0  # Note: cargo exits 0 here to explicitly test F1 (verdict fail in CAPLOG must fail summary)
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
        echo "running 1 test"
        echo "CAPLOG {\"step\": \"${target}\", \"verdict\": \"bogus\", \"exit\": 0, \"duration_ms\": 10}"
        echo "test result: ok. 1 passed; 0 failed"
        exit 0
        ;;
    secret_caplog)
        echo "running 1 test"
        echo "CAPLOG {\"step\": \"${target}\", \"verdict\": \"pass\", \"exit\": 0, \"duration_ms\": 10, \"expected\": \"ghp_EXPECTEDSECRET1234567890\", \"observed\": {\"k\": \"ghp_OBSERVEDSECRET1234567890\"}}"
        echo "test result: ok. 1 passed; 0 failed"
        exit 0
        ;;
    inf)
        echo "running 1 test"
        echo "CAPLOG {\"step\": \"${target}\", \"verdict\": \"fail\", \"duration_ms\": 1e400}"
        exit 0
        ;;
    r103)
        echo "remote unavailable"
        exit 103
        ;;
    secret_step_bead)
        echo "running 1 test"
        echo 'CAPLOG {"step": "step_ghp_123456789012", "bead": "bead_ghp_123456789012", "verdict": "pass"}'
        exit 0
        ;;
    *)
        echo "Unknown stub mode $mode" >&2
        exit 1
        ;;
esac
STUB
chmod +x "${STUB_BIN_DIR}/rch"

export PATH="${STUB_BIN_DIR}:${PATH}"
export FSS_E2E_LOG_DIR="${TEST_SANDBOX}/logs"

# HARD GUARD against reaching real rch
if [[ "$(command -v rch)" != "${STUB_BIN_DIR}/rch" ]]; then
    echo "HARD GUARD FAIL: rch resolved to $(command -v rch), not ${STUB_BIN_DIR}/rch" >&2
    exit 97
fi

echo "=== Test 1: Happy path e2e execution ==="
(
    export STUB_RCH_MODE="pass"
    SUITE_DIR="${TEST_SANDBOX}/suite1"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite1" "fss-2h5zq.1"
e2e_step "step_echo" echo "hello world"
e2e_expect_eq "step_eq" "val1" "val1"
e2e_expect_exit "step_echo" 0
e2e_cargo_test "fss-cli" "test_target"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)

LOG1="${FSS_E2E_LOG_DIR}/suite1/run_0001.log"
if [[ ! -f "$LOG1" ]]; then
    echo "FAIL: Expected log file $LOG1 does not exist" >&2
    exit 1
fi
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG1"
echo "PASS: Test 1"

echo "=== Test 2: F1 & Mutant 6 - CAPLOG verdict fail with exit 0 fails summary ==="
set +e
(
    export STUB_RCH_MODE="fail"
    SUITE_DIR="${TEST_SANDBOX}/suite2"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite2" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_fail_target"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
T2_EXIT=$?
set -e

if [[ $T2_EXIT -eq 0 ]]; then
    echo "FAIL: F1 mutant survived! CAPLOG fail verdict gave exit 0!" >&2
    exit 1
fi
LOG2="${FSS_E2E_LOG_DIR}/suite2/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG2"
if ! tail -n 1 "$LOG2" | grep -q '"verdict": "fail"'; then
    echo "FAIL: Summary in $LOG2 does not report fail" >&2
    exit 1
fi
echo "PASS: Test 2"

echo "=== Test 3: Mutant 6 - Zero-CAPLOG failure ==="
set +e
(
    export STUB_RCH_MODE="zero_caplog"
    SUITE_DIR="${TEST_SANDBOX}/suite3"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite3" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_no_caplog"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
T3_EXIT=$?
set -e

if [[ $T3_EXIT -eq 0 ]]; then
    echo "FAIL: Zero-CAPLOG test survived with exit 0!" >&2
    exit 1
fi
LOG3="${FSS_E2E_LOG_DIR}/suite3/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG3"
if ! python3 -c '
import json, sys
summary = json.loads(open(sys.argv[1]).read().splitlines()[-1])
assert summary["verdict"] == "fail" and summary["steps"] == 0
assert summary["run_failures"] == ["no_caplog_emitted"]
' "$LOG3"; then
    echo "FAIL: Expected documented no-evidence run failure in $LOG3" >&2
    exit 1
fi
echo "PASS: Test 3"

echo "=== Test 4: F2 - Non-numeric run_abc.log skipped and fail closed ==="
SUITE4_DIR="${FSS_E2E_LOG_DIR}/suite4"
mkdir -p "$SUITE4_DIR"
touch "${SUITE4_DIR}/run_stray_abc.log"
(
    SUITE_DIR="${TEST_SANDBOX}/suite4"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite4" "fss-2h5zq.1"
e2e_step "step1" echo "ok"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
LOG4="${SUITE4_DIR}/run_0001.log"
if [[ ! -f "$LOG4" ]]; then
    echo "FAIL: Expected $LOG4 created despite stray run_stray_abc.log" >&2
    exit 1
fi
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG4"
echo "PASS: Test 4"

echo "=== Test 5: F3 & Mutant 5 - Secret redaction of planted secrets and token shapes ==="
(
    export GITHUB_TOKEN="ghp_superfaketoken1234567890"
    export AWS_SECRET_ACCESS_KEY="AKIAIOSFODNN7EXAMPLE"
    export MYPASS="supersecretpassword123"

    SUITE_DIR="${TEST_SANDBOX}/suite5"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite5" "fss-2h5zq.1"
e2e_step "leak_step" echo "\$GITHUB_TOKEN \$AWS_SECRET_ACCESS_KEY \$MYPASS sk-ant-api03-faketoken123456 Bearer faketoken123456"
e2e_expect_eq "leak_expect" "Authorization: Bearer \$GITHUB_TOKEN" "Authorization: Bearer \$GITHUB_TOKEN"
e2e_skip "leak_skip" "Skipping because \$MYPASS is secret"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
LOG5="${FSS_E2E_LOG_DIR}/suite5/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG5"

for secret in "ghp_superfaketoken1234567890" "AKIAIOSFODNN7EXAMPLE" "supersecretpassword123" "sk-ant-api03-faketoken123456" "faketoken123456"; do
    if grep -q "$secret" "$LOG5"; then
        echo "FAIL: Secret '$secret' leaked into log file $LOG5!" >&2
        exit 1
    fi
done

# Verify _e2e_redact_file explicitly redacts environment secrets (kills M17)
(
    source "${REPO_ROOT}/scripts/e2e/lib.sh"
    test_m17_file="${TEST_SANDBOX}/test_m17_sec.txt"
    export MY_M17_PASS="custom_needle_987654"
    echo "output containing $MY_M17_PASS and trailing text" > "$test_m17_file"
    red_res=$(_e2e_redact_file "$test_m17_file")
    if [[ "$red_res" == *"$MY_M17_PASS"* ]]; then
        echo "FAIL: _e2e_redact_file leaked secret into excerpt (kills M17)!" >&2
        exit 1
    fi
    trap - EXIT
)

echo "PASS: Test 5"

echo "=== Test 6: Mutant 4 & Mutant 4b - Excerpt cap <= 4096 bytes with non-hex filler ==="
(
    SUITE_DIR="${TEST_SANDBOX}/suite6"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite6" "fss-2h5zq.1"
e2e_step "large_output" python3 -c 'print("Z" * 12000)'
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
LOG6="${FSS_E2E_LOG_DIR}/suite6/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG6"

# Verify excerpt size strictly capped at 4096 bytes (kills M4b)
python3 -c "
import json, sys
for line in open('$LOG6'):
    rec = json.loads(line)
    if rec.get('step') == 'large_output':
        ex = rec.get('stdout_excerpt', '')
        b = ex.encode('utf-8')
        if len(b) > 4096:
            sys.exit(1)
        assert len(b) == 4096, f'Expected exactly 4096 bytes, got {len(b)}'
"
echo "PASS: Test 6"

echo "=== Test 7: Mutant 12 & F7 & F8 - Path traversal rejection & no escaped dirs ==="
set +e
ESCAPED_TARGET="${FSS_E2E_LOG_DIR}/../../escaped_dir_m12_test_$$"
T7_OUT=$(
    source "${REPO_ROOT}/scripts/e2e/lib.sh"
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
# Kills M12: assert escaped directory does not exist outside log root
if [[ -d "$ESCAPED_TARGET" || -d "${REPO_ROOT}/escaped" || -d "${TEST_SANDBOX}/escaped" ]]; then
    echo "FAIL: M12 mutant survived: escaped directory exists outside log root!" >&2
    exit 1
fi
echo "PASS: Test 7"

echo "=== Test 8: Mutant 14 - Forensics tmpdir preserved on fail, kept across passing run ==="
SUITE8_DIR="${TEST_SANDBOX}/suite8"
mkdir -p "$SUITE8_DIR"

# Run 1: Fails
cat <<TESTSCRIPT > "${SUITE8_DIR}/run_fail.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite8_tmp" "fss-2h5zq.1"
TMP=\$(e2e_tmpdir)
echo "data1" > "\${TMP}/data.txt"
echo "\$TMP" > "${SUITE8_DIR}/tmp_fail.txt"
e2e_expect_eq "must_fail" "expected_val" "observed_val"
e2e_summary
TESTSCRIPT
chmod +x "${SUITE8_DIR}/run_fail.sh"
set +e
T8_FAIL_OUT=$("${SUITE8_DIR}/run_fail.sh" 2>&1)
T8_FAIL_RC=$?
set -e
if [[ $T8_FAIL_RC -eq 0 ]]; then
    echo "FAIL: run_fail.sh should have exited non-zero" >&2
    exit 1
fi
TMP_FAIL=$(cat "${SUITE8_DIR}/tmp_fail.txt")
if [[ ! -d "$TMP_FAIL" ]]; then
    echo "FAIL: Forensics tmpdir $TMP_FAIL was not preserved on failure!" >&2
    exit 1
fi
if [[ ! "$T8_FAIL_OUT" =~ "forensics_preserved" ]]; then
    echo "FAIL: Expected 'forensics_preserved' in output on failure" >&2
    exit 1
fi

# Run 2: Passes in the same suite
cat <<TESTSCRIPT > "${SUITE8_DIR}/run_pass.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite8_tmp" "fss-2h5zq.1"
TMP=\$(e2e_tmpdir)
echo "data2" > "\${TMP}/data2.txt"
echo "\$TMP" > "${SUITE8_DIR}/tmp_pass.txt"
e2e_step "step_pass" echo "ok"
e2e_summary
TESTSCRIPT
chmod +x "${SUITE8_DIR}/run_pass.sh"
"${SUITE8_DIR}/run_pass.sh"

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
echo "PASS: Test 8"

echo "=== Test 9: Mutant 15 & F9 - Strict JSON type comparison (1 vs '1', 1 vs true, 1 vs 1.0) ==="
SUITE9_DIR="${TEST_SANDBOX}/suite9"
mkdir -p "$SUITE9_DIR"
cat <<TESTSCRIPT > "${SUITE9_DIR}/run.sh"
#!/usr/bin/env bash
MODE="\${1:-}"
set --
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite9" "fss-2h5zq.1"
case "\$MODE" in
    str)   e2e_expect_json_field "s" '{"a":1}' .a '"1"' ;;
    bool)  e2e_expect_json_field "b" '{"a":1}' .a true ;;
    float) e2e_expect_json_field "f" '{"a":1}' .a 1.0 ;;
    pass)  e2e_expect_json_field "p" '{"a":1}' .a 1 ;;
esac
e2e_summary
TESTSCRIPT
chmod +x "${SUITE9_DIR}/run.sh"

set +e
"${SUITE9_DIR}/run.sh" str >/dev/null 2>&1
RC_STR=$?
"${SUITE9_DIR}/run.sh" bool >/dev/null 2>&1
RC_BOOL=$?
"${SUITE9_DIR}/run.sh" float >/dev/null 2>&1
RC_FLOAT=$?
"${SUITE9_DIR}/run.sh" pass >/dev/null 2>&1
RC_PASS=$?
set -e

if [[ $RC_STR -eq 0 || $RC_BOOL -eq 0 || $RC_FLOAT -eq 0 || $RC_PASS -ne 0 ]]; then
    echo "FAIL: M15 mutant survived! Strict types not enforced: str=$RC_STR bool=$RC_BOOL float=$RC_FLOAT pass=$RC_PASS" >&2
    exit 1
fi
echo "PASS: Test 9"

echo "=== Test 10: Mutant 16 - Unknown argument rejection ==="
SUITE10_DIR="${TEST_SANDBOX}/suite10"
mkdir -p "$SUITE10_DIR"
cat <<TESTSCRIPT > "${SUITE10_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite10" "fss-2h5zq.1" "\$@"
e2e_step "s" echo hi
e2e_summary
TESTSCRIPT
chmod +x "${SUITE10_DIR}/run.sh"

set +e
STDERR_10=$("${SUITE10_DIR}/run.sh" --bogus-unknown-flag 2>&1)
RC_10=$?
set -e

if [[ $RC_10 -eq 0 ]]; then
    echo "FAIL: Unknown argument was accepted without error!" >&2
    exit 1
fi
# Kills M16: Must output specific error message about unrecognized argument
if [[ ! "$STDERR_10" =~ "unrecognized argument: --bogus-unknown-flag" ]]; then
    echo "FAIL: M16 mutant survived: expected unrecognized argument error message, got: $STDERR_10" >&2
    exit 1
fi
echo "PASS: Test 10"

echo "=== Test 11: Mutant 8 - CAPLOG verdict enum validation ==="
set +e
(
    export STUB_RCH_MODE="bad_verdict"
    SUITE_DIR="${TEST_SANDBOX}/suite11"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite11" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_bad_verdict"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
RC_11=$?
set -e

if [[ $RC_11 -eq 0 ]]; then
    echo "FAIL: M8 mutant survived: CAPLOG with verdict 'bogus' was accepted with exit 0!" >&2
    exit 1
fi
LOG11="${FSS_E2E_LOG_DIR}/suite11/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG11"
if ! grep -q '"step": "test_target:invalid_verdict"' "$LOG11"; then
    echo "FAIL: M8 mutant survived: expected test_target:invalid_verdict failure record in $LOG11" >&2
    exit 1
fi
echo "PASS: Test 11"

echo "=== Test 12: Mutant 9 - Trap fails closed on uninitialized abort ==="
set +e
ERR_M9=$(bash -c 'source "'"${REPO_ROOT}"'/scripts/e2e/lib.sh"; exit 42' 2>&1)
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
set +e
(
    export STUB_RCH_MODE="secret_caplog"
    SUITE_DIR="${TEST_SANDBOX}/suite13"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite13" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_secret_caplog"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
T13_EXIT=$?
set -e
if [[ $T13_EXIT -eq 0 ]]; then
    echo "FAIL: Secret-CAPLOG run should have failed closed!" >&2
    exit 1
fi
LOG13="${FSS_E2E_LOG_DIR}/suite13/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG13"

# Kills M11: planted secret in expected and observed must be sanitized
if grep -q "ghp_EXPECTEDSECRET" "$LOG13" || grep -q "ghp_OBSERVEDSECRET" "$LOG13"; then
    echo "FAIL: M11 mutant survived: secret in CAPLOG line was not sanitized!" >&2
    exit 1
fi
echo "PASS: Test 13"

echo "=== Test 14: Repro command execution with --only ==="
SUITE14_DIR="${TEST_SANDBOX}/suite14"
mkdir -p "$SUITE14_DIR"
cat <<TESTSCRIPT > "${SUITE14_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite14" "fss-2h5zq.1" "\$@"
e2e_step "step_a" echo "A"
e2e_expect_eq "step_fail" "expected_val" "actual_val"
e2e_summary
TESTSCRIPT
chmod +x "${SUITE14_DIR}/run.sh"

set +e
"${SUITE14_DIR}/run.sh"
T14_EXIT=$?
set -e
if [[ $T14_EXIT -eq 0 ]]; then
    echo "FAIL: Initial run of suite14 should have failed" >&2
    exit 1
fi
LOG14="${FSS_E2E_LOG_DIR}/suite14/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG14"

# Extract repro command from the summary record and actually execute it
REPRO_CMD=$(tail -n 1 "$LOG14" | python3 -c 'import sys, json; print(json.loads(sys.stdin.read())["repro"])')
if [[ -z "$REPRO_CMD" ]]; then
    echo "FAIL: No repro command found in summary record" >&2
    exit 1
fi

set +e
eval "$REPRO_CMD"
REPRO_EXIT=$?
set -e
LOG14_2="${FSS_E2E_LOG_DIR}/suite14/run_0002.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG14_2"
if grep -q '"step": "step_a"' "$LOG14_2"; then
    echo "FAIL: step_a was run during repro execution when only step_fail should run!" >&2
    exit 1
fi
if ! grep -q '"step": "step_fail"' "$LOG14_2"; then
    echo "FAIL: step_fail was not run during repro execution!" >&2
    exit 1
fi
echo "PASS: Test 14"

echo "=== Test 15: Mutant N31 - Ingester safe_int with duration_ms 1e400 and py_rc ==="
set +e
(
    export STUB_RCH_MODE="inf"
    SUITE_DIR="${TEST_SANDBOX}/suite15"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite15" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_inf_duration"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
T15_EXIT=$?
set -e
if [[ $T15_EXIT -eq 0 ]]; then
    echo "FAIL: Ingester fail-open on 1e400 overflow!" >&2
    exit 1
fi
LOG15="${FSS_E2E_LOG_DIR}/suite15/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG15"
if ! tail -n 1 "$LOG15" | grep -q '"verdict": "fail"'; then
    echo "FAIL: Summary in $LOG15 does not report fail" >&2
    exit 1
fi
echo "PASS: Test 15"

echo "=== Test 16: Mutant N32 - Keyword line drop in stdout/stderr ==="
(
    SUITE_DIR="${TEST_SANDBOX}/suite16"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite16" "fss-2h5zq.1"
e2e_step "step_kw" bash -c 'printf "Authorization: Basic S3CRET_AUTH_TOKEN\nkeep_this_safe_line\n"'
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
LOG16="${FSS_E2E_LOG_DIR}/suite16/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG16"
if grep -q "S3CRET_AUTH_TOKEN" "$LOG16"; then
    echo "FAIL: Keyword line with Authorization was not dropped from log!" >&2
    exit 1
fi
if ! grep -q "keep_this_safe_line" "$LOG16"; then
    echo "FAIL: Non-keyword line was unexpectedly dropped!" >&2
    exit 1
fi

# Direct check of _e2e_redact_file keyword drop (kills N32)
(
    source "${REPO_ROOT}/scripts/e2e/lib.sh"
    test_n32_file="${TEST_SANDBOX}/test_n32_drop.txt"
    printf "Authorization: custom_auth_data\nkeep_this_line\n" > "$test_n32_file"
    red_res=$(_e2e_redact_file "$test_n32_file")
    if [[ "$red_res" == *"custom_auth_data"* ]]; then
        echo "FAIL: _e2e_redact_file failed to drop keyword line (kills N32)!" >&2
        exit 1
    fi
    trap - EXIT
)

echo "PASS: Test 16"

echo "=== Test 17: Mutant N33 - URL credential redaction ==="
(
    SUITE_DIR="${TEST_SANDBOX}/suite17"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite17" "fss-2h5zq.1"
e2e_step "step_url" echo "Connecting to https://user:mycred123@endpoint.local/test"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
LOG17="${FSS_E2E_LOG_DIR}/suite17/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG17"
if grep -q "mycred123" "$LOG17"; then
    echo "FAIL: URL credentials were not redacted in $LOG17!" >&2
    exit 1
fi
if ! grep -q "https://user:<redacted>@endpoint.local/test" "$LOG17"; then
    echo "FAIL: Expected <redacted> in URL credentials in $LOG17!" >&2
    exit 1
fi
if ! grep -F -q '([A-Za-z][A-Za-z0-9+.-]*://[^/\s:@]+:)[^/\s:@]+(@)' "${REPO_ROOT}/scripts/e2e/lib.sh"; then
    echo "FAIL: N33 survived: URL credential redaction missing from lib.sh!" >&2
    exit 1
fi
echo "PASS: Test 17"

echo "=== Test 18: Mutant N34 - --password flag redaction ==="
(
    SUITE_DIR="${TEST_SANDBOX}/suite18"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite18" "fss-2h5zq.1"
e2e_step "step_pw" echo "--password MY_FLAG_VAL_98765"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
LOG18="${FSS_E2E_LOG_DIR}/suite18/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG18"
if grep -q "MY_FLAG_VAL_98765" "$LOG18"; then
    echo "FAIL: --password secret was not redacted in $LOG18!" >&2
    exit 1
fi
if ! grep -F -q '(--password(?:=|\s+))\S+' "${REPO_ROOT}/scripts/e2e/lib.sh"; then
    echo "FAIL: N34 survived: --password flag redaction missing from lib.sh!" >&2
    exit 1
fi
echo "PASS: Test 18"

echo "=== Test 19: Mutant N35 - mysql -p flag redaction ==="
(
    SUITE_DIR="${TEST_SANDBOX}/suite19"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite19" "fss-2h5zq.1"
e2e_step "step_mysql" echo "mysql -pMY_MYSQL_VAL_54321"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
LOG19="${FSS_E2E_LOG_DIR}/suite19/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG19"
if grep -q "MY_MYSQL_VAL_54321" "$LOG19"; then
    echo "FAIL: mysql -p secret was not redacted in $LOG19!" >&2
    exit 1
fi
if ! grep -q -- "-p<redacted>" "$LOG19"; then
    echo "FAIL: Expected -p<redacted> in $LOG19!" >&2
    exit 1
fi
if ! grep -F -q '(?<!\S)-p\S+' "${REPO_ROOT}/scripts/e2e/lib.sh"; then
    echo "FAIL: N35 survived: mysql -p redaction missing from lib.sh!" >&2
    exit 1
fi
echo "PASS: Test 19"

echo "=== Test 20: Mutant N36 - Bounded 103 retry ==="
set +e
(
    export STUB_RCH_MODE="r103"
    SUITE_DIR="${TEST_SANDBOX}/suite20"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite20" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_r103_retry"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
T20_EXIT=$?
set -e
if [[ $T20_EXIT -eq 0 ]]; then
    echo "FAIL: 103 retry succeeded with 0 when it should fail after 3 retries!" >&2
    exit 1
fi
LOG20="${FSS_E2E_LOG_DIR}/suite20/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG20"
echo "PASS: Test 20"

echo "=== Test 21: Mutant N37 - Trap blames script:exit, not last step ==="
set +e
(
    SUITE_DIR="${TEST_SANDBOX}/suite21"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
set -e
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite21" "fss-2h5zq.1"
e2e_step "pass_good" echo "fine"
false
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
T21_EXIT=$?
set -e
if [[ $T21_EXIT -eq 0 ]]; then
    echo "FAIL: Script that failed with false should have exit != 0" >&2
    exit 1
fi
LOG21="${FSS_E2E_LOG_DIR}/suite21/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG21"
python3 - "$LOG21" <<'PY'
import json, sys
records = [json.loads(line) for line in open(sys.argv[1])]
summary = records[-1]
assert summary["verdict"] == "fail"
assert summary["failures"] == [], summary
assert summary["run_failures"] == ["script_exit"], summary
assert records[1]["step"] == "pass_good" and records[1]["verdict"] == "ran"
assert "--only" not in summary["repro"], summary
PY
echo "PASS: Test 21"

echo "=== Test 22: Mutant N38 - Dot name '.' refused ==="
set +e
(
    source "${REPO_ROOT}/scripts/e2e/lib.sh"
    e2e_init "." "fss-2h5zq.1"
) 2>"${TEST_SANDBOX}/n38.err"
T22_EXIT=$?
set -e
if [[ $T22_EXIT -eq 0 ]]; then
    echo "FAIL: N38 survived: e2e_init '.' should have failed!" >&2
    exit 1
fi
if ! grep -q "invalid suite name '.'" "${TEST_SANDBOX}/n38.err"; then
    echo "FAIL: Expected 'invalid suite name \'.\'' in stderr" >&2
    exit 1
fi
echo "PASS: Test 22"

echo "=== Test 23: Mutant N39 - Summary without init refused ==="
set +e
(
    source "${REPO_ROOT}/scripts/e2e/lib.sh"
    e2e_summary
) 2>"${TEST_SANDBOX}/n39.err"
T23_EXIT=$?
set -e
if [[ $T23_EXIT -eq 0 ]]; then
    echo "FAIL: N39 survived: e2e_summary before init should have failed!" >&2
    exit 1
fi
if ! grep -q "uninitialized" "${TEST_SANDBOX}/n39.err"; then
    echo "FAIL: Expected 'uninitialized' in stderr" >&2
    exit 1
fi
echo "PASS: Test 23"

echo "=== Test 24: Mutant N40 - Preserved tmpdirs in log ==="
set +e
(
    SUITE_DIR="${TEST_SANDBOX}/suite24"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite24" "fss-2h5zq.1"
TMP=\$(e2e_tmpdir)
echo "forensic data" > "\${TMP}/evidence.txt"
e2e_expect_eq "must_fail" "exp" "obs"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
T24_EXIT=$?
set -e
if [[ $T24_EXIT -eq 0 ]]; then
    echo "FAIL: Suite24 should have failed" >&2
    exit 1
fi
LOG24="${FSS_E2E_LOG_DIR}/suite24/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG24"
PRESERVED_24=$(tail -n 1 "$LOG24" | python3 -c 'import sys, json; print(json.loads(sys.stdin.read()).get("preserved_tmpdirs", []))')
if [[ "$PRESERVED_24" == "[]" || -z "$PRESERVED_24" ]]; then
    echo "FAIL: N40 survived: preserved_tmpdirs is empty in summary record: $PRESERVED_24" >&2
    exit 1
fi
echo "PASS: Test 24"

echo "=== Test 25: Mutant N41 - Cap step count matches written records ==="
set +e
(
    SUITE_DIR="${TEST_SANDBOX}/suite25"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
export _E2E_MAX_LOG_BYTES=100000
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite25" "fss-2h5zq.1"
big=\$(python3 -c 'print("q"*4000)')
big2=\$(python3 -c 'print("w"*4000)')
i=0
while :; do
    i=\$((i+1))
    e2e_expect_eq "f\$i" "\$big" "\$big2" || break
done
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
T25_EXIT=$?
set -e
if [[ $T25_EXIT -eq 0 ]]; then
    echo "FAIL: Cap exceeded run should have exit != 0" >&2
    exit 1
fi
LOG25="${FSS_E2E_LOG_DIR}/suite25/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG25"
echo "PASS: Test 25"

echo "=== Test 26: Mutants N43, N44 - CAPLOG step name and bead sanitized ==="
(
    export STUB_RCH_MODE="secret_step_bead"
    SUITE_DIR="${TEST_SANDBOX}/suite26"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite26" "fss-2h5zq.1"
e2e_cargo_test "fss-cli" "test_secret_step_bead"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
LOG26="${FSS_E2E_LOG_DIR}/suite26/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG26"
if grep -q "ghp_123456789012" "$LOG26"; then
    echo "FAIL: N43/N44 survived: secret in step name or bead was not sanitized in $LOG26!" >&2
    exit 1
fi
echo "PASS: Test 26"

echo "=== Test 27: Mutant N45 - expect_exit cmd sanitized ==="
set +e
(
    SUITE_DIR="${TEST_SANDBOX}/suite27"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite27" "fss-2h5zq.1"
e2e_step "step_norm" echo "ok"
e2e_expect_exit "step_norm" "ghp_123456789012"
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
T27_EXIT=$?
set -e
if [[ $T27_EXIT -eq 0 ]]; then
    echo "FAIL: Expected suite27 to fail with exit != 0" >&2
    exit 1
fi
LOG27="${FSS_E2E_LOG_DIR}/suite27/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG27"
if grep -q "ghp_123456789012" "$LOG27"; then
    echo "FAIL: N45 survived: secret in expect_exit expected_str was not sanitized in cmd!" >&2
    exit 1
fi
echo "PASS: Test 27"

echo "=== Test 28: Mutant N46 - Repro rerun runs cargo target on mixed only ==="
SUITE28_DIR="${TEST_SANDBOX}/suite28"
mkdir -p "$SUITE28_DIR"
cat <<TESTSCRIPT > "${SUITE28_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite28" "fss-2h5zq.1" "\$@"
e2e_cargo_test "fss-cli" "cargo_pkg"
e2e_step "reg_step" echo "regular"
e2e_summary
TESTSCRIPT
chmod +x "${SUITE28_DIR}/run.sh"

"${SUITE28_DIR}/run.sh" --only test_target,reg_step
LOG28="${FSS_E2E_LOG_DIR}/suite28/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG28"
if ! grep -q '"step": "test_target"' "$LOG28"; then
    echo "FAIL: N46 survived: test_target was skipped when --only test_target,reg_step was specified!" >&2
    exit 1
fi
echo "PASS: Test 28"

echo "ALL E2E LIB TESTS PASSED SUCCESSFULLY."
