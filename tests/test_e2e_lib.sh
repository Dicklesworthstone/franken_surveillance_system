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
if ! grep -q '"verdict": "fail"' "$LOG2"; then
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
if ! grep -q "no CAPLOG line observed" "$LOG3"; then
    echo "FAIL: Expected 'no CAPLOG line observed' in $LOG3" >&2
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
if ! grep -q "malformed CAPLOG line observed" "$LOG11"; then
    echo "FAIL: M8 mutant survived: expected 'malformed CAPLOG line observed' in $LOG11" >&2
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
e2e_step "step_b" echo "B"
e2e_summary
TESTSCRIPT
chmod +x "${SUITE14_DIR}/run.sh"

"${SUITE14_DIR}/run.sh" --only step_b
LOG14="${FSS_E2E_LOG_DIR}/suite14/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG14"
if grep -q '"step": "step_a"' "$LOG14"; then
    echo "FAIL: step_a was run when --only step_b was specified!" >&2
    exit 1
fi
if ! grep -q '"step": "step_b"' "$LOG14"; then
    echo "FAIL: step_b was not run when --only step_b was specified!" >&2
    exit 1
fi
echo "PASS: Test 14"

echo "ALL E2E LIB TESTS PASSED SUCCESSFULLY."
