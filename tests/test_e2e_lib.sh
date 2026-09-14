#!/usr/bin/env bash
# tests/test_e2e_lib.sh
# Comprehensive self-test for scripts/e2e/lib.sh.
# Runs with a stub rch on PATH (never touches real rch or cargo).
# Kills all mutants and validates F1-F9 fixes.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEST_SANDBOX="$(mktemp -d /tmp/e2e_lib_test_XXXXXX)"

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
    *)
        echo "Unknown stub mode $mode" >&2
        exit 1
        ;;
esac
STUB
chmod +x "${STUB_BIN_DIR}/rch"

export PATH="${STUB_BIN_DIR}:${PATH}"
export FSS_E2E_LOG_DIR="${TEST_SANDBOX}/logs"

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

echo "=== Test 6: Mutant 4 - Excerpt cap <= 4096 bytes ==="
(
    SUITE_DIR="${TEST_SANDBOX}/suite6"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite6" "fss-2h5zq.1"
e2e_step "large_output" python3 -c 'print("A" * 12000)'
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
LOG6="${FSS_E2E_LOG_DIR}/suite6/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG6"
echo "PASS: Test 6"

echo "=== Test 7: F7 & F8 - Path traversal rejection & tmpdirs forensics ==="
set +e
(
    source "${REPO_ROOT}/scripts/e2e/lib.sh"
    e2e_init "../../escaped" "fss-2h5zq.1"
)
T7_EXIT=$?
set -e

if [[ $T7_EXIT -eq 0 ]]; then
    echo "FAIL: Path traversal suite name was accepted!" >&2
    exit 1
fi

# Test forensics preservation on fail
SUITE7_DIR="${TEST_SANDBOX}/suite7"
mkdir -p "$SUITE7_DIR"
cat <<TESTSCRIPT > "${SUITE7_DIR}/run_fail.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite7" "fss-2h5zq.1"
TMP=\$(e2e_tmpdir)
echo "test-data" > "\${TMP}/data.txt"
echo "\$TMP" > "${SUITE7_DIR}/tmp_recorded.txt"
e2e_expect_eq "must_fail" "a" "b"
e2e_summary
TESTSCRIPT
chmod +x "${SUITE7_DIR}/run_fail.sh"
set +e
T7_FAIL_STDERR=$("${SUITE7_DIR}/run_fail.sh" 2>&1)
T7_FAIL_EXIT=$?
set -e
if [[ $T7_FAIL_EXIT -eq 0 ]]; then
    echo "FAIL: run_fail.sh should have exited non-zero" >&2
    exit 1
fi
RECORDED_TMP=$(cat "${SUITE7_DIR}/tmp_recorded.txt")
if [[ ! -d "$RECORDED_TMP" ]]; then
    echo "FAIL: Forensics tmpdir $RECORDED_TMP was not preserved on failure!" >&2
    exit 1
fi
if [[ ! "$T7_FAIL_STDERR" =~ "forensics_preserved" ]]; then
    echo "FAIL: Expected 'forensics_preserved' in stderr on failure" >&2
    exit 1
fi

# Test cleanup on pass
cat <<TESTSCRIPT > "${SUITE7_DIR}/run_pass.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite7_pass" "fss-2h5zq.1"
TMP=\$(e2e_tmpdir)
echo "\$TMP" > "${SUITE7_DIR}/tmp_pass.txt"
e2e_step "pass_step" echo "ok"
e2e_summary
TESTSCRIPT
chmod +x "${SUITE7_DIR}/run_pass.sh"
"${SUITE7_DIR}/run_pass.sh"
PASS_TMP=$(cat "${SUITE7_DIR}/tmp_pass.txt")
if [[ -d "$PASS_TMP" ]]; then
    echo "FAIL: Tmpdir $PASS_TMP was not cleaned up on pass!" >&2
    exit 1
fi
echo "PASS: Test 7"

echo "=== Test 8: F9 - Strict type comparison in expect_json_field ==="
set +e
(
    SUITE_DIR="${TEST_SANDBOX}/suite8"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite8" "fss-2h5zq.1"
# Compare string "1" with integer 1: must fail!
e2e_expect_json_field "type_step" '{"count": 1}' ".count" '"1"'
e2e_summary
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh"
)
T8_EXIT=$?
set -e

if [[ $T8_EXIT -eq 0 ]]; then
    echo "FAIL: Type comparison ('\"1\"' vs 1) passed when it should fail!" >&2
    exit 1
fi
echo "PASS: Test 8"

echo "=== Test 9: Unknown argument rejection ==="
set +e
(
    SUITE_DIR="${TEST_SANDBOX}/suite9"
    mkdir -p "$SUITE_DIR"
    cat <<TESTSCRIPT > "${SUITE_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite9" "fss-2h5zq.1" "\$@"
TESTSCRIPT
    chmod +x "${SUITE_DIR}/run.sh"
    "${SUITE_DIR}/run.sh" --unrecognized-option
)
T9_EXIT=$?
set -e

if [[ $T9_EXIT -eq 0 ]]; then
    echo "FAIL: Unknown argument was accepted without error!" >&2
    exit 1
fi
echo "PASS: Test 9"

echo "=== Test 10: Repro command execution with --only ==="
SUITE10_DIR="${TEST_SANDBOX}/suite10"
mkdir -p "$SUITE10_DIR"
cat <<TESTSCRIPT > "${SUITE10_DIR}/run.sh"
#!/usr/bin/env bash
source "${REPO_ROOT}/scripts/e2e/lib.sh"
e2e_init "suite10" "fss-2h5zq.1" "\$@"
e2e_step "step_a" echo "A"
e2e_step "step_b" echo "B"
e2e_summary
TESTSCRIPT
chmod +x "${SUITE10_DIR}/run.sh"

# Run with --only step_b
"${SUITE10_DIR}/run.sh" --only step_b
LOG10="${FSS_E2E_LOG_DIR}/suite10/run_0001.log"
python3 "${REPO_ROOT}/scripts/e2e/validate_log.py" "$LOG10"
if grep -q '"step": "step_a"' "$LOG10"; then
    echo "FAIL: step_a was run when --only step_b was specified!" >&2
    exit 1
fi
if ! grep -q '"step": "step_b"' "$LOG10"; then
    echo "FAIL: step_b was not run when --only step_b was specified!" >&2
    exit 1
fi
echo "PASS: Test 10"

echo "ALL E2E LIB TESTS PASSED SUCCESSFULLY."
