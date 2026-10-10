#!/usr/bin/env bash
# scripts/e2e/selftest_matrix.sh
# Runner-level fault-matrix self-test (TEST-E2E-HARNESS-001, bead fss-x4a.28.41):
# drives scripts/e2e/matrix_driver.py, which generates purpose-built mini
# scenarios and proves the runner's verdict semantics on each: control pass,
# expectation failure, tamper (missing summary / malformed log), crash,
# deterministic replay, orphan reaping, and deadline enforcement.
# Run it through the parent runner: scripts/e2e/run.sh scripts/e2e/selftest_matrix.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${REPO_ROOT}/scripts/e2e/lib.sh"

e2e_init "selftest_matrix" "fss-x4a.28.41" "$@"

e2e_step "runner_fault_matrix" python3 "${REPO_ROOT}/scripts/e2e/matrix_driver.py"
e2e_expect_exit "runner_fault_matrix" 0

e2e_summary
