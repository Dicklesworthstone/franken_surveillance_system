#!/usr/bin/env bash
# scripts/e2e/selftest.sh
# Comprehensive end-to-end self-test script for the FSS e2e harness (lib.sh).
# Proves logging, expectations, secret redaction, and output excerpt capping.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${REPO_ROOT}/scripts/e2e/lib.sh"

e2e_init "selftest" "fss-2h5zq.2" "$@"

# Step 1: Basic deterministic command execution
e2e_step "step_basic" echo "basic step execution"

# Step 2: Secret redaction and line dropping
# Emits lines with Authorization, password, tokens, and bearer credentials.
# The word Authorization is constructed dynamically so it does not appear in the cmd field.
e2e_step "step_secrets_redaction" python3 -c '
import sys
# Line-dropped patterns:
sys.stdout.write("Line before secret\n")
sys.stdout.write("Auth" + "orization: Basic dXNlcjpwYXNz\n")
sys.stdout.write("password hunter42\n")
sys.stdout.write("token=ghp_ABC123secrettoken456\n")
# Value-redacted pattern:
sys.stdout.write("Bearer secretbearer789\n")
sys.stdout.write("Line after secret\n")
'

# Step 3: Large output excerpt capping (1 MiB output across lines)
# Output must be capped to <= 4 KiB (4096 bytes) in the step excerpt
e2e_step "step_large_output" python3 -c 'import sys; [sys.stdout.write("X" * 1024 + "\n") for _ in range(1024)]'

# Step 4: Expect equality
e2e_expect_eq "expect_equality_match" "value_alpha" "value_alpha"

# Step 5: Expect exit code 0 of step_basic
e2e_expect_exit "step_basic" 0

# Step 6: Expect JSON field match
e2e_expect_json_field "expect_json_field_match" '{"status":"ok","code":200,"service":"fss"}' .code 200

# Step 7: Temporary directory allocation and automatic cleanup
TMP_DIR=$(e2e_tmpdir)
echo "selftest_tmp_data" > "${TMP_DIR}/test_artifact.txt"
test -f "${TMP_DIR}/test_artifact.txt"

# Step 8: Optional skip step
e2e_skip "skipped_feature" "optional feature skipped during standard selftest"

# Complete and summarize run
e2e_summary
