#!/usr/bin/env bash
# FSS-194 (`fss-x4a.26.14`) E2E verification: complete qualification, local receipt
# sealing, SBOM/license/lock cross-check, separated signing authority refusal, and
# root-last release publication/reconciliation/verification with GitHub-hosted runners
# and `gh` CLI completely unavailable.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_194_github_unavailable_release.sh"
e2e_init "fss_194_github_unavailable_release" "fss-x4a.26.14" "$@"

e2e_step "unit_and_negative_mutation_suite" -- python3 -m unittest -v tests/test_fss_194_github_unavailable_release.py
e2e_expect_exit "unit_and_negative_mutation_suite" 0

e2e_step "live_offline_github_unavailable_drill" -- python3 scripts/offline_github_unavailable_drill.py
e2e_expect_exit "live_offline_github_unavailable_drill" 0

e2e_step "negative_hosted_authority_refusal" -- python3 scripts/offline_github_unavailable_drill.py --simulate-hosted-authority-request
e2e_expect_exit "negative_hosted_authority_refusal" 1

e2e_summary
