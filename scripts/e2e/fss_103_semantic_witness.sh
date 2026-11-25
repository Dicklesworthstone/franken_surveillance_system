#!/usr/bin/env bash
# FSS-103 (`fss-x4a.9.10`) E2E verification: positive, negative, and hierarchical semantic
# ledger witnesses with mandatory CoverageWitness non-collapse and Merkle inclusion/non-inclusion.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_103_semantic_witness.sh"
e2e_init "fss_103_semantic_witness" "fss-x4a.9.10" "$@"
e2e_cargo_test "fss-ledger" "fss_103_semantic_witness_contract"
e2e_summary
