#!/usr/bin/env bash
# FSS-128 (`fss-x4a.13.12`) E2E verification: RaptorQ / systematic GF(256) post-repair canonical
# digest gate, quarantine on mismatch/corrupt symbols, XFER-INV-006 authority non-escalation,
# durability-gated symbol refresh, FSS-127 closure bridge, and FSSPRG01 binary wire codec.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_128_post_repair_digest_gate.sh"
e2e_init "fss_128_post_repair_digest_gate" "fss-x4a.13.12" "$@"
e2e_cargo_test "fss-object" "fss_128_post_repair_digest_gate_contract"
e2e_summary
