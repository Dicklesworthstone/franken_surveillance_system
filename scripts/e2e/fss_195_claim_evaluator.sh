#!/usr/bin/env bash
# FSS-195 (`fss-x4a.26.15`) E2E verification: deterministic public claim scope, evidence,
# exclusion, tombstoned/stale generation, expiry, and cooperative cancellation evaluator.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_195_claim_evaluator.sh"

e2e_init "fss_195_claim_evaluator" "fss-x4a.26.15" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_195_claim_evaluator_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-core --test fss_195_claim_evaluator_contract -- --nocapture
e2e_expect_exit "fss_195_claim_evaluator_contract" 0

e2e_step "fss_195_claim_proof_bundle_checker" -- \
  python3 "$ROOT/scripts/claim_proof_bundle_checker.py"
e2e_expect_exit "fss_195_claim_proof_bundle_checker" 0

e2e_summary
