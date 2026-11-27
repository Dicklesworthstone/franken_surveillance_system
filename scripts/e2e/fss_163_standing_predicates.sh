#!/usr/bin/env bash
# End-to-end proof for FSS-163 (fss-x4a.23.13): incremental retract/add standing predicates over
# DBSP Z-set delta streams with exact full-recompute parity and atomic fail-closed refusals.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_163_standing_predicates.sh"

e2e_init "fss_163_standing_predicates" "fss-x4a.23.13" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_163_standing_predicates_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-graph-algorithms --test fss_163_standing_predicates_contract -- --nocapture
e2e_expect_exit "fss_163_standing_predicates_contract" 0

e2e_summary
