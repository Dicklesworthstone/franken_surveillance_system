#!/usr/bin/env bash
# FSS-241 (`fss-x4a.24.41`) E2E verification: ContractBasis canonical binary freeze,
# live repository registry digest binding, compatibility negotiation, superseded-generation
# refusal (capabilities-v1/v2/v3 and cost-v1), stale-anchor refusal, and planted binary bypasses.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_241_contract_basis.sh"

e2e_init "fss_241_contract_basis" "fss-x4a.24.41" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_241_contract_basis_unit_tests" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-core --lib contract_basis::
e2e_expect_exit "fss_241_contract_basis_unit_tests" 0

e2e_step "fss_241_contract_basis_contract_tests" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-core --test contract_basis_contract
e2e_expect_exit "fss_241_contract_basis_contract_tests" 0

e2e_summary
