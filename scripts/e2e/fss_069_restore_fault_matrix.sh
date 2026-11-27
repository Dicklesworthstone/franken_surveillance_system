#!/usr/bin/env bash
# FSS-069 (`fss-x4a.13.9`) E2E verification: deterministic remote archive restore & fault matrix
# (10-scenario restore/fault matrix, replica failover, custody-floor non-collapse, indeterminate
# observation, cancellation cleanup, independent reconstruction, and remote eventual consistency).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_069_restore_fault_matrix.sh"

e2e_init "fss_069_restore_fault_matrix" "fss-x4a.13.9" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_069_restore_fault_matrix_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-object --test fss_069_restore_fault_matrix_contract -- --nocapture
e2e_expect_exit "fss_069_restore_fault_matrix_contract" 0

e2e_step "fss_069_independent_reconstruction_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-object --test fss_135_independent_reconstruction_contract
e2e_expect_exit "fss_069_independent_reconstruction_contract" 0

e2e_step "fss_069_remote_eventual_consistency_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-object --test remote_eventual_consistency_contract
e2e_expect_exit "fss_069_remote_eventual_consistency_contract" 0

e2e_summary
