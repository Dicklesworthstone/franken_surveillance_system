#!/usr/bin/env bash
# End-to-end proof for FSS-242 (fss-x4a.24.42):
# Universal `AgentRequestEnvelope`/`AgentResponseEnvelope` dispatch with
# operation-registry-owned typed payload validation, ContractBasis negotiation,
# stale-anchor & authority/taint/budget/cancellation fault handling, vault
# canary containment, and live 4-surface transcript equivalence across
# EnvelopeDispatch, Direct Rust API, `fss` CLI binary, and `fss-mcp` stdio server.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_242_universal_envelope_dispatch.sh"

e2e_init "fss_242_universal_envelope_dispatch" "fss-x4a.24.42" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "envelope_dispatch_unit_suite" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --lib envelope_dispatch -- --nocapture
e2e_expect_exit "envelope_dispatch_unit_suite" 0

e2e_step "fss_core_envelope_contracts" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-core --test agent_request_contract --test agent_response_contract --test contract_basis_admission_contract -- --nocapture
e2e_expect_exit "fss_core_envelope_contracts" 0

e2e_step "fss_242_live_four_surface_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --test fss_242_universal_envelope_dispatch_contract -- --nocapture
e2e_expect_exit "fss_242_live_four_surface_contract" 0

e2e_summary
