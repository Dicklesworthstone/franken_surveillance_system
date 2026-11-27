#!/usr/bin/env bash
# MODEL-INV-002 / MODEL-INV-003 / MODEL-INV-005 / MODEL-INV-007 / MODEL-INV-008 E2E verification:
# versioned preprocessing program, explicit typed tensor semantics, derived-only non-authority
# outputs, offline immutable model artifacts, hard 8-dimension resource envelopes, and foreign
# runtime absence proof.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/model_invariants_proof.sh"

e2e_init "model_invariants_proof" "fss-x4a.14.23.8" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "model_invariants_proof_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-reference --test model_invariants_proof_contract -- --nocapture
e2e_expect_exit "model_invariants_proof_contract" 0

e2e_step "tensor_canonical_family" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-tensor --test canonical_tensor_family --test tensor_core_contract
e2e_expect_exit "tensor_canonical_family" 0

e2e_step "foreign_model_runtime_absence" -- \
  python3 "${ROOT}/scripts/foreign_model_runtime_absence.py"
e2e_expect_exit "foreign_model_runtime_absence" 0

e2e_summary
