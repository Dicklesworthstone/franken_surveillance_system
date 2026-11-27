#!/usr/bin/env bash
# DOC-052 (`fss-x4a.5.52`) E2E verification: deterministic media movement (remux-before-transcode),
# live delivery surface clamps, 6 archive storage tiers with dated pricing, backend-neutral
# portability without semantic identity rewrite, and MediaDerivativeReceipt binding.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/doc_052_media_delivery_decision_card.sh"

e2e_init "doc_052_media_delivery_decision_card" "fss-x4a.5.52" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "doc_052_media_delivery_decision_card_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-tensor --test doc_052_media_delivery_decision_card_contract -- --nocapture
e2e_expect_exit "doc_052_media_delivery_decision_card_contract" 0

e2e_step "doc_041_media_derivative_receipt_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-tensor --test doc_041_media_derivative_receipt_contract
e2e_expect_exit "doc_041_media_derivative_receipt_contract" 0

e2e_summary
