#!/usr/bin/env bash
# DOC-041 (`fss-x4a.5.41`) E2E verification: canonical MediaDerivativeReceipt lineage
# (multi-stage parent composition, retained-anchor & explicit-omission bindings, mask-before-egress
# and root-last publication enforcement, non-impersonation of raw source custody, latest-alias and
# deleted-parent refusal, wire-level forgery refusal, and cooperative cancellation).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/doc_041_media_derivative_receipt.sh"

e2e_init "doc_041_media_derivative_receipt" "fss-x4a.5.41" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "doc_041_media_derivative_receipt_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-tensor --test doc_041_media_derivative_receipt_contract -- --nocapture
e2e_expect_exit "doc_041_media_derivative_receipt_contract" 0

e2e_summary
