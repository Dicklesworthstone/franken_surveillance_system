#!/usr/bin/env bash
# FSS-119 (`fss-x4a.12.18`) E2E verification: generation-leased immutable frame pools
# (zero-copy linear leases over TensorStorage + BufferAccountant, lease fan-out caps,
# generation retirement drain, FIFO unleased reclamation, canonical receipts, and cancellation).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_119_frame_pool.sh"

e2e_init "fss_119_frame_pool" "fss-x4a.12.18" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_119_frame_pool_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-tensor --test fss_119_frame_pool_contract -- --nocapture
e2e_expect_exit "fss_119_frame_pool_contract" 0

e2e_summary
