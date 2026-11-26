#!/usr/bin/env bash
# FSS-057 (`fss-x4a.12.6`) E2E verification: deterministic live preview bounded fan-out
# (zero-copy FramePool lease fan-out, drop-oldest-unviewed bounded queues with 0 leaks,
# privacy-mask egress gate, MediaDegradationRung stride/pause shedding, priority lease caps,
# generation advance drain, tamper-evident PreviewFanoutReceipt, and cooperative cancellation).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_057_preview_fanout.sh"

e2e_init "fss_057_preview_fanout" "fss-x4a.12.6" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_057_preview_fanout_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-tensor --test fss_057_preview_fanout_contract -- --nocapture
e2e_expect_exit "fss_057_preview_fanout_contract" 0

e2e_summary
