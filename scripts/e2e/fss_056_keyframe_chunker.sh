#!/usr/bin/env bash
# FSS-056 (`fss-x4a.12.5`) E2E verification: deterministic keyframe-aware media chunker
# (pre-sync discard caps, random-access GOP sealing, open-GOP bound quarantine, gap interruption
# sync reset, canonical chunk receipts, and cooperative cancellation).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_056_keyframe_chunker.sh"

e2e_init "fss_056_keyframe_chunker" "fss-x4a.12.5" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_056_keyframe_chunker_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-container --test fss_056_keyframe_chunker_contract -- --nocapture
e2e_expect_exit "fss_056_keyframe_chunker_contract" 0

e2e_summary
