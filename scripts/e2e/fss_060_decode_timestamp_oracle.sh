#!/usr/bin/env bash
# FSS-060 (`fss-x4a.12.9`) E2E verification: deterministic decode and timestamp differential oracle
# (real fragmented AVC MP4 demux parity, rational i128 tick conversion, B-frame PTS display-order
# verification, gap-witness preservation, all 6 adversarial divergence classes, and cancellation).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_060_decode_timestamp_oracle.sh"

e2e_init "fss_060_decode_timestamp_oracle" "fss-x4a.12.9" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_060_decode_timestamp_oracle_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-container --test fss_060_decode_timestamp_oracle_contract -- --nocapture
e2e_expect_exit "fss_060_decode_timestamp_oracle_contract" 0

e2e_summary
