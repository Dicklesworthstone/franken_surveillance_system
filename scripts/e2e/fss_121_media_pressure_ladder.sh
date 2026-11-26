#!/usr/bin/env bash
# FSS-121 (`fss-x4a.12.20`) E2E verification: registered media pressure degradation ladder
# (ordered derived shedding, source custody protection through Rung 4, mandatory coverage-gap
# witness on Rung 4/5, single-step recovery hysteresis, canonical receipts, and cancellation).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_121_media_pressure_ladder.sh"

e2e_init "fss_121_media_pressure_ladder" "fss-x4a.12.20" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_121_media_pressure_ladder_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-tensor --test fss_121_media_pressure_ladder_contract -- --nocapture
e2e_expect_exit "fss_121_media_pressure_ladder_contract" 0

e2e_summary
