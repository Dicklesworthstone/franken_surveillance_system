#!/usr/bin/env bash
# FSS-058 (`fss-x4a.12.7`) E2E verification: deterministic decoded-frame and tensor buffer
# accounting (aligned checked reservations, per-class/per-generation/per-owner balances,
# pressure tiers, peak watermarks, revocation fences, canonical snapshots, and cancellation).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_058_buffer_accounting.sh"

e2e_init "fss_058_buffer_accounting" "fss-x4a.12.7" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_058_buffer_accounting_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-tensor --test fss_058_buffer_accounting_contract -- --nocapture
e2e_expect_exit "fss_058_buffer_accounting_contract" 0

e2e_summary
