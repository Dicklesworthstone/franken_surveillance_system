#!/usr/bin/env bash
# End-to-end proof for FSS-235 (fss-x4a.24.35):
# Direct Rust API, live `fss` CLI binary, and live `fss-mcp` stdio server
# 3-surface transcript-equivalence harness covering all 14 registered AOP-001..AOP-014
# operations, exact read-only/query/refusal parity, stateful mission lifecycle parity,
# vault canary containment, and planted-bug divergence detection.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_235_transcript_equivalence.sh"

e2e_init "fss_235_transcript_equivalence" "fss-x4a.24.35" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "transcript_equivalence_unit_suite" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --lib transcript_equivalence -- --nocapture
e2e_expect_exit "transcript_equivalence_unit_suite" 0

e2e_step "fss_235_live_three_surface_harness" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --test fss_235_transcript_equivalence_harness -- --nocapture
e2e_expect_exit "fss_235_live_three_surface_harness" 0

e2e_step "operation_crosswalk_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --test operation_crosswalk_contract -- --nocapture
e2e_expect_exit "operation_crosswalk_contract" 0

e2e_summary
