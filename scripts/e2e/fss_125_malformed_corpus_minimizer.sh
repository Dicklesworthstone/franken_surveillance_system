#!/usr/bin/env bash
# FSS-125 (`fss-x4a.12.24`, `TEST-MEDIA-MALFORMED-001`) E2E verification: malformed compressed-stream
# adversarial corpus, deterministic delta-debugging minimizer, canonical reproducer receipts, and
# cross-crate malformed-media gauntlets (container + H.264 + H.265 + MJPEG).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_125_malformed_corpus_minimizer.sh"

e2e_init "fss_125_malformed_corpus_minimizer" "fss-x4a.12.24" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_125_malformed_corpus_minimizer_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-container --test fss_125_malformed_corpus_minimizer_contract -- --nocapture
e2e_expect_exit "fss_125_malformed_corpus_minimizer_contract" 0

e2e_step "fss_125_demux_malformed_gauntlet" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-container --test demux_malformed_gauntlet
e2e_expect_exit "fss_125_demux_malformed_gauntlet" 0

e2e_summary
