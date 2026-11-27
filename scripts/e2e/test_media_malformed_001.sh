#!/usr/bin/env bash
# TEST-MEDIA-MALFORMED-001 (`fss-x4a.28.4`, mandatory before `GATE-020`) E2E verification:
# corrupt/hostile codec & container corpus across all 5 pure-Rust media crates, hard output
# dimension/byte/frame bounds, stale generation refusal, cooperative cancellation, zero buffer
# leaks, deterministic delta-debugging minimization (`FSS-125`), and sealed proof manifest.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/test_media_malformed_001.sh"

e2e_init "test_media_malformed_001" "fss-x4a.28.4" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "test_media_malformed_001_proof_family" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-reference --test test_media_malformed_001_proof_family -- --nocapture
e2e_expect_exit "test_media_malformed_001_proof_family" 0

e2e_step "test_media_malformed_001_container_gauntlets" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-container \
    --test fss_125_malformed_corpus_minimizer_contract \
    --test demux_malformed_gauntlet
e2e_expect_exit "test_media_malformed_001_container_gauntlets" 0

e2e_step "test_media_malformed_001_pure_rust_codecs" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-codec-mjpeg -p fss-codec-jpeg-encode -p fss-codec-h264 -p fss-codec-h265 --lib --tests
e2e_expect_exit "test_media_malformed_001_pure_rust_codecs" 0

e2e_summary
