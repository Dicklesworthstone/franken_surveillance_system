#!/usr/bin/env bash
# FSS-124 (`fss-x4a.12.23`) E2E verification: first admitted pure-Rust H.264 profile decoder subset
# (Constrained Baseline, Main, and High 8-bit 4:2:0 scalar decoder, bit-exact FFmpeg oracle SHA-256
# conformance, POC types 0/1/2, MMCO/random-access recovery, hostile input refusal, and malformed
# media gauntlet).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_124_h264_profile_decoder.sh"

e2e_init "fss_124_h264_profile_decoder" "fss-x4a.12.23" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_124_h264_lib_and_conformance_tests" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-codec-h264 \
    --lib \
    --test decode_conformance \
    --test real_stream_contract \
    --test access_unit_boundary \
    --test poc_type1 \
    --test poc_type1_rtp \
    --test random_access_recovery \
    --test hostile_input \
    --test malformed_media_gauntlet
e2e_expect_exit "fss_124_h264_lib_and_conformance_tests" 0

e2e_summary
