#!/usr/bin/env bash
# FSS-054 (`fss-x4a.12.3`) E2E verification: bounded pure-Rust decode engine with scalar reference
# semantics across MJPEG/JPEG, H.264/AVC, and H.265/HEVC, including bit-exact conformance, hostile
# input/malformed media gauntlets, RTSP loopback reassembly, and decode/gap/custody receipts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_054_pure_rust_decode_engine.sh"

e2e_init "fss_054_pure_rust_decode_engine" "fss-x4a.12.3" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_054_codec_mjpeg_scalar_and_gauntlet" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-codec-mjpeg --lib --tests
e2e_expect_exit "fss_054_codec_mjpeg_scalar_and_gauntlet" 0

e2e_step "fss_054_codec_h264_scalar_and_gauntlet" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-codec-h264 --lib --tests
e2e_expect_exit "fss_054_codec_h264_scalar_and_gauntlet" 0

e2e_step "fss_054_codec_h265_scalar_and_gauntlet" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-codec-h265 --lib --tests
e2e_expect_exit "fss_054_codec_h265_scalar_and_gauntlet" 0

e2e_step "fss_054_reference_decode_gap_and_custody_receipts" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-reference \
    --test decode_jpeg_contract \
    --test decode_receipt_contract \
    --test decode_gap_coverage_contract \
    --test rtpdump_decode_contract \
    --test rtpdump_custody_decode_contract
e2e_expect_exit "fss_054_reference_decode_gap_and_custody_receipts" 0

e2e_summary
