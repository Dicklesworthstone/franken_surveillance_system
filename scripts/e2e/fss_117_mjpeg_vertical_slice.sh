#!/usr/bin/env bash
# FSS-117 (`fss-x4a.12.16`) E2E verification: safe pure-Rust JPEG/MJPEG reference decoder
# vertical slice across baseline/progressive JPEG, HTTP/multipart MJPEG, RTP/RTSP loopback
# reassembly, AVI MJPEG container demux, CLI import, malformed gauntlets, and examples.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_117_mjpeg_vertical_slice.sh"

e2e_init "fss_117_mjpeg_vertical_slice" "fss-x4a.12.16" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_117_mjpeg_codec_and_gauntlet_suites" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-codec-mjpeg --lib --tests
e2e_expect_exit "fss_117_mjpeg_codec_and_gauntlet_suites" 0

e2e_step "fss_117_avi_mjpeg_container_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-container --test avi_mjpeg_contract
e2e_expect_exit "fss_117_avi_mjpeg_container_contract" 0

e2e_step "fss_117_rtsp_jpeg_import_cli" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --test rtsp_jpeg_import_cli
e2e_expect_exit "fss_117_rtsp_jpeg_import_cli" 0

e2e_step "fss_117_mjpeg_examples_compile" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline check --locked -q -p fss-codec-mjpeg --examples
e2e_expect_exit "fss_117_mjpeg_examples_compile" 0

e2e_summary
