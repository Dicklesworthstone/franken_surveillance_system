#!/usr/bin/env bash
# FSS-055 (`fss-x4a.12.4`) E2E verification: bounded pure-Rust encode and rendition kernels
# (deterministic integer JPEG grayscale/RGB 4:4:4 baseline encoding, source-pin binding,
# bounded work/output ceilings, cooperative cancellation, file range, frame window, and MJPEG stream).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_055_encode_rendition_kernels.sh"

e2e_init "fss_055_encode_rendition_kernels" "fss-x4a.12.4" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_055_jpeg_encode_unit_and_contracts" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-codec-jpeg-encode --lib --tests
e2e_expect_exit "fss_055_jpeg_encode_unit_and_contracts" 0

e2e_summary
