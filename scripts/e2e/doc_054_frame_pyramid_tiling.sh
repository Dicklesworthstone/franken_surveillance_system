#!/usr/bin/env bash
# DOC-054 (`fss-x4a.5.54`) E2E verification: shared multi-scale frame pyramids, cache-friendly
# spatial tiling, and optional accelerator isolation behind deterministic scalar reference truth.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/doc_054_frame_pyramid_tiling.sh"

e2e_init "doc_054_frame_pyramid_tiling" "fss-x4a.5.54" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "doc_054_frame_pyramid_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-tensor --test doc_054_frame_pyramid_contract -- --nocapture
e2e_expect_exit "doc_054_frame_pyramid_contract" 0

e2e_summary
