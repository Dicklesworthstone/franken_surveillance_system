#!/usr/bin/env bash
# FSS-123 (`fss-x4a.12.22`) E2E verification: safe SIMD image transform candidates
# (bilinear luma resize, BT.601 RGB-to-luma, min/max normalize) with bit-exact
# differential parity against FSS-122 scalar oracle and same-binary A/A + A/B
# experiment receipts (FSS-196).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_123_image_kernels_simd.sh"
e2e_init "fss_123_image_kernels_simd" "fss-x4a.12.22" "$@"
e2e_cargo_test "fss-reference" "image_kernels_simd_contract"
e2e_summary
