#!/usr/bin/env bash
set -euo pipefail

# Realistic E2E runner for FSS-142 (`fss-x4a.14.13`: packed-weight and tiled CPU matrix kernels
# in safe Rust).
# Certifies 0-ULP scalar oracle equivalence across dense/1x1/grouped/depthwise/fused-SiLU packed
# Conv2d and 4x8 tiled broadcast MatMul, non-multiple edge shapes, IEEE-754 special values,
# multi-thread bit-exactness, packed resident bytes, cancellation, budget refusal, and FSS-141
# static dispatch integration.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "packed_conv2d_variants_and_fused_silu_are_0ulp_bit_exact_across_threads"
  echo "tiled_4x8_broadcast_matmul_edge_shapes_ieee754_specials_and_faults"
  exit 0
fi

cd "${ROOT_DIR}"
exec cargo test \
  --locked \
  --offline \
  -p fss-reference \
  --test fss_142_packed_tiled_matrix_kernels_contract \
  -- --nocapture "$@"
