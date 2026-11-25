#!/usr/bin/env bash
set -euo pipefail

# Realistic E2E runner for FSS-139 (`fss-x4a.14.10`: scalar operator executor for first detector graph).
# Exercises the real 12-node ONNX detector fixture (`detector_split_pool.onnx`), raw RGB frame
# preprocessing, ModelInvocationReceipt binding, 4-way 0-ULP equivalence (ScalarExecutor ==
# PlannedScalar == OptimizedGraph 1T/2T == independent mathematical oracle), Model IR v2 detector
# neck/head (Conv2d + Silu + MaxPool2d + grouped Conv2d + Add + LayerNorm + MatMul + Sigmoid +
# Softmax), and fail-closed fault/budget/cancel/generation/dtype/non-finite abstention campaigns.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "first_detector_graph_real_onnx_preprocess_receipt_and_four_way_bit_exact_equivalence"
  echo "detector_neck_and_head_v2_silu_sigmoid_softmax_conv_matmul_equivalence"
  echo "detector_executor_faults_budget_cancel_generation_dtype_shape_and_nonfinite_abstain"
  exit 0
fi

cd "${ROOT_DIR}"
exec cargo test \
  --locked \
  -p fss-reference \
  --test fss_139_scalar_detector_executor_contract \
  -- --nocapture "$@"
