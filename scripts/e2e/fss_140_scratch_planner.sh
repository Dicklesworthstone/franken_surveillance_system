#!/usr/bin/env bash
set -euo pipefail

# Realistic E2E runner for FSS-140 (`fss-x4a.14.11`: shape/layout/liveness scratch planner).
# Verifies alignment-aware ScratchArenaPlan slot reuse on the real 12-node detector_split_pool.onnx
# graph and a 10-layer chain (80% activation reuse), independent pairwise zero-aliasing oracle,
# bit-exact equivalence with ScalarExecutor/CompiledScalarPlan, and fail-closed fault/wire checks.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "detector_and_deep_chain_scratch_plans_reuse_slots_zero_aliasing_and_match_scalar_execution"
  echo "scratch_planner_faults_alignment_budget_cancel_aliasing_oracle_and_wire_fail_closed"
  exit 0
fi

cd "${ROOT_DIR}"
exec cargo test \
  --locked \
  -p fss-reference \
  --test fss_140_scratch_planner_contract \
  -- --nocapture "$@"
