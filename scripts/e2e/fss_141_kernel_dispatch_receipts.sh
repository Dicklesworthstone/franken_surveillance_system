#!/usr/bin/env bash
set -euo pipefail

# Realistic E2E runner for FSS-141 (`fss-x4a.14.12`: static kernel dispatch & decision-path receipts).
# Verifies thread-count-invariant static dispatch receipts on the real 12-node detector_split_pool.onnx
# graph, 0-ULP scalar oracle verification, strict zero-fallback refusal, hybrid fallback receipts,
# cancellation, budget bounds, and hostile FSSKDR01 wire decoding.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "detector_static_dispatch_is_thread_invariant_0ulp_oracle_verified_and_wire_deterministic"
  echo "hybrid_fallback_strict_refusal_cancel_budget_and_hostile_wire_fail_closed"
  exit 0
fi

cd "${ROOT_DIR}"
exec cargo test \
  --locked \
  -p fss-reference \
  --test fss_141_kernel_dispatch_receipts_contract \
  -- --nocapture "$@"
