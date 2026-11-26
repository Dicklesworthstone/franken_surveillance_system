#!/usr/bin/env bash
set -euo pipefail

# Realistic E2E runner for FSS-143 (`fss-x4a.14.14`: model preprocess/postprocess fusion laws).
# Verifies 0-ULP equivalence across all 24 preprocess filter/aspect/channel/scale combinations,
# identity-resize composition, postprocess monotonic-logit/unletterbox/canonical-NMS fusion with
# permutation invariance, and hostile FSSMFU01 wire decoding.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "preprocess_and_identity_resize_fusion_laws_are_bit_exact_across_all_modes"
  echo "postprocess_fusion_law_nms_permutation_invariance_faults_and_wire"
  exit 0
fi

cd "${ROOT_DIR}"
exec cargo test \
  --locked \
  -p fss-reference \
  --test fss_143_preprocess_postprocess_fusion_contract \
  -- --nocapture "$@"
