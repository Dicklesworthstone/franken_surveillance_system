#!/usr/bin/env bash
# model claim lane — inference, detector cascade and stream-detector contracts.
#
# No weights are downloaded: the suites pin behaviour against retained fixtures and registered
# identities only.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

export CARGO_NET_OFFLINE=true
export RUSTUP_AUTO_INSTALL=0
export RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}"

"${RUN[@]}" cargo --offline test --locked -q -p fss-reference \
  --test fss_139_scalar_detector_executor_contract \
  --test fss_140_scratch_planner_contract \
  --test fss_141_kernel_dispatch_receipts_contract \
  --test fss_142_packed_tiled_matrix_kernels_contract \
  --test fss_143_preprocess_postprocess_fusion_contract \
  --test fss_150_thermal_pressure_scheduler_contract \
  --test model_invariants_proof_contract \
  --test test_model_host_001_proof_family
"${RUN[@]}" cargo --offline test --locked -q -p fss-cli \
  --test inference_cli_contract \
  --test detector_cascade_cli_contract \
  --test watch_stream_detector_cli
