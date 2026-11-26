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
"${RUN[@]}" cargo --offline test -q -p fss-reference \
  --test fss_139_scalar_detector_executor_contract \
  --test fss_140_scratch_planner_contract \
  --test fss_141_kernel_dispatch_receipts_contract \
  --test fss_143_preprocess_postprocess_fusion_contract
"${RUN[@]}" cargo --offline test -q -p fss-cli \
  --test inference_cli_contract \
  --test detector_cascade_cli_contract \
  --test watch_stream_detector_cli
