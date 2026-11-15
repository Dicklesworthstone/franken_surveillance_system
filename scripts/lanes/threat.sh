#!/usr/bin/env bash
# threat claim lane — multi-source corroboration contracts (independent evidence, fusion, streams).
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi
"${RUN[@]}" cargo --offline test -q -p fss-cli \
  --test corroborate_cli_contract \
  --test corroborate_fusion_cli_contract \
  --test corroborate_stream_cli \
  --test corroborate_stream_detector_cli
