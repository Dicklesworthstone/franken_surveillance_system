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
"${RUN[@]}" cargo --offline test -q -p fss-cli \
  --test inference_cli_contract \
  --test detector_cascade_cli_contract \
  --test watch_stream_detector_cli
