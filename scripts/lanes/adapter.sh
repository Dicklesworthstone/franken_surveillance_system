#!/usr/bin/env bash
# adapter claim lane — RTSP capture driver behaviour against loopback servers.
#
# These suites stand up their own TCP listeners, so they exercise the adapter without registered
# hardware; QL-ADAPTER-001's hardware half is separate and still needs the units.
#
# NOT yet green: on macOS 13 pass and 64 fail with `os error 35` (EAGAIN) and
# ERR-CAPTURE-RTSP-ROOT-001, identically at -j1 --test-threads=1, so it is an environment or code
# prerequisite rather than concurrency. Kept out of `full`/`release` until it is green.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi
"${RUN[@]}" cargo --offline test -q -p fss-cli \
  --test capture_rtsp_cli \
  --test capture_rtsp_duration_cli \
  --test capture_rtsp_index_cli \
  --test capture_rtsp_interruption_cli \
  --test capture_rtsp_interruption_reconnect_cli \
  --test capture_rtsp_keepalive_cli \
  --test capture_rtsp_progress_cli
