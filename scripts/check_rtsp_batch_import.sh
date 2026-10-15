#!/usr/bin/env bash
# Native reference checks only; not camera qualification or DSR release authority.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

cargo +nightly-2026-08-31 test --locked --offline -p fss-cli \
  --bin fss-import-rtsp --bin fss-capture-rtsp
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli \
  --test capture_rtsp_cli --test capture_rtsp_reconnect_cli
