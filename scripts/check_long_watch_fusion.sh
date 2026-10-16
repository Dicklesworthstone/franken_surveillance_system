#!/usr/bin/env bash
# Native fixture checks only; repository-owned qualification and DSR remain release authority.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_NET_OFFLINE=true
status=0
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --lib event_fusion || status=1
cargo +nightly-2026-08-31 test --no-fail-fast --locked --offline -p fss-cli \
  --test event_fusion_cli --test watch_stream_detector_cli || status=1
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --test long_watch_contract || status=1
exit "$status"
