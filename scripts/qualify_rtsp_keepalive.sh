#!/usr/bin/env bash
# Supplementary native contracts, not field qualification or release authority.
set -euo pipefail
cd "$(dirname "$0")/.."
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-0}"
export CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-0}"
export CARGO_NET_OFFLINE=true
status=0
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --lib rtsp::authentication::tests || status=1
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --lib rtsp::live_archive || status=1
cargo +nightly-2026-08-31 test --no-fail-fast --locked --offline -p fss-reference \
  --test rtsp_keepalive_contract --test rtsp_payload_selection_streaming \
  --test live_hevc_archive_contract --test rtsp_prefix_recovery_contract \
  --test rtsp_read_reset_contract || status=1
cargo +nightly-2026-08-31 test --no-fail-fast --locked --offline -p fss-cli \
  --bin fss-capture-rtsp --test capture_rtsp_keepalive_cli \
  --test capture_rtsp_reconnect_cli || status=1
exit "$status"
