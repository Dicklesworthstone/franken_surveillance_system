#!/usr/bin/env bash
# Direct local entrypoint; hosted execution is supplementary, never release authority.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --lib ingest::rtpdump::track::tests
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --test rtpdump_tracking_contract --test rtpdump_detection_contract
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --bin fss-decode-rtp --test rtp_tracking_cli --test rtp_detection_cli
