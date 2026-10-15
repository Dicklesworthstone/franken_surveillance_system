#!/usr/bin/env bash
# Shared native and presentation checks; no hidden workflow-only test logic.
set -euo pipefail
cd "$(dirname "$0")/.."
node --test tests/test_dashboard_model.mjs tests/test_spatial_model.mjs
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --bin fss-dashboard --test dashboard_cli
cargo +nightly-2026-08-31 build --locked --offline -p fss-cli --bin fss-dashboard --bin fss-file
python3 -B tests/test_dashboard_http.py --binary "${CARGO_TARGET_DIR:-target}/debug/fss-dashboard"
python3 -B tests/test_dashboard_spatial_http.py --binary "${CARGO_TARGET_DIR:-target}/debug/fss-dashboard" --importer "${CARGO_TARGET_DIR:-target}/debug/fss-file"
