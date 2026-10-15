#!/usr/bin/env bash
# One reproducible native + presentation check, shared by local use and CI.
set -euo pipefail
cd "$(dirname "$0")/.."
node --test tests/test_dashboard_model.mjs
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --bin fss-dashboard --test dashboard_cli
cargo +nightly-2026-08-31 build --locked --offline -p fss-cli --bin fss-dashboard
python3 -B tests/test_dashboard_http.py --binary "${CARGO_TARGET_DIR:-target}/debug/fss-dashboard"
