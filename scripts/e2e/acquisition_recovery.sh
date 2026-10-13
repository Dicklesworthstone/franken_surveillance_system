#!/usr/bin/env bash
# Focused supplementary native checks; full scripts/qualify.sh remains release authority.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

readonly toolchain=nightly-2026-08-31
cargo +"$toolchain" test --locked --offline --no-fail-fast -p fss-core \
  --test acquisition_lifecycle_contract \
  --test acquisition_recovery_contract \
  --test acquisition_reconnect_guard_contract
cargo +"$toolchain" test --locked --offline -p fss-core --lib \
  acquisition::recovery::checkpoint::tests
