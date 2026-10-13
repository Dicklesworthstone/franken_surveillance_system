#!/usr/bin/env bash
# Focused supplementary native checks, not release authority.
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-tests}" in
  tests)
    cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-reference \
      --test rtpdump_decode_contract --test rtpdump_retained_decode_contract \
      --test rtpdump_avc_contract --test rtpdump_recovery_contract
    ;;
  format)
    rustup run nightly-2026-08-31 rustfmt --check --edition 2024 --config skip_children=true \
      crates/fss-reference/src/ingest/rtpdump/decode.rs \
      crates/fss-reference/src/ingest/rtpdump/recovery.rs \
      crates/fss-reference/src/ingest/rtpdump/recovery/decode.rs \
      crates/fss-reference/tests/rtpdump_decode_contract.rs \
      crates/fss-reference/tests/rtpdump_retained_decode_contract.rs
    ;;
  *) printf 'usage: %s [tests|format]\n' "$0" >&2; exit 2 ;;
esac
