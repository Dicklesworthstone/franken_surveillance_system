#!/usr/bin/env bash
# Focused supplementary native checks, not release authority.
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-tests}" in
  tests)
    status=0
    cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-reference \
      --test rtpdump_decode_contract --test rtpdump_retained_decode_contract \
      --test rtpdump_custody_decode_contract --test rtpdump_frame_receipt_contract \
      --test rtpdump_motion_contract \
      --test rtpdump_receipt_stream_contract \
      --test rtpdump_avc_contract --test rtpdump_recovery_contract || status=1
    cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-cli \
      --bin fss-decode-rtp --bin fss-file --test retained_rtp_decode_cli \
      --test rtp_current_custody_cli --test rtp_receipts_cli --test rtp_motion_cli || status=1
    exit "$status"
    ;;
  format)
    rustup run nightly-2026-08-31 rustfmt --check --edition 2024 --config skip_children=true \
      crates/fss-reference/src/ingest/pixel_change/rtp.rs \
      crates/fss-reference/tests/rtpdump_motion_contract.rs \
      crates/fss-reference/src/ingest/rtpdump/decode.rs \
      crates/fss-reference/src/ingest/rtpdump/recovery.rs \
      crates/fss-reference/src/ingest/rtpdump/recovery/decode.rs \
      crates/fss-reference/src/ingest/rtpdump/recovery/checked_decode.rs \
      crates/fss-reference/src/ingest/rtpdump/recovery/checked_decode/receipt.rs \
      crates/fss-reference/src/ingest/rtpdump/receipt_stream.rs \
      crates/fss-reference/tests/rtpdump_decode_contract.rs \
      crates/fss-reference/tests/rtpdump_retained_decode_contract.rs \
      crates/fss-reference/tests/rtpdump_custody_decode_contract.rs \
      crates/fss-reference/tests/rtpdump_frame_receipt_contract.rs \
      crates/fss-reference/tests/rtpdump_receipt_stream_contract.rs \
      crates/fss-cli/src/bin/fss-decode-rtp.rs \
      crates/fss-cli/src/bin/fss-decode-rtp/receipt_cmd.rs \
      crates/fss-cli/src/bin/fss-decode-rtp/motion_cmd.rs \
      crates/fss-cli/tests/rtp_motion_cli.rs \
      crates/fss-cli/src/bin/fss-file/pgm_stream.rs \
      crates/fss-cli/src/bin/fss-file/private_output.rs \
      crates/fss-cli/tests/retained_rtp_decode_cli.rs \
      crates/fss-cli/tests/rtp_current_custody_cli.rs \
      crates/fss-cli/tests/rtp_receipts_cli.rs
    ;;
  *) printf 'usage: %s [tests|format]\n' "$0" >&2; exit 2 ;;
esac
