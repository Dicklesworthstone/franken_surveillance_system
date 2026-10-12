#!/usr/bin/env bash
# scripts/e2e/cap_decode_receipt.sh — CAP- DECODE receipt/lineage e2e
# (fss-2h5zq.42). Ingests an MJPEG fixture, decodes all capsules and logs,
# per frame: capsule id, source digest, tensor digest and receipt digest.
# The tamper step's typed refusal is proven by the suite itself.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${REPO_ROOT}/scripts/e2e/lib.sh"

e2e_init "cap_decode_receipt" "fss-2h5zq.42" "$@"

# The decode-receipt contract suite carries the full verification surface:
# canonical round-trips, stored-chunk tamper (typed CustodyMismatch before
# decode, nothing retained), restart reopen + fresh-root rebuild equality,
# and unsupported/failed outcomes receipted.
e2e_step "decode_receipt_contract" env RUST_SHIM_LOCAL_IDE=1 rustup run nightly-2026-08-31 cargo test -p fss-reference --test decode_receipt_contract -- --nocapture
e2e_expect_exit "decode_receipt_contract" 0

e2e_summary
