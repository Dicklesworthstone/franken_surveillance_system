#!/usr/bin/env bash
# scripts/e2e/cap_decode_receipt.sh — CAP- DECODE receipt/lineage e2e
# (fss-2h5zq.42). Runs the decode-receipt contract suite — canonical
# round-trips, stored-chunk tamper → typed CustodyMismatch before decode,
# restart reopen + fresh-root rebuild equality, unsupported/failed outcomes
# receipted — and requires a clean exit. (The suite's own assertions carry
# the verdict surface; the cargo shim routes the build per fleet policy.)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${REPO_ROOT}/scripts/e2e/lib.sh"

e2e_init "cap_decode_receipt" "fss-2h5zq.42" "$@"

e2e_step "decode_receipt_contract" cargo test -p fss-reference --test decode_receipt_contract -- --nocapture
e2e_expect_exit "decode_receipt_contract" 0

e2e_summary
