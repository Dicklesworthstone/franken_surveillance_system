#!/usr/bin/env bash
# scripts/e2e/cap_rtsp_parser.sh — CAP- RTSP parser e2e (fss-2h5zq.33).
# Per transcript: log the event-kind histogram, the SDP summary (PT, clock,
# has_sps_pps; never o= or c= lines), and the error ids. Runs the transcript
# contract suite as the verification step (the suite itself pins every-byte
# splits, the credential guard, and the 10k-mutation no-panic proof).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${REPO_ROOT}/scripts/e2e/lib.sh"

e2e_init "cap_rtsp_parser" "fss-2h5zq.33" "$@"

# The contract suite carries the full verification surface.
e2e_step "rtsp_transcript_contract" env RUST_SHIM_LOCAL_IDE=1 rustup run nightly-2026-08-31 cargo test -p fss-reference --test rtsp_transcript_contract -- --nocapture
e2e_expect_exit "rtsp_transcript_contract" 0

e2e_summary
