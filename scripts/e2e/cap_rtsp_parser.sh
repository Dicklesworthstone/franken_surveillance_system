#!/usr/bin/env bash
# scripts/e2e/cap_rtsp_parser.sh — CAP- RTSP parser e2e (fss-2h5zq.33).
# Runs the transcript contract suite — which pins per-transcript event
# sequences, every-byte incremental splits, the credential guard + mutant
# table, limit tests, and the 10k-mutation no-panic proof — and requires a
# clean exit. (The suite's own assertions carry the verdict surface; the
# cargo shim routes the build per fleet policy.)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
source "${REPO_ROOT}/scripts/e2e/lib.sh"

e2e_init "cap_rtsp_parser" "fss-2h5zq.33" "$@"

e2e_step "rtsp_transcript_contract" cargo test -p fss-reference --test rtsp_transcript_contract -- --nocapture
e2e_expect_exit "rtsp_transcript_contract" 0

e2e_summary
