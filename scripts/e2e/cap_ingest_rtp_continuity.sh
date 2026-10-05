#!/usr/bin/env bash
# CAP- INGEST recorded RTP continuity -> AcquisitionSession (fss-2h5zq.29 / fss-2h5zq.30).
#
# Runs the continuity contract target through the shared harness. Each test prints one CAPLOG
# record per variant (clean, loss, store order, reorder within/beyond tolerance, SSRC change,
# sequence restart, jitter, canonical non-decodable fixtures, cancellation) carrying the session
# transitions, witness or evidence digests and degradation reasons; it prints only after its
# assertions passed, so a failed assertion fails the cargo step and leaves its record missing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_ingest_rtp_continuity.sh"
e2e_init "ingest_rtp_continuity" "fss-2h5zq.30" "$@"
# Every variant must report; a missing record is a failure, not a silent skip.
export FSS_EXPECTED_ROSTER="clean_continuity_verified,loss_degraded_gap_refused,store_order_gap_refused,reorder_within_tolerance,reorder_beyond_tolerance,ssrc_change_new_generation,sequence_restart_new_generation,jitter_degraded_not_reverified,canonical_fixtures_unverified,cancellation_refused"
e2e_cargo_test "fss-reference" "rtp_continuity_contract"
e2e_summary
