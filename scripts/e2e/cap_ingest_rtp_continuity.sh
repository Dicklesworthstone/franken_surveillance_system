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
export FSS_EXPECTED_ROSTER="clean_continuity_verified,loss_degraded_gap_refused,store_order_gap_refused,reorder_within_tolerance,reorder_beyond_tolerance,ssrc_change_new_generation,sequence_restart_new_generation,jitter_degraded_recovered,first_window_gap_recovered,consecutive_gaps_replayed,canonical_fixtures_unverified,cancellation_refused,stray_foreign_ssrc_refused,foreign_payload_type_refused_foreign_pt,foreign_payload_type_refused_foreign_pt_bound_pcmu,foreign_payload_type_refused_foreign_pt_pcmu_bound,pre_first_frame_loss_blocks,pre_first_frame_faults_block,reversed_offset_degrades,unsequenced_fault_by_arrival,contiguous_generations_outside,query_bounds_outside"
e2e_cargo_test "fss-reference" "rtp_continuity_contract"
e2e_summary
