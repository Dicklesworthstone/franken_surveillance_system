#!/usr/bin/env bash
# The retained-file lifecycle, including torn appends and a pre-publication staging crash.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_ingest_file_session.sh"
e2e_init "ingest_file_session" "fss-2h5zq.26" "$@"
export FSS_EXPECTED_ROSTER="complete,truncated,malformed_gaps,cancel-stage,cancel-publish,refused,capacity,indeterminate,resumed_after_cancel,reopened,malformed_mid_file,crash_before_publish,first_append_body,first_append_commit"

# The reproduction command names the observed outcome. Several outcomes share one Rust test.
case "${_E2E_ONLY:-}" in
    malformed_gaps) filter=truncated_and_gapped ;;
    cancel-stage|cancel-publish) filter=cancellation_mid_import ;;
    resumed_after_cancel) filter=import_resumed_after_cancellation ;;
    reopened) filter=retained_history_survives_reopen ;;
    crash_before_publish) filter=crash_before_first_publication ;;
    first_append_body|first_append_commit) filter=first_capsule_append ;;
    *) filter="" ;;
esac
e2e_cargo_test "fss-reference" "file_session_contract" "$filter"
e2e_summary
