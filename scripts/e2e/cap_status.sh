#!/usr/bin/env bash
# CAP- STATUS: `fss status --json --root <dir>` over real roots (fss-2h5zq.59 / fss-2h5zq.60).
#
# Runs the status contract target through the shared harness. Each case builds its own root
# (lab quiet and intrusion, MJPEG and Annex-B file imports, a recorded RTP session, an import
# cancelled before its manifest batch, a lock-held root, and missing/empty/corrupt/over-budget
# refusals), proves the read is read-only by tree digest, runs the readiness guard, and prints one
# CAPLOG record only after its assertions passed, so a failed assertion leaves its record missing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/cap_status.sh"
e2e_init "status" "fss-2h5zq.60" "$@"
# Every case must report; a missing record is a failure, not a silent skip.
export FSS_EXPECTED_ROSTER="legacy_unchanged,lab_roots,file_import_roots,rtpplay_root,refusals,incomplete_import,held_writer"
e2e_cargo_test "fss-cli" "status_real_root"
e2e_summary
