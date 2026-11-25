#!/usr/bin/env bash
# FSS-135 (`fss-x4a.13.19`) E2E verification: independent reconstruction of archive roots from
# raw manifests, GF(256) repair recovery, differential post-order parity with FSS-127, and FSSIRP01 wire.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_135_independent_reconstruction.sh"
e2e_init "fss_135_independent_reconstruction" "fss-x4a.13.19" "$@"
e2e_cargo_test "fss-object" "fss_135_independent_reconstruction_contract"
e2e_summary
