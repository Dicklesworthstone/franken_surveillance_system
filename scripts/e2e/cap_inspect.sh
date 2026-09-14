#!/usr/bin/env bash
# scripts/e2e/cap_inspect.sh
# End-to-end runner for the CAP- DOCTOR0 read-only inspection contracts (fss-2h5zq.67).
#
# Runs the four inspect contract test targets through the shared harness in scripts/e2e/lib.sh
# (e2e_init / e2e_cargo_test / e2e_summary). Every corpus in those targets prints one CAPLOG
# record whose verdict, expected, and observed values are computed from its checks; lib.sh turns
# each record into one JSON-lines step, and a failed step, a malformed record, a target without
# any record, or a non-zero cargo exit fails the run. Nothing here patches or overrides lib.sh.
#
# Usage: scripts/e2e/cap_inspect.sh [--list] [--only <target>] [--verbose] [--keep-tmp]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

e2e_init "cap_inspect" "fss-2h5zq.67" "$@"

e2e_cargo_test "fss-object" "spool_inspect_contract"
e2e_cargo_test "fss-publication" "local_inspect_contract"
e2e_cargo_test "fss-ledger" "durable_inspect_contract"
e2e_cargo_test "fss-reference" "effect_journal_inspect_contract"

e2e_summary
