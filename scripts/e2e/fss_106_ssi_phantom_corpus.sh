#!/usr/bin/env bash
# E2E proof driver for FSS-106 (fss-x4a.9.13): Negative-read phantom & SSI write-skew schedule corpus.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "ssi_and_negative_phantom_corpus_passes_all_schedules_deterministically"
    "ssi_corpus_cancel_and_hostile_wire_fail_closed"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "fss_106_ssi_phantom_corpus"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-ledger --test fss_106_ssi_phantom_corpus_contract -- "${s}" --exact --nocapture
done
e2e_finish
