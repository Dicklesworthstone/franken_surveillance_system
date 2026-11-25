#!/usr/bin/env bash
# E2E proof driver for FSS-147 (fss-x4a.14.18): Model package RaptorQ/GF(256) protection & ATP activation.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "model_package_gf256_protection_erasure_recovery_root_last_activation_and_rollback"
    "model_atp_refuses_latest_license_violation_missing_approval_corrupt_blob_and_wire"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "fss_147_model_package_raptorq_atp_activation"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-object --test fss_147_model_package_raptorq_atp_activation_contract -- "${s}" --exact --nocapture
done
e2e_finish
