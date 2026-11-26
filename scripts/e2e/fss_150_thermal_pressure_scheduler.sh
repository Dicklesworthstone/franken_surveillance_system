#!/usr/bin/env bash
set -euo pipefail

# Realistic E2E runner for FSS-150 (`fss-x4a.14.21`: CPU thermal/pressure-aware model scheduler
# with hard floors).
# Verifies exhaustive 96-case differential oracle parity, critical hard-floor preemption,
# thermal hysteresis anti-flapping, idempotency/quarantine/stale-auth/cancellation faults,
# live detector execution invariance across thermal throttling, and hostile FSSMMS01 wire checks.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "exhaustive_thermal_pressure_class_matrix_matches_independent_oracle"
  echo "critical_hard_floor_preempts_lower_classes_and_thermal_hysteresis_prevents_flapping"
  echo "idempotency_quarantine_stale_auth_cancel_live_detector_and_hostile_wire_fail_closed"
  exit 0
fi

cd "${ROOT_DIR}"
exec cargo test \
  --locked \
  --offline \
  -p fss-reference \
  --test fss_150_thermal_pressure_scheduler_contract \
  -- --nocapture "$@"
