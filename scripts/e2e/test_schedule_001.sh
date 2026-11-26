#!/usr/bin/env bash
set -euo pipefail

# Realistic E2E proof-family runner for TEST-SCHEDULE-001 (`fss-x4a.28.3`:
# cancellation and fault schedule exploration over asupersync::lab::LabRuntime).
# Executes multi-seed/multi-worker schedule exploration, 128-seed RTSP/TUTK/daemon/alert
# deterministic fault campaign, cancellation completion/drain contracts, blocking-pool drain,
# and nested-region FORMAL-001/FORMAL-008 schedule proof manifest verification.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "lab_schedule_exploration"
  echo "asupersync_lab_fault_campaign"
  echo "cancellation_completion_contract"
  echo "drained_blocking_contract"
  echo "test_schedule_001_proof_family"
  exit 0
fi

cd "${ROOT_DIR}"
exec cargo test \
  --locked \
  --offline \
  -p fss-runtime \
  --test lab_schedule_exploration \
  --test asupersync_lab_fault_campaign \
  --test cancellation_completion_contract \
  --test drained_blocking_contract \
  --test test_schedule_001_proof_family \
  -- --nocapture "$@"
