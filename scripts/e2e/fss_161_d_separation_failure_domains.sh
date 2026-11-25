#!/usr/bin/env bash
set -euo pipefail

# Realistic E2E runner for FSS-161 (`fss-x4a.23.11`: d-separation & shared-failure-domain analysis).
# Exercises exact Bayes-Ball vs Lauritzen moralized-ancestral oracle over 240 seeded DAGs,
# shared-failure-domain corroboration refutation, capability/privacy redaction downgrades,
# cycle/budget/cancellation refusals, and FSSDSE01 v1 checksummed wire round-trips.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "bayes_ball_matches_moralized_ancestral_oracle_across_structures_and_seeded_dags"
  echo "shared_failure_domains_refute_corroboration_and_redaction_downgrades_certification"
  echo "cycles_authority_budget_cancellation_and_hostile_wire_fail_closed"
  exit 0
fi

cd "${ROOT_DIR}"
exec cargo test \
  --locked \
  -p fss-graph-algorithms \
  --test fss_161_d_separation_failure_domains_contract \
  -- --nocapture "$@"
