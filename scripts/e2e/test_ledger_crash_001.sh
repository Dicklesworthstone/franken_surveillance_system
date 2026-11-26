#!/usr/bin/env bash
set -euo pipefail

# Registered proof family E2E runner for TEST-LEDGER-CRASH-001 (`fss-x4a.28.8`, GATE-040):
# exercises 20 durable kill points across v1 Journal (all 8 AppendPhase variants), v1
# DurableReferenceLedger vs LedgerOracle, v2 MerkleEpochLedger multi-epoch rollover + torn tails +
# corrupt checkpoint quarantine, FSS-033 v1->v2 migration crash, FSS-034 rebuild cursor checkpoint
# corruption, and FSS-036 retention/hold atomic persistence with leftover temp isolation.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"

if [[ "${1:-}" == "--list" ]]; then
  echo "test_ledger_crash_001_exhaustive_kill_points_every_durable_transition"
  exit 0
fi

cd "${ROOT_DIR}"
exec cargo test \
  --locked \
  -p fss-ledger \
  --test test_ledger_crash_001_proof_family \
  -- --nocapture "$@"
