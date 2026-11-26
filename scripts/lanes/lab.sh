#!/usr/bin/env bash
# QL-LAB-001 (local half) — deterministic lab replays, crash matrix, recovery, ingest, and
# TEST-SCHEDULE-001 cancellation/fault schedule exploration contracts.
#
# Cold-process tests over the lab runtime; no camera or provider is contacted.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi
"${RUN[@]}" cargo --offline test -q -p fss-runtime \
  --test lab_schedule_exploration \
  --test asupersync_lab_fault_campaign \
  --test cancellation_completion_contract \
  --test drained_blocking_contract \
  --test test_schedule_001_proof_family
"${RUN[@]}" cargo --offline test -q -p fss-cli \
  --test lab_cli \
  --test lab_crash_matrix_cli \
  --test lab_decode_cli \
  --test lab_file_activity_cli \
  --test lab_ingest_cli \
  --test lab_real_crates \
  --test lab_recover_cli
