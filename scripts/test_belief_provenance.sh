#!/usr/bin/env bash
# Supplementary native provenance contracts, not a replacement for scripts/qualify.sh.
set -uo pipefail
cd "$(dirname "$0")/.."
evidence=${1:?supply an evidence output directory}
mkdir -p "$evidence"
git rev-parse HEAD > "$evidence/commit.txt"
status=0
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-core --lib belief_verification 2>&1 | tee "$evidence/core.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-core --test belief_graph_contract --test belief_graph_scope_contract 2>&1 | tee "$evidence/graph.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-object --lib belief_verification 2>&1 | tee "$evidence/object.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-publication --lib --tests 2>&1 | tee "$evidence/publication.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-reference --test activity_replay_contract --test activity_model_contract 2>&1 | tee "$evidence/activity.log" || status=1
exit "$status"
