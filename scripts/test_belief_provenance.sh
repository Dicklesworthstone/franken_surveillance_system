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
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-object --lib 2>&1 | tee "$evidence/object.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-publication --lib --tests 2>&1 | tee "$evidence/publication.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-reference --test activity_model_contract --test activity_replay_contract --test activity_belief_contract 2>&1 | tee "$evidence/activity.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-reference --test deletion_belief_contract --test deletion_belief_admission_contract --test deletion_index_proof_contract --test deletion_batches_contract 2>&1 | tee "$evidence/deletion.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-reference --test local_source_hydration_contract --test deployment_source_hydration_contract --test deployment_disclosure_contract --test source_deletion_closure_contract --test source_binding_recovery_contract --test source_binding_registration_contract 2>&1 | tee "$evidence/hydration.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-reference --lib hydration::cursor_checkpoint 2>&1 | tee "$evidence/custody-checkpoints.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-reference --lib agent_session::checkpoint::journal::disclosure 2>&1 | tee "$evidence/disclosure-journal.log" || status=1
cargo +nightly-2026-08-31 test --locked --offline --no-fail-fast -p fss-reference --lib coordination::investigations::journal::source_citation 2>&1 | tee "$evidence/source-citation.log" || status=1
exit "$status"
