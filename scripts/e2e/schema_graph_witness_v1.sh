#!/usr/bin/env bash
# E2E proof driver for SCHEMA-GRAPH-WITNESS-001 (fss-x4a.30.13): GraphAlgorithmWitness (`fss.graph_algorithm_witness.v1`).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"

SCENARIOS=(
    "graph_witness_v1_roundtrips_binary_json_neg_zero_and_compatibility"
    "graph_witness_v1_refuses_hostile_json_wire_and_non_canonical_maps"
)

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' "${SCENARIOS[@]}"
    exit 0
fi

e2e_init "schema_graph_witness_v1"
for s in "${SCENARIOS[@]}"; do
    e2e_cargo_test "${s}" -p fss-core --test schema_graph_witness_v1_contract -- "${s}" --exact --nocapture
done
e2e_finish
