#!/usr/bin/env bash
# End-to-end proof for all 9 prose-mandated graph algorithm families closing
# GRAPH-ALGORITHM-SEMANTIC-GAPS-001 (`fss-x4a.23.70`, `fss-x4a.23.70.1..9`):
# - ALG-FACILITY-001, ALG-ISO-001, ALG-MOTIF-001, ALG-SUBISO-001, ALG-KCORE-001,
#   ALG-PLANAR-001, ALG-LINKPRED-001, ALG-CDS-001, ALG-HYPER-001.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/graph_algorithm_gap_families.sh"

e2e_init "graph_algorithm_gap_families" "fss-x4a.23.70" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "atlas_gap_families_certification" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-graph-algorithms --test atlas_gap_families_certification -- --nocapture
e2e_expect_exit "atlas_gap_families_certification" 0

e2e_step "atlas_36_completion_certification" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-graph-algorithms --test atlas_completion_certification -- --nocapture
e2e_expect_exit "atlas_36_completion_certification" 0

e2e_step "architecture_registry_consistency_36_algorithms" -- \
  python3 "$ROOT/scripts/architecture_registry_consistency.py"
e2e_expect_exit "architecture_registry_consistency_36_algorithms" 0

e2e_summary
