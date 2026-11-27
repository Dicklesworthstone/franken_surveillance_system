#!/usr/bin/env bash
# End-to-end proof for authorized projection graph-algorithm families FSS-154 through FSS-160
# (fss-x4a.23.4 .. fss-x4a.23.10):
# - FSS-154 dynamic connectivity reference vs optimized lanes + cancel/stale-snapshot refusals
# - FSS-155 bridges/articulation points + dominators/postdominators + privacy absence preservation
# - FSS-156 shortest path, multi-source distance, k-shortest diverse paths, & temporal reachability
# - FSS-157 matching, k-best assignment (preserving ambiguity), & min-cost flow
# - FSS-158 max-flow/min-cut & Gomory-Hu cut tree
# - FSS-159 SCC/condensation & topological/critical-path schedule
# - FSS-160 set-cover, submodular active perception, Steiner tree, & network interdiction
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_154_160_graph_families.sh"

e2e_init "fss_154_160_graph_families" "fss-x4a.23.4" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_154_160_authorized_projection_families_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-graph-algorithms --test fss_154_160_projection_families_contract -- --nocapture
e2e_expect_exit "fss_154_160_authorized_projection_families_contract" 0

e2e_step "certified_oracle_differential_suites" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-graph-algorithms \
  --test bridge_certification \
  --test weighted_certification \
  --test path_time_certification \
  --test optimization_certification \
  --test resilience_certification \
  --test set_cover_contract \
  --test submodular_contract
e2e_expect_exit "certified_oracle_differential_suites" 0

e2e_summary
