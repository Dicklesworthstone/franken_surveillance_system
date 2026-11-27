#!/usr/bin/env bash
# XFER-INV-001..010 (`fss-x4a.13.21..30`) E2E verification: all 10 normative ATP object-graph
# transfer invariants (immutable roots, deterministic TransferId, non-collapsed counters,
# root-last commit, path delivery != completion, repair cannot invent authority, adaptive
# transport fail-closed, cancellation owns staged work, retention/deletion explicit graph
# effects, and canonical tamper-evident journal/receipt evidence).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/xfer_invariants_proof.sh"

e2e_init "xfer_invariants_proof" "fss-x4a.13.21" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "xfer_invariants_proof_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-object --test xfer_invariants_proof_contract -- --nocapture
e2e_expect_exit "xfer_invariants_proof_contract" 0

e2e_step "xfer_supporting_atp_and_deletion_contracts" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-object \
    --test atp_lifecycle_contract \
    --test fss_127_object_graph_closure_contract \
    --test fss_128_post_repair_digest_gate_contract \
    --test fss_129_multipath_race_loser_drain_contract \
    --test fss_133_graph_complete_deletion_contract
e2e_expect_exit "xfer_supporting_atp_and_deletion_contracts" 0

e2e_summary
