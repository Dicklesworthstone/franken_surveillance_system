#!/usr/bin/env bash
# End-to-end proof for FSS-164 (fss-x4a.23.14): full-recompute versus incremental graph equivalence
# fuzzer across ALG-DYNCONN-001, ALG-ZSET-001 standing predicates, H_vis incremental updates, and
# G_phys crosswalk delta updates.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_164_incremental_equivalence_fuzzer.sh"

e2e_init "fss_164_incremental_equivalence_fuzzer" "fss-x4a.23.14" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_164_incremental_vs_full_recompute_fuzzer" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-graph-algorithms --test fss_164_incremental_equivalence_fuzzer -- --nocapture
e2e_expect_exit "fss_164_incremental_vs_full_recompute_fuzzer" 0

e2e_summary
