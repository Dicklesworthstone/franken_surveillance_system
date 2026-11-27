#!/usr/bin/env bash
# DOC-049 (`fss-x4a.5.49`) E2E verification: bounded deterministic scalar BOCPD regime monitor
# strictly scoped to clamped advisory workload and sensor adaptation (zero event/effect authority).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/doc_049_bocpd_regime_monitor.sh"

e2e_init "doc_049_bocpd_regime_monitor" "fss-x4a.5.49" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "doc_049_bocpd_regime_monitor_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-runtime --test doc_049_bocpd_regime_monitor_contract -- --nocapture
e2e_expect_exit "doc_049_bocpd_regime_monitor_contract" 0

e2e_summary
