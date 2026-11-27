#!/usr/bin/env bash
# TEST-MODEL-HOST-001 (`fss-x4a.28.10`) E2E verification: registered proof family covering
# OOM/memory-pressure refusal, hang/deadline/cancellation drain, crash/panic isolation,
# malformed-output/latest-alias refusal, zero-leak resource cleanup, privacy minimization
# before inference (`PRIV-003`), and foreign-runtime absence (`FSS-149`).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/test_model_host_001.sh"

e2e_init "test_model_host_001" "fss-x4a.28.10" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "test_model_host_001_proof_family" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-reference --test test_model_host_001_proof_family -- --nocapture
e2e_expect_exit "test_model_host_001_proof_family" 0

e2e_step "test_model_host_001_quotas_family" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-model-ir --test quotas_family
e2e_expect_exit "test_model_host_001_quotas_family" 0

e2e_step "test_model_host_001_foreign_runtime_absence" -- \
  python3 "${ROOT}/scripts/foreign_model_runtime_absence.py"
e2e_expect_exit "test_model_host_001_foreign_runtime_absence" 0

e2e_summary
