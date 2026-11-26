#!/usr/bin/env bash
# DOC-039 (`fss-x4a.5.39`) E2E verification: enforces the integrated mechanical-sympathy
# and operation-cost doctrine across registered operation-cost rows, zero-global-lock/bounded
# concurrency guard, decoded-frame/tensor buffer accounting (FSS-058), generation-leased
# immutable frame pools (FSS-119), flat-combining commit batching/cancellation, scalar-backed
# SIMD/kernel/fusion/thermal contracts, and a full 8-step live QL-PERF-001 run + strict verifier.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/doc_039_mechanical_sympathy_doctrine.sh"

e2e_init "doc_039_mechanical_sympathy_doctrine" "fss-x4a.5.39" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "doc_039_concurrency_and_cost_registries" -- \
  bash -c 'set -euo pipefail; python3 "$1/scripts/slo_validate.py" && python3 "$1/tests/test_slo_operation_cost_consistency.py" && python3 "$1/scripts/asupersync_concurrency_guard.py"' _ "$ROOT"
e2e_expect_exit "doc_039_concurrency_and_cost_registries" 0

e2e_step "doc_039_buffer_accounting_and_frame_pools" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-tensor \
    --test fss_058_buffer_accounting_contract \
    --test fss_119_frame_pool_contract
e2e_expect_exit "doc_039_buffer_accounting_and_frame_pools" 0

e2e_step "doc_039_flat_combining_fairness_and_recovery" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-projection-store \
    --test concurrency_and_combiner
e2e_expect_exit "doc_039_flat_combining_fairness_and_recovery" 0

run_full_perf_lane_and_verify() {
  local tmp_base run_dir
  tmp_base="$(e2e_tmpdir)" || return 1
  run_dir="${tmp_base}/perf-full"
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
    bash "$ROOT/scripts/lanes/perf.sh" --receipt-dir "$run_dir"
  bash "$ROOT/scripts/lanes/perf.sh" --verify-receipt "${run_dir}/perf-receipt.json"
}

e2e_step "doc_039_live_full_ql_perf_lane_and_strict_verifier" -- run_full_perf_lane_and_verify
e2e_expect_exit "doc_039_live_full_ql_perf_lane_and_strict_verifier" 0

e2e_summary
