#!/usr/bin/env bash
# End-to-end proof for DOC-050 (fss-x4a.5.50 / IMP-AS-SUBJECT-001 / INT-AS-001):
# Typed semantic subject fabric with separate Packet, Authority, and Reasoning
# service classes, versioned subject schemas with tombstones, capability/privacy/
# locality/pressure/profile route compilation, ATP immutable object-graph boundary,
# bounded queues, weighted fairness, backpressure, lease fencing, idempotency,
# request->drain->finalize quiescence, and deterministic lab scheduling invariance.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/doc_050_semantic_subject_fabric.sh"

e2e_init "doc_050_semantic_subject_fabric" "fss-x4a.5.50" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "semantic_subject_unit_suite" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-runtime --lib semantic_subject -- --nocapture
e2e_expect_exit "semantic_subject_unit_suite" 0

e2e_step "doc_050_semantic_subject_fabric_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-runtime --test doc_050_semantic_subject_fabric_contract -- --nocapture
e2e_expect_exit "doc_050_semantic_subject_fabric_contract" 0

e2e_step "semantic_plane_checker" -- python3 "$ROOT/scripts/semantic_plane_checker.py"
e2e_expect_exit "semantic_plane_checker" 0

e2e_step "asupersync_concurrency_guard" -- python3 "$ROOT/scripts/asupersync_concurrency_guard.py"
e2e_expect_exit "asupersync_concurrency_guard" 0

e2e_summary
