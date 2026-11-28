#!/usr/bin/env bash
# End-to-end proof for DOC-033 (fss-x4a.5.33 / INV-088):
# Deterministic staged natural-language to taint-preserving AgentQueryPlan compiler,
# capability-first/privacy-first symbol projection (zero count/rank leak), all 15
# ARES-001..ARES-015 resource URI templates, direct/indirect prompt-injection refusal,
# effectful-intent downgrade to witnessed preparedIntentDraftId, dangerous ambiguity
# (ERR-AGENT-AMBIGUOUS-001), orthogonal epistemic states, 11-dimension cost/budget
# gating, ContractBasis/anchor/world-envelope binding, live AgentRequestEnvelope
# dispatch against a real ReferenceDeployment, and vault canary containment.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/doc_033_nl_query_plan_compiler.sh"

e2e_init "doc_033_nl_query_plan_compiler" "fss-x4a.5.33" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "nl_query_compiler_unit_suite" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-reference --lib nl_query_compiler -- --nocapture
e2e_expect_exit "nl_query_compiler_unit_suite" 0

e2e_step "fss_core_agent_query_plan_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-core --test agent_query_plan_contract -- --nocapture
e2e_expect_exit "fss_core_agent_query_plan_contract" 0

e2e_step "doc_033_live_nl_query_plan_compiler_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --test doc_033_nl_query_plan_compiler_contract -- --nocapture
e2e_expect_exit "doc_033_live_nl_query_plan_compiler_contract" 0

e2e_summary
