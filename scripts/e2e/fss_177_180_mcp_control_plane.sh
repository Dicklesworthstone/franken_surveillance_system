#!/usr/bin/env bash
# End-to-end proof for WP-180 MCP control plane (FSS-177, FSS-178, FSS-179, FSS-180):
# - FSS-177 (fss-x4a.25.2): request-owned Asupersync MCP regions, live cancel/drain, bounded frames/outputs
# - FSS-178 (fss-x4a.25.3): durable application-owned task/session/case/claim/follow projection surviving SIGKILL
# - FSS-179 (fss-x4a.25.4): protocol taint, secret-canary containment, H3 privacy-mask/dual-gate redaction
# - FSS-180 (fss-x4a.25.5): exhaustive shell/SQL/vendor/codec/model/drone escape-hatch prohibition & 14-tool allowlist
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_177_180_mcp_control_plane.sh"

e2e_init "fss_177_180_mcp_control_plane" "fss-x4a.25.2" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_mcp_transport_and_budget_unit_suite" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --bin fss-mcp -- --nocapture
e2e_expect_exit "fss_mcp_transport_and_budget_unit_suite" 0

e2e_step "fss_177_180_mcp_control_plane_conformance" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --test fss_177_180_mcp_control_plane_conformance -- --nocapture
e2e_expect_exit "fss_177_180_mcp_control_plane_conformance" 0

e2e_step "operation_crosswalk_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --test operation_crosswalk_contract -- --nocapture
e2e_expect_exit "operation_crosswalk_contract" 0

e2e_step "mcp_14_ops_adversarial_security_and_privacy_mask_e2e" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --test mcp_14_ops_adversarial_e2e scenario_2_adversarial_security_privacy_masks_and_refusals -- --nocapture
e2e_expect_exit "mcp_14_ops_adversarial_security_and_privacy_mask_e2e" 0

e2e_step "mcp_control_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --test mcp_control_contract -- --nocapture
e2e_expect_exit "mcp_control_contract" 0

e2e_summary
