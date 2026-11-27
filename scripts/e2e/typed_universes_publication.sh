#!/usr/bin/env bash
# Complete 12-universe typed graph atlas E2E verification (`GRAPH-PROJECTION-SEMANTICS-001`, `fss-x4a.23.69`):
# - PROJ-PHYSICAL-001   (`G_phys`,     `fss-x4a.23.69.1`)
# - PROJ-VISIBILITY-001 (`H_vis`,      `fss-x4a.23.69.2`)
# - PROJ-SENSOR-001     (`G_sensor`,   `fss-x4a.23.69.3`)
# - PROJ-TIME-001       (`G_time`,     `fss-x4a.23.69.4`)
# - PROJ-ASSOC-001      (`G_assoc`,    `fss-x4a.23.69.5`)
# - PROJ-EVIDENCE-001   (`G_evidence`, `fss-x4a.23.69.6`)
# - PROJ-EFFECT-001     (`G_effect`,   `fss-x4a.23.69.7`)
# - PROJ-OBJECT-001     (`G_object`,   `fss-x4a.23.69.8`)
# - PROJ-AUTH-001       (`G_auth`,     `fss-x4a.23.69.9`)
# - PROJ-MEMORY-001     (`G_memory`,   `fss-x4a.23.69.10`)
# - PROJ-AGENT-001      (`G_agent`,    `fss-x4a.23.69.11`)
# - PROJ-WORLD-001      (`G_world`,    `fss-x4a.23.69.12`)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/typed_universes_publication.sh"

e2e_init "typed_universes_publication" "fss-x4a.23.69" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "typed_universes_publication_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-graph-algorithms --test typed_universes_publication_contract -- --nocapture
e2e_expect_exit "typed_universes_publication_contract" 0

e2e_step "typed_universes_complete_atlas_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-graph-algorithms --test typed_universes_complete_atlas_contract -- --nocapture
e2e_expect_exit "typed_universes_complete_atlas_contract" 0

e2e_step "immutable_projection_core_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-graph-algorithms --lib projection::
e2e_expect_exit "immutable_projection_core_contract" 0

e2e_summary
