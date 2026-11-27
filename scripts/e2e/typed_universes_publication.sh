#!/usr/bin/env bash
# Typed graph universes E2E verification (`H_vis`, `G_effect`, `G_auth`, `G_world`):
# - PROJ-VISIBILITY-001 (`fss-x4a.23.69.2`)
# - PROJ-EFFECT-001 (`fss-x4a.23.69.7`)
# - PROJ-AUTH-001 (`fss-x4a.23.69.9`)
# - PROJ-WORLD-001 (`fss-x4a.23.69.12`)
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

e2e_step "immutable_projection_core_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-graph-algorithms --lib projection::
e2e_expect_exit "immutable_projection_core_contract" 0

e2e_summary
