#!/usr/bin/env bash
# FSS-053 (`fss-x4a.12.2`) E2E verification: bounded pure-Rust media probe engine
# (family recognition, Annex-B / MP4 / Matroska / FLV parameter extraction, borrowed spans,
# cooperative cancellation, hard byte/unit/geometry bounds, and shipped `fss-probe` CLI).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_053_media_probe.sh"

e2e_init "fss_053_media_probe" "fss-x4a.12.2" "$@"
e2e_cargo_test "fss-container" "fss_053_media_probe_contract"

# Also verify the unit test suites in `fss-container::probe` and `fss-cli --bin fss-probe`.
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

CARGO_NET_OFFLINE=true RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-container --lib probe::
CARGO_NET_OFFLINE=true RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli --bin fss-probe

e2e_summary
