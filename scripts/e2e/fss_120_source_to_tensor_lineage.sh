#!/usr/bin/env bash
# FSS-120 (`fss-x4a.12.19`) E2E verification: source-to-tensor span and transform lineage
# (checked SourceByteSpan bounds, Decode-led TransformStep chains, canonical Tensor digest
# verification, non-inheritance of source custody, forbidden latest refusal, and cancellation).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_120_source_to_tensor_lineage.sh"

e2e_init "fss_120_source_to_tensor_lineage" "fss-x4a.12.19" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_120_source_to_tensor_lineage_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-tensor --test fss_120_source_to_tensor_lineage_contract -- --nocapture
e2e_expect_exit "fss_120_source_to_tensor_lineage_contract" 0

e2e_summary
