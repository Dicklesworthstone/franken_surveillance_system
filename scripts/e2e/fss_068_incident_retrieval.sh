#!/usr/bin/env bash
# FSS-068 (`fss-x4a.13.8`) E2E verification: deterministic incident archive retrieval and
# independent verification (nested manifest closure, encryption-context coverage, non-collapsed
# CustodyLevel floors, authority-before-read, indeterminate/corrupt preservation, scoped S3
# retrieval observation, and loopback S3 retrieval native contract).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_068_incident_retrieval.sh"

e2e_init "fss_068_incident_retrieval" "fss-x4a.13.8" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_068_incident_retrieval_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-object --test fss_068_incident_retrieval_contract -- --nocapture
e2e_expect_exit "fss_068_incident_retrieval_contract" 0

e2e_step "fss_068_retrieval_observation_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-object --test retrieval_observation_contract
e2e_expect_exit "fss_068_retrieval_observation_contract" 0

e2e_step "fss_068_s3_retrieval_native_contract" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-reference --test s3_retrieval_native_contract
e2e_expect_exit "fss_068_s3_retrieval_native_contract" 0

e2e_summary
