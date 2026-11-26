#!/usr/bin/env bash
# FSS-064 (`fss-x4a.13.4`) E2E verification: multipart upload idempotency, durable upload journal,
# lost-ACK -> HEAD -> GET reconciliation under visibility lag and partial part lists, independent
# byte-proof retrieval observation, and cold-process S3 archive CLI contracts.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/e2e/lib.sh
source "${SCRIPT_DIR}/lib.sh"
_E2E_SCRIPT_PATH="scripts/e2e/fss_064_multipart_idempotency.sh"

e2e_init "fss_064_multipart_idempotency" "fss-x4a.13.4" "$@"

ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' "$ROOT/rust-toolchain.toml" 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

e2e_step "fss_064_object_multipart_and_observation" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-object \
    --test multipart_family \
    --test uploader_family \
    --test upload_journal_namespace \
    --test uploader_source_contract \
    --test completion_observation_contract \
    --test retrieval_observation_contract \
    --test remote_eventual_consistency_contract
e2e_expect_exit "fss_064_object_multipart_and_observation" 0

e2e_step "fss_064_reference_s3_upload_and_retrieval" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-reference \
    --test s3_upload_native_contract \
    --test s3_retrieval_native_contract
e2e_expect_exit "fss_064_reference_s3_upload_and_retrieval" 0

e2e_step "fss_064_cli_archive_s3_and_journal_process" -- \
  env CARGO_NET_OFFLINE=true RUSTUP_AUTO_INSTALL=0 RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}" \
  "${RUN[@]}" cargo --offline test --locked -q -p fss-cli \
    --test upload_inspect_cli_contract \
    --test archive_s3_upload_process \
    --test archive_s3_verification_process \
    --test archive_upload_journal_cli
e2e_expect_exit "fss_064_cli_archive_s3_and_journal_process" 0

e2e_summary
