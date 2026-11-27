#!/usr/bin/env bash
# QL-ARCHIVE-001 (archive half) — process contracts for the archive tooling.
#
# These are cold-process tests over on-disk state and bounded loopback S3 fixtures;
# no external provider is contacted. Individual files gate themselves with
# `cfg(target_os = "linux")` where the fixture needs Linux semantics.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

export CARGO_NET_OFFLINE=true
export RUSTUP_AUTO_INSTALL=0
export RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}"

"${RUN[@]}" cargo --offline test --locked -q -p fss-ledger \
  --test test_ledger_crash_001_proof_family

"${RUN[@]}" cargo --offline test --locked -q -p fss-object \
  --test multipart_family \
  --test uploader_family \
  --test upload_journal_namespace \
  --test uploader_source_contract \
  --test completion_observation_contract \
  --test fss_068_incident_retrieval_contract \
  --test fss_069_restore_fault_matrix_contract \
  --test retrieval_observation_contract \
  --test remote_eventual_consistency_contract

"${RUN[@]}" cargo --offline test --locked -q -p fss-reference \
  --test deployment_backup_contract \
  --test s3_upload_native_contract \
  --test s3_retrieval_native_contract

"${RUN[@]}" cargo --offline test --locked -q -p fss-cli \
  --test deployment_backup_cli \
  --test archive_s3_upload_process \
  --test archive_s3_verification_process \
  --test archive_operator_process \
  --test archive_pin_process \
  --test archive_replay_process \
  --test archive_upload_journal_cli \
  --test archive_work_process \
  --test upload_inspect_cli_contract
