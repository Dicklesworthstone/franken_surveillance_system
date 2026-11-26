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

"${RUN[@]}" cargo --offline test -q -p fss-ledger \
  --test test_ledger_crash_001_proof_family

"${RUN[@]}" cargo --offline test -q -p fss-object \
  --test completion_observation_contract \
  --test retrieval_observation_contract

"${RUN[@]}" cargo --offline test -q -p fss-reference \
  --test s3_upload_native_contract \
  --test s3_retrieval_native_contract

"${RUN[@]}" cargo --offline test -q -p fss-cli \
  --test archive_s3_upload_process \
  --test archive_s3_verification_process \
  --test archive_operator_process \
  --test archive_pin_process \
  --test archive_replay_process \
  --test archive_upload_journal_cli \
  --test archive_work_process \
  --test upload_inspect_cli_contract
