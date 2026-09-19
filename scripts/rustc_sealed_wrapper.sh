#!/usr/bin/env bash
# Fail-closed rustc wrapper for sealed qualification (fss-x4a.26.3, FSS-183).
#
# Called in place of rustc via the RUSTC env var. Refuses -Z feature flags
# at the point of injection (stronger than a post-hoc log scan), records
# every invocation for audit, then execs the real rustc.
#
# FSS_RUSTC_REAL must point to the real rustc binary; the caller sets it
# before prepending the wrapper directory to PATH.

set -Eu

for arg in "$@"; do
  if [[ "$arg" == "-Z" || "$arg" == "-Z"* ]]; then
    printf 'FSS-RUSTC-SEAL: refused -Z flag in sealed qualification: %s\n' "$arg" >&2
    exit 101
  fi
done

if [[ -n "${FSS_RUSTC_LOG:-}" ]]; then
  printf 'rustc %s\n' "$*" >> "$FSS_RUSTC_LOG"
fi

exec "${FSS_RUSTC_REAL:?FSS_RUSTC_REAL must point to the real rustc binary}" "$@"
