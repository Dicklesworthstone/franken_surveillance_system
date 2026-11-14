#!/usr/bin/env bash
# Focused provider regressions; full release qualification remains scripts/qualify.sh.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

channel="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' rust-toolchain.toml)"
if [[ -z "$channel" ]]; then
  echo "provider custody checks: missing pinned toolchain" >&2
  exit 1
fi

cargo "+$channel" test --locked --offline --no-fail-fast \
  -p fss-object --lib \
  --test provider_property_family \
  --test oracle_family \
  --test provider_root_integrity
