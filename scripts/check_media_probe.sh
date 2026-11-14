#!/usr/bin/env bash
# Bounded media probing contracts; full release qualification remains scripts/qualify.sh.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

channel="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' rust-toolchain.toml)"
if [[ -z "$channel" ]]; then
  echo "media probe checks: missing pinned toolchain" >&2
  exit 1
fi

probe_test_status=0
cargo "+$channel" test --locked --offline --no-fail-fast \
  -p fss-container --lib probe:: || probe_test_status=1
cargo "+$channel" test --locked --offline --no-fail-fast \
  -p fss-cli --bin fss-probe || probe_test_status=1
exit "$probe_test_status"
