#!/usr/bin/env bash
# Focused native retained-perception contracts; supplementary feedback, not release authority.
# Provision the exact toolchain and locked dependencies with scripts/bootstrap_toolchain.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

channel="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' rust-toolchain.toml)"
[[ -n "$channel" ]] || { printf 'missing pinned toolchain\n' >&2; exit 1; }
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_NET_OFFLINE=true
export RUSTUP_AUTO_INSTALL=0

status=0
check() {
    local name="$1"
    shift
    printf '==> %s\n' "$name"
    if "$@"; then
        printf '%s PASS\n' "$name"
    else
        status=1
        printf '%s FAIL\n' "$name" >&2
    fi
}

check retained-localization cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-reference --test recorded_twin_localization_contract
check incremental-dwell cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-reference --lib ingest::long_dwell::tests
check operator-unit cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-cli --bin fss-file --bin fss-event
# Integration targets require Cargo's normal executable builds. These suites also invoke
# fss and fss-replay-dwell; limiting unit-test binaries does not suppress those executable builds.
check operator-integration cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-cli --test retained_localization_cli --test watch_stream_dwell_cli \
    --test agent_rehearsal_contract
exit "$status"
