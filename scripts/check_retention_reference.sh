#!/usr/bin/env bash
# Focused reference checks only; no qualification or release authority.
set -euo pipefail
cd "$(dirname "$0")/.."
out="${1:-out/retention-reference}"
mkdir -p "$out"
status=0
check() {
    local name="$1"
    shift
    if "$@" >"$out/$name.log" 2>&1; then
        printf '%s PASS\n' "$name"
    else
        status=1
        printf '%s FAIL\n' "$name"
    fi
    cat "$out/$name.log"
}
check deletion-unit cargo test --locked --offline -j 2 -p fss-reference --lib deletion::
check deletion-cli cargo test --locked --offline -j 2 -p fss-cli --bin fss-event delete::
if [[ -f crates/fss-reference/tests/retention_contract.rs ]]; then
    check retention-contract cargo test --locked --offline -j 2 -p fss-reference --test retention_contract
fi
# Report formatting separately, never convert compilation/test failure into success.
check formatting cargo fmt --all -- --check
exit "$status"
