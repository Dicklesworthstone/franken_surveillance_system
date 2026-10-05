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
check retention-storage cargo test --locked --offline -j 2 -p fss-cli --no-fail-fast \
    --test retention_cli_contract --test deletion_cli_contract --test deletion_scope_cli_contract
# Report formatting separately, never convert compilation/test failure into success.
check formatting cargo fmt --all -- --check
exit "$status"
