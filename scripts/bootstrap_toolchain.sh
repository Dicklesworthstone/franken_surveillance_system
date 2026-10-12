#!/usr/bin/env bash
# scripts/bootstrap_toolchain.sh — install the repo-pinned Rust toolchain.
# Owned by the repository so workflows stay thin delegations (fss policy:
# workflows are portable supplementary specifications; unique setup logic
# lives in repo scripts). Channel comes from rust-toolchain.toml, the single
# source of truth — never hardcoded here.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
channel="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "${REPO_ROOT}/rust-toolchain.toml")"
if [[ -z "$channel" ]]; then
    echo "bootstrap_toolchain: no channel in rust-toolchain.toml" >&2
    exit 1
fi

rustup toolchain install "$channel" --profile minimal --component rustfmt --component clippy --component rust-src
