#!/usr/bin/env bash
# scripts/bootstrap_toolchain.sh — provision the pinned Rust toolchain and locked dependencies.
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

# Bootstrap is the network-enabled acquisition boundary. Fresh runners also need
# the lockfile's registry closure before the offline compilation/qualification
# lanes can resolve the workspace (including fss-runtime's pinned Asupersync).
# Scope the override to fetch; tests and qualification retain their offline policy.
CARGO_NET_OFFLINE=false cargo "+$channel" fetch --locked --manifest-path "${REPO_ROOT}/Cargo.toml"
