#!/usr/bin/env bash
# Supplementary daemon regression checks. Local DSR qualification remains release authority.
# Keep the commands here so local runs and hosted feedback exercise the same contracts.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

export CARGO_NET_OFFLINE=true
export RUSTUP_AUTO_INSTALL=0

cargo test --locked --offline -p fss-daemon --all-targets

cargo test --locked --offline -p fss-cli \
    --test dashboard_live_contract \
    --test mcp_14_ops_adversarial_e2e
