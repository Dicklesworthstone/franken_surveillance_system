#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 scripts/check-policy.py
if command -v cargo >/dev/null 2>&1; then
  cargo fmt --all --check
  cargo check --workspace --all-targets
  cargo clippy --workspace --all-targets -- -D warnings
  cargo test --workspace
else
  printf '%s\n' 'cargo is unavailable; Rust qualification was not executed' >&2
  exit 3
fi
