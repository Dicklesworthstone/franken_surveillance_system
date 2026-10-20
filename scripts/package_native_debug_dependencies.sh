#!/usr/bin/env bash
# Package only public, checksum-verified locked dependency sources, never Cargo home or credentials.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:?existing debug output directory required}"
[[ -d "$out" && -f "$out/SHA256SUMS" && ! -e "$out/dependencies.tar.gz" ]]
out="$(cd "$out" && pwd)"
python3 - "$root/Cargo.lock" <<'PY'
import sys
import tomllib
from pathlib import Path
lock = tomllib.loads(Path(sys.argv[1]).read_text())
for package in lock['package']:
    source = package.get('source')
    if source is not None and source != 'registry+https://github.com/rust-lang/crates.io-index':
        raise SystemExit('debug dependency packaging refuses non-public-registry sources')
PY
channel="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' "$root/rust-toolchain.toml")"
[[ -n "$channel" ]]
scratch="$(mktemp -d "${TMPDIR:-/tmp}/fss-public-dependencies.XXXXXX")"
# scratch contains only disposable public package sources and the generated source replacement.
trap 'rm -rf -- "$scratch"' EXIT
(cd "$scratch" && cargo "+$channel" vendor --locked --offline --versioned-dirs \
    --manifest-path "$root/Cargo.toml" vendor > vendor-config.toml)
tar -C "$scratch" -czf "$out/dependencies.tar.gz" vendor vendor-config.toml
(cd "$out" && sha256sum dependencies.tar.gz >> SHA256SUMS)
