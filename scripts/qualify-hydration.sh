#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
TOOLCHAIN="$(python3 - <<'PY'
import pathlib
import tomllib
print(tomllib.loads(pathlib.Path("rust-toolchain.toml").read_text())["toolchain"]["channel"])
PY
)"
rustup run "${TOOLCHAIN}" cargo build --locked --offline --quiet -p fss-cli --bin fss-hydration-rehearsal
TARGET="${CARGO_TARGET_DIR:-${ROOT}/target}"
[[ "${TARGET}" = /* ]] || TARGET="${ROOT}/${TARGET}"
if [[ -n "${CARGO_BUILD_TARGET:-}" ]]; then
  TARGET="${TARGET}/${CARGO_BUILD_TARGET}"
fi
BINARY="${TARGET}/debug/fss-hydration-rehearsal"
[[ -f "${BINARY}.exe" ]] && BINARY="${BINARY}.exe"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fss-hydration-qualification.XXXXXX")"
trap 'rm -rf "${WORK}"' EXIT

for scenario in success budget-fallback privacy-denied expired h4-denied h4-qualified; do
  "${BINARY}" --scenario "${scenario}" > "${WORK}/${scenario}.first.ndjson"
  "${BINARY}" --scenario "${scenario}" > "${WORK}/${scenario}.second.ndjson"
done
python3 scripts/check_hydration_transcript.py "${WORK}"
