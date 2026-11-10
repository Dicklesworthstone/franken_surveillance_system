#!/usr/bin/env bash
# Focused supplementary ONNX execution and package contracts.
# Local DSR qualification remains authoritative; this does not replace any lane.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

selection="${1:-all}"
if (( $# > 1 )) || [[ "$selection" != pure && "$selection" != all ]]; then
  printf 'usage: %s [pure|all]\n' "$0" >&2
  exit 2
fi

toolchain="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' rust-toolchain.toml)"
if [[ -z "$toolchain" ]]; then
  printf 'ONNX package checks: missing pinned toolchain\n' >&2
  exit 2
fi

result=0
run_tests() {
  local label="$1"
  shift
  printf 'Running %s\n' "$label"
  if cargo "+$toolchain" test --no-fail-fast --locked --offline "$@"; then
    return 0
  else
    result=1
  fi
}

run_tests 'ONNX lowering through production scalar and optimized kernels' \
  -p fss-model-ir --test onnx_attention_execution

if [[ "$selection" == all ]]; then
  run_tests 'source-preserving ONNX packages and native retained-frame detection' \
    -p fss-reference --test onnx_package_import
  run_tests 'strict ONNX import command admission and package options' \
    -p fss-cli --bin fss-infer onnx_cli::
fi

exit "$result"
