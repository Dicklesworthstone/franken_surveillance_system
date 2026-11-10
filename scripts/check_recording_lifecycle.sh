#!/usr/bin/env bash
# Focused supplemental contracts for recorder replay and review expiry.
# Local DSR qualification remains authoritative; this does not replace any lane.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

selection="${1:-replay}"
if (( $# > 1 )) || [[ "$selection" != all && "$selection" != replay ]]; then
  printf 'usage: %s [all|replay]\n' "$0" >&2
  exit 2
fi

toolchain="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' rust-toolchain.toml)"
if [[ -z "$toolchain" ]]; then
  printf 'recording lifecycle checks: missing pinned toolchain\n' >&2
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

if [[ "$selection" == all || "$selection" == replay ]]; then
  run_tests 'native AVC/HEVC recorder replay and durable receipts' \
    -p fss-reference --test recording_replay_contract --test rtsp_replay_contract \
    --test live_hevc_archive_contract
  run_tests 'approved recorder replay through the capture CLI' \
    -p fss-cli --test capture_rtsp_cli replay::
  run_tests 'cold recorder replay inspection through the archive CLI' \
    -p fss-cli --test archive_replay_process
fi


exit "$result"
