#!/usr/bin/env bash
# Focused supplemental contracts for recorder replay and review expiry.
# Local DSR qualification remains authoritative; this does not replace any lane.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

selection="${1:-all}"
if (( $# > 1 )) || [[ "$selection" != all && "$selection" != replay && "$selection" != review-expiry ]]; then
  printf 'usage: %s [all|replay|review-expiry]\n' "$0" >&2
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
  run_tests 'codec-bound recorder replay planning' \
    -p fss-cli --bin fss-capture-rtsp replay
fi

if [[ "$selection" == all || "$selection" == review-expiry ]]; then
  run_tests 'retained review expiry, deletion obligations and retention holds' \
    -p fss-reference --test review_media_contract \
    --test deletion_effect_lifecycle_contract --test retention_cohort_contract
  run_tests 'legacy deletion compatibility and review expiry canonical bounds' \
    -p fss-reference --lib deletion::
  run_tests 'review expiry and scoped deletion through the CLI' \
    -p fss-cli --test review_expiry_cli_contract --test deletion_scope_cli_contract
  run_tests 'strict review expiry command admission' \
    -p fss-cli --bin fss-event delete::review_expiry::tests
fi

exit "$result"
