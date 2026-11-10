#!/usr/bin/env bash
# Focused supplemental contracts for recorder discovery, replay and review expiry.
# Local DSR qualification remains authoritative; this does not replace any lane.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

selection="${1:-all}"
if (( $# > 1 )) || [[ "$selection" != all && "$selection" != onvif-recording && "$selection" != replay && "$selection" != review-expiry ]]; then
  printf 'usage: %s [all|onvif-recording|replay|review-expiry]\n' "$0" >&2
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

if [[ "$selection" == all || "$selection" == onvif-recording ]]; then
  run_tests 'actual recording SOAP parser and shared hostile-input contracts' \
    -p fss-core --test onvif_recording_wire_contract
  run_tests 'scoped recording discovery and existing ONVIF wire/authentication contracts' \
    -p fss-reference --test onvif_recording_contract --test onvif_wire_contract \
    --test onvif_onboarding_contract --test onvif_authentication_contract
  run_tests 'exact ONVIF operator plans and private credential admission' \
    -p fss-cli --bin fss-onvif
  run_tests 'approved ONVIF recording inventory and private replay handoff production' \
    -p fss-cli --test capture_rtsp_cli onvif::recording
  # The all selector runs these cases once in the complete replay group below.
  if [[ "$selection" == onvif-recording ]]; then
    run_tests 'recording selection provenance and hostile cold-receipt substitution' \
      -p fss-reference --test recording_replay_contract onvif
    run_tests 'protected ONVIF replay capture, approval and cold receipt provenance' \
      -p fss-cli --test capture_rtsp_cli replay::onvif
  fi
fi

if [[ "$selection" == all || "$selection" == replay ]]; then
  run_tests 'recorded RTP time assertions and explicit-era boundaries' \
    -p fss-packet --test onvif_replay_contract
  run_tests 'native AVC/HEVC recorder replay and durable receipts' \
    -p fss-reference --test recording_replay_contract --test rtsp_replay_contract \
    --test live_hevc_archive_contract
  run_tests 'approved recorder replay through the capture CLI' \
    -p fss-cli --test capture_rtsp_cli replay::
  run_tests 'cold recorder replay inspection and historical time queries through the archive CLI' \
    -p fss-cli --test archive_replay_process
  run_tests 'codec-bound recorder replay planning' \
    -p fss-cli --bin fss-capture-rtsp replay
fi

if [[ "$selection" == all || "$selection" == review-expiry ]]; then
  run_tests 'canonical local review delivery receipts and malformed metadata' \
    -p fss-core --test review_delivery_record_contract
  run_tests 'private review delivery and restart recovery through the CLI' \
    -p fss-cli --bin fss-export review::
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
