#!/usr/bin/env bash
# Supplemental contracts for recorder discovery, replay, review expiry and retained events.
set -euo pipefail
export CARGO_NET_OFFLINE=true
export RUSTUP_AUTO_INSTALL=0

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
  run_tests 'actual pinned recording custody and pre-original replay admission' \
    -p fss-container --test pinned_recording_contract
  run_tests 'native AVC/HEVC recorder replay and durable receipts' \
    -p fss-reference --test recording_replay_contract --test rtsp_replay_contract \
    --test recording_clock_contract --test recording_catalog_local_contract \
    --test hevc_catalog_local_contract --test hevc_recording_publication_contract \
    --test live_hevc_archive_contract --test rtsp_replay_time_pinned_contract
  run_tests 'source-authorized recorder assertions with current deployment context' \
    -p fss-reference --test agent_recording_replay_context_contract
  run_tests 'canonical recorder UTC CLI admission' \
    -p fss-cli --lib recorder_utc
  run_tests 'MCP recorder UTC exact pins, schema and owner permission' \
    -p fss-cli --bin fss-mcp replay_
  run_tests 'actual CLI and MCP recorder UTC parity and whole-query refusals' \
    -p fss-cli --test recording_replay_query_contract
  run_tests 'whole recorder replay retained custody, cold decode and review provenance' \
    -p fss-reference --test rtsp_replay_import_contract --test rtsp_replay_import_lifecycle_contract \
    --test rtsp_retained_replay_time_contract
  run_tests 'exact whole replay import plans and source-free command-line decoding' \
    -p fss-cli --bin fss-import-rtsp replay::
  run_tests 'approved whole replay custody through real import and retained-media commands' \
    -p fss-cli --test rtsp_replay_import_cli
  run_tests 'retained recorder-time query admission without ambient input' \
    -p fss-cli --bin fss-file replay_time::
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

if [[ "$selection" == all ]]; then
  run_tests 'durable event evidence hydration' \
    -p fss-reference --test agent_event_hydration_contract
  run_tests 'CLI event evidence hydration' \
    -p fss-cli --test event_hydration_query_cli_contract
  run_tests 'native exact event revision comparisons' \
    -p fss-reference --test agent_event_changes_contract
  run_tests 'CLI event revision and explanation compatibility' \
    -p fss-cli --test event_changes_cli_contract --test explain_support_cli_contract --test explain_custody_cli
  run_tests 'exact explanation receipts preserve context provenance' \
    -p fss-cli --lib support_preserves_why_and_what_changed_receipts_without_reclassifying_context
  run_tests 'MCP query and schema contracts' \
    -p fss-cli --bin fss-mcp
fi

exit "$result"
