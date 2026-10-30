#!/usr/bin/env bash
# Focused native retained-perception contracts; supplementary feedback, not release authority.
# Provision the exact toolchain and locked dependencies with scripts/bootstrap_toolchain.sh.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

channel="$(sed -n 's/^channel[[:space:]]*=[[:space:]]*"\(.*\)"/\1/p' rust-toolchain.toml)"
[[ -n "$channel" ]] || { printf 'missing pinned toolchain\n' >&2; exit 1; }
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_NET_OFFLINE=true
export RUSTUP_AUTO_INSTALL=0

status=0
check() {
    local name="$1"
    shift
    printf '==> %s\n' "$name"
    if "$@"; then
        printf '%s PASS\n' "$name"
    else
        status=1
        printf '%s FAIL\n' "$name" >&2
    fi
}

check retained-localization cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-reference --test recorded_twin_localization_contract
check incremental-dwell cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-reference --lib ingest::long_dwell
check retained-delivery-recovery cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-reference --test original_media_export_contract --test onvif_capture_operation \
    --test deployment_missing_journal_contract --test doctor_deployment_contract
check durable-follow-wait cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-reference --lib deployment_session::follow::wait::tests
check historical-health-catalog cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-reference --lib ingest::historical_health::exposure::
check event-fusion cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-cli --lib event_fusion::
check durable-follow-cli cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-cli --lib follow_cmd::
check native-onvif-cli cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-cli --bin fss-onvif-metadata
check durable-follow-mcp cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-cli --bin fss-mcp durable_follow
check episode-learning-compatibility cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-cli --test agent_effect_cli_contract \
    closed_episode_feedback_publishes_captured_learning_with_cold_cli_mcp_recovery
check operator-unit cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-cli --bin fss-file --bin fss-event --bin fss-fusion-profile
# Integration targets require Cargo's normal executable builds. These suites also invoke
# fss and fss-replay-dwell; limiting unit-test binaries does not suppress those executable builds.
check operator-integration cargo "+$channel" test --locked --offline --no-fail-fast \
    -p fss-cli --test retained_localization_cli --test watch_stream_dwell_cli \
    --test agent_rehearsal_contract --test watch_stream_detector_cli \
    --test event_fusion_cli --test fusion_profile_cli \
    --test rtsp_event_media_export_cli --test onvif_native_capture_cli \
    --test follow_subscription_cli_contract --test supervisor_retained_contract
exit "$status"
