#!/usr/bin/env bash
# Regenerates the sealed-lab H.264 fixture for fss-codec-h264 real-stream
# contracts. FFmpeg is the laboratory oracle per DEPENDENCY_CONSTITUTION —
# it generates fixtures OFFLINE and never enters the production closure;
# the Rust tests only read the committed bytes and never invoke ffmpeg.
#
# Usage: scripts/generate_h264_fixture.sh
set -euo pipefail
cd "$(dirname "$0")/.."

FIXTURE="crates/fss-codec-h264/tests/fixtures/baseline_i64.h264"
EXPECTED_SHA256="e2aab0bbf0bca60507c964d782ea50918de7471f5a06ddf2ef34e07f15704589"

# Deterministic encoder settings: Constrained Baseline, CAVLC (cabac=0),
# I+P frames only, one second at 2 fps, 64x64.
ffmpeg -y -v error \
  -f lavfi -i "testsrc=duration=1:size=64x64:rate=2" \
  -c:v libx264 -profile:v baseline -pix_fmt yuv420p \
  -preset ultrafast -tune zerolatency \
  -x264-params "keyint=2:min-keyint=2:scenecut=0:bframes=0:ref=1:cabac=0" \
  -f h264 "$FIXTURE"

ACTUAL_SHA256=$(sha256sum "$FIXTURE" | cut -d' ' -f1)
if [[ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]]; then
  echo "NOTE: oracle output changed (encoder version drift)."
  echo "  expected: $EXPECTED_SHA256"
  echo "  actual:   $ACTUAL_SHA256"
  echo "If accepted, update STREAM_SHA256_HEX in"
  echo "crates/fss-codec-h264/tests/real_stream_contract.rs and re-run tests."
  exit 1
fi
echo "fixture regenerated; digest matches provenance anchor"
