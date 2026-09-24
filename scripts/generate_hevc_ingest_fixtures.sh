#!/usr/bin/env bash
# Regenerates the sealed-lab HEVC *ingest* fixtures for fss-reference.
#
# FFmpeg/libx265 is the laboratory oracle only (DEPENDENCY_CONSTITUTION). It
# encodes one synthetic moving-object scene and decodes streams to packed
# I420 in output order OFFLINE. Rust tests read the committed bitstream and
# the committed per-frame SHA-256 digests; they never invoke ffmpeg and never
# trust the Rust decoder's own output as an expectation.
#
# Usage: scripts/generate_hevc_ingest_fixtures.sh [output-dir]
# Default output: crates/fss-reference/tests/fixtures/hevc_ingest
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-crates/fss-reference/tests/fixtures/hevc_ingest}"
CODEC_FIXTURES="crates/fss-codec-h265/tests/fixtures/decode"
mkdir -p "$OUT"

COMMON=(-hide_banner -loglevel error -y)
# Same deterministic libx265 settings as scripts/generate_h265_decode_fixtures.sh.
X265_BASE="log-level=error:pools=1:frame-threads=1:info=0:scenecut=0"

# Moving-object scene for the watch pipeline, identical in geometry to the
# MJPEG watch test scene: 96x48, 14 frames, luma 40 background; from frame 3
# a 16x16 luma-220 square enters at the left edge and moves 8 px right per
# frame along rows 8..24. Chroma is neutral (128). Raw frames are piped to
# libx265: one IDR then P pictures (no B frames), QP 12.
python3 - <<'PY' | ffmpeg "${COMMON[@]}" -f rawvideo -pix_fmt yuv420p -s 96x48 -r 10 -i pipe:0 \
  -an -c:v libx265 -pix_fmt yuv420p \
  -x265-params "${X265_BASE}:keyint=30:bframes=0:qp=12" \
  -f hevc "$OUT/watch_96x48_moving.h265"
import sys
width, height, frames = 96, 48, 14
out = sys.stdout.buffer
for index in range(frames):
    luma = bytearray([40]) * (width * height)
    if index >= 3:
        left = (index - 3) * 8
        for y in range(8, 24):
            for x in range(left, left + 16):
                luma[y * width + x] = 220
    out.write(bytes(luma))
    out.write(bytes([128]) * ((width // 2) * (height // 2) * 2))
PY

# Oracle decode: identical to scripts/generate_h265_decode_fixtures.sh.
oracle_digests() {
  # oracle_digests <name> <ffmpeg input options...>
  local name="$1"
  shift
  {
    echo "# ${name}; oracle: $(ffmpeg -version | head -n1)"
    ffmpeg "${COMMON[@]}" -threads 1 "$@" -fps_mode passthrough \
      -c:v rawvideo -pix_fmt yuv420p -f framehash -hash sha256 - \
      | grep -v '^#' | awk -F', *' '{ print NR - 1, $5, $6 }'
  } > "$OUT/${name}.sha256"
}
oracle_digests watch_96x48_moving -i "$OUT/watch_96x48_moving.h265"

# CRA-led range oracle: FFmpeg decodes b_qcif_opengop from the parameter sets
# that open its mid-stream CRA access unit (retained segment 5) to the end.
# Decoding then starts at that CRA, so FFmpeg skips its RASL picture exactly
# as the Rust decoder must when a retained range starts there.
python3 - "$CODEC_FIXTURES/b_qcif_opengop.h265" <<'PY' | oracle_digests b_qcif_opengop_from_cra -f hevc -i pipe:0
import re, sys
data = open(sys.argv[1], "rb").read()
starts = [m.start() for m in re.finditer(b"\x00\x00\x01", data)]
cra = next(s for s in starts if (data[s + 3] >> 1) & 0x3F == 21)
# Back up to the VPS (type 32) that opens the CRA's access unit, including a
# four-byte start code's leading zero.
vps = max(s for s in starts if s < cra and (data[s + 3] >> 1) & 0x3F == 32)
if vps > 0 and data[vps - 1] == 0:
    vps -= 1
sys.stdout.buffer.write(data[vps:])
PY
echo "fixtures and oracle digests written to $OUT"
