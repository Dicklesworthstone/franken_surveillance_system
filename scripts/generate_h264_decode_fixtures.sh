#!/usr/bin/env bash
# Regenerates the sealed-lab H.264 *pixel decode* fixtures for fss-codec-h264.
#
# FFmpeg/libx264 is the laboratory oracle only (DEPENDENCY_CONSTITUTION): it
# encodes synthetic testsrc2 scenes and decodes them to raw I420 OFFLINE. The
# Rust tests read the committed bitstreams and the committed per-frame SHA-256
# digests; they never invoke ffmpeg and never trust the Rust decoder's own
# output as an expectation.
#
# Usage: scripts/generate_h264_decode_fixtures.sh [output-dir]
# Default output: crates/fss-codec-h264/tests/fixtures/decode
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-crates/fss-codec-h264/tests/fixtures/decode}"
mkdir -p "$OUT"

COMMON=(-hide_banner -loglevel error -y)
X264_BASE="threads=1:lookahead_threads=1:bframes=0:scenecut=0:aud=0"

encode() {
  # encode <name> <size> <frames> <extra x264 params> [extra lavfi filters]
  local name="$1" size="$2" frames="$3" params="$4" filters="${5:-}"
  ffmpeg "${COMMON[@]}" -f lavfi -i "testsrc2=size=${size}:rate=10${filters}" \
    -frames:v "$frames" -an -c:v libx264 -profile:v baseline -pix_fmt yuv420p \
    -x264-params "${X264_BASE}:${params}" -f h264 "$OUT/${name}.h264"
}

# Intra-only, three quantizers (I_NxN + I_16x16 mixes, deblocking on).
encode i_qcif_qp28 176x144 3 "keyint=1:qp=28"
encode i_qcif_qp12 176x144 2 "keyint=1:qp=12"
encode i_qcif_qp44 176x144 2 "keyint=1:qp=44"
# Non-multiple-of-16 size: frame cropping (right/bottom), I then P.
encode ip_100x60_crop 100x60 6 "keyint=6:ref=1"
# Three slices per picture (slice-edge neighbour availability).
encode ip_qcif_slices3 176x144 4 "keyint=4:slices=3:qp=30"
# Deblocking disabled (disable_deblocking_filter_idc = 1).
encode ip_qcif_nodeblock 176x144 4 "keyint=4:no-deblock=1:qp=32"
# Deblocking with nonzero alpha/beta offsets.
encode ip_qcif_deblockoffs 176x144 4 "keyint=4:deblock=-3,2:qp=26"
# Longer P run, three reference frames, every partition incl. 4x4 sub-blocks.
encode p_qcif_ref3_p4x4 176x144 12 "keyint=12:ref=3:partitions=all:qp=30"

# constrained_intra_pred_flag = 1: intra MBs in P slices must ignore
# inter-coded neighbours. Deterministic temporal noise (the noise filter's
# fixed default seed) makes the encoder choose intra MBs inside P slices.
encode ip_constrained_intra 128x96 3 "keyint=3:constrained-intra=1:qp=36" \
  ",noise=alls=70:allf=t+u"

# Hand-assembled I_PCM streams (libx264 never emits I_PCM).
python3 scripts/generate_h264_pcm_fixture.py "$OUT"

# Header-only rewrites for syntax libx264 cannot emit (macroblock data is
# copied verbatim; see the script): slice-edge deblocking mode 2, and
# picture order count type 0.
python3 scripts/rewrite_h264_headers.py --deblock-idc2 \
  "$OUT/ip_qcif_slices3.h264" "$OUT/ip_qcif_slices3_idc2.h264"
python3 scripts/rewrite_h264_headers.py --poc-type0 \
  "$OUT/ip_100x60_crop.h264" "$OUT/ip_100x60_poc0.h264"

# Oracle decode: every frame to packed planar I420 via rawvideo; framehash
# hashes each packet, i.e. exactly one frame (Y, then Cb, then Cr, no
# padding). Output columns: frame index, byte count, sha256.
oracle_digests() {
  local stream="$1" name="$2"
  {
    echo "# ${name}; oracle: $(ffmpeg -version | head -n1)"
    ffmpeg "${COMMON[@]}" -threads 1 -i "$stream" -fps_mode passthrough \
      -c:v rawvideo -pix_fmt yuv420p -f framehash -hash sha256 - \
      | grep -v '^#' | awk -F', *' '{ print NR - 1, $5, $6 }'
  } > "$OUT/${name}.sha256"
}
for stream in "$OUT"/*.h264; do
  oracle_digests "$stream" "$(basename "$stream" .h264)"
done
# Existing committed streams, reused in place (not regenerated here).
oracle_digests crates/fss-codec-h264/tests/fixtures/baseline_i64.h264 baseline_i64
oracle_digests crates/fss-packet/tests/fixtures/avc/baseline.264 fss_packet_baseline
echo "fixtures and oracle digests written to $OUT"
