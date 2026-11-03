#!/usr/bin/env bash
# Regenerates the sealed-lab H.264 *pixel decode* fixtures for fss-codec-h264.
#
# FFmpeg/libx264 is the laboratory oracle only (DEPENDENCY_CONSTITUTION): it
# encodes synthetic testsrc2/mandelbrot scenes (Baseline, Main and High
# profile) and decodes them to raw I420 in output order OFFLINE. The
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

# ----- Main and High profile (CABAC, B slices, 8x8 transform, scaling) -----
# encode_profile <name> <profile> <size> <frames> <x264 params> [lavfi source]
# The x264 parameter string is complete here (no implicit bframes=0).
X264_MH="threads=1:lookahead_threads=1:scenecut=0:aud=0"
encode_profile() {
  local name="$1" profile="$2" size="$3" frames="$4" params="$5"
  local source="${6:-testsrc2=size=${size}:rate=10}"
  ffmpeg "${COMMON[@]}" -f lavfi -i "$source" \
    -frames:v "$frames" -an -c:v libx264 -profile:v "$profile" -pix_fmt yuv420p \
    -x264-params "${X264_MH}:${params}" -f h264 "$OUT/${name}.h264"
}

# Stage 1: CABAC I and P slices (Main).
encode_profile m_i_cabac_qp26 main 176x144 2 "keyint=1:bframes=0:qp=26"
encode_profile m_ip_cabac_ref3 main 176x144 8 \
  "keyint=8:bframes=0:ref=3:partitions=all:qp=30"
encode_profile m_ip_cabac_slices3 main 176x144 4 "keyint=4:bframes=0:slices=3:qp=34"
encode_profile m_ip_cabac_100x60_nodeblock main 100x60 6 \
  "keyint=6:bframes=0:no-deblock=1:qp=22"
encode_profile m_ip_cabac_qp40 main 128x96 5 "keyint=5:bframes=0:qp=40" \
  "mandelbrot=size=128x96:rate=10"
# Explicit weighted prediction in P slices (weightp=2 on a fade).
encode_profile m_ip_cabac_weightp main 128x96 6 "keyint=6:bframes=0:weightp=2:qp=30" \
  "testsrc2=size=128x96:rate=10,fade=in:0:6"
# Constrained intra with CABAC (intra MBs in P slices; deterministic noise).
encode_profile m_ip_cabac_constrained main 128x96 3 \
  "keyint=3:bframes=0:constrained-intra=1:qp=36" \
  "testsrc2=size=128x96:rate=10,noise=alls=70:allf=t+u"

# Stage 2: B slices (Main), display-order output.
encode_profile m_b_spatial main 176x144 10 \
  "keyint=10:bframes=2:b-pyramid=none:direct=spatial:weightb=0:ref=2:qp=30"
encode_profile m_b_temporal main 176x144 10 \
  "keyint=10:bframes=2:b-pyramid=none:direct=temporal:ref=2:qp=30"
encode_profile m_b_pyramid_ref3 main 176x144 12 \
  "keyint=12:bframes=3:b-pyramid=normal:direct=spatial:ref=3:partitions=all:qp=28"
encode_profile m_b_implicit_weight main 128x96 9 \
  "keyint=9:bframes=3:b-pyramid=normal:direct=temporal:weightb=1:ref=2:qp=30" \
  "testsrc2=size=128x96:rate=10,fade=in:0:9"
encode_profile m_b_cavlc main 176x144 9 \
  "keyint=9:cabac=0:bframes=2:b-pyramid=normal:direct=spatial:ref=2:qp=30"
# pic_order_cnt_lsb wraparound (log2_max_poc_lsb = 5 -> 32) over 24 frames
# at 64x48, with non-reference B pictures.
encode_profile m_b_pocwrap_64x48 main 64x48 24 \
  "keyint=24:bframes=2:b-pyramid=none:ref=2:qp=30"

# Stage 3: High profile (8x8 transform, 8x8 intra, scaling matrices).
encode_profile h_8x8dct_i high 176x144 2 "keyint=1:bframes=0:8x8dct=1:qp=24"
encode_profile h_8x8dct_b high 176x144 9 \
  "keyint=9:bframes=2:b-pyramid=normal:8x8dct=1:partitions=all:ref=2:qp=28"
encode_profile h_cqm_jvt high 176x144 6 "keyint=6:bframes=2:8x8dct=1:cqm=jvt:qp=28"
encode_profile h_cavlc_8x8 high 176x144 6 "keyint=6:cabac=0:bframes=2:8x8dct=1:qp=26"
encode_profile h_cqm_custom_100x60 high 100x60 5 \
  "keyint=5:bframes=1:8x8dct=1:qp=24:cqm4i=6,12,19,26,12,19,26,33,19,26,33,40,26,33,40,47:cqm4p=9,14,18,22,14,18,22,26,18,22,26,30,22,26,30,34:cqm8=6,10,13,16,18,23,25,27,10,11,16,18,23,25,27,29,13,16,18,23,25,27,29,31,16,18,23,25,27,29,31,33,18,23,25,27,29,31,33,36,23,25,27,29,31,33,36,38,25,27,29,31,33,36,38,40,27,29,31,33,36,38,40,42"

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
oracle_digests crates/fss-packet/tests/fixtures/avc/high_cropped.264 fss_packet_high_cropped
echo "fixtures and oracle digests written to $OUT"
