#!/usr/bin/env bash
# Regenerates the sealed-lab H.265 *pixel decode* fixtures for fss-codec-h265.
#
# FFmpeg/libx265 is the laboratory oracle only (DEPENDENCY_CONSTITUTION): it
# encodes synthetic testsrc2 / mandelbrot / smptebars scenes and decodes them
# to raw I420 in output order OFFLINE. The Rust tests read the committed
# bitstreams and the committed per-frame SHA-256 digests; they never invoke
# ffmpeg and never trust the Rust decoder's own output as an expectation.
#
# Usage: scripts/generate_h265_decode_fixtures.sh [output-dir]
# Default output: crates/fss-codec-h265/tests/fixtures/decode
set -euo pipefail
cd "$(dirname "$0")/.."

OUT="${1:-crates/fss-codec-h265/tests/fixtures/decode}"
mkdir -p "$OUT"

COMMON=(-hide_banner -loglevel error -y)
# Deterministic libx265: a one-thread pool (pools=none mis-encodes slices in
# this x265 build), one frame thread,
# no encoder-version SEI (info=0), no scene-cut decisions.
X265_BASE="log-level=error:pools=1:frame-threads=1:info=0:scenecut=0"

encode() {
  # encode <name> <lavfi source> <frames> <x265 params> [ffmpeg options...]
  local name="$1" source="$2" frames="$3" params="$4"
  shift 4
  ffmpeg "${COMMON[@]}" -f lavfi -i "$source" -frames:v "$frames" -an \
    -c:v libx265 "$@" -pix_fmt yuv420p -x265-params "${X265_BASE}:${params}" \
    -f hevc "$OUT/${name}.h265"
}

# ----- Stage 1: intra-only Main streams, in-loop filters off -----
# Every frame is forced to be a key frame: an IDR picture followed by
# TRAIL_R pictures made of I slices (with keyint=1 libx265 would signal the
# range-extensions "Main Intra" profile instead of Main).
INTRA="keyint=30:bframes=0:no-deblock=1:no-sao=1:wpp=0"
intra() {
  local name="$1" source="$2" frames="$3" params="$4"
  encode "$name" "$source" "$frames" "${INTRA}:${params}" -force_key_frames "expr:1"
}
intra i_64x64_ctu32_qp30 "testsrc2=size=64x64:rate=10" 3 \
  "ctu=32:min-cu-size=8:qp=30"
intra i_qcif_ctu64_qp22 "testsrc2=size=176x144:rate=10" 2 \
  "ctu=64:min-cu-size=8:tu-intra-depth=3:qp=22"
intra i_qcif_ctu16_qp37 "testsrc2=size=176x144:rate=10" 2 \
  "ctu=16:min-cu-size=8:qp=37"
intra i_mandel_128x96_qp12 "mandelbrot=size=128x96:rate=10" 2 \
  "ctu=32:wpp=1:qp=12"
intra i_100x60_crop "testsrc2=size=100x60:rate=10" 3 "ctu=32:qp=27"
intra i_qcif_tskip "smptebars=size=176x144:rate=10" 2 \
  "ctu=32:tskip=1:qp=27"
intra i_qcif_scaling_default "testsrc2=size=176x144:rate=10" 2 \
  "ctu=32:scaling-list=default:qp=27"
intra i_qcif_nosignhide "mandelbrot=size=176x144:rate=10" 2 \
  "ctu=32:signhide=0:rdoq-level=2:qp=24"
intra i_qcif_cuqp "testsrc2=size=176x144:rate=10" 3 \
  "ctu=64:aq-mode=2:qg-size=8:crf=28"
intra i_qcif_wpp "testsrc2=size=176x144:rate=10" 2 "ctu=32:wpp=1:qp=30"
intra i_qcif_slices4 "testsrc2=size=176x144:rate=10" 2 "ctu=16:slices=4:wpp=1:qp=30"
intra i_64x64_lossless "testsrc2=size=64x64:rate=10" 2 "ctu=32:lossless=1"
intra i_qcif_nostrong "smptebars=size=176x144:rate=10" 2 \
  "ctu=64:strong-intra-smoothing=0:tu-intra-depth=1:qp=32"

# Custom SPS scaling lists (every sizeId/matrixId explicit) from an
# HM-format list file written here.
SCALING="$(mktemp)"
trap 'rm -f "$SCALING"' EXIT
python3 - "$SCALING" <<'PY'
import sys
out = []
def ramp(n, base, step):
    return ",".join(str(min(255, base + (i * step) // 7)) for i in range(n))
for k, name in enumerate(["INTRA4X4_LUMA", "INTRA4X4_CHROMAU", "INTRA4X4_CHROMAV",
                          "INTER4X4_LUMA", "INTER4X4_CHROMAU", "INTER4X4_CHROMAV"]):
    out.append(f"{name} =\n{ramp(16, 8 + 2 * k, 9 + k)}")
for size in (8, 16, 32):
    for k, kind in enumerate(["INTRA", "INTRA", "INTRA", "INTER", "INTER", "INTER"]):
        if size == 32 and k not in (0, 3):
            continue
        comp = ["LUMA", "CHROMAU", "CHROMAV"][k % 3]
        name = f"{kind}{size}X{size}_{comp}"
        out.append(f"{name} =\n{ramp(64, 10 + size // 4 + k, 5 + k + size // 8)}")
        if size >= 16:
            out.append(f"{name}_DC =\n{9 + k + size // 8}")
open(sys.argv[1], "w").write("\n".join(out) + "\n")
PY
intra i_qcif_scaling_custom "testsrc2=size=176x144:rate=10" 2 \
  "ctu=32:scaling-list=${SCALING}:qp=27"
# Forced key frames with forced-idr: IDR, then CRA pictures mid-stream
# (NoRaslOutputFlag 0: picture order count continues across them).
encode i_qcif_cra "testsrc2=size=176x144:rate=10" 3 "${INTRA}:ctu=32:qp=32" \
  -forced-idr 1 -force_key_frames "expr:1"
# Hand-assembled PCM stream (libx265 never emits pcm_flag).
python3 scripts/generate_h265_pcm_fixture.py "$OUT"


# ----- Stage 2: P and B slices (inter prediction), in-loop filters off -----
INTER="no-deblock=1:no-sao=1:wpp=0"
encode p_qcif_ref1 "testsrc2=size=176x144:rate=10" 6 \
  "${INTER}:keyint=6:bframes=0:ref=1:ctu=32:qp=30"
encode p_qcif_ref3_amp "testsrc2=size=176x144:rate=10" 8 \
  "${INTER}:keyint=8:bframes=0:ref=3:ctu=32:rect=1:amp=1:max-merge=5:qp=28"
encode p_100x60_crop "testsrc2=size=100x60:rate=10" 6 \
  "${INTER}:keyint=6:bframes=0:ref=2:ctu=16:min-cu-size=8:qp=32"
encode p_mandel_tu_inter "mandelbrot=size=128x96:rate=10" 5 \
  "${INTER}:keyint=5:bframes=0:ref=2:ctu=64:tu-inter-depth=3:max-merge=2:qp=26"
encode p_qcif_constrained_intra "testsrc2=size=176x144:rate=10,noise=alls=60:allf=t+u" 4 \
  "${INTER}:keyint=4:bframes=0:ref=1:ctu=32:constrained-intra=1:qp=34"
encode p_qcif_notmvp_merge1 "testsrc2=size=176x144:rate=10" 6 \
  "${INTER}:keyint=6:bframes=0:ref=2:ctu=32:temporal-mvp=0:max-merge=1:qp=30"
encode b_qcif_pyramid "testsrc2=size=176x144:rate=10" 12 \
  "${INTER}:keyint=12:bframes=3:b-adapt=0:b-pyramid=1:ref=3:ctu=32:rect=1:amp=1:qp=30"
encode b_qcif_nopyramid_ref1 "testsrc2=size=176x144:rate=10" 9 \
  "${INTER}:keyint=9:bframes=2:b-adapt=0:b-pyramid=0:ref=1:ctu=16:min-cu-size=8:qp=33"
encode b_128x96_weighted "testsrc2=size=128x96:rate=10,fade=in:0:10" 10 \
  "${INTER}:keyint=10:bframes=2:b-adapt=0:ref=2:ctu=32:weightp=1:weightb=1:qp=28"
encode b_qcif_opengop "testsrc2=size=176x144:rate=10" 12 \
  "${INTER}:keyint=6:min-keyint=6:open-gop=1:bframes=3:b-adapt=0:ref=2:ctu=32:qp=32"
encode b_qcif_wpp_slices "testsrc2=size=176x144:rate=10" 8 \
  "no-deblock=1:no-sao=1:wpp=1:slices=2:keyint=8:bframes=2:b-adapt=0:ref=2:ctu=16:qp=30"


# ----- Stage 3: in-loop filters (deblocking, SAO) -----
encode f_qcif_deblock_ip "testsrc2=size=176x144:rate=10" 6 \
  "no-sao=1:wpp=0:keyint=6:bframes=0:ref=2:ctu=32:qp=34"
encode f_qcif_deblock_offsets "testsrc2=size=176x144:rate=10" 4 \
  "no-sao=1:wpp=0:keyint=4:bframes=0:ctu=16:min-cu-size=8:deblock=-2,3:qp=37"
encode f_mandel_sao_only "mandelbrot=size=128x96:rate=10" 4 \
  "no-deblock=1:sao=1:wpp=0:keyint=4:bframes=0:ctu=32:qp=32"
encode f_qcif_full_b "testsrc2=size=176x144:rate=10" 9 \
  "wpp=1:keyint=9:bframes=3:b-adapt=0:ref=3:ctu=32:qp=32"
encode f_100x60_full "testsrc2=size=100x60:rate=10" 5 \
  "wpp=0:keyint=5:bframes=1:b-adapt=0:ref=2:ctu=16:qp=30"
encode f_qcif_cuqp_chroma_offsets "smptebars=size=176x144:rate=10,noise=alls=20:allf=t" 4 \
  "wpp=0:keyint=4:bframes=0:ref=1:ctu=32:aq-mode=2:qg-size=16:crf=30:cbqpoffs=-4:crqpoffs=3"
encode f_64x64_lossless_filters "testsrc2=size=64x64:rate=10" 3 \
  "wpp=0:keyint=3:bframes=0:ctu=32:lossless=1"
encode f_qcif_slices_filters "testsrc2=size=176x144:rate=10" 4 \
  "wpp=1:slices=2:keyint=4:bframes=0:ref=1:ctu=16:qp=36"
encode f_qcif_constrained_intra_filters "testsrc2=size=176x144:rate=10,noise=alls=60:allf=t+u" 3 \
  "wpp=0:keyint=3:bframes=0:ref=1:ctu=32:constrained-intra=1:qp=40"
encode f_qcif_default "testsrc2=size=176x144:rate=10" 8 "keyint=8"

# ----- Negative fixtures: must be refused, never decoded -----
# Range-extensions "Main Intra" profile (libx265 with keyint=1).
encode unsupported_rext_main_intra "testsrc2=size=64x64:rate=10" 1 \
  "keyint=1:no-deblock=1:no-sao=1:qp=30"
# Main 10 (10-bit samples).
ffmpeg "${COMMON[@]}" -f lavfi -i "testsrc2=size=64x64:rate=10" -frames:v 1 -an \
  -c:v libx265 -pix_fmt yuv420p10le -x265-params "${X265_BASE}:qp=30" \
  -f hevc "$OUT/unsupported_main10.h265"
# 4:2:2 (Main 4:2:2 10 range-extensions profile).
ffmpeg "${COMMON[@]}" -f lavfi -i "testsrc2=size=64x64:rate=10" -frames:v 1 -an \
  -c:v libx265 -pix_fmt yuv422p -x265-params "${X265_BASE}:qp=30" \
  -f hevc "$OUT/unsupported_422.h265"

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
for stream in "$OUT"/*.h265; do
  name="$(basename "$stream" .h265)"
  case "$name" in
    unsupported_*) ;;
    *) oracle_digests "$stream" "$name" ;;
  esac
done
echo "fixtures and oracle digests written to $OUT"
