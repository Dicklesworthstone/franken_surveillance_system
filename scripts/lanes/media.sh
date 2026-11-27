#!/usr/bin/env bash
# QL-MEDIA-001 — media probe lane (FSS-053).
#
# The probe is a contract on *exit status*, so the lane drives the real binary instead of only calling
# the library: a lane that passes without executing the shipped path proves nothing. Every fixture is a
# header prefix; the expected status is the assertion.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
TOOLCHAIN="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml 2>/dev/null || true)"
if [[ -n "$TOOLCHAIN" ]]; then RUN=(rustup run "$TOOLCHAIN"); else RUN=(); fi

export CARGO_NET_OFFLINE=true
export RUSTUP_AUTO_INSTALL=0
export RCH_SHIM_LOCAL_IDE="${RCH_SHIM_LOCAL_IDE:-1}"

# Reuse a binary if one is present: the lane is about behaviour, and rebuilds are the slowest thing in
# it (a flaky build queue must not read as a probe failure).
BIN=""
HOST="$(rustc -vV 2>/dev/null | sed -n 's/^host: //p')"
TARGET_BASE="${CARGO_TARGET_DIR:-target}"
for candidate in \
  "${TARGET_BASE}/${HOST}/debug/fss-probe" \
  "${TARGET_BASE}/debug/fss-probe" \
  "target/${HOST}/debug/fss-probe" \
  target/*/debug/fss-probe \
  target/debug/fss-probe; do
  [[ -x "$candidate" ]] && { BIN="$candidate"; break; }
done
if [[ -z "$BIN" ]]; then
  BIN="$("${RUN[@]}" cargo --offline build --locked -q --message-format=json -p fss-cli --bin fss-probe \
    | python3 -c 'import json,sys
for line in sys.stdin:
    m = json.loads(line)
    if m.get("reason") == "compiler-artifact" and m["target"]["name"] == "fss-probe":
        print(m["executable"])')"
fi
[[ -x "$BIN" ]] || { printf 'fss-probe is neither built nor buildable\n' >&2; exit 1; }

check() { # check <expected-exit> <label> <printf-format>
  local want="$1" label="$2" fixture="$3"
  local got=0
  printf "$fixture" | "$BIN" --bytes 16 >/dev/null 2>&1 || got=$?
  if [[ "$got" != "$want" ]]; then
    printf 'probe %s: exit %s, wanted %s\n' "$label" "$got" "$want" >&2
    exit 1
  fi
  printf 'probe %s: exit %s\n' "$label" "$got"
}

checkp() { # checkp <expected-exit> <label> <printf-format>  — --parameters mode
  local want="$1" label="$2" fixture="$3"
  local got=0
  printf "$fixture" | "$BIN" --parameters --bytes 16 >/dev/null 2>&1 || got=$?
  if [[ "$got" != "$want" ]]; then
    printf 'parameters %s: exit %s, wanted %s\n' "$label" "$got" "$want" >&2
    exit 1
  fi
  printf 'parameters %s: exit %s\n' "$label" "$got"
}

checkfile() { # checkfile <expected-exit> <label> <file> [extra fss-probe args...]
  local want="$1" label="$2" file="$3"
  shift 3
  local got=0
  "$BIN" "$@" < "$file" >/dev/null 2>&1 || got=$?
  if [[ "$got" != "$want" ]]; then
    printf 'probe-file %s: exit %s, wanted %s\n' "$label" "$got" "$want" >&2
    exit 1
  fi
  printf 'probe-file %s: exit %s\n' "$label" "$got"
}

check 0 matroska            '\x1a\x45\xdf\xa3matroska'
check 0 isobmff-brand       '\x00\x00\x00\x18ftypavc1'
check 0 jpeg                '\xff\xd8\xff\xe0ACameraX'
check 10 short-head         'FLV'
check 11 unknown            'RIFFxxxxWAVE'
check 12 contradictory      '\x00\x00\x01\x67ftypisom'
checkp 10 parameters-short  '\x00\x00\x00\x01\x67'
checkfile 0 mp4-avc-params  crates/fss-container/tests/fixtures/fragmented_av.mp4 --parameters
checkfile 0 mp4-hevc-params crates/fss-container/tests/fixtures/hevc_fragmented_av.mp4 --parameters
checkfile 0 mkv-avc-params  crates/fss-container/tests/fixtures/avc_av.mkv --parameters
checkfile 0 mkv-hevc-params crates/fss-container/tests/fixtures/hevc_av.mkv --parameters
checkfile 14 mp4-unit-limit crates/fss-container/tests/fixtures/fragmented_av.mp4 --parameters --units 1

# FSS-053 — bounded media probe engine library, contract, and CLI unit suites.
"${RUN[@]}" cargo --offline test --locked -q -p fss-container --lib probe::
"${RUN[@]}" cargo --offline test --locked -q -p fss-container --test fss_053_media_probe_contract
"${RUN[@]}" cargo --offline test --locked -q -p fss-cli --bin fss-probe

# FSS-115 — deterministic fragmented MP4/CMAF writer, reader, timeline, and malformed gauntlets.
"${RUN[@]}" cargo --offline test --locked -q -p fss-container \
  --test fss_115_fragmented_mp4_cmaf_contract \
  --test avc_mux_contract \
  --test hevc_remux_contract \
  --test implicit_fragment_contract \
  --test inband_mp4 \
  --test mixed_mp4 \
  --test movie_output_contract \
  --test movie_timing_contract \
  --test demux_malformed_gauntlet

# FSS-054 / FSS-117 — bounded pure-Rust scalar decode engine (MJPEG/JPEG, H.264/AVC, H.265/HEVC),
# AVI MJPEG vertical slice, hostile-input refusal, malformed media gauntlets, and custody/gap receipts.
"${RUN[@]}" cargo --offline test --locked -q -p fss-codec-mjpeg -p fss-codec-h264 -p fss-codec-h265 --lib --tests
"${RUN[@]}" cargo --offline test --locked -q -p fss-container --test avi_mjpeg_contract
"${RUN[@]}" cargo --offline test --locked -q -p fss-reference \
  --test decode_jpeg_contract \
  --test decode_receipt_contract \
  --test decode_gap_coverage_contract \
  --test rtpdump_decode_contract \
  --test rtpdump_custody_decode_contract

# FSS-055 — bounded pure-Rust encode and rendition kernels (deterministic JPEG/MJPEG derivatives).
"${RUN[@]}" cargo --offline test --locked -q -p fss-codec-jpeg-encode --lib --tests

# FSS-057 / FSS-058 / FSS-119 / FSS-120 / FSS-121 / DOC-041 / DOC-054 — buffer accounting,
# frame pools, lineage, pressure ladder, preview fan-out, derivative receipts, and frame pyramids.
"${RUN[@]}" cargo --offline test --locked -q -p fss-tensor \
  --test fss_057_preview_fanout_contract \
  --test fss_058_buffer_accounting_contract \
  --test fss_119_frame_pool_contract \
  --test fss_120_source_to_tensor_lineage_contract \
  --test fss_121_media_pressure_ladder_contract \
  --test doc_041_media_derivative_receipt_contract \
  --test doc_052_media_delivery_decision_card_contract \
  --test doc_054_frame_pyramid_contract

# FSS-056 / FSS-060 / FSS-125 — keyframe-aware chunker, decode/timestamp oracle, and malformed corpus minimizer.
"${RUN[@]}" cargo --offline test --locked -q -p fss-container \
  --test fss_056_keyframe_chunker_contract \
  --test fss_060_decode_timestamp_oracle_contract \
  --test fss_125_malformed_corpus_minimizer_contract
