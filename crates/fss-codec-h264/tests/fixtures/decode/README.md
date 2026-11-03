# H.264 pixel-decode oracle fixtures

Every `.h264` stream here has a sibling `.sha256` file holding one SHA-256
per decoded frame, computed by the sealed laboratory oracle: FFmpeg decodes
the stream to packed planar I420 (`yuv420p` rawvideo: Y, then Cb, then Cr,
no padding) and hashes each frame in FFmpeg's OUTPUT (display) order.
`tests/decode_conformance.rs` requires the Rust decoder to reproduce every
digest in the same order, the frame count and the frame size exactly; for
B-frame streams it also checks that output order differs from decode order
and that POC increases. The Rust tests never run FFmpeg, and no expected
value is derived from this crate's output.

Only synthetic `testsrc2` / `mandelbrot` scenes (optionally with FFmpeg's
deterministic `noise` and `fade` filters) and hand-assembled bitstreams are
used. No camera footage.

Oracle / encoder: `ffmpeg version 8.0.1-3ubuntu2` with libx264, one thread.
Other FFmpeg/x264 versions may encode different bytes; the committed bytes
and digests are the reference.

Regenerate everything (streams and digests) with:

```sh
scripts/generate_h264_decode_fixtures.sh
```

That script records the exact commands. Summary:

| Stream | Size | Frames | Content |
| --- | --- | --- | --- |
| `i_qcif_qp28` / `qp12` / `qp44` | 176x144 | 3 / 2 / 2 | Intra only (`keyint=1`), I_NxN + I_16x16 |
| `ip_100x60_crop` | 100x60 (coded 112x64) | 6 | Frame cropping, I + P, `ref=1` |
| `ip_qcif_slices3` | 176x144 | 4 | Three slices per picture, I + P, `qp=30` |
| `ip_qcif_nodeblock` | 176x144 | 4 | `no-deblock=1` (disable_deblocking_filter_idc 1) |
| `ip_qcif_deblockoffs` | 176x144 | 4 | `deblock=-3,2` (alpha/beta offsets) |
| `p_qcif_ref3_p4x4` | 176x144 | 12 | `ref=3`, `partitions=all` (8x8 sub-partitions down to 4x4) |
| `ip_constrained_intra` | 128x96 | 3 | `constrained-intra=1` + temporal noise: intra MBs inside P slices |
| `pcm_mixed` / `_nodeblock` | 48x32 | 1 | Hand-assembled I_PCM + I_16x16 (`scripts/generate_h264_pcm_fixture.py`) |
| `ip_qcif_slices3_idc2` | 176x144 | 4 | `ip_qcif_slices3` with every slice rewritten to disable_deblocking_filter_idc 2 |
| `ip_100x60_poc0` | 100x60 | 6 | `ip_100x60_crop` rewritten to pic_order_cnt_type 0 |

Main and High profile streams (`encode_profile` in the script; x264
parameters are given in full, `threads=1:lookahead_threads=1:scenecut=0`):

| Stream | Profile | Size | Frames | Exercises |
| --- | --- | --- | --- | --- |
| `m_i_cabac_qp26` | Main | 176x144 | 2 | CABAC I slices (I_NxN, I_16x16) |
| `m_ip_cabac_ref3` | Main | 176x144 | 8 | CABAC P, `ref=3`, all partitions, list modification |
| `m_ip_cabac_slices3` | Main | 176x144 | 4 | CABAC with three slices per picture |
| `m_ip_cabac_100x60_nodeblock` | Main | 100x60 | 6 | CABAC, cropping, deblocking disabled |
| `m_ip_cabac_qp40` | Main | 128x96 | 5 | CABAC at QP 40, `mandelbrot` source |
| `m_ip_cabac_weightp` | Main | 128x96 | 6 | explicit weighted P prediction (`weightp=2` on a fade) |
| `m_ip_cabac_constrained` | Main | 128x96 | 3 | CABAC + constrained intra, intra MBs in P slices |
| `m_b_spatial` | Main | 176x144 | 10 | B slices, spatial direct, default bi-averaging (`weightb=0`) |
| `m_b_temporal` | Main | 176x144 | 10 | temporal direct, implicit bi-prediction weights |
| `m_b_pyramid_ref3` | Main | 176x144 | 12 | `bframes=3`, B pyramid (reference B pictures), MMCO 1, `ref=3` |
| `m_b_implicit_weight` | Main | 128x96 | 9 | temporal direct + implicit weights on a fade, MMCO 1 |
| `m_b_cavlc` | Main | 176x144 | 9 | B slices with CAVLC (`cabac=0`), B pyramid |
| `m_b_pocwrap_64x48` | Main | 64x48 | 24 | `pic_order_cnt_lsb` wraparound (32-value range), non-reference B |
| `h_8x8dct_i` | High | 176x144 | 2 | Intra_8x8 prediction + 8x8 transform (CABAC) |
| `h_8x8dct_b` | High | 176x144 | 9 | 8x8 transform in P/B, B pyramid |
| `h_cqm_jvt` | High | 176x144 | 6 | `cqm=jvt`: PPS scaling matrices using the default lists |
| `h_cavlc_8x8` | High | 176x144 | 6 | CAVLC 8x8 residual (four interleaved 4x4), B slices |
| `h_cqm_custom_100x60` | High | 100x60 | 5 | custom 4x4/8x8 scaling lists, fall-back rule A, cropping |

Coverage gaps the encoder cannot produce, and how they are covered instead:

- `cabac_init_idc` 1 and 2: libx264 always writes 0. The context
  initialisation tables for all three values are checked against
  hand-typed rows of Tables 9-12/9-13 in `src/cabac.rs` unit tests.
- Long-term reference pictures and MMCO 2..6: libx264 (through FFmpeg)
  never emits them. `tests/hostile_input.rs` decodes a hand-assembled stream
  with an IDR marked long-term, a `modification_of_pic_nums_idc == 2`
  selection and MMCO 2, with hand-computed pixels. MMCO 1 is exercised by
  the B-pyramid fixtures above.
- SPS-level scaling lists (fall-back rule B): libx264 writes matrices in
  the PPS only; rule B is unit-tested in `src/params.rs`.
- CABAC I_PCM: libx264 does not emit I_PCM (the CAVLC path is covered by
  `pcm_mixed`).

All libx264 encodes use `-profile:v baseline -pix_fmt yuv420p` and
`threads=1:lookahead_threads=1:bframes=0:scenecut=0:aud=0`, with the
per-stream parameters shown in the script, for example:

```sh
ffmpeg -f lavfi -i testsrc2=size=176x144:rate=10 -frames:v 12 -an -c:v libx264 \
  -profile:v baseline -pix_fmt yuv420p \
  -x264-params threads=1:lookahead_threads=1:bframes=0:scenecut=0:aud=0:keyint=12:ref=3:partitions=all:qp=30 \
  -f h264 p_qcif_ref3_p4x4.h264
ffmpeg -threads 1 -i p_qcif_ref3_p4x4.h264 -fps_mode passthrough \
  -c:v rawvideo -pix_fmt yuv420p -f framehash -hash sha256 -
```

The `_idc2` and `_poc0` streams come from `scripts/rewrite_h264_headers.py`.
It rewrites only parameter-set and slice-header fields and copies the
macroblock data verbatim, because libx264 cannot emit those syntax paths.
Their pixels still come only from FFmpeg. As a sanity check, FFmpeg decodes
`ip_100x60_poc0` to exactly the same frame digests as `ip_100x60_crop`.

Three committed streams are reused in place, and their digests are
generated by the same script:

- `baseline_i64.sha256` is for `../baseline_i64.h264` (64x64, I + P).
- `fss_packet_baseline.sha256` is for
  `crates/fss-packet/tests/fixtures/avc/baseline.264` (160x128, I P P I).
- `fss_packet_high_cropped.sha256` is for
  `crates/fss-packet/tests/fixtures/avc/high_cropped.264` (High profile,
  64x36, B frames, 8x8 transform).

The CABAC context tables in `src/cabac_tables.rs` are generated from the
same FFmpeg release's sources by `scripts/generate_h264_cabac_tables.py`.

`unsupported_high422.h264` (1.9 KB) is a negative fixture: High 4:2:2 from
`ffmpeg -f lavfi -i testsrc2=size=64x48:rate=10 -frames:v 4 -c:v libx264 -profile:v high422 -pix_fmt yuv422p -bf 0 -f h264`.
It must be refused as unsupported (chroma format), never decoded.
