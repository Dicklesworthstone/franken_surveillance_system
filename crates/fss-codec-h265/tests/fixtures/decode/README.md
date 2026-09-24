# H.265 pixel-decode oracle fixtures

Every `.h265` stream here (except the `unsupported_*` negatives) has a
sibling `.sha256` file holding one SHA-256 per decoded frame, computed by the
sealed laboratory oracle: FFmpeg decodes the stream to packed planar I420
(`yuv420p` rawvideo: Y, then Cb, then Cr, no padding) and hashes each frame
in FFmpeg's OUTPUT (display) order. `tests/decode_conformance.rs` requires
the Rust decoder to reproduce every digest in the same order, the frame
count and the frame size exactly. The Rust tests never run FFmpeg, and no
expected value is derived from this crate's output.

Only synthetic `testsrc2` / `mandelbrot` / `smptebars` scenes and
hand-assembled bitstreams are used. No camera footage.

Oracle / encoder: `ffmpeg version 8.0.1-3ubuntu2` with libx265. Other
FFmpeg/x265 versions may encode different bytes; the committed bytes and
digests are the reference.

Regenerate everything (streams and digests) with:

```sh
scripts/generate_h265_decode_fixtures.sh
```

That script records the exact commands. All libx265 encodes use
`log-level=error:pools=1:frame-threads=1:info=0:scenecut=0` (one-thread
pool; `pools=none` mis-encodes multi-slice pictures in this x265 build).

## Stage 1: intra-only Main profile, in-loop filters off

Every frame is forced to be a key frame (`-force_key_frames expr:1`,
`keyint=30`): an IDR picture followed by TRAIL_R pictures made of I slices
(libx265 with `keyint=1` signals the range-extensions "Main Intra" profile
instead of Main). Common parameters:
`keyint=30:bframes=0:no-deblock=1:no-sao=1:wpp=0`.

| Stream | Size | Frames | Exercises |
| --- | --- | --- | --- |
| `i_64x64_ctu32_qp30` | 64x64 | 3 | CTB 32, min CB 8, QP 30 |
| `i_qcif_ctu64_qp22` | 176x144 | 2 | CTB 64, `tu-intra-depth=3`, QP 22, 32x32 transforms, strong smoothing |
| `i_qcif_ctu16_qp37` | 176x144 | 2 | CTB 16, QP 37 |
| `i_mandel_128x96_qp12` | 128x96 | 2 | `mandelbrot`, QP 12 (Rice / exp-Golomb escapes), wavefront (WPP) |
| `i_100x60_crop` | 100x60 (coded 104x64) | 3 | conformance window cropping |
| `i_qcif_tskip` | 176x144 | 2 | `smptebars`, transform skip |
| `i_qcif_scaling_default` | 176x144 | 2 | `scaling-list=default` (default lists, Tables 7-5/7-6) |
| `i_qcif_scaling_custom` | 176x144 | 2 | explicit SPS scaling lists for every size / matrix, DC values |
| `i_qcif_nosignhide` | 176x144 | 2 | `signhide=0`, `rdoq-level=2`, `mandelbrot` |
| `i_qcif_cuqp` | 176x144 | 3 | `aq-mode=2:qg-size=8:crf=28`: cu_qp_delta, QP prediction |
| `i_qcif_wpp` | 176x144 | 2 | `wpp=1`: entropy_coding_sync context storage / sync |
| `i_qcif_slices4` | 176x144 | 2 | CTB 16, four slices per picture, WPP |
| `i_64x64_lossless` | 64x64 | 2 | `lossless=1`: cu_transquant_bypass |
| `i_qcif_nostrong` | 176x144 | 2 | `strong-intra-smoothing=0`, CTB 64 |
| `i_qcif_cra` | 176x144 | 3 | `-forced-idr 1`: IDR then CRA pictures (POC continues) |
| `pcm_mixed_nodeblock` | 32x16 | 1 | hand-assembled PCM (5-bit luma, 6-bit chroma) + intra CUs |

`pcm_mixed_nodeblock` comes from `scripts/generate_h265_pcm_fixture.py`,
which writes the parameter sets and slice header bit by bit and encodes the
slice data with a small CABAC encoder (libx265 never emits `pcm_flag`).
Its pixels still come only from FFmpeg; the Rust test additionally checks
the PCM samples against the generator's pattern.

## Stage 2: P and B slices, in-loop filters off

Common parameters: `no-deblock=1:no-sao=1:wpp=0` (libx265 enables
`weightp` by default, so every P stream signals `weighted_pred_flag`).

| Stream | Size | Frames | Exercises |
| --- | --- | --- | --- |
| `p_qcif_ref1` | 176x144 | 6 | P slices, one reference, merge / AMVP, TMVP |
| `p_qcif_ref3_amp` | 176x144 | 8 | three references, rectangular + AMP partitions, 5 merge candidates |
| `p_100x60_crop` | 100x60 | 6 | CTB 16, two references, motion vectors past the picture edge (reference sample clamping), cropping |
| `p_mandel_tu_inter` | 128x96 | 5 | `mandelbrot`, CTB 64, `tu-inter-depth=3`, 2 merge candidates |
| `p_qcif_constrained_intra` | 176x144 | 4 | `constrained-intra=1` with temporal noise: intra CUs in P slices ignore inter neighbours |
| `p_qcif_notmvp_merge1` | 176x144 | 6 | `temporal-mvp=0`, `max-merge=1` (no merge_idx) |
| `b_qcif_pyramid` | 176x144 | 12 | `bframes=3`, B pyramid, `ref=3`, rect + AMP, output reordering |
| `b_qcif_nopyramid_ref1` | 176x144 | 9 | `bframes=2`, no pyramid, CTB 16 |
| `b_128x96_weighted` | 128x96 | 10 | `weightp=1:weightb=1` on a fade: explicit uni- and bi-predictive weights |
| `b_qcif_opengop` | 176x144 | 12 | `open-gop=1`, `keyint=6`: mid-stream CRA with decodable RASL pictures |
| `b_qcif_wpp_slices` | 176x144 | 8 | B slices with wavefronts and two slices per picture |

## Negative fixtures (refused, never decoded)

| Stream | Expected refusal |
| --- | --- |
| `unsupported_rext_main_intra` | `Unsupported(Profile)`: libx265 `keyint=1`, range-extensions Main Intra profile |
| `unsupported_main10` | `Unsupported(SampleFormat)`: `yuv420p10le`, Main 10 |
| `unsupported_422` | `Unsupported(SampleFormat)`: `yuv422p` |

## Coverage gaps the encoder cannot produce

- Tiles and dependent slice segments: libx265 cannot emit them; the decoder
  refuses both (`Unsupported(Tiles)`, `Unsupported(DependentSlices)`).
- PPS scaling lists: libx265 writes lists in the SPS only; the shared
  `scaling_list_data()` parser is unit-tested in `src/params.rs`.
- `cabac_init_flag`, initType 1/2 context values: checked against
  hand-typed rows of the standard's tables in `src/cabac.rs` unit tests.
