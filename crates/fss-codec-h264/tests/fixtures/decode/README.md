# H.264 pixel-decode oracle fixtures

Every `.h264` stream here has a sibling `.sha256` file holding one SHA-256
per decoded frame, computed by the sealed laboratory oracle: FFmpeg decodes
the stream to packed planar I420 (`yuv420p` rawvideo: Y, then Cb, then Cr,
no padding) and hashes each frame. `tests/decode_conformance.rs` requires
the Rust decoder to reproduce every digest, the frame count and the frame
size exactly. The Rust tests never run FFmpeg, and no expected value is
derived from this crate's output.

Only synthetic `testsrc2` scenes (optionally with FFmpeg's deterministic
`noise` filter) and hand-assembled bitstreams are used. No camera footage.

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

Two committed streams are reused in place, and their digests are generated
by the same script:

- `baseline_i64.sha256` is for `../baseline_i64.h264` (64x64, I + P).
- `fss_packet_baseline.sha256` is for
  `crates/fss-packet/tests/fixtures/avc/baseline.264` (160x128, I P P I).
