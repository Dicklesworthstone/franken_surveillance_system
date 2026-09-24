# HEVC ingest fixtures

Laboratory-oracle fixtures for retained H.265 (`hevc`) import, range decode and the model-free
watch pipeline. FFmpeg/libx265 (`ffmpeg version 8.0.1-3ubuntu2`) produced every file offline; the
Rust tests never run FFmpeg and never use the Rust decoder's own output as an expectation.

Regenerate with:

```sh
scripts/generate_hevc_ingest_fixtures.sh
```

| File | Content |
| --- | --- |
| `watch_96x48_moving.h265` | 96x48, 14 frames: luma-40 background; from frame 3 a 16x16 luma-220 square enters at the left edge and moves 8 px right per frame along rows 8..24 (the geometry of the MJPEG watch test scene). Neutral chroma. Raw `yuv420p` frames piped to libx265 with `log-level=error:pools=1:frame-threads=1:info=0:scenecut=0:keyint=30:bframes=0:qp=12` (one IDR then P pictures). |
| `watch_96x48_moving.sha256` | FFmpeg `yuv420p` framehash of that stream, one SHA-256 per frame in output order. |
| `b_qcif_opengop_from_cra.sha256` | FFmpeg framehash of `crates/fss-codec-h265/tests/fixtures/decode/b_qcif_opengop.h265` decoded from the VPS that opens its CRA access unit (retained segment 5) to the end, fed to FFmpeg on stdin. Decoding starts at the CRA, so FFmpeg skips that CRA's RASL picture (segment 6), as the Rust decoder must for a range that starts there. |

The oracle command is identical to `scripts/generate_h265_decode_fixtures.sh`:
`ffmpeg -threads 1 -i <stream> -fps_mode passthrough -c:v rawvideo -pix_fmt yuv420p -f framehash
-hash sha256 -`, keeping the frame index, byte count and digest columns.

Only synthetic scenes are used. No camera footage.
