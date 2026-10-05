# Indexed AVC MP4 laboratory fixture

`indexed_avc.mp4` is generated `testsrc2`, not footage of people or property. It contains ten 64x48 H.264 Main-profile frames at 5 fps, two IDRs, B-picture reordering, an avcC configuration, ordinary nonfragmented sample tables, and a unit-rate edit mapping media tick 4096 to movie time zero.

Generated in the authoring environment with FFmpeg 7.1.5 (lab oracle only):

```sh
ffmpeg -f lavfi -i 'testsrc2=size=64x48:rate=5:duration=2' -an \
  -c:v libx264 -profile:v main -pix_fmt yuv420p \
  -x264-params 'bframes=2:keyint=5:min-keyint=5:scenecut=0:threads=1' \
  -movflags +faststart indexed_avc.mp4
```

Source SHA-256: `b0f3e3baead39e711559e54250a62967d322d54889e353291f19e0ac73c33ccb` (4338 bytes).

The independent Python table-join/extraction probe matched FFprobe's ten sample offsets and sizes. Copying configuration plus all original sample NAL payloads with four-byte Annex-B start codes produced 3407 bytes, SHA-256 `d3dc6674d2727b4fb49fb40c0de6a72887a89eebb684e0b89011f6d285e115ff`. FFmpeg decoded those bytes and the original MP4 into identical ten-frame I420 output. This executed laboratory check is not execution of the Rust implementation.

The Rust `demux` tests consume these retained bytes directly and require no installed encoder. Eleven tests also cover independently constructed tables, truncation, offsets, overlap, selection, encrypted/external references, composition signedness, NAL framing, exact copy maps, budgets and cancellation. Rust compilation/tests/rustfmt were unavailable in the authoring environment and are not claimed passing. This fixture is not quality or production-qualification evidence.
