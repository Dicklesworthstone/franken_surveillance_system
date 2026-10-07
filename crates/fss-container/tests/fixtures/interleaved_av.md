# Interleaved audio/video AVC MP4 laboratory fixture

`interleaved_av.mp4` is generated `testsrc2` video plus a 440 Hz `sine` tone, not footage of
people or property. The video is the same ten 64x48 H.264 Main-profile frames as
`indexed_avc.mp4` (5 fps, two IDRs, B-picture reordering); an 8 kHz mono AAC track is stored
interleaved with it inside `mdat`, and `moov` follows `mdat` (no `faststart`). It exercises an
ordinary camera/phone export layout: video samples separated by other tracks' bytes, and the
`avcC` configuration after the media.

Generated with FFmpeg 6.1.1 (lab oracle only):

```sh
ffmpeg -f lavfi -i 'testsrc2=size=64x48:rate=5:duration=2' \
  -f lavfi -i 'sine=frequency=440:duration=2:sample_rate=8000' \
  -c:v libx264 -profile:v main -pix_fmt yuv420p \
  -x264-params 'bframes=2:keyint=5:min-keyint=5:scenecut=0:threads=1' \
  -c:a aac -b:a 8k -ac 1 -bitexact -map_metadata -1 interleaved_av.mp4
```

Source SHA-256: `21815d58d34cef6550de7934f184d46953603e3d15dc61d11bfe0be8496a6231` (7262 bytes).
Top-level boxes: `ftyp` (0, 32), `free` (32, 8), `mdat` (40, 5542), `moov` (5582, 1680).

`indexed_avc_i420.sha256` holds FFmpeg's per-frame SHA-256 of packed I420 output (presentation
order, columns: frame index, byte count, digest) for the video track of both MP4 fixtures, which
decode to identical frames:

```sh
ffmpeg -threads 1 -i FILE -map 0:v:0 -fps_mode passthrough -c:v rawvideo -pix_fmt yuv420p \
  -f framehash -hash sha256 - | grep -v '^#' | awk -F', *' '{ print NR - 1, $5, $6 }'
```

The `fss-reference` retained-decode tests import both files as `mp4avc` and require the
pure-Rust decode of the retained custody to reproduce these digests. FFmpeg is not needed to run
the tests. This fixture is not quality or production-qualification evidence.
