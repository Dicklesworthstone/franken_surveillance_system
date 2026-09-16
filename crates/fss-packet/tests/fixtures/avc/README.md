# AVC laboratory fixtures

Both fixtures contain only a generated `testsrc2` scene. No camera footage, person,
account, credential, model, or external recording was used. They are real encoded
bitstreams, unlike the older synthetic slice-body fixtures. This does not make the
FSS parser a decoder or a production-qualified implementation.

Laboratory encoder: FFmpeg `7.1.5-0+deb13u1`, libx264, one encoder/lookahead thread.
Exact bytes are retained; future encoder versions need not reproduce the hashes.
Expected metadata, NAL types, picture identities, and SHA-256 are in `expected.json`.

```sh
ffmpeg -hide_banner -loglevel error -f lavfi -i 'testsrc2=size=160x128:rate=25' \
  -frames:v 4 -an -c:v libx264 -profile:v baseline -pix_fmt yuv420p \
  -x264-params 'threads=1:lookahead_threads=1:keyint=3:min-keyint=3:scenecut=0:bframes=0:ref=1:repeat-headers=1:aud=0' \
  -f h264 baseline.264
ffmpeg -hide_banner -loglevel error -f lavfi -i 'testsrc2=size=64x36:rate=25' \
  -frames:v 6 -an -c:v libx264 -profile:v high -pix_fmt yuv420p \
  -x264-params 'threads=1:lookahead_threads=1:keyint=6:min-keyint=6:scenecut=0:bframes=2:ref=3:8x8dct=1:repeat-headers=1:aud=0' \
  -f h264 high_cropped.264
ffprobe -v error -count_frames \
  -show_entries stream=profile,width,height,coded_width,coded_height,has_b_frames,nb_read_frames \
  -of json baseline.264
```

These commands are laboratory provenance, not build scripts or runtime downloads.
