# Inter-coded long-dwell fixtures

Synthetic scene only (no camera footage): 300 frames, 48x32, 10 fps; luma 40 background and,
from frame 3 on, a static 16x16 luma-220 square at x 8..24, y 8..24 (the scene of the MJPEG
long-dwell test `scene(true, None, None, false)`).

Generated with FFmpeg 6.1.1 / libx264 (lab oracle only) from raw `gray` frames piped on stdin:

```sh
ffmpeg -f rawvideo -pix_fmt gray -s 48x32 -r 10 -i - -c:v libx264 -pix_fmt yuv420p \
  -x264-params 'keyint=60:min-keyint=60:bframes=2:scenecut=0:qp=8:threads=1' \
  -bitexact -map_metadata -1 -movflags +faststart square_300.mp4
ffmpeg -i square_300.mp4 -c copy -bsf:v h264_mp4toannexb -f h264 square_300.h264
```

| File | SHA-256 | Bytes |
| --- | --- | --- |
| `square_300.mp4` | `93c8fba615e53e48553957d340243400196d92233b332c224f2a2f451e2feb05` | 8721 |
| `square_300.h264` | `12300fa75f28da26c37922a824700909e0a7d680e03ccaf43771e835d023629f` | 5221 |

Both carry B-pictures (`has_b_frames=2`), so coding order differs from display order. The
long-dwell tests require the MP4 (timed from container presentation times) to yield one
whole-range episode in display order, and the Annex-B stream (timed by coding order) to be
refused because its capture clock would run backwards.
