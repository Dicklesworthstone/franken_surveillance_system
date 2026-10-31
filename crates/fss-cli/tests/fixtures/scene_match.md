# Synthetic grayscale stereo fixtures

`scene_match_left.jpg` and `scene_match_right.jpg` are original, independently
encoded baseline grayscale JPEGs generated only for native matching tests. Their
combined size is 2,361 bytes. They contain no photographs, personal information,
camera metadata or retained deployment evidence.

An LCG seeded with `1973`, using `state = (1664525*state + 1013904223) mod 2^32`,
generates 26 by 16 grayscale tile values `20 + ((state >> 16) mod 180)`. Each tile
is an 8 by 8 constant patch, producing a 208 by 128 source raster. The left image
is its 192 by 128 crop starting at x=0; the right image starts at x=16. Pillow
encodes each crop separately with grayscale mode, quality=95, optimize=False,
progressive=False and subsampling=0. No external decoder runs in production or
in the Rust tests: both frames pass through `fss-codec-mjpeg`.

The analytic oracle uses identity camera rotations, optical centers [0,0,0]
and [1,0,0], focal lengths [160,160], and principal point [96,64]. The corresponding
image texture therefore has disparity 16 pixels on a stationary plane at z=10
in relative source-world units. Native feature extraction and descriptor matching
select the feature locations without a supplied correspondence list. Expected
positions follow the independent rectified-stereo formulas z=160/16,
x=(u-96)/16, and y=(v-64)/16.

The 16-pixel crop displacement preserves JPEG block phase. Matching decoded
interior patches therefore have identical encoded transform content; boundaries
and the complete 33 by 33 descriptor footprint remain explicitly excluded by the
native extractor. These ideal synthetic images qualify software behavior only;
they do not establish real camera calibration or field matching accuracy.

SHA-256 identities:

- left: `84ef1792126cbe6426494cb4b177e5affa9876273040be2e9f70a8a43a54f652`
- right: `e284cf5d0ad54929798a5393ab115e18352e5dc38d80087dd46b228a5c1c6eb8`
