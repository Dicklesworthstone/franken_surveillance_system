# Native JPEG/MJPEG decoding and incremental framing

WP-060 implementation slice: `fss-codec-mjpeg` consumes owner-supplied compressed
bytes without a foreign decoder, filesystem, clock, thread or runtime dependency.
It depends only on `fss-core`; all Rust targets forbid unsafe code.

`decode_luma` accepts one complete, self-contained SOF0 Huffman JPEG: 8-bit
quantizers, grayscale or explicitly declared YCbCr 4:4:4, 4:2:2, or 4:2:0, one
sequential scan, and optional restart intervals. It validates chroma entropy even
though only full-resolution luma is reconstructed. The Q14 separable integer IDCT
has bounded i64 intermediates. Tables are never inherited or invented; malformed
codes, restarts, padding, missing EOI and trailing data refuse the whole result.
Progressive, arithmetic, RGB/CMYK, abbreviated and multi-scan coding remain outside
this decoder. Exif orientation and ICC transforms are not silently applied.

The result retains encoded and decoded SHA-256 values, explicit interpretation,
decoder identity, MCU/block/restart counts and metadata accounting. This is not
source custody, authentication, capture timing, calibration, or physical accuracy.

`stream::JpegStream` incrementally frames a contiguous concatenation of JPEG
images. Input slices pin their absolute offset. Segment lengths protect embedded
marker-like metadata bytes; entropy stuffing and restart markers are handled
structurally. A push stops after one image and reports the consumed prefix, leaving
the next image's bytes with its caller. A frame retains original bytes, absolute
half-open source range, stream generation, ordinal and digest. Framing is not
entropy validation: `FramedJpeg::decode` performs the complete decoder operation.

Offsets, frame bytes, marker counts, allocation and work are bounded. Any error
latches; no resynchronization silently skips bytes. `abort` returns buffered source
bytes without needing spare budget, even after cancellation. `finish` succeeds
only between frames. Earlier valid frames are not a claim that a later truncated
stream completed. This module is not an HTTP, UVC, AVI or live-device adapter.

## Reproduction

```sh
cargo test --locked --offline -p fss-codec-mjpeg
cargo run --locked --offline -p fss-codec-mjpeg --example decode_frame -- INPUT SHA256 grayscale
cargo run --locked --offline -p fss-codec-mjpeg --example decode_stream -- INPUT SHA256 grayscale
```

The explicit owner-run file examples bound file sizes, verify hashes and report
actual computed results; the stream example emits completion only after all
frames decode and framing ends cleanly. They are not registered `fss/1` commands.

This recovery includes 35 authored Rust tests (2 unit, 16 decode, 17 streaming),
synthetic grayscale/subsampled/restart fixtures and independently decoded luma.
The separate recovery bundle's 13 Python reference tests passed again during this
session, including 60 encoded cases, 2,000 transform-bound cases and exhaustive
fixture chunk splits. Rust compilation, native tests and field qualification have
NOT run in this environment, which has no Rust toolchain. No broader gate or bead
is closed by this source addition. The existing reference-only splitter is retained.
