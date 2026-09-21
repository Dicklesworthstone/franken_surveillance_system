# Native baseline JPEG color reconstruction

`fss_codec_mjpeg::color::decode_rgb` reconstructs packed RGB from actual grayscale
or JPEG Y/Cb/Cr data. It shares the existing bounded marker, Huffman, restart,
coefficient and inverse-transform implementation. The previous `decode_luma`
entry point retains its API, Y reconstruction arithmetic and luma work charges.

This is not a luma image repeated into three channels when the input is YCbCr.
Every admitted chroma block is reconstructed. Grayscale inputs are explicitly
replicated because no chroma exists in that source format.

## Supported numerical contract

The admitted coding subset remains one self-contained baseline sequential
Huffman scan, grayscale or YCbCr 4:4:4, 4:2:2 or 4:2:0. Reordered scan components,
odd raster sizes and restart intervals use the existing parser. Progressive,
arithmetic, multiscanned, table-inheriting, incompatible-color, truncated or
trailing-byte inputs remain explicit failures. A bad suffix cannot return pixels.

The implementation retains a single MCU's component tiles, not full-resolution
floating-point chroma planes. Nearest-cell replication is the explicit chroma
upsampling rule. Full-range JPEG Y/Cb/Cr is converted with this fixed Q16 matrix:

```text
R = Y + 91881 / 65536 * (Cr - 128)
G = Y - 22554 / 65536 * (Cb - 128) - 46802 / 65536 * (Cr - 128)
B = Y + 116130 / 65536 * (Cb - 128)
```

Rounding adds 32768, uses Euclidean integer division by 65536, then clamps to
0..255. Output bytes are tightly packed RGB HWC. This policy is deliberately not
libjpeg's optional fancy chroma interpolation, ICC color management, Exif
orientation, lens rectification, or an assertion about camera color calibration.
Metadata remains reachable through the complete original compressed input digest.

## Interface and limits

`RgbDecodeLimits` combines the existing `DecodeLimits` with an independently
narrowable `maximum_output_bytes`. The hard bounds remain 16 MiB compressed input,
4096 per axis, 4,194,304 pixels, and 4096 non-entropy markers. Packed output has a
separate ceiling of 12,582,912 bytes. Its allocation is checked before allocation;
no limit causes implicit resizing, cropping, or partial output.

`DecodedRgb` has immutable `pixels()`, `dimensions()` and `receipt()` accessors.
`RgbDecodeReceipt` binds the complete encoded digest, actual RGB digest,
implementation identity, component interpretation, dimensions, MCU/block/restart
counts and metadata accounting. RGB identity is deliberately distinct from the
old Y-only decoder identity. Source-profile hashing is charged to `DecodeBudget`.
The caller owns cancellation, framing, source custody and permission to decode.

## Authored tests and measured scope

Nine Rust contract tests cover actual JPEG syntax, sampling modes, scan order,
edge MCUs, color preservation, restart sequences, digests, malformed suffixes,
resource bounds and cancellation. The shared fixture builder encodes real
DC-only JPEG blocks rather than manufacturing decoder output objects.

Rust compilation and tests were not run in the authoring environment, which has
no Rust toolchain. Independent Python checks compared 264 encoded uniform-color
fixtures with Pillow's decoder; the maximum observed channel difference was zero.
An exhaustive comparison of 16,777,216 Y/Cb/Cr triples against the independent
decimal-coefficient matrix differed by at most one channel code value. These
checks validate the transcribed math and fixture syntax, not the compiled Rust
implementation. There is no real-camera or release-qualification claim.
