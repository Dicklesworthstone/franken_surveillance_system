# Baseline generation compatibility

Progressive SOF2 images use a new source-bound decoder identity. SOF0 images continue through
the unchanged baseline parser, entropy decoder and inverse transform. `decode_luma_v1` and
`color::decode_rgb_v1` replay the original baseline generation, including its unsupported-SOF2
refusal. The default entrypoints select progressive only from an explicit frame header in the
bounded marker prefix; marker-looking metadata bytes never select a decoder.

The original RGB identity was a hash of five complete source files. Adding a format dispatcher
to `lib.rs` and `color.rs` would otherwise rename every baseline image and model generation,
despite identical pixels and accounting. Its exact existing identity is therefore frozen:

`71e2b78082d9c8d4f16b6f263abeaada4eab0f231380ce1b85e2668148138edc`

The auditable preimages are the files at commit
`309ecc62e7edf7b90cafdceb42747e7a1e6c6d9b`, under `crates/fss-codec-mjpeg/src`:

| File | Bytes | SHA-256 |
|---|---:|---|
| color.rs | 7108 | 9b250dbc6ecbcffb84acf0e305ee2a82b9bee77d9c5f2ae7d5a02b21eb32c1df |
| image.rs | 15879 | d47cf83b929fcb851ed57f0787cfa3ba5443b69634862cd9947904376a9e7b53 |
| entropy.rs | 5999 | f65771835480873280ddb02b7cf4f84bf113a1c78e7d0abf6868fd0e37567d95 |
| transform.rs | 1685 | ceed9f6dfd3575246727f7e4cf791c207a90e3c2ac03ff193b334fb433943276 |
| lib.rs | 10874 | 927582fc8f72d3ea6488ef8d623fa8f815bb8e882a2bc967797d5f0b1d6fb5bb |

The identity is SHA-256 of six concatenated SHA-256 values: first the UTF-8 label
`fss/jpeg-rgb/reference/1;nearest-chroma;q16-half-up;rgb-hwc`, then the five file hashes in table
order. The baseline RGB work charge for those source bytes stays exactly **41,545**. The luma
identity remains its existing fixed value. Tests reconstruct the RGB fingerprint from these
preimages, compare baseline/default receipts and work at an exact allowance, and replay original
SOF2 refusals with their original work allowance.

New progressive luma and RGB identities hash their explicit numeric-policy label and current
`progressive.rs`, `entropy.rs`, `transform.rs`, `lib.rs`, and `color.rs` source preimages. They are
distinct generations. Changes to this new implementation must not silently replace a retained
generation in a later release; add an explicit replay implementation or migrate through an
authorized new derivation when that becomes necessary.

## Admitted progressive images

The new engine decodes self-contained 8-bit Huffman SOF2 grayscale and YCbCr 4:4:4, 4:2:2 and
4:2:0 images. It supports interleaved DC and single-component AC scans, spectral selection,
successive DC/AC approximation, EOB runs, four Huffman/quantizer destinations, 8-bit quantizers,
restart intervals and table changes between scans. A quantizer destination becomes immutable
once used in the image. Arithmetic coding, 12-bit samples, lossless JPEG, unsupported sampling,
hierarchical coding, DNL heights, inherited external tables and trailing bytes remain refusals.

All components must transmit DC before EOI, and each component's first DC must precede its AC.
Spectral first scans cannot overlap; refinements must name the previously transmitted precision
and improve it by exactly one bit. Unsent AC positions remain zero, and EOI can finish at the
declared approximation precision. This is an encoded progression, not truncation concealment:
missing entropy, wrong EOB lengths, absent EOI and malformed padding always refuse the image.

The entire image's quantized coefficients use bounded signed-16-bit storage, with a 32 MiB hard
ceiling in addition to the existing dimension/pixel ceilings. There are at most 256 scans and
4096 markers. Allocation, each scan MCU/block, reconstruction and fingerprints consume the
explicit cancellation-aware work budget. The conservative `luma_work_bound` includes this new
scan ceiling; actual baseline charges and exact custom-budget acceptance are unchanged.

MCU and entropy-block receipt counts sum visits across progressive scans, including refinement.
Restart counts sum only validated markers. Pixel reconstruction uses the same Q14 inverse DCT,
nearest-cell chroma and Q16 color transform as baseline. No partial pixels escape before exact
EOI validation. Independent libjpeg progressive/baseline pairs must produce byte-identical native
luma and RGB, with the separately retained FFmpeg luma oracle within the declared IDCT rounding
tolerance of one sample value.

## Retained outcomes

The existing success/refusal canonical formats already encode a decoder identity. Their keys
now use the actual generation from that field, preserving all baseline bytes and keys. Default
retained decoding selects the generation from verified source bytes, so an old unsupported-SOF2
refusal cannot suppress new progressive decoding. `RetainedRefusal::open_with_decoder` reopens
the old record explicitly, and replay dispatches its original generation. Old refusal and new
success remain separate immutable evidence; no historical outcome is overwritten.

The existing v1 temporal watch/dwell/health/corroboration recipes, detector/sentinel/cascade
recipes, calibration/rectification domains, HTTP luma-check chains and reconnect luma
configuration explicitly pin baseline decoding. Those owners now call `decode_luma_v1` or
`decode_rgb_v1`, preserving old refusal-as-gap and replay behavior. This change does not
silently upgrade their immutable recipes. Progressive decoding
is available through the current native luma/RGB entrypoints, retained file decoding and RGB
inference/capture paths that bind the actual frame receipt. `fss-lab decode` reports the actual
generation of progressive/mixed rows and marks uncompleted work without guessing its generation;
completed baseline-only JSON bytes are unchanged.

Normative syntax and coefficient rules: ITU-T T.81 (1992), Annexes A, B and G,
<https://www.w3.org/Graphics/JPEG/itu-t81.pdf>. Offline fixture provenance and reproduction are
in `tests/fixtures/progressive_jpeg/manifest.json` and `generate.py`.
