# Native JPEG derivative encoding

`fss-codec-jpeg-encode` converts one explicitly supplied grayscale or RGB pixel
plane into one complete baseline JPEG using first-party safe Rust. It supports
bounded compressed review derivatives without introducing a foreign production
codec. The crate performs no filesystem, network, clock, process, thread or
publication operation.

The production dependency is `fss-core`. The native JPEG decoder is a development
dependency used by the contract tests. Keeping encoding in a separate crate
preserves the existing JPEG decoder implementation identities and historical
decode receipts.

## Admitted profile

| Property | Contract |
|---|---|
| Input | Tightly packed full-range 8-bit grayscale, or full-range R,G,B channel order |
| Output | One SOF0 baseline sequential JPEG, one scan |
| Color | Fixed Q16 RGB to JPEG Y/Cb/Cr, 4:4:4; no chroma subsampling |
| Dimensions | Positive axes, each at most 4096; at most 4,194,304 pixels |
| Output size | At most 16 MiB, including headers, entropy padding and EOI |
| Quality | Explicit integer 1 through 100; all values remain lossy |
| Transform | Exact DC; fixed Q14 separable AC transform; nearest quantization with ties away from zero |
| Entropy | Fixed Annex K Huffman tables, DC prediction, AC zero runs and FF byte stuffing |
| Padding | Repeat the last actual pixel and last actual row to complete 8x8 blocks |
| Metadata | No APP or COM segments, EXIF, ICC, comments, source timestamps or thumbnails |
| Ownership | Caller supplies and retains original pixels; only a complete compressed result can escape |

The syntax and fixed example tables follow ITU-T T.81, principally Annexes B, C,
F and K. The [JPEG committee's specification index](https://jpeg.org/jpeg/workplan.html)
identifies the normative edition; the [T.81 text](https://www.w3.org/Graphics/JPEG/itu-t81.pdf)
provides the marker, sequential DCT and Huffman definitions. The encoder declares
its own deterministic numerical and quality-scaling profile.

The transmitted quantizer for base-table value `b` is
`clamp((b * scale + 50) / 100, 1, 255)`, using integer division, where
`scale = 5000 / quality` below 50 and `200 - 2 * quality` otherwise.
Quality 50 transmits the base tables; quality 100 transmits all-one quantizers.

The exact DC coefficient before quantization is the sum of the 64 level-shifted
samples divided by eight. It does not use the approximate Q14 cosine basis:
otherwise a mathematically exact half-tie could round in the wrong direction.
For AC, the two integer matrix passes retain their full intermediate precision
and round once after division by `2^30 * quantizer`. Both signs use ties away
from zero. Intermediate values are bounded in signed 64-bit integers, and the
encoder refuses any coefficient outside the baseline category bounds.

RGB conversion uses these fixed Q16 expressions, rounded half up and saturated
to 0 through 255:

- `Y = (19595 R + 38470 G + 7471 B + 32768) >> 16`
- `Cb = (-11059 R - 21709 G + 32768 B + 128*65536 + 32768) >> 16`
- `Cr = (32768 R - 27439 G - 5329 B + 128*65536 + 32768) >> 16`

These are coded-pixel transformations. They do not apply display profiles,
orientation, lens correction, HDR interpretation, limited-range expansion or
implicit resizing.

## Library use

The owner must supply a nonzero SHA-256 digest that was independently pinned to
the exact input pixel buffer. A digest computed from arbitrary bytes does not
establish original-source custody or authorize disclosure.

```rust
use fss_codec_jpeg_encode::{
    EncodeBudget, EncodeConfig, EncodeLimits, PixelFormat, encode_jpeg,
};

fn encode_screened_luma(
    width: u32,
    height: u32,
    screened_pixels: &[u8],
    expected_pixel_sha256: [u8; 32],
    operation_budget: &mut EncodeBudget<'_>,
) -> Result<Vec<u8>, fss_codec_jpeg_encode::EncodeError> {
    let result = encode_jpeg(
        width,
        height,
        screened_pixels,
        expected_pixel_sha256,
        EncodeConfig { quality: 90, format: PixelFormat::Grayscale },
        &EncodeLimits::default(),
        operation_budget,
    )?;
    let receipt = result.receipt();
    // The owning operation retains receipt and its current privacy/source binding.
    let _receipt_digest = receipt.digest();
    Ok(result.into_bytes())
}
```

A caller can borrow its existing cancellation flag with
`EncodeBudget::with_cancellation`, or a cheap synchronous cancellation/deadline
probe with `EncodeBudget::with_cancellation_probe`. The codec starts no timer.
Sharing one budget across a sequence charges all frames to that same allowance.
A failed call does not replenish work already consumed.

`EncodedJpeg::bytes()` borrows a complete encoded image,
`into_bytes()` transfers its allocation, and `receipt()` returns its copyable
transformation record. Debug output never prints compressed or raw pixels.

## Bounds and failures

Shape, quality and caller ceilings are validated before image work. The caller's
limits can narrow the admitted profile; zero and above-profile limits refuse.
A positive output allowance too small to contain the complete JPEG returns a
resource refusal. No implicit downsampling, quality reduction, output truncation
or source fallback occurs.

Only the output JPEG requires a growing allocation. Its growth is fallible and
never requests a capacity beyond the admitted output ceiling. Input is borrowed;
component blocks, transform intermediates, tables and hashes use fixed bounded
storage. RGB processing converts one padded MCU at a time and never allocates a
second full RGB or Y/Cb/Cr image.

Every error exposes an `EncodeError` without compressed or raw payload:

- `InvalidConfiguration`: invalid quality or limit declaration.
- `InvalidPixels`: empty dimensions or a buffer inconsistent with the shape/layout.
- `SourceMismatch`: missing or mismatched pixel identity.
- `Limit`: dimension, pixel, whole-output or arithmetic ceiling.
- `Allocation`: a fallible output reservation failed.
- `BudgetExhausted`: the operation's work allowance is insufficient.
- `Cancelled`: the owner's borrowed flag or probe requests a stop.
- `CoefficientRange`: a coefficient, differential or entropy category leaves the profile.

Cancellation is checked before each work charge, including input and output
hashing in chunks of at most 16 KiB, each MCU and component block, encoded writes,
and final return. A complete but still unreturned internal JPEG is discarded if
the final cancellation or work check refuses.

This all-or-error guarantee covers the codec result. A caller that writes
already returned frames to a file still owns partial-file and finalization
semantics for a multi-frame operation.

## Identity, receipts and cost

`encoder_identity()` hashes a fixed 160-byte preimage: the hash of
`ENCODER_PROFILE`, followed by hashes of `src/lib.rs`, `src/tables.rs`,
`src/entropy.rs` and `src/transform.rs`, in that order. The profile begins with
`fss.jpeg_encoder.profile.v1` and names the numeric, framing and source-bound
construction. Encoding computes this identity once per frame, with its source
hashing charged once to the frame's work. It is never rehashed per pixel.

`EncodeReceipt` binds:

- Exact input pixel SHA-256 and complete output JPEG SHA-256.
- Encoder implementation identity.
- Original width, height, explicit format and quality.
- Complete byte count, MCU count and component-block count.
- Work charged by this call, distinct from the shared budget's cumulative total.

`EncodeReceipt::digest()` uses a fixed 170-byte canonical preimage: SHA-256 of
`fss.jpeg_encoder.receipt.v1`; the pixel, JPEG and encoder digests; two
big-endian u32 dimensions; a format byte (gray zero, RGB one); a quality byte;
then big-endian u64 byte, MCU, block and work counts. The receipt contains no
ambient time, path, principal or disclosure authority.

`ENCODE_WORK_MODEL` specifies deterministic reference units:

| Operation | Charge |
|---|---|
| Per-frame setup | 256 |
| Each SHA-256 invocation | 128 plus the exact number of hashed bytes |
| Each appended output byte | 1, including FF stuffing and all headers |
| Each MCU | 1 plus 64 per component |
| Each transformed/entropy-coded component block | 4096 |

The output is charged once for construction and once for hashing. These units
are a deterministic quota model, not elapsed time, energy or a throughput claim.
`EncodeLimits::work_bound(format)` gives a conservative allowance for one image
within valid declared limits; it does not guarantee that the independently
limited output will fit.

## Source and privacy meaning

The encoder sees supplied pixels, not the retained camera source or the current
deployment privacy policy. The consuming owner must verify source identity,
current deletion/privacy state, authorized frame selection and any output
authority before passing screened pixels and releasing a result.

Compression does not retain the unmasked input behind a supplied mask. It can,
however, change reconstructed samples near a masked boundary through lossy
quantization. Even quality 100 is not a proof of pixel-exact reconstruction.
A JPEG created from a screened black rectangle therefore cannot itself satisfy
a contractual requirement that every decoded mask pixel equal exact black.

This crate advances the derivative stage required by VIT-023 and DOC-052. It
does not supply FLDT media grants, source-side payment-mask attestation,
frame-accurate timestamp trimming, a timed playback container, recipient delivery
or current export authorization. Concatenating the outputs creates a JPEG frame
stream; playback cadence and source/capture timing remain separately declared.

## Verification status and reproduction

The authored core contracts comprise six internal unit tests and fifteen
`encode_contract` integration tests. They include hand-derived flat-block
Huffman vectors, exact DC half-ties, coefficient basis values, primary-color
conversion, complete marker structure, native decoder checks, odd dimensions,
quality extremes, exact and one-short work/output limits, shared allowance,
source mismatch, invalid shapes and limits, cancellation at every actual
checkpoint, receipt-field binding, and the difference between screened input and
lossy reconstructed mask edges.

At this checkpoint the executor became unavailable before a completed native
encoder test run or the planned independent FFmpeg/Pillow comparison. Those
gates remain pending; source presence and authored test vectors are not a runtime
pass.

```sh
cargo test --locked --offline -p fss-codec-jpeg-encode --lib --test encode_contract
```

Independent laboratory verification should decode deterministic grayscale,
RGB, odd-edge, constant-extreme and high-frequency outputs with pinned FFmpeg or
Pillow, inspect declared sampling/dimensions, and compare decoded pixels against
the supplied inputs and native reconstruction. Any retained evidence must pin
the exact source-bound encoder identity. These laboratory tools are not a
production dependency or an automatic runtime fallback.
