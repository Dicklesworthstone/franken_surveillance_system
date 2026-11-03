# Native H.264 picture ordering

The pure-Rust H.264 decoder admits picture-order-count (POC) types **0, 1 and 2**
within its existing progressive, 8-bit, 4:2:0 Baseline/Main/High profile. This
closes the type-1 decoding gap in FSS-124: the packet layer could already preserve
that syntax, but the decoder previously refused it before producing pixels.
The same decoder is used by retained-file and native RTSP media analysis.

## Type-1 behavior

The decoder reads the SPS reference-picture offset cycle, signed non-reference
and top-to-bottom offsets, the always-zero-delta flag, and both applicable slice
POC deltas. It calculates frame-number wrap from the previous decoded picture,
including non-reference pictures, and derives each frame's POC from the minimum
of its two field counts. The existing decoded-picture buffer uses that POC for
reference lists and display order; callers continue to bind source evidence by
decode index rather than assuming arrival order equals display order.

Cycle length is bounded at 255 entries. Signed arithmetic, both field counts and
the accumulated frame-number offset are checked before admission. IDR and MMCO 5
reset ordering state. Slices assembled into one picture must agree on both POC
deltas. A malformed header, inconsistent picture, exhausted existing decoder
allowance or unavailable reference still refuses through the existing typed
error and IDR-resynchronization paths. No partial picture is returned as a
successful decode.

The interpretation follows ITU-T H.264 (08/2024), sections 7.4.2.1.1, 8.2.1 and
8.2.1.2. Interlaced pictures, unsupported chroma/bit-depth modes and other
previously unsupported coding tools retain their existing refusals. This adds
one coding mode; it does not qualify every camera or H.264 bitstream.

## Evidence and compatibility

The pinned native codec suite passes **162 tests** on `nightly-2026-08-31`:

- Three new real encoded streams cover a reference-offset cycle, explicit deltas
  across three slices per picture, and reordered Main-profile I/P/B pictures.
  All 19 frames match frozen FFmpeg I420 hashes in display order. The test runtime
  uses only the native Rust decoder; FFmpeg is an offline fixture oracle.
- Eleven focused synthetic-stream tests exercise signed cycles and deltas,
  non-reference pictures, frame-number wrap, empty cycles, always-zero deltas,
  IDR/MMCO 5 reset, inconsistent slices, overflow, truncation and decoder limits.
- Two RTP integration tests run the actual packet receiver, AVC reconstruction
  and decoder together. They check FU-A fragmentation, reordered packets,
  sequence-number wrap, exact source byte spans and the independently frozen
  pixel hashes.
- The existing conformance corpus remains bit-exact, and the existing hostile
  input and malformed-media tests continue to pass, including 2,000 mutations
  and structural cuts.

Run the complete native codec suite with:

```sh
cargo +nightly-2026-08-31 test --locked --offline -j1 -p fss-codec-h264 --lib --tests
```

Fixture provenance and reproduction commands are in the
[decode fixture README](../crates/fss-codec-h264/tests/fixtures/decode/README.md).
The offline rewrite script changes ordering headers while retaining the encoded
macroblock payloads; it never derives expected pixels from the Rust decoder.

Previously admitted type-0/type-2 pixels and existing recorded-frame receipt
encodings and decoder labels are unchanged. Type-1 inputs were previously
refused, so the new admission does not reinterpret an older successful type-1
receipt. Packet custody, capture timestamps, privacy and source authorization
remain owned by their existing boundaries. Codec and RTP tests establish this
bounded media path, not physical-device interoperability or full release
qualification.
