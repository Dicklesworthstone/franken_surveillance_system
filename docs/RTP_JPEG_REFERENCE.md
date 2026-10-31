# Native RFC 2435 RTP/JPEG reception

The packet owner reconstructs complete baseline JPEG images from RFC 2435 RTP
payloads. The result is a **derived JPEG interchange stream**. It preserves copied
compressed bytes, interpreted header dependencies and generated header ranges
separately. Original datagrams, source retention and transport authentication remain
independent responsibilities.

## Admitted image contract

The reconstruction profile is `fss.rtp_jpeg.rfc2435.whole_frame.v1`.
It admits non-interlaced baseline images with three 8-bit Y/Cb/Cr components,
standard JPEG Huffman tables and one interleaved scan:

| RTP field | Admitted behavior |
|---|---|
| Type | 0/64: 4:2:2; 1/65: 4:2:0 |
| Type-specific | Zero only; field-coded/interlaced forms refuse |
| Width/height | Nonzero multiples of eight, at most 2040 pixels per axis and the owner's narrower limit |
| Q=1..99 | RFC Appendix A integer-scaled luminance/chrominance quantizers |
| Q=128..254 | Two explicit 8-bit quantizers, immutable for that Q within the stream epoch; a zero-length table header may reuse an admitted prior definition |
| Q=255 | Two fresh explicit 8-bit quantizers on every first fragment; never cached |
| Reserved Q | 0 and 100..127 refuse |
| Quantization header | MBZ must be zero; exactly 128 table bytes or a permitted cached-table reference; used precision bits must describe 8-bit coefficients |
| Restart types | Nonzero restart interval, consistent through the image; complete-frame decoding only |
| Fragmentation | Increasing ordered RTP sequences and exact contiguous scan offsets; one timestamp and one parameter tuple per image |
| Completion | Marker on the final packet; optional terminal EOI is retained or generated when absent |

A one-table payload, 16-bit quantizers, other sampling/type assignments, arbitrary
trailing padding, partial-frame recovery and restart-based concealment have no
admitted interpretation. The actual JPEG decoder independently validates all
entropy, restart order, padding and component blocks before releasing pixels.
Transport completion alone never establishes pixel validity.

## Ownership, losses and bounded work

`fss_packet::jpeg::JpegDepacketizer` accepts already ordered, epoch-bound
packets. `JpegReceiver` composes it with the existing RTP sequence and reorder
owner. Ingest admits transport; polling performs ordered reconstruction and returns
the immutable original datagram even when reconstruction fails.

A confirmed gap, wrong offset, changed image parameters, timeout, cancellation or
EOF cannot publish a partial image. Duplicate/late traffic neither appends bytes nor
renews the original frame deadline. A new first fragment explicitly retires an
incomplete predecessor. A source restart closes the old owner; reconnect needs a
new stream generation.

Bounds are independent: complete derived image bytes (default 8 MiB, hard maximum
16 MiB), packets per image (at most 4096), immutable cached Q mappings (at most 127),
dimension limit and absolute pending-image lifetime. The RTP queue keeps its own
packet, byte and delay bounds. Reservations are fallible. Cache lookup examines at
most127 entries; reconstruction scans at most the bounded image and source maps.

A static quantizer definition can outlive its first image. Cached reuse retains the
original table packet's sequence, complete JPEG header dependency including the Q
selector, and exact copied quantizer ranges. The caller must retain that earlier
source packet to reproduce later images. Valid explicit parameter definitions may
enter the bounded cache before the associated image's pixel decode succeeds;
caching is not a claim that those pixels were valid.

`JpegFrame::source_spans` and `generated_ranges` partition the complete
derived JPEG without overlap. `header_sources` records interpreted source
dependencies, including cached definitions. Sequence ranges belong to the explicit
ingress/generation/SSRC owner; the 90 kHz timestamp is an uncalibrated media clock.
Debug and error output exclude packet and image contents.

## Retained independent fixtures and native checks

`scripts/generate_rtp_jpeg_fixtures.py` is an explicitly authorized laboratory
generator, not production code. It retains six deterministic synthetic baseline
JPEGs with both sampling layouts, extreme and ordinary quantizers, restart markers
and edge MCUs. The fixture manifest records encoder/oracle versions and exact byte
digests. FFmpeg luma outputs are retained, so Rust tests never launch a foreign
codec or process.

The packet contract checks all admitted RTP types, every entropy split boundary,
source-range partitioning, table caching and redefinition, loss, reorder,
sequence wrap, extension/padding exclusion, expiration, cancellation and bounds.
The codec contract runs the actual first-party luma and RGB decoders over retained
images reconstructed through computed, cached/static and dynamic quantizers.
Decoded luma is compared with retained FFmpeg output under the existing one-sample
tolerance; native decoded luma/RGB also match the original JPEG's native result.

Run the focused native targets:

```sh
cargo test --locked --offline -p fss-packet --test jpeg_contract
cargo test --locked --offline -p fss-codec-mjpeg --test rtp_jpeg_decode
```

These tests do not qualify a physical camera, capture clock, durable custody,
network deployment, full release matrix or unsupported JPEG/RTP profile.

Protocol basis: [RFC 2435](https://www.rfc-editor.org/rfc/rfc2435), especially
sections 3.1, 3.1.7, 3.1.8, 4.1 and Appendices A/B.
