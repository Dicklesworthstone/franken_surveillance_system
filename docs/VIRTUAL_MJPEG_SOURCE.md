# Decodable virtual MJPEG source

`fss_reference::ingest::virtual_mjpeg` connects the existing first-party JPEG
fixture encoder to `SourcePacket`, native JPEG framing/decoding, delivery fault
injection and the existing root-last reference capture publisher. It is an
explicit synthetic profile. The legacy `VirtualCameraSpec` PRNG source, its
byte generation and public entry points remain unchanged.

## Run a complete source-to-decode example

```sh
cargo run -p fss-reference --example virtual_mjpeg_capture -- /tmp/fss-scene.mjpeg
```

The example generates twelve 128x96 grayscale frames with three background-only
warmup frames, verifies every frame with `fss-codec-mjpeg::decode_luma`, then
writes the original concatenated JPEG bytes. The file can be fed to the existing
file-ingest path. The output is create-new: existing files are never overwritten.
An I/O failure may leave a partial new file, not a completed capture receipt.
No external codec, network service or model download is needed.

## Library workflow

Construct `MjpegCameraSpec` with an explicit capture/sensor identity, seed,
frame count, dimensions, frame period, uncertainty, fragment cap and number of
warmup frames. Construct `VirtualClock` at the declared start; optional existing
clock skew and jitter remain available. Pass it and a `MjpegSourceBudget` backed
by the owner's `AtomicBool` cancellation flag to `generate_mjpeg_source`.

The result exposes immutable `packets()` and `frames()`. `frame_bytes(index)`
reassembles a complete original JPEG; the frame span binds its SHA-256,
conservative capture interval, packet range, and synthetic rectangle recipe.
`GeneratedMjpegSource::publish(plan, objects, ledger)` passes the same original
source packets to the existing root-last capture implementation. Delivery loss,
reordering, duplication and corruption are separate observations. An invalid
plan is refused before object or authority mutation. Subsequent storage failures
retain the existing publisher's semantics; root-last publication is not a promise
of all-or-nothing deletion of staged objects.

Repeated JPEG headers and other identical fragments share one content-addressed
object. The source manifest now names unique objects, while its ordered source
trace retains every packet's sequence, capture interval and digest. This fixes
the former duplicate-child refusal without erasing packet multiplicity.

## Scene, timing and resource contract

The scene is a background at luma 32 and, after warmup, a 16x16 rectangle at
luma 224. It advances eight pixels horizontally per frame, wrapping at the scene
boundary. Seed selects its starting phase and vertical row. Axes are multiples
of eight from 24 through 256 pixels. Each block is constant; quality-100 baseline
grayscale encoding uses the existing encoder. There is no second JPEG codec.

The complete canonical synthetic recipe is embedded in each frame's COM segment,
including capture/sensor identity, seed, frame ordinal, scene specification and
actual capture interval. Standard decoders may ignore COM metadata; they must
not silently promote it to authenticated camera timing or calibration.

The clock advances once per **frame**. Every fragment of that frame carries the
same conservative interval. It is never replaced with a transport arrival time
or collapsed to a point. Generation stages a clone of the clock and only updates
the caller after the complete session succeeds. Cancellation, insufficient work,
clock overflow or capacity refusal returns no partial generated source. Reserved
pixel budget is not refunded when work has already started.

Hard bounds are 4096 frames, 8,388,608 rendered pixels per session, 16 MiB of
compressed bytes, 64 KiB per complete JPEG, 65,536 source packets, and 4096 bytes
per packet. Caller work allowance may be smaller. Cancellation is polled per
rendered row and fragment and around each encoder call; one at-most-256x256
fixture encoding is the longest non-interruptible step. Store and manifest
limits can impose additional publication bounds.

## Verification and claim boundary

`cargo test -p fss-reference ingest::virtual_mjpeg` exercises native pixel
round trips, one-byte and multi-frame stream inputs, source-frame capture
mapping, deterministic replay, sensor/seed binding, decoded motion, dimension
limits, clock rollback, cancellation, pixel/packet limits, custody publication,
invalid-plan refusal and repeated-fragment manifests. The example also performs
native decode verification before output.

These tests were authored but not executed in the editing environment, which
had no Rust toolchain or `rch`. They require the repository's normal compilation,
formatting, lint and qualification runs before a passing qualification claim.
The fixtures exercise bytes, state and provenance; rectangles do not validate a
person detector, cross-camera calibration, deployment accuracy or alert safety.
