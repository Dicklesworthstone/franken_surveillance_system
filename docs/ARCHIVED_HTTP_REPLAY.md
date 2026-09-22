# Exact archived HTTP/MJPEG replay

`fss_reference::ingest::http_replay::HttpWireReplay` reconstructs native
source-mapped JPEG frames after the acquisition process and its parser state are
gone. It consumes an independently retained `HttpWirePin` and the existing
`HttpWireArchive`/`LocalRootPublisher`. It does not open a network connection or
introduce a second source format, spool, splitter, model runtime, or event owner.

## Workflow

1. Use the existing HTTP wire prepare/publish protocol during acquisition. Keep the
   exact expected pin independently before publication; resolve a lost return using
   that pin rather than reacquiring or silently following a newer head.
2. Open the existing publisher and load `HttpWireArchive` with the exact scope,
   pin, independent limits, and current original-byte disclosure authority.
3. Construct `HttpWireReplay::new(&archive, pin, limits)`. Each `step` receives
   `HttpReplayAccess`: the read-only publisher, live disclosure/cancellation probe,
   storage work budget, and native framing budget. The first step re-verifies the
   complete exact prefix. Subsequent steps perform one native parse or bounded read.
4. On `FrameReady`, inspect the existing `HttpJpegFrame` and use `take_frame` with
   its exact ordinal and encoded hash. All JPEG-to-wire spans are freshly read and
   verified before transfer. The ordinary native decoder and RGB inference paths
   accept the reconstructed original JPEG. `http_rgb_exposure` gives the same source
   identity regardless of the replay read-buffer size.
5. Preserve terminal classification and use `retire` for every unfinished original
   buffer, entity, frame, HTTP remainder, MIME remainder, and observed end receipt.

A held frame backpressures all further source reads. A failed storage read leaves
its cursor unchanged; a native parser failure latches because a failed parser call
may already have accepted a prefix. Late cancellation preserves completed work.
Failed transfer, deletion, or corrupt source bytes never releases a different frame.

## Completion is not archive exhaustion

`Complete` requires both native MIME completion and length/chunk-delimited HTTP
completion, with no pinned trailing response bytes. `PrefixExhausted` is separate:
raw read roots contain no durable socket-EOF witness. A valid close-delimited
capture therefore remains partial at the HTTP layer even when its original live
session observed EOF. Truncated headers, chunks and MIME bodies also remain partial
when the stored prefix simply stops. No `finish()` call is fabricated at that point.

Replay does not assert sensor authentication, capture time, continuity beyond the
pin, absence of objects, trained-model quality, canonical event publication, or
present-day durability after its last verification. Source disclosure is a separate
live capability from permission to retain or view derived detections.

## Validation scope

`cargo test -p fss-reference --test http_wire_replay` contains native-loopback,
real-filesystem and cold-restart contracts for length/chunked equivalence, exact
exposure/source-map identity under rechunking, close/truncated prefixes, stale
pins, backpressure, corruption, cancellation, parser-budget latching, frame ceilings,
and trailing data. Rust compilation, this test target, rustfmt, Clippy and native
qualification were not run in the editing environment: it has no Rust toolchain.
No qualification gate or release claim is advanced by these source changes.
