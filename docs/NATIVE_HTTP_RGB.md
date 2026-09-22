# Native HTTP to RGB neural trajectories and zones

`fss_reference::ingest::http_camera::rgb::HttpRgbCapture` connects the existing
native HTTP acquisition owner to the existing RGB JPEG/neural/detector/tracking/
zone pipeline. The original HTTP/MIME parsers, RGB decoder, frozen model executor,
head projection, assignment and zone engines are reused, not reimplemented.

## Entry points and ownership

Create an owner-approved `HttpCamera` and a `RgbJpegZonePipeline` over the exact
frozen model/head and selected-class `RgbZoneTracker`, then `attach` them before
acquisition starts. A refused attachment returns both unchanged owners. No new
thread, runtime, connection, authentication, model activation or retry is hidden
in attachment.

`step` exposes the existing exact `WireReady` custody boundary. Save or otherwise
explicitly account for those original bytes before `acknowledge_wire`. The
acknowledgement is responsibility transfer, **not a durability proof**. Existing
`http_archive::HttpWireArchive` publication remains available against the borrowed
`pending_wire()`; original HTTP headers require their own retention authority.

`AwaitingContext` exposes the complete original `HttpJpegFrame`. Compute its
`http_rgb_exposure` and bind that exact handle into an independent
`RgbFrameAdmission`. Supply the expected full response head and original part
ordinal, explicit component interpretation, capture interval, camera/clock/domain/
calibration generations, original mask, and availability evidence. `analyze`
accepts no caller JPEG or boxes: its bytes come only from that retained part.

The exposure handle binds the response/MIME identities and full JPEG-to-wire map.
It identifies an acquisition record, not authenticated camera identity or proof
that physically independent exposures occurred. Equal JPEG bytes in different
parts have different handles. HTTP admission/receive time remains distinct from
camera capture time. `Available` is an owner declaration, not a neural confidence
threshold or a health finding; this path does not replace independent screening.

## Failures and backpressure

Read `processing_result()` and `phase()`, not just the outer Result. Every native
accepted stage is recorded before post-work source-authority revalidation. A
revocation can therefore return an error **after** inference or tracking accepted;
all of that work and the mapped JPEG remain owned and recoverable.

`AnalysisRefused(Ready)` permits a corrected same-frame retry. Other accepted
phases require `resume`, which accepts no decoder, JPEG, model replacement, mask
or revised capture declaration. Projection, tracking, zone and output-copy
pressure preserve the completed upstream stage. No camera read advances while
accepted computation or an untaken complete result is pending. All budgets and
cancellation owners are caller supplied; no allowance automatically refills.

`ResultReady` supplies an opaque `HttpRgbReceipt` over the source and exact
inference/detection/tracking/zone roots. `take_result` requires that complete key
and live release authority, then transfers **both** the original mapped JPEG and
complete owned `RgbZoneCompletion`. Later frames cannot overwrite old events.
A separate slot preserves the neural result if final `ReleaseFrame` is refused
after the processor transferred it. No fallible allocation follows either
transfer. `retire` closes acquisition and returns all remaining original bytes,
parser state, unfinished tensors/permissions, completed results and error status.
A pending temporal-zone obligation remains in the separately owned tracker.

## Compatibility and bounds

Only a child-module declaration changes the original HTTP camera source. Existing
HOG and standalone RGB APIs, protocol parsers, durable formats, model imports,
source custody and event/alert policies are unchanged. The new hashes are local
reference derivation identities, not a new canonical event or storage dialect.
Linking charges `512 + 128 * source_span_count` units plus a 256-unit completion
reservation before native processing. It uses bounded stack scratch; there is no
wrapper image/tensor copy. Original camera/session and neural/temporal limits
still apply to their full inputs; nothing is top-k truncated to fit.

This is an explicitly approved **plaintext HTTP MJPEG** composition, not HTTPS,
UVC, ONVIF, RTSP video decoding, a pretrained neural detector, physical calibration,
or canonical event/alert publication. No real operator camera is contacted by the
authoring work. Numerical JPEG/convolution fixtures are not trained model weights.

## Durable raw-read custody before parsing

The optional `rgb::custody` integration turns the existing raw-read barrier into
**publish-before-acknowledge**. Call `prepare_wire_custody` against the explicit
`HttpWireArchive` and independently retain its `HttpRgbWirePlan::expected_pin()`
before performing storage I/O. The plan binds the unchanged original read and
exact archive scope/root; it is not a storage permission or a durability claim.

`retain_wire` rehashes the same pending read and checks the same expected root,
then invokes the existing archive and `LocalRootPublisher` under caller-owned
storage authority/cancellation and work bounds. It acknowledges the camera only
after the original archive returns a durable root-last publication. Until then,
no bytes from that raw read are parsed and no next network read replaces them.
No new disk format, alternate ledger, spool, background flush or repair exists.

An outer refusal leaves the read unacknowledged. A storage failure may still have
staged/visible work or an unknown outcome; use the original publisher's recovery
contract and independently retained expected pin. In particular, loss after root
rename is resolved by reopening and verifying that exact pin, then retrying the
same pending read. Existing publication returns `AlreadyPublished`; neither a
second source record nor another GET is manufactured. Earlier cuts containing
unresolved temporary roots still require the existing explicit recovery path.

Once storage succeeds, `HttpRgbWireCommit` always retains the publication and a
**separate** camera acknowledgement result. Late camera revocation can therefore
return durable publication plus denied acknowledgement without hiding the disk
write or releasing the original bytes. Explicit camera retirement still returns
the unacknowledged read. The caller may inspect the independently stored prefix
through existing cold read/verification APIs. Completed neural output remains
separately derived; durable source does not certify model accuracy or an event.

Manual `acknowledge_wire` remains available for other explicit custody owners;
using it alone makes no durability claim. Native RGB result publication and
canonical event/alert delivery remain separate integrations.

## Verification and handoff

Scope: the WP-090 perception/acquisition integration highlighted by the project
brief. Source anchor: `ac9176e7ee94d0ba9083d3ca620b8f01621527c8`; the comprehensive
plan and bead graph were read. No program bead or qualification gate is closed.

Fourteen authored RGB capture tests exercise actual loopback sockets and the existing
JPEG/neural fixture, source reconstruction, entry/dwell/exit, masks and temporal
uncertainty, original-read acknowledgement, backpressure, stale result keys,
retry, late authority refusal, and lossless retirement. They require the native
Rust toolchain and have **NOT been compiled or executed in the authoring sandbox**;
cargo, rustc, rustfmt and rch are unavailable. Independent Python checks cover
HTTP template/framing and a finite ownership model, not the compiled Rust path.
Run `cargo test -p fss-reference --test http_rgb_capture`, existing HTTP/RGB test
lanes, formatting, Clippy and native qualification before upgrading any claim.

Eight further authored custody tests combine native loopback reads with real
filesystem publication: cold source restoration and frame re-verification, every
root-publication crash cut, exact lost-ack recovery, late acknowledgement revocation,
cancellation/work refusal, changed scope, stale reads and pre-publication denial.
All **22 Rust tests remain uncompiled and unexecuted here**. The updated helper
still uses one bounded test thread, and all original 14 tests remain unchanged.
Run `cargo test -p fss-reference --test http_rgb_custody` as well. No source/model/
capability registry, bead, release or device-qualification claim is promoted.
