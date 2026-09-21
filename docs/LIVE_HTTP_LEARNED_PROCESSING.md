# Live HTTP MJPEG to learned trajectories and zone observations

`fss_reference::ingest::http_camera::learned::HttpHogCapture` connects the native
`HttpCamera` acquisition owner to the existing `JpegHogPipeline`. It owns both,
not another detector, association algorithm, event state machine or storage log.
The first-party `fss-geometry` and `fss-twin` dependencies were already admitted by
the RGB trajectory integration; this composition adds no dependency or runtime.

The complete callable path is:

```text
exact authorized TCP peer -> HTTP/MIME framing -> exact JPEG-to-wire spans
  -> independently supplied capture/mask/calibration context
  -> native JPEG decoding and rectification -> independent image health
  -> explicitly loaded HOG coefficients -> original tracking/zone pipeline
  -> source-linked completion -> explicit result acknowledgement
```

This is bounded live input and reference learned-event processing, not a claim of
real-camera qualification, modern detector accuracy, canonical event publication,
alert delivery or a complete Asupersync production service. The pretrained model
is explicitly selected with `load_opencv_people_candidate`, as documented in
`PRETRAINED_HOG_CANDIDATE.md`; no model is selected/downloaded or activated here.

## Ownership progression

Attach two fresh owners with `HttpHogCapture::attach`. The camera must not yet
have sent or received source bytes and the processor must be awaiting its first
image. A rejected attachment returns both original owners rather than silently
closing the socket or dropping a pending image. The camera remains available only
through immutable access: callers cannot bypass the combined backpressure gate.

`step` advances at most one underlying socket/framing operation. `WireReady`
requires saving/handling the exact raw read before `acknowledge_wire`, exactly as
in `NATIVE_HTTP_CAMERA.md`. An acknowledgement accepts a custody obligation; it
does not prove that a storage service retained the bytes. Transfer/MIME headers
may be sensitive and are never printed by the library's Debug implementations.

`AwaitingContext` means a complete mapped JPEG is available. Supply an
`HttpFrameContext` naming the expected HTTP head, exact encoded hash, independent
exposure/camera/capture-clock interval, permission mask and calibration/image mode.
The screening sequence must equal the original MIME ordinal, and its generation
must match the original wire stream. The existing image and health APIs check the
remaining source, mask, calibration, receive-clock and episode constraints.

**An arrival timestamp is not a camera capture timestamp.** No capture interval is
constructed from socket reads, MIME ordinals or uninterpreted vendor header text.
A deployment lacking admitted capture-time evidence must resolve that separately;
this library does not manufacture timing precision to obtain trajectory events.
The caller is also responsible for binding supplied context to the actual device.

`analyze` runs the actual borrowed JPEG through the existing image processor. An
outer image error leaves the original frame intact and permits an explicitly
corrected retry before source acceptance. Once any image is accepted, another
`analyze` call is refused: only `resume` may continue its unfinished stages. A
complete scan is not rerun to recover a tracking budget failure, and an accepted
tracking update is never replayed to recover a zone budget failure.

`AnalysisPending` and `ResultReady` both keep the frame in the camera owner.
Neither state permits another source read or another frame to overwrite the
current image. After handling the source, health, scan, track and zone reports,
call `acknowledge_result` with the exact opaque `HttpHogCompletion`. It transfers
the original mapped frame and opens the input gate. No failure can occur after
that original frame leaves the source owner. A stale completion cannot release a
new frame, and acknowledgement does not implicitly publish a ledger event,
acknowledge semantic custody to the screening monitor or authorize an alert.

## Receipts, work and failure boundaries

A completion binds the original response identity, framing mode, MIME ranges and
header hashes, every JPEG-to-wire span and the four existing completed computation
roots. Fragmenting the same wire stream differently does not make an independent
image or change the complete source mapping. Different transfer wrappers remain
different source records even when they contain the same JPEG; the underlying
model results are not misrepresented as independently corroborated observations.

Separate finite budgets cover decoding, rectification/source linking, foreground,
health, inference and downstream processing. All wrapper hashing is reserved
before the mutation-bearing processor call. Failed work remains charged; nothing
refills per frame, scale, retry, or wait. Share the owner's cancellation flag
across the supplied budgets. Link-budget failure before resume leaves the accepted
image/scan/trajectory intact and does not require repeating prior stages.

The same live authority checks every source operation, analysis/resume and result
release. Even a revocation detected just after successful analysis preserves that
exact completed or pending result before the camera is fenced. `retire` transfers
both original source recovery objects and the existing resumable processor, along
with current completion/refusal information. It does not create another exposure,
reconnect, retry a request, replace a generation, or imply durable storage.

`analysis()` exposes only the currently accepted frame's processor, never the
previous frame as current while a new frame is acquiring or awaiting context.
`last_acknowledged()` is explicitly historical. `poll_health` remains available
under model pressure and does not read from the socket. Successful whole-response
HTTP/MIME termination is exposed separately from an individual frame's successful
analysis; neither one supplies physical coverage or negative scene evidence.

## Verification targets

```sh
cargo test -p fss-reference ingest::http_camera::tests
cargo test -p fss-reference ingest::http_camera::tests::learned
```

Thirteen additional Rust contracts exercise actual pretrained coefficients, native
JPEG/rectification/health, original tracking/zone reports, all downstream budget
cut classes, source-context mismatch, image retry, post-analysis revocation,
stale or denied result release, fragment-invariant lineage, live watchdog polling,
attachment refusal, and real loopback TCP through the learned path. The tiny
procedural codec fixture is upsampled only to exercise the model's input shape;
it is not a person, a detection-quality corpus or evidence of added source detail.

These Rust tests, compilation, rustfmt and Clippy were not runnable in the
authoring sandbox because no Rust toolchain was available. Lexical and exact
source/hash checks are supplementary. No acceptance gate or bead is closed.

The live socket abstraction preserves `Send`, so the camera and compound learned
owner can move into an owned runtime task without detaching the connection or
reconstructing state. Two handoff contracts move an unacknowledged raw read and
an accepted-but-pending learned image between joined threads, respectively. The
moved owner keeps the same source bytes, counters and image receipt and resumes
without another network read. This is a task-ownership/type contract, not a claim
that an Asupersync service or a production scheduler has been implemented.
