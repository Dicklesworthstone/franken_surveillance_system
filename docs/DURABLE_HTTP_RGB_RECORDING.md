# Durable native HTTP RGB recording

`fss_reference::ingest::http_rgb_recording::HttpRgbRecording` joins the existing
native HTTP camera, original-wire archive, RGB neural detector, anonymous tracker
and image-zone processor under one exclusive owner. It closes the responsibility-only
acknowledgement escape of manually composed `HttpRgbCapture` operations: callers
cannot release raw reads, replace the archive, or advance the camera independently.
The numerical engines, source formats, privacy-mask rules and original-root publication
format are unchanged. This is a library integration boundary, not an always-on daemon.

## Drive one bounded connection

Build the existing `HttpCamera` with an exact route and explicit live camera authority,
and attach a ready `RgbJpegZonePipeline` with a frozen model, head and temporal owner.
Pass the resulting fresh `HttpRgbCapture`, `LocalRootPublisher`, `HttpWireScope`,
whole-recording `HttpCheckLimits`, and independent camera/storage access probes to
`HttpRgbRecording::attach`. Attachment checks an empty source namespace before any
HTTP request is sent. An existing recorded generation is a recovery task, not a new
connection. Failure returns the entire capture owner, including its TCP socket.

Drive `poll` from the authorized outer event loop:

* `Pending` means wait; `Advanced` means one bounded native operation progressed.
* `WirePrepared(plan)` means independently save `plan.expected_pin()`, then call
  `commit_wire` with that exact plan. Storage is root-last and durable before the
  camera's parse barrier can be released. Inspect **both** publication and camera
  acknowledgement; a late revocation does not undo or hide a successful disk write.
* `Analysis(AwaitingContext)` means supply the actual mapped frame's independently
  declared capture/availability context to `analyze`. The original frame is reverified
  against current retained source before native decoding or model execution. The
  named sensor's current retained privacy mask is resolved by the existing RGB owner.
* Pending/refused analysis retains accepted tensors and temporal state. Use `resume`
  for unfinished stages only, or `retire`; never submit a replacement JPEG or reset the
  model to conceal a refusal. Current original custody is checked again on resume.
* `Analysis(ResultReady(receipt))` keeps the original frame and complete neural/track/
  zone result held until `take_result` revalidates source custody and transfers both
  under that exact receipt. No subsequent frame can displace an untransferred result.
* `CompletionPrepared(pin)` requires actual native HTTP **and** MIME termination,
  all raw reads accounted for and every perception result transferred. Independently
  save the pin and call `commit_completion`. The existing terminal publisher verifies
  the complete original-read closure. Exact publication retries are idempotent.

`HttpRecordingAccess` is reused: camera and original-byte storage/disclosure authority
are independent. `capture()` exposes read-only phase, pending frame, accepted results,
work errors and source counts, not mutable acknowledgement authority. These historical
references do not grant fresh disclosure permission. Original headers/media remain
unmasked custody; only the named sensor's correctly masked pixels enter perception.

## Cuts, bounds and retirement

The original archive and HTTP/MIME work allowances accumulate across the whole session.
Frame and poll limits are refusals, never fabricated EOF or successful completion.
Neural/projection/temporal budgets remain explicitly caller-owned; the wrapper does
not refill them on another frame or retry. `work()` separates consumed source/framing
work and transferred results from the native camera's frame count.

After a storage crash cut, retain the same recording and expected plan, reopen the
poisoned publisher with its existing recovery contract, and retry that exact plan.
There is no mutable archive escape or hidden reconnect. `retire` closes without another
request and returns the native source remainder, accepted processor/held output, archive
inventory, pending read plan, prepared terminal record and successful completion pin.
No fallible optional operation follows a successful result transfer or durable terminal
publication, so cancellation cannot retroactively turn those successes into errors.

The completion pin certifies locally retained original input and native termination,
**not durable perception output, scene coverage, detector accuracy or alert authority**.
Transferred results still need their existing RGB evidence/archive owner for durable
numerical replay. A caller-supplied timestamp is not authenticated capture time.
No new authoritative event or effect is automatically published.

## Validation status

`cargo test -p fss-reference --test http_rgb_recording` exercises real single-thread
loopback input and the existing native neural fixtures. It covers both fixed-length
and chunked responses, read/result backpressure, observed zone transition, exact
terminal publication and cold source recovery, all four original-root crash cuts,
storage cancellation, successful-storage/failed-camera acknowledgement, and accepted
result retention after delivery revocation. These are plumbing tests, not model-quality
or incident-recall qualification.

**Rust compilation and these native tests have not been run in the implementation
environment: no Rust toolchain is installed.** No release or production gate is promoted.
