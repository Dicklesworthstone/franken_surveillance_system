# Native HTTP completion survives restart

`fss_reference::ingest::http_replay::completion` closes a recovery gap for
close-delimited MJPEG. Retained read bytes do not prove that a socket returned EOF.
The existing prefix-only replay still reports `PrefixExhausted` rather than guessing.

## Record the actual ending

After the native `HttpCamera` has completed both HTTP and MIME and its last frame
has been transferred, call `PreparedHttpCompletion::from_camera`. This API accepts
the opaque source owner and exact `HttpWireArchive`; it accepts no caller-authored
EOF boolean, HTTP end, or frame count. The same camera getter is available from a
completed `HttpRgbCapture` after its last analysis result has been taken.

Keep `plan.pin()` independently before calling `publish`. Publication re-verifies
every original root and byte, stages canonical metadata, and publishes the complete
object graph through the existing `LocalRootPublisher`. Its direct children include
EVERY original-read root, not just the last link of an untraversed predecessor chain.
One immutable terminal slot per source scope refuses conflicting endings. Exact
retries reuse the same root. A lost acknowledgement after root rename is resolved
by reopening and loading the independently retained pin. No new journal or storage
backend is introduced; existing crash, cancellation, tombstone and repair rules apply.

## Finish cold replay explicitly

Load `VerifiedHttpCompletion` against the exact retained archive and completion pin.
Drive the ordinary `HttpWireReplay`, consuming each complete frame. On
`PrefixExhausted`, call `finish_completed` with the loaded witness and current
`HttpReplayAccess`. This rechecks the completion graph and original source NOW,
then permits the existing HTTP/MIME engines to use the recorded native EOF.
If EOF completes a final MIME delimiter lacking CRLF, its last frame is returned as
`FrameReady` and must be consumed before `Complete`. Capture, source-map and
`http_rgb_exposure` identities are unchanged. Explicit length/chunk termination
records are checked against the ordinary replay's exact HTTP/frame accounting.

A parser failure during finalization latches, with consumed state retained. Source
corruption, a stale pin, exhausted work or current access refusal never manufactures
a successful ending. A completed in-memory parse survives late cancellation, while
fresh source verification remains mandatory for transferring its original frame.

## Trust and compatibility

The new reference metadata tag is `fss.http_camera_completion.v1`; the enclosing
object family is `http_camera_completion_v1`. Metadata uses the existing bounded
canonical encoder/decoder and names the exact source scope/head/read count/byte
count, original HTTP head identities and framing, HTTP terminal accounting, MIME
frame count and source-owner EOF observation. Unknown tags, trailing bytes,
noncanonical enum values, mismatched roots and extra/missing children are refused.
Existing wire archives and prefix replay remain unchanged and readable.

The independently pinned root is a trusted archive-writer statement, NOT a
signature or an independently authenticated camera. Raw access able to forge both
archive metadata and its independently selected pin remains outside this reference
type-level threat boundary. Close-delimited EOF plus valid MIME proves framing
completion, not that a physical scene was continuously observed, all expected
exposures arrived, a detector is accurate, or an effect is authorized.

This advances the reference replay/source-lineage work in FSS-019/FSS-120/FSS-135;
it does not close their full qualification gates. Nine native-loopback/filesystem
regressions are in `crates/fss-reference/tests/http_completion.rs`. Rust compilation,
those tests, rustfmt and Clippy were NOT RUN in this editing environment because a
Rust toolchain is unavailable. Source and independent framing-model checks are not
substitutes for the repository's native qualification lanes.
