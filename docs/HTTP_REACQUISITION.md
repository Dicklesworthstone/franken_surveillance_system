# Bounded native HTTP reacquisition

Status: implemented reference APIs; **not compiled, natively tested or qualified in the
implementation session**. The session environment has no `cargo`, `rustc` or `rustfmt`.
No real-camera, timing, detection-quality, coverage or production-readiness claim is made.

## What is implemented

`fss_reference::ingest::http_reconnect::HttpReconnect` composes the existing native
`HttpCamera` over a frozen list of at most 32 independently selected connections.
`fss_reference::ingest::http_reconnect_recording::HttpReconnectRecording` adds the existing
root-last `HttpWireArchive`: original bytes must become durable before parsing or changing
source generations. Both execute native TCP acquisition; neither is just a retry planner.

Each slot reserves an exact route, a strictly increasing stream generation and independent
connection bounds. Every slot names the same literal peer, Host mapping, request target and
source identity. No reconnect invents a generation or permits endpoint fallback. Fresh
connections send a complete new GET with a fresh response-offset space; they do not resend a
possibly escaped suffix or pretend to resume the preceding response.

The supervisor checks the sum of every slot's wire/entity/chunk/frame/I/O/connect-time
reservation before starting. Unused reservations are not recycled. One framing budget and
one absolute network deadline span all connections. The durable owner additionally uses one
source/publication/verification work budget and one poll ceiling across the complete plan.
Backoff grows exponentially to the owner's cap; readiness waits and sleeps belong to the
external runtime owner. No hidden worker, asynchronous runtime, unbounded loop or dependency
was added.

## Durable caller loop

Construct `HttpReconnectRecordingPlan` with explicit `HttpReconnectRecordingSlot`s,
`HttpReconnectPolicy`, `source_work`, `maximum_steps` and `deadline_ns`. Each source's
`http.wire_bytes` must fit its `HttpArchiveLimits.maximum_bytes` (at most 256 MiB).
`HttpReconnectRecording::new(plan, now_ns)` validates the entire plan without I/O. Supply
the existing `LocalRootPublisher` and an independent `HttpRecordingAccess` on operations.
The network authority must independently check actual elapsed time, route, source generation,
revocation and cancellation. The storage authority covers **original headers and media**;
route construction or a plan is not a grant.

Handle every `poll` result, without discarding a failure or treating it as EOF:

- `Connected`, `Advanced`, `Pending`, `Waiting`: drive bounded progress under the external
  owner. Waiting carries an earliest admission time, not permission to skip authority checks.
- `WirePrepared(plan)`: independently preserve `plan.expected_pin()` and `plan.wire()`, then
  call `commit_wire` with the exact plan. An outer error retains the source and prepared key;
  storage may contain staged/visible work. Recover the same publisher and exact key, never
  reacquire the source. A successful publication is returned separately from its camera ACK;
  a late ACK denial cannot hide the successful disk write.
- `FrameReady(key)`: `take_frame` rehashes the original source and transfers that exact
  compressed part under current authority. It decodes no pixels. Downstream pixel consumers
  still require the current sensor privacy projection.
- `BoundaryReady(boundary)`: preserve the exact original-prefix pin and the source's terminal
  observation/discontinuity. `release_boundary` re-verifies all required roots and bytes
  after any external delay, then transfers the complete original retirement. No next
  connection is admitted before this release. An occupied next-generation namespace is a
  recovery task and is refused before TCP.
- `Stopped`: no further connections are scheduled. Inspect the retained boundary's outcome
  and stop reason; stopping is not a claim of capture continuity or scene absence.

A post-read revocation can occur before the normal read-publication barrier is reached.
The durable owner preserves that last raw read, publishes it only under independent current
storage authority, and never acknowledges or parses the retired source. Revocation does not
become a reason to retry with a fresh generation. When custody cannot be completed, `retire`
transfers all pending bytes, parser remainders, prepared pins, archive indexes and boundaries
without network I/O or silent repair.

## Failure policy and limits

Only selected connect/read/write transport failures, zero-byte request writes, and explicit
HTTP/MIME truncation are retryable. Authentication/status responses (including 503), malformed
framing, resource exhaustion, peer mismatch, cancellation, revocation and other authorization
failures are terminal. Starting another generation after a genuinely complete HTTP/MIME
response requires `reconnect_after_complete: true`.

The low-level supervisor's handoff ACK accepts ownership responsibility; it is **not** durable
custody proof. Use the durable recording owner when persistence before parse/reconnect is
required. A recording boundary preserves real native completion/failure and a verified source
prefix; it does not publish the existing `HttpCompletionPin` completion family. Nor is the
boundary itself a durable cross-generation journal. Preserve all pins independently and use
existing exact-pin archive recovery after a crash; automatic cold restart of acquisition is
not implemented. The `fss-capture` CLI remains the existing single-connection interface.

Seventeen Rust regression tests were added across these two modules. They cover plan bounds,
identity/generation drift, exact handoff barriers, non-recycled slots, deadlines/backoff,
fail-closed retry classification, actual loopback truncation/reconnection, publication refusal,
late ACK revocation, original-read preservation after revocation, cold exact-prefix recovery,
occupied-generation refusal, and shared work/poll limits. **These tests are written but were
not executed in this session.** On the pinned repository toolchain, focused commands are:

```sh
cargo test -p fss-reference http_reconnect
cargo fmt --all -- --check
cargo clippy -p fss-reference --all-targets -- -D warnings
```

These commands are not a replacement for `scripts/qualify.sh` and the repository's retained
native qualification lanes. No requirement, bead, adapter or release qualification is promoted
by the presence of these implementations or tests.

## CLI frame-target postcondition (2026-10-11)

The separate `fss-capture-reconnect` CLI accepts `--stop-after-frames N`. With that
option, success requires the requested count across all approved generations, including
successful optional decode/privacy processing and output of the last frame row. Without
that option, a final complete response remains a successful completion. Reaching a count
is not EOF, a durable completion root, capture continuity, or certified scene coverage.

Previously the CLI could receive one frame for a two-frame request, reach a genuinely
complete response, and emit `request_satisfied: true`. Completion now checks the request
postcondition before producing the final report or exit result. A complete response below
the requested count produces `status: refused`, `request_satisfied: false`, and the existing
`ERR-CAPTURE-RECONNECT-LIMIT-001` identity with an explicit requested/retained-count reason.
When a count was requested, the final report also includes `requested_frames` and
`frames_shortfall`. The latter counts missing source-verified frames only: zero does not
mean that decoding, output, or the overall request succeeded. Consumers must still inspect
`request_satisfied` and the error. Existing source, authority, storage, decode and output
failures keep their original identity rather than being replaced by a count failure.

This is a fail-closed exit-behavior correction for explicit count requests. It does not
change approval bytes, the wire/history formats, capability scope, connection policy,
privacy policy or budgets. In particular, a shortfall does NOT permit another connection
when `--after-complete no` stopped acquisition, refill an exhausted generation list, or
retry a denied source. Native complete/failure observations and all retained prefix and
history pins remain intact even when the overall request is refused. The constant-time
postcondition and two optional counters perform no I/O and retain no additional media.

Four added tests in `driver_history_tests.rs` cover the completion truth table (including
zero, overshoot and integer boundaries), six early-EOF/exhausted-slot/truncation cases
across ordinary and durable-history modes, exact-count stopping without a third GET, and
HTTP denial without failure relabeling. The shortfall cases reopen and verify the exact
saved durable history. Existing tests were not removed or weakened.

Validation boundary for this change: base files were matched byte-for-byte to GitHub blob
identities at `cf8f1751aa898ad1277c055fed36673a076a2b0c`; the patch was checked for whitespace
errors and reviewed against those files. **Rust compilation, tests, rustfmt, Clippy and
native qualification were not run: the editing environment has no Rust toolchain or rch.**
Run the following on the pinned toolchain with the repository's dependency closure:

```sh
cargo test -p fss-cli --bin fss-capture-reconnect
cargo test -p fss-reference http_reconnect
cargo fmt --all -- --check
cargo clippy -p fss-cli --all-targets -- -D warnings
```

This change does not close the recorded-RTP reordering work in `fss-2h5zq.30`, promote a
bead or release gate, or supply a native proof bundle. The pending task is to execute the
above regressions and the required qualification lanes; preserve failures as evidence.
