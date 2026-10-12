# Native recording-progress supervision

The bounded RTSP reconnect command can supervise AVC or HEVC recording progress:

```text
fss-capture-rtsp reconnect [ordinary capture options] \
  --max-attempts 3 --retry-delay-ms 250 --retry-max-delay-ms 5000 \
  --progress-timeout-ms 5000
```

Run without `--approve` first, inspect the complete preview, and repeat with its
**outer** approval. Use `--max-attempts 1` to supervise without reconnecting.
`--progress-timeout-ms` is optional and accepts 1 through 600000 milliseconds.
Omitting it preserves the existing reconnect approval bytes and behavior. Ordinary
single-attempt capture is unchanged and does not accept this new option.

## What is measured

The observer arms when the native RTSP owner reaches `Playing`. Only an increase
in the native collector's accepted picture count renews its allowance. Control
replies, TCP bytes, RTCP, duplicates and pictures skipped while waiting for an IDR
are not recording progress. Accepted pictures are source-linked native assembly
results, not proof that pixels decode or that the archive is already durable.

Elapsed owner-monotonic time is charged while acquisition is enabled. Storage
backpressure pauses this allowance without refilling it. Sampling before and after
each bounded native step preserves the remaining interval across storage pauses.
Protocol, fragment, collection, storage-pause, live-lease and final-drain deadlines
remain independent and are never extended by this observer. A stalled storage
operation remains a storage/deadline failure, not permission to reconnect.

Expiry is latched before a late picture-counter increase can renew the timer.
Each newly authorized attempt has an independent observer, source generation,
receive/decode clocks, archive namespace and protected journal. Earlier attempts
are neither overwritten nor presented as continuous footage.

This is an **owner-observed recording-progress limit**, not a physical camera
outage diagnosis. Local processing, output and scheduling time while acquisition
is active can contribute. It supplies no camera capture time, source EOF, decoding,
physical coverage, detection recall or absence certificate. The total excluded
pause time in a stall receipt is cumulative for that attempt.

## Safe stop and retry

At expiry the driver revalidates its live network grant and current credential
lease. A held authentication challenge, authority withdrawal, cancellation or
expired lease stops the run rather than becoming a transient media condition.
No new socket readiness is enabled after the stall decision. The existing native
owner attempts to seal only already-collected pictures, close input, and finish
its ordinary independently journaled checkpoint, window and catalog publications.
An unfinished HEVC picture still requires real boundary evidence; timeout cannot
manufacture it, just as it cannot manufacture an AVC fragment tail.

The attempt reports `ERR-CAPTURE-RTSP-PROGRESS-001` / `recording_progress_stalled`
only after native **OwnerStopped** finalization, with every collected picture
durable and every durable window indexed. The separately approved finite
controller can then classify `recording_progress_stalled` as retryable. Its normal
attempt limit, capped backoff, fresh destinations and recovery vetoes still apply.
An unsupervised controller refuses this new retry reason.

Pending candidate pins, uncertain acknowledgements, pending windows, unindexed
windows or unpublished prepared work block another connection. A failure while
sealing, authenticating, publishing, draining or flushing output overrides the
stall result and remains a failure. In particular, buffered/unoffered native work
that prevents a safe seal can terminate with its original refusal and explicit
omissions; the command does not promise recovery from every stalled pipeline.
There is no automatic archive repair, crash resume or unlimited watch mode.

## Reports and verification

Supervised attempts add `recording_supervision` and, on expiry,
`recording_stalled` rows to the existing native JSONL transcript. Both bind the
verified outer approval, exact policy and timeout. The stall row records owner
observation time, last observed progress time, preceding picture count, active
waiting time and excluded pause time. It explicitly does **not** claim source EOF,
camera offline, archive drain or certifiable absence. Preserve the following native
terminal row: only that later row accounts for the attempted drain and its actual
result. A failed or partial output row never authorizes a successor connection.

The outer preview binds this optional policy and timeout in the existing
`fss.rtsp_reconnect_cli_plan.v1` domain with a distinct supervised policy tag.
Child capture approvals and recording identities are unchanged: supervision adds
an approved early owner-stop rule, not a new codec, capture-time assertion or
retention policy. All original per-attempt byte, work and lifetime ceilings apply.

Focused native checks:

```sh
cargo test -p fss-cli --bin fss-capture-rtsp \
  --test capture_rtsp_reconnect_cli --test capture_rtsp_cli
```

The new pure observer and controller contracts cover startup, exact/late expiry,
storage pauses, fresh attempts, clock/count regression, maximum timestamps,
approval isolation and recovery/output vetoes. Source review and content checks
are not compilation or test execution. This editing environment could not run
Rust tooling; native execution and controlled-host qualification remain required.
