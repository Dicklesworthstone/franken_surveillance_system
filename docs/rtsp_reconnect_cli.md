# Bounded native RTSP reconnect capture

`fss-capture-rtsp reconnect` runs a finite, explicitly approved sequence of native
capture attempts. It reuses the existing AVC and HEVC capture, scoped Digest,
source-linked recording, archive publication and independent pin-journal owners.
It does not start subprocesses or introduce an alternate media path.

## Plan, inspect, approve

Use the ordinary `fss-capture-rtsp` options after the `reconnect` subcommand and add:

```text
--max-attempts 3 --retry-delay-ms 250 --retry-max-delay-ms 5000
```

Without `--approve`, planning performs no filesystem, clock, secret or network I/O.
The JSON preview enumerates every possible child capture plan, including its exact
peer, codec, original-retention policy, effective limits, source epoch and output
paths. Repeat exactly with the OUTER approval digest to execute. A child approval
cannot authorize the reconnect plan, and changing any child or retry limit changes
the outer approval. Ordinary single-attempt approval identities are unchanged.

`--root /owner/archive` and `--pins /independent/pins` are prefixes in this mode.
The actual first destinations are `/owner/archive.attempt-0001` and
`/independent/pins.attempt-0001`, then `...attempt-0002`, and so on. Parents must
already exist. Each native attempt exclusively creates new, separately protected
outputs; existing files, directories and aliases are refused. Earlier attempts
are never deleted, overwritten or automatically recovered.

## Reconnect boundaries

Every retry increments the owner generation, keeping the exact ingress, peer,
SSRC, selected payload and codec. Receive-clock and journal identities are derived
separately for each attempt; the native decode clock and archive namespace bind
those changes. A new native receiver starts fresh probation and IDR selection.
No packet, prediction state, timing baseline or source-continuity claim crosses
into the next attempt. A camera changing its SSRC still needs a new owner plan;
this command does not guess an alternative source or codec.

Only typed transient AVC connection I/O failures and actual AVC/HEVC source EOF
with settled storage admit another attempt. Connection refusal/reset/abort/timeout
must come from the native Connect operation, not a generic error string.
Authentication, credential/entropy failure, revocation, cancellation, protocol or
codec refusal, timing mismatch, exhausted work/deadline budgets, output failure
and storage failures stop the entire run. HEVC constructor errors currently stop;
they are not interpreted as transient based on their broad diagnostic label.

A candidate pin, unrecorded work receipt, pending window or source-only boundary
work, unpublished prepared recording, unindexed durable window, or unfinished
archive work blocks retry. A confirmed work pin alone is not permission to retry.
Preserve the native terminal JSONL row and perform explicit archive recovery.
Unsealed/unselected source omissions remain in the native terminal report; a retry
cannot turn them into retained footage or witnessed absence.

`--stop-after-pictures` is a **per-attempt** target. The first successful attempt
stops the run. Earlier partial captures are counted separately in
`durable_pictures_all_attempts`, never treated as one continuous recording.
After the last permitted failed attempt, the command exits unsuccessfully.
Backoff doubles after each retry and is capped; it cannot run after exhaustion,
failed output or cancellation. There is no unlimited watch or crash resume mode.

## Reporting, costs and identities

Native attempt rows keep `fss.rtsp_capture_cli.v1` unchanged. Outer control rows
use `fss.rtsp_reconnect_cli.v1`: `attempt_started`, `attempt_finished`, `backoff`
and `reconnect_terminal`. Attempt rows bind the outer approval, child approval,
ordinal and generation. Preserve both row types. Failure to flush a native
terminal row never authorizes another connection.

The preview sums all potential source-byte, archive-spool, native-report and
capture/drain lifetime ceilings and backoff allowances. The separate outer
control transcript has a 262,144-byte ceiling bound into its approval. These are
conservative per-attempt reservations, not a claim of physical RSS, whole-disk
usage or a hard wall-clock bound on a blocking output sink. Secret-file leases,
when configured, are freshly loaded and revalidated by each native attempt.

The canonical approval domain is `fss.rtsp_reconnect_cli_plan.v1` over policy,
control-report bound, backoff bounds and the ordered child approval digests.
`fss.rtsp_reconnect_receive_clock.v1` and `fss.rtsp_reconnect_journal.v1` each bind
the corresponding owner-provided base digest, zero-based attempt ordinal and
resulting generation. They never assert camera capture time.

Focused checks:

```sh
cargo test -p fss-cli --bin fss-capture-rtsp
```

Controller tests use deterministic effects to exercise policy transitions;
they are not a substitute for the native loopback capture/process contracts or
controlled-host qualification. This implementation was source-reviewed in an
offline editing environment; native execution and rustfmt were not available.
