# Source-first RTSP capture (bounded reference mode)

`fss-capture-rtsp retain-source` explicitly retains complete original RTP/RTCP
interleaved datagrams before the next capture poll. It works with the existing
AVC and HEVC single-session recording paths. A datagram need not complete a
picture: sequence-probation packets, duplicates, incomplete codec fragments and
malformed packets can acquire source custody without becoming recordings.

## Preview and approval

Use the ordinary single-capture arguments, prefixed with `retain-source`, and add:

```text
--source-root /absolute/new/source-directory
--source-retention-evidence sha256:<owner-retention-decision-digest>
--max-datagrams 8192
--source-storage-bytes 268435456
--source-work 1000000000
```

Without `--approve`, the command emits a pure preview: it does not inspect/create
paths, open a camera or read credentials. Execute the same arguments with the
**top-level** preview `approval`. The nested `capture_plan.approval` is not valid
for this mode. The outer approval binds the ordinary capture plan plus the source
root, exact source scope, retention decision, spool limits and total source work.
Changing any of these requires a new approval.

The source directory, recording archive and independent pin journal must all be
new, nonnested and disjoint. Existing parent aliases are resolved before creating
any archive or connecting. The source directory is separate from credentials.
Omitting this mode preserves the original capture behavior and approval identity;
`--retain-originals yes` alone does not grant this additional source retention.

This is **unencrypted** local custody. The explicit retention decision must cover
both configured RTP and RTCP channels, including malformed and nonselected input.
A digest identifies the decision; it is not an independently authenticated grant.
Current route, credential, cancellation and time authority are still checked at
source publication boundaries. No control response, request, authentication
challenge, raw TCP chunk or partial interleaved datagram is persisted by this mode.
RTCP and camera-supplied media payloads can themselves contain sensitive metadata.

## Durable source is not a recording

After source-first, root-last publication and local synchronization, the command
emits `datagram_durable`. Its `prefix` contains the exact source scope, chained
head, datagram count and payload-byte count. Each record includes the original
parser completion time, channel and payload digest. It precedes subsequent media
progress; a later `window_durable` has its own recording meaning and independent
pin/work barriers. A failed publication or output delivery stops capture, never
silently continuing with an unretained source gap.

Preserve the pure preview, exact capture arguments, complete JSONL receipts and
all three stores. The terminal `datagram_source` reports the acknowledged prefix,
an unacknowledged candidate when applicable and consumed/remaining source work.
It never asserts that all TCP input was retained. A durable-source receipt does
not assert a picture, camera timestamp, scene continuity, remote EOF or completed
capture. The original full-wire omission and the separate RTP/RTCP custody remain
distinct in terminal reporting.

## Recovery after process loss

A process killed **after** `datagram_durable` requires no Drop handler or final
recording window to retain that prefix. Reopen its source store with
`LocalRootPublisher` and call `DatagramArchive::recover` using the original
`DatagramScope`, explicit finite limits and the saved prefix as the minimum pin.
Recovery verifies the ordered source-root closure, scope and requested prefix;
`DatagramArchive::read` returns exact original payloads at **one-based** ordinals.
Do not append a new connection to that epoch or treat an unacknowledged tail as
successful capture. Missing, altered, conflicting or tombstoned source refuses.

The source archive is not a codec checkpoint. Independent original SDP/parameter
sets, stream mapping and timing evidence remain necessary for reconstruction.
Existing AVC reconstruction recipes use that separately approved interpretation;
this mode does not generate a recipe or infer a HEVC recording from an incomplete
fragment. Normal completed windows still use the existing import/playback tools.

## Bounds, cost and qualification

Datagram count, payload bytes, physical source-spool bytes, source work, capture
steps, report bytes and original live deadlines are independent finite ceilings.
Exhaustion stops the attempt: no ring overwrite, eviction, new allowance, rollover
or reconnect is implicit. The source work counter is shared across the whole run,
not replenished per datagram. Native capture/recording settings remain unchanged.
The preview prices the additional spool and its metadata; the source format is
unchanged and uses one root with two children per datagram (objects may deduplicate).

This synchronous reference path may publish and synchronize per datagram. The
existing archive rechecks its growing root inventory, so total inventory work can
be quadratic in datagram count. It is not a throughput-qualified always-on NVR.
There is no claim that bytes still in a socket, partially framed bytes, or source
between read and durable acknowledgement survive a crash. Process-kill tests are
not host-power-loss, filesystem or physical-camera qualification.

`capture_rtsp_source_cli` exercises actual child-process kills after durable
incomplete AVC/HEVC input, exact cold source/RTCP reopening, rejection of stale
approvals and canonical path aliases, malformed input retention, source-capacity
refusal, authentication exclusion and ordinary native recording completion.
