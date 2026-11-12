# Canonical recorder queries from retained imports

After a native AVC or HEVC recorder replay has been imported, agents can query its
recorder UTC assertions using the destination deployment alone. The original
archive may be offline or removed. This is the existing AOP-005 recordings query,
with an exact retained_import selector and the same independently supplied
original recorder pins.

The query verifies completed destination custody and reconstructs the native
packet-linked result. It returns the ordinary protected agent envelope, metadata
evidence identities, explicit unknowns and read accounting. Original media is
read internally under a separate grant and is never included in the response.

## CLI

Use the import identity returned by the approved whole-receipt import. Preserve
the independently selected original receipt, request and recording scope; an
import identity alone does not choose an interpretation.

~~~bash
fss query --json --target recordings \
  --root "$DEPLOYMENT" --retained-import "$IMPORT_IDENTITY" \
  --principal "$PRINCIPAL" \
  --codec hevc --sensor "$SENSOR" --stream "$STREAM" \
  --generation "$GENERATION" --source-anchor "$SOURCE_ANCHOR" \
  --receive-clock "$RECEIVE_CLOCK" --decode-clock "$DECODE_CLOCK" \
  --time-scale "$TIME_SCALE" \
  --replay-root "$REPLAY_ROOT" --replay-request "$REPLAY_REQUEST" \
  --ntp-era "$NTP_ERA" \
  --utc-start-ns "$UTC_START_NS" --utc-end-ns "$UTC_END_NS" \
  --verify-replay-source=yes
~~~

Use --codec avc for AVC. The deployment must be an existing absolute path.
There is no archive path in this mode. The source anchor and generation retain
their historical meaning; they are not replaced by the destination's current
anchor. Optional --anchor pins the current destination authority and effect
history separately.

The UTC interval is half-open in exact integer Unix nanoseconds. The explicit
NTP era interprets the original recorder assertion. PLAY ranges, destination
receive time and RTP ticks do not fill missing UTC. The common native pin and
interval contract is documented in [recorder UTC queries](AGENT_RECORDER_TIMESTAMP_QUERY.md).

## MCP

Launch the ordinary stdio server with its fixed destination and principal:

~~~bash
fss-mcp --root "$DEPLOYMENT" --principal "$PRINCIPAL" \
  --allow-replay-source-verification
~~~

An archive root is not required for retained queries. Calls to the archive
variant still require the launcher's explicit archive binding. A client cannot
enable source verification or override the deployment, archive or principal.

Call query with target "recordings", retained_import "sha256:..." and all common
original recorder pins. The closed request contract is
[agent_retained_recording_replay_query.v1.json](../schemas/agent_retained_recording_replay_query.v1.json).
The import, roots and clocks are canonical SHA-256 strings. Generation, UTC
nanoseconds and payload limits use exact decimal strings; time scale, NTP era,
window/sample/packet/result limits use JSON integers.

CLI and MCP use the same canonical parser, native query and renderer. A client
cannot combine this selector with archive paths, archive syscall quotas,
catalog/discovery/session selectors, node-clock bounds or decode-tick ranges.
Every successful result must be complete within its bounds.

## Immutable custody and one read budget

The new ImmutableRetainedSource opens native existing history without
constructing a publisher, acquiring its writer lock, recovering a partial tail,
creating files or appending authority/effects. A sealed RetainedSource contract
lets the established retained-import and original-packet verifiers consume this
owner without gaining a mutation handle.

One nonrenewing allowance covers opening authority history, destination manifest
and completion proof, source ancestry, original recorder packets, and final
revalidation:

| Limit | Default | Maximum |
| --- | ---: | ---: |
| Aggregate payload bytes (--max-query-read-bytes) | 1 GiB | 4 GiB |
| Payload read attempts (--max-query-read-objects) | 1,000,000 | 4,000,000 |
| Native reserved original bytes (--max-query-source-bytes) | 256 MiB | 2 GiB |
| Complete native matches, unknowns and source-only rows | 32 | 128 |
| Complete protected response | 256 KiB | 256 KiB |
| Cooperative deadline | 60 seconds | 60 seconds |

Native window/sample/packet limits remain unchanged. Native reserved source
bytes are a separate bound from actual repeated payload reads. A source read
failure permanently invalidates the remaining balance. Counters do not refill
for another window, a second opening, or final verification.

Accounting reports successful bounded payload bytes and attempted payload
reads, including metadata and rereads. It does not claim to measure filesystem
syscalls, framing overhead or total CPU work. The retained response explicitly
labels this accounting profile; archive accounting retains its existing meaning.

Before exposing a result, the owner rehashes every selected object and rechecks
publication and deletion markers, then observes current history again. Layout,
site lineage, exact authority/effect positions and both journal roots must still
match. Partial journal tails, pending selected publications, changed originals,
committed deletion, cancellation and insufficient final-read allowance refuse
the whole query. No caller callback or additional source read occurs after the
final authority comparison in the canonical bridge.

These bounded observations are not an atomic filesystem snapshot or a promise of
future availability. A later use must acquire its own current authority.

## Native API

The entry point is
agent_recording_context::replay::retained::query_retained_recordings_replay_in_deployment.
It requires an opaque RetainedReplaySourceReadPermit. Its issuer supplies a real
ContextAuthority with query, media-read and replay-I/O grants, matching principal
and original source scope, sufficient allowance and a current cancellation/deadline
check. The permit binds the exact root, import, native query, expected current
anchor and all limits before filesystem access.

The canonical bridge completes final owner revalidation itself. Lower-level
callers using query_retained_replay_time with an immutable source must call
ImmutableRetainedSource::revalidate before releasing their projected result;
the source supplies a pinned authority view until that final check. The
operational ReferenceDeployment implementation retains its existing ownership
contract.

## Meaning and verification status

For equivalent original pins and native limits, native report and index
identities remain the same as the archive/native retained query. The envelope
adds independently verified destination import, publication root and manifest
identities. Missing, conflicting and malformed recorder assertions remain
explicit. HEVC source-only groups remain evidence without becoming published
pictures. Custody does not authenticate a recorder clock, establish camera
exposure time or certify continuous coverage, activity or absence.

Regression sources cover genuine native AVC/HEVC custody with the archive offline
and writer lock held, aggregate budget exhaustion during final revalidation,
late packet damage, tombstones, pending publications, partial journals and
committed deletion. Real-process CLI/MCP regressions compare native report/index
identities and complete output, exercise the launcher grant without an archive,
and check that reads/refusals leave all destination bytes and directory entries
unchanged. Exact permit reuse and revocation also have native contract coverage.

These new reference and CLI tests are **authored but not yet executed in this
session**. Independent source review, pinned Rust formatting and JSON schema
validation are available; they are not a native compilation result. The actual
eight passing new tests in this session exercise the separate fusion-ablation
core. Reference build attempts stalled without new compiler diagnostics and were
stopped. No recorder/device interoperability qualification is claimed.

This advances the recorder access portion of VIT-008, VIT-015 and VIT-022. Those
beads remain open. Migration of full QSR/inference to the immutable retained owner
is separate unfinished work.

