# Durable RTSP campaign history

`fss-capture-rtsp reconnect` can retain the lifecycle of a finite, approved capture
campaign in an independent metadata store. Each attempt still owns its original
recording archive, pin journal, clocks and generation. History makes those
independent attempts discoverable after the capture process exits, including
failed, empty and interrupted attempts that produced no usable catalog.

This is an explicit option. Existing reconnect commands and their approval bytes
are unchanged when no history option is present. It does not provide an always-on
recorder, crash resume, cross-archive event detection, continuity or scene coverage.

## Approve metadata retention with capture

Add these options to the ordinary reconnect command described in
[the campaign guide](rtsp_capture_campaign.md):

```text
--history-root /private/camera/campaign-history
--history-max-records 33
--history-object-bytes 262144
--history-max-scan-entries 4096
--history-metadata-bytes 16777216
--history-storage-bytes 33554432
--history-work 10000000000
```

Only `--history-root` is required; the other values shown are the defaults and
maximum CLI ceilings. Record, storage and retained-metadata capacity apply to the
**whole campaign**, not to each attempt. In live capture,
`--history-metadata-bytes` bounds the cumulative retained canonical plan, record
and manifest bytes. Every append also reverifies its prior prefix under bounded
read allowances; one whole-campaign work account pays for all those rereads and
publications. A new camera session replenishes neither work nor retained
capacity. The record ceiling must admit two records per planned attempt plus one
terminal record. The maximum campaign is still 16 attempts.

The destination must be a new absolute directory with an existing canonical
parent path, separate from every archive, pin journal, source store and credential
file. A symlinked parent that changes the approved path refuses before directory
creation. The native camera owners retain their existing path, custody, secret,
deadline, publication and resource checks.

First run the complete command without `--approve`. Planning does not create the
history directory, read credentials or connect to the camera. The preview's
`campaign_history` object reports the frozen history plan digest and every
ceiling. Its `approval` binds the history destination and limits as well as the
unchanged child capture plans. Repeat the exact command with that outer approval.
An old reconnect approval or an individual child's approval cannot enable
history retention.

History retains canonical metadata and exact native evidence coordinates. It does
not copy media or credentials. The directory is created privately on Unix and is
unencrypted, like the existing local original-evidence stores. Protect it
according to the deployment's existing custody policy.

## Durable boundaries and failure behavior

The outer owner publishes immutable objects through the existing root-last
publisher:

1. An attempt's start becomes durable before camera admission. This records that
   the attempt was admitted; it does not prove a connection was established.
2. The native owner closes and finalizes its work, then supplies a typed
   observation before writing its terminal stdout row. That observation includes
   its result, durable picture count, unresolved custody state and available
   snapshot, journal, catalog and original-datagram coordinates.
3. The controller checks the approved completion and retry rules. It retains the
   native observation and controller decision before reporting the outer finish
   or admitting a successor.
4. A separate durable terminal record establishes the campaign's reported final
   result. In continue-after-success mode, a later success cannot erase an earlier
   failed attempt.

Every successful publication emits a `history_durable` control row containing:

```json
{
  "transition": "attempt_started",
  "attempt": 1,
  "pin": {
    "approval": "sha256:...",
    "plan": "sha256:...",
    "root": "sha256:...",
    "records": 1
  },
  "save_independently": true
}
```

Save each complete pin independently of the history store. All four coordinates
are required. The `root` identifies the exact immutable transition manifest;
`plan` identifies the complete frozen campaign plan. Neither is a mutable
"latest" pointer.

Any history publication failure stops further capture. There is no automatic
retry of history writes, adoption of an existing history directory, budget
replenishment, deletion or resume. Preserve every store and every complete
receipt on failure.

Output failure remains separate from native capture. If native capture finalized
successfully but its terminal stdout fails, the available typed native
observation is retained with a controller/output failure and no successor. If
there was no native observation, the history explicitly records it as unavailable;
picture counts and custody are not manufactured as zero.

A finish can become durable before its receipt is lost to output failure. The
controller still refuses a successor. An independently saved earlier start pin
selects only that earlier prefix: it must not discover or imply the later finish.
Without a selected terminal record, overall campaign completion remains unknown.

## Inspect an exact saved prefix after restart

The standalone inspection command requires no original capture arguments:

```bash
fss-capture-rtsp campaign-inspect \
  --history-root /private/camera/campaign-history \
  --principal principal:local-operator \
  --approval "$SAVED_APPROVAL" \
  --plan-digest "$SAVED_PLAN" \
  --root-digest "$SAVED_ROOT" \
  --records "$SAVED_RECORDS"
```

Use the exact values from an independently saved pin and the original principal
label. That label is an audit identity, not account authentication. The current
read operation separately checks its principal, path, selected pin, authority and
resource ceilings before metadata access and disclosure.

Inspection uses the existing read-only object-store inspector. It does not open a
camera, read a credential file, access the original media archives, create a
directory or lock, repair storage, publish an object or authorize another capture.
It works when the original recording and pin-journal paths are unavailable.

The four pin coordinates select exactly one immutable prefix. A missing,
mismatched or corrupt selected object refuses; the reader never switches to an
older root or chooses a root from a directory listing. The report preserves:

| Selected evidence | Reported meaning |
| --- | --- |
| Start without a selected finish | `started_completion_unknown` |
| Finish with no native observation | Native result, counts and custody unavailable |
| Native failure followed by another attempt | Original failure retained; independent successor shown |
| Separate successful terminal | The frozen campaign completion predicate passed |
| Separate failed terminal | The observed campaign failed with its retained error identity |
| No selected terminal | Overall completion `unknown` |
| Planned attempt absent from the selected prefix | Unknown, not proven never started |

`next_attempt_planned` is the recorded decision, not evidence that the next camera
session actually started. An older valid prefix does not prove there are no later
records. A missing history store does not prove no capture occurred.

The inspector rehashes the selected canonical metadata graph. It does not freshly
fsync the store, so `durability_resynced` is false. It also reports
`possibly_stale` when writer state cannot be established. Catalog roots, source
pins and journal anchors are **recorded native observations**; present media
custody remains `unchecked` until the corresponding original store is verified
through its existing native reader. A snapshot digest is an inventory identity,
not an object publication root.

## Bound cold reads and preserve recovery semantics

The inspector accepts the same `--history-*` resource options and a bounded
`--max-report-bytes` (default and maximum 1,048,576). These are current inspection
ceilings. They may narrow the original grant; insufficient work, metadata,
storage, object, scan, record or report capacity refuses rather than truncating an
attempt or returning a partial conclusion. Work and metadata allowances are
shared across the selected history. The report includes consumed and remaining
work.

Native recording recovery remains explicit. Repeat the original reconnect
options, including the original history options, when using `--recover yes` or
`--recover index`; this preserves the original capture identity. Recovery uses
its own observed approval and original store barriers. It neither creates nor
rewrites the campaign history. A later successful recovery cannot retroactively
turn a retained failed native attempt into a successful capture.

The process contracts in `capture_rtsp_cli/history.rs` cover independent
successful and failed epochs, exact earlier-prefix selection after restart,
unavailable media paths, empty retained source pins, refusal before camera work,
wrong pins/principals, exhausted current ceilings and corrupt selected objects.
They exercise native loopback capture and persistence wiring; they do not qualify
real-camera interoperability, continuous scene coverage or deployed detection.
