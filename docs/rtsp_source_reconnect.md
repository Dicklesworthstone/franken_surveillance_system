# Source-first custody across bounded RTSP sessions

`fss-capture-rtsp reconnect` accepts the existing explicit source-retention
options alongside duration, progress supervision, interrupted-prefix retry and
finite campaigns. The same native AVC/HEVC owners publish complete interleaved
RTP/RTCP datagrams before further media progress. No second receiver or source
queue is introduced, and ordinary capture does not acquire extra retention.

Add these options to the complete existing reconnect command:

```text
--source-root /owner/private/source-prefix
--source-retention-evidence sha256:<independently-approved-retention-evidence>
--max-datagrams 8192
--source-storage-bytes 268435456
--source-work 1000000000
```

Preview without `--approve`, inspect `datagram_source_custody`, then repeat the
complete command with the new OUTER approval. The example limits are the existing
source defaults, not a throughput or duration guarantee. Any source option
requires both the source directory and its explicit retention evidence. Source
payloads are UNENCRYPTED; they include probation, duplicates, malformed packets
and incomplete pictures and need their own privacy/retention authorization.
RTSP messages, credentials, TCP framing and partial datagrams are not retained.

## Independent, priced attempts

`--root`, `--pins` and `--source-root` are separate path prefixes. Attempt one
uses their `.attempt-0001` directories; attempt two uses `.attempt-0002`, and so
on. All parents must exist. Each source scope is rebuilt from the exact child
binding, generation, receive clock, channels and retention evidence. No prior
source directory is adopted, overwritten, merged or deleted.

Source limits are PER ATTEMPT. The outer preview prices the sum of source
spool bytes, payload bytes, datagram counts and work over every possible attempt.
Unused source allowance is not carried forward. The source grant does not enlarge
the native recording, network, report or lifetime ceilings. A source child's
approval, an ordinary capture approval or an old reconnect approval cannot start
the combined plan. Omitting all source options preserves the previous reconnect
approval encoding, preview shape and execution path.

Source publication failure or unresolved source work blocks every successor,
even if the recording windows are fully durable. It is never a transient camera
failure or permission to allocate another spool. Existing authentication,
authority, protocol, timing, control, output and media-custody barriers remain.
Each native terminal report is flushed before the controller admits a successor.
Keep the preview and every `datagram_durable` receipt with all three stores.

## Timers, interruption and recovery

Measured synchronous source-publication/output time is excluded from the
no-picture-progress allowance. It still counts against capture duration and all
native deadlines. An earlier progress failure remains latched; late picture
progress or a later duration boundary cannot turn it into success.

`--retry-interrupted yes` still requires the original recording to finalize its
verified nonempty prefix and all control/custody obligations to settle. Source
datagram durability alone is not a complete picture, recording checkpoint,
source EOF or continuity claim. `--continue-after-success yes` retains its
all-planned-attempts-success contract; later success cannot erase an interruption.
This remains bounded repeated capture, not gap-free always-on recording.

`--recover yes` and `--recover index` support source-retained reconnect plans.
Repeat **all original source options** with the original reconnect plan and remove
the capture approval. The storage-only preview binds each source directory's
identity and complete verified current datagram head. Restoration and indexing
require every original recording RTP packet, including lookahead packets outside
the decoded samples, to exist in that source chain with its unchanged receive
time. All three stores stay locked; a missing or damaged later source blocks
restoration of earlier media during preflight.

An optional `--minimum-source-pins` map binds independently retained
`datagram_durable` prefix receipts. Source stores are never created, appended,
reconstructed or resumed by recovery. The operation has no camera connection,
credential lease or new network epoch. See [source-retained recovery](rtsp_source_recovery.md)
for commands, exact source coordinates, retry behavior and bounds.

## Initial validation scope

201 capture-binary unit tests passed with pinned `nightly-2026-08-31`, locked
offline Cargo and debug assertions. Fourteen new cases cover source grants,
independent scopes and summed limits, stale approvals, fail-closed delegation,
unsettled source custody, the initial recovery refusal and source-publication clock accounting.
A real loopback AVC smoke run completed two independent source-retaining sessions.
The capture modules were verified against `40681520`; unrelated dependency source
came from the independently verified `caa59a97` source/compiler artifact. This
initial result is not full current-workspace, physical-camera, power-loss or
release qualification. The repository's qualification gates remain unchanged.

The storage-only recovery extension passed all **215 capture-binary unit tests**
with the repository's pinned toolchain, locked offline Cargo and debug assertions.
Twelve new native disk cases cover AVC/HEVC original-window restoration, catalog
completion, exact retries, missing or corrupt source, source prefix and directory
changes, complete original RTP membership, retained locks, cancellation and
cumulative work. Two additional parser cases cover canonical minimum-source maps
and their bounds. This validates the capture binary and native fixture paths;
it does not establish physical-camera, full-workspace or release qualification.
