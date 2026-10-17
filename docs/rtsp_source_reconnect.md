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

`--recover yes` and `--recover index` currently REFUSE source-retained reconnect
plans before effects. Existing recording recovery does not verify the extra
source stores, so accepting those options would silently omit custody. Preserve
all stores and their exact scopes/pins. The existing `DatagramArchive` library
can reopen and verify retained source prefixes; this command does not resume or
automatically reconstruct them, change retention, or grant a new network epoch.

## Initial validation scope

201 capture-binary unit tests passed with pinned `nightly-2026-08-31`, locked
offline Cargo and debug assertions. Fourteen new cases cover source grants,
independent scopes and summed limits, stale approvals, fail-closed delegation,
unsettled source custody, recovery refusal and source-publication clock accounting.
A real loopback AVC smoke run completed two independent source-retaining sessions.
The capture modules were verified against `40681520`; unrelated dependency source
came from the independently verified `caa59a97` source/compiler artifact. This
initial result is not full current-workspace, physical-camera, power-loss or
release qualification. The repository's qualification gates remain unchanged.
