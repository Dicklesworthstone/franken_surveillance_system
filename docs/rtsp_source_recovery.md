# Recover media while preserving its original RTP/RTCP custody

Source-retained `fss-capture-rtsp reconnect` campaigns can restore saved native
recording work and finish catalog discovery without reconnecting to a camera.
Recovery verifies all three original stores: the recording archive, independent
work-pin journal and complete original datagram archive. It uses the existing
native AVC/HEVC recovery and publication owners.

## Restore the original work

Keep the original capture command, preview and independent receipts. Remove its
`--approve` value and repeat all original options, including source retention,
duration, supervision, retry policy and per-attempt limits:

```sh
fss-capture-rtsp reconnect [ALL ORIGINAL CAPTURE AND SOURCE OPTIONS] \
  --recover yes \
  --recovery-timeout-ms 30000
```

This preview inspects complete protected journals and rehashes the complete raw
source chain of every observed attempt. It does not read native recordings,
credentials or camera traffic. Its `datagram_source_custody` section reports each
original source path, verified current scope/head/count/byte coordinates and
cumulative source work used. The separate recovery approval binds those values,
directory identities, selected native work, original limits and the recovery
deadline. Adding recovery never changes the original capture identity or epochs.

Repeat the command with the preview's exact `--approve sha256:HEX`. Before the
first media confirmation or publication, recovery verifies every selected native
work object and every original recording RTP packet against the complete retained
source chain. This includes initialization and lookahead datagrams outside the
decoded samples. Payload bytes, receive timestamps and the RTP channel must match;
RTCP, duplicates and malformed raw input may remain in the source archive without
becoming a media sample. Full raw source custody is an additional precondition to
the existing native recording replay.

All observed source owners and journals remain locked throughout the operation,
alongside the selected recording owners. Complete source checks repeat before
each restoration. The `datagram_source_preflight_complete` row marks successful
source preflight before any media publication starts. Recovery restores only the
original pending window or catalog under its original slot and root.

## Finish catalog discovery

After original work settles, request a separate catalog preview with the same
original options:

```sh
fss-capture-rtsp reconnect [ALL ORIGINAL CAPTURE AND SOURCE OPTIONS] \
  --recover index \
  --recovery-timeout-ms 30000
```

This preview also reads every observed original recording, verifies its RTP
membership in retained source and quotes the exact next catalog. Approve this
preview separately to finish discovery through the existing independent
journal/work/confirmation/catalog barriers. Source custody is rechecked after
work-confirmation output and before catalog publication. Indexing preserves the
original windows and reports existing catalog roots on a no-op retry.

## Keep independent source receipts

For either recovery mode, optionally supply exact prefixes saved independently
from native `datagram_durable` receipts:

```text
--minimum-source-pins 1:DATAGRAMS:PAYLOAD_BYTES:sha256:HEAD,2:DATAGRAMS:PAYLOAD_BYTES:sha256:HEAD
```

Each row identifies one original one-based attempt. Read the cumulative count,
payload bytes and head from the receipt's `detail.prefix` object; its head is the
complete source-prefix digest. The original
attempt defines the source scope; no new generation or clock is introduced.
Every coordinate must match an exact prefix of the complete current chain.
Descendants require a fresh preview, and damaged newer records always refuse even
when an older saved prefix remains valid. The separate
[`--minimum-pin-anchors`](rtsp_recovery_minimum_pins.md) option protects the media
work journal; both maps may be supplied together.

## Failure and retry behavior

An observed attempt needs all three original stores. A partial layout, symlink,
replaced directory, missing source payload, invalid source head or unmatched RTP
witness refuses. Every attempt is preflighted before the first restoration, so a
known bad later source cannot permit earlier media publication. All three absent
stores are reported as `all_three_stores_unobserved`; an independently saved
source or journal minimum makes that absence a refusal.

Restoration remains incremental across attempts. A later runtime failure or lost
output can leave earlier native work durable. Preserve every store, preview the
current state and approve that exact state to retry the original slots. A stale
approval never authorizes newly observed source or journal state. Source objects
are never created, appended, repaired, reconstructed or deleted by these modes.
An index interruption may leave an original catalog work pin to restore with
`--recover yes` before retrying indexing.

The recovery deadline covers the whole operation. All source validation passes
within one operation consume a single original `--source-work` allowance per
attempt; repeated checks do not replenish it. Source store size, datagram count,
payload and scan limits remain the original finite limits. A budget or
cancellation refusal cannot be turned into a fresh network attempt.

Without independently retained minima, rollback trust remains in the protected
directories. Source hashes do not authenticate a camera, encrypt stored bytes or
prove scene coverage. Recovery establishes neither session completion nor
continuity across independent attempts and never certifies physical absence.
This is a native reference recovery path, not a physical-camera or release
qualification claim.
