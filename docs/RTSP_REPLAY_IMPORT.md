# Recorder replay into ordinary retained analysis

`fss-import-rtsp replay` brings one complete, independently pinned recorder replay
receipt and **every native AVC or HEVC window it names** into the ordinary retained
file workflow. Native decode, motion, inference, event analysis, movie review and
original-media export can then use that import while retaining the recording's
historical retrieval provenance. The destination can be inspected and verified
after the source archive is offline.

This closes the replay-provenance handoff gap within VIT-022. It does not close the
broader recorder-retrieval work: hardware interoperability, remote search sessions,
vendor-specific discovery, device-clock calibration and proof that the recorder
delivered an entire historical interval remain separate work.

## Import an exact retained replay

First capture a finite historical request with
[`fss-capture-rtsp`](RTSP_RECORDER_REPLAY.md), optionally using the protected
[`from-onvif-replay` discovery handoff](ONVIF_RECORDING_DISCOVERY.md). Keep the
returned replay root, independent replay request digest and complete source scope.
The archive's existing `inspect-replay` command can verify those exact pins.

Use the same scope and receipt pins in an offline import plan:

```sh
fss-import-rtsp replay \
  --archive /srv/fss/recorder-archive --root /srv/fss/analysis --site site:home \
  --codec hevc \
  --expected-replay-root sha256:REPLAY_ROOT \
  --expected-replay-request sha256:REPLAY_REQUEST \
  --sensor-id sensor:front-door --stream-id stream:recorder-channel1 \
  --generation 1 --anchor sha256:SOURCE_AUTHORITY_ANCHOR \
  --receive-clock sha256:SOURCE_RECEIVE_CLOCK \
  --decode-clock sha256:REPLAY_DECODE_CLOCK --time-scale 90000 \
  --receive-time-ns 1793872800000000000 \
  --owner-authorized yes --read-originals yes --retain-originals yes
```

The digest labels and attribution above are placeholders. Supply the exact real
values, including the replay-derived decode clock rather than the original base
clock. `--receive-time-ns` records the destination's declared receive time; it is
not the start of the requested historical interval. Source and destination must
be distinct, non-nested absolute paths with existing parents.

The command first prints a bounded JSON plan and its `approval_digest`, without
filesystem, clock or network I/O. Repeat the identical options with
`--approve sha256:...` to execute. Approval binds the source/destination paths,
site, principal, both replay pins, codec, complete scope, time assumptions, gap
policy, read limits, work allowance and deadline. It also binds the explicit
original-read and destination-retention policy.

The source archive is opened under its native exclusive owner lock and may finish
existing publication recovery. No recorder is contacted. Existing native window,
catalog and page import commands remain available with their original identities;
select this replay command when the companion historical retrieval receipt must
survive ordinary analysis.

## What survives the handoff

The retained origin proof binds the complete original replay root and metadata,
the exact original capture approval, every window root, source packet pack,
recording index, initialization segment and media fragment. Protected ONVIF
recording-selection provenance remains a digest binding; credentials, tokens and
replay URIs are not disclosed in the import report.

Every native original is verified before destination staging. The imported MP4
preserves sample bytes and decode/presentation timing. Only the derived fragments'
four-byte sequence numbers are renumbered to form one valid movie. Original
fragments remain byte-for-byte retained. There is no transcoding, padding, timestamp
repair, source-only-tail promotion or silently selected prefix.

All receipt windows must fit the selected bounds. The fixed maxima are 64 windows,
16,384 complete samples, 128 MiB of retained original objects, 64 MiB of derived
media and 4 MiB of canonical origin proof. The owner can reduce the first four
through `--max-windows`, `--max-frames`, `--max-original-bytes` and
`--max-media-bytes`. Metadata and aggregate native read allowances are admitted
before original reads; reads, native verification and publication remain bounded
and cancellation-aware. A bound refusal does not truncate the receipt.

An empty replay has no usable import. All windows must share the declared scope,
codec and byte-identical initialization, in nonoverlapping decode order.
Configuration changes or overlapping windows require separate imports. Decode
gaps refuse by default. `--decode-gaps preserve` explicitly admits positive gaps
only with independently decodable restart samples, retains every gap's original
coordinates and carries gap flags into ordinary retained processing. This choice
changes the exact plan and import identity.

## Partial retrieval and time stay explicit

A receipt stopped by a byte budget, deadline, cancellation, input end or other
condition can still contain usable complete windows. Importing its full retained
closure preserves its original `replay_termination` and
`replay_publication_complete`; it cannot turn an incomplete recorder result into a
completed interval. Even a complete publication is not evidence that the recorder
retained or delivered all historical footage.

The successful report includes exact replay request/root/approval digests,
requested and acknowledged `clock=...` ranges, optional ONVIF source binding,
window/frame counts, decode range and gaps, and the retained import/proof identities.
`upstream_interval_completeness` remains `unknown`. Continuity, absence and
historical UTC calibration are never certified by this operation.

Capture time defaults to `unknown`. An optional pair of `--capture-start-ns` and
`--capture-uncertainty-ns` supplies a separate, approval-bound operator assumption
based on native presentation offsets. Neither the requested replay range, the
recorder's narrower acknowledgement, RTP timestamps nor host receive clocks are
implicitly promoted into calibrated frame time. The separate
[recorder timestamp query](RECORDER_TIMESTAMP_QUERY.md) retains its assertion-only
interpretation and does not establish physical clock accuracy.

## Cold inspection, analysis and retries

Use the returned `import_identity` with the ordinary retained commands:

```sh
fss-file inspect --root /srv/fss/analysis --site site:home \
  --import-id sha256:IMPORT_ID
fss-file verify --root /srv/fss/analysis --site site:home \
  --import-id sha256:IMPORT_ID
fss-file decode --root /srv/fss/analysis --site site:home \
  --import-id sha256:IMPORT_ID --segment 0 --segment-count 32 \
  --interpretation ycbcr --work-units 1000000000
```

Choose a segment count actually present in the import. Inspection verifies
retained root membership and the original replay metadata, and reports historical
provenance without needing archive slots. `verify` additionally reconstructs and
checks every original recording and the exact derived movie from destination
custody. Decode and movie review perform their existing native source verification;
cached reads continue to reject deleted or substituted evidence. Current
destination privacy masks apply to analysis. Original source retention remains
local and unencrypted, as in the existing native archive import profile.

Exact retries reconcile the same complete import without duplicate ledger or
effect records, but still require the original source archive and current
authority. A missing source is refused and never recreated. This differs from
cold destination verification, which is self-contained. Changed scope, codec,
time assumptions, limits or gap policy produce a different approved request;
existing publication bytes and identities are never rewritten. Retention holds,
deletion planning and original-media export include the complete replay closure.

## Contracts and qualification

The public library entry point is
`fss_reference::ingest::rtsp_import::replay::import_rtsp_replay`. The retained-origin
adapter is `ADP-RTSP-REPLAY-ARCHIVE-001`, with new request, identity and proof domains.
Existing native replay receipt and older import formats are unchanged. The strict
JSON projection schema is
[`rtsp_replay_import_operator.v1.json`](../schemas/rtsp_replay_import_operator.v1.json);
its validation grants no custody or execution authority.

Focused contracts live in `rtsp_replay_import_contract`, the import binary's
`replay::tests`, and the real executable `rtsp_replay_import_cli` target. They
cover both codecs, full ONVIF/original closure, archive removal, native decoding,
movie selection, tamper/deletion refusal, gaps, cancellation, limits, privacy masks,
exact retries and honest partial/time reports. They are included in
`scripts/check_recording_lifecycle.sh replay`. See
[`IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md) for the actual executed
validation scope; source review and synthetic fixtures do not qualify a recorder
or a production deployment.
