# Recorded RTP import, recovery and picture replay

Reference implementation for the file-ingest capability in `fss-2h5zq.27`.
Source implementation is present; Rust compilation and qualification are **not
claimed** by this delivery. The bead and acquisition/media release gates remain open.

## Public entrypoints

`fss_reference::ingest::rtpdump` connects the existing packet kernel to recorded
rtptools input without sockets, device credentials, new crates or changes under
`crates/fss-packet/**`.

- `RtpDumpReader`: bounded original-record framing, exact file offsets, explicit
  RTP/RTCP/snaplen discrimination, and terminal malformed-suffix refusal.
- `replay::RtpDumpReplay`: the actual `SequenceTracker` and `H264Depacketizer`, with
  original records, typed dispositions and verified absolute-file copy/FU-header
  mappings. This receipt path classifies reordering but does not repair it.
- `import::{prepare_rtp_import, publish_rtp_import, load_rtp_import}` and
  `FileIngestAdapter::ingest_rtp`: source-first custody, NAL-linked capsules,
  root-last publication, deterministic capsule batches and complete readback.
- `recovery::inspect_rtp_import`: read-only verification by an exact durable root,
  without the original source pathname or an in-memory receipt. It reconstructs
  ordered source chunks and replays the packet kernel to check the entire stored
  report and object closure. The recovered state separates complete import batches
  from pending ledger work. `RecoveredRtpImport::resume` explicitly completes that
  work, revalidating the exact anchor/root and reusing existing batch identities.
- `avc::RecordedAvcReplay`: an additional derivative view through the existing
  `AvcReceiver`, including its bounded reorder queue and picture assembler. It
  requires explicit exact SPS/PPS and owner configuration; source mappings remain
  recoverable when capture arrival order differs from extended RTP sequence order.
  Its picture groups are not automatically persisted by the NAL import path.

## Truth and failure boundaries

The entire original file is retained, including recorder headers, probation,
duplicates, RTCP, rejected media and any malformed terminal suffix. Synthesized
NAL bytes are separately identified derivatives, never substituted for source.

Every imported capsule declares **zero decoded frames**. NAL reconstruction and
AVC picture grouping do not establish macroblock completeness, decoded pixels,
first-frame observation or live continuity. Capture time remains unknown within
`[0, owner_receive_time]`; recorder-relative milliseconds drive only a monotonic
laboratory replay timer. No path certifies absence or silently creates a new SSRC,
stream generation, credential or network capability.

Expiry is processed before later input can complete a fragment or picture. The AVC
view preserves real receiver loss/retirement events. Snaplen-limited RTP and failed
admissions conservatively fence that derivative attempt while still exposing later
original records. Malformed container framing cancels pending AVC work rather than
turning an unknown suffix into a clean EOF picture. Cancellation never deletes source.

Publication can stop after staging or after the source root is durable but before
capsule/terminal ledger batches complete. Root inspection does not repair this
implicitly. Resume is explicit and idempotent; changed anchors require reinspection.
Recovery currently requires an already published root, not an orphan-staging scan.
A verified read is point-in-time evidence, not a future availability guarantee.

## Example commands

These local reference commands use deployment lineage `site:recorded-rtp`. They do
not authenticate remote devices and are not a race-proof filesystem sandbox.
The generic sniff-only file entrypoint still refuses RTP: explicit stream binding
is required by `ingest_rtp`.

```sh
cargo run --locked -p fss-reference --example ingest_rtpdump -- \
  capture.rtp deployment-directory sensor:cam-1 stream:recorded-video \
  1 0x11223344 96 1000000000 operator:local

# Use the exact sha256 root printed by the import command.
cargo run --locked -p fss-reference --example recover_rtpdump -- \
  inspect deployment-directory sha256:<root-hex> operator:local

# Only this explicit action completes pending ledger batches.
cargo run --locked -p fss-reference --example recover_rtpdump -- \
  resume deployment-directory sha256:<root-hex> operator:local
```

For other site lineages use the Rust API with the existing `ReferenceDeployment`.
For ordered picture replay supply `AvcDumpConfig`, exact parsed SPS/PPS, and the
verified original bytes, then drive `RecordedAvcReplay::step` through terminal
drain. Retain source mappings from `map_nal` before dropping the replay instance.

## Verification status and reproduction

There are **42 authored Rust tests** across five integration targets:

```sh
cargo test --locked -p fss-reference \
  --test rtpdump_framing \
  --test rtpdump_replay_contract \
  --test rtpdump_import_contract \
  --test rtpdump_recovery_contract \
  --test rtpdump_avc_contract
```

They cover framing cuts, NAL equivalence, sequence wrap/reorder/duplicates,
fragment loss/expiry, original-byte provenance, bounded reads, publication retry,
readback corruption, cold receipt loss, partial publication, stale recovery,
picture grouping, capture-limited input and cancellation. The delivery environment
had no `cargo` or `rustc`, so these tests, the examples, Rustfmt, Clippy and the
repository qualification entrypoint were **not executed**. Source/API review and
uploaded blob checks are not substitutes for that execution.

The independent fixture oracle was executed successfully:

```sh
python3 scripts/check_rtpdump_ingest_fixture.py
```

This laboratory-only Python/FFmpeg/FFprobe check pins the existing first-party AVC
fixture, reconstructs its nine NALs from single-NAL and FU-A recordings, verifies
original-file copy spans, compares all four decoded frames' pixels, refuses 14,574
cuts inside incomplete records and checks missing-FU-start refusal. It does **not**
execute the new Rust reader, publisher, recovery or picture replay. The receipt is
`docs/evidence/rtpdump-fixture-oracle.json`; its `rust_executed` field is false.
FFmpeg and Python remain laboratory tools, not production dependencies or fallbacks.

## Remaining implementation frontier

Execute and repair the Rust targets against the accepted toolchain before claiming
qualification. Then connect the source-mapped picture view to admitted decoding,
source-to-tensor receipts and the real acquisition lifecycle. Persist picture-group
outputs under a separately pinned derivative identity rather than changing existing
NAL-import roots. Network/device I/O and new runtime/dependency admission remain
separate owner decisions. No requirement or release gate was closed by these commits.
