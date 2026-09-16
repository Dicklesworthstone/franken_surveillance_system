# Source-linked local recording windows

Status: implemented reference source; Rust compilation, Rust tests and native
filesystem fault execution are outstanding. Advances FSS-068/FSS-115 and the
WP-030/WP-060/WP-070 recording/custody boundary, not their full qualification.

## Working boundary

`fss_reference::rtsp::recording` seals existing `AvcPictureGroup` values and
explicit `TimedAvcPicture` timing into independently IDR-led recording windows.
Preparation uses the actual `fss-container::AvcMuxer`, then validates its output
against exact original RTP datagrams. It never advances a live mux cursor.

A root has exactly four children, with the index also named as typed metadata:

| Role | Contents |
|---|---|
| Source | Canonical pack of exact RTP datagrams, extended sequences and receive times |
| Initialization | Exact MP4 configuration with the selected SPS/PPS |
| Media | Fragmented MP4 samples; compressed NAL bytes are not transcoded |
| Index | Stable owner scope, child identities, sample timing and original-to-output byte maps |

The source pack names a receive-clock epoch. Receive time is not camera capture
time and may decrease in sequence order after transport reordering. The index
binds canonical sensor/stream identities, stream generation and owner anchor;
process-local ingress handles never become durable IDs. Anchor/clock digests
are references, not claims that those external authority objects are archived.

Preparation and readback reconstruct NALs through the real H.264 depacketizer.
Every copy span and synthesized FU header must agree with the original packets.
Every MP4 byte is covered by the supported box grammar or an exact source NAL;
relocated SPS/PPS bytes point into the initialization. Source gaps that interrupt
fragments, incomplete tails, extra packets/NALs, wrong payload/SSRC/epochs,
parameter changes and inconsistent primary-picture identities are refused.

IDR syntax and macroblock-zero presence do not certify successful decoding or a
complete picture. Boundary classifications are retained producer receipts;
`RtpMarker` remains a sender assertion and a next-picture witness may lie outside
the selected window. Unverified EOF boundaries are rejected. Explicit media
DTS/PTS/duration are not inferred from receive time or presented as capture time.

## Root-last publication and recovery

Open the existing `LocalRootPublisher` with explicit root and spool bounds.
`RecordingPublication::new` borrows that exact owner and a sealed plan, fixes one
slot/deadline and checks the payload reservation. Each `step` stages one child,
source first, or calls the existing root-last publisher after all children.
There are at most five successful steps for a fresh window. Preparation/staging
is not a durable root; only the actual publisher's receipt proves its rung.

A lost final receipt is reconciled against the same immutable root. An identical
root is reverified as `AlreadyPublished`; another root in that slot is a conflict,
never an overwrite. No retry remuxes or advances sequence/timing. Keep the sealed
plan until the root is durable or the exact outcome has been reconciled.

The underlying publisher owns crash recovery and indeterminate I/O. Reopen
reverifies a root and its children before reporting durability. Children left
before root publication are unreferenced custody, not partial archives. A crash
leaving an orphan root temporary produces an explicit repair obligation; this
composition does not silently delete it. No `Drop` path publishes or deletes.

Cancellation and supplied monotonic deadlines stop new steps. Cancellation is
also passed through existing pre-commit cut points. Entry time is not an elapsed
syscall deadline: a real runtime must enforce deadline/revocation through its
live cancellation probe. Cancellation after commit does not retract a root.

`load_recording` requires an exact expected root and scope, a durable slot and an
already-open owner. It refuses poisoned/tombstoned/conflicting roots, rehashes
all objects and verifies the complete source relationship before returning any
media. This is a point-in-time read, not a permanent retrieval certificate.

## Resource and privacy limits

A window permits at most 4,096 datagrams, 256 picture samples, 16,384 NAL mappings,
16,384 source spans, 2 MiB index metadata and 32 MiB combined object/root payload.
Each original datagram is at most 65,535 bytes. Limits precede bounded allocation
where the format permits; during load a rejected object can temporarily coexist
with prior accepted bytes, bounded by prior payload plus one spool-sized object.
The existing spool independently limits disk bytes, object count and object size.

This is **unencrypted local reference custody** through the current synchronous
rooted I/O owner, not a production storage capability or privacy transformation.
The caller must separately authorize full-source retention and readback. No
remote disclosure, mask bypass, inference authority, secret handling or new
runtime is introduced. A production encrypted/Asupersync/ledgered archive remains
separate work. Full source capture before derivative failure and a continuous
ring/GOP collector remain the ingress owner's obligations.

## Reproduction

```sh
cargo test --locked -p fss-reference \
  --test recording_archive_contract \
  --test recording_publication_contract \
  --test recording_golden_contract
cargo run --locked -p fss-reference --example recording_archive_replay -- NEW_DIRECTORY
python3 scripts/check_recording_window_fixture.py
bash scripts/qualify.sh --lane rust
```

There are 34 authored Rust test functions: 16 preparation/provenance contracts,
12 disk/cancellation/recovery contracts and 6 golden/self-consistent-hash
adversaries. The replay uses the retained synthetic baseline bitstream and
prints hashes/counts and actual root receipts, never raw media or filesystem paths.

Only the independent Python/FFmpeg/FFprobe laboratory check ran during authoring.
It constructed single-NAL and FU-A versions of one IDR window, decoded the same
pixels as the original and retained exact media timing. Its hashes are pinned
in the Rust golden tests. This does not execute the Rust implementation or its
filesystem operations; those tests and whole-repository qualification remain
outstanding. No device, production, remote or complete-picture claim is made.
