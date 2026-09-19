# Replay-verified HEVC recording windows

`rtsp::recording::hevc::prepare_hevc_recording` seals an immutable, IDR-led
recording from full original RTP datagrams and explicit sample timing. It
connects the existing HEVC depacketizer, picture assembler and native fragmented
MP4 writer to the existing source/initialization/media/index object model.
It does not open sockets, run a decoder, infer a frame rate, or retain secrets.

## Preparation and source boundaries

Supply `RecordingScope`, an immutable `HevcConfiguration`, a positive media
time scale, one `HevcRecordingTiming` per requested picture, and sequence-ordered
`RecordingPacket` values. The scope binds the canonical sensor, logical stream,
generation, owner anchor and receive-clock basis. These are owner assertions,
not authorization inferred from packet headers. Saved receive times may be out
of sequence after reordering and are never used as decode time or capture time.

The supplied packets must be contiguous in extended sequence, bound to one
SSRC/payload mapping, and contain complete HEVC NAL reconstruction. The shared
assembler must observe exactly the requested number of boundary-closed groups.
No EOF flush, synthetic EOS, injected SDP packet, missing-FU repair or RTP marker
can manufacture the last picture boundary. The original source must include
the actual next-prefix/first-slice/AUD/EOS/EOB witness. Incomplete or malformed
input, extra completed groups, discontinuities and unsupported codec cases fail.

A next-picture boundary may share a datagram with media or leave a bounded next
prefix/picture pending. Those complete trailing NALs stay in the source object
and are counted by `source_only_nals()`; they are not silently discarded,
remuxed into the last sample, or certified as another complete picture. At most
256 trailing NALs are admitted. Every packet is retained whole, including RTP
headers, extensions and padding. Configuration bytes supplied out of band have
initialization ranges but no invented RTP provenance.

Reconstruction uses synthetic replay time zero. This is a new offline derivation
from retained bytes, not resurrection of expired live state and not a claim
that live deadlines or coverage succeeded. The caller remains responsible for
live stream/authority/custody validity before choosing a source window.

The prepared result exposes exact bytes, sample boundaries/timing, per-NAL
RTP-to-container mappings (including FU header-synthesis inputs), original
packets, parameter ranges and source-only accounting. Its `publication_plan()`
is accepted by the existing `RecordingPublication` state machine: original
source first, then initialization/media/index, then the immutable root last.
The plan itself proves no I/O, encryption, replication or durable publication.

## Verification

`verify_hevc_recording` first checks the complete object closure and externally
supplied expected scope. It then replays **all** original datagrams through the
same depacketizer, assembler, configuration reader and muxer. Initialization,
media, every sample receipt, every source map, actual boundary class and
source-only count must match the stored objects exactly. Rehashing a forged
boundary or byte mapping does not make it valid. A source-only prefix cannot
be reclassified as a media sample without an actual closing witness.

The root is a content commitment, not a signature or source-authentication
certificate. Changing original source bytes and consistently deriving an
entirely new recording creates a different root; callers must pin the expected
root when retrieving an existing recording. Return of a verified summary does
not prove decoded picture completeness, capture continuity, full parameter-set
compatibility, physical coverage or authority-anchor custody.

## Versioned representation and compatibility

The manifest kind is `hevc_recording_window_v1`, distinct from the unchanged
`avc_recording_window_v1`. The source child reuses the exact existing
`fss.recording_window.source.v1` representation. AVC verification never accepts
a HEVC index. No existing schema, boundary tag or durable byte format changes.

The new canonical index starts with `fss.hevc_recording_window.index.v1`, then
uses the existing `CanonicalEncoder` field grammar in this order:

1. Sensor and stream text, generation u64, anchor digest, receive-clock digest.
2. SSRC u32, payload type u32 (0..127), positive time scale u32.
3. Source, initialization and media digests; VPS, SPS, PPS ranges (u64 pairs).
4. Source-only NAL count u64, sample count u64 and sample records.
5. NAL-mapping count u64 and NAL records. Trailing bytes are forbidden.

A sample contains media range, decode/presentation u64 times, duration and RTP
u32 timestamp, IDR bool, boundary u64 tag, and NAL-mapping ordinal range.
Boundary tags are 1 next-first-slice, 2 next-access-unit-prefix, 3 AUD, 4 EOS,
5 EOB, and 6 unverified EOF. Tag 6 is representable but fails recording replay.
A NAL record contains sample/NAL ordinals, output range, source-span count and
spans. Each span contains extended sequence, wire range, NAL range and an
optional FU-header wire range. All ranges are half-open and all ordinals are
zero-based. There is no serialized process-local ingress handle.

The existing combined 32 MiB child/root budget, 4,096-packet, 256-sample and
16,384-NAL/span bounds apply. The index is capped at 2 MiB. Reconstruction and
assembly keep their independent bounded work limits; metadata allocation is
fallible. Preparation and verification are synchronous bounded work with no
new worker/runtime or I/O. Transient replay/remux buffers are additional to the
sealed payload budget, but remain bounded by these fixed limits.

## Regression entrypoint

```sh
cargo test -p fss-reference --test hevc_recording_contract
```

Tests use retained synthetic Main-profile source NALs through the real packet,
assembly and container owners. They exercise source preservation, exact replay,
boundary lookahead, sequence wrap, AP/FU mapping, EOF refusal, malformed/foreign
input, independent clocks, explicit timing, scope isolation, forged rehashed
metadata/payloads, canonical framing, determinism and resource limits.
Rust execution is not available in the editing environment; these authored
tests are not a passing build or qualification receipt. The normative
qualification entrypoint remains `scripts/qualify.sh` on its admitted hosts.
