# Pure-Rust streaming and media kernel

**Document class:** normative media architecture
**Revision:** 1
**Date:** 2026-08-31

## 1. Doctrine

FSS must preserve source evidence, deliver low-latency live views, and feed bounded decoded tensors to cognition. Those are three distinct representations with different semantics. The production system owns their parsing, timing, custody, and transformation in pure Rust. FFmpeg/ffprobe and vendor players remain laboratory differential oracles, not required runtime components.

## 2. Layered media stack

```text
transport bytes
→ framed protocol packets
→ elementary stream access units
→ container/sample timeline
→ source object custody
→ optional decode surfaces
→ live proxy and analysis derivatives
```

Each layer can retain exact byte spans into its parent, diagnostics, limits, and transformation receipts.

## 3. Transport and camera protocols

Initial first-party protocol targets:

- USB UVC/UAC descriptor/control/stream handling through admitted platform primitives;
- RTSP session state and authentication;
- RTP/RTCP sequence, timestamp, loss, jitter, sender-report, and feedback semantics;
- ONVIF SOAP/XML narrow profiles for discovery, media, events, and PTZ where authorized;
- HTTP(S) object/playlist transport needed by owned adapters;
- file/container replay.

Proprietary adapters terminate vendor protocols into the same packet/capsule contract. They cannot bypass timing, source custody, or authority layers.

## 4. Packet truth

A packet record includes:

```text
stream_generation
transport_sequence_and_wrap_epoch
receive_monotonic_interval
source_timestamp_and_clock_basis
payload_byte_span_or_object
marker/keyframe/config flags
loss/reorder/duplicate status
authentication/integrity status
adapter_and_protocol_generation
```

Late, reordered, duplicated, corrupted, or discontinuous packets are recorded honestly. A decoder receiving a frame does not retroactively prove continuity.

## 5. Elementary stream parsers

FSS owns bounded, nonrecursive parsers for admitted codec bitstreams. Initial priorities are driven by cheap cameras:

- H.264/AVC access-unit and parameter-set parsing;
- H.265/HEVC access-unit and parameter-set parsing;
- MJPEG/JPEG framing and decode path;
- AAC/G.711/PCM audio as required;
- AV1 as an archive/proxy target after its kernel is admitted.

Parser responsibilities include configuration epochs, keyframe/random-access classification, dimensions/crop/color metadata, reference requirements, and malformed-input diagnostics. Parser acceptance is separate from decoder acceptance.

## 6. Container and segmentation

First-party narrow container support focuses on the exact FSS waist:

- fragmented MP4/CMAF for live and archive derivatives;
- Matroska/WebM where needed for import/export;
- MPEG-TS only where device compatibility requires it;
- canonical FSS packet-object format for lossless replay.

Remux is preferred over transcode. Container writers use deterministic box/element ordering, explicit timescales, checked arithmetic, and child-first/root-last publication.

## 7. Source evidence path

Original encoded bytes are preserved whenever policy permits. A source object records:

- exact received bytes or declared reconstruction;
- packet/span map;
- capture-time interval and clock evidence;
- stream/adapter/device generations;
- codec/configuration epochs;
- continuity/loss/corruption metadata;
- custody/encryption/publication state.

A transcoded proxy never replaces the source root or inherits its evidentiary status.

## 8. Decoder architecture

Decoder implementations have:

- scalar/reference semantics;
- bounded parser/state limits;
- safe-Rust optimized kernels;
- explicit reference-frame ownership;
- generation-pinned parameter sets;
- deterministic or tolerance-certified pixel output;
- color/range/chroma policy;
- cancellation checkpoints between bounded units;
- malformed stream and resource-exhaustion tests.

Decoded frame storage uses immutable/frozen buffers or region-owned pools with generation tokens. A model/view cannot retain a buffer after reuse without owning a frozen reference.

## 9. Live operator path

The live path prioritizes bounded latency and graceful quality reduction:

1. preserve source path independently;
2. select/remux an already browser/UI-compatible stream where possible;
3. otherwise decode/scale/encode a low-latency proxy;
4. publish short independently decodable fragments;
5. drop or reduce derivative quality under pressure before compromising source custody;
6. report actual end-to-end latency, discontinuity, and degradation state.

The UI consumes a generation-pinned surface; stale frames cannot be mislabeled live.

## 10. Analysis path

The analysis scheduler requests only the frames/regions/resolutions needed by the current cascade. It can:

- decode keyframes or adaptive samples;
- crop before expensive model stages;
- share immutable decoded surfaces among compatible consumers;
- fuse color conversion/resize/normalization into first model kernels;
- retain exact source-to-tensor mappings for explanations;
- stop refinement on budget exhaustion while preserving early results.

Sampling policy is versioned and included in model-event receipts.

## 11. Safe performance strategy

- zero-copy only where ownership and backing-generation rules are proven;
- scatter/gather over immutable packet spans;
- ring buffers with explicit leases, not raw pointer lifetimes;
- columnar timestamp/offset/index metadata;
- cache-aligned storage supplied by safe first-party primitives;
- shape-specialized transforms and safe SIMD;
- share-nothing per-stream hot paths;
- bounded pools with backpressure;
- no per-packet heap map/string allocation;
- deterministic batch/merge ordering;
- same-binary reference/optimized arms.

## 12. Backpressure hierarchy

When resources are constrained, FSS degrades in registered order:

1. reduce optional UI thumbnails/refresh;
2. reduce expensive semantic refinement;
3. reduce analysis sample rate/resolution within policy floor;
4. delay nonurgent archive replication while preserving local spool;
5. reject new optional work;
6. mark observability degraded.

It does **not** silently drop source evidence, continuity records, authority deltas, committed effects, or required deletion obligations.

## 13. Differential oracles

FFmpeg/ffprobe, browsers, vendor players, and known decoders are pinned in lab images. The gauntlet compares:

- parser acceptance/rejection;
- access-unit boundaries and timestamps;
- decoded pixel digests/tolerance;
- color metadata and crop behavior;
- seek/random access;
- malformed and truncated streams;
- container round-trips;
- performance distributions.

Divergences are classified and retained. Oracle agreement on errors only does not count as successful support.

## 14. Admission sequence

1. exact packet replay format and timing oracle;
2. RTP/RTCP and RTSP reference implementation;
3. H.264/H.265/MJPEG parsers without decode claims;
4. deterministic container/remux path;
5. MJPEG/JPEG decode as the simplest full vertical slice;
6. H.264 baseline/main profiles needed by fixtures;
7. device-specific profile expansion;
8. live proxy encoder path;
9. audio codecs;
10. AV1/archive optimization;
11. proprietary adapters only after the common waist is stable.

Every stage can ship with honest capability matrices; unsupported profiles fail closed or preserve source bytes for later analysis.
