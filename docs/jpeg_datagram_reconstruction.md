# JPEG images from retained original RTSP datagrams

`DatagramJpegReplay` reconstructs native RFC 2435 JPEG images from the existing
durable `DatagramArchive`. A cold process can reopen the same local publisher,
verify an independently selected source prefix, reconstruct complete images and
decode their pixels with the first-party JPEG decoder. The original RTP/RTCP
objects, archive chain and root-last publication format are shared with AVC and
HEVC capture.

## Retain originals before interpreting them

Pass an actual `RtspWireFrame` to `DatagramArchive::prepare_frame`, then publish
that exact prepared observation with `DatagramArchive::publish`. Retain the
returned `DatagramPin` after the publication reports local durability. A prepared
candidate or an uncertain publication result must remain distinct from the last
acknowledged prefix. Control responses, requests and authentication challenges
are refused before payload work; their bodies cannot enter the media archive.

Every source observation keeps its original interleaved channel, parser-completion
receive timestamp, payload digest, byte count and arrival ordinal. RTP headers,
extensions and padding stay in the original object. Duplicates, probation packets
and malformed input remain separate original observations even when the JPEG
receiver cannot use them.

The codec-neutral custody implementation lives in `rtsp/datagram_archive/source.rs`.
The existing public `rtsp::datagram_archive` facade preserves the AVC capture APIs
and reexports the same source types. This is one archive, with no JPEG-specific
storage history or replacement publication implementation.

## Select an exact complete prefix

Reopen `LocalRootPublisher` and call `DatagramPrefix::recover` with the original
`DatagramScope`, independent finite archive limits and the exact selected pin.
Recovery verifies the complete current namespace, including later observations,
before exposing the selected historical prefix. The selected source stays fixed;
`observed_head()` separately identifies the newer head verified during recovery.
Missing, corrupt, tombstoned, forked or unresolved source cannot become an empty
successful replay. This operation performs no repair or source reacquisition.

Use `prefix.archive()` to construct:

```rust,ignore
let mut replay = DatagramJpegReplay::new(
    prefix.archive(),
    JpegReplaySpec {
        payload_type,
        reorder: reorder_limits,
        jpeg: jpeg_limits,
        reduced_rtcp,
        configuration_evidence,
    },
    JpegReplayBounds {
        max_source_bytes,
        max_steps,
        deadline_ns,
    },
    now_ns,
)?;
```

The source always starts at its original first observation. A caller cannot skip
to a selected image sequence and silently omit earlier cached quantizer tables.
To select later images, replay the complete selected prefix and filter completed
outputs. Missing quantizers remain a typed native codec refusal. The current
scope binds ingress, generation, asserted SSRC, route, channels, receive clock and
retention evidence; the replay never carries cached tables across generations.

The interpretation digest binds the exact source pin, negotiated payload,
configuration evidence, RTCP policy, every packet/reorder/JPEG bound, native
reconstruction profile and deterministic scheduling policy. Configuration evidence
does not grant source access. Supply current cancellation and one finite
`WorkBudget` across the complete replay; its deadline uses the current owner clock.

## Drive bounded progress and retain every result

Call `step(&publisher, now_ns, cancel, &mut budget)` once per progress opportunity.
Each call drains one native event, reads and admits one reverified original,
advances one historical timer, or transfers terminal ownership. There is no loop
waiting for more packets inside a step.

- `Rtp` and `Rtcp` transfer the exact reverified original and its typed admission or
  compound-validation result. Invalid RTCP does not invent a video gap or clock.
- `Media` carries the unchanged `JpegReceivePoll`. Complete frames additionally
  carry an opaque `JpegFrameProvenance`; partial images never receive one.
- `ClockAdvanced` identifies a receiver wake bounded by a later retained arrival.
- `InputRefused` and confirmed restarts transfer the original triggering source
  and receiver retirement. A restart needs a separately selected new generation.
- `PrefixExhausted` transfers the exact selected pin and pending receiver accounting.
  It never calls `finish`, invents EOF, or runs a future timer beyond retained input.

Historical receive time drives reordering and fragment expiry. Current storage
time governs the replay lease. Neither becomes physical capture time, DTS or
wall-clock calibration. Equal-time arrivals and intermediate native polls follow
the frozen scheduler; this is a new deterministic interpretation of originals,
not restoration of an unrecorded live polling schedule.

Clock regression is a safe refusal with no progress. Other runtime failures stop
the attempt and return `JpegReplayRetirement`. If cancellation or a budget refusal
occurs after producing an output, `withheld` owns that complete output, including
its image and any bound provenance. No successful output escapes after revocation,
and repeated terminal calls cannot transfer the same retirement again.

## Connect original objects to native pixels

For each complete frame, the provenance getters expose:

| Getter | Meaning |
| --- | --- |
| `source()` | Exact full selected source prefix, including RTCP and duplicates |
| `interpretation()` | Frozen source/configuration/reconstruction/scheduler identity |
| `encoded_digest()` | Exact derived JPEG bytes to pass to the native decoder |
| `digest()` | Canonical frame source-map identity, distinct from image and pixel digests |
| `dependencies()` | Unique original admitted datagrams, ordered by extended RTP sequence |
| `receive_clock()` | Owner-selected original parser-completion clock identity |
| `capture_clock()` | `None`: physical capture clock remains unknown |

Each `JpegSourceDependency` binds an extended sequence to its actual
`DatagramRecord`: source root, payload digest, original arrival ordinal, channel
and receive timestamp. An equal later retransmission cannot replace the admitted
source. A cached quantizer definition may precede the current frame's sequence
interval; it remains an explicit dependency. The bounded source index stores
metadata only, with ordered binary lookup for delivered originals.

The native `JpegFrame` retains copied byte ranges, interpreted header ranges and
generated header ranges. The provenance digest commits these maps, the exact
encoded image, the source dependencies and unknown capture clock. Generated JPEG
headers are derived bytes, not a claim that the camera originally sent that file.

Pass the owned frame and `provenance.encoded_digest().bytes()` to
`jpeg_client::pictures::decode_luma_frame` or `decode_rgb_frame`, retaining the
provenance beside the returned picture. The native decoder validates the complete
image and returns its pixel receipt; failure returns the intact reconstruction.
The source proof describes this verified replay, not perpetual future custody.
Re-read original dependencies through the selected archive when current retrieval
is required.

The native test target `fss-codec-mjpeg --test rtsp_jpeg_contract` compiles these
exact production modules with real `fss-object` and `fss-publication` dependencies.
Its retained fixtures exercise root-last publication, process-state loss, cold
prefix recovery, cached table lineage, sequence wrap/reordering, duplicate
originals, byte-exact source maps, native luma against the existing independent
oracle, cancellation after completed output, and corruption after recovery.
These synthetic fixtures do not qualify an untested camera or deployment.
