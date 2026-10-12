# Recorded HEVC RTP reconstruction

`fss_reference::ingest::rtpdump::hevc` adds an owner-driven, source-preserving
HEVC transport path for retained `rtpdump` / `rtpplay1.0` recordings. It reuses
`fss_packet::H265Receiver`, the shared RTP reorder kernel, and the existing
container reader. It does not introduce another depacketizer or a foreign media
runtime. The existing AVC APIs and import behavior are unchanged.

## Owner contract

Construct `HevcDumpConfig` with the authorized `StreamKey`, selected payload
type, negotiated `sprop_max_don_diff`, explicit RTCP mode, and independent dump,
reorder, and reconstruction limits. Nonzero DON requirements are refused rather
than inferred away. The input recording must already have been opened under the
owner's file authority; the adapter borrows its bytes and performs no I/O.

Create `RecordedHevcReplay::new(input, config)` and repeatedly call
`step(&ReplayCx)`. Each step exposes one original record or one native receiver
event. `HevcDumpStep::Record` includes probation packets, duplicates, malformed
inputs, captured prefixes, and originals whose derivative admission is fenced.
Handle the native `Progress` events, including gap and retirement receipts, not
only successful NAL output. `InputEnded` is not quiescence: continue until
`Exhausted` so accepted originals drain and unfinished fragments are accounted for.

For NALs in a successful `H265ReceivePoll::Packet` result, call `map_nal` before
dropping the replay instance. Each mapping names its original file record, copied
byte range, destination NAL range, and optional three-byte FU header range.
The adapter checks copied bytes, the RTP media timestamp, and the synthesized
two-byte HEVC NAL header. CSRC lists, RTP extensions, padding, and AP length fields remain in the
original but are not falsely included in reconstructed media. Duplicate input
cannot replace the first admitted original for a sequence; cross-epoch mappings
are refused.

## Failure and timing behavior

Capture offsets are laboratory timing inputs, not authenticated capture times.
Decreasing offsets are reported without reversing receiver time. Reorder and
fragment deadlines are visited in order before a later original is admitted,
including arrivals exactly at the deadline. Sparse arrivals therefore cannot
rescue a fragment by postponing delivery of its start until the tail arrives.

A snaplen-limited record or transport admission failure retires pending work and
fences further derivatives while keeping later originals inspectable. Codec
refusals and malformed RTCP retain their exact sources and do not hide subsequent
independent valid NALs. A confirmed source restart closes the current derivative
epoch; opening another requires a new explicit owner binding. Malformed container
termination is not clean EOF. Cancellation accounts separately for queued
originals and incomplete fragments, and terminal steps do not repeat receipts.

## Scope and validation

This API reconstructs transport NALs only. It does **not** assert VPS/SPS/PPS
availability, complete pictures, decoded pixels, live continuity, durable archive
publication, or retained source custody. Those remain separate contracts. No CLI
codec switch or HEVC archive-import support is implied by this library addition.

The focused contract target is:

```sh
cargo test -p fss-reference --test rtpdump_hevc_contract
```

It uses synthetic transport probes through the real native receiver, covering
single NAL/AP/FU input, extensions and padding, sequence wrap, duplicates,
reordering, reversed offsets, exact/late/maximum-offset deadlines, cancellation,
malformed input, incomplete EOF, owner mismatch, and resource/negotiation
refusals. These probes are not picture-decode or camera qualification evidence.
The companion AVC timing regressions are in `rtpdump_avc_deadline_contract`.
