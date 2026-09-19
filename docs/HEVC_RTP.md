# HEVC RTP reconstruction

`fss-packet::H265Depacketizer` implements the RFC 7798 transport-reconstruction
slice of the comprehensive plan's section 12.4. It accepts an explicitly bound
owner ingress/generation, SSRC, payload type, and negotiated
`sprop-max-don-diff = 0` in single-stream transmission order.

The public API supports single NAL packets, aggregation packets (AP), and
fragmentation units (FU). It preserves layer and temporal identity, original RTP
timestamps, marker observations, and exact source-datagram copy ranges. FU
receipts also identify the three source-header bytes used to reconstruct the
two-byte HEVC NAL header. No Annex-B delimiter is fabricated.

Every AP is fully validated before any member is emitted. The aggregate byte
budget cannot be multiplied by the permitted member count. Pending FU work is
bounded by bytes, packet count, and a representable monotonic deadline. Gaps,
malformation, interruption, expiry, cancellation, and EOF retire incomplete
reconstruction with payload-free receipts. Duplicate or late packets cannot
resurrect retired chains. Wrong-owner and reversed-time inputs do not consume
sequence state or alter a pending chain.

For already ordered input, the owner drives `H265Depacketizer::expire` at
`next_deadline_ns`, including when no network input arrives. Original source custody remains independent of
this derivative receiver. Debug and refusal output contain metadata, not media.

This is not a HEVC decoder, access-unit/picture validator, complete RTSP HEVC
adapter, authentication mechanism, or production qualification claim. DONL/DOND
ordering, PACI, and cross-stream decoding order are explicitly unsupported.
Parameter-set availability and random-access decodability are not inferred from
a NAL type or RTP marker.

## Ordered receiver

`fss-packet::H265Receiver` composes the shared `RtpReorderBuffer` and HEVC
reconstruction. Supply complete datagrams to `ingest`, then drive `poll` until
pending and at `next_wake_ns`. A poll returns one original datagram plus its
reconstruction result, one delivery gap, or one retirement receipt. Codec refusal
never hides the original datagram. Sequence probation, duplicates, conflicting
retransmissions, late recovery, and queue pressure retain the shared RTP semantics.

Reconstruction uses monotonic delivery time; each original retains its possibly
out-of-order arrival time. Timer expiry does not consume queued source input.
Capacity refusals leave the packet retryable after draining. `finish` drains
accepted input before codec EOF, while `cancel` accounts for both layers at once.
Confirmed source restarts close the old receiver. `restart` requires a strictly
newer generation for the same ingress and never discards the old owner's work;
the owner must separately drain or cancel that instance.

## Verification

The public-API regression suite is `crates/fss-packet/tests/h265_contract.rs`:

```sh
cargo test -p fss-packet --test h265_contract --test h265_receiver_contract
```

The suite covers valid reconstruction, all layer/temporal bit combinations,
fragment split points, AP header minima and malformed suffixes, sequence wrap,
loss, late input, expiry, cancellation, EOF, ownership, resource ceilings,
source ranges through RTP extensions/padding, and deterministic replay.
The authoritative qualification entrypoint remains `scripts/qualify.sh`.
Tests were added but could not be executed in the implementation container,
which had no Rust compiler; no passing Rust receipt is asserted here.

Protocol reference: RFC 7798 sections 4.4.1, 4.4.2, and 4.4.3.
