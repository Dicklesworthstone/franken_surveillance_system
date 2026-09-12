# Packet kernel reference slice

Status: implemented source and contract tests; not production- or device-qualified.
Owning work: FSS-048 / FSS-112, WP-050 / WP-060, QL-MEDIA-001.

`fss-packet` is the dependency-free, safe-Rust packet boundary anticipated by the
comprehensive plan. It consumes supplied bytes, never opens sockets or files,
starts no workers, and neither authenticates a sender nor creates an effect.
The transport owner retains custody and binds observations to the exact stream,
adapter, device, clock, and authority generations.

## Wire parsing

`RtpPacket::parse` borrows the original datagram. It validates RTP v2, CSRCs,
extensions, and padding before exposing the encoded payload and its exact source
range. Extensions remain opaque. The payload type needs a negotiated mapping;
the marker is not a generic keyframe flag; timestamps are not wall-clock time.
Empty payloads and zero-length header extensions are represented honestly.

`RtcpCompound::parse` validates the entire datagram before yielding any report.
It checks declared packet/report/chunk counts, sender and receiver reports,
SDES termination/alignment, BYE reasons, APP minima, and final-only RTCP padding.
Conventional compound mode requires an initial SR/RR and the first sender's CNAME.
Reduced-size framing is an explicit caller choice, not automatic fallback.
Unknown packet types and report-profile extensions remain exact opaque bytes.

Sender reports retain NTP seconds/fraction and raw RTP timestamp/counters without
inventing an NTP era or an authoritative capture-time mapping. Reception reports
preserve signed 24-bit loss, extended sequence numbers, jitter, LSR, and DLSR.
There is no floating-point or system-clock dependency in wire interpretation.

Limits bound datagram bytes, extension bytes, and compound packet count. Parsing
allocates nothing. Debug views omit packet payloads, extensions, and SDES text.
Malformed suffixes cannot publish a valid prefix as a successful compound.

## Sequence and timing

`SequenceTracker` validates the owner epoch, negotiated SSRC, and payload type
before mutation. Two sequential packets establish the baseline. A fixed 128-bit
window suppresses duplicates and recovers reordered positions across sequence
wrap; missing positions and received/unique counts remain separate. Two
consecutive discontinuous packets latch `RestartRequired`: reopening requires a
strictly newer owner epoch, rather than silently resetting prior coverage.
This is sequence admission, not authentication or a live coverage certificate.

`JitterEstimator` implements the RFC 3550 integer recurrence in arrival order,
including accepted duplicates/reordered timestamps. Supplied monotonic arrival
clock reversals and ambiguous half-cycle deltas fail without mutating the state.
`arrival_ticks` uses bounded integer arithmetic. `SenderReportClock` preserves the
NTP-era ambiguity, binds the stream epoch, bounds extrapolation, rounds intervals
outwards, includes caller-supplied drift/measurement uncertainty, and computes
LSR/DLSR without guessing capture truth. An owner must retain report provenance
and justify the uncertainty and extrapolation ceilings.

## Contracts and qualification

The implementation follows RFC 3550 sections 5.1, 5.3.1, 6.1, and 6.4-6.7.
The source specification is https://www.rfc-editor.org/rfc/rfc3550.html .
The acceptance boundary is deliberately narrower than a complete RTP session:
no RTSP negotiation, sockets, SRTP, RTCP transmission scheduling, trusted clock
estimation, camera capture, codec decoding, or archive publication is claimed.

Run on the repository's accepted toolchain:

```sh
cargo test --locked -p fss-packet
cargo clippy --locked -p fss-packet --all-targets -- -D warnings
cargo fmt --all -- --check
bash scripts/qualify.sh --lane rust
```

`wire_contract` includes fixed-layout fixtures, compound CNAME binding, signed
loss extremes, wrap-valued report fields, profile extensions, malformed/truncated
headers and suffixes, padding, chunk termination, limits, non-disclosing Debug,
and a deterministic 8,192-input hostile-byte corpus. Presence of these tests is
not a retained pass receipt. No Rust compiler was available in the authoring
container; execution and whole-repository qualification remain outstanding.
FSS-112 remains open until the full bead's timing, recovery, integration, oracle,
and retained qualification requirements are met.
