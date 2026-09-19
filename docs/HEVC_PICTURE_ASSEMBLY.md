# Source-linked HEVC picture grouping

`fss_packet::hevc::HevcAssembler` extends the RFC 7798 reconstructed-NAL path
with bounded, single-layer picture grouping. This implements the grouping slice
of the media kernel in comprehensive-plan section 12.4. It introduces no runtime,
I/O, dependency, or canonical durable format.

The assembler reads only the parameter-independent slice prefix: the first-slice
flag, IRAP-only no-output-of-prior-pictures flag, and PPS identity. Its bounded
reader consumes at most fifteen bits. VCL kinds 0..9 and 16..21 are admitted;
reserved kinds and nonzero layer identities fail explicitly. It does not parse
PPS-dependent segment addresses, entropy data, POC, reference lists or pixels.

A first-slice flag, subsequent access-unit prefix, AUD, EOS or EOB supplies an
observed boundary. RTP markers are preserved but do not close a group. Each
picture requires an observed first slice; its following segments must agree on
PPS identity, VCL kind, temporal identity, IRAP flag and RTP timestamp. Source-copy
spans must advance without overlap, including AP members sharing one packet.
VPS/SPS/PPS/prefix-SEI NALs before the slice and suffix-SEI/filler after it retain
their original bytes and provenance. Control-NAL trailing bits are checked.
Parameter-set and SEI bodies remain opaque metadata, not verified configuration.

The admitted subset deliberately rejects a next picture with the same timestamp
as the current picture or the most recently emitted one; no decoder identity is
available to disambiguate that case. It does not enforce numerical timestamp
monotonicity or confuse RTP wrap/B-frame presentation order with clock reversal.
Missing or conflicting input cannot silently become a complete picture.

`push` returns the exact NAL on refusal. Pending assembly is retired on known
loss, invalid source order, malformed/unsupported input, conflicting slice
prefixes, byte/count/span limits, or its fixed first-NAL deadline. New slices,
RTP markers, and late boundary packets cannot extend that deadline. The next
admitted group exposes `discontinuity_before`. Direct users must call
`discontinuity` for packet/codec failures that do not themselves produce a NAL.

`expire` must be driven at `next_wake_ns`, including without further traffic.
`finish(now)` emits an explicitly `EndOfInputUnverified` VCL tail, never an
invented verified boundary, and retires metadata-only state. An end marker with
no picture is returned as a standalone NAL. EOB closes assembly; EOS only ends
the current sequence. Cancellation is terminal and accounts for pending bytes
once. Independent original-source custody remains the transport owner's duty.

## Picture-aware RTSP client

`fss_reference::rtsp::hevc_client::pictures::RtspHevcPictureClient` connects this
assembler directly to the existing plain/Digest `RtspHevcClient`. It does not
replace or change that client's public NAL-only API. Its constructors add
independent `HevcAssemblyLimits`; requests and borrowed credentials use the
existing authentication, URL scope, correlation, lifetime and teardown owners.

Poll until a waiting/terminal state and always arrange `next_wake_ns`. Original
control frames, RTP admission and RTCP validation events remain intact. Ordered
source datagrams are returned before their complete NALs are processed one at a
time. Gaps, reconstruction refusals, fragment deadlines and incomplete-FU EOF
invalidate picture assembly automatically; callers cannot forget this wiring.
An invalid RTCP compound does not become a video discontinuity.

The extra complete-NAL queue holds at most one reconstruction output and has a
fixed residence deadline. Delayed consumers cannot revive expired NALs by
starting fresh picture deadlines. Queue expiry retires both queued NALs and
any affected pending picture while permitting explicit discontinuous recovery.
Client/session/wire deadlines take priority over queued derivative work. Picture
timers remain visible while a Digest challenge is waiting for credentials.

Assembly refusals return the original NAL, source failures retain their original
datagrams, and cancellation accounts for the complete-NAL queue, picture work,
raw-client queues/fragments, held challenges/retries, and unprocessed TCP. EOB
closes the local connection without sending an invented TEARDOWN; later buffered
wire is retained and remote-session uncertainty remains explicit. Clean EOF or
TEARDOWN can return an unverified picture tail, but incomplete-fragment EOF may
not flush the preceding partial picture. Repeated terminal polls never repeat
picture or source retirement ownership.

This path groups supplied TCP media; it still does not open sockets, decode HEVC,
verify parameter-set compatibility, write an archive, prove camera coverage, or
turn source bytes into durable custody. Those remain separate qualification and
implementation boundaries.

## Bounds and validation

All retained NAL bytes, NAL count, source-span count, and age have independent
limits. Syntax-prefix work is constant per VCL NAL; source checking is linear in
its bounded span count. Metadata reservation grows geometrically to its count
ceiling; media bytes are moved, not recopied. Filler validation is linear in its
bounded NAL length. No output, queue, recursion or retry is unbounded.

`hevc_assembly_contract.rs` exercises the public API with NALs created by the real
RTP depacketizer, not a bypass constructor. It covers all admitted prefix-field
combinations, first-slice versus marker behavior, metadata boundaries, AP source
spans, loss/expiry, owner/time isolation, resource limits, cancellation and EOF.
`rtsp_hevc_picture_contract.rs` adds wire-level negotiation, authentication,
reordering, fault propagation, queue pressure/residence, cancellation, EOF,
EOB, RTCP isolation and TCP-partition invariance contracts:

```sh
cargo test -p fss-packet --test hevc_assembly_contract
cargo test -p fss-reference --test rtsp_hevc_picture_contract
```

Rust execution is unavailable in the editing environment. Added tests are not
claimed to have passed; a local pinned-toolchain run is still required. A picture
group is not a decoded frame, random-access guarantee, complete-picture proof,
retained archive, camera qualification or evidence of physical coverage.
