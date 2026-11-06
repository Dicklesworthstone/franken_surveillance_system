# Bounded recorder RTSP replay

The native AVC RTSP session can request historical footage from an explicitly
supplied recorder replay URI. This advances VIT-022
(`fss-vit022-recorder-retrieval-5js5o`); it does not implement recording search,
ONVIF GetReplayUri, vendor URI discovery or upstream retention inventory.

## Protocol contract

After DESCRIBE, an owner explicitly selects `ClientCommand::SetupReplay` instead
of live SETUP. The successful SETUP permits exactly one
`ClientCommand::PlayReplay(ReplayWindow)`. Both requests carry
`Require: onvif-replay`; PLAY also carries a closed canonical
`Range: clock=START-END` and `Rate-Control: no`. A replay SETUP cannot authorize
live PLAY, and live SETUP cannot authorize replay PLAY. Other codecs refuse the
replay command before dispatch.

`ReplayWindow::from_timestamps(start, end)` accepts compact UTC coordinates
`YYYYMMDDThhmmss[.fraction]Z`, with one through nine fractional digits. Gregorian
dates are validated in 1970–9999; leap seconds are outside the admitted profile.
Rendering removes insignificant fractional zeros. The interval must be forward,
nonempty and at most seven days, to the nanosecond. This bound does not enlarge
the independent connection deadline, authority lease or media/work/byte ceilings.

A successful PLAY must include exactly one closed clock range contained in the
request. A narrower accepted range is retained explicitly. Missing, duplicate,
malformed, open or widened ranges refuse before the session enters Playing.
This is deliberately a stricter profile than general RTSP frame alignment:
playing before or after the approved historical interval needs separate authority.
Optional Rate-Control/Scale echoes must agree with unpaced forward playback;
they need not be echoed, but duplicate or contradictory assertions refuse.

`ClientProgress::ReplayAccepted(ReplayAcceptance)` carries the requested
interval, acknowledged interval and actual successful PLAY CSeq. Session matching,
request deadlines and channel admission remain enforced. Digest authentication
retains the exact range and required option across authorized retries, signs the
ordinary SETUP/PLAY wire methods, and exposes the final successful CSeq.

Replay statuses 456, 457 and 551 have distinct payload-free typed refusals. A 457
means invalid/out-of-bounds range; it is **not proof of upstream retention expiry**.
There is no automatic live fallback, URI substitution, request expansion, seek,
reverse playback or queued-range behavior.

## Time and custody

Requested UTC and acknowledged UTC are protocol intent and recorder assertions.
They do not establish calibrated capture time, received-frame UTC, continuity,
complete retrieval or physical absence. Existing RTP arrival clocks and relative
decode timing retain their meanings. ONVIF per-frame historical RTP extensions
can remain in the original datagrams without being interpreted by this slice.

The session API exposes the acknowledgement to a recording owner. The existing
live CLI does not yet select replay commands in this protocol-only checkpoint.
Durable request/acknowledgement receipts and the explicit single-capture CLI
mode are separate integration work; callers must retain protocol provenance
alongside any original recording they create.

## Regression coverage

`crates/fss-reference/tests/rtsp_replay_contract.rs` contains 15 native contracts:
calendar and exact nanosecond bounds, unchanged live request bytes, replay
headers, narrowed acknowledgements, mode isolation, malformed/widened responses,
policy echoes, CSeq/session correlation, typed status handling, cancellation,
expiry, interim responses and Digest retry identity. Existing session-auth
contracts include the new explicit command variants.

The local execution environment became unavailable before these new protocol
tests could run. They are authored and independently source-reviewed, not locally
validated. The supplementary RTSP control workflow invokes the new target without
changing the existing repository qualification gate or its result. Hardware
recorder interoperability and release qualification remain open.

## Primary specifications

- [ONVIF Streaming Specification](https://www.onvif.org/specs/stream/ONVIF-Streaming-Spec.pdf),
  replay transport, required option, range and rate-control sections.
- [ONVIF Replay Control Service](https://www.onvif.org/specs/srv/replay/ONVIF-ReplayControl-Service-Spec.pdf),
  obtaining an explicit replay URI.
- [RFC 2326](https://www.rfc-editor.org/rfc/rfc2326.html), PLAY and status semantics.
