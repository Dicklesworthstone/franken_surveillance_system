# HEVC RTSP negotiation and reception

`RtspClientSession::with_codec(config, ClientCodec::H265)` enables the RFC 7798
transport subset on the existing RTSP/1.0 session. The ordinary `new(config)`
constructor remains H.264-only. There is no automatic codec or media-track
fallback. `media()` returns H.264 parameters only; `hevc_media()` returns the
separate immutable `HevcClientMedia` type only after successful DESCRIBE.

The accepted HEVC subset is a single explicitly selected video media line,
H265/90000, RTP/AVP or RTP/AVP/TCP, SRST transmission order, and zero
sprop-max-don-diff. Missing transmission-mode and DON fields use the RFC 7798
transport defaults. Nonzero DON/reordering requirements, multi-stream or
source-specific dependencies, RTCP multiplexing, and unknown fmtp requirements
are rejected. Multiple payload choices and conflicting/duplicated decision
attributes are rejected rather than given last-wins semantics.

Optional VPS/SPS/PPS lists are decoded using the existing bounded Base64 parser.
They retain signaling order and are screened for NAL kind, forbidden bit,
nonzero temporal ID, and byte/count limits. Missing lists remain missing;
in-band parameter sets are not fabricated. Header screening is NOT validation
of parameter-set syntax, cross-set compatibility, decode readiness, or profiles.
Advertised profile fields remain explicitly unverified signaling. Debug and
error output exclude parameter bytes, URLs, challenges, and credentials.

All existing owner subtree checks, exact CSeq correlation, one-outstanding-
request rule, SHA-256 Digest policy, session-token binding, issue-time deadlines,
keepalive, TEARDOWN, and remote-session uncertainty apply unchanged to HEVC.
No socket, DNS lookup, credential store, decoder, or external runtime is added.

## Owner-driven TCP reception

`rtsp::hevc_client::RtspHevcClient` connects this negotiation to the existing
exact-frame `RtspWireIntake` and reorder-aware `H265Receiver`. Its `new` method
binds the owner URL scope, expected ingress/generation/SSRC, RTP queue limits,
and HEVC reconstruction limits before any request. `with_digest` additionally
pins a credential realm and explicit authentication policy. It does not open a
socket, select an interface, resolve a host, provide transport encryption, or
authorize a camera. The transport owner still supplies those boundaries.

Prepare OPTIONS/DESCRIBE/SETUP/PLAY/keepalive/TEARDOWN with `request`, or use
`request_digest` on an authenticated connection. A prepared request must be
written once or the connection closed; preparation does not prove dispatch.
Feed at most `MAX_WIRE_CHUNK` bytes and drive `poll` to a waiting or terminal
state. Always arrange `next_wake_ns`, including while the socket is silent.

The public events preserve the existing distinctions:

- `Control` returns the exact original accepted response and session progress.
  `Rtp` returns its complete original TCP frame plus admission accounting;
  `Media` subsequently returns ordered datagrams and reconstructed HEVC NALs.
  SDP parameter sets are never injected as if observed in an RTP packet.
- `Rtcp` validates the whole compound under the negotiated reduced-size policy
  and retains malformed source bytes. RTCP failure does not invent a video gap
  or an NTP-era/capture-time mapping.
- `AuthenticationRequired` retains a matching Digest 401. `respond_digest`
  returns BOTH its original challenge and the newly prepared signed request.
  Credential waits do not reset original request or oldest-wire-byte deadlines.
  Unsupported or unsolicited challenges never become credential prompts.
- `Backpressure` retains exactly one unconsumed RTP frame and its original
  residence deadline. No input retry is admitted twice. A datagram that cannot
  fit an empty queue fails rather than waiting forever. Wire-blocked sessions
  wake for hard expiry, not a busy loop over an unserviceable keepalive.
- `Fault` and `Ended` retain local shutdown accounting and remote uncertainty.
  Cancellation returns unprocessed wire, a held challenge/retry, and separate
  queue/fragment retirement. EOF drains complete input; an incomplete suffix
  remains a failure. TEARDOWN stops new admission and returns any lookahead.

Outer `RtspWireFrame::received_ns` records final-byte intake time. The nested
ordered RTP receipt records queue-admission time, which may be later under
backpressure. HEVC reconstruction uses monotonic processing time after packet
reordering. None of these times is silently presented as camera capture time.
Raw returned frames may contain media or authentication material; their Debug
implementations expose only sizes/metadata. The explicit owner must apply its
custody, retention, encryption, and privacy policy when retaining or exporting
those bytes. Returning original bytes is not itself durable source custody.

The pump creates no worker or second runtime. Intake has one bounded partial
buffer, at most one held retry/challenge, one bounded RTP queue and one bounded
HEVC fragment chain. Each poll performs at most one frame/admission/media step.
Parameter-set syntax, picture grouping, HEVC decode surfaces and HEVC archive
publication are still outside this slice; reconstructed NALs are not frames.

## Verification

The focused public API tests are in `rtsp_hevc_session_contract.rs` and
`rtsp_hevc_client_contract.rs`:

```sh
cargo test -p fss-reference --test rtsp_hevc_session_contract --test rtsp_hevc_client_contract
cargo test -p fss-reference --test rtsp_client_contract
```

This is an implemented reference transport slice of comprehensive-plan sections
9.3 and 12.4, not a completed device adapter, HEVC decoder, recording product, or
qualification gate. The implementation environment has no Rust toolchain; no
passing Rust build/test/format/qualification receipt is asserted by this change.

Protocol basis: RFC 7798 sections 7.1 and 7.2. No new canonical durable format.
