# HEVC RTSP negotiation

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

The focused public API tests are in `rtsp_hevc_session_contract.rs`:

```sh
cargo test -p fss-reference --test rtsp_hevc_session_contract --test rtsp_client_contract
```

This is an implemented reference transport slice of comprehensive-plan sections
9.3 and 12.4, not a completed device adapter, HEVC decoder, recording product, or
qualification gate. The implementation environment has no Rust toolchain; no
passing Rust build/test/format/qualification receipt is asserted by this change.

Protocol basis: RFC 7798 sections 7.1 and 7.2. No new canonical durable format.
