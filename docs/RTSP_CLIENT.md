# Scoped RTSP client and AVC receive path

Status: implemented reference source with scoped passing Rust contract tests.
Owner-supplied Digest authentication is opt-in; real-device qualification remains
outstanding. This advances FSS-047/FSS-111 and WP-050 without closing live I/O,
device-matrix, or release qualification gates.

## Functional path

`fss_reference::rtsp::client::RtspClientSession` composes the existing RTSP/1.0
message and SDP parsers with explicit OPTIONS, DESCRIBE, SETUP, PLAY, keepalive,
and TEARDOWN states. `rtsp::avc_client::RtspAvcClient` adds bounded TCP framing,
negotiated RTP/RTCP routing, and the existing loss-aware `AvcReceiver`.

The path is:

```text
owner-supplied authorized TCP bytes and monotonic time
  -> existing incremental RTSP parser
  -> exact CSeq/session/transport and scoped SDP admission
  -> original RTP/RTCP datagram receipts
  -> ordered RTP, complete NALs, and parameter-bound AVC picture groups
```

There are no sockets, workers, ambient clocks, foreign runtimes, implicit retries,
or automatically broadened network permissions. The unauthenticated path retains
no authentication secrets; the opt-in Digest path borrows owner-supplied credentials.
Only the already-local `fss-packet` dependency moves from development-only into
the reference composition. A PLAY acknowledgement is not a first-frame,
continuity, retained-custody, decoded-picture, or coverage certificate.

### Opt-in Digest authentication

The client pins the expected realm and explicit algorithm/qop policy before signing.
It accepts the parser's typed `AuthRequired` response for a complete 401 challenge;
public parser output remains redacted. The credential-owning adapter validates the
original wire challenge separately. Retries preserve the original response deadline,
advance CSeq, and refuse wrong realms, proxy authentication, implicit downgrades,
and nonce replay. Neither a challenge nor its `domain` field broadens the authorized
request target. Authentication does not grant transport or effect authority.

## Driver contract

The owner supplies a credential-free presentation URI, an explicit control URI
subtree, one video media index, offered consecutive TCP channels, request and
session time limits, and a nonzero ingress/stream epoch plus expected SSRC.
Same-authority control URLs are resolved under the declared subtree. Redirects,
userinfo, traversal, ambiguous duplicate fields, unsupported transport changes,
and audio selection are refused. Session tokens and URLs are omitted from Debug.

Prepare one request with `request(command, now_ns)` and write its exact bytes
through the separately authorized transport. Preparation reserves the CSeq and
deadline but does not prove transmission. Do not resend it blindly after a
partial write or lost response. Close/reconcile the old connection and retain
its remote-session uncertainty before a new owner generation is opened.

Feed chunks of at most 4,096 bytes to `ingest`; poll between feeds. `poll` returns
at most one visible step. Continue until `Pending` with no immediate wake,
`Backpressure`, `KeepAliveDue`, a fault, or terminal EOF. An immediate Pending
wake requires another poll. Honor `next_wake_ns` even without incoming traffic.
On `KeepAliveDue`, issue the explicit KeepAlive command (OPTIONS) or close;
repeated polling does not send requests. A backpressured original RTP frame
stays owned by the pump until ordered delivery makes space. No retry input is
copied over it and no sequence is consumed by a capacity refusal.

The parser's partial buffer is bounded at 135,168 bytes and a partial message
has a fixed five-second lifetime. A late completing byte cannot erase expiry.
Session lifetime is conservatively measured from request preparation, not from
a delayed acknowledgement. Informational responses do not extend deadlines.

## Negotiated subset and media semantics

The client admits one selected H.264 video format at 90 kHz, packetization mode
zero or one, and exactly one out-of-band SPS/PPS pair. Optional profile-level-id
must agree with that SPS. The real AVC parser validates parameter bytes before
PLAY can start. SETUP must retain the offered unicast TCP channels; a declared
server SSRC must agree with the owner binding. RTP source binding is still not
authentication. Unknown, malformed, ambiguous, or unsupported input fails closed.

Reduced-size RTCP is accepted only when SDP explicitly signals it. Otherwise the
whole conventional compound, including CNAME, must validate. Malformed RTCP is
returned with its exact original payload and typed refusal; it does not invent
a video gap. RTCP clocks remain source assertions, not trusted capture time.

Each RTP admission returns exact original payload bytes even on probation or
late arrival. Later AVC outputs retain their original source spans. Loss,
malformed video, fragment timeouts, and restart propagate through the existing
NAL/picture owners. Fatal framing/session/binding failures retire all buffered
derivatives. Original TCP stream custody, including framing/control bodies and
rejected inputs, remains an independent owner responsibility.

`finish` means TCP EOF, not verified remote TEARDOWN. It stops new admission and
drains accepted complete events before codec EOF. Truncated framing retires
pending derivatives instead of certifying a picture. A final unbounded-by-next-
picture tail remains `EndOfInputUnverified`. `cancel` reports outstanding CSeq,
possible remote session, queued media and framing bytes, and every retained
RTP/NAL/picture derivative. A confirmed source restart closes the old connection;
there is no silent epoch reuse or source identity substitution.

## Reproducible checks

The session file contains 19 tests, including every split of a full DESCRIBE
response, CSeq replay, URL scope, session identity/timeout, malformed transport,
profile agreement, duplicate signaling, lifecycle, and Debug redaction. The
composed client adds 16 tests covering six TCP chunk sizes over real encoded
fixtures, original-source equality, picture counts, negotiated RTCP, early-media
refusal, SSRC/parameter validation, bounded retries, deadlines, deferred parse
errors, EOF, restart, and cancellation. The expected SSRC is owner supplied.

```sh
cargo test --locked -p fss-reference --test rtsp_client_contract --test rtsp_avc_client_contract
cargo run --locked -p fss-reference --example rtsp_avc_replay
cargo clippy --locked -p fss-reference --all-targets -- -D warnings
bash scripts/qualify.sh --lane rust
```

The executable replay uses the retained synthetic baseline and High/B-picture
bitstreams. It prints command metadata, original datagram and NAL hashes, picture
identity/boundaries, timer-driven loss, and cancellation receipts. It opens no
network connection and prints no URI, session token, or raw image bytes.

The scoped RCH run for the Digest event-variant repair passed all 11 Digest client,
12 Digest AVC, 8 authentication, and 68 RTSP parser contract tests. These are reference
fixture results, not live-device or release qualification. Independent Python/FFprobe
fixture checks do not qualify the Rust implementation. Admitted Asupersync socket
ownership, UDP/fallback, ONVIF, real-camera interoperability, codec decoding, and
end-to-end durable archive qualification remain open.
