# Native owner-authorized RTSP/JPEG input

The JPEG lane composes the existing RTSP session, Digest authentication, exact TCP
framing, native socket owner, RTP reorder owner and first-party JPEG decoder. It adds
RFC 2435 camera reception without another network runtime, archive format or codec.
The admitted image profile and retained independent fixtures are documented in
[RTP_JPEG_REFERENCE.md](RTP_JPEG_REFERENCE.md).

## Exact negotiation and image reception

`rtsp::client::ClientCodec::Jpeg` selects one video media section. Static payload 26
uses its registered JPEG/90000 mapping when rtpmap is absent. An explicitly conflicting
mapping refuses. Dynamic payloads 96 through 127 require JPEG/90000. Multiple JPEG
offers require an exact payload selection; unsupported selected fmtp, clock or channel
fields refuse. Other tracks retain their ordinal positions. The existing URI subtree,
CSeq, Session, transport/channel and expected-SSRC rules remain authoritative.

`rtsp::jpeg_client::RtspJpegClient` accepts bounded caller-supplied TCP chunks and
returns one progress event per poll. It exposes the same explicit request, Digest,
keepalive, deadline, EOF and cancellation lifecycle as the existing session owner.
Every original interleaved frame survives successful admission, probation, duplicate
admission and protocol/media failure. Ordered RTP events preserve the original final
TCP-byte receive time even when packets arrive out of order.

`rtsp::live_jpeg::LiveJpegConnection` owns the real native TCP connection. The caller
supplies an exact resolved peer, route, plaintext approval, stream generation, live
`TcpAuthority`, readiness, monotonic clock, limits and optional borrowed credentials.
Each poll performs bounded semantic work and at most one socket operation. Accepted
original TCP chunks transfer before parsed events. There is no automatic redirect,
DNS lookup, reconnect, credential fallback, detached worker or cleanup TEARDOWN.

## Original source custody and derived pixels

The owner must process each source-bearing event before polling for more progress:

1. Retain or explicitly account for each original `LiveJpegStep::Wire` chunk under
   the owner's separate wire/privacy policy.
2. For the `RtspWireFrame` carried by an RTP/RTCP event or an interleaved failure,
   call the existing `DatagramArchive::prepare_frame` and its existing publication
   lifecycle when original datagram custody is required. It preserves channel,
   parser-completion time and exact datagram bytes. It refuses control responses,
   requests and authentication challenges before work or allocation. No JPEG-specific
   archive or parallel root sequence is introduced.
3. Subsequent `JpegClientPoll::Jpeg` events return ordered originals and reconstruction
   outcomes. A successful marker-completed image still requires pixel validation.
4. Pass the complete frame, independently computed derived-image digest, caller
   limits and cancellable work budget to `jpeg_client::pictures::decode_luma_frame`
   or `decode_rgb_frame`. These run the actual native decoder and retain the packet
   source maps alongside complete pixels. A failed decode returns the intact
   reconstruction and typed refusal; it never returns partial pixels.

The JPEG digest identifies the derived interchange image, including generated JPEG
headers. It cannot replace original RTP source identity or authenticated custody.
Cached quantizer definitions may reference earlier original datagrams in the same
epoch; retaining only packets between an image's first and last sequence is therefore
insufficient. The uncalibrated 90 kHz RTP timestamp and parser receive time do not
establish a camera capture clock, physical coverage or synchronized camera time.

## Native verification boundary

The focused target compiles the exact production RTSP, Digest, framing, socket,
JPEG reception and pixel-composition files with their real first-party dependencies:

```sh
cargo test --locked --offline -p fss-codec-mjpeg --test rtsp_jpeg_contract
```

Its contracts exercise static and dynamic negotiation, source binding, byte-wise TCP
fragmentation, packet reorder/loss, RTCP failures, cancellation, borrowed Digest
credentials and complete native luma/RGB decoding. Real loopback sockets exercise
short reads/writes, live authority, original-wire ordering, authentication queue
failure and EOF draining. No protocol, socket, packet or pixel implementation is
replaced by a stub, and no foreign process runs in these tests.

This bounded native lane does not certify a physical camera, durable archive
publication, a capture CLI, camera calibration or the full reference/release matrix.
