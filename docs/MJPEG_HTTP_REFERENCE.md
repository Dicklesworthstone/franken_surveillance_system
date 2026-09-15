# HTTP response bytes to source-mapped MJPEG entities

`fss_codec_mjpeg::http::HttpResponseStream` implements the missing HTTP message
framing stage upstream of the existing multipart and JPEG decoder. It consumes
already-authorized plaintext response bytes for one GET. It does not open sockets,
perform TLS, read clocks, send credentials, follow redirects, or assert device
identity. This is a synchronous WP-060 integration component, not a live adapter.

## Implemented response handling

The admitted subset is HTTP/1.0 or HTTP/1.1, status 200, a required Content-Type,
and absent/identity Content-Encoding. Fixed Content-Length, exactly one chunked
transfer coding, and close-delimited bodies are supported. The owner narrows
explicit limits on header/trailer bytes, returned fragments, chunks, wire bytes
and entity bytes. No whole live response is buffered. Interim responses, other
statuses, coding chains, compression, folded lines, bare LF, ambiguous or duplicate
framing fields, and framing overrides nominated by Connection/Trailer are refused.
Repeated unrelated header fields are retained without interpretation.

Chunk sizes use checked u64 arithmetic, including on 32-bit targets. Token and
quoted-string chunk extensions are parsed but remain uninterpreted source text.
Chunk data must be followed by CRLF. Bounded trailer fields are retained separately;
framing, authentication, representation and other forbidden trailer fields cannot
replace accepted headers. These deliberate admission restrictions are narrower
than a general-purpose browser or HTTP proxy.

Every push stops at one Head, Data or Control event. The caller retains any input
suffix and ALL emitted wire records. Data has identical byte content in both its
plaintext response range and transfer-decoded entity range; chunk framing is never
mixed into image bytes. The entity source identity derives from the original stream
basis and the exact response-header digest. It must not be confused with TCP/TLS
packet offsets or the original transport's custody record. Capturing those upstream
relationships remains the authorized transport owner's job.

Data events are validated transfer prefixes, NOT whole-message success. A later bad
chunk delimiter or truncated trailer can invalidate response completion after useful
image bytes have already arrived. `finish` distinguishes explicit framing from
close-delimited EOF: HTTP alone cannot distinguish an interrupted close-delimited
body from an intended close. Downstream multipart closure and complete JPEG decoding
remain separate checks. A zero-byte push is not EOF; explicit-length completion
stops before a following response, leaving those bytes with the caller.

Any error latches. `HttpFailure` reports the exact accepted prefix and next offset.
`abort` returns buffered unexposed bytes without allocation or spare work; previously
emitted records stay caller-owned. Cancellation cannot produce a partial successful
record. A failed stream never searches for a convenient new header or JPEG marker.
Debug/error output does not print header values, cookies, credentials or image data.
Source hashes and receipts are not authentication, persistence, calibration or a new
registered canonical wire format.

## Verification

```sh
cargo test --locked --offline -p fss-codec-mjpeg --test http_contract
python3 -B scripts/test_mjpeg_http_reference.py
```

Thirteen authored Rust tests cover three body-framing modes, every fixture fragment
size and two-way split, byte-for-byte wire reconstruction, source-map and identity
goldens, conflicting framing, status refusals, malformed suffixes, every truncated
prefix, exact limits, cancellation/abort, next-response isolation and 32-bit-safe
large lengths. Rust compilation/execution remain NOT_RUN in the authoring container,
which has no Rust toolchain. No release or broader feature gate is closed.

Eight independent Python controls passed. They compare binary response bodies with
Python's HTTP client for 768 cases and 300 randomized chunkings, verify exact source
maps and the entity-basis golden, and exercise truncation and close-delimited loss.
They are reference checks, not execution of the Rust implementation.

Primary protocol reference: RFC 9112 sections 4-8,
https://www.rfc-editor.org/rfc/rfc9112.html . No source implementation was copied.
