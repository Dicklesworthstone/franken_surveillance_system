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

## HTTP to decoded images and the property-image pipeline

`http_mjpeg::HttpMultipartStream` consumes actual `ResponseHead` and `EntityData`
objects produced by `HttpResponseStream`. It takes the multipart boundary from
that exact response, checks response and entity identity and consecutive offsets,
and invokes the existing MIME parser. Each push borrows the original data event,
accepts at most one part, and reports the consumed entity prefix. Several MIME
frames in one HTTP fragment are handled by submitting the remaining suffix of
that same event. The caller always retains the original HTTP records, even if
MIME parsing, map construction or decoding fails later.

`HttpJpegFrame` couples an existing `MultipartFrame` with a complete, ordered map
from its JPEG payload offsets to the original plaintext HTTP response ranges.
Chunk headers, CRLF, trailers and MIME delimiters never enter JPEG payload maps.
Adjacent map runs coalesce only if BOTH domains are contiguous and the chunk
identity agrees. This makes network fragmentation independent of source mapping
without merging across actual transfer overhead. The configured run ceiling is
1..=65536, applied to complete retained lineage; overflow fails instead of
truncating a map. Older run storage is released after frame publication, not
retained for the duration of an unbounded camera connection.

Mapping/cancellation failure after MIME framing retains the completed but
unexposed frame for `abort`; the input HTTP event also remains caller-owned.
The same applies to final MIME completion. Successful `finish` requires the
matching HTTP end receipt AND successful MIME closure at that exact entity
length. The HTTP termination classification survives unchanged. A complete JPEG
or MIME delimiter does not manufacture a successful HTTP termination. None of
these process-local public records authenticates the original transport or
substitutes for existing persistent custody/publication contracts.

`fss_twin::mjpeg::http::detect_http` checks the independently expected HTTP stream
identity and original frame hash before reusing `detect_multipart`, JPEG decoding,
rectification and frozen-background foreground analysis. The result borrows the
HTTP/MIME frame alongside its image analysis so the full wire relationship is
not discarded. Camera capture time, mask, calibration, image domain and semantic
contact claims remain separate explicit inputs. No model labels or clock values
are inferred from a response header. No production dependency is added.

## Executable composition and verification

```sh
cargo test --locked --offline -p fss-codec-mjpeg --test http_contract --test http_mjpeg_contract
cargo test --locked --offline -p fss-twin --test http_mjpeg_pipeline_contract
cargo run --locked --offline -p fss-codec-mjpeg --example decode_http -- RESPONSE SHA256 grayscale 4096
python3 -B scripts/test_mjpeg_http_pipeline_reference.py
python3 -B scripts/test_mjpeg_http_native.py
```

The read-only file harness bounds and hashes the actual response bytes, streams
those bytes through HTTP/MIME/JPEG, and emits only genuinely decoded frame
receipts plus exact JPEG/wire maps. Its final completion line requires every
frame and both framing layers to succeed. This is an owner-operated replay
harness, not a new registered fss/1 operation or live network/device service.

Nine additional codec composition contracts cover all response modes, every
fixture fragment size, one-byte HTTP chunks, several MIME parts in one data
record, EOF-finalized delimiters, original-byte map reconstruction, decoder
agreement, source changes, partial-publication cancellation and mapping overflow.
Two twin contracts compose chunked response bytes through actual compressed-frame
analysis and check mask preservation and stale-response refusal. Together with
the first increment there are 24 authored Rust contracts; none has executed here.

Six independent Python composition checks passed, including standard-library
HTTP and MIME decoding, actual encoded JPEG decoding through the laboratory
Pillow oracle, 300 randomized source-map comparisons with a per-byte-origin
oracle, missing MIME termination and exact compressed-input identity. The
native driver's golden luma digest comes from the independent Q14 reference
calculation. Its actual invocation returned NOT_RUN (exit 3) because Cargo is
absent. Native compilation, Rust tests, live transport ownership, authentication,
TLS, reconnection, H.264/HEVC, semantic/contact inference and real footage/field
qualification remain open. These reference tests do not close any release gate.
