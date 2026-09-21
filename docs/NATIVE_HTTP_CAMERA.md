# Native owner-authorized HTTP MJPEG camera input

`fss_reference::ingest::http_camera::HttpCamera` connects one explicitly approved
TCP peer, sends one non-secret HTTP GET, and returns complete source-mapped MJPEG
parts through the existing native HTTP and multipart parsers. It does not spawn
workers, resolve names, retry/reconnect, follow redirects, interpret vendor clocks,
or substitute a foreign codec. This implements a bounded acquisition slice toward
comprehensive-plan sections 9, 12 and 16; it is not production qualification.

## Authority and supported routes

`HttpCameraRoute` binds an exact `SocketAddr`, Host authority, absolute ASCII path,
source-stream identity and generation. `HttpCameraSecurity::OwnerApprovedPlaintext`
is mandatory. This limited transport has no TLS or authentication support. It does
not provide camera identity authentication or confidentiality. Only use it on a
route independently approved for plaintext and an operator-owned/authorized camera.
Query strings, percent escapes, fragments, userinfo and request/header injection
are refused. Cameras needing those forms, credentials or TLS are unsupported;
there is no insecure downgrade or credential-in-URL fallback.

Every network attempt, parsing advance, raw acknowledgement and frame transfer is
checked by `HttpCameraAuthority`. Implement that boundary with the owning `Cx` or
equivalent explicit capability. The implementation must check the exact route,
principal, generation, current authorization/revocation, cancellation, independent
resource allowance and actual elapsed deadline. The supplied `now_ns` is admission
time, not evidence of the clock after a syscall. Connect is bounded by both the
explicit timeout (at most 60 seconds) and the remaining lease. Reads/writes are
nonblocking and perform at most one syscall per `step`; readiness waits belong to
the caller. No permissive live authority is provided by the library.

## Source preservation and backpressure

The progression is one request prefix or one raw read or one framing operation per
call. A `WireReady` result names exactly `pending_wire()` with original response
range, SHA-256 and read-admission time. The owner must save/handle those exact raw
bytes BEFORE calling `acknowledge_wire`. No further read or parse can overwrite an
unacknowledged read. An acknowledgement is acceptance of a custody obligation,
not a storage receipt, durable publication or assurance that source bytes survived
an OS/process crash. Use an authorized persistent storage owner when required.

The existing HTTP parser handles fixed length, chunked and close-delimited
responses, rejects unsupported statuses without following redirects, and preserves
entity-to-wire correspondence. The existing MIME parser validates delimiters and
part lengths. `HttpJpegFrame::source_spans()` maps every JPEG byte to the original
plaintext-response bytes, excluding transfer/MIME overhead. Raw acknowledgements
cover those overhead bytes too. Framing does not establish successful entropy
decode; the existing native `HttpJpegFrame::decode` or image pipeline must do that.

`FrameReady` blocks further input until the exact ordinal and encoded hash are
passed to `take_frame`. Keep the returned frame while downstream inference or
publication is pending. No timestamp is inferred from an ordinal, header string,
receive time, or pixel appearance. A downstream temporal processor must receive
independently established capture intervals and a clock generation.

## Failure and end semantics

A read returned by the OS is retained and counted BEFORE post-read authority is
revalidated. Thus cancellation/revocation immediately after I/O closes the socket
without erasing accepted source. Likewise, an already sent request prefix remains
accounted for after a post-write refusal. Parser failures are terminal because a
prefix may already have been consumed; never replay it with a new work budget.

`retire()` closes locally without another HTTP command and transfers all remaining
raw, HTTP-entity, MIME and frame objects, exact parser positions, partial request,
first failure and any completed termination receipts. It requires no new budget,
I/O or authority and provides the recovery route even after cancellation. Earlier
acknowledged bytes remain the caller's responsibility. No background finalizer,
automatic source recapture or mutable retry queue is introduced.

`Complete` requires both HTTP and MIME termination. A true close-delimited socket
EOF remains distinguished from explicit HTTP framing. Missing closing MIME,
exhausted receive/I/O/part allowance, deadline and deliberately stopping are NOT
successful response completion, coverage or negative scene evidence. Reaching
the exact configured frame ceiling stops the owner rather than reading ahead to
find out whether more frames exist. A prefix of valid frames remains usable with
its explicit later failure; it never proves a complete recording.

Independent limits cover complete response/entity/chunk/header sizes, complete
MIME frame/header/wrapper sizes, original wire runs, read bytes, syscall attempts,
frame count and finite lease. Existing codec budgets cover HTTP/MIME computation;
network counters account for source hashing and syscall work separately. No
allowance silently resets per frame, scale, wait, interruption or retry.

## Validation

```sh
cargo test -p fss-reference ingest::http_camera::tests
```

Fifteen tests were authored: real native loopback GET through first-party decoding;
source mapping under 1/7/4096-byte delivery and all three transfer modes;
wire/frame backpressure; post-read and post-write revocation; parser cancellation
or work exhaustion; truncated MIME after earlier frames; byte/call/frame ceilings;
WouldBlock/Interrupted handling; route rejection before connect; clock regression;
non-followed redirects; exact wire ceilings versus real EOF; and trailing response bytes.
Scripted sockets are used only to isolate failure
cuts. The loopback test supplies actual socket bytes and the existing real JPEG
fixture, but is not evidence of interoperability with a physical camera.

Rust compilation/tests, rustfmt and Clippy were unavailable in the authoring
sandbox. Source/lexical/hash checks are supplementary, not a green Rust build.
No program bead or acceptance gate is closed by this implementation.
