# Native HTTP recording owner

`fss_reference::ingest::http_recording::HttpRecording` connects an explicitly
selected camera route to the existing original-wire archive, optional native JPEG
decoder and root-last completion publisher. This is an executable synchronous
reference composition, not a new runtime, journal, source format or event authority.

## Data path

Construct `HttpRecordingRequest` from an exact source generation, receive-clock
identity, raw-header/media retention scope, literal peer, Host mapping and non-secret
path. `connect` validates complete bounds and re-verifies the source's EMPTY archive
namespace before attempting TCP. An existing generation is a recovery task: the
owner never reconnects or appends newly acquired bytes to a previous connection.
The caller provides current camera and original-byte storage/disclosure authority.

`poll` performs one bounded native source/parser step. It stops at:

- `WirePrepared`: independently retain the exact expected `HttpWirePin`, then call
  `commit_wire`. Original bytes are staged and published durably before the existing
  camera's parse barrier is acknowledged. There is no manual responsibility-only
  acknowledgement method on this composition.
- `FrameReady`: call `take_frame` with the exact opaque source/ordinal/hash key.
  Every original JPEG span is re-read from the existing archive before transfer.
  Optional grayscale or Y/Cb/Cr luma decoding validates the complete native JPEG,
  not just its dimensions. Returned originals can feed the existing RGB pipeline.
- `CompletionPrepared`: native HTTP AND MIME have finished and all frames were
  transferred. Retain the terminal pin before `commit_completion` publishes every
  original-read root and the actual ending. Only then does `Complete` apply.

There are no hidden reads while wire or frame work is held. Independent source,
framing and decoding budgets are recording-wide, not replenished per frame/retry.
The frame ceiling admits exactly the requested number; one bounded lookahead part
can prove excess but is never transferred. Capacity, timeout, missing EOF, corrupt
JPEGs and cancellation never become clean completion or absence of objects.

## Interrupted work

A wire storage failure keeps the exact prepared key and original read. Storage may
have staged/visible effects; reopen a poisoned publisher and reconcile/retry the
original prepared pin, never silently start another camera generation. Earlier root
cut points may require explicit orphan-temp repair. The recording owner performs no
repair or cleanup. A successful publication is returned separately from a late
camera-acknowledgement refusal, so the disk write cannot disappear behind that error.

A final frame-release refusal retains both the original frame and accepted decode
result. `retire` closes the connection without another request and transfers every
raw buffer, parser remainder, held frame, accepted decode, pending wire/terminal
plan, durable prefix and work counter. Dropping it is not proof that unfinished
source was retained. Synchronous bounded codec/filesystem calls are not forcibly
preempted mid-call; this is not a hard-real-time deadline claim.

## Scope and qualification

The admitted source route is owner-approved plaintext only. There is no DNS,
authentication, credential transport, redirect, TLS fallback, reconnect, arbitrary
URL or discovery scan. It is not authenticated-camera identity or a production
Asupersync service. Receive times do not become capture times. Neither native decode
nor durable completion authorizes event publication, alerts or a coverage claim.

This advances the source/recording/replay path of FSS-019/FSS-120/FSS-135 and the
WP-060 media path. `cargo test -p fss-reference --test http_recording` contains ten
native single-thread loopback/filesystem contracts, including all three HTTP
framings, durable-before-parse ordering, cold recovery, exact frame ceilings,
publication cuts, lost returns, stale keys, revocation and retained decoded work.
Rust compilation, tests, rustfmt and Clippy were NOT RUN in the editing environment:
no Rust toolchain is installed. Supplementary static/model checks are not native
qualification. No Bead or release gate is closed by source presence.
