# Interrupted AVC capture: verified-prefix preservation

`fss-capture-rtsp` preserves an already-collected, source-verified AVC prefix when
its native socket read fails abruptly. It uses the original approved archive,
source generation, timing, independent pin journal and resource ceilings. No
additional capture option, new destination or automatic retry is introduced.

## What the operator observes

The existing `window_accepted` receipt is followed by `source_interrupted` when
the native owner has closed its socket and admitted the verified prefix. Neither
receipt asserts durability. The existing candidate-pin, work-confirmation,
`window_durable` and `catalog_published` barriers still apply in their normal order.
The driver starts its already-approved bounded storage drain and prepares no more
RTSP commands or credential responses. It does not call an owner-stop operation to
turn a failed source into a successful recording.

After a complete drain, the terminal report remains unsuccessful with
`ERR-CAPTURE-RTSP-SOURCE-001`. Its durable-picture/window counts and snapshot refer
to actual completed publication. `complete`, `peer_eof` and `input_end_observed`
remain false for the reset case. An unresolved keepalive remains
`unsettled_request`; durable media does not establish that the remote command
completed. This error is not promoted to a reconnect or campaign continuation.

Preserve stdout JSONL and both stores. Durable window/catalog receipts can be used
with the existing retained-import workflow. A storage failure instead retains its
original pending work and journal references for explicit recovery; do not assume
that every observed picture became durable merely because preservation started.

## Admission and ownership

Only typed abrupt *read* failures are eligible. Authentication, authority,
revocation, deadline, budget, protocol and write failures retain their prior
failure behavior. An untimed picture, undrained event or existing ready window
prevents this finalization path. The original-source verifier must accept all
selected complete pictures, their original timing and whole source datagrams.
There is no guessed EOF, repaired packet, truncated datagram or inferred timestamp.

`UnsealedRecording::prepare_verified_prefix` also exposes pure offline preparation
for a caller that still owns its original retired collection. Success returns an
immutable prepared recording, the exact remainder and the original stop reason.
Refusal returns the entire input unchanged. The caller supplies its original
scope and time scale; this container is not an independent sensor/clock authority.
Preparation alone is not publication. Live finalization reuses this same verifier
and the original writer rather than a second publication path.

## Tests and limits

`bash scripts/qualify_rtsp_keepalive.sh` runs the native prefix-recovery, actual
TCP-reset and capture-process contracts alongside the existing regressions. The
RST fixtures use bounded loopback sockets and zero-linger close, not injected
network errors. They cover single-NAL and fragmented AVC, short socket reads,
independent pin ordering, cold source/media reopening, an empty reset, and a real
capture process whose keepalive is left unacknowledged.

This is AVC-only preservation of a completed prefix still present in memory. It
does not make uncheckpointed memory survive a process crash, qualify a physical
camera, recover an incomplete picture, provide HEVC parity, prove scene continuity
or authorize a release. Existing independent storage cancellation, finite work,
storage-pause and publication deadlines remain effective after socket retirement.
