# Native owner-authorized RTSP TCP transport

`rtsp::tcp::RtspTcpLink` owns one real standard-library TCP connection to an
explicitly supplied socket address. It makes one bounded connect attempt, checks
the peer, configures nonblocking I/O, and transfers prepared RTSP requests and
original response/media bytes. No DNS lookup, alternate address, redirect,
automatic reconnect, retry-on-another-socket, thread, runtime, timer or reactor
is introduced. The existing RTSP/SDP/Digest and codec owners remain separate.

## Authority and lifetime

`TcpBinding` contains the exact stream key, caller-resolved peer, and RTSP
host[:port] mapping. It is a requested scope, NOT an authorization grant.
Every connection, configuration, queue admission and read/write boundary uses
an explicit `TcpAuthority` supplied by the owner. There is no default permissive
implementation. The owner must enforce principal, route, generation, privacy,
revocation, live time and resource permission through its Cx or equivalent.
`TcpSecurityPolicy::OwnerApprovedPlaintext` is mandatory. Digest does not encrypt
media; TLS, Basic authentication, DNS and transport-security downgrade are not
implemented or implied. No third-party camera is discovered or probed.

Queue admission also binds the immutable request target to the exact
owner-approved `TcpBinding` authority. It reads only the first request line and
uses the same URI validator as the protocol owner; a Digest header cannot supply
or override the target. Host spelling, case and explicit ports must match exactly,
consistent with the existing RTSP session scope. The caller-resolved peer address
is not a substitute authority.

A mismatch returns payload-free `TcpError::RequestScope` with the original
`ClientRequest` intact. It is checked before queue retention or send-budget
reservation and performs no socket I/O. The valid route remains usable. Matching
unsigned and Digest requests retain their original wire bytes. This check binds
the request's target authority; it does not add ingress, generation or session
provenance to `ClientRequest`. The owner still enforces those permissions, including
isolation between sessions sharing the same authority.

The owner supplies monotonic admission time and an absolute lease. A connect
attempt uses the smaller of its configured timeout and remaining lease, then
rechecks live authority before any RTSP write. One connect or individual socket
call cannot be preempted by this API. Admission timestamps are not post-syscall
clock observations, camera capture times, or hard-real-time guarantees.

## Bounded dispatch and receipt semantics

Only an existing typed `ClientRequest` can enter the send cursor. The queue
reserves its complete request size against the remaining send budget before
accepting it. A short write advances only the accepted prefix; WouldBlock and
Interrupted preserve the exact remaining suffix. Each call performs at most
one socket operation. Eight consecutive interrupted attempts fail closed, and
all attempts count against the independent I/O budget. A full local socket send
is NOT a matching RTSP acknowledgement or proof that the remote effect happened.

There is one read chunk of at most 4 KiB. No further bytes are read until it is
acknowledged by the next semantic owner. Read bytes retain their original
admission time and fixed residence deadline. Byte/call budget exhaustion is an
error, never fabricated EOF. Live authority is checked again after successful
I/O; any accepted write prefix or acquired read bytes are recorded BEFORE that
check, so a late revocation cannot erase what happened.

Fatal errors and EOF release the owned socket. `retire` transfers exact unread
bytes and the original partially dispatched request with its accepted prefix
length. Even a complete write followed by a failed post-I/O check retains the
unacknowledged request. Never replay it on another connection as though nothing
was sent. Original requests/chunks can contain authentication material; Debug
and errors expose only metadata. No cleanup attempts a new TEARDOWN or deletes
source. The protocol owner must independently account for remote uncertainty.

This transport is an implemented reference slice for comprehensive-plan section
9.3. It is not a new agent effect authority, completed device qualification,
source-custody store, encrypted transport, or runtime/Asupersync integration.

## Validation

```sh
cargo test -p fss-reference --lib rtsp::tcp::tests
```

Sixteen authored contracts cover real loopback TCP, exact partial dispatch,
WouldBlock/Interrupted behavior, pre/post-I/O denial, retained unread bytes,
work and byte limits, EOF versus failure, original deadlines, and debug privacy.
The deterministic I/O seam is private and test-only construction does not expose
an arbitrary-stream injection surface to callers.

The three request-authority regressions cover mismatched hosts, ports, aliases and
case; retained and redacted Digest retries; no socket work or spent send budget on
refusal; and byte-for-byte dispatch on the matching route. Exact source received
independent review. Scoped pinned rustfmt checks passed before the executor became
unavailable, and the captured patches were recovered through GitHub. Native RTSP
test execution remains pending; the shared validation host failed during the earlier
core/ledger build attempts. No camera, full-workspace or release qualification is
claimed. See `docs/SESSION_HANDOFF_2026-11-20_RTSP_AUTHORITY.json` for the exact
validation boundary and retry command.
