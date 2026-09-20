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

Thirteen authored contracts cover real loopback TCP, exact partial dispatch,
WouldBlock/Interrupted behavior, pre/post-I/O denial, retained unread bytes,
work and byte limits, EOF versus failure, original deadlines, and debug privacy.
The deterministic I/O seam is private and test-only construction does not expose
an arbitrary-stream injection surface to callers.

Rust compilation/tests/rustfmt/Clippy and qualification remain unrun in this
editing environment, which has no Rust toolchain or network provisioning.
Lexical/delimiter and uploaded-byte checks are not passing Rust execution.
