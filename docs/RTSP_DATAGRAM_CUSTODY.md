# Retain interleaved source before a recording seals

`rtsp::datagram_archive::DatagramArchive` persists original complete RTP and RTCP
datagrams using the existing exclusively owned `LocalRootPublisher`. It preserves
packets before there is a complete picture, IDR-led recording window or archive
catalog. Each small root binds original bytes, channel, parser-completion receive
time, observation ordinal and predecessor. It is not a second media journal.

## Source prefix and authority

Supply an exact `DatagramScope`: TCP route and stream key, selected RTP/RTCP channels,
receive-clock identity and explicit evidence authorizing original-media/RTCP
retention. The supplied publisher and cancellation probe are the actual I/O and
retention capabilities; scope fields do not grant access. RTCP may contain private
participant metadata. Scope commitments include route/SSRC/channel/clock/policy,
but route strings are not written into the metadata objects. Rebinding those fields
cannot escape occupied slots for the same ingress/generation. A new connection
requires an explicitly new source epoch, never an implicit retry under an old one.

The public preparation API accepts an opaque `InterleavedSource` from the existing
AVC client. It does not accept RTSP control bodies, credentials, session tokens or
Digest challenges. Original TCP chunks and incomplete interleaved frames remain a
separate retention/omission obligation. This is not complete raw-TCP preservation.

`prepare` performs no I/O and borrows source bytes. Retain its candidate `pin()`
independently when protection against archive rollback is required. `publish`
stages the original payload, then metadata, then the exact immutable root. Only
an actual local-durable receipt advances the in-memory prefix. Staged children or
a root whose acknowledgement is lost are not acknowledged as successful by the
failed call. The typed publisher error and unchanged source plan remain available.

Retry the SAME prepared plan to repeat an attempted publication. Preparing another
identical datagram creates another observation. Retransmissions, duplicate RTP
sequences, equal receive times, probation packets, invalid RTCP and zero-byte
interleaved datagrams are not coalesced into one source observation. The archive
does not reinterpret packet syntax or invent a coverage gap from malformed RTCP.

## Recovery and source replay

`recover` rehashes the whole currently durable namespace, in contiguous observation
order. It rejects intermediate holes, conflicting scopes, malformed slot names,
wrong object families, extra graph children, source corruption, tombstones and
unresolved temporary/broken roots. It never repairs or deletes storage. Supplying a
minimum `DatagramPin` requires that exact prefix, allowing explicitly reverified
descendants after a lost acknowledgement. Without a minimum, the caller trusts the
selected protected local store's current inventory; checksums alone do not defeat
rollback or replacement of that entire store.

`read` re-verifies one original datagram and its metadata. `DatagramReplay` reads
at most one observation per step with an independent total output allowance,
absolute storage deadline and cooperative work/cancellation budget. A failed
read stops that replay attempt. Stored receive times are returned unchanged and
are not substituted for the current storage clock or camera capture/DTS time.

The terminal replay result is `PrefixExhausted`, NOT codec or transport EOF. A
crash can leave a durable prefix ending inside an RTP fragmentation unit or an
incomplete picture. Replay must not automatically call a codec's finish method,
synthesize a final frame, or claim continuous recording. Configuration, SPS/PPS,
remote session, timing decisions, authority and privacy are not restored by this
source-only prefix. Source bytes remain useful for explicit later reconstruction
and diagnostics under separately verified configuration and authorization.

## Native capture and recording integration

`datagram_archive::live::RetainedAvcRecording` wraps the existing native
`LiveAvcRecording`. Supply its normal live/recording configuration, exact datagram
scope, independent source limits, an already-open publisher, live TCP authority,
storage cancellation and cooperative work allowance. The route, channels and
receive-clock interpretation must match before a connection is attempted. An
occupied source namespace is refused rather than silently extending it with a
new connection under an old epoch.

Poll with explicit readiness, current time, authority and the same publisher.
Every complete RTP/RTCP source event, including failed RTP admission and invalid
RTCP, is published before returning that event or polling the subsequent media,
picture-timing or recording-window result. The original protocol admission and
validation results remain unchanged. Source storage is performed only on a
protocol-output step, with no socket read/write during that publication. There
is no additional source queue, mutable bare-capture escape or next-packet read
ahead around a pending source write.

`RetainedRecordingStep::datagram` contains the actual local root receipt only for
an original interleaved datagram. `None` on a raw TCP chunk, control response,
prepared window or terminal output does not claim source custody for that item.
RTSP control messages and credentials are never copied into this datagram store;
raw TCP chunks remain explicit caller-owned outputs with their separate
retention/omission obligations. Original RTCP can contain private participant
metadata and must be authorized by the supplied retention policy.

The publisher is supplied per poll, not held through an exclusive lifetime borrow.
A caller can therefore publish a returned `PreparedRecording` through the existing
`RecordingPublication` using the same storage owner between polls. Normal source
objects and window payloads retain their existing formats. The datagram roots do
not substitute for recording publication or archive indexing. DTS, duration and
composition offset still require explicit timing; a refused timing input leaves
the same picture available for correction. Publication never guesses media time.

Any source-capacity, work, cancellation or storage failure stops live capture and
returns the exact withheld source event, unsealed/capture/network retirement,
last acknowledged prefix and any prepared candidate pin. A root-write error can
mean that the candidate already committed; reopen/reconcile the same storage and
recover that exact prefix rather than recapturing or renumbering it. If storage
commits and the post-I/O live-authority/cancellation check then fails, retirement
also retains the actual successful publication receipt. Neither case is reported
as a successfully delivered media event, complete recording, or synthetic EOF.

Current authority is checked before progress, inside supported publication cut
points and after storage. An admission timestamp is not the elapsed syscall time:
the supplied live probe must enforce real deadline/revocation itself. Existing
protocol, collector and connection deadlines are not renewed by storage. Repeated
calls consume finite work; clock regression is a safe refusal. Cancellation does
not publish, delete source, send a speculative TEARDOWN or reopen the connection.

Eleven additional authored contracts exercise actual loopback TCP and existing
encoded AVC, timing followed by same-owner recording publication, TCP chunk sizes
1/7/4096, incomplete FU-A recovery without a completed picture, repeated RTP,
invalid RTCP, terminal malformed RTP, source-capacity refusal, lost root replies,
post-commit cancellation with a retained actual receipt, revocation, wrong owners,
occupied epochs and replay deadlines. Together with the twelve source-store
contracts, this increment contains 23 authored tests, not 23 executed passes.

## Bounds and verification

Counts, cumulative payload, full publisher scans, object allocations and work are
independently bounded. Capacity refusal does not evict evidence or silently rotate
epochs. Recovery uses the actual spool's allocation ceiling BEFORE reading. Each
root is independent: predecessor commitments do not trigger recursive historical
root descent. Publication can execute several bounded filesystem operations and
is not preemptible inside a syscall; cancellation must enforce live deadlines and
revocation at the existing publisher's cut points. Per-datagram roots are a
correctness-first reference path, not a high-throughput production storage claim.

Twelve authored filesystem tests cover original bytes and timing, cold recovery,
retransmissions versus exact retries, zero/malformed input, all four root crash
cuts, stale owners, prefix rollback/forks, missing roots, scope changes, cancellation,
bounds, corruption, wrong families, extra children and truncated metadata.

```sh
cargo test -p fss-reference --lib rtsp::datagram_archive
# The native-loopback subset is rtsp::datagram_archive::tests::live.
```

Compilation, Rust tests, rustfmt and Clippy were not run in the authoring
environment, which has no cargo/rustc. Static checks do not qualify this path,
assert live-device compatibility or close a requirement/gate.
