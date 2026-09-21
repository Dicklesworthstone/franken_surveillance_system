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
```

Compilation, Rust tests, rustfmt and Clippy were not run in the authoring
environment, which has no cargo/rustc. Static checks do not qualify this path,
assert live-device compatibility or close a requirement/gate.
