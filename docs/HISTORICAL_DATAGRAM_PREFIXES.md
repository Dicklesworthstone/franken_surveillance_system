# Historical source prefixes during continued capture

`rtsp::datagram_archive::prefix::DatagramPrefix` makes an independently pinned
older source prefix available to existing native replay and recipe APIs while
its camera namespace contains later observations. It is a read-only selection,
not a second source format, shortened capture history, or mutable latest pointer.

`recover(publisher, scope, limits, selected, cancellation, work)` first uses the
ordinary `DatagramArchive::recover` to verify the complete current chain and every
original payload under independently supplied limits. The selected root, source
scope, observation count and cumulative byte count must match an actual position.
It then keeps only the selected metadata in a privately owned read view. Neither
the publisher nor a separate capture writer is changed. The wrapper has no mutable
archive accessor, write method or conversion into a writable truncated owner.

`pin()` is the exact replay input. `observed_head()` is the complete chain head
verified when this view was recovered. They must not be conflated: newer packets
are excluded from the old recipe's source, interpretation and output identities.
Even an empty selected prefix can coexist with a nonempty observed namespace.
`archive()` exposes the existing immutable source APIs. Per-observation reads
reverify current bytes and refuse ordinals beyond the selected prefix.

`revalidate` checks the whole current namespace again and accepts only descendants
of the previously observed head. Thus an attempt cannot use its old selected pin
to silently accept rollback or a fork in later work it already observed. It returns
the newly verified head without changing either frozen identity. Loss of all such
independently retained later pins still requires a protected external rollback
anchor; checksums and source metadata do not provide authentication by themselves.

This path does NOT ignore problematic descendants to salvage an older prefix.
Missing intermediate roots, corruption, tombstones, unresolved temporary roots and
scope conflicts still refuse ordinary recovery, even when they occur later than
the selection. Limits and work cover the whole current chain; bounds that fit only
the old prefix do not authorize reading an arbitrarily large newer history. No
repair, deletion, new camera session or fallback source is introduced. Individual
filesystem calls retain the existing owner's cancellation and durability boundary.

The source-store tests use real filesystem publication and reopening for cold
historical selection, empty input, simultaneous independent append ownership,
exact pin fields, corrupt descendants, missing roots, rollback, every publication
crash cut, external ceilings and cancellation. They are authored Rust contracts,
not executed passes in this environment, which has no Rust toolchain.

```sh
cargo test -p fss-reference --lib rtsp::datagram_archive::prefix
```
