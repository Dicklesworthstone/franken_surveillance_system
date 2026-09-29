# Durable HTTP reconnect boundaries

`fss_reference::http_reconnect_history::DurableReconnectRecording` composes the
existing native reconnect recorder with the existing immutable object-graph publisher.
It has no mutable inner-recorder escape, new append journal, mutable current-head file,
network retry policy, inferred generation, camera timestamp or event authority.

Each ended connection yields `BoundaryPrepared(pin)`. Save the exact expected pin,
then call `commit_boundary`. The writer re-verifies the selected predecessor history
and every original read of the ended connection, stages bounded canonical metadata,
and publishes its root last. After an actual durable acknowledgement, the owner yields
`BoundaryDurable(pin)`. `release_boundary` re-verifies the entire history after any
external delay before releasing the native recorder's barrier. Failed storage,
output, cancellation or verification never permits the next connection.

The original raw recorder API is unchanged. The wrapper exposes only a shared borrow
of that recorder for statistics; it owns all mutable source/transfer operations. Its
poll budget remains the native recorder's budget. Native source/framing allowances
are unchanged, and a separately declared history-work allowance covers all history
reads/publications across the complete run. Neither allowance resets at a reconnect.

## Immutable format

A boundary is `http_reconnect_boundary_v1`, with canonical metadata beginning with
`FSSHRB01`, version 1 and `fss.http_reconnect_boundary.v1`. Its slot is
`fsshrb1-<64 hex digits of plan identity>-<connection ordinal>`.
Every manifest directly includes its metadata, its predecessor boundary (except the
first), and every original-read root of the current generation. The exact read roots
are never replaced by only a count or the last digest.

Metadata binds the acquisition plan digest, connection ordinal, predecessor root,
source generation, receive-clock and original-retention scope, complete original
prefix, native outcome class, local network counters, terminal admission time,
reserved next generation, backoff and stop reason. Original payload-free failure
text is retained as bounded **uninterpreted diagnostic data**: readers must not parse
Rust diagnostic wording to make a retry, authorization or classification decision.
Control-bearing outcome and stop tags have fixed versioned encodings.

Setup failures with no accepted response bytes are still real boundaries. Once their
root is published, the session namespace is occupied even though no wire-read root
exists. A new recorder refuses occupied/broken/orphaned session slots before the
first TCP attempt. Later reserved slots are rechecked while awaiting connection,
not leased indefinitely by an earlier empty check.

The constructor takes an explicit admission time and the existing native plan's
absolute deadline. All generation/clock integers retain their complete 64-bit values.
No policy, budget or clock value is recovered by guessing from a prior capture.

## Cold verification

`VerifiedReconnectHistory::load` takes an independently saved `(session, root,
connections)` pin, live original-custody read authority and caller-owned work budget.
It traverses at most 32 boundaries iteratively. Every selected boundary's family,
metadata, canonical encoding, source prefix and exact direct children are checked.
Parent ordinals, planned next generations and backoff order must agree. Source reads
and bytes are aggregated before any complete result is returned. Independent limits
cap the history at 8192 reads and 512 MiB, with a bounded per-generation source reader.
A missing parent, changed metadata/source, tombstone or budget failure rejects the
whole result. No successful partial history or inferred latest head is returned.

Verification means that the selected local archive-writer statements and original
source are retrievable through the existing publisher. It is not a signature or proof
that a foreign writer was honest. The caller must select the trusted root independently.
A verified prefix does not prove that the run ended, that there was no later attempt,
or that a reserved next source was actually connected. A native-complete boundary is
not an `HttpCompletionPin` and cannot authorize replay to invent socket EOF.

A requested frame-count stop, process death or failure before a native boundary can
leave only an earlier history prefix plus a current wire prefix. These are reported
separately, never collapsed into complete capture or continuous physical coverage.
Original HTTP headers/media remain private unencrypted local custody. History neither
exports nor encrypts them and never grants access, resumes acquisition or changes
retention/deletion policy. Retire transfers all unfinished source and the exact pending
boundary identity without extra I/O. Reconcile an ambiguous pin against storage; do not
reacquire the same generation or silently discard an orphaned publication.

## Validation

Native tests cover real loopback truncation followed by a fresh generation, durable
barriers, cancellation before publication, idempotent publication, cold reopening,
exact verification-work limits, corrupt metadata preventing reconnect, byte-empty
setup failure, malformed metadata, every truncated encoding, parent/generation drift
and integer extremes. Run:

```sh
cargo test -p fss-reference http_reconnect_history --locked --offline
```

Rust compilation, native tests, rustfmt, Clippy and full qualification were not executed
in the implementation environment: it has no Rust toolchain. Source/hashing checks are
not substitutes for those lanes. This reference implementation does not close any bead
or establish device, detection, timing, availability or production qualification.
