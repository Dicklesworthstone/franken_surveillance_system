# Crash-recoverable evidence disclosure

`agent_session::checkpoint::journal::disclosure::DurableDisclosureStore` owns a
session store and its hydration catalog together. Successful evidence delivery
commits the cumulative token charge, cursor issuance/consumption snapshot, and
request/response admission identities in **one existing session-journal record**
before returning the response. This includes source-backed context expansion,
not just cached previews. No source payload is written to this journal.

## Use one exclusive owner

Create the journal with `DurableDisclosureStore::create`, supplying the existing
`DurableSessionLimits` and an authority-projected catalog with no issued cursors.
Open a projected session with `open_session`. Use `bind` and the ordinary
`hydrate` / `hydrate_from_source` APIs, or pass an exact published context slot to
`hydrate_context_slot` / `hydrate_context_slot_from_source`. Local-source variants
borrow the existing lock-owning `LocalRootPublisher` and its `SpoolIo` capability.
They do not open, repair, or substitute another custody owner.

The wrapper never exposes mutable session or catalog access. Its registration
methods are trusted runtime boundaries, not agent-facing requests. Source and
context APIs reuse their existing principal, lease, exact descriptor, privacy,
full-vector budget, and continuation checks. Historical source verification still
uses `SourceObjectBinding::validate_response` or
`BoundContextHydration::verify_source_for`; a journal root does not prove current
custody or that a preview is original source evidence.

Use a dedicated session-only journal with this owner from the first disclosure.
Do not alternate it with legacy `DurableSessionStore` hydration. Existing work-
claim/case-journal hydration APIs are unchanged and are **not upgraded** by this
feature. Migration of already-issued legacy cursors or coordination histories
into this owner is not provided. The path and parent directory still require
exclusive, protected ownership; this reference adapter is not an interprocess
locking service or a production database integration.

## Failure and recovery semantics

A successful call returns `JournaledDisclosure<T>` containing the ordinary typed
response, historical `DisclosureAdmission`, and exact committed journal root.
The trusted runtime must retain/pin the root independently of the journal.
Admission means the result passed checks and was committed, **not** that a remote
recipient acknowledged receiving bytes.

A refusal may advance the trusted session clock or tombstone an expired session.
Those changes persist, but no token charge or staged cursor mutation is published.
A failure while preparing or appending a successful admission fences the owner
and returns no response payload. A complete append followed by a lost sync/ACK
can nevertheless have committed both the charge and consumed cursor.

For an in-process uncertain append, use `reconcile_pending` with an explicit tail
policy. A committed outcome installs both charging and replay protection; an
uncommitted outcome preserves the predecessor. Neither outcome redelivers source,
refunds tokens, or automatically retries. Capacity exhaustion without an attempted
append requires reopening the verified prior root after resolving capacity, not
pretending there is a pending write to reconcile.

For process restart, rebuild the **current** authoritative descriptors, preview
artifacts, and source bindings; then call `open_existing` with the independently
trusted exact root. Only cursor metadata is recovered into the catalog. The
runtime does not recover obsolete authority from a historical descriptor or keep
a second source cache. A torn final append requires `recover_existing` with an
explicit policy and independently authorized committed-prefix root. Complete
newer records are never discarded to satisfy an older root.

`admissions` queries a bounded set of committed invocations for an exact request
under its live owning session. This supports lost-acknowledgement inspection
without reading source again. Identical non-continuation requests remain separate
charged deliveries; they are not free idempotent retries. A spent continuation
remains spent after reopening. Closed or expired sessions do not gain audit access
through this session-facing lookup.

## Durable representation and validation

The existing session-checkpoint record kind carries a versioned disclosure
wrapper containing a normal session checkpoint, bounded checksummed cursor
metadata, exact predecessor checkpoint digest, and admission identities. It does
not add a second canonical evidence ledger or a new public hydration protocol.
Old readers that only understand plain checkpoints reject the wrapper.

Replay reconstructs the successful session clock/charge transition and compares
the exact resulting checkpoint. Cursor replay rejects live-record loss, changed
issuance identity, consumed-to-active rollback, cross-session mutation, and
issuance/consumption not named by the recorded invocation. Record/byte ceilings
fail closed and never evict live replay tombstones. Zero-token, same-clock reads
still create records because they can issue or consume cursors.

## Validation boundary

Focused regression tests cover restart, each journal append fault stage,
explicit cold recovery, stale root refusal, zero-cost cursor issuance, error-side
clock persistence, journal capacity, repeated requests, session-scoped admission
lookup, and resealed charge forgery. The checkpoint tests also cover every-byte
truncation and mutation, trailing data, rollback, and expired retirement.

On the accepted repository toolchain, run:

```sh
cargo test -p fss-reference cursor_checkpoint
cargo test -p fss-reference agent_session::checkpoint::journal::disclosure
cargo test -p fss-reference agent_session::checkpoint::journal
cargo test -p fss-reference --test context_source_hydration
```

These tests were added but **not executed in the authoring environment**, which
had no Rust toolchain. This slice does not close FSS-210, establish production
qualification, persist the whole hydration catalog, implement retention/deletion
scheduling, or establish CLI/MCP/TUI parity. Token charges are descriptor quotes,
not measured total runtime resource consumption.
