# Session-authorized original-source hydration (FSS-210)

`ReferenceSessionStore::hydrate_from_source` and `hydrate_from_local_source` connect the existing
live source verifier to the same session admission and cumulative token accounting as cached
hydration. The request, descriptor, receipt, artifact, and continuation formats are unchanged.
These are Rust owner APIs, not new public `fss/1` verbs or transport authentication services.

## Admission before custody access

The runtime authenticates the principal, owns the session store and catalog, supplies trusted
service time, and lends a narrowly scoped source reader. An agent cannot supply that reader or
register arbitrary source bindings. The local method borrows the already lock-owning
`LocalRootPublisher` and the same `SpoolIo` capability used by that publisher; it does not open,
repair, migrate, or implicitly initialize storage.

All delivery modes share one private admission/accounting function. It resolves the exact
session-local symbol and checks its generation, descriptor, subject, H0 grants and privacy. It
then verifies request integrity, session identity, ContractBasis, anchor, issue time, requested
authority subsets, and the full requested token allowance against the session's remaining grant.
The existing catalog additionally checks level-specific authority, privacy, retention, the full
cost vector, laboratory access and single-use continuation before source I/O. Narrow request
grants remain narrow; the implementation never replaces them with all available session grants.

H3 source bindings are registered by the evidence owner against a real publication. Every H3
disclosure re-verifies the bound publication and source through the existing reader. The catalog
independently verifies returned bytes and exact artifact identity. Local disclosure compares
on-disk roots, complete closure and tombstones with the live publisher before and after reading.
No H3 source payload enters the catalog cache, and an earlier successful disclosure cannot
substitute for current custody after deletion or corruption.

## Results and budgets

A cached lower-level result or an explicitly permitted policy/budget downgrade uses the same
receipt and cursor semantics as ordinary hydration. An actual custody/integrity failure never
becomes evidence of absence or a silent preview fallback. A valid H4 artifact is preferred under
the existing laboratory policy; requesting more detail never bypasses its grants.

`agent_session::hydration::SessionSourceHydrationError` separates session admission/accounting
from source/catalog failure. Its display excludes private paths, source bytes and object IDs;
detailed nested causes are for authorized diagnostics. Every successful delivery consumes the
receipt's quoted token cost. Exact non-continuation retries are additional deliveries, not free
replays. A refused delivery consumes no tokens or source continuation, but may advance session
clock watermarks or close an expired session. Quotes are not measured I/O, CPU or latency use.

These ReferenceSessionStore methods are the in-memory reference. They do not persist the session
charge or catalog cursor ledger (the durable source wrapper below commits session charges), execute a probe/model, admit an investigation citation, authenticate a transport,
or promote source identity into a claim about physical reality. The local publisher's existing
custody boundaries are unchanged. Production still needs Asupersync ownership and qualified
budget/cancellation enforcement around the complete request.

## Regression coverage

The session/source contracts exercise actual root-published objects, original-byte binding,
cache separation, cached/source lower-level equivalence, repeated-delivery charging, exhaustion,
forged request identity/basis/time/grants, closed/expired sessions, revoked source authority,
retention, symbol rotation, corrupt closure metadata, deletion after disclosure, and failed
reads followed by successful single-use continuation. Counting readers verify pre-I/O refusals.

```sh
cargo test -p fss-reference --test session_source_hydration_contract
```

Rust compilation, tests, rustfmt and clippy were not available in the editing environment.
Committed regression source and static checks are not executed qualification evidence.

## Commit-before-disclosure delivery

`DurableSessionStore::hydrate_from_source` stages the session and catalog privately, verifies
fresh source custody, and commits the updated session checkpoint before returning source bytes
or installing cursor changes. It works with session-only and joint session/work/case journals;
no initialization, record kind, schema migration or reader-selected codec is introduced. Existing
coordinator/case state is preserved across source-charge checkpoint records.

`agent_session::checkpoint::journal::coordination::source_hydration::DurableSourceHydrationError`
separates persistence failure from a committed semantic refusal. It reuses the published
`SessionSourceHydrationError` rather than introducing a second session admission path.
A custody failure can still advance the session clock; that mutation is committed before the
refusal. Expired-session tombstones likewise survive restart. Checkpoint or append failures fence
the shared owner and withhold all source output and catalog mutations. Capacity exhaustion does
not implicitly make reads free, discard history, or refund a committed charge.

Pending reconciliation and exact-root cold recovery use the existing journal methods. They never
reread source or redeliver a withheld response. A completed write with a lost acknowledgement can
leave a durable token charge without a delivered response; it cannot be rolled back using the old
root. Explicit later retries recheck current custody and may charge again. An incomplete final
write is removable only through the existing explicitly authorized recovery policy.

Only normal session checkpoints are persisted: raw source bytes are absent from the journal and
the catalog source cache. Catalog cursors remain separately owned, non-durable reference state,
exactly as with the existing cached durable hydrator. The owner must persist/recover its cursor
tombstones separately; this bridge does not claim replay-safe catalog restoration, authenticate
recovery roots, provide cross-process locking, or establish future custody after disclosure.

Seventeen additional tests retain the eight prepared session/source regressions and add nine
durability regressions. The latter cover charge/restart continuity, all four append phases, shared fencing,
withheld cursor mutations, hot/cold recovery and stale roots, refusal-side clock/tombstone
persistence, capacity, interleaved case/work preservation and cached-path compatibility. These
include denial before I/O after journal mutation. The existing twelve public session/source
contracts and their production implementation are preserved unchanged. Compilation, Cargo tests, rustfmt, clippy and full qualification
remain unrun because the editing environment has no Rust toolchain.

```sh
cargo test -p fss-reference source_hydration
cargo test -p fss-reference agent_session::checkpoint::journal
```
