# Reference workspace revisions and recovery

FSS-204 (`fss-x4a.24.4`) remains open. The executable reference slice is
`fss_reference::agent_session::workspace`, with checkpoint support in its
`checkpoint` module and journal integration in
`agent_session::checkpoint::journal::workspace`. It uses the existing Rust
`SessionCapsule`; it is not a new public protocol or a claim of complete
JSON-schema/surface parity.

## Publication and resume

`ReferenceWorkspaceStore::publish` takes a live `ReferenceSessionStore`, an
already authenticated principal, an explicit runtime timestamp, and a
`WorkspaceWrite`. Revision zero has no parent and starts at the session's exact
anchor. Every later write names the exact predecessor digest and increments the
revision by one. Competing writes are refused. An exact retry returns the original
revision, including after another revision became the head; it never rewinds the
head or consumes storage again.

`resume` requires an exact revision digest. It returns that revision, the retained
head digest, and explicit `superseded` and `rebase_required` flags. It never follows
an implicit latest alias. A revision binds its full session capability/privacy
scope independently of the capsule's declarative capability projection. Narrowing
any captured grant refuses access, including exact retries and restored history.
Unknown sessions, closed/expired sessions, wrong principals, and regressing clocks
remain subject to the existing session authority checks.

Ordinary writes cannot drop obligations, unknowns, not-observable domains,
epistemic debt, hypotheses, bookmarked evidence, or required next actions. Removed
assumptions must remain as explicit debt. Rebase requires an admitted successor
anchor, new situation/decision identities, and carrying old assumptions as debt.
Old actions are retained as invalidated; the rebased capsule contains no executable
next actions. Workspace text and references never authenticate evidence, validate
a plan, discharge an effect obligation, or increase the session's actual budget.

## Checkpoint contract

`checkpoint(max_bytes)` seals the complete history into bounded canonical bytes.
Protect those bytes and pin the returned digest in independently trusted custody.
`restore_checkpoint(bytes, expected_digest, ceilings, max_bytes)` checks the pin,
format, limits, canonical encoding, sorted session identities, contiguous revision
numbers, predecessor chain, authorization metadata, protected-content preservation,
and exact rebase invalidations before returning a store. Recovery creates no
sessions or grants; every subsequent read/write still needs live authorization.

The checkpoint format is `fss.reference_workspace_checkpoint.v1`; enclosed revisions
use `fss.reference_workspace_revision.v2` to bind the full capability scope. Earlier
private revision encodings are refused, not silently migrated. Checksums carried
beside untrusted bytes do not establish authenticity or prevent rollback.

## Shared durable journal

The existing exclusive `DurableSessionStore` now provides:

- `initialize_workspaces(WorkspaceLimits)` for one-way, bounded initialization;
- `publish_workspace(principal, write, now)` for joint workspace/session publication;
- `resume_workspace(principal, session, digest, now)` for exact authorized recovery.

A successful write records one sealed revision plus the pre/post session and full
workspace-history digests. Cold recovery executes the same workspace write against
the preceding session and workspace state and checks exact output bytes. It cannot
adopt a replacement snapshot, omit another workspace, reset limits, or substitute
an unvalidated decision. Ordinary session, disclosure, and coordination records do
not erase workspace history. Legacy readers reject the new record kinds rather
than silently losing that history.

Publication and its clock watermark are one synchronized journal record, not two
independently acknowledged files. Refused reads/writes still durably preserve
clock/expiry mutations before returning the refusal. An uncertain append withholds
the result and fences the shared owner. `reconcile_pending` classifies committed
versus not committed using the existing journal fault protocol; it neither invents
a result nor refunds charges. Cold reopening and explicit torn-tail recovery use
the existing exact-root APIs. After a lost acknowledgement, retrying the exact
workspace request recovers its original immutable revision without rewinding the
head. Same-clock exact retries append nothing.

`JournaledWorkspace` binds the ordinary result to the committed joint journal root,
session checkpoint, and workspace checkpoint. Those roots require independent
trusted custody. The caller must exclusively own and protect the journal path;
this is not a cross-process lock, authentication service, or distributed transaction.
Full bounded replay is the reference implementation: journal and workspace limits
are enforced, but no production throughput or native-storage qualification is claimed.

## Atomic authority rebase

`DurableSessionStore::rebase_workspace(principal, refresh, write, now)` combines the
existing `SessionRefresh` and a `WorkspaceWriteMode::Rebase` request. The runtime
must still verify the new anchor. The ordinary session CAS, grant-narrowing,
lineage/epoch checks, and workspace preservation rules run on staged state. One
synchronized record publishes the new anchor, invalidated session symbols, and
workspace revision together. A refused rebase keeps the prior anchor, grants,
symbol generation, and workspace, while persisting clock or expiry observations.
An uncertain append fences the same owner until reconciliation determines whether
both halves committed. No individual half can be acknowledged as complete.

Exact lost-acknowledgement retries match the entire retained refresh plus workspace
request, then reauthorize the historical revision against today's live session.
They never rerun the old refresh, rewind a newer anchor/head, restore revoked grants,
or replenish tokens. Same-clock exact retries append nothing; a later read time
records only its new clock watermark. A different refresh paired with the same
capsule is refused rather than treated as an idempotency shortcut.

The private `fss.reference_workspace_journal_rebase.v1` envelope uses the existing
workspace-write record family. Recovery reruns both owners' state transitions and
checks the before/after session and workspace identities. Readers predating this
envelope refuse its unknown domain. It is not a second authority log or a public
protocol/schema change.

## Boundaries and validation

The in-memory/checkpoint primitives perform no I/O. The journal adapter uses the
existing session journal's synchronized append, fencing, inspection, and recovery.
A separate session refresh followed by workspace rebase remains two operations;
use `rebase_workspace` when both must commit together. The same four workspace
methods are also available on `DurableDisclosureStore`: initialize, publish,
resume, and rebase. They delegate to its existing exclusive session owner and
never expose a mutable journal/session/catalog borrow or open a second writer.
Workspace failures fence evidence disclosure, and disclosure charges/cursor
tombstones survive workspace writes and recovery. Rebasing does not retarget old
context slots or issue new evidence permissions. Verified discharge/resolution,
privacy reprojection, negotiated objective changes, complete plan/lease payloads,
and CLI/MCP/handoff equivalence remain separate work. No gate or bead is closed here.

The original workspace modules contain 24 tests. The journal module adds 11 tests
covering restart, lost acknowledgement, stale writers, expiry, revoked grants,
protected-content refusal, all four append phases, capacity, forged valid-checksum
records, duplicate initialization, and every truncated write-record prefix.
The atomic-rebase module adds 11 further tests for one-record recovery, rollback
of refused refreshes, exact retry after later work, current-grant revalidation,
expiry, stale CAS/head/lineage, every append phase, malformed records, and grants.
The public `durable_context_disclosure` integration fixture adds four tests using
its actual deterministic capture, event, compiled context, and retained source.
They interleave workspace revisions with H2/H3 delivery and restart; preserve
charges, consumed cursors, source provenance, and admission receipts; demonstrate
that a refused rebase leaves the prior context usable; reject an old context after
a committed rebase; and fence source reads after workspace persistence fails.
They run with zero session-alias capacity and assert that source payloads are
neither cached by the catalog nor written into the session/workspace journal.
These tests are **added but not executed** in the editing environment, which has
neither `cargo` nor `rustc`. Run them with the repository's accepted toolchain:

```sh
cargo test -p fss-reference agent_session::workspace
cargo test -p fss-reference agent_session::checkpoint::journal::workspace
cargo test -p fss-reference --test durable_context_disclosure
```

The repository-owned local qualification/DSR lanes remain the release authority.
