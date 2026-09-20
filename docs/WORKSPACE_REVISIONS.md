# Reference workspace revisions and recovery

FSS-204 (`fss-x4a.24.4`) remains open. The executable reference slice is
`fss_reference::agent_session::workspace`, with checkpoint support in its
`checkpoint` module. It uses the existing Rust `SessionCapsule`; it is not a new
public protocol or a claim of complete JSON-schema/surface parity.

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

## Boundaries and validation

These primitives perform no I/O. Atomic integration of session-clock/expiry changes
and workspace publication into the existing durable session journal is still
required before acknowledging crash-durable workspace operations. A caller must
persist error-side session mutations too. Verified discharge/resolution, privacy
reprojection, negotiated objective changes, complete plan/lease payloads, and
CLI/MCP/handoff equivalence remain separate work. No gate or bead is closed here.

The workspace test modules contain 24 deterministic and adversarial tests, including
all truncated checkpoint prefixes, individual bit flips, stale writers, revoked
grants, exact retries, rebase, omission, reordered/forged history, and storage bounds.
They have been added but **not executed**: the editing environment has no Rust
toolchain. Run the focused tests with the repository's accepted toolchain:

```sh
cargo test -p fss-reference agent_session::workspace
```

The repository-owned local qualification/DSR lanes remain the release authority.
