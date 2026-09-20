# Graph-aware local evidence retention

`fss_object::retention::RetentionStore` implements the local reference slice of
comprehensive-plan sections 22.6 and 22.7: explicit retention reasons, evidence
holds, dependency-aware expiry, bounded execution, and exact recovery metadata.
It owns its object custody exclusively rather than accepting an incomplete list
of objects to delete from an unrelated mutable store.

## Register the real dependency graph

Create the owner with an accepted policy digest, `ObjectLimits`, and
`RetentionLimits`. Register original bytes with `put_source`, derived bytes with
`put_derivative`, and root manifests with `publish_manifest`. Each call supplies a
`RetentionRule` containing a policy-owned deadline and a bounded reason identity.
No universal retention duration is assumed. A deadline permits considering expiry;
it does not override an evidence hold or another object's dependency.

A derivative must name every controlled source dependency. A manifest uses its
actual children, including its typed metadata object. Live retained objects keep
their complete dependency closures, so an incident retained longer than a rolling
buffer also preserves the source evidence it needs. Shared source objects remain
protected until every live dependent is eligible for deletion.

Dependencies must already exist, and identical content cannot be rebound to new
retention rules, object kinds, or dependency sets. Exact registrations are no-ops.
The fixed policy digest and immutable rules deliberately do not implement policy
migration or automatic shortening. An opaque payload that happens to contain
manifest-like bytes is not silently promoted into a publication.

The owner exposes only read-only custody through `custody()`. Callers can use that
capability with existing published-source hydration. This does not authenticate a
transport or authorize disclosure. All controlled renditions, caches, indexes,
exports, and replicas must be enrolled by the runtime before any corresponding
whole-system deletion guarantee could be made; this slice does not enroll them.

## Holds and bounded expiry

`add_hold` requires an exact state precondition, a stable hold ID, a live subject,
and a verified witness. The subject and witness closures remain pinned. Only an
explicit `release_hold` releases that protection, under another exact state
precondition and verified release witness. Released IDs remain tombstoned and
cannot be reused. These are trusted runtime mutation boundaries: witness digests
are audit references, not signatures or independently authenticated permissions.

`prepare_expiry` is read-only. It returns an exact `RetentionPlan` distinguishing
selected objects, expired-but-protected objects, otherwise eligible objects
deferred by the batch budget, active hold roots, and objects not yet due. It
propagates protection through the entire graph and selects eligible objects in
dependents-first order, using content digests as deterministic tie-breakers.

`RetentionBudget` separately limits object count, deleted payload bytes, and the
additional payload bytes allowed for the reference transaction's custody clone.
If a dependent cannot fit a byte budget, its sources remain deferred. Thus even a
one-object batch cannot leave retained objects referencing deleted sources.
Expiry scheduling is caller-driven; no background timer or daemon is introduced.

## Execute one exact authorized plan

The trusted runtime supplies `RetentionAuthorization` with the exact policy and
plan digests, permitted object set, verified witness, and authority lease. It must
authenticate the operator and project that scope itself. A plan or a checksum does
not grant permission to delete. The witness cannot be selected for deletion in
the same invocation.

`execute_expiry` revalidates the plan, graph, custody, authority, and budgets.
Adding a hold or a dependent invalidates a previously prepared plan. It performs
all tombstone mutations in a bounded candidate and publishes the candidate only
after verifying the surviving graph and exact released payload quota. A failure
leaves the original state unchanged. Success returns a `DeletionReceipt`; exact
authorized retries return that historical receipt rather than deleting twice.
Permanent object tombstones prevent same-digest reimport through this owner.

This is **in-process reference atomicity and local custody deletion**, not a disk
transaction, allocator zeroization, cryptographic key erasure, or verification of
remote-provider copies. A source previously disclosed into another component's
memory is outside this owner's deletion claim. Retained identity/hold/receipt
metadata is bounded and never silently evicted to make room for more work.

## Recover rules, holds, and deletion history

`checkpoint` serializes private metadata and exact retry receipts, not source
payloads. Protect these bytes and pin the returned checkpoint digest independently.
`restore_checkpoint` requires that independently trusted root, the accepted policy,
current matching custody, and explicit metadata/custody-clone ceilings.

Recovery checks canonical ordering, bounded counts and text, acyclic dependencies,
active holds, live-byte accounting, exact deletion memberships, tombstone records,
receipt identities, and canonical round-trip equality. It refuses missing, extra,
corrupt, or resurrected custody and different tombstone witnesses. Old metadata
cannot be combined with custody where its live sources have already been deleted.
A checksum provided beside an untrusted snapshot is not a trusted root; supplying
both old metadata and old custody is outside the independent-root contract.

Recovery returns a reference owner containing an explicitly bounded custody clone.
It does not reopen storage, synchronize metadata with disk deletion, restore
session permissions, or reconstruct remote copies. A durable retention journal,
crash reconciliation, policy migration, and distributed deletion obligations
remain separate work. The checkpoint format is private reference storage, not a
new public semantic protocol or canonical evidence ledger.

## Source-hydration integration and validation

`crates/fss-reference/tests/retention_source_hydration.rs` starts with a deterministic
synthetic camera packet, publishes it through retention-owned custody, and reads it
through existing session-authorized H3 hydration. The tests exercise a hold keeping
a capture readable, release followed by expiry of source/provenance/root, and
metadata recovery against tombstoned custody. A stale `Available` descriptor cannot
recreate source bytes or charge another successful delivery after local expiry.
Previously valid source receipts remain historical evidence, not current access.
The fixture uses no separately cached H3 payload and makes no claim about H0-H2
payload caches owned by other components.

The Rust additions contain 30 tests: 18 graph/expiry tests, 9 checkpoint tests, and
3 source-hydration integration tests. The graph tests include all four-node
insertion-ordered DAGs and count budgets. An independent Python path-closure oracle
also checked 56,320 graph/pin/object-budget/byte-budget combinations. That oracle
checks the selection algorithm, not Rust compilation or execution.

Run on the accepted repository toolchain:

```sh
cargo test -p fss-object retention
cargo test -p fss-reference --test retention_source_hydration
```

Rust compilation and these Rust tests were not run in the authoring environment,
which had no Rust toolchain. API review, lexical checks, and the independent
algorithm oracle are not production or aggregate deletion qualification.
