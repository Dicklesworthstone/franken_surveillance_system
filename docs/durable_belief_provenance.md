# Native durable belief verification: local-slot reference profile

`fss_publication::custody_audit::belief_snapshot::durable::verify_durable_belief`
connects the existing retained graph verifier to an opened `DurableReferenceLedger` and
`LocalRootPublisher`. These are available from an already-open `ReferenceDeployment` through its
read-only `ledger()` and `publisher()` accessors. The caller separately supplies its authorized slot
selection, explicit I/O and cancellation authority, extra deny-set, budgets and trusted registered
engine. An offered statement never chooses the engine or grants scope.

## What is verified

The input must decode completely within the encoded-byte allowance and match the current anchor
and independently selected engine identity/generation. Each selected slot must be current,
locally durable, and named by a generation-1 authority-plane `local_root_reachability` revision.
The exact on-disk slot record, including its record digest and child count, must match the opened
publisher; another slot with the same manifest digest cannot stand in for it.

The durable store identity and native committed-tail verifier are checked before and after work.
Committed batches are deterministically replayed under explicit bounds and the resulting complete
snapshot must equal the durable owner's current snapshot. The replay is an input to the existing
core graph engine, never a substitute for durable authority.

Native custody capture verifies the complete selected closures, including unused siblings and
metadata. Capture uses one outer I/O meter across audit, rehashed payload copies and bracketing
publication-catalogue comparisons. The graph verifier consumes those immutable captured bytes,
retains typed ancestry, and independently rederives the entire offered belief. The returned
`VerifiedDurableBelief` privately retains the captured inputs and borrows the durable owners.
Knowledge-cell projection checks the durable head again and remains cognition-only.

## Explicitly unsupported rather than fail-open

The default entry point still refuses any history containing `batch:deletion:` identities,
`deletion_` families or root retractions. `fss_reference::deletion::belief` now supplies the trusted
reference deletion-owner bridge: it replays the complete canonical deletion proof from committed
batches plus retained plan/completion objects and converts every deleted spool object into a denial.
The deletion-aware durable entry point merges that deny-set with caller denials before custody reads.
Malformed, orphaned, reordered, missing, or conflicting deletion authority fails closed; a caller
cannot make a deletion disappear with an empty map. Unrelated intact slots can therefore remain
verifiable after another closure is deleted, while deleted objects remain unreadable. Local
tombstones independently restrict capture. Event manifests without local slots remain unsupported.

The API does not authenticate a principal, apply deployment privacy policy on the caller's behalf,
register or activate production engines, authorize effects, or certify absence. It must be called
only after the application establishes read authority. Existing structural belief methods are not
silently converted into provenance checks, and `fss-s1gcl` is not closed by this increment.

## Resource and observation boundaries

`DurableBeliefLimits` bounds encoded input, replay batches, history entries, cumulative snapshot
entries and repeated copied text, native custody work, retained payloads and graph input copies.
Successful results expose separate replay reservations, logical graph usage and native capture
read counters; these are not all interchangeable with CPU or allocator measurements. A core graph
failure preserves its usage. A unified partial-work receipt for earlier replay/capture failures
remains outstanding. Captured bytes and core input copies can coexist under their separate budgets.

The durable-head check is the existing bounded tail check, not a full historical disk scrub.
Matching catalogue observations detect observed changes, not arbitrary ABA races or an atomic
filesystem snapshot. Retained in-memory inputs are not a lease on original files or a promise of
future availability. The publisher and ledger borrows prevent cooperating mutation while the
result is used; filesystem mutation outside those owners is not physically prevented.

## Validation

The existing `scripts/test_belief_provenance.sh` now also executes the publication library and
integration suites. The preceding disk-capture commit `5ea8b816a97e93119eb145688e5935d02bdce80a`
compiled and passed 44 existing provenance tests plus 222 publication tests in native run
`38459780557`; one pre-existing privileged-filesystem test was ignored. New capture-specific test
uploads were blocked by the editing tool. These existing tests are compatibility coverage, not
new regression coverage for the capture or this durable composition. Native compilation and the
existing suites must be checked on this increment separately. This is not release qualification.


## Deletion-aware durable profile

The deletion-aware profile is deliberately opt-in. `CommittedDeletionBeliefAuthority` implements the
publication-layer `DurableBeliefDeletionAuthority` trust boundary using `DeletionIndex::from_batches`.
The publication crate therefore does not learn the deletion-plan schema or depend back on the
reference crate. Applications that do not explicitly select a trusted deletion owner retain the old
blanket refusal. The authority receives the exact opened durable ledger and publisher, validates the
whole deletion history, and may only add denials; it has no write or repair surface.

The focused regression creates a real retained file import, commits its graph-complete deletion, and
proves an unrelated ledgered belief source remains independently verifiable. It also confirms the
same history is refused by the default API and that a forged orphan `batch:deletion:*` marker is
rejected by the deletion owner rather than acting as a bypass.
