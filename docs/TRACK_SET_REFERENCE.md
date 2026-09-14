# Atomic multi-target source updates

`fss_twin::stream::batch::ContactTrackSet` closes the in-memory mutation gap between
`AssociationSelection` and the existing contact tracker. It consumes an explicitly
adjudicated partial assignment, stages every selected source update through the
same implementation as single-track `ingest`, then publishes all track states,
frame watermark, operation sequence and receipt together. No fallible allocation,
callback, I/O or cancellation poll occurs after the final publication barrier.
A failed second projection, motion fit or budget check cannot leave the first
track advanced. No full copy of the prior motion/geometry state is required.

Construction takes 1..32 already-seeded tracks with unique anonymous IDs and one
identical frozen camera registry/clock. Membership and camera changes require a
new explicit owner session. The set exposes immutable snapshots for the existing
association gate and route/forecast APIs, never individual mutable track access.
Each selected observation retains its original detection evidence, image domain,
exposure, camera and capture interval. The adjudication record is retained by the
source-pair fitter; compatibility alone is not identity authority.

## Explicit choices, exact retries

A `BatchOperation` carries the next sequence number (starting at one) and a nonzero
adjudication-evidence reference. The caller supplies an already checked
`AssociationSelection`; there is no automatic nearest/first/maximum-cardinality
choice. The complete graph source membership must equal the set, including tracks
left unmatched. Input signatures bind the source receipts and observations, twin,
camera model, exposure, detection proposals (including unselected ones), matching
assumption and policies, pair uncertainties/overlaps, explicit links and operation.
These are reference fingerprints, not new registered canonical durable schemas.

Receipts retain before/after revisions for the entire set, selected source updates,
all unmatched tracks/detections and the source-frame identity. Unmatched tracks
retain historical observations; an empty detection set does not delete targets or
establish negative evidence. An all-unmatched decision still advances batch history
and the exposure watermark, preventing a later silent reassignment of that frame.

Exact cached retries return the original acknowledgement even after newer batches,
without rolling state back. Changed inputs/adjudication under the same sequence
are conflicting retries. Evicted operations fail rather than applying twice. The
receipt cache is explicitly bounded to 1..256 entries; new sequence gaps fail.
Per-camera lower-capture watermarks survive cache eviction. These are not a global
infinite source-ID registry: the canonical owner must prohibit recycled identities,
retain custody and reorder delayed inputs or explicitly rebase a session.

Set-wide invalidation needs no spare work budget. Active snapshots and updates then
fail; the last receipt remains readable for reconciliation. Cancellation arriving
before the publication barrier leaves everything unchanged. Cancellation arriving
after it does not interrupt the small in-memory commit section.

## Composition

```rust
let graph = gate_contact_batch(&twin, frame, &set.snapshots(&mut budget)?,
    &contacts, gate_options, &mut budget)?;
let family = factorize_associations(&graph, assignment_policy, &mut budget)?;
let selected = family.check_assignment(&explicit_links, &mut budget)?;
let update = set.apply_selection(&twin, &selected, operation, &mut budget)?;
```

This is derived-state ownership, not a persistent authority transaction, a detector,
automatic target-birth/death policy, Asupersync service or calibration activation.
Process termination loses in-memory state. Original observations, graph alternatives
and adjudication evidence must remain available from the existing canonical owner.
No permissions, identity adjudication, camera settings, custody, retention or alert
policy are acquired by construction of a Rust value or a hash.

## Tests and qualification

`cargo test --locked --offline -p fss-twin --test track_set_contract --test stream_contract`
exercises both the new batch owner and unchanged single-track behavior. Ten new Rust
contracts cover all-or-none staging (including failure on the second track), original
source preservation, stale/subset membership, sequence gaps, old exact retries,
conflicting unselected inputs, receipt eviction, empty/all-unmatched decisions,
cancellation and work-limit rollback. These contracts have been authored but not
executed in the current environment; no Rust toolchain is available.

The independent Python state-machine fault campaign exercises publication boundaries,
retries and eviction. It is not execution of the Rust implementation. Native compiler,
test, full ledger/runtime and recorded-camera qualification remain outstanding.
The broad FSS-099 / BTI-008 acceptance gates remain open.
