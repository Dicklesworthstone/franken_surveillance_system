# Auditing canonical-authority manifest roots

`fss_publication::custody_audit::audit_authority_roots` extends the existing
read-only custody walker to roots selected from a separately verified authority.
The original `audit_local_roots` still requires a valid local `.root` record for
every selected root. Neither API grants access or establishes event truth.

## The event-publication boundary

`ReferenceDeployment::publish_event` commits an `event_revision` delta whose
payload is an immutable `event-revision` manifest. `stage_event_revision` stages
that manifest directly; it does not also publish a local slot. The manifest
contains the canonical event metadata and its retained model/provenance receipts.
A local-slot-only walker therefore rejects an ordinary committed event root as
`RootNotPublished`, even when all of its bytes are retained and verified.

The additive API does not manufacture a slot or change historical event roots.
The caller must verify the selected manifest digests against canonical authority
and pass deletion denials before entering the walk. Only those selected roots
receive an additional manifest role. All other objects expand only when their
own local publication records declare a manifest. Manifest-shaped opaque leaves
remain opaque; embedded semantic references are not followed speculatively.

When a local record also names a selected authority root, its child count is
still enforced. Corrupt, pending or changed local catalogues are never bypassed.
Missing, deleted or invalid selected manifests retain an incomplete-expansion
state rather than becoming apparently intact opaque leaves. Both entry points
share the same I/O meter, limits, cancellation checks, tombstone handling,
unique-object deduplication, edge accounting and before/after catalogue checks.

`LocalCustodyAudit::root_basis()` exposes `local_publication_records` or
`caller_verified_authority`. The latter records the caller's prerequisite; it is
not a claim that the publication crate independently replayed a ledger. Callers
must revalidate their authority/deletion basis after the audit. Sequential reads
are not an atomic snapshot, a future-availability promise or a durability upgrade.

## Validation

Six native library contracts cover slotless roots, declared versus opaque nested
manifests, missing/corrupt/non-manifest roots, deletion before payload reads,
local child-count and pending-publication constraints, shared-root deduplication,
combined work ceilings and cancellation. Existing slot-only contracts remain.

```sh
cargo test -p fss-publication --test authority_custody_contract
cargo test -p fss-publication --test custody_audit_contract
```

These contracts have been authored but not run: the authoring environment has no
Rust toolchain or network access to obtain one. No release qualification is
inferred from source inspection or supplementary semantic checks.


## Committed-event operator integration

`fss-custody audit --root DIR --site SITE --event-id EVENT` now uses the authority
entry point. Both its before and after deployment reads resolve the exact current
event, verify its complete revision chain, bind the canonical event record and
committed root, and reconstruct deletion denials. The two bindings must agree.
`--expected-root` still refuses a changed current revision. The diagnostic exposes
`root_basis: caller_verified_authority`; it grants no new read or effect scope.

Six process contracts use real deployment and event publication before launching
the custody binary. They cover intact source and counterevidence, missing/corrupt
sources, lost provenance, local tombstones, exact pins, resource refusals and
unverifiable authority. No fake `.root` event record is written by their fixture.
The first contract also establishes that the old local-slot API rejects the same
ledger-selected root, preventing a fixture from hiding this integration mismatch.

```sh
cargo test -p fss-cli --test custody_authority_cli
cargo test -p fss-cli --bin fss-custody
```

The process targets are authored, not executed here. A full native run remains
required before claiming this path works end to end on the pinned toolchain.
