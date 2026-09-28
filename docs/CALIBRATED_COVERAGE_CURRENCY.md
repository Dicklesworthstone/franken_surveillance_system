# Guarded coverage approval currency

The shared `GuardedCoverageSet` API already verifies its own source custody,
ancestry and authority. These changes close the lower-level path: a caller using
`recorded_coverage::check_approval` / `retain_coverage` directly must not bypass
version-6 privacy and adoption checks. The shared set remains the CLI's full
retention path; this is not an alternate publisher or a new source-custody proof.

A version-6 full-camera screening receipt records a computation against particular
privacy and calibration authority. It is not a lease that permits later retention
under different authority. `recorded_coverage::check_approval` now revalidates
guarded records before looking up existing retained payloads, before any staging,
and before `retain_coverage` can return `AlreadyRetained`.

The checks are deliberately sensor/camera scoped, not a comparison with the whole
ledger head. Publishing an unrelated event or another sensor's mask does not by
itself invalidate an otherwise unchanged coverage approval.

## Exact bindings

Both the current mask binding digest **and its ledger generation** must match the
receipt. The explicit no-policy marker has generation zero. Replacing a policy
and later restoring its old bytes therefore cannot resurrect the old receipt.
Unreadable or corrupt privacy authority is a refusal, not a fallback to no mask.

Retained adoption is checked through the existing `adopted_currency` semantics:
calibration digest, camera handle, intrinsics/extrinsics generations, and sensor
must agree. `adopted_current` additionally requires the exact retained adoption
receipt named by the coverage provenance. Missing or superseded receipts fail.
An owner-asserted or unasserted basis remains valid only while that camera has no
retained adoption; it cannot silently turn into an adoption-backed claim. A new
camera handle cannot bypass an adoption already binding the same sensor to a
different handle. Damaged adoption custody fails closed.

The new typed `CoverageError::Currency { sensor, reason }` uses the already
registered `ERR-COVERAGE-001` refusal identity. Its reasons direct reanalysis and
expose no mask coordinates, secrets, or new capability.

## Compatibility and effect boundary

Only version-6 guarded approvals acquire these new checks. Historical
`CoverageRecord::from_bytes` remains independent of today's authority, so old
bytes can still be audited. Version-1..5 approval behavior is intentionally
unchanged; this is **not** a claim that all legacy coverage has current-authority
protection. Migrating legacy approvals is separate work, not a silent durable
format reinterpretation.

All records in a mixed batch are checked before the first record is staged. The
CLI also performs this preflight before publishing separately approved positive
events in a mixed request, and ordinary coverage retention checks again. No new
transaction protocol, external lock guarantee, or physical calibration claim is
introduced; the existing deployment authority/serialization boundary still owns
concurrent mutation.

## Native regressions and qualification

Added tests cover exact mask-generation comparisons, actual retained-adoption
binding semantics, no silent currency promotion, a missing claimed adoption,
unrelated-sensor changes, historical decode compatibility, and a privacy change
that must refuse a mixed batch without changing its ledger anchor or filesystem
bytes. Existing receipt tests remain intact.

```sh
cargo test --locked --offline -p fss-reference calibrated_coverage
cargo test --locked -p fss-reference --test guarded_coverage_currency_contract
cargo test --locked -p fss-reference recorded_coverage
cargo test --locked -p fss-cli --bin fss-event
```

These native tests were written but **not run** in the authoring environment,
which lacked a Rust toolchain. Python model and source-bundle checks are separate
evidence; they do not certify Rust compilation or deployment behavior. No bead,
release gate or qualification status is closed by these changes.
