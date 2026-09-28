# Lossless calibrated coverage proposals

`fss-event corroborate --calibration FILE --calibration-digest sha256:…` now
composes the existing full-camera covariance screen with the existing version-6
coverage receipt. This replaces the command's former all-or-nothing coverage
interlock. It does not change the positive event analysis, event approval digests,
alert policy, or the meaning of a calibration candidate.

## The useful distinction

When the screen rejects one zone, only that zone's former coverage witnesses
become `calibration_uncertainty` intervals. Safe zones retain their original
witness segment ranges, certain capture bounds, source domains and authority
anchor, with receipt-bound pipeline and predicate identities. The shared `calibrated_coverage::GuardedCoverageSet` owns atomic set construction
and calls `apply_calibration_coverage`; the CLI does not duplicate its transformation,
mixed-anchor checks, duplicate-camera checks, companion bounds or privacy bindings.

Every pre-existing uncovered interval remains unchanged, including observed zone
entries, missing frames, decode refusals, source gaps, privacy exclusions,
background warm-up and confirmation latency. A clear screen never manufactures a
witness, repairs unknown time, or grants an absence claim. A completely rejected
record remains useful: the explicit exclusions and assessment receipt can be
retained, even when its witness count is zero.

## Approval and publication

The command renders and checks the approval of the **guarded records**, not the
nominal analysis. A stale or nominal coverage approval is rejected before event
publication in a mixed event/coverage request. Both camera records go through the
shared `GuardedCoverageSet::retain` path, which revalidates source custody,
retained ancestry, mask generation and adoption under the caller's read limits
before invoking `recorded_coverage::retain_coverage` in one batch; neither camera's
record is exposed as a partial screening result.

The calibrated camera is matched by name plus the recording's sensor, import
identity and import root. A second camera without a calibration keeps its original
record. The already digest-verified `SiteCalibration` is reused; it is not reread
from a mutable file halfway through analysis. Masks come from the deployment's
current sensor-specific privacy authority.

When positive events are published without coverage retention, nominal coverage
is recomputed at the new anchor, then screened again. The displayed record,
approval and guard diagnostics all come from that reanalysis. The old receipt is
never attached to a newly anchored nominal proposal. As with the pre-existing
command, failure during this post-publication computation cannot roll back an
already approved event publication.

No-calibration requests keep the existing analysis, retention and JSON-rendering
branches. Existing version-1..5 bytes and historical records are not rewritten.
The native compatibility tests must still run before any qualification claim.

## Diagnostics and budgets

The `coverage` member retains its existing `fss.recorded_watch_coverage.v1` report
shape and includes version-6 per-zone guard receipts through the existing renderer.
`calibration_uncertainty_guard` now uses the separate diagnostic format
`fss.calibration_coverage_proposal.v1`, registered in `registries/SCHEMAS.md` and
`schemas/calibration_coverage_proposal.v1.json`. The older whole-proposal guard and
refusal formats remain historical identities; their meanings are not reused.

One explicit 64,000,000-unit allowance covers calibrated camera screens, receipt
transformations and the second screening pass after event publication. It is not
reset for another camera or reanalysis. `work_units` names the current guard pass;
`work_units_total` names the consumed allowance for the request, and
`work_units_remaining` names its remainder. These are registered reference work
units, not a CPU instruction count, wall-time measurement, or the cost of the
separate decode/tracking pipeline.

The full-camera screen is a conditional **local linearized** calculation. Its
radius-three contour is not a calibrated confidence probability, proof of
nonlinear visibility, verified camera currency, or physical observability.
Previously retained coverage is not silently retracted. There is no new effect
authority, runtime, dependency, or automatic policy activation.

## Validation boundary

Native regressions exercise mixed and fully uncertain zones, missing-time
non-promotion, preservation of positive entries and gaps, receipt binding,
aggregate transformation budgets, and deterministic rendering. Run:

```sh
cargo test --locked --offline -p fss-reference calibrated_coverage
cargo test --locked -p fss-reference calibration_coverage
cargo test --locked -p fss-cli --bin fss-event
```

The authoring environment did not have `cargo`, `rustc` or `rustfmt`. Rust
compilation, native tests and full local qualification were **not executed** there.
Independent Python partition, authority-state, schema and patch-application checks passed.
Those checks are not execution of the Rust implementation or a release qualification receipt.
