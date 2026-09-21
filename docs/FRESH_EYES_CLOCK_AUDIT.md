# Fresh-eyes clock and source audit

Reviewed source anchor: `74d800bfc254e48b2db2fe61fc874cd0a6a0ddc1`.
Scope: `VirtualClock::advance` -> `VirtualSource::emit_interval` ->
`emit_packet` and the staged `generate_source_with_clock` caller. This is a
contained repair of the deterministic source/time contract tracked by
`fss-x4a.7.1`, not closure or requalification of that program bead.

## Confirmed defects and repairs

1. Clock jitter was sampled into live PRNG state before validating the effective
   step and resulting timestamp. A refused zero step or timestamp overflow could
   therefore alter the random stream used by a later successful retry. Sampling
   is now speculative and committed only with the complete accepted step.
2. Clock time and fractional-skew residual were assigned before the step counter's
   checked increment. Counter overflow could return an error after moving time.
   All four candidate values are now checked before the single state commit.
3. The source committed sequence and clock advancement, and cleared a pending
   indeterminate read, before interval-upper-bound construction could overflow.
   Source attempts now stage the small clock and typed result before committing
   clock, sequence, and the pending flag together. An outer error consumes no
   packet or jitter. Successful Indeterminate, Unobservable and Failed outcomes
   retain their original, distinct sequence-consumption rules.

No payload generator, canonical encoding, time unit, skew/jitter distribution,
source identifier, dependency, capability, or effect behavior is changed.
Previously successful source/clock traces retain their exact recurrence. Traces
that previously continued after one of these rejected operations intentionally
stop inheriting its partial mutation. Callers must not depend on state changes
from a failed operation.

## Regression evidence and limits

Nine Rust regression tests are added in `clock/atomic_tests.rs` and
`source/atomic_tests.rs`. They compare entire clock/source state on refusal,
retry equivalence, indeterminate-read pinning, counter overflow, timestamp
boundaries, accepted fault outcomes and the original successful recurrence.

Independent Python integer transcriptions reproduced six baseline failure
scenarios. They checked 200,000 identical successful clock steps, 20,000 atomic
clock refusals, 19,289 identical successful source attempts and 5,711 atomic
source refusals. These checks are not execution of the Rust implementation.

Rust compilation, the nine new tests, existing `virtual_clock_source_contract`
regressions, rustfmt, Clippy and `scripts/qualify.sh` have NOT run in the authoring
sandbox: cargo/rustc/rustfmt are unavailable. Run the native reference and fault
lanes on the pinned toolchain before claiming qualification. No bead, gate or
release status has been upgraded.

## Review handoff

Alert dispatch/response handling and convex image-zone geometry were also
sampled; no change was made without a concrete reproduced finding. The separate
clock-synchronization conversion review is recorded below. Source evidence and
failed attempts are not coverage or absence certificates.

## Clock synchronization interval repair

Tracing `ClockSyncEstimate` from the fitted sensor-minus-reference residuals into
both prediction methods found two additional errors:

- Inverse conversion divided the nominal sensor time by the fitted rate, but then
  added the sensor-domain error unchanged in reference nanoseconds. With a half-
  rate sensor, reading 100 and error 10 produced [190, 210], excluding reference
  times 180 and 220 that the same model admits. The complete sensor interval is
  now inverted, with the lower endpoint rounded down and the upper endpoint up.
- Both prediction methods saturated `sample_uncertainty + max_residual` at
  `u64::MAX` before expanding i128 timestamps. This silently understated a larger
  finite radius. The two u64 values are now summed exactly in i128.

The forward model retains its existing integer truncation of the skew term. For
nonzero skew its difference from the exact affine value is less than one sensor
nanosecond. The inverse explicitly reserves one sensor tick for that rounding
before scaling, rather than accidentally excluding times on either side of the
anchor. The half-rate example therefore returns [178, 222], not a falsely tight
[190, 210]. Zero skew needs no extra rounding tick and retains its previous exact
intervals when the uncertainty sum already fit u64.

Eight further Rust tests cover slow/fast rates, negative deltas, directed endpoint
inequalities, a fitted half-rate clock, forward/inverse containment, exact wide
uncertainty, preserved zero-skew behavior, and typed missing/stale/overflow
refusals. The estimator fitting, inlier selection, evidence-root encoding,
generation state and fit-variance code remain byte-identical. The existing
nominal-reference-time validity check is unchanged. This is a correction to the
model's numeric enclosure, not a new physical clock-certification claim.

Independent Python checks compared 50,000 endpoint pairs with exact Fraction
arithmetic and verified 32,361 integer forward/inverse enclosures. The old formula
excluded 4,476 of those admitted reference times. Another 160 zero-skew checks
retained exact intervals. Rust compilation, all 17 newly authored tests, rustfmt,
Clippy and native qualification remain UNRUN. No registry/gate status is promoted.
