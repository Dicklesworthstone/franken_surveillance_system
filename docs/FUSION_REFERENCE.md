# Deterministic fusion reference

`fss-fusion` implements a bounded, deterministic reference for the next decision about one event
hypothesis. It contributes to `fss-x4a.16.9` (`FUSION-CALIBRATION-001`) and the common-cause boundary
of `fss-x4a.16.10` (`MODEL-INDEPENDENCE-001`). It remains unqualified for deployment threat claims.
Neither a fusion decision nor a calibration report grants authority to dispatch an alert.

The owning contracts are the comprehensive plan sections 16.9–16.10 and 17.3–17.8, `INV-013`
(generation separation), and `INV-016` (coverage gaps cannot support absence). The executable
reference is in `crates/fss-fusion/src`, with adversarial and seeded contract tests in
`crates/fss-fusion/tests/fusion_contract.rs`.

## Intrinsic sensor common cause

Every observation supplies a producing `sensor` and a bounded nonempty set of declared
`failure_domains`. The reference always adds `sensor:<sensor>` to its effective domain set.
Two observations from the same sensor therefore share a failure domain even if their declarations
name only different models, frames, or preprocessing paths. Additional declared domains can make
observations dependent; omitting the sensor label cannot make them independent.

The same normalization applies to a predicted corroboration `Opportunity`. A future frame from
the sensor that already supplied evidence cannot be selected as independent corroboration just
because the opportunity names different domain labels. A `Probe` has no separate sensor field;
its declared domains must include every relevant source and shared dependency.

The reference joins observations transitively over shared effective domains. For example:

| Observation | Sensor | Declared domains | Effective common cause |
|---|---|---|---|
| First model result | `cam-a` | `model:first` | `sensor:cam-a` connects it to the second result |
| Second model result | `cam-a` | `clock:shared` | The sensor and clock connect both neighboring results |
| Third camera result | `cam-c` | `clock:shared` | The shared clock joins it to the same cluster |

All three belong to one dependency cluster. Each output cluster includes its effective domains,
sorted members, likelihood hull, and direction, so this decision is inspectable and digest-bound.
Input ordering does not change the query or decision digest.

As a concrete numerical case, suppose the prior log-odds interval is `[-2000, -1500]` millibans,
and two observations carry `[1600, 2000]` and `[1500, 1900]`. If they come from independent
declared domains and distinct sensors, the reference posterior is `[1100, 2400]`. If both come
from the same sensor, their cluster contributes the hull `[1500, 2000]` once, producing
`[-500, 500]`. With an alert threshold of `1000` and a two-cluster support requirement, only the
first case reaches the ordinary alert decision.

## Missing evidence and terminal decisions

Unobservable, redacted, and stale observations are excluded explicitly. Observed scores without
an admitted calibration are listed as uncalibrated and contribute no numeric likelihood.
These are incomplete evidence states, including when the remaining calibrated evidence or the
prior alone gives a low posterior.

A rejection requires all of the following:

- The posterior upper bound is at or below the policy's reject threshold.
- Coverage is `Complete` for the hypothesis scope.
- At least one usable calibrated cluster exists.
- No observation was excluded or left uncalibrated.
- The assessment is not conflicted.

Otherwise a below-threshold result is retained with `AbsenceNotCertified`, preserving evidence
and the uncertainty about absence. The same rules apply when computing leave-one-cluster-out
counterfactuals. Removing the last calibrated observation cannot turn a low base rate into an
observed absence.

An urgent single-domain exception also requires at least one robustly supporting calibrated
cluster. A high prior, an uncalibrated model phrase, or a set of entirely missing observations
cannot produce `AlertSingleDomainUnconfirmed`. The exception still requires its configured
threshold and the ordinary sequential correction, and retains its unconfirmed label.

## Numeric boundary and compatibility

Input likelihood endpoints stay within `[-100000, 100000]` millibans. Policy thresholds have
their separately declared bounds. Validation uses inclusive range comparisons, including at
`i64::MIN` and `i64::MAX`; out-of-range input returns a stable fusion refusal rather than
overflowing while taking an absolute value. The public display-probability conversion also
handles the complete `i64` domain with outward saturation, without negating `i64::MIN`.

The semantic implementation identity is
`fss-fusion:reference:hull-cluster-interval-sum:sequential-v2`. The registered query and decision
encoding domains remain `fss.fusion.query.v1` and `fss.fusion.decision.v1`: field layouts have not
changed. Every query digest already includes the implementation identity, and every decision
digest binds its query digest. The revised common-cause and terminal-decision rules therefore
produce a distinct identity even when the input and numerical result otherwise match an older
run. Earlier reports retain their original identity; they must not be relabeled as v2 results.

## Assumptions and remaining qualification

The hull rule is a simple reference model: a dependency cluster contributes one member's
admissible likelihood interval, and distinct clusters' likelihood intervals are summed under the
declared independence assumptions. The hull encloses those admissible single-member choices.
It does not establish a general bound on arbitrary dependent joint evidence.

Producing-sensor identity is now enforced intrinsically. Model lineage, training data,
preprocessing, modality, clock, network, power, geometry, and observed shared failure history
still require complete caller declarations and generation-specific qualification. Distinct
strings or model names do not prove independent errors. The current reference does not supply
measured joint-error evidence, deployment-regime validity, or independent-verifier qualification.

Score calibrations currently derive per-bin marginal Wilson intervals. They do not establish
simultaneous multi-bin coverage or an anytime-valid event-level guarantee. Sequential threshold
adjustments remain versioned policy inputs whose field-level false-alert exposure needs measured
qualification. These implementation changes leave those broader beads open.

## Focused validation

Run under the accepted repository toolchain:

```sh
cargo test -p fss-fusion
```

The suite includes same-sensor declarations that omit sensor labels, transitive common causes,
same-sensor future-observation rejection, empty and uncalibrated evidence, urgent alerts without
support, numeric extremes, ordinary independent-camera decisions, and input-order equivalence.
The 4,000-seed corpus checks posterior containment under the reference model, support thresholds,
coverage and calibration requirements for rejection, bounded waits, counterfactuals, and
deterministic digests. This is focused deterministic reference evidence; it is not the full local
release or deployment-quality qualification lane.
