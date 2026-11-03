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

## Sequential hypothesis and transcript boundary

`SequentialEProcess` owns exactly one hypothesis. A query for another hypothesis is refused
before likelihoods, supporting-domain components, counters or transcript history can change.
An invalid fusion query likewise leaves the accumulator untouched.

The historical `fss.fusion.eprocess_step.v1` numerical digest retains its original bytes. It is
not an evidence identity: different sources can produce identical numbers, and the original
infallible reset API accepts text beyond the numerical encoder's historical limit. Each accepted
observation or reset now also returns an immutable `fss.fusion.eprocess_transcript.v1` receipt.
It binds the exact fusion query and decision, or exact reset arguments; the predecessor receipt;
the canonical supporting-domain inventory; and a separate fixed-size state commitment covering
the hypothesis, configuration, step/regime and all numerical state. Exact text hashes preserve
this binding even when a historical v1 numerical encoding exceeds its text limit. Supporting-domain
components use sorted, tagged digest folds without an additional inventory-sized encoding buffer.

Replay the original ordered queries and reset reasons through the accumulator and compare
transcript digests. Reordering evidence within one canonical query preserves identity; changing
source identities, policy generations or execution history does not. Regime resets clear active
numeric evidence and support while retaining transcript ancestry. Neither the digest nor replay
establishes source custody, measured independence or a valid test supermartingale.

The legacy caller-score CLI exposes this through the explicit selector
`fss-event supervise --root DIR --site SITE --plan PLAN --transcript yes`. Its
`fss.supervisor_transcript_report.v1` wrapper contains the unchanged v1 report, ordered fusion/reset
transcripts and a separate supervisor transcript digest covering deterministic report fields,
cancellation and window metadata. Wall-clock `elapsed_ns` is excluded. Without the selector,
the original v1 JSON and numerical receipt behavior remain unchanged. The retained native
supervisor has its own custody and receipt owner; this selector does not alter that path.

## Explicit source-once sequential profile

The historical `SequentialEProcess` sums each submitted window. Its common-cause bookkeeping
prevents a repeated camera from becoming an additional independent cluster, but does not prevent
the same source from adding its likelihood again. Once two supporting clusters exist, repeatedly
submitting the same two observations can therefore cross a numerical threshold. Its default
behavior and existing receipts remain unchanged for compatibility.

`UniqueSourceEProcess` is a separate, explicitly selected profile. Its constructor takes the
original numerical configuration and a nonrefillable lifetime allowance of 1–4,096 numeric
sources. Every original evidence ID must have a binding to an optional declared source digest;
an observed calibrated row requires a digest, while nonnumeric diagnostics may explicitly have
no source. No source identity is invented for missing observations. Canonical source equality
uses digest algorithm and bytes, so the nonencoded laboratory marker cannot manufacture another
source slot.

Before changing any state, the profile validates the complete original query and exact binding
inventory. It then processes aliases in canonical order. A newly declared numeric source adds
its signed likelihood once; later identical aliases, retries and repeated windows add zero.
This applies to supporting, refuting and zero likelihoods. The original query, effective query
and every alias disposition remain in the new receipt, including steps with no new evidence.
All nonnumeric rows and query-wide coverage survive filtering, preserving missing-data and
absence semantics.

After numeric admission, a source's sensor, domains, calibration generation/likelihood,
observability and event kind are immutable within this process. A conflicting interpretation,
including conflicting aliases in one query, refuses the complete step. Query-wide coverage may
change because of other cameras; it is bound by the original/effective query receipts rather
than frozen into an individual source. A first nonnumeric sighting consumes no lifetime slot
and may later become a calibrated observation. Capacity exhaustion never accepts a valid prefix
or evicts old identities. Numerical resets clear active accumulation while retaining the source
inventory, first-admission indices and both transcript chains, so a reset cannot re-admit old
evidence or replenish the allowance.

The new `fss.fusion_unique_source_step.v1` interchange schema has a separate canonical receipt
domain, `fss.fusion.unique_source_step.v1`. Its digest binds capacity, complete lifetime inventory,
original input, all alias/source/disposition rows and the existing inner transcript, which binds
the exact effective query, decision, configuration and numerical state. Callers verify it by
replaying their ordered original queries, bindings and resets. Source keys are declarations:
changing a key declares a new source, and this profile does not independently establish custody,
physical deduplication, temporal independence, calibrated field quality or an anytime guarantee.
The native retained supervisor already owns source-row verification and cumulative deduplication;
its behavior is separate from this profile.

The explicit legacy-plan entry point is
`fss-event supervise --root DIR --site SITE --plan PLAN --unique-sources N`, with `N` in
1–4,096; the corresponding typed API is `run_unique_source_supervisor`. This selector is separate
from `--transcript yes` and is refused with retained/discovery modes. Default invocation and
transcript-only output retain their original behavior and bytes.

Each calibrated plan observation uses its supplied `evidence_digest` directly as the declared
source key. The supervisor also remembers a bounded digest of the original sensor, class label
and exact unbinned score. Reusing a source with a changed label or a different score in the same
calibration bin therefore refuses the complete run. These raw facts are committed separately
from the core likelihood interpretation. Observations discarded by a clock/health reset window
are not consumed; later actual observations may still admit those sources. Missing-source
diagnostics retain explicit null keys.

`fss.unique_source_supervisor_report.v1` contains the numerical report, every source-once step,
per-window raw-input commitments, complete core/raw lifetime inventory digests and the full
numerical configuration/source allowance. Configuration and empty inventories remain independently
bound even when cancellation occurs before the first transition. Failed runs produce no accepted
report or report export. These are still caller-score simulation results, with source custody,
statistical qualification and effects authorization explicitly unverified.

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
deterministic digests. Sequential regressions additionally cover no-mutation hypothesis refusal,
source/policy/history separation, canonical input order, reset ancestry, historical numerical
goldens and oversized reset reasons/sensors preserving complete context and subsequent state.
Source-once regressions cover repeated-source threshold inflation, alias/reordering equivalence,
mixed new/replayed/neutral steps, signed and zero increments, transactional conflicts and
capacity exhaustion, source-marker normalization and lifetime inventory preservation across resets.
This is focused deterministic reference evidence; it is not the full local
release or deployment-quality qualification lane.

## Source-once restart and continuation

The explicit `UniqueSourceEProcess` profile now supports complete bounded checkpoint export
and independently digest-pinned restoration. See [FUSION_CHECKPOINT.md](FUSION_CHECKPOINT.md)
for the frozen binary format, lifetime replay/capacity rules and caller recovery contract.
A checkpoint preserves derived state and transcript ancestry; current custody, freshness,
statistical qualification and authority remain separate owner responsibilities.
