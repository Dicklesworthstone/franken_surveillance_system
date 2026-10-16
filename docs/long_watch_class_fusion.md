# Whole-recording watch: source-bound calibrated class advice

Reference implementation for the whole-recording portion of fss-808pm. Native compilation,
fixture execution and qualification are pending for this increment. It does not close the
entire bead or qualify a detector, camera, calibration dataset or deployment.

## Operator flow

Run the existing `fss-event watch --stream-watch` with the native detector package, digest
and inference allowance. The full native report contains `analysis_digest`, `analysis_root`
and `detector_cascade.recipe_digest`. A frame count beyond the short-window limit remains
part of one complete native analysis; this adapter does not sample it down to 128 frames.

Bind an explicit labelled-count calibration, prior, decision policy, look count and evidence
clock to those exact identities. The library authoring entry point is:

```rust,ignore
let profile = EventFusionProfile::from_long_watch_counts_json(
    counts_bytes,
    expected_counts_digest,
    native.analysis_digest(),
    native.detector_recipe().ok_or("detector recipe required")?.digest(),
    native.analysis_root(),
)?;
let profile_json = profile.to_json()?;
let exact_file_digest = ContentDigest::sha256(profile_json.as_bytes());
```

The count request is the existing `fss.event_class_fusion_counts.v1` document: explicit
class index, prior, policy, severity, looks, time and per-sensor labelled bin counts. The
native `ScoreCalibration` owner calculates its likelihood intervals and digests. No new
probability, calibration or common-cause implementation is introduced. A synthetic fixture
is not a source of deployment calibration. Every applicability assertion belongs to the
operator, and authoring a file neither activates a generation nor changes policy.

Persist the exact emitted JSON bytes outside the deployment, compute their SHA-256, and
repeat the original analysis with:

```text
--fusion-profile /absolute/path/profile.json --fusion-digest sha256:HEX
```

The result keeps the native whole-recording report and adds `calibrated_class_advice`.
There is no second decode or inference pass inside fusion. Profile verification precedes
package/media reads; after the native scan, advice consumes its original class records.
Publication or retention requires a separate invocation **without** fusion options. The
native proposal digest does not authorize advice, and advice does not authorize the proposal.

## Version-two scope is not coverage

Whole-recording profiles use `fss.event_class_fusion_profile.v2`, adding the mandatory
`long_watch_analysis_root`. The field `plan_digest` binds the full **analysis digest**, not
`WatchPlan::digest()`. `cascade_digest` binds the complete retained detector recipe. The
profile must have `coverage_digests: []`: an analysis graph is not a coverage witness.

The report uses `fss.event_class_fusion_report.v2` and explicitly exposes those identities,
its source scope, bounded work and `coverage_witness_supplied: false`. The profile, context,
queries and candidate bindings preserve their distinct identities. No native media format,
recording clock, event proposal, source object or publication approval is rewritten.

Version-one input bytes and semantic digest encoding remain unchanged. Short-window APIs
refuse whole-recording profiles; whole-recording watch refuses version-one profiles. Changing
a root, analysis, detector recipe, sensor, generation, native limits or calibration requires
a newly bound profile. A file hash is checked before parsing, and native source custody,
privacy, principal, deployment anchor and requested health screening are checked around
derived analysis. Missing detections, skipped inferences and other classes are never promoted
to zero-score negative evidence.

## Complete inventory and authority boundary

The adapter admits the full bounded candidate/evidence inventory or refuses it. A candidate
with no class observation still consumes evidence budget, and refused/budget-exhausted model
work remains visible. Repeated observations sharing sensor/model/package/recipe common causes
remain one dependency cluster under the existing fusion engine. Counterfactuals and calibrated
milliban intervals therefore preserve the engine's no-double-counting rules.

Advice is read-only derived cognition. It does not publish events, retain health or coverage,
activate calibrations, certify class absence, or grant effect authority. A fusion decision
whose descriptive kind says alert is not an alert dispatch authorization.

## Focused validation

```sh
bash scripts/bootstrap_toolchain.sh
bash scripts/check_long_watch_fusion.sh
```

The focused checks cover profile compatibility, exact whole-recording scope, common-cause
clustering, missing/skipped inference accounting, late entries beyond the short-window limit,
empty recordings, stale bindings, read-only publication gates, health fencing, and AVC/HEVC
display-order inputs. These tests are fixture contracts, not field-camera or model-quality
qualification.

Whole-recording dwell and whole-recording cross-camera corroboration fusion remain separate
work. Release authority remains the repository's qualification/DSR process.
