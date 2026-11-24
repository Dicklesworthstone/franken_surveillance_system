# Evaluate every class at the same threshold

Pooled event metrics can hide a failed class. The optional class breakdown in
`fss-evaluate` reports each observed class separately, including classes that have
only missed truths, only false alerts, or only observations excluded by coverage gaps.
A declared inventory also displays classes with no truths or candidates.

The threshold is supplied once with `--fixed-threshold-ppm`. Choose it on the
calibration split before evaluating holdout labels. The breakdown applies that exact
inclusive threshold to every class, even when its false-alert budget is exceeded.
It never chooses a threshold per class or activates any threshold.

## Declared-label and candidate files

Use the existing version 1 TSV formats and add:

```sh
fss-evaluate \
  --labels heldout-labels.tsv --candidates heldout-candidates.tsv \
  --pipeline-generation pipeline-1 --model-generation model-1 \
  --policy-generation policy-1 \
  --max-false-alerts 1 --per-observed-ns 86400000000000 \
  --fixed-threshold-ppm 800000 \
  --class-breakdown person,vehicle,animal
```

`--class-breakdown all` includes every class present in the input truths or
candidates. A comma-separated list adds an explicit inventory; it does not filter
away other observed classes. Identifiers are exact and case-sensitive. Duplicate or
malformed inventory identifiers are refused. At most 256 distinct classes are
admitted across the observed union and declared inventory.

Each class reports its full-matching counts, precision/recall curve and AUPRC, plus
true positives, false positives, false negatives, precision, recall, budget status
and detection latency at the common fixed threshold. A zero-positive class has
undefined recall and AUPRC; an observable class with no detections has zero recall
and zero AUPRC. No alerts means undefined precision.

A label mismatch remains a false alert for the candidate's class and a missed
event for the truth's class. One-to-one matching, duplicate-alert penalties, score
ties and coverage-neutral candidates are inherited from the pooled evaluation.

## Exposure and false-alert budgets

Every class uses the **entire evaluation's observed clip time**, after merged
coverage gaps are removed. Negative clips remain in the denominator. Duration is
not restricted to clips containing a truth or candidate of that class. The
`denominator_basis` field is `all_observed_clip_time`, and `observed_ns`
is shared by all class rows. An evaluation with zero observed time has
`no_observed_time` budget status.

Class budgets are reported against the original declared budget. Multiple classes
can each be within budget while their pooled false-alert count exceeds it; retain
the pooled fixed operating point when deciding whether the overall budget is met.

## Native retained outputs

`fss-evaluate retained-package` accepts the same two options. It continues to
derive candidates exclusively from source-verified retained native outputs, with
the same custody revalidation, cancellation, source-byte and output-size limits.
No manual candidate rows or fabricated generation identities are admitted.

The selected native label is automatically included in the class inventory,
including on a negative clip with no candidates or truths. Other declared empty
classes show absence of samples; they do not claim that the single-label native
evaluation exercised those classes. The existing one-clip, one-native-label scope
remains explicit.

## Compatibility and binding

Without `--class-breakdown`, output is unchanged. With it, the existing pooled
JSON and evaluation digest remain unchanged, and a separate `class_breakdown`
object is appended. Its schema is `fss.evaluation.class_breakdown.v1`. Its
canonical digest binds the pooled report digest, sorted declared inventory,
common threshold, full exposure and every class metric. Reordering input rows or
inventory entries does not change the result.

This is a bounded projection of the existing matching; it does not repeat
candidate-by-truth matching once per class. It verifies that labels and candidates
match the parent report's canonical input digests before emitting class metrics.

These reports are derived measurements, not evidence of deployment quality.
Coverage and holdout split membership remain caller declarations. This feature
does not provide property/session split enforcement, confidence intervals,
hard-negative subtype manifests or a multi-clip native corpus reader.
