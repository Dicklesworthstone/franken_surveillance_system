# Sensor and failure-domain loss explanations

`fss_fusion::ablate` answers one bounded counterfactual: what would the current fusion query conclude if a selected set of sensors or declared failure domains were unavailable? The result is derived advice. It does not assert that an outage occurred, certify physical independence or coverage, change a policy, or authorize an effect.

## Recompute the remaining evidence graph

A common-cause cluster can contain several sensors joined transitively. Removing one sensor is therefore different from subtracting its entire cluster. The owner preserves every evidence row and its calibration and likelihood. Matching observed rows become explicitly `NotObservable`; existing stale, redacted and not-observable reasons remain intact. The ordinary fusion rule then rebuilds the remaining usable components and their likelihood hulls from scratch. A removed bridge can split a component, so a counterfactual posterior can increase as well as decrease. That change describes the declared dependency graph, not newly measured evidence or independently qualified physical independence.

Matching future observation opportunities and probes are removed from the available choices. Sensor selectors match the producing sensor and explicit `sensor:<id>` dependencies. Failure-domain selectors match exact declared domain strings, including the intrinsic `sensor:<producing sensor>` domain of evidence and opportunities. Probes have no producing-sensor field, so their dependencies must be declared explicitly.

Coverage never improves. An existing gap and its reason are preserved. Complete or degraded coverage becomes a gap because the caller supplied no replacement coverage witness. Remaining negative evidence cannot turn this scenario into certified absence. The prior, policy, severity, evidence-clock time and number of looks remain exactly as supplied.

## Inputs, bounds and refusal

`AblationTarget::Sensor` and `AblationTarget::FailureDomain` select exact identities. Between one and 16 unique selectors form one simultaneous scenario. Each selector must match at least one evidence row, opportunity or probe, even if another selector overlaps it. Empty, malformed, duplicate, absent or excessive selectors refuse the entire request. Invalid original fusion queries also refuse; the caller's input is never mutated.

Existing query bounds still apply: at most 256 evidence rows, 64 opportunities and 64 probes. Every selector is checked against every row, so selector work is at most 6,144 checks. The owner performs exactly two ordinary fusion evaluations, one for the original query and one for the counterfactual. The exposed work counters measure those selector checks and evaluation calls; they are not a total internal-operation or CPU-time measurement.

The immutable `FusionAblation` exposes canonically ordered selectors, the complete original and projected queries, both recomputed outcomes, all affected evidence/opportunity/probe identities and measured work. Callers do not supply a trusted baseline outcome. No evidence stream, native source owner or live policy is changed.

## Receipt identity

The SHA-256 receipt uses canonical domain `fss.fusion.ablation.v1` and implementation discriminator `fss-fusion:ablation:unavailable-evidence:recluster:coverage-gap:v1`. Its ordered encoding is:

1. Domain and implementation text.
2. Original query digest and original decision digest.
3. Selector count (`u32`), then each sorted selector's kind and exact identity text.
4. For affected evidence, removed opportunities and removed probes, in that order: count (`u32`) and sorted identity text.
5. Counterfactual query digest and counterfactual decision digest.
6. Selector checks (`u64`) and fusion evaluations (`u32`).

Existing query and decision digests bind the complete numerical inputs, uncertainty and outputs. Input row order and selector order do not change the receipt. The receipt establishes reproducibility of this explanation; native source custody, raw-score calibration lineage, current ledger authority and physical coverage remain the responsibility of their original owners and any enclosing projection.

## Regression coverage

`cargo +nightly-2026-08-31 test --locked --offline -p fss-fusion --test ablation_contract` exercises bridge removal and re-clustering, retained correlated members, intrinsic and explicit dependency selectors, unknown/negative evidence, unavailable future choices, simultaneous order invariance, repeated-look preservation, refusal atomicity and the maximum selector bound.
