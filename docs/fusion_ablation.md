# Sensor and failure-domain loss explanations

`fss_fusion::ablate` answers one bounded counterfactual: what would the current fusion query conclude if a selected set of sensors or declared failure domains were unavailable? The result is derived advice. It does not assert that an outage occurred, certify physical independence or coverage, change a policy, or authorize an effect.

## Current retained events through CLI and MCP

The canonical `explain` operation exposes declared failure-domain loss for a current,
exactly pinned retained event with `--question what_if --counterfactual '<JSON>'`.
The request supplies a complete explicit score map and verified calibration; retained
support/contradiction labels never manufacture measurements. This projection preserves
unknown physical coverage and shared calibration dependencies, includes both complete
queries and results, and performs bounded current metadata revalidation without writing
to the deployment. It accepts declared event domains, rather than inferring physical
sensor identities from event labels. See [current event counterfactuals](AGENT_EVENT_COUNTERFACTUALS.md)
for the request schema, CLI/MCP examples, whole-result budgets and refusal behavior.

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


## Offline command

A query-only invocation keeps its existing output. Add exact source-loss selectors to request a complete explanation instead:

~~~sh
fss-fuse --query query.json \
  --without-sensor camera-west \
  --without-domain power:north > source-loss.json
~~~

The selectors form one simultaneous scenario. Repeat either option up to the shared 16-target limit. These options are incompatible with sequence/checkpoint mode: a hypothetical loss cannot consume sources or create another look.

The output schema is `fss.fusion_ablation_report.v1`. Its `ablation` field contains `fss.fusion_ablation.v1`, including `baseline.query`, `baseline.outcome`, `counterfactual.query` and `counterfactual.outcome`. Each complete query can be saved and supplied to the ordinary `fss-fuse --query` command to reproduce its numerical query and decision digests. Every opportunity and probe is included in those replay inputs, including choices that exist only in the baseline.

`calibration_provenance` retains loaded calibration identities, exact raw-score bindings and the selected prior calibration. Both the baseline and projected calibrated-input digests are included. The unchanged raw scores remain attached even when the hypothetical loss makes their observations unavailable. Two raw scores in the same calibration bin can yield the same numerical ablation while still producing distinct enclosing report receipts. A loaded artifact's identity alone does not establish calibration applicability.

`baseline_transit` is the original temporal reachability projection, when supplied. Its exact JSON SHA-256 is included as `baseline_transit_digest` and bound into the report receipt. It describes how the original opportunities were derived; the counterfactual query separately removes future choices that depend on the selected losses.

The CLI receipt domain `fss.fusion.cli_ablation.v1` encodes, in order: the domain text; core ablation digest; baseline and projected calibrated-input digests; loaded calibration count (`u32`) and each calibration's generation/digest in digest order; then a Boolean and, when present, the exact baseline transit JSON digest. The complete response, including its newline, is bounded to 16 MiB. Both replay queries must independently fit the ordinary one-MiB query parser bound. Refusal prints no partial stdout and writes no checkpoint or deployment file.

## Native event report explanations

Existing calibrated watch, corroboration and dwell reports continue to expose replayable numerical candidate queries. Those queries can be used with the offline command, where they remain caller-declared inputs and receive no new native-source claim.

A caller holding the sealed native `EventFusionReport` can also retain the original native context:

~~~rust
let explanation = report.explain_ablation(
    candidate,
    &[fss_fusion::AblationTarget::Sensor(sensor_id.to_owned())],
    cx,
)?;
let json = explanation.to_json()?;
~~~

This produces `fss.event_class_fusion_ablation.v1`. It includes the complete original report, all native source-record and raw-score/calibration links, the selected candidate's original proposal/provenance, its historical authority basis and the separate numerical ablation. The original approval and policy remain unchanged. The method checkpoints cancellation before and after the bounded computation and complete encoding.

The explanation is explicitly a historical report snapshot: `source_basis_revalidated` is false. The method does not reopen a recording or claim that the original ledger basis remains current. Existing source owners must still perform their ordinary current-authority checks for any subsequent read or native operation.

The native receipt domain `fss.event_class_fusion.ablation.v1` encodes the domain text, original report digest, exact original report JSON SHA-256, profile digest, source context digest, package digest, complete canonical historical ledger anchor, selected candidate, candidate binding, original native proposal, original native provenance and the core ablation digest. Its complete output is bounded to the same 16 MiB, with no successful prefix.

The additional regressions are `cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --test fusion_ablation_cli` and the library filter `event_fusion::tests::ablation`. They cover real CLI replay, future-choice removal, raw-score identity inside one calibration bin, incompatible sequence flags, complete native snapshot retention, historical-basis binding and cancellation/refusal.
