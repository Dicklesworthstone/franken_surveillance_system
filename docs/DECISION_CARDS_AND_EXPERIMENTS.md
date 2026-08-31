# Decision cards, adaptive policies, and honest experiments

**Document class:** normative decision/evidence methodology
**Revision:** 1
**Date:** 2026-08-31
**Schema:** [`../schemas/decision_card.v1.json`](../schemas/decision_card.v1.json)

## 1. Purpose

FSS will contain many tempting adaptive decisions: sampling rate, model cascade depth, ATP path/repair overhead, cache admission, graph refinement, archive object size, alert review threshold, and calibration observation planning. Adaptation can save enormous compute and improve quality, but only if it remains subordinate to hard invariants and is experimentally auditable.

A `DecisionCard` is the immutable record of an adaptive or optimization choice.

## 2. Required fields

```text
decision_id and policy generation
scope/workload class
basis anchor and input feature digest
candidate arms
hard clamps and forbidden arms
objective/loss model
uncertainty/evidence state
selected arm and deterministic tie-break
shadow recommendation if not active
decision-path digest
rollback arm and trigger
outcome linkage
```

## 3. Hard versus adaptive layers

Hard rules define:

- authority/capability;
- privacy/redaction;
- freshness and coverage floors;
- source custody and integrity;
- model/calibration compatibility;
- required independent verification;
- maximum resource/thermal/financial limits;
- physical-effect prohibitions.

Adaptive policy can choose only within the surviving feasible set. Missing, reset, or uncertain adaptation falls back to a safe static baseline.

## 4. Shadow-first promotion

A new policy runs in shadow mode, emitting decision cards without changing production behavior. Evaluation compares paired outcomes against the active policy. Promotion requires:

- minimum sample/effective sample size;
- held-out or time-forward validation;
- no protected-slice regression beyond bound;
- cost/latency improvement or quality gain;
- sequentially valid evidence where monitoring is continuous;
- explicit rollback target;
- no new invariant violation.

## 5. Same-binary experiment doctrine

Performance experiments use one binary with runtime-selected arms. They share:

- input root and workload manifest;
- semantic request;
- output schema and canonical digest;
- compiler/host/profile;
- warmup and measurement method;
- receipt format.

Before timing:

1. A/A null establishes measurement noise;
2. reference and candidate output equivalence is proven;
3. workload identity is sealed;
4. resource counters are validated.

Results report distributions, tails, variation, sample count, and negative outcomes—not only a best number.

## 6. Sequential evidence

Anytime-valid e-processes or confidence sequences can monitor changes without repeated-peeking invalidity. They may trigger investigation, shadow promotion review, or rollback. They cannot bypass minimum quality/coverage/security clamps.

## 7. Conformal and calibration outputs

Conformal intervals/sets are valid only under their declared exchangeability/regime assumptions. A card includes calibration corpus, validity region, coverage target, realized coverage, drift state, and fallback. “95% confidence” without those fields is forbidden.

## 8. Negative evidence

Rejected optimizations and failed policies are retained with:

- exact hypothesis and expected mechanism;
- workload/root/toolchain;
- results and uncertainty;
- semantic divergences;
- resource regressions;
- reason for rejection;
- conditions under which retesting is worthwhile.

This prevents agents from repeatedly rediscovering seductive failures.

## 9. Initial decision families

- `DEC-ATP-PATH-001`: choose transfer path/hedge under integrity/privacy/cost clamps;
- `DEC-ATP-REPAIR-001`: choose RaptorQ overhead/cadence;
- `DEC-COGNITION-DEPTH-001`: choose cascade refinement depth;
- `DEC-FRAME-SAMPLE-001`: choose sampling rate/resolution within recall floor;
- `DEC-GRAPH-REFINE-001`: choose witness/algorithm refinement budget;
- `DEC-CACHE-ADMIT-001`: cache admission and tier;
- `DEC-ARCHIVE-OBJECT-001`: chunk/object sizing;
- `DEC-CAL-NEXT-VIEW-001`: next calibration observation by value of information;
- `DEC-MODEL-ROUTE-001`: CPU/model specialization selection;
- `DEC-ALERT-REVIEW-001`: request independent verifier/human review, never waive required review.

## 10. Admission tests

- deterministic card generation and tie-breaks;
- hard-clamp non-bypass property tests;
- reset/missing-state safe fallback;
- shadow/active isolation;
- delayed/out-of-order outcome attribution;
- regime-change and stale-card invalidation;
- protected-slice rollback triggers;
- A/A false-win rate;
- replay of every promoted policy decision;
- privacy-safe feature and report surfaces.
