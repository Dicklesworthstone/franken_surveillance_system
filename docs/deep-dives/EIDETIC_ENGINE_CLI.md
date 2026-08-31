# Deep dive: `eidetic_engine_cli` as cautious operational memory for FSS

**Document class:** normative import analysis
**Status:** design input, not an implementation claim
**FSS semantic owner:** `fss-memory`, `fss-search`, `fss-explain`, `fss-policy-advice`
**Primary source:** <https://github.com/Dicklesworthstone/eidetic_engine_cli>

## 1. Why operational memory is necessary—and dangerous

A household surveillance deployment accumulates knowledge that is not reducible to raw video:

- a firmware build intermittently stalls after key rotation;
- a tree shadow produces a recurring hard negative at sunset;
- one camera's clock jumps after power loss;
- a delivery route normally crosses a particular zone;
- an alert policy created fatigue and was rolled back;
- a calibration solve is unreliable when foliage obscures a marker;
- a model performs poorly on snow, fog, glare, or crawling subjects;
- an archive provider requires a particular multipart retry discipline.

Remembering these facts can radically improve operation and agent efficiency. But operational memory is derived, fallible, and capable of becoming self-reinforcing folklore. `eidetic_engine_cli` contributes the right posture: local-first, evidence-backed, typed memory; deterministic retrieval; provenance; confidence and decay; explicit curation; harmful feedback; no silent mutation; derived indexes that can be rebuilt.

## 2. Memory classes in FSS

FSS uses four levels, each with different authority and retention:

| Level | FSS examples | Default role |
|---|---|---|
| Working | current investigation notes, unresolved hypotheses, temporary query state | session-scoped advisory |
| Episodic | a particular outage, false alert, calibration mission, repair, or incident | evidence-linked historical record |
| Semantic | stable device behavior, environmental pattern, model limitation, site fact | reusable advisory fact |
| Procedural | validated runbook, troubleshooting rule, deployment check, rollback sequence | proposed operational guidance |

None of these is raw evidence. Every memory names its source evidence, derivation, confidence, scope, and policy epoch.

## 3. Typed memory and relation vocabulary

A memory is not a prose blob alone. It includes:

```text
memory_id
workspace_or_site_scope
level
kind
statement
source_evidence_edges
valid_time_interval
recorded_at_anchor
confidence
importance
freshness_model
helpful_and_harmful_feedback
applicability_predicates
supersedes
revival_conditions
taint_and_privacy_class
```

Relations include `SUPPORTED_BY`, `CONTRADICTED_BY`, `SUPERSEDES`, `DERIVED_FROM`, `APPLIES_TO_DEVICE_GENERATION`, `APPLIES_TO_ZONE`, `APPLIES_TO_MODEL_GENERATION`, `CAUSED_BY`, `MITIGATED_BY`, and `FAILED_UNDER`.

## 4. Evidence before promotion

A candidate procedural rule cannot become established merely because an agent wrote it. Promotion considers:

- independent evidence count and shared-failure domains;
- success and failure outcomes;
- recency and environment/firmware/model applicability;
- contradiction edges;
- held-out or replay validation where possible;
- harmful-feedback weight;
- confidence decay;
- human approval policy for high-impact guidance.

An unsupported rule remains a candidate and is ranked accordingly.

## 5. Trauma guard and anti-pattern inversion

Harmful feedback is intentionally asymmetric. A rule that repeatedly causes bad outcomes should lose trust faster than a helpful mark increases it. When evidence crosses a registered threshold, the rule is not silently deleted. It is superseded or inverted into an explicit anti-pattern such as:

> Avoid restarting adapter generation `X` before sealing its staged media root; this previously orphaned source chunks under fault schedule `Y`.

The anti-pattern preserves the causal history and becomes highly visible to future agents.

The guard is advisory. It can increase review, suggest rollback, or block automatic promotion under policy; it cannot rewrite authoritative evidence or grant/revoke capabilities by itself.

## 6. Deterministic context packs

For a task such as “investigate the west-gate alert,” FSS constructs a reproducible context pack from:

- exact event and evidence anchors;
- site/device/model/calibration-specific memories;
- relevant anti-patterns and known limitations;
- recent comparable episodes;
- procedural runbooks;
- graph-neighborhood and causal-path signals;
- strict privacy and token budgets.

The packer uses deterministic tie-breaks, type quotas, relevance/freshness/confidence components, and redundancy control. The result includes a pack hash and score ledger so an agent can ask why an item appeared or what would have changed the selection.

## 7. Memory indexes are derived assets

The canonical memory rows and evidence edges live in the authority ledger. Lexical, semantic, and graph indexes are immutable derived generations with consumed high-water marks. They can be rebuilt. Losing an index must not lose memory history or curation audit.

A query pins one memory/search/graph generation. It does not combine fresh ledger rows with stale graph scores without stating the mismatch.

## 8. Revival conditions

Some guidance becomes obsolete only while a condition holds. FSS supports explicit revival predicates:

- firmware generation changed;
- model generation retired or reintroduced;
- camera moved into a former pose;
- missing repair artifact appeared;
- archive provider behavior changed;
- a previously occluded zone became observable;
- a deferred migration completed.

Checking revival predicates is read-only. Reinstating a memory requires a recorded transition and revalidation.

## 9. Memory hygiene

The system continuously reports—not silently fixes—memory debt:

- unsupported high-confidence rules;
- stale applicability epochs;
- contradictory facts without adjudication;
- duplicate or near-duplicate memories;
- orphan evidence pointers;
- procedural rules with no outcome feedback;
- privacy scopes broader than source evidence permits;
- frequently retrieved memories that never help;
- known demand with no captured lesson.

Curation is propose → review/validate → apply, with immutable audit entries.

## 10. FSS-specific applications

### Device interoperability memory

Store exact device/firmware/app/account-region behavior, but never secrets. A memory can say a token refresh path failed under an exact tuple and cite the sanitized trace bundle.

### Environmental hard-negative memory

Record recurring glare, insects, headlights, branches, raccoons, shadows, snow, steam, or rain patterns with zone/time/season scope and exemplar evidence.

### Calibration and coverage memory

Retain why a solve was rejected, which views were degenerate, which geometry drift pattern indicated physical movement, and which zones remain uncertified.

### Model behavior memory

Record generation-scoped strengths, blind spots, calibration drift, inference-device quirks, and accepted thresholds. Never generalize across model spaces without evidence.

### Incident response memory

Capture which evidence resolved ambiguity, which alert route failed, which operator action helped, and which policy caused fatigue.

### Release and deployment memory

Surface platform-specific DSR failures, device-lab requirements, migration hazards, and exact qualification commands.

## 11. Failure modes a superficial import would create

1. **Folklore becomes fact.** Agent prose silently affects alerts.
2. **Self-confirming memories.** Retrieval boosts a claim that then creates more supporting interpretations.
3. **Global applicability.** A firmware-specific quirk is applied to every camera.
4. **Silent mutation.** A steward rewrites rules mid-investigation.
5. **Index as authority.** Deleted/stale rows remain active through embeddings.
6. **Helpful/harmful symmetry.** Dangerous rules retain trust too long.
7. **No provenance.** An agent cannot distinguish observation from remembered advice.
8. **Privacy leakage.** A context pack crosses site, zone, or principal boundaries.
9. **Nondeterministic packs.** Replay cannot reconstruct an agent's context.
10. **Memory grants authority.** A runbook sentence unlocks an effect.

## 12. Admission evidence

The operational-memory subsystem is admitted only when:

1. every memory has typed scope, provenance, and applicability epochs;
2. promotion, consolidation, supersession, retirement, and revival are immutable audited transitions;
3. pack output is byte-stable for fixed inputs/configuration;
4. every ranking component and tie-break replays;
5. harmful-feedback and decay laws have property tests and boundary fixtures;
6. deleting source evidence either deletes, redacts, or invalidates every dependent memory/index edge according to policy;
7. stale/contradictory memories are surfaced, not silently merged;
8. derived index loss and rebuild preserve canonical memory semantics;
9. capability noninterference proves memory text cannot authorize effects;
10. privacy-scoped retrieval prevents count, absence, and graph-neighborhood leakage;
11. context-pack token/byte/item budgets are hard limits;
12. replay studies show that memory improves investigation efficiency without increasing calibrated false-alert risk.

## 13. Final import rule

FSS imports Eidetic Engine's **local-first, evidence-backed, deterministic, cautiously curated memory discipline**. Operational memory can influence attention, explanation, troubleshooting, and proposed policy. It cannot alter source truth, silently mutate policy, or become an authority channel.
