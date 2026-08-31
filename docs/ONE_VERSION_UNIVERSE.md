# One version universe and the `EvidenceDeltaBatch`

**Document class:** normative state architecture
**Revision:** 1
**Date:** 2026-08-31
**Schema:** [`../schemas/evidence_delta_batch.v1.json`](../schemas/evidence_delta_batch.v1.json)

## 1. Thesis

FSS must not have one chronology in the ledger, another in the graph, another in the search index, another in model caches, and a fifth in subscriptions. Those systems may lag or compact differently, but they consume one canonical ordered delta universe.

The unit is `EvidenceDeltaBatch`: an immutable, content-identified, canonically ordered batch published under one authority anchor.

## 2. Anchor

An `EvidenceAnchor` names:

```text
site_lineage
ledger_epoch
commit_sequence
adapter_registry_epoch
schema_epoch
policy_epoch
privacy_epoch
state_root
```

Optional cognition roots—graph, search, model-result, calibration, twin—name the exact anchor high-water mark they consumed. A derived generation cannot masquerade as current beyond that mark.

## 3. Delta batch

A batch contains ordered typed deltas such as:

- device/stream generation transitions;
- source capsule and media-object publication;
- clock-bound or health revisions;
- calibration/twin/coverage activation or invalidation;
- model invocation result publication;
- track/association/event revisions;
- alert/effect outcome transitions;
- archive replication/retrievability/repair transitions;
- privacy/redaction/deletion transitions;
- operational-memory proposals and audited curation;
- registry and compatibility changes.

Each delta has stable object identity, prior/new generation, validity interval, authority class, provenance, and optional witness/operation reference.

## 4. Canonical order

Within a batch, order is deterministic:

1. causal/precondition dependencies;
2. effect outcome monotonicity;
3. stable family order;
4. stable external object identity;
5. generation/revision;
6. delta identity.

Hash-map or thread-completion order is never canonical. If two independent deltas commute, canonical order remains a serialization choice and the trace records that independence.

## 5. Reserve → materialize → publish

A producer reserves a candidate batch with basis anchor and intended object set. It materializes all child objects and receipts under an unpublished root. The publication coordinator validates:

- basis and generation fences;
- read/write/negative witnesses;
- object closure and digests;
- policy/schema/adapter/model epochs;
- deterministic ordering;
- effect-state monotonicity;
- privacy/deletion constraints.

Only then does it assign the next commit sequence and publish the batch root. Readers never observe a batch that references missing children.

## 6. Multiple writers and deterministic combining

Capture, archive, model, graph, policy, and operator producers work concurrently. They prepare complete candidates independently. A narrow deterministic combiner sequences only the authority publication decision. It does not decode video, run models, execute graph algorithms, or upload objects while holding the publication point.

Conflicts use hierarchical semantic witnesses. Refinement can prove disjointness; budget exhaustion yields conservative conflict, never permission.

## 7. Positive and negative witnesses

A prepared decision records what it relied on:

- object generation or field value/presence;
- source interval continuity and quality;
- zone occupancy or non-occupancy over a bounded observed domain;
- track/edge existence or absence;
- coverage/calibration/model/policy generation;
- aggregate value and contributor set;
- archive/object root state;
- capability and lease fences.

Negative witnesses include explicit coverage domains. “No intruder observed” cannot be validated by cache absence.

## 8. Derived consumers

### Graph

Incrementally applies deltas into immutable graph generations. Standing Z-set-style relations retract prior tuples and add new tuples. The graph root names the consumed batch sequence and projection/capability policy.

### Search

Updates an immediately searchable bounded delta and periodically seals immutable generations. Search results cite source delta/object identities.

### Model result cache

Keys by exact input roots, model/preprocess/numeric/kernel generation, and privacy policy. Cache entries never cross version spaces.

### Subscriptions

Receive batch identities or authorized projections, not ad hoc mutable notifications. Resume uses the last verified high-water mark.

### Replication/ATP

Moves immutable batches and child object graphs. Receiver stages and verifies graph closure, then publishes the remote high-water root last.

### Time travel and branches

A branch roots at an anchor and applies hypothetical semantic deltas in an isolated namespace. It can run graph/model/policy analysis. It cannot merge fabricated state into live authority; it emits candidate intents that are recompiled against live state.

### Agent cognition, sessions, and handoff

The agent operating layer consumes the same ordered batches and publishes derived, immutable
workspace revisions. It does not maintain a conversational side chronology. In particular:

- a `SituationCapsule` names one authority anchor and the exact graph/search/model/calibration/
  memory high-water marks used by its inner `SituationFrame`;
- that frame's `WorldEnvelope` names the evidence candidate universe, certified core/absence
  witnesses, material alternative-world branch roots, protected adversarial residuals, and one
  canonical digest; the outer `controlEnvelope` is derived from that same digest and cannot mix a
  newer affordance frontier with an older belief space;
- a `MeaningfulDelta` is computed between named capsule/frame revisions and reports decision impact,
  not merely changed rows;
- an `InvestigationCase`, `HypothesisWorkspace`, finding, affordance frontier, and `ControlPlan`
  each name the anchor and prior revision on which they depend;
- a `ContextPack` and `SemanticCompressionReceipt` name the complete candidate universe and the
  exact selected/omitted classes at that anchor;
- an `ExecutionEpisode` preserves the objective, prediction, selected plan, consumed evidence,
  receipts, outcome, and residual uncertainty as they existed;
- a `HandoffCapsule` is a root-last immutable continuity graph, not a mutable snapshot exported from
  hidden client state.

Workspace publication follows reserve → materialize children → verify semantic closure → publish
workspace root. A session resume starts a new workspace revision. It rebases the handoff against the
current universe and explicitly marks stale knowledge, invalid assumptions, expired grants/leases,
obsolete aliases, superseded plans, unresolved obligations, and changed affordances. It never
silently carries an old claim or capability forward.

## 9. Compaction

Compaction changes representation, not history semantics. A compaction manifest proves equivalence between an input batch interval and a sealed state/checkpoint plus retained audit tail. Tombstones, deletion obligations, and legal retention constraints are preserved.

Old readers can continue on immutable roots. New roots publish only after independent reconstruction and replay checks.

## 10. Migration

Schema/semantic migrations are deterministic transforms from named input roots to named output roots. They carry:

- source and destination schema epochs;
- transform identity;
- loss/approximation declaration;
- row/object counts and digests;
- rejected/quarantined records;
- replay command;
- rollback root.

A migration does not edit history in place.

## 11. High-water semantics

Every response that combines authority and cognition reports:

```text
authority_anchor
search_high_water
graph_high_water
model_result_high_water
calibration_generation
coverage_generation
mission_revision
workspace_revision
situation_capsule_id
world_envelope_digest
control_envelope_digest
context_pack_root
investigation_and_plan_revisions
handoff_root_if_any
staleness_or_gap
```

Callers can require exact alignment, accept bounded lag, or receive a typed stale/degraded result. Silent generation mixing is forbidden.

## 12. Recovery

On restart:

1. find the last published authority root;
2. verify its child closure;
3. quarantine incomplete reservations/staging roots;
4. reconcile external effects and archive transfers;
5. restore derived consumers from their high-water roots;
6. replay remaining batches;
7. begin a new process/adapter observation epoch;
8. emit a recovery receipt naming unresolved or indeterminate obligations.

## 13. Admission tests

- single-threaded reference ledger differential;
- crash at every reserve/materialize/publish cut;
- concurrent disjoint/overlapping candidate schedules;
- negative-read phantom insertion;
- deterministic ordering under randomized producer schedules;
- graph/search incremental versus full rebuild equivalence;
- branch isolation and stale-live-intent refusal;
- compaction replay equivalence;
- migration determinism/rollback;
- ATP replica resume and root-last publication;
- deletion/tombstone preservation through every derived consumer.
- deterministic `SituationCapsule`/`MeaningfulDelta` generation from the same mission, anchor, and budget;
- `WorldEnvelope`/`controlEnvelope` digest alignment, possible-world closure, and protected-residual preservation;
- semantic-compression critical-preservation and omission-counterfactual tests;
- session/workspace concurrent revision and stale-rebase tests;
- handoff root-last closure plus resume under anchor/policy/model/calibration/authority drift;
- experience/learning publication that cannot mutate active truth or policy.
