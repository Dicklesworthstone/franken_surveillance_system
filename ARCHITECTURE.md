# Architecture reference

This is the compact operational reference. The comprehensive plan owns the full normative detail.

## 1. System boundary

FSS runs primarily on an operator-owned edge node. Production acquisition, packet/media parsing, model execution, graph algorithms, policy, and effects are first-party pure Rust under Asupersync. Foreign codec/model/vendor applications are pinned laboratory or migration oracles only. Cloud services are optional archives or owner-authorized vendor bridges, not the canonical cognition/control plane.

```text
camera VLAN / USB / owner cloud / drone app
                 │
      first-party scoped Rust adapters
                 │  packet capsules + receipts
                 ▼
      acquisition and continuity regions
                 │
  EvidenceDeltaBatch + source-object custody
                 │
       ┌─────────┴──────────┐
       ▼                    ▼
 live proxy          analysis/event pipeline
       │                    │
 operator UI      geometry + Rust model runtime
                            │
                    immutable event revisions
                            │
           ┌────────────────┼───────────────┐
           ▼                ▼               ▼
       alert policy      search/graph     archive root
           │                │               │
       effect receipts    agent views    B2/R2/local
```

## 2. Semantic planes

### Authority plane

Owns identities, generations, policies, receipts, original media manifests, redaction/retention,
calibration certificates, event revisions, and archive roots. It is the only plane allowed to
authorize an effect or declare canonical state.

### Cognition plane

Owns decoded surfaces, quality metrics, detections, tracks, embeddings, geometry estimates,
hypotheses, rankings, explanations, and memories. Its outputs are immutable, provenance-bearing,
versioned, and rebuildable. It can propose but not authorize.

### Effect plane

Owns alert delivery, PTZ, camera settings, exports, archive mutation, retention changes, and future
drone missions. It uses immutable intent, capability, lease fencing, idempotency, precondition
revalidation, commit, observation, and verification.

### Agent operating membrane — explicitly not a truth plane

The agent layer composes authority, cognition, effect, transfer, and presentation owners into one
mission-relative cognitive instrument. It owns `AgentSession`/`AgentWorkspace` continuity,
`SituationCapsule` construction, investigations, context packs, affordance frontiers, control-plan
composition, explanation, handoff, and advisory learning. It owns no physical fact and no effect
outcome.

```text
runtime authority and object custody
              ↓
source evidence
              ↓
canonical world facts + coverage
              ↓
derived beliefs + uncertainty
              ↓
SituationCapsule
  ├─ SituationFrame
  │    └─ WorldEnvelope: certified core/absence + material/adversarial possibilities
  ├─ MeaningfulDelta + ContextPack + SemanticCompressionReceipt
  └─ obligations/resources + robust/conditional/probe/wait/blocked control envelope
              ↓
InvestigationCase + HypothesisWorkspace + counterfactual branch
              ↓
ObjectiveContract + ControlPlan
              ↓
prepared effects → commit → observe → verify/reconcile
              ↓
ExecutionEpisode + ExperienceCapsule + reviewed learning proposal
              ↓
AgentSessionCapsule / root-last HandoffCapsule
```

Every upward projection retains stable downward evidence handles. Every downward control request
retains the mission objective, witnesses, authority, budget, expected proof, and invalidators that
justify it. Required continuity state may never exist only in conversation.

All lower semantic owners meet the membrane through the internal `CognitiveFacet` narrow waist:
identity/owner, anchor/high-water, scope/validity, typed knowledge, coverage/health,
contradictions/unknowns, evidence handles, obligations/effect uncertainty, resource cost,
affordance seeds, invalidators/degradation, and proof/continuation. This is what makes the crate DAG
modular without making the product cognitively fragmented.

## 3. Trust domains

| Domain | May access | Must not access |
|---|---|---|
| safe semantic core | typed values and injected capabilities | ambient network/filesystem/time/secrets |
| acquisition adapter | one scoped device/account and bounded output channel | canonical DB, unrelated devices, model prompts |
| media kernel | designated packet/object bytes and declared transforms | credentials, policy, archive keys, unbounded allocation |
| model runtime | authorized redacted tensors and immutable model packages | effects, vendor credentials, arbitrary filesystem/network |
| pure-Rust archive service | encrypted chunks and scoped bucket credentials | plaintext media unless policy explicitly selects it |
| report renderer | typed redacted report model and provided assets | independent data fetch or secret lookup |
| agent/MCP server | bounded projections and explicitly granted effects | generic shell, raw secret, arbitrary vendor method |

## 4. Identity and generations

Every record that can affect interpretation names exact generations:

- `device_generation`: manufacturer/model/hardware revision/serial pseudonym/firmware/app/API;
- `stream_generation`: one start/reconnect/config epoch;
- `clock_generation`: synchronization model and uncertainty;
- `calibration_generation`: intrinsics/extrinsics/time alignment/coverage certificate;
- `privacy_generation`: masks, zones, redaction, retention;
- `model_generation`: code, weights, preprocessing, runtime, quantization, hardware policy;
- `index_generation`: producer model and canonical anchor;
- `policy_generation`: alert and effect rules;
- `build_generation`: FSS source/toolchain/features/dependencies.

A query’s version universe is complete or rejected. “Latest of each” is not a coherent snapshot.

## 5. Acquisition state machine

```text
Requested
  └─ Authenticated
       └─ AdapterAccepted
            └─ FirstFrameObserved
                 └─ ContinuityVerified
                      ├─ Degraded ↔ ContinuityVerified
                      ├─ Cancelled
                      ├─ Failed
                      └─ Indeterminate
```

No transition is inferred from time alone. It requires a typed witness. A reconnect starts a new
stream generation; sequence resets cannot silently continue the old one.

## 6. Event state machine

```text
Hypothesized → Witnessed → Corroborated → Adjudicated → AlertDelivered → Resolved
      │            │             │              │
      ├────────────┴─────────────┴──────────────┴→ Rejected
      └──────────────────────────────────────────→ Indeterminate
```

Each transition creates a new immutable event revision. Rejection does not delete earlier
hypotheses. Corroboration normally requires independent failure domains; registered urgent
single-sensor exceptions must be explicit and separately measured.

## 7. Time model

Each observation stores:

- device timestamp, when present;
- host receive monotonic time;
- disciplined UTC mapping, when available;
- earliest/latest capture time;
- delay/jitter model and evidence;
- clock generation;
- sequence and discontinuity markers.

Cross-camera association operates on overlapping time intervals, not exact timestamp equality.
Uncertainty expands under packet buffering, vendor relay, dropped metadata, clock steps, and
reconnect. Excess uncertainty degrades geometry and coverage rather than quietly widening gates.

## 8. Media path

FSS has three distinct media representations:

1. **Source evidence:** original packets/files whenever policy permits. Never silently transcoded.
2. **Live proxy:** low-latency, disposable, operator-oriented stream.
3. **Analysis surfaces:** decoded/color-converted/scaled/sampled frames with exact derivation receipts.

The production media path is first-party Rust: transport, RTP/RTCP, container/timeline, access-unit parsing, source maps, bounded codec kernels, live proxy, and analysis transforms. Remux is preferred to decode/re-encode. Scalar parsers/kernels remain semantic oracles for safe optimized implementations. FFmpeg/ffprobe are differential laboratory tools only and cannot be required by a supported production profile.

## 9. Cognition path

```text
continuity + image quality + tamper
          ↓
motion/change/audio candidate generation
          ↓
fast detector / segmenter
          ↓
within-camera tracks
          ↓
geometry-constrained cross-camera association
          ↓
open-vocabulary and temporal reasoning
          ↓
independent verifier
          ↓
calibration + sequential/conformal policy
          ↓
event revision, abstention, or request for evidence
```

Every stage can degrade independently. The policy receives both positive evidence and missing-
evidence reasons. Model executors emit structured outputs only; free-form prose is an explanation
projection, not the decision contract.

## 10. Geometry path

The geometry core owns coordinate frames, transforms, uncertainty, lens/crop models, rolling
shutter, terrain/building geometry, semantic zones, visibility, occlusion, and expected transit
constraints. Learned 3D models generate proposals; robust optimization and geometric residuals
qualify them. NeRF/Gaussian splats are derived visualizations.

## 11. Storage and publication

Canonical ledger records are transactional. Large bytes live in content-addressed object storage.
Publication is:

```text
reserve identities
→ stage children
→ hash/encrypt/verify
→ commit child metadata
→ publish root last
→ verify reachability
→ schedule retrievability sample
```

Object-store success does not imply ledger publication; ledger commit does not imply remote
retrievability. Receipts preserve each boundary.


## 11.1 One version universe

Every canonical change is an immutable ordered `EvidenceDeltaBatch`. Ledger projections, graph/search generations, subscriptions, checkpoints, replicas, and branches consume the same stream and declare exact high-water marks. Every read pins an `EvidenceAnchor`; every absence claim carries a `CoverageWitness`.

## 11.2 ATP object plane

Large immutable source, checkpoint, model, graph/search, export, proof, and release objects move through ATP manifests with quarantine, per-object verification, graph-closure verification, resumable journals, repair symbols, root-last publication, and retrievability receipts. ATP never carries non-idempotent effect authority.

## 11.3 Certified graph kernel

Graph queries operate on authorized immutable projections. Non-unique results declare CGSE tie policy and output ordering. Planning-relevant calls emit `GraphAlgorithmWitness` with anchor, projection, complexity counts, budget, exactness/error bound, decision-path digest, and output digest.

## 12. Agent operating model

The primary driver publication is an immutable, anchor-pinned `SituationCapsule`:

- inner `SituationFrame`: the minimum sufficient mission-relative world projection;
- `MeaningfulDelta`: changed conclusions, invalidated assumptions/plans, obligation transitions,
  coverage changes, and newly enabled/expired affordances;
- epistemic map: knowledge state, provenance, uncertainty, contradictions, coverage, redactions,
  and validity;
- active investigations, plans, obligations, indeterminate effects, and resource pressure;
- `ContextPack` plus `SemanticCompressionReceipt` naming selected/omitted material and expansion
  handles;
- nondominated typed affordances with value, cost, latency, risk, reversibility, prerequisites,
  invalidators, authority requirements, alternatives, sensitivity, and expected terminal proof.

Knowledge state (`known`, `estimated`, `unknown`, `conflicted`, `stale`, `not_observable`,
`redacted`, `indeterminate`, `not_applicable`), provenance (`observed`, `derived`, `predicted`,
`remembered`, `operator_asserted`, `vendor_claimed`, `policy`), and hypothesis disposition are
orthogonal. None is compressed into a single confidence value.

The public `fss/1` operation grammar is:

```text
session.open · session.resume · session.orient · session.follow
query · investigate · plan · commit · wait · cancel · explain
handoff · feedback · doctor
```

Every operation accepts the same `AgentRequestEnvelope` and returns the same
`AgentResponseEnvelope`. Their `ContractBasis` pins the semantic protocol plus schema, ontology,
operation, view, capability, error, cost, producer-release, and nightly identities. The operation
registry alone selects the typed payload schema. Contract drift is therefore an explicit protocol
state rather than a hidden interpretation mismatch.

Free-form requests compile into an inspectable `AgentQueryPlan`. Domain behavior is expressed as
typed targets, query predicates, intent families, views, and evidence handles, not one privileged
tool per subsystem. Effects require an immutable prepared plan, current witnesses, exact domain
capabilities, and lease fences; recommendations never grant authority.

All responses use `AgentResponseEnvelope`. Nonterminal responses return a valid affordance or an
explicit blocked/waiting/unauthorized/redacted/not-observable/indeterminate reason. Errors preserve
valid partial results and state the next safe refresh, rebase, narrow, approve, wait, cancel,
reconcile, repair, or alternate operation. CLI, Rust API, MCP, TUI, reports, and future UI surfaces
share the same operation/view registries; MCP is a presentation adapter rather than the semantic
owner.

See [`AGENT_COGNITION_AND_CONTROL.md`](AGENT_COGNITION_AND_CONTROL.md),
[`AGENT_COGNITIVE_CONTROL_PLANE.md`](AGENT_COGNITIVE_CONTROL_PLANE.md), and
[`AGENT_OPERATING_MODEL.md`](AGENT_OPERATING_MODEL.md).
### 12.1 Evidence–possibility–control closure

The `SituationFrame` carries a `WorldEnvelope` that distinguishes the nominal estimate, certified
facts and absences, material alternative worlds, adversarial residuals, common invariants, and
unresolved dimensions. The outer `SituationCapsule` categorizes the resulting affordance frontier
into robust, conditional, information-gathering, wait/watch, and blocked actions.

This closes the cognitive-control loop without moving truth or authority into the presentation
plane:

```text
canonical evidence → protected possible-world frontier → robust/conditional control envelope
       ↑                                                         ↓
       └──────────── successor evidence and terminal proof ──────┘
```

High-consequence residual possibilities survive token compression and ranking until a witness or
explicit scope/policy decision removes them. Control plans bind the exact world-envelope digest and
name worlds in which each step is supported or unsafe.


## 13. Deployment profiles

| Profile | Intended hardware | Behavior |
|---|---|---|
| `edge-lite` | laptop/SBC/CPU-only | standards acquisition, source custody, cheap motion/detection, remote optional verifier |
| `edge-gpu` | desktop GPU/Apple Silicon/NVIDIA edge | full local detector/tracker, bounded VLM, geometry |
| `split-gpu` | edge node + trusted pure-Rust GPU executor | encrypted/authorized evidence capsules over ATP-style transport |
| `archive-only` | NAS/server | restore, scrub, search, report; no live acquisition |
| `lab` | isolated test network | proprietary adapters, packet capture, firmware matrix, aggressive faults |

Profiles change resource placement, not semantic contracts.
