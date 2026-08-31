# Agent cognition, control, and accretion constitution

**Document class:** normative agent operating model, semantic protocol, and cognition/control architecture  
**Revision:** 1  
**Date:** 2026-08-31  
**Status:** binding design input; umbrella machine contract in `architecture/agent_contracts.json`  
**Companion specifications:** `AGENT_COGNITIVE_CONTROL_PLANE.md` (internal architecture) and `AGENT_OPERATING_MODEL.md` (driver-facing workflow)  
**Primary source DNA:** Dwarf Fortress MCP, Eidetic Engine CLI, FastMCP Rust, Asupersync, FrankenSQLite, Frankensearch, FrankenGraphDB, FrankenNetworkX, Franken Markdown

---

## Document hierarchy and naming

This constitution owns the public vocabulary and non-bypassable semantics.
`AGENT_COGNITIVE_CONTROL_PLANE.md` refines how the types compose internally;
`AGENT_OPERATING_MODEL.md` explains how an agent drives the same contracts. Neither companion may
define a second public verb, epistemic-state, view, or lifecycle universe. The machine umbrella is
`architecture/agent_contracts.json`; specialized registries are referenced from it.

Canonical names used throughout the repository are:

- `AgentSession`: the live region-owned runtime relationship with a principal;
- `AgentWorkspace`: the explicit versioned cognitive working set of that session;
- `AgentSessionCapsule`: one immutable serialized `AgentWorkspace` revision;
- `SituationCapsule`: the primary anchor-pinned driver publication;
- `SituationFrame`: the minimum sufficient mission-relative world projection nested inside a `SituationCapsule`;
- `ContextPack`: a budget-shaped publication of selected frame/case/evidence material;
- `HandoffCapsule`: a root-last portable object graph containing the minimum sufficient workspace,
  cases, plans, obligations, budgets, authority, and continuations for safe resumption.

### Object composition crosswalk

The object tower is deliberately nested rather than duplicative:

```text
MissionContract
  └── ObjectiveContract
AgentSession
  └── AgentSessionCapsule (immutable workspace revision)
SituationCapsule
  ├── SituationFrame
  ├── MeaningfulDelta
  ├── ContextPack
  ├── SemanticCompressionReceipt
  └── ActionAffordance[] / obligations / resource state
InvestigationCase
  └── HypothesisWorkspace / AgentFinding[] / probes / stop rules
ControlPlan
  └── prepared domain effects / waits / verification obligations
ExperienceCapsule
  └── ExecutionEpisode[] → FeedbackProposal / LearningProposal
AgentResponseEnvelope
  └── typed payload such as SituationCapsule or AgentCognitiveEnvelope
HandoffCapsule
  └── minimum sufficient root-last graph of the above continuity state
```

`AgentResponseEnvelope` is the universal transport contract. `AgentCognitiveEnvelope` is an
optional decision-oriented payload, never a competing response protocol.

Knowledge state, provenance class, and hypothesis disposition are orthogonal fields. A proposition
can be `estimated` with `derived` provenance while a hypothesis containing it is `disfavored`; no
one of those fields substitutes for the others.

## 0. North star

The agent should never have to reconstruct the property, the incident, the system health, or the
meaning of an operation by manually joining a dozen unrelated tool responses in its context window.
FSS must do that semantic integration once, deterministically, below the presentation layer.

Every agent-facing interaction should answer four questions, at the requested level of detail:

1. **What is happening?** Current material state and meaningful change.
2. **Why do we believe that?** Evidence, provenance, uncertainty, contradictions, and shared failure domains.
3. **What do we not know?** Staleness, missing coverage, unresolved hypotheses, redactions, and indeterminate effects.
4. **What can be done next?** Capability-valid affordances with expected value, cost, risk, prerequisites, and success proof.

The agent operating layer is therefore not a collection of convenience endpoints. It is a
**cognitive instrument** over a partially observed physical world: a stable tower of linked
abstractions, an explicit workspace for investigation, and a small semantic control protocol.
It makes correct reasoning cheap, incorrect confidence difficult, and consequential action
separable from interpretation.

---

## 1. Constitutional decisions

The following decisions override weaker or more tool-centric language elsewhere.

1. **The unit of interaction is a situation, not a subsystem response.** Device, media, model,
   graph, archive, policy, and effect facts are composed into one anchor-pinned `SituationCapsule`
   whose inner `SituationFrame` preserves the minimum sufficient world projection.
2. **The agent operating layer is not a fourth truth plane.** It is an inspectable, session-owned
   projection over authority and cognition that may submit typed intents to the plan/effect path.
3. **Every claim has an epistemic state.** `known`, `estimated`, `unknown`, `conflicted`, `stale`,
   `not_observable`, `redacted`, `indeterminate`, and `not_applicable` are distinct values, not
   variants of null or omitted output.
4. **Every claim has a provenance class.** Observation, derivation, prediction, memory, operator
   assertion, vendor claim, and policy are never flattened into one confidence number.
5. **Agent state is explicit and portable.** Mission, focus, active cases, cursors, selected
   evidence, budgets, and output preferences live in a versioned `AgentWorkspace`, not hidden
   conversational memory.
6. **The public verb set is deliberately small.** Open, orient, follow, query, investigate, plan,
   commit, wait, cancel, explain, handoff, feedback, and doctor compose the system. Domain-specific
   behavior is data and intent vocabulary, not a proliferation of privileged tools.
7. **Every response is progressive.** A bounded useful answer arrives before optional expensive
   refinement. Later refinement cannot erase provenance or silently change the basis anchor.
8. **Every empty result is qualified.** “No event found” is returned only with domain, continuity,
   freshness, authorization, model floor, exclusions, and stop reason.
9. **Every recommendation is an affordance object.** It states why now, expected decision benefit,
   cost, latency, risk, reversibility, required capability, preconditions, invalidators, and terminal
   success predicate.
10. **Recommendations are not authority.** An affordance can make the next move obvious without
    granting permission to execute it.
11. **Investigations preserve alternatives.** FSS maintains competing hypotheses, supporting and
    contradicting evidence, predicted observations, falsifiers, and shared failure domains until a
    registered stop rule is met.
12. **The system optimizes value of information, not information volume.** It selects the smallest
    evidence or observation set expected to reduce decision loss subject to hard safety, privacy,
    freshness, and observability floors.
13. **The system exposes why-not and what-would-change answers.** It must explain why an alert was
    not sent, why absence is uncertified, why a plan is blocked, and which evidence would change the
    decision.
14. **Meaningful deltas replace raw event spam.** Follow streams preserve terminal transitions,
    new contradictions, coverage loss, effect uncertainty, and invalidated assumptions while
    coalescing low-value churn.
15. **Silence has semantics.** A heartbeat can claim “no meaningful change” only for a declared,
    continuously observed domain and anchor interval.
16. **Long work is a durable case, plan, or obligation.** It is never tied to a live MCP request or
    assumed to vanish when the client disconnects.
17. **Counterfactuals are branches.** They can compare camera placement, model routing, policy, or
    response options, but fabricated branch state can produce only a candidate intent.
18. **Multi-agent work is coordinated without shared scratch races.** Private branches support
    speculation; shared case boards carry immutable revisions and bounded work claims; effect
    authority remains separately fenced.
19. **Context is reusable by handle.** The agent receives stable semantic handles and hydrates only
    the evidence, media, graph neighborhood, or source span needed for the current decision.
20. **Every interaction is cost-accounted.** Tokens, bytes, rows, graph operations, model work,
    latency, energy, and effect risk are visible and budgeted.
21. **Accretion is proposal-driven.** Resolved cases can emit evidence-linked learning candidates,
    hard negatives, adapter quirks, runbook improvements, and policy/model proposals. Nothing
    silently mutates canonical truth or active thresholds.
22. **Handoff is a first-class protocol.** A new agent can resume the mission, active cases,
    obligations, uncertainty, work claims, and next moves without rereading the full history.
23. **All presentations share one semantic protocol.** CLI, MCP, TUI, reports, and future UI render
    the same types and state transitions; no interface contains unique business logic.
24. **Errors are recovery instructions.** Every failure says what completed, what did not begin,
    what may have happened, what remains true, what became invalid, and the next safe protocol step.
25. **Agent quality is a release property.** FSS measures task correctness, calibration, evidence
    use, tokens, calls, latency, duplicate work, unsafe retries, handoff continuity, and operator
    intervention under a sealed scenario corpus.

---

## 2. Position in the system

FSS retains the packet, authority, cognition, and effect planes. The **agent operating layer** sits
above them as a semantic composition and control surface:

```text
                                  ┌─────────────────────────────────────────────┐
                                  │ AGENT OPERATING LAYER                       │
                                  │ mission · workspace · situation · cases     │
                                  │ context packs · affordances · handoffs       │
                                  └───────────────────┬─────────────────────────┘
                                                      │ typed intent only
             anchor-pinned projections                ▼
┌────────────────────┐   ┌────────────────────┐   ┌─────────────────────────────┐
│ AUTHORITY          │   │ COGNITION          │   │ PLAN / EFFECT               │
│ evidence · policy  │──▶│ tracks · graph     │──▶│ prepare · revalidate        │
│ coverage · receipts│   │ models · search    │   │ commit · observe · verify   │
└─────────▲──────────┘   └─────────▲──────────┘   └──────────────┬──────────────┘
          │                        │                             │ receipts
          │                        │                             ▼
          └──────────── EvidenceDeltaBatch version universe ────┘
```

The layer owns no physical fact and no effect outcome. It owns:

- session and mission negotiation;
- an explicit working set;
- situation composition and semantic deltas;
- investigations and hypothesis branches;
- context selection and progressive disclosure;
- capability-valid affordances;
- handoff and learning proposals;
- agent-task evaluation receipts.

An `AgentWorkspace` can be deleted without deleting property history. Rebuilding it from its
mission, handoff root, anchors, and case roots must reproduce the same working state.

### 2.1 The semantic narrow waist: `CognitiveFacet`

FSS becomes a synthetic system by requiring every semantic owner to project through one internal
narrow waist before it reaches the agent compositor. The contract is `CognitiveFacet`; it is owned
by `fss-agent-core` but each facet's facts retain their original domain owner.

Every facet carries the same coordinates:

```text
facet identity and semantic owner
basis anchor plus consumed high-water marks
scope, validity, capability, and privacy projection
knowledge cells with epistemic state and provenance
coverage, health, contradictions, and explicit unknowns
evidence handles and hydration prices
open obligations and indeterminate effects
resource pressure and complete operation cost
affordance seeds, prerequisites, and expected proof
invalidators, degradation, continuation, and replay identity
```

Device, media, model, graph, archive, policy, effect, and memory subsystems do not return bespoke
agent prose. They contribute only the facts and operations they semantically own through this
contract. `fss-situation` composes compatible facets at one anchor into the `SituationFrame`,
`WorldEnvelope`, `ContextPack`, and outer `SituationCapsule`; it may select and connect them, but it
cannot strengthen their epistemic state, erase their failure domain, or reinterpret completion.

This narrow waist gives the architecture both modularity and coherence: a new camera adapter or
model adds a facet producer, not a new agent ontology; a new presentation renders the same capsule,
not a new business API; and an agent can transfer its operating strategy across every subsystem
because identity, uncertainty, cost, evidence, affordance, and recovery mean the same thing
throughout the system.

---

## 3. The tower of linked abstractions

The architecture is a tower rather than a bag of components. Each level narrows raw possibility
into a more decision-useful object while retaining a reversible path to its basis.

```text
L10 Workspace and handoff
    versioned AgentWorkspace revision · resumable HandoffCapsule
     ↑ preserves
L9  Learning and memory
    scoped evidence-linked proposal · anti-pattern · fixture · runbook candidate
     ↑ derived from
L8  Outcome and episode
    prediction · execution · receipts · resource ledger · attribution · residual uncertainty
     ↑ closes
L7  Plan and effect
    witnessed contingent DAG · prepare · revalidate · commit · obligation · reconcile · prove
     ↑ selected from
L6  Affordance frontier
    robust · conditional · information-gathering · wait/watch · blocked nondominated actions
     ↑ acts on
L5  Investigation and hypotheses
    competing explanations · evidence · contradictions · predictions · falsifiers · stop rule
     ↑ reasons over
L4  Situation capsule
    SituationFrame + WorldEnvelope · MeaningfulDelta · ContextPack · control envelope
     ↑ composes
L3  Derived beliefs
    entities · tracks · associations · events · graph/search/model projections · uncertainty
     ↑ derived from
L2  World facts and coverage
    device · geometry · calibration · coverage · policy · archive · effect facts at one anchor
     ↑ grounded in
L1  Source evidence
    sensor capsules · source objects · continuity · capture-time intervals · boundary receipts
     ↑ governed by
L0  Runtime authority and custody
    context · identity · capabilities · budgets · regions · obligations · object roots · receipts
```

This is the one canonical numbered tower frozen by `architecture/agent_abstraction_stack.json`.
The physical world and external providers are outside the tower; presentation surfaces render it
rather than adding another semantic layer. `MissionContract`/`ObjectiveContract`, semantic protocol,
privacy/capability projection, and cost policy are cross-cutting coordinates over every layer.

Every level has the same seven cross-cutting coordinates:

1. **Identity** — stable external ID plus generation-safe internal handle.
2. **Basis** — exact anchor, parent roots, and consumed high-water marks.
3. **Validity** — spatial, temporal, policy, model, device, and privacy scope.
4. **Epistemics** — provenance class, uncertainty, completeness, and contradictions.
5. **Cost** — work already spent and expected marginal cost of refinement.
6. **Affordances** — valid next semantic operations, prefiltered by state and capability.
7. **Invalidation** — explicit conditions that make the object stale, unsupported, or unsafe.

A caller may move down the tower by hydrating evidence handles or move up by requesting a more
compressed decision view. No upper-level summary can sever the path to lower-level evidence.

### 3.1 Why this matters to an agent

Without the tower, an agent must remember which device response maps to which stream generation,
which detection belongs to which track, which graph path was computed against which calibration,
and whether an alert receipt was merely accepted or actually verified. That work consumes tokens
and creates silent generation errors.

With the tower, the common questions become local:

- “What changed?” compares two `SituationFrame` roots.
- “Why is this suspicious?” traverses one minimal evidence subgraph.
- “What are the alternatives?” opens the case hypothesis set.
- “What should I inspect next?” reads ranked discriminating affordances.
- “Can I act?” sees capability, precondition, risk, and approval on the affordance.
- “Did it work?” follows the plan’s obligations to terminal proof.

---

## 4. Semantic protocol: `fss/1`

MCP, CLI, and library negotiation are presentation concerns. The logical protocol is independently
versioned as `fss/1`. Session negotiation records:

```text
semantic protocol version
schema catalog digest
ontology and operation-registry generation
server implementation and release identity
supported view profiles
principal and capability grants
privacy projection
mission contract
initial EvidenceAnchor
freshness and alignment policy
resource budgets
continuation and task-resume support
```

No operation except capability/schema discovery is callable before `session.open` or
`session.resume` succeeds.

### 4.0 Exact `ContractBasis` and universal envelopes

Every public operation accepts `AgentRequestEnvelope` and returns `AgentResponseEnvelope`. The
operation registry names the one typed request payload schema for each verb; the outer envelope is
identical across Rust, CLI, MCP, TUI, report, desktop, and mobile surfaces.

`ContractBasis` pins the semantic universe used to interpret either envelope:

```text
fss/1 semantic protocol
schema catalog digest
ontology generation
operation and view registry digests
capability and error registry digests
cost registry digest
producer release identity
accepted nightly, when relevant
compatibility notes
```

The request envelope additionally binds request/principal/session/mission identity, input anchor,
expected workspace revision and decision fingerprint, registered view, target URIs, typed payload,
multidimensional budget and deadline, requested capability/privacy projection, idempotency,
continuation, maximum hydration level, compression acceptance, and control-text taint.

The server fails closed when the contract basis is unavailable or incompatible. It never guesses
that a field or operation retained its old meaning. This lets an agent cache schemas and compact
aliases safely while making semantic drift mechanically visible.

### 4.1 Minimal verb set

| Verb | Purpose | Effect authority |
|---|---|---|
| `session.open` | negotiate mission, authority, budgets, views, and initial frame | none |
| `session.resume` | restore an explicit handoff/workspace root and revalidate it | none |
| `session.orient` | produce the smallest sufficient current situation | none |
| `session.follow` | stream meaningful deltas and progress from an exact cursor | none |
| `query` | run bounded structured/semantic query at an anchor | none |
| `investigate` | create or advance a durable evidence-seeking case | none |
| `plan` | compile a desired outcome into an immutable witnessed plan | prepare only |
| `commit` | revalidate and start the exact prepared plan | capability-gated |
| `wait` | observe plans, tasks, cases, and obligations | none |
| `cancel` | request/drain/reconcile/finalize owned work | capability depends on target |
| `explain` | answer why, why-not, what-changed, or what-if | none |
| `handoff` | publish a portable session/case continuation capsule | none |
| `feedback` | propose evidence-linked correction or learning candidate | none |
| `doctor` | diagnose system/agent-state consistency and propose repair | prepare only |

Domain behavior is selected through typed targets and intent classes. For example, `plan` can
compile an alert, PTZ move, export, deletion, activation, or repair intent without exposing a
separate unbounded transport method for each provider.

### 4.2 Resource model

Illustrative resource URIs:

```text
fss://deployment/{deployment}/anchor/{anchor}
fss://deployment/{deployment}/situation/{frame}
fss://deployment/{deployment}/sensor/{sensor}
fss://deployment/{deployment}/zone/{zone}
fss://deployment/{deployment}/event/{event}/revision/{revision}
fss://deployment/{deployment}/case/{case}/revision/{revision}
fss://deployment/{deployment}/hypothesis/{hypothesis}
fss://deployment/{deployment}/evidence/{digest}
fss://deployment/{deployment}/plan/{plan}
fss://deployment/{deployment}/obligation/{obligation}
fss://session/{session}/workspace/{workspace}
fss://session/{session}/handoff/{root}
fss://doctor/{bundle}
```

Knowing a URI grants no authority. Resource reads are capability- and privacy-projected before
lookup, count, graph expansion, or absence evaluation.

---

## 5. Mission contract

The mission tells FSS what “useful” means for this session. It prevents attention ranking and
context selection from becoming generic anomaly chasing.

A mission includes:

- objective and completion criteria;
- property, zone, sensor, event, or operational scope;
- time horizon and urgency;
- protected assets and threat/benign priorities;
- privacy and disclosure constraints;
- allowed effect classes and approval requirements;
- hard resource budgets and optional soft budgets;
- freshness and completeness requirements;
- acceptable degradation;
- explicit non-goals;
- desired output/view profile;
- handoff and retention policy for agent workspace artifacts.

Examples:

```text
Investigate event E9 and determine whether an unauthorized person entered the rear yard.
Do not alert unless two independent evidence families corroborate or policy requires escalation.
Spend at most 1,800 tokens, 400 MB evidence hydration, and 2 seconds of model time.
Finish with: resolved-benign, resolved-threat, indeterminate-needs-human, or not-observable.
```

```text
Restore certified nighttime coverage of the west perimeter without moving privacy boundaries.
Prepare but do not commit device changes. Compare at least two plans and include rollback and
coverage impact.
```

The mission can be amended only through an explicit workspace revision. An untrusted camera name,
OCR string, transcript, vendor response, or retrieved document cannot rewrite it.

---

## 6. Agent workspace

An `AgentWorkspace` is the explicit state the server maintains to save the agent from restating
its task and rereading unchanged facts. It contains only references and derived working state:

```text
workspace identity and revision
mission contract and principal
current anchor and meaningful-delta cursor
selected view profile and output constraints
focus entities/zones/events
active investigation cases and private branches
pinned evidence/context-pack handles
prepared plans and observed obligations
work claims and collaborators
remaining budgets
known hazards and anti-pattern references
pending feedback/learning proposals
last SituationFrame and handoff roots
```

### 6.1 Workspace properties

- **Explicit:** the agent can inspect the entire workspace state.
- **Versioned:** updates are immutable revisions with a basis digest.
- **Portable:** a handoff capsule can reconstruct it on another authorized client.
- **Non-authoritative:** it never becomes property truth or effect proof.
- **Capability-scoped:** it cannot retain handles outside the session’s allowed projection.
- **Anchor-aware:** stale selected facts are marked or invalidated on resnapshot.
- **Deterministic:** same mission, roots, policy, and cursor produce the same reconstructed state.
- **Bounded:** working sets, cases, evidence handles, and retained transcripts have hard limits.

### 6.2 Region ownership

```text
agent-session region
├── mission/workspace coordinator
├── meaningful-delta follower
├── situation-frame builder
├── investigation case
│   ├── hypothesis branches
│   ├── evidence acquisition tasks
│   ├── graph/search/model refinement
│   └── stop-rule evaluator
├── prepared plan
│   └── committed plan obligations (after commit)
├── handoff publisher
└── feedback proposal writer
```

Closing a session drains request-owned work. Application-owned cases/plans either continue under a
durable supervisor, are explicitly transferred, or terminate with a cancellation/indeterminate
receipt. Client disconnection is never equivalent to successful cancellation.

---

## 7. Situation capsule and inner situation frame

`SituationCapsule` is the primary agent read publication. Its nested `SituationFrame` is the
minimum sufficient mission-relative world model: an immutable, anchor-pinned, budget-shaped
projection—not a mutable dashboard object. The capsule adds meaningful change, obligations,
resource pressure, context/compression proof, and the categorized control envelope.

A frame contains:

```text
identity, session, mission, anchor, previous-frame basis
one-paragraph situation summary
meaningful changes since the previous frame
highest-value attention items
current events, cases, plans, and obligations
sensor/coverage/archive/model/calibration health relevant to the mission
knowledge cells with epistemic state
contradictions and invalidated assumptions
observability and privacy limits
resource pressure and remaining session budgets
capability-valid action affordances
stable evidence and drill-down handles
continuations and resnapshot requirements
frame digest and generation identities
```

### 7.1 Mandatory summary grammar

Every nontrivial frame answers:

```text
NOW:       what materially holds at this anchor
CHANGED:   what became true/false/uncertain since the basis frame
WHY:       strongest evidence and independent corroboration
UNKNOWN:   decision-relevant missing/conflicted/stale/not-observable facts
AT RISK:   deadlines, coverage loss, indeterminate effects, or invalid assumptions
NEXT:      ranked valid affordances with marginal value and cost
```

The labels are logical fields, not necessarily literal prose headings in compact JSON.

### 7.2 Frame consistency

A frame cannot mix authority and derived generations without declaring bounded lag. The caller may
request:

- **strictly aligned:** wait/refine or return `alignment_unavailable`;
- **bounded lag:** accept named maximum high-water lag;
- **best available:** return current components with explicit staleness.

The frame builder preserves the highest-priority warnings even under a small token budget.
Optional detail is removed before uncertainty, coverage degradation, effect state, or required
operator action.

### 7.3 Evidence–possibility–control envelope

For surveillance, a single best estimate is not enough. The agent must see three linked envelopes:

1. **Evidence envelope:** facts and absences established by the current anchor, including the exact
   authorized coverage and continuity witnesses that make an absence claim possible.
2. **Possibility envelope:** materially different worlds still compatible with the evidence,
   especially high-consequence adversarial residuals that survive because of occlusion, sensor
   loss, clock uncertainty, redaction, model abstention, or conflicting observations.
3. **Control envelope:** affordances robust across every protected material world, affordances
   conditional on named worlds, information-gathering probes, wait/watch choices, and actions that
   are blocked or unsafe.

`WorldEnvelope` is the frame-level evidence/possibility object. The outer `SituationCapsule`
contains the categorized control envelope. This gives the agent a closed loop:

```text
evidence constrains possible worlds
possible worlds constrain robust control
control or observation produces new evidence
new evidence publishes a successor anchor and recomputed envelope
```

A low-ranked but catastrophic possibility cannot be compressed away. It remains an
`adversarial_residual` until a named witness, explicit scope change, or policy decision rules it
out. A consequential irreversible action is admissible only when it is robust across every
protected material world, or when the exact branch assumptions, discriminating evidence,
approval, and residual loss are explicit.

---

## 8. Knowledge cells and epistemic discipline

A `KnowledgeCell` is the smallest composable assertion in the situation model. It records subject,
predicate, value, basis, validity, epistemic state, provenance class, evidence, confidence interval,
coverage/completeness, privacy, taint, invalidators, and contradiction edges.

### 8.1 Epistemic states

| State | Meaning |
|---|---|
| `known` | directly established within the declared scope and evidence class |
| `estimated` | inferred with a registered uncertainty/calibration contract |
| `unknown` | no sufficient evidence; not equivalent to false |
| `conflicted` | material evidence supports incompatible values/explanations |
| `stale` | once supported but invalidated or outside freshness requirements |
| `not_observable` | the authorized sensor/coverage domain cannot answer the question |
| `redacted` | value exists but policy forbids disclosure to this principal |
| `indeterminate` | an external effect or transition may have occurred but cannot yet be resolved |
| `not_applicable` | the predicate has no meaning for this subject/scope |

### 8.2 Provenance classes

| Class | Meaning |
|---|---|
| `observed` | source/authority evidence directly supports the value |
| `derived` | deterministic or calibrated computation over named evidence |
| `predicted` | counterfactual or future expectation, never current truth |
| `remembered` | advisory operational memory with provenance and applicability |
| `operator_asserted` | human assertion retained distinctly from sensor evidence |
| `vendor_claimed` | device/provider statement, useful but independently qualified |
| `policy` | normative rule, threshold, or grant active at the anchor |

A value can be `estimated` and `derived`; an operator assertion can remain `conflicted`; a vendor
claim can be `stale`. Epistemic state and provenance are orthogonal.

### 8.3 No confidence laundering

Confidence is never used to erase the evidence class. A high model probability cannot turn
`derived` into `observed`. Two outputs from models sharing frames, weights, preprocessing, or
training data do not become independent corroboration merely because their scores agree.

---

## 9. Meaningful deltas and follow streams

Raw packet, frame, model, and ledger changes are too frequent and too low-level for an agent.
`session.follow` emits `MeaningfulDelta` objects derived from the one version universe.

A meaningful delta states:

- changed subject and semantic predicate;
- before/after basis or digests;
- why the change matters to the mission;
- causal parents and evidence;
- new contradiction or resolved contradiction;
- coverage/observability impact;
- assumptions, cases, plans, or obligations invalidated;
- new capability-valid affordances;
- priority and expiry;
- exact cursor and new anchor.

### 9.1 Coalescing rules

Backpressure may coalesce repeated low-value updates by stable semantic key. It may not drop:

- first appearance or terminal event transitions;
- newly `not_observable` or recovered coverage;
- a new contradiction affecting an active decision;
- an effect transition to `indeterminate`, `verified`, `failed`, or `cancelled`;
- a plan precondition becoming stale;
- an obligation deadline breach;
- a privacy/capability change;
- a model/calibration/adapter generation activation or revocation;
- a work-claim conflict or handoff failure.

### 9.2 Silence certificate

A no-change heartbeat identifies the observed domain, cursor interval, continuity, coverage
certificate, freshness, and excluded classes. It never means “nothing happened everywhere.”

---

## 10. Investigation cases and hypothesis workspaces

An investigation is a durable, shareable cognitive transaction. It has a question, completion
states, evidence budget, stop rule, and a `HypothesisWorkspace`.

### 10.1 Case structure

```text
case identity and immutable revision
mission and question specification
basis anchor and allowed observation interval
candidate hypotheses
supporting and contradicting evidence graph
shared-failure-domain map
unknowns and observability gaps
predicted observations and falsifiers
ranked discriminating evidence/observation affordances
cost and information-gain ledger
current best explanation and residual risk
stop rule and terminal disposition
```

Suggested terminal states:

```text
resolved_supported
resolved_rejected
resolved_benign
resolved_threat
abstained_insufficient_evidence
not_observable
operator_decision_required
cancelled
indeterminate
```

### 10.2 Competing hypotheses

FSS does not collapse an investigation to the current top score while material alternatives remain.
For a dark figure near a rear gate, hypotheses may include:

- resident following a normal route;
- delivery/service worker;
- wildlife plus shadow/occlusion artifact;
- unauthorized person testing the gate;
- replay/tamper or camera artifact;
- cross-camera association error.

Each hypothesis records prior basis, current probability interval or qualitative support,
evidence for/against, shared failure domains, and observations that would discriminate it.

### 10.3 Falsification and contradiction

The case engine actively seeks counterevidence. A high-risk hypothesis without attempted
falsification is incomplete. Contradiction edges are retained even after resolution so replay can
show why the decision was difficult and which evidence was decisive.

### 10.4 Stop rules

A case stops because a registered condition is met, not because the token budget happened to end.
Examples:

- required threat/benign confidence and evidence-independence thresholds reached;
- next evidence has lower expected decision value than its cost;
- all remaining discriminators are unavailable or privacy-forbidden;
- policy requires operator decision;
- time deadline reached with explicit abstention;
- external effect remains indeterminate and reconciliation is the only valid next step.

Budget exhaustion returns a resumable partial case with exactly what remains unresolved.

---

## 11. Value of information and active perception

FSS ranks candidate observations and computations by **expected reduction in decision loss**, not by
novelty alone.

For candidate action `a` under case state `s`:

```text
VOI(a | s) = expected_loss_before
           - E[expected_loss_after_observation(a)]
           - execution_cost(a)
           - privacy_cost(a)
           - operational_risk(a)
```

The exact model may be bounded, empirical, or heuristic, but it is a registered Decision Card with
hard clamps and a safe fallback.

Candidate information actions include:

- hydrate one crop, clip, audio segment, packet trace, or source span;
- inspect an adjacent camera/time interval;
- run a higher-quality detector or independent verifier;
- compare a track against geometry/temporal paths;
- ask for operator confirmation;
- move a PTZ camera through a prepared reversible plan;
- request a manually flown calibration/observation capture;
- query historical hard negatives or device quirks;
- wait for a predicted next-camera appearance;
- run archive/provider reconciliation.

### 11.1 Hard floors

VOI can choose effort only after these are satisfied:

- privacy/capability authorization;
- minimum source continuity and timing validity;
- mandatory verifier/review policy;
- effect safety and precondition freshness;
- required evidence retention;
- resource reservations for committed obligations.

A cheap but unsafe observation is inadmissible, not merely low-scoring.

### 11.2 Submodular evidence selection

Context and observation sets often have diminishing returns. FSS uses registered greedy/submodular
selection with a deterministic tie-break to choose a diverse evidence set under budget. The scalar
exhaustive oracle remains available on bounded fixtures. Selection emits a score ledger and
coverage of required evidence families.

---

## 12. Affordances: making the right next move obvious

An `ActionAffordance` is a state-valid, capability-filtered description of one possible next
semantic operation. It is the bridge between understanding and control.

Required fields include:

```text
affordance identity and verb
target and prefilled typed arguments
basis anchor and workspace/case revision
why it is relevant now
expected information gain or utility interval
estimated tokens/bytes/model/graph/time/energy cost
risk and irreversibility class
required capability, approval, lease, and privacy scope
preconditions and invalidators
predicted change and affected zones/objects/obligations
success and terminal verification predicates
rollback, compensation, or reconciliation path
alternatives and reason for rank
```

Affordances are generated after capability and privacy projection. An unauthorized operation is not
teased through hidden counts or a disabled button with sensitive metadata; it is absent or replaced
with a non-leaking denial explanation.

### 12.1 Read and effect affordances

Read/cognition affordances can execute directly within budget. Effect affordances invoke `plan`,
not the effect itself. The returned immutable plan may differ from the initial affordance after
full witness expansion and cost/risk analysis.

### 12.2 Affordance stability

An affordance is valid only for its basis anchor and invalidators. `commit` never accepts an old
affordance directly; it accepts an exact prepared plan after revalidation.

---

## 13. Planning and control

The agent states a desired semantic outcome. FSS compiles it into a plan rather than exposing
imperative provider calls.

A prepared plan includes:

- mission and intent identity;
- basis anchor and semantic read/write/negative witnesses;
- affected property, device, privacy, archive, and authority scopes;
- capability, lease, and approval requirements;
- action/obligation DAG with canonical ordering;
- predicted state, coverage, uncertainty, cost, and resource impact;
- reversible and irreversible boundaries;
- checkpoints and rollback/compensation paths;
- dispatch idempotency and operation lookup;
- per-step and terminal verification predicates;
- known failure/indeterminate paths;
- minimal explanation and decision fingerprint.

### 13.1 Preflight branch

Before a consequential commit, the agent can inspect a counterfactual branch showing:

- predicted `SituationFrame` diff;
- lost/gained observability;
- privacy and retention impact;
- expected alert or archive behavior;
- resource pressure;
- obligations and critical path;
- alternatives and sensitivity to uncertain inputs.

The branch is advisory. Commit recompiles/revalidates the intent against live authority.

### 13.2 Control hierarchy

```text
mission objective
→ semantic intent
→ prepared plan
→ effect tickets
→ adapter/provider/physical boundary
→ canonical observations and receipts
→ obligation proof
→ situation-frame and learning update
```

No lower-level response can skip an upper-level contract. A provider ACK cannot bypass the
obligation proof; a model recommendation cannot bypass the semantic intent and capability gate.

---

## 14. Explanation as a first-class operation

`explain` supports four canonical modes:

### `why`

Why is a fact, hypothesis, ranking, alert, plan step, or compatibility decision present? Return the
minimal sufficient evidence subgraph, score components, policy/model generations, uncertainty, and
shared failure domains.

### `why_not`

Why was an alternative, alert, absence claim, model route, or operation rejected? Return hard
constraint failures, missing evidence, stale preconditions, capability/privacy limits, and the
closest admissible alternatives.

### `what_changed`

What changed between anchors/frames and which assumptions, cases, plans, obligations, or memories
were invalidated?

### `what_if`

What would likely happen under a candidate observation, camera placement, policy, model route,
retention change, or effect? Return a branch result, not a claim about current reality.

Every explanation distinguishes:

```text
observed facts
calibrated derivations
policy rules
advisory memory
predictions/counterfactuals
unknown/conflicted/not-observable facts
```

---

## 15. Context packs and progressive disclosure

FSS serves views by decision need, not by database table.

### 15.1 Standard profiles

| Profile | Typical budget | Purpose |
|---|---:|---|
| `pulse` | 80–250 tokens | highest-priority material change, coverage, and obligations |
| `brief` | 400–1,000 tokens | complete mission-oriented `SituationFrame` |
| `case` | 1,000–3,000 tokens | one investigation, alternatives, contradictions, next discriminators |
| `forensic` | caller-defined | evidence graph, timelines, source spans, media handles, model receipts |
| `handoff` | caller-defined bounded root | resume mission/cases/plans/obligations without history replay |
| `machine_compact` | byte/item budget | dense deterministic JSON for automated loops |
| `human_report` | page/section budget | deterministic Franken Markdown rendering of the same semantics |

### 15.2 Selection priority

When shrinking output, preserve in this order:

1. safety/privacy/capability warnings;
2. effect and obligation state, especially indeterminate;
3. coverage and observability limits;
4. contradictions and invalidated assumptions;
5. mission-critical state and meaningful change;
6. next valid affordances;
7. evidence handles and score summaries;
8. optional narrative and low-priority detail.

No object is truncated mid-record. Omitted detail is represented by handles and continuation with
estimated cost.

### 15.3 Context pack score

A deterministic packer can combine:

```text
mission relevance
+ decision-criticality
+ causal proximity
+ evidentiary independence
+ contradiction value
+ freshness
+ calibrated confidence
+ actionability
+ novelty
+ memory applicability
- redundancy
- privacy/disclosure cost
- token/byte/latency cost
```

Hard-required items bypass ranking but remain budget-accounted. Every selected item explains its
components and tie-break.

---

## 16. Error and recovery protocol

A generic exception string is not an agent interface. The response envelope for an error or
partial result includes:

```text
stable error code and phase
current authority anchor and workspace revision
what completed and is durable
what did not begin
what may have happened
what remains true
which assumptions/handles/plans became invalid
retry class
required refresh, reconciliation, authority, or operator action
safe next affordances
budget spent and retained partial artifacts
support/evidence handles
```

Retry classes are:

```text
never_unchanged
safe_read_retry
refresh_and_retry
rebase_required
backoff
reconciliation_required
operator_action_required
resume_from_continuation
```

The system never tells an agent merely to “retry” an indeterminate effect. It identifies the
reconciliation operation and prevents duplicate commit under the same or conflicting idempotency
identity.

---

## 17. Multi-agent coherence

Multiple agents can improve coverage and parallelism only if FSS prevents duplicated investigation,
contradictory scratch state, and effect races.

### 17.1 Private and shared state

- **Private branch:** speculative notes, hypothesis changes, query results, and candidate plans.
- **Shared case board:** immutable accepted case revisions, evidence tasks, contradictions, and
  results visible to authorized collaborators.
- **Authority/effect state:** canonical system truth, leases, fences, plans, and obligations.

A private branch merge produces a proposal and conflict report. It does not overwrite the shared
case or authority.

### 17.2 Work claims

An `AgentWorkClaim` reserves bounded cognitive work such as:

- inspect camera C over interval T;
- test hypothesis H with evidence family F;
- reconcile provider operation P;
- evaluate calibration alternative A;
- review hard-negative cluster K.

Claims have owner session, scope, basis anchor, expiry, lease incarnation, dependencies, progress,
and result root. They reduce duplicate work but **confer no effect authority**.

### 17.3 Role-shaped views

Roles such as sentinel, investigator, operator, diagnostician, curator, and release verifier may
receive different mission defaults and affordance catalogs, but all use the same semantic types.
Role is never a substitute for a concrete capability grant.

### 17.4 Shared attention

The case board exposes:

- unclaimed high-value questions;
- overlapping or conflicting claims;
- results waiting for review;
- evidence that invalidated another agent’s branch;
- effect/obligation states requiring one owner;
- handoffs whose target has not acknowledged custody.

---

## 18. Accretive learning

An agent interaction is accretive when it leaves behind reusable, scoped, evidence-backed value
without contaminating truth or silently changing policy.

### 18.1 Learning candidates

After case resolution, adjudication, repair, qualification, or effect completion, FSS may propose:

- a recurring benign routine;
- a hard-negative exemplar or cluster;
- a missed-threat or near-miss slice;
- an adapter/firmware/account-region quirk;
- a calibration failure or invalidator;
- a model-generation limitation;
- a runbook or diagnostic improvement;
- a privacy or policy change proposal;
- an interface/affordance improvement;
- a new regression, replay, or red-team fixture.

Each proposal names exact evidence, applicability, counterexamples, confidence, expected benefit,
risks, privacy class, and required review. Promotion is separate and audited.

### 18.2 Feedback channels

Feedback distinguishes:

```text
fact correction
hypothesis adjudication
alert helpful/harmful
context item helpful/harmful
suggested affordance useful/misleading
runbook success/failure
model/adapter/calibration issue
interface friction or missing abstraction
```

A feedback event updates no active detector threshold or capability directly. It creates evidence
for curation, evaluation, or a prepared policy/model change.

### 18.3 Agent experience ledger

FSS retains privacy-scoped task evidence such as:

- semantic operations and anchors used;
- context packs and evidence hydrated;
- decisions and alternatives considered;
- plans prepared/committed;
- outcomes and corrections;
- tokens, bytes, model/graph work, latency, and duplicate work;
- stale-anchor and recovery events;
- handoff success;
- operator intervention.

It does not require or store hidden chain-of-thought. The ledger records externally visible
inputs, selections, actions, and outcomes sufficient for task evaluation and interface improvement.

---

## 19. Handoff and resume

A `HandoffCapsule` is a root-last ATP object graph containing the smallest sufficient continuation
state:

```text
mission and principal-compatible scope
source session/workspace identity and latest revision
current anchor and delta cursor
latest SituationFrame/context-pack roots
active case roots and competing hypotheses
prepared plans and exact validity/expiry
live obligations and reconciliation requirements
work claims and collaborator state
unresolved questions, contradictions, and observability gaps
known hazards and applicable anti-pattern handles
remaining budgets and requested view profile
ranked next affordances
learning candidates not yet curated
stable evidence handles and privacy projection
```

Resume revalidates:

- principal/capability/privacy compatibility;
- anchor and generation continuity;
- plan/affordance expiry;
- active work ownership;
- evidence/pack root availability;
- schema/semantic protocol compatibility.

Invalid items are not silently discarded. The new session receives a handoff-diff explaining what
is still valid, stale, conflicted, inaccessible, completed, or indeterminate.

---

## 20. Resource and cost model

Agent efficiency is measured across the complete decision path, not response latency alone.

### 20.1 Budget dimensions

```text
wall and monotonic time
output tokens and bytes
ledger rows and evidence objects
media bytes and decoded pixels
model invocations, device time, and scratch memory
graph nodes/edges/operations
search candidates and rerank depth
archive/provider operations and egress
human/operator review minutes
effect count and irreversibility/risk budget
```

### 20.2 Marginal-value scheduling

The session coordinator allocates remaining budget among:

- frame refresh;
- case evidence acquisition;
- model or graph refinement;
- explanation hydration;
- plan simulation;
- mandatory obligation monitoring;
- handoff publication.

Committed obligations and safety/privacy work reserve resources before optional cognition.
Adaptation may improve throughput but cannot starve terminal verification or hide coverage loss.

### 20.3 Cache semantics

Anchor-pinned query, evidence, model, graph, and context-pack results can be reused only when their
mission/profile/privacy/capability and generation identities match. Cache hits never change
completeness or authority. A cache miss may cost more; it cannot change the semantic result.

---

## 21. Self-description and robot ergonomics

An agent should be able to learn the system without reading prose documentation first. FSS exposes:

```text
fss capabilities --json
fss protocol describe --json
fss schema list|show --json
fss ontology show --json
fss recipes list|show --json
fss errors list|show --json
fss costs list|estimate --json
fss robot-docs guide
```

The catalog includes:

- semantic protocol and schema digests;
- verb/input/output contracts;
- resource URI templates;
- capability and effect registries;
- view profiles and budgets;
- stable error/retry classes;
- example transcripts and recovery recipes;
- current implementation/readiness status;
- supported and degraded device/model/graph/archive tuples;
- qualification evidence roots.

Examples are generated from the same registries used by CLI/MCP dispatch and schema validation.
A documentation example that cannot replay against the deterministic reference server is stale.

---

## 22. CLI and MCP shape

### 22.1 CLI

```text
fss session open|resume|show|close
fss orient [--view pulse|brief|case|forensic] [--since FRAME]
fss follow --cursor CURSOR [--interest SPEC]
fss query --spec FILE|- [--anchor ANCHOR]
fss case open|show|advance|claim|release|resolve
fss explain why|why-not|what-changed|what-if TARGET
fss plan --intent FILE|-
fss commit PLAN --idempotency-key KEY
fss wait TARGET
fss cancel TARGET
fss handoff create|inspect|resume
fss feedback propose|show
fss evidence inspect|hydrate
fss doctor [--workspace WORKSPACE]
```

Domain-oriented aliases may exist for humans, but they compile to this operation registry and emit
the same receipts.

### 22.2 MCP

The MCP surface mirrors the small verb set. Resources provide drill-down access. Long-running
cases/plans/tasks are application-owned and survive request completion. Progress notifications are
hints; durable state is queried by stable ID.

### 22.3 Unified response envelope

Every machine response includes:

```text
schema and semantic protocol
request/session/workspace identity
anchor and relevant derived high-water marks
status: success|partial|abstained|error|indeterminate|resnapshot_required
payload schema and payload
completeness/coverage class
budget spent and remaining
warnings/degradation/taint
capability-valid next affordances
continuation or durable task identity
```

Payloads do not need to repeat unchanged frame state. The envelope can reference a basis frame and
return only meaningful deltas.

---

## 23. Crate ownership and internal composition

Planned semantic owners:

| Concern | Owner |
|---|---|
| mission contract and negotiation | `fss-mission` |
| epistemic cells and situation composition | `fss-knowledge`, `fss-situation` |
| attention and value-of-information frontier | `fss-attention` |
| cases, hypotheses, stop rules, and work claims | `fss-investigation` |
| deterministic progressive packs | `fss-context-pack` |
| explicit session/workspace revisions | `fss-agent-workspace` |
| affordance generation and ranking | `fss-affordance` |
| transport-independent verb/resource protocol | `fss-agent-protocol` |
| handoff and resume object graphs | `fss-handoff` |
| CLI/MCP/TUI/report adapters | `fss-cli`, `fss-mcp`, `fss-tui`, `fss-report` |
| task-level evaluation and replay | `fss-agent-gauntlet` |

Internal Asupersync subjects use semantic messages rather than subsystem leakage:

```text
agent.situation.delta.v1
agent.attention.delta.v1
agent.case.command.v1
agent.case.result.v1
agent.affordance.delta.v1
agent.plan.progress.v1
agent.obligation.delta.v1
agent.handoff.command.v1
agent.feedback.proposal.v1
```

Each subject has one owner, bounded payloads, reserve/commit semantics where loss matters, explicit
ordering, replay identity, and a documented backpressure/coalescing policy.

---

## 24. Security, privacy, and taint

The agent layer is a high-value disclosure and authority boundary.

- Mission, workspace, search, graph, and context selection apply capability/privacy projection
  before expansion or scoring.
- Counts, degree, absence, snippets, attention priority, and affordance presence cannot leak hidden
  entities or zones.
- Raw media hydration requires a narrower capability than event-summary access.
- Context packs are labeled for data class, principal, purpose, retention, and exportability.
- Camera/OCR/audio/vendor/document text remains tainted and can never become a mission amendment,
  capability request, tool invocation, or confirmation seal.
- Handoffs are encrypted/authorized object graphs and cannot widen the target principal’s scope.
- Agent experience telemetry excludes secrets and unnecessary private content.
- Multi-agent work claims reveal only authorized task scope and status.

Prompt injection is treated as a provenance and authority problem, not a string-filtering problem.
Untrusted text may become evidence; only typed authenticated protocol fields can request work.

---

## 25. Determinism and qualification

The agent layer has a dedicated local qualification lane `QL-AGENT-001`.

### 25.1 Deterministic properties

For fixed source roots, mission, principal projection, anchor, workspace revision, policy,
registries, view profile, and budget:

- `SituationFrame` bytes or canonical logical digest reproduce;
- meaningful delta membership and order reproduce;
- context-pack selection, score ledger, and omissions reproduce;
- affordance membership/rank and rejection reasons reproduce;
- hypothesis updates and stop decisions reproduce;
- handoff and resume diffs reproduce;
- errors and retry classifications reproduce.

### 25.2 Scenario gauntlet

Required scenarios include:

1. cold-start orientation with no prior context;
2. overnight summary from a stale cursor;
3. ambiguous event with competing threat/benign hypotheses;
4. sensor outage turning a prior negative into `not_observable`;
5. contradictory models sharing a failure domain;
6. value-of-information choice under tight token/model budget;
7. effect lost-ACK requiring reconciliation, not resend;
8. stale plan after camera/calibration/policy change;
9. client crash followed by handoff/resume;
10. two agents claiming overlapping evidence work;
11. malicious OCR/vendor text attempting to redirect the agent;
12. privacy-scoped agent unable to infer hidden counts or graph degree;
13. context-pack harmful memory counterexample;
14. operator correction producing a proposal but no silent threshold change;
15. degraded archive/model/search components while authority remains truthful.

### 25.3 Metrics

```text
task correctness and terminal disposition correctness
calibration of confidence/abstention
evidence precision, recall, and independence coverage
calls, tokens, bytes, model time, graph operations, and wall time
first-useful-answer latency and final-resolution latency
stale-anchor/rebase frequency
unsafe retry count (must be zero)
duplicate investigation work
contradictions noticed before action
operator intervention and correction rate
handoff continuity and lost-work rate
context/affordance usefulness feedback
privacy/capability noninterference
```

The release compares the integrated agent layer against lower-level/raw-tool baselines on the same
scenario corpus. A faster answer that is less calibrated, less complete, or less privacy-preserving
is not an improvement.

---

## 26. Admission sequence

1. Freeze protocol vocabulary, knowledge states, view profiles, and schemas.
2. Build a deterministic in-memory authority/cognition fixture and `SituationCapsule` reference with `WorldEnvelope` and categorized control envelope.
3. Implement mission/workspace revisions and exact frame/delta cursors.
4. Implement knowledge cells, contradictions, and coverage-qualified emptiness.
5. Implement cases with explicit hypotheses, evidence edges, and static stop rules.
6. Implement deterministic context packs and evidence handles.
7. Implement static capability-valid affordances with no adaptive ranking.
8. Implement plan compilation, progress, obligation, and error recovery projection.
9. Implement handoff/resume and multi-agent work claims.
10. Add value-of-information and adaptive ranking only in shadow with Decision Cards.
11. Add CLI, then MCP/TUI/report adapters over the same protocol.
12. Run sealed scenario, privacy, cancellation, crash, and resource gauntlets.
13. Promote only after task-level evidence shows lower resource cost without semantic regressions.

---

## 27. Anti-patterns and explicit rejections

The following designs fail review:

- one tool per camera/vendor/model/archive command;
- an agent expected to join raw subsystem responses in its prompt;
- a hidden server-side conversational memory that cannot be inspected or handed off;
- a mutable dashboard snapshot with no anchor or previous-frame basis;
- omitted fields used to mean false, unknown, redacted, stale, and not observable;
- “top hypothesis” with no alternatives, contradictions, or falsifiers;
- next-step prose that is not machine-invokable or capability-checked;
- a recommendation without cost, risk, success proof, and invalidators;
- an empty search result without coverage/completeness;
- a progress notification treated as durable task state;
- a client timeout treated as cancellation;
- context packs selected nondeterministically or without score/evidence ledger;
- multi-agent coordination through shared mutable notes;
- work claims that accidentally confer effect authority;
- silent learning from operator feedback into active thresholds;
- memory text treated as current state or permission;
- raw media automatically embedded in every response;
- effect details hidden to make the interface look simpler;
- a “smart” agent layer that can bypass the semantic plan/effect protocol;
- an MCP-specific semantic model that diverges from CLI/library/TUI behavior.

---

## 28. Final system synthesis

The agent-intuitive system is not achieved by adding more helpful text to existing endpoints. It is
achieved by moving the semantic integration boundary downward until the agent receives coherent,
versioned, proof-carrying objects that match the way decisions are actually made.

Asupersync owns the lifetime and budgets of the session, cases, observations, and handoffs.
FrankenSQLite supplies multi-version workspaces, witnesses, and safe concurrent revision.
FrankenFS and ATP publish context, evidence, and handoff object graphs root-last and make them
repairable and portable. Frankensearch retrieves progressively; FrankenGraphDB and
FrankenNetworkX maintain the situation/evidence/task graphs and choose deterministic, complexity-
witnessed answers. Franken Markdown renders the same typed semantics for humans without creating a
second truth model. FastMCP Rust carries the small protocol without owning it. Eidetic memory makes
resolved experience reusable while remaining advisory. DSR qualifies the entire operating loop on
local machines using sealed scenarios and exact artifacts.

The resulting tower is coherent because every layer shares identity, anchor, epistemics,
capability, cost, and invalidation. It is ergonomic because the right next operation is explicit.
It is accretive because resolved work becomes scoped evidence and reviewed learning rather than
folklore. It is trustworthy because uncertainty, coverage loss, contradictions, and indeterminate
effects cannot be hidden by a convenient summary.
