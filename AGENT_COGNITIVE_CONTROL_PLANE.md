# Agent Cognitive Control Plane

**Document class:** normative internal architecture supplement to `AGENT_COGNITION_AND_CONTROL.md`  
**Status:** design specification, pre-implementation  
**Revision:** 1  
**Date:** 2026-08-31  
**Umbrella contract:** `architecture/agent_contracts.json`  
**Machine companion:** `architecture/agent_abstraction_stack.json`  
**Human registry:** `registries/AGENT_ABSTRACTIONS.md`  
**Primary schemas:** `schemas/agent_cognitive_envelope.v1.json`, `schemas/agent_session_capsule.v1.json`, and `schemas/agent_control_plan.v1.json`

---

## Document authority

`AGENT_COGNITION_AND_CONTROL.md` owns the public semantic protocol, canonical names, knowledge
states, provenance classes, and invariants. This document owns internal composition, control-loop
mechanics, evidence hydration, and crate boundaries. `AGENT_OPERATING_MODEL.md` is the driver-facing
workflow. Where wording differs, the constitution and `architecture/agent_contracts.json` win.

## Object composition crosswalk

The internal control plane implements the canonical nesting frozen by
`architecture/agent_contracts.json`: `SituationCapsule` contains `SituationFrame`,
`MeaningfulDelta`, `ContextPack`, `SemanticCompressionReceipt`, obligations, resources, and
`ActionAffordance` rows; `AgentResponseEnvelope` wraps the typed payload; `MissionContract` contains
an `ObjectiveContract`; `InvestigationCase` owns/references a `HypothesisWorkspace`; `ControlPlan`
owns a contingent DAG but not effect authority; `ExperienceCapsule` groups `ExecutionEpisode`
evidence and can emit advisory learning proposals; `HandoffCapsule` publishes continuity root-last.

## 0. Prime directive

`franken_surveillance_system` must be understandable and controllable as **one coherent partially
observed world**, not as a bag of camera, storage, graph, model, and alert APIs.

The system is designed for an agent that must repeatedly answer four questions:

1. **What is happening, and how do I know?**
2. **What remains uncertain, contradictory, stale, or unobservable?**
3. **What is the best next information-gathering or control action under the current budgets and authority?**
4. **Did the action actually produce the intended physical or operational result, and what should be learned from the outcome?**

The agent-facing design therefore follows one closed loop:

```text
resume
  → orient
  → hypothesize
  → choose objective
  → acquire the minimum sufficient evidence
  → simulate or plan
  → prepare effect
  → commit effect
  → watch obligations
  → verify terminal postconditions
  → attribute outcome
  → propose learning
  → publish a resumable handoff/session capsule
```

No subsystem may force the agent to reconstruct this loop from unrelated endpoints. Every subsystem
must project into the same cognitive vocabulary, version universe, evidence-handle system, budget
model, capability model, explanation model, and obligation model.

---

## 1. Constitutional role: an orthogonal control membrane

The Agent Cognitive Control Plane, abbreviated **ACCP**, is not a fourth source-of-truth plane. It is
an orthogonal membrane over the authority, cognition, effect, and evidence-transfer planes.

It owns:

- task-relative view construction;
- cognitive envelopes;
- session continuity;
- objectives and constraints;
- hypothesis workspaces;
- context selection and evidence hydration;
- contingent control plans;
- semantic next-action ranking;
- agent-facing explanation;
- execution-episode attribution;
- typed handoff;
- learning proposals and procedural-memory candidates.

It does **not** own:

- source observations;
- canonical event truth;
- model inference truth;
- policy truth;
- device credentials;
- effect authority;
- storage durability;
- graph/search/model semantics;
- autonomous learning promotion.

The membrane composes those owners without erasing their boundaries. A `SituationCapsule` may summarize through its inner `SituationFrame`
an event, but the event revision remains owned by the authority plane. A `ControlPlan` may contain a
prepared alert step, but the effect protocol remains owned by the effect plane. An explanation may
select a minimal causal subgraph, but graph output remains a derived projection with a witness.

### 1.1 `CognitiveFacet`: the internal composition ABI

Every lower semantic owner implements one typed `CognitiveFacet` projection. It carries owner and
facet identity, basis/high-water, scope/validity, typed knowledge cells, coverage/health,
contradictions/unknowns, evidence handles and prices, open obligations/indeterminate effects,
resource state/cost, affordance seeds, invalidators/degradation, and proof/continuation. The
projection is capability- and privacy-filtered before composition.

The situation compositor accepts only mutually compatible facets from the same version universe.
It may join and compress them, but cannot change owner semantics, infer hidden counts, convert a
model result into observation, convert dispatch into completion, or invent an operation not present
in the registered facet/operation universe. This is the internal ABI that lets independently owned
subsystems form one cognitive instrument without coupling their implementations.

---

## 2. The tower of linked abstractions

The central design is a tower in which each layer answers one agent question, retains handles to the
layer below, and supplies typed inputs to the layer above.

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

This tower is intentionally **not** a pipeline that always runs end to end. The agent may enter at any
level and drill downward only when required. A routine status check can stop at L4. An ambiguous
perimeter event may move among L4, L5, and L6 several times. A consequential effect never skips L7,
and learning never skips the L8 outcome/attribution record.

`MissionContract` and `ObjectiveContract` supply purpose, constraints, budgets, and terminal proof
across the tower rather than occupying a competing numbered layer. Presentation surfaces are views
over the tower; the physical world is outside it. The machine registry assigns stable
`AGT-LAYER-*` identifiers and semantic owners to every canonical layer.

---

## 3. Universal response envelope and cognitive payload

Every CLI, library, MCP, TUI, and operator-facing result MUST use
`fss.agent_response_envelope.v1`. Decision-bearing payloads MAY use
`fss.agent_cognitive_envelope.v1`; orientation normally carries
`fss.situation_capsule.v1`. This two-level contract separates universal transport/lifecycle facts
from specialized cognitive content without allowing each subsystem to invent an answer shape.

### 3.0 Exact contract basis and request envelope

Every public operation enters through `fss.agent_request_envelope.v1`. The envelope carries a
`ContractBasis` that pins `fss/1`, schema/ontology/operation/view/capability/error/cost registry
digests, producer release identity, and accepted-nightly compatibility. It then binds the request
lifecycle, principal/session/mission, input anchor and expected workspace revision, registered view,
target URIs, operation-specific typed payload, budget/deadline, requested authority and privacy
projection, idempotency, continuation, expected decision fingerprint, hydration ceiling,
compression policy, and untrusted-control-text taint.

`architecture/agent_operations.json` is the sole mapping from `AOP-*` to its request payload schema.
A transport may serialize differently but may not invent a second parameter vocabulary or bypass
the envelope. An incompatible `ContractBasis` is a typed refusal with discovery/upgrade
information, never a best-effort reinterpretation.

### 3.1 Required envelope fields

Every envelope includes:

```text
identity
  schema
  request_id
  session_id / session_revision
  response_id
  trace_id
  decision_digest

world position
  deployment_id
  basis_anchor
  result_anchor
  derived_generation_roots
  freshness interval
  continuation basis

task position
  objective_id
  question or semantic verb
  active plan/step/obligation identities
  caller capability projection

epistemic contract
  answer class
  known facts
  inferred propositions
  contradictions
  unknowns
  not-observable domains
  stale claims
  assumptions
  invalidators
  confidence/calibration metadata

coverage and omission
  authorized domain
  observed domain
  indexed/derived domain
  omitted item count
  omission reasons
  truncation policy
  stop reason

resource account
  requested budget
  consumed budget
  remaining budget
  degraded dimensions
  marginal work declined

evidence access
  stable evidence handles
  current hydration level
  permitted hydration levels
  redaction/privacy transform
  source lineage and digest

control affordances
  ranked next actions
  expected information gain
  expected objective gain
  estimated cost
  risk and reversibility
  required capability/grant
  stale/invalidating conditions
  deadline/lease/fence requirements
  whether the action is read, simulation, prepare, commit, verify, or repair

continuity
  resumable cursor
  recommended re-anchor condition
  session-capsule delta
  unresolved obligations
```

### 3.2 Answers are typed, not prose-shaped

An answer declares one of these coarse classes:

- `direct_fact` — supported by canonical facts at the named anchor;
- `bounded_summary` — a task-relative projection with declared coverage and omissions;
- `hypothesis_set` — competing explanations with supporting and contradicting evidence;
- `recommendation` — a policy/decision result with alternatives and loss factors;
- `plan` — an immutable contingent DAG;
- `effect_status` — lifecycle state of a prepared/committed effect;
- `obligation_status` — unresolved work and terminal criteria;
- `learning_proposal` — advisory, evidence-linked candidate for future reuse;
- `refusal` — authority, privacy, freshness, evidence, or budget preconditions were not met;
- `indeterminate` — the system cannot truthfully classify the physical or external outcome.

Human-readable prose is a rendering of these fields, never the sole semantic contract.

### 3.3 Knowledge state, provenance, and hypothesis disposition are not flattened

Every material proposition carries one knowledge state from the canonical registry:

```text
known · estimated · unknown · conflicted · stale
not_observable · redacted · indeterminate · not_applicable
```

It separately carries one or more provenance classes:

```text
observed · derived · predicted · remembered
operator_asserted · vendor_claimed · policy
```

A hypothesis has its own disposition (`live`, `supported`, `disfavored`, `refuted`, `resolved`, or
`superseded`). These coordinates answer different questions and may never be collapsed into a
single confidence scalar. Compression, context packing, rendering, resume, and handoff preserve all
three. In particular, `unknown`, `not_observable`, `redacted`, and `indeterminate` never become
“false,” and an omitted contradiction may never make a hypothesis appear uncontested.

### 3.4 Ranked next actions are part of the answer

A good agent-facing response should not merely report state. It should expose a bounded action set
that makes the control topology legible. Each next action carries a decision card:

```text
action_id and semantic verb
what uncertainty or objective component it addresses
expected information gain and objective gain
estimated latency, tokens, bytes, CPU/GPU, energy, archive, and human attention
risk, privacy exposure, reversibility, and blast radius
required capability, grant, lease, fence, and approval
preconditions and invalidators
safe fallback and stop condition
expected terminal evidence
```

The ranking may adapt to task and budget, but hard safety/privacy/authority clamps dominate any
learned preference.

---

## 4. Stable evidence handles and progressive hydration

Agents should reason primarily over compact stable handles and hydrate only the evidence that changes
a decision.

### 4.1 Handle contract

An `EvidenceHandle` names:

- canonical object identity;
- source/object digest;
- basis anchor or source-capsule interval;
- media/time/spatial span;
- privacy class and applied transform;
- current availability and retention horizon;
- permissible hydration levels;
- required capability;
- expected hydration cost;
- lineage to derivative crops, embeddings, tracks, or explanations.

Hydrating a handle never changes what it denotes. If the underlying object was superseded, deleted,
expired, corrupted, or privacy-transformed, hydration returns that state rather than silently binding
the handle to a replacement.

### 4.2 Hydration ladder

```text
H0 Identity
   digest, type, time/spatial bounds, source and availability only

H1 Semantic synopsis
   compact typed facts, model outputs, contradictions, provenance, and quality

H2 Decision artifact
   redacted keyframes/crops/audio features/trajectory/graph neighborhood needed for review

H3 Source evidence
   authorized encoded packets, original object bytes, exact metadata, or full-resolution media

H4 Laboratory expansion
   replay bundle, intermediate tensors, alternate decoder/model outputs, or oracle comparison
```

H0/H1 are optimized for routine agent work. H2 is the default for incident adjudication. H3 requires
stronger evidence-access capability. H4 is qualification-only unless an explicit debugging grant
exists.

### 4.3 Hydration is value-of-information driven

The system estimates whether hydration is worth its marginal cost. It never forces the agent to
retrieve a full clip merely because one exists. It also never suppresses evidence that is required
for a consequential effect or absence certificate. The action selector records why it hydrated,
deferred, or declined each candidate.

---

## 5. `SituationCapsule` and its minimum sufficient `SituationFrame`

A raw world snapshot is too large, while a prose summary is too lossy. `SituationFrame` is a typed,
anchor-pinned, task-relative projection. `SituationCapsule` is the primary publication that combines
that frame with meaningful delta, obligations, resource pressure, affordances, a selected
`ContextPack`, semantic-compression proof, validity, and continuation.

### 5.1 Contents

A frame includes:

- objective and authorized scope;
- anchor and freshness;
- salient entities, zones, tracks, events, devices, and obligations;
- active causal/dependency subgraph;
- material changes since the preceding frame;
- top contradictions and uncertainty drivers;
- coverage and sensor-health state relevant to the task;
- policy, model, calibration, adapter, privacy, and archive generations that matter;
- deadlines, expiring leases, retention hazards, and unresolved external effects;
- compact evidence handles;
- excluded domains and omission reasons;
- recommended information/control actions.

### 5.2 Minimal sufficient, not merely short

Context selection solves a constrained decision problem rather than a generic top-k ranking.
Candidates are scored using:

```text
expected harm avoided
+ objective relevance
+ uncertainty reduction
+ causal/dependency criticality
+ deadline urgency
+ actionability
+ novelty
+ contradiction value
+ obligation closure value
- redundancy
- token/byte/model/latency cost
- privacy exposure
- cognitive fragmentation
```

Hard inclusions override the score:

- any fact whose omission can reverse the selected action;
- any contradiction that invalidates the leading hypothesis;
- any unobservable domain relevant to an absence or safety claim;
- any active consequential obligation;
- any capability or policy constraint blocking an apparently available action;
- any stale generation used by an active plan.

The selector uses graph dominators, minimal cuts, causal ancestors, submodular coverage, and typed
quotas to find a compact **decision-sufficient evidence subgraph**. It emits a selection witness and
a counterfactual omission test: removing each load-bearing item should either preserve the decision
or be identified as decision-changing.

### 5.3 Frame delta

A resumed agent receives a frame delta before a new full frame:

- facts added, revised, invalidated, or deleted;
- hypotheses strengthened, weakened, split, merged, or refuted;
- plans/steps made stale;
- obligations created, progressed, completed, or made indeterminate;
- budgets consumed or replenished;
- relevant model/adapter/calibration/policy/privacy generation changes;
- new procedural memories or warnings that match the objective.

This prevents cold re-reading while avoiding “memory” that silently survives invalidation.

### 5.4 The evidence–possibility–control doctrine

`SituationFrame` carries a `WorldEnvelope`, not merely a point estimate. The envelope has three
coupled projections:

- **certified core:** propositions and absence predicates established for the current anchor;
- **material possibility frontier:** nondominated alternative worlds and protected adversarial
  residuals still compatible with evidence, capability, privacy, and observability limits;
- **unresolved dimensions and collapse affordances:** the cheapest authorized observations that
  would separate worlds or prove that a distinction no longer matters.

The outer `SituationCapsule.controlEnvelope` classifies each currently addressable affordance as:

```text
robust_across_envelope
conditional_on_named_worlds
information_gathering
wait_and_watch
blocked
unavailable
```

The control plane therefore plans in **belief space**. A `ControlPlan` step names the exact
WorldEnvelope digest, the worlds it supports, the worlds in which it is unsafe, and its robustness
class. Observation steps may shrink or split the possibility frontier; coverage loss or contradiction may expand it. Effect steps may commit only
when their robustness/branch contract remains true at revalidation.

This is stricter than choosing the most probable hypothesis. Rare but protected high-loss worlds
remain decision-relevant even when their posterior mass is small. Their removal requires evidence,
not ranking pressure.

---

## 6. `HypothesisWorkspace`: explicit competing explanations

An agent should never have to maintain competing event interpretations only in its transient chain of
thought. The system exposes a durable, typed hypothesis workspace.

### 6.1 Hypothesis structure

Each hypothesis contains:

- proposition and scope;
- originating question/objective;
- basis anchor;
- supporting, contradicting, and missing evidence handles;
- causal/temporal/spatial constraints;
- likelihood or confidence with calibration class;
- observability prerequisites;
- assumptions and invalidators;
- predicted future observations;
- distinguishing tests against competitors;
- consequences if accepted, rejected, or left unresolved;
- status: proposed, viable, leading, weakened, refuted, merged, split, or retired.

### 6.2 Competition, not premature collapse

The workspace preserves multiple hypotheses until evidence or a bounded decision rule justifies
selection. A high model score cannot erase a low-probability/high-loss alternative. The system can
choose an action under uncertainty while still retaining competitors.

Example for a rear-yard trajectory:

```text
H1 resident taking out trash
H2 raccoon near bins
H3 delivery worker crossing permitted route
H4 crawling intruder exploiting camera blind strip
H5 image artifact caused by rain/IR bloom
```

The next observation should be selected for its ability to discriminate among these hypotheses,
not merely to increase confidence in H1.

### 6.3 Expected surprise and active observation

A hypothesis declares predicted observations. Incoming evidence is scored for surprise. High surprise
can trigger:

- additional camera hydration;
- a different model family;
- graph/trajectory recomputation;
- operator review;
- calibration or sensor-health inspection;
- a new hypothesis rather than forced assimilation.

Surprise is advisory. It cannot authorize an effect.

---

## 7. `ObjectiveContract`: making intent executable and bounded

Natural-language goals are useful for elicitation but too ambiguous to drive effects. The system
compiles them into an immutable `ObjectiveContract`.

### 7.1 Contract fields

```text
objective identity and human/agent source
semantic desired outcome
success predicates
failure predicates
terminal/stop conditions
hard safety, privacy, legal, and authority constraints
soft preferences and utility weights
spatial, temporal, subject, device, and data scope
quality/recall/false-alert requirements
latency and deadline requirements
resource budgets
allowed observation and effect classes
required approvals
acceptable uncertainty and abstention behavior
reversibility/rollback requirements
escalation policy
learning/feedback policy
```

### 7.2 Lexicographic constraints before utility

The planner first eliminates actions violating hard constraints. It then minimizes expected loss or
maximizes utility among admissible actions. An inexpensive action is never preferred if it violates
privacy scope, loses evidence required for verification, exceeds authority, or increases a
high-severity miss risk beyond the objective contract.

### 7.3 Objective decomposition

Objectives compile into a typed DAG of subobjectives, evidence requirements, and terminal predicates.
For “investigate overnight activity and alert only if warranted,” the DAG may contain:

```text
establish sensor/coverage validity
→ enumerate candidate event intervals
→ associate tracks across cameras
→ distinguish resident/animal/artifact/intruder hypotheses
→ quantify unresolved high-loss alternatives
→ prepare alert only if policy predicate holds
→ verify delivery or reconcile indeterminacy
→ publish incident summary and learning proposal
```

Decomposition is recorded so later outcomes can be attributed to the failing assumption or step.

---

## 8. Cognitive economy and the value-of-information scheduler

The system should spend the least resources that preserve decision quality, not merely minimize
latency or token count.

### 8.1 Unified budget vector

Every request, session, and plan carries a vector budget:

```text
wall/virtual time
tokens and result bytes
source-media bytes
network bytes
CPU cycles or normalized compute units
accelerator milliseconds and memory
model invocations by class
graph/search expansions
archive reads and egress
energy/thermal allowance
privacy exposure budget
human-attention requests
retry and external-effect attempts
```

Budgets are inherited and narrowed through Asupersync `Cx`. A child cannot recover a dimension that
a parent removed.

### 8.2 Marginal decision value

Candidate work is ordered by:

```text
E[decision loss before work] - E[decision loss after work]
----------------------------------------------------------
weighted marginal resource and privacy cost
```

The estimate includes uncertainty and a conservative fallback. The system stops refinement when:

- the objective’s terminal predicate is proven;
- remaining uncertainty cannot change the admissible action;
- the next action has negative marginal value;
- a hard budget is exhausted;
- the world has changed enough to require re-anchoring;
- a required capability/approval is absent;
- the domain is not observable with current sensors.

### 8.3 Asymmetric rare-event loss

Security decisions are highly asymmetric. The scheduler cannot optimize average convenience while
starving low-frequency, high-loss hypotheses. It reserves protected evidence and compute budgets for:

- stealth/crawl/occlusion/night/rain threat families;
- deteriorated coverage;
- contradictions between independent sensors;
- model abstention on high-severity zones;
- active alert/effect obligations;
- privacy/deletion deadlines.

### 8.4 Resource degradation is explicit

When resources are reduced, the envelope declares exactly which dimension degraded:

- lower temporal sampling;
- lower spatial resolution;
- fewer model families;
- coarser graph refinement;
- uncertified absence;
- delayed archive hydration;
- broader confidence interval;
- operator review required.

The system never turns reduced work into unchanged confidence.

---

## 9. Public semantic operation surface

The public `fss/1` operation registry is intentionally narrow and is shared by the Rust API, CLI,
MCP, TUI, reports, and handoff transcripts:

```text
session.open     negotiate mission, authority, privacy, budgets, views, and initial frame
session.resume   restore a workspace/handoff root and enumerate invalidated state
session.orient   produce the smallest sufficient current SituationFrame
session.follow   stream meaningful deltas from an exact continuation
query            run a bounded typed or natural-language-compiled read
investigate      create or advance a durable evidence-seeking case
plan             compile an immutable witnessed contingent plan
commit           revalidate and start the exact prepared plan
wait             observe cases, plans, effects, transfers, and obligations
cancel           request, drain, reconcile/compensate, and finalize owned work
explain          answer why, why-not, what-changed, or what-if
handoff          publish a root-last portable continuation capsule
feedback         record a correction, outcome signal, or learning proposal
doctor           diagnose consistency and prepare sealed repair affordances
```

Hydration, comparison, counterfactual simulation, work claiming, adjudication, repair, activation,
export, deletion, PTZ, and alerting are typed targets or intent families under these operations.
They do not create a second public verb universe. `plan` is non-effectful; `commit` is the ordinary
consequential effect boundary. A transport may omit an unqualified operation but cannot redefine
it. Exact fields, schemas, capability requirements, retry classes, and default views live in
`architecture/agent_operations.json`.

---

## 10. `ControlPlan`: a contingent DAG, not a command list

### 10.1 Plan identity

A plan is immutable and bound to:

- objective contract;
- basis anchor and allowed freshness window;
- selected situation frame and context-pack root;
- hypothesis workspace revision;
- policy/model/calibration/adapter/privacy generations;
- caller capability projection;
- budget allocation;
- planner/tie-break/numeric policy;
- complete step DAG and decision digest.

### 10.2 Step kinds

```text
Observe         acquire or hydrate authoritative evidence
Compute         derive a deterministic projection
Compare         test alternatives under a declared criterion
Simulate        evaluate a branch without live effects
Decide          choose among typed alternatives
PrepareEffect   reserve and seal an exact consequential intent
CommitEffect    cross an external effect boundary
WaitFor         await a condition/deadline/receipt under an owned obligation
Verify          prove a semantic postcondition
Repair          apply a sealed, revalidated repair plan
Learn           produce an advisory outcome-attributed proposal
Checkpoint      publish resumable episode/session state
```

Observation/compute/simulation steps and effect steps are type-distinct. A planner cannot reinterpret
an `Observe` step as a `CommitEffect` step through free-form parameters.

### 10.3 Per-step contract

Every step declares:

- stable identity and dependencies;
- owner subsystem and semantic verb;
- input/output schema;
- read/write/negative witnesses;
- required capability, grant, lease, and fence;
- budget and deadline;
- expected information and objective gain;
- risk, privacy exposure, and reversibility;
- preconditions and invalidators;
- expected evidence/receipt;
- success, failure, cancellation, and indeterminate transitions;
- fallback/replan/compensation rule;
- terminal proof requirement;
- deterministic tie-break for multiple runnable steps.

### 10.4 Online replanning

A plan does not pretend the physical world is static. Before a step runs, the executor compares its
witnesses with the current anchor. It can:

- continue because witnesses remain valid;
- refine a conservative witness;
- skip a now-satisfied step;
- choose a registered contingent edge;
- pause for approval/capability;
- recompile the affected subgraph;
- mark the plan stale and return a reorientation envelope.

It cannot silently execute a semantically different step under the old plan identity.

### 10.5 Plan explanation

An agent can ask:

- Why is this step necessary?
- What evidence does it depend on?
- Which alternative was rejected, and under which loss assumptions?
- What would make the step unnecessary?
- Why is the system stopping now?
- Which remaining uncertainty could reverse the effect decision?
- What is the cheapest safe plan?
- What is the most robust plan if one camera fails?

The answer is generated from retained decision records, not post-hoc prose alone.

---

## 11. Effects, obligations, and closed-loop control

### 11.1 No open-loop success claims

For every consequential action, the system distinguishes:

```text
intent prepared
intent committed locally
request dispatched
remote/device/provider accepted
physical or external mutation observed
semantic postcondition verified
effect disproven
outcome indeterminate
```

The agent never receives “done” merely because a request returned 200 or a command entered a queue.

### 11.2 Obligation cockpit

Every session frame includes outstanding obligations ranked by:

- severity if unresolved;
- deadline/expiry;
- uncertainty about external effect;
- dependency criticality;
- privacy/retention consequences;
- ability to block other work;
- estimated closure cost.

The agent can `watch` or `verify` an obligation, delegate it through a typed handoff, or explicitly
accept an indeterminate terminal outcome under policy. No obligation disappears because the creating
request ended.

### 11.3 Effect authority remains narrow

The ACCP may recommend or prepare only registered effects. It never exposes generic shell, SQL,
filesystem mutation, vendor RPC, arbitrary model prompt, or drone-control escape hatches. A plan
step’s typed effect capability cannot be widened by text found in camera names, OCR, transcripts,
metadata, documentation, or model output.

---

## 12. Agent sessions as immutable cognitive state

### 12.1 `AgentSessionCapsule`

A session capsule is an immutable revision containing:

```text
principal and capability projection
objective contract and subobjective state
base, prior, and current anchors
situation-frame/context-pack roots
active hypotheses and their evidence state
explicit assumptions, unknowns, not-observable domains, and epistemic debt
selected plan and current step frontier
open obligations, leases, fences, deadlines, and approvals
budget ledger and reserved resources
bookmarked evidence handles
decision and effect receipts
pending learning proposals
prior capsule identity and reason for revision
recommended next actions and re-anchor triggers
```

Capsules are content-addressed, root-last published, and optionally moved through ATP. A session can
be resumed on another process or machine if authority permits.

### 12.2 Rebase semantics

`resume` never assumes that prior context remains current. It computes:

1. delta from prior anchor to current anchor;
2. witness invalidation for facts, hypotheses, and plan steps;
3. policy/model/calibration/adapter/privacy generation changes;
4. obligation transitions that occurred while the agent was absent;
5. expired handles, leases, approvals, and retention windows;
6. new memories/anti-patterns applicable to the objective;
7. minimum context required to continue.

The result is a new capsule revision. Stale assumptions remain visible as invalidated history rather
than being silently dropped.

### 12.3 Epistemic debt

When an agent proceeds under unresolved assumptions, the capsule records **epistemic debt**:

- proposition assumed;
- why resolution was deferred;
- decision/effect that depends on it;
- estimated consequence if wrong;
- cheapest future test;
- expiration or mandatory-review point.

This allows economical progress without turning temporary assumptions into permanent facts.

---

## 13. Multi-agent cooperation and typed handoff

### 13.1 Shared task graph

Multiple agents operate over a shared, versioned task/obligation graph. Work claims use leases and
fences. Branches permit independent analysis without mutating live state. Results merge through
semantic deltas or candidate intents, never through raw state overwrite.

### 13.2 Role-scoped agents

Examples:

- sensor-health agent;
- incident investigator;
- geometry/calibration agent;
- archive/retention custodian;
- privacy reviewer;
- release qualifier;
- red-team evaluator.

Each role receives only the capabilities and evidence projection required by its task. Degree,
counts, absence, and graph neighborhoods are filtered before expansion so restricted agents cannot
infer hidden data indirectly.

### 13.3 Handoff capsule

A handoff MUST include:

- objective and success/stop criteria;
- current anchor and freshness;
- compact situation frame;
- active hypotheses and distinguishing evidence gaps;
- plan/frontier and why it was selected;
- open obligations and effect indeterminacy;
- assumptions and epistemic debt;
- budget spent/reserved/remaining;
- authority/capability limitations;
- exact evidence/context roots;
- ranked next actions;
- sender’s confidence and unresolved disagreements.

A prose note may accompany the capsule but cannot replace it.

### 13.4 Disagreement is first-class

Agents may submit competing hypothesis or plan revisions. Resolution uses explicit evidence,
objective contract, and decision policy. “Last agent wins” is forbidden. A dissenting high-loss
hypothesis remains visible until refuted, retired by policy, or moved outside objective scope.

---

## 14. Agent-accretive learning

The system should become easier and safer to operate after each episode, without allowing an agent’s
mistake to become self-reinforcing policy.

### 14.1 `ExecutionEpisode`

Every substantive objective produces an episode linking:

- initial situation and hypotheses;
- objective contract;
- selected and rejected plans;
- predicted costs, information gains, risks, and outcomes;
- executed step/decision/effect receipts;
- observed terminal result;
- residual uncertainty and unresolved obligations;
- resource consumption;
- operator feedback;
- counterfactual or oracle evaluation where available.

### 14.2 Outcome attribution

The system compares prediction with observation and attributes discrepancy to candidate causes:

- incomplete or stale evidence;
- incorrect hypothesis;
- poor context selection;
- model/calibration/adapter drift;
- flawed decision policy;
- execution failure;
- external nondeterminism;
- budget starvation;
- capability/approval delay;
- misleading prior memory/procedure;
- irreducible unobservability.

Attribution remains a hypothesis until supported. It does not rewrite canonical history.

### 14.3 Learning proposal classes

- `fact_candidate` — stable deployment fact with source evidence;
- `procedure_candidate` — reusable sequence with applicability and terminal proof;
- `anti_pattern_candidate` — action or assumption correlated with failure/harm;
- `diagnostic_signature` — recognizable symptom → test/fix mapping;
- `adapter_quirk` — exact tuple-specific behavior;
- `model_failure_mode` — scoped error family and detector;
- `coverage_or_geometry_lesson` — placement/calibration insight;
- `cost_model_update` — measured resource estimate correction;
- `policy_review_candidate` — evidence suggesting a versioned policy change;
- `benchmark_fixture_candidate` — hard case suitable for sealed evaluation.

### 14.4 Procedure contract

A reusable procedure includes:

```text
applicability predicate
required evidence and capabilities
steps and semantic owner
expected cost distribution
success and terminal proof
known failure signatures
rollback/compensation
counterexamples and exclusions
confidence and evidence count
time/firmware/model/calibration scope
helpful and harmful outcomes
review/expiry/revival conditions
```

Procedures are advisory until selected into a new plan under current evidence. They cannot bypass
witness validation or effect preparation.

### 14.5 Trauma guard and negative evidence

Harmful outcomes weigh more heavily than convenient successes. Repeated harm can demote, retire, or
invert a procedure into an anti-pattern. Failed experiments, unsupported device tuples, benchmark
regressions, and strategies that consumed resources without decision value are retained as negative
evidence so future agents do not repeat them.

### 14.6 Explicit promotion

Learning follows:

```text
capture → propose → review → validate → shadow → promote → monitor → demote/retire/revive
```

No model output, agent reflection, or operator note silently becomes policy or authoritative fact.

---

## 15. Explanation as a navigable proof object

### 15.1 Explanation layers

An explanation is available at several depths:

1. **Decision summary:** conclusion, confidence, main evidence, main contradiction, next action.
2. **Evidence graph:** supporting/contradicting paths, source handles, coverage and freshness.
3. **Decision card:** alternatives, loss factors, constraints, selected policy, tie-break.
4. **Execution trace:** plan steps, receipts, budget, obligations, postconditions.
5. **Replay package:** exact anchor, context pack, model/graph/search generations, deterministic trace.

The agent chooses depth through hydration rather than receiving every detail by default.

### 15.2 Counterfactual queries

The system supports:

- Why was this event classified as suspicious?
- Why was no alert sent?
- What evidence would reverse the decision?
- What if camera C3 had been unavailable?
- What if this track were a known resident routine?
- What is the cheapest additional observation that distinguishes H1 from H4?
- Why did the planner stop rather than invoke the largest model?
- Which assumption caused the plan to become stale?
- Why is absence uncertified?

Answers retain the same anchor and decision model or explicitly fork a branch.

### 15.3 Minimal explanation subgraph

For routine use, the explainer computes a minimal sufficient subgraph that preserves the decision
under the registered policy. It retains:

- causal dominators;
- decisive contradictions;
- hard clamps;
- coverage limitations;
- policy threshold crossings;
- effect/obligation dependencies.

It records what was pruned and offers handles for expansion.

---

## 16. Presentation and transport equivalence

### 16.1 One semantic core

CLI, library, MCP, TUI, desktop, mobile review, and report generation all consume the same typed
operation registry and cognitive-envelope structures. They differ only in framing, rendering,
streaming, and available qualified capabilities.

### 16.2 CLI examples

```bash
fss agent resume --session <capsule> --json
fss agent orient --objective <objective.json> --budget-tokens 1200 --json
fss agent ask "Is the rear-yard event likely benign?" --session <id> --json
fss agent inspect evh_... --hydrate H2 --json
fss agent hypothesize --session <id> --from event:E9 --json
fss agent simulate --session <id> --plan candidate:P3 --json
fss agent plan --session <id> --objective investigate-and-alert --json
fss agent prepare --plan <id> --step <id> --json
fss agent commit --prepared <digest> --json
fss agent watch --session <id> --until terminal --stream --format jsonl
fss agent verify --obligation <id> --json
fss agent explain --decision <id> --counterfactual "camera rear absent" --json
fss agent learn propose --episode <id> --json
fss agent handoff --session <id> --to-role incident-review --json
```

The existing subsystem commands remain lower-level equivalents and diagnostic escape valves, not
the expected cognitive workflow.

### 16.3 MCP qualification

FastMCP Rust exposes the same verbs only when its transport and cancellation semantics are qualified.
Every request owns a region and budget. Long-running observations use progress/continuation. Effects
are prepared and committed separately. An MCP transport incapable of receiving cancellation during a
handler cannot advertise equivalent interruptibility.

### 16.4 Human/agent dual rendering

The canonical envelope can render as:

- compact JSON/JSONL for agents;
- a concise terminal summary with expandable handles;
- an incident timeline;
- a spatial/graph view;
- a mobile action card;
- a durable Markdown/PDF report through Franken Markdown.

All renderings expose the same decision digest and source handles.

---

## 17. Crate and ownership implications

The following first-party crates become explicit owners:

| Crate | Responsibility |
|---|---|
| `fss-agent-core` | cognitive envelope, epistemic states, stable handles, semantic verb registry |
| `fss-context-pack` | task-relative frame construction, context selection, hydration planning, selection witnesses |
| `fss-agent-session` | immutable session capsules, resume/rebase, handoff, epistemic debt |
| `fss-investigation` | competing hypothesis workspaces, predictions, distinguishing tests, surprise |
| `fss-objective` | objective compilation, hard/soft constraints, terminal predicates, utility/loss model |
| `fss-agent-plan` | contingent DAGs, step typing, replanning, plan explanation |
| `fss-episode` | execution episodes, prediction/outcome attribution, learning inputs |
| `fss-learning` | proposal lifecycle, procedures, anti-patterns, trauma guard, promotion evidence |
| `fss-agent-eval` | cognitive-economy, handoff, plan, and closed-loop benchmark harness |

These crates depend on lower-level typed interfaces. Authority/storage crates do not depend on them.
The presentation layer consumes them through `fss-api`; it does not reimplement their semantics.

---

## 18. Agent-specific invariants

The machine registry extends the constitutional invariant set with `INV-083` through `INV-100`.
The most important consequences are:

- every decision-bearing response uses the cognitive envelope;
- every frame is anchor-pinned and declares omissions;
- epistemic distinctions survive compression and handoff;
- evidence handles have stable identity across hydration;
- objectives, plans, actions, and effects are separately typed;
- next actions expose value, cost, risk, authority, and reversibility;
- sessions rebase explicitly and preserve invalidated assumptions;
- consequential plan execution closes obligations through semantic verification;
- learning is advisory and evidence-gated;
- multi-agent handoff is typed;
- attention optimization cannot starve safety/privacy/urgent obligations;
- every agent decision is replayable from exact context/objective/plan identities;
- resource degradation cannot fabricate certainty.

---

## 19. Qualification and metrics

The ACCP is not qualified by schema presence. It requires task-level evidence.

### 19.1 Cognitive usability metrics

- cold-start tokens, calls, and wall time to a correct situation model;
- time/tokens to locate decisive evidence;
- context precision and recall for load-bearing facts;
- contradiction retention rate;
- unknown/not-observable classification accuracy;
- decision stability under harmless context reordering;
- decision sensitivity when load-bearing evidence is removed;
- information gain per token, model millisecond, source byte, joule, and human interruption;
- percentage of next-action rankings whose estimated value/cost calibration holds;
- redundant hydration and repeated-discovery rate.

### 19.2 Control metrics

- objective success and terminal-proof rate;
- stale-plan detection before effect;
- replan rate and replan cause attribution;
- effect duplication rate under retries/crashes;
- obligation closure and indeterminate-outcome reconciliation rate;
- unsafe/unauthorized action proposal and commit rates;
- time from event to verified action outcome;
- quality/cost frontier versus fixed monolithic strategies.

### 19.3 Accretion metrics

- handoff information-loss rate;
- session-resume rediscovery saved;
- percentage of learning proposals with valid evidence and applicability scope;
- future episode utility of promoted procedures;
- harmful-memory detection/demotion latency;
- repeated negative-experiment rate;
- improvement on held-out future sessions without leakage into sealed evaluation.

### 19.4 Required benchmark families

1. cold agent, no prior session;
2. warm resume after many world deltas;
3. ambiguous event with several viable hypotheses;
4. high-severity low-observability event;
5. multi-agent handoff mid-plan;
6. external effect with lost acknowledgement;
7. model/adapter/calibration generation drift;
8. strict token/compute budget;
9. privacy-limited evidence domain;
10. misleading prior procedure that should trigger trauma guard;
11. one-camera failure requiring robust replan;
12. long-running archive/deletion/repair obligation.

### 19.5 Gate

`GATE-115` passes only when the end-to-end loop:

```text
resume/orient → hypothesis/objective → value-of-information acquisition
→ contingent plan → prepare/commit → obligation verification
→ execution episode → learning proposal → resumable handoff
```

replays deterministically, respects capability/privacy/budget constraints, retains epistemic
uncertainty, and outperforms the subsystem-command baseline on task success per resource without a
safety or evidence regression.

---

## 20. Failure modes explicitly rejected

- one MCP tool per subsystem command with no shared cognitive model;
- a giant world dump presented as “agent context”;
- prose summaries without anchor, coverage, omissions, or evidence handles;
- top-k retrieval that omits a low-score contradiction capable of reversing an effect;
- recommendations without alternatives, cost, risk, authority, or invalidators;
- free-form plan text executed as commands;
- implicit rebase of stale session state;
- “success” at request dispatch rather than semantic postcondition;
- context compression that turns `not_observable` into a false/absent conclusion;
- repeated full-media hydration when a compact handle suffices;
- hidden model escalation that violates compute/privacy budgets;
- agent memories promoted without outcome attribution and counterexamples;
- last-writer-wins multi-agent coordination;
- prose-only handoff;
- learned attention policy allowed to starve an urgent obligation;
- transport-specific semantics that diverge between CLI and MCP;
- an agent benchmark scored only on final label while ignoring cost, evidence, and effects.

---

## 21. Implementation sequence

1. Freeze cognitive envelope, epistemic-state, evidence-handle, objective, plan, episode, session, and learning schemas.
2. Build single-threaded reference implementations for frame selection, hydration, hypothesis update, objective compilation, and plan execution.
3. Add deterministic scenario fixtures and a minimal semantic verb dispatcher over the existing in-memory world.
4. Implement session capsule publication and resume/rebase before adding broad presentation surfaces.
5. Connect one read-only incident workflow end to end: orient → ask → inspect → explain.
6. Add hypothesis discrimination and value-of-information observation planning.
7. Add one reversible prepared effect with obligation verification.
8. Add typed handoff and branch-per-agent analysis.
9. Add execution episodes and evidence-gated learning proposals.
10. Integrate Frankensearch, certified graph, operational memory, and model runtime behind equivalent reference semantics.
11. Add FastMCP and richer UI renderings only after CLI/library semantics are stable.
12. Qualify `GATE-115` through local DSR lanes and retained proof bundles.

The sequence deliberately builds the cognitive oracle before optimizing context selection or adding
many device integrations. Otherwise FSS would merely make an incoherent tool collection faster.

---

## 22. What success feels like from the driver’s seat

A capable agent joining an unfamiliar deployment should be able to issue one `resume` or `orient`
request and immediately see:

- the objective;
- the current anchor and what changed;
- the few world facts that actually govern the decision;
- the certified core, materially different possible worlds, and protected adversarial residuals;
- which next moves are robust, conditional, information-gathering, waiting, or blocked;
- live competing explanations;
- decisive evidence and contradictions;
- where the system cannot observe;
- open obligations and deadlines;
- remaining resource/authority envelope;
- the safest highest-value next actions;
- exactly what would make each action stale;
- how to drill into evidence without losing identity;
- how to simulate before acting;
- how an effect will be verified;
- what a successor agent needs to continue;
- what the system learned from prior similar episodes and why that memory should be trusted.

The agent should not need to memorize the repository’s crate graph to operate the product. The crate
graph exists so the product can present a small, coherent cognitive world without lying.
