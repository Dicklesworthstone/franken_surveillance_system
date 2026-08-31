# Agent operating model for `franken_surveillance_system`

**Document class:** normative driver-facing workflow supplement to `AGENT_COGNITION_AND_CONTROL.md`  
**Revision:** 1  
**Date:** 2026-08-31  
**Status:** binding driver model; public semantics remain owned by `AGENT_COGNITION_AND_CONTROL.md` and `architecture/agent_contracts.json`; workflow registries live in `architecture/agent_operating_model.json`, `architecture/agent_operations.json`, and `architecture/agent_views.json`

---

## Document authority

This is the view from the driver’s seat. It explains how to use the constitutional types and
operations efficiently; it does not create alternative names or lifecycle semantics.
`AGENT_COGNITIVE_CONTROL_PLANE.md` specifies internal composition. The constitution and machine
registries win if a narrative example drifts.

## 0. Prime directive

FSS SHALL feel to an agent like one coherent epistemic control system, not a directory of unrelated
camera, graph, model, archive, and alert commands.

The primary job of the agent substrate is to answer, with the least necessary expenditure of
attention and resources:

1. **What am I trying to accomplish?**
2. **What is the situation now, at one coherent evidence anchor?**
3. **What changed, and what conclusions or plans did that invalidate?**
4. **What is known, estimated, conflicted, unknown, stale, redacted, indeterminate, or not observable, and from which provenance class?**
5. **What matters most under the mission's loss function and deadline?**
6. **Which next observations or actions are available, safe, and worth their cost?**
7. **What proof will each action produce, and how will completion be monitored?**
8. **What was learned that should make the next investigation cheaper or more accurate?**

The system therefore exposes one universal operating loop:

```text
restore/resume
  → orient
  → prioritize
  → inspect
  → hypothesize
  → acquire discriminating evidence
  → compare/counterfactually simulate
  → plan
  → prepare
  → commit
  → watch/monitor
  → reconcile
  → resolve
  → learn
  → hand off or close
```

Every step is anchor-pinned, budgeted, capability-scoped, resumable, and evidence-bearing. No
presentation surface may invent a second lifecycle.

---

## 1. Why a command catalog is insufficient

A large command catalog makes the agent responsible for reconstructing the system's ontology,
state machine, and hidden prerequisites on every turn. That wastes tokens and model calls, causes
stale-state mistakes, and encourages tool selection by naming rather than by expected value.

The failure pattern is predictable:

```text
list sensors
→ inspect several cameras
→ list events
→ guess which event matters
→ search related clips
→ discover calibration is stale
→ reread status
→ call a low-level action without the right anchor
→ receive a conflict
→ rebuild context from scratch
```

FSS instead owns the cognitive scaffolding that is invariant across agents:

- mission state and success criteria;
- one coherent version universe;
- explicit epistemic states;
- attention and decision-impact ranking;
- context-specific affordances;
- semantic zoom and continuation;
- plan/prepare/commit/watch/reconcile grammar;
- durable investigations, findings, branches, and handoffs;
- evidence-linked experience capture.

The agent remains responsible for judgment. FSS removes repetitive bookkeeping and makes the basis
of that judgment legible.

### 1.1 What makes the parts feel like one system

Every subsystem contributes through the same internal `CognitiveFacet` contract. From the driver's
seat this means camera health, archive lag, model uncertainty, graph reachability, effect state, and
operational memory all expose the same coordinates: exact basis, epistemic/provenance state,
coverage, evidence handles, cost, valid next operations, obligations, invalidators, and recovery.
The agent learns one grammar and one lifecycle rather than a private dialect per component.

---

## 2. The tower of linked abstractions

FSS presents a tower in which each layer has one semantic owner and every upward projection keeps a
handle back to its basis.

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

No layer may silently strengthen the authoritativeness of a lower layer. The physical world and
external systems feed L1 through explicit L0 capabilities but are not themselves a software truth
layer. Presentation is a registered view over the tower, not an additional semantic layer. A
summary is not an event fact; a memory is not policy; a branch is not live state; a model score is
not source evidence; an alert receipt is not proof of physical outcome.

`MissionContract`/`ObjectiveContract`, semantic protocol, privacy/capability projection, identity,
basis, validity, epistemic state, cost, and invalidation cut across every layer. This prevents each
subsystem or surface from inventing a rival hierarchy.

### 2.1 Cross-layer addressability

Every object returned above L0 contains stable handles for:

- exact global identity;
- mission-local alias, when useful;
- evidence anchor and producer generation;
- basis objects or basis query;
- expansion operation and estimated cost;
- invalidators and freshness;
- capability projection that determined visibility.

This makes the tower navigable in both directions: summarize upward, inspect downward, and replay
from the basis.

---

## 3. Mission: the durable unit of purposeful work

A **mission** is the top-level agent work object. It is not a chat session and not a free-form goal
string. It binds purpose to state, authority, budgets, and proof.

A mission contains:

- immutable mission identity and deployment scope;
- objective and optional parent mission;
- measurable success, acceptable-degradation, failure, and stop criteria;
- protected interests and asymmetric loss terms;
- capability grants and privacy scope;
- time, token, byte, model-call, CPU/accelerator, energy, network, storage-operation, privacy, and
  operator-attention budgets;
- baseline and current evidence anchors;
- active investigations, branches, plans, operations, obligations, and leases;
- decision deadline and escalation policy;
- unresolved questions, assumptions, constraints, and blocked dependencies;
- retained findings, resolutions, feedback, and learning candidates;
- terminal state and closure receipt.

### 3.1 Mission states

```text
Draft
  → Active
      ↔ Paused
      → AwaitingEvidence
      → AwaitingApproval
      → Executing
      → Reconciling
      → Resolved
      → Failed
      → Cancelled
      → Indeterminate
      → Closed
```

A mission can have concurrent investigations and operations, but one deterministic mission revision
orders canonical control-state updates. Cancellation closes owned work through Asupersync and does
not erase indeterminate external effects.

### 3.2 Stateless reads

Simple read-only requests may declare `stateless=true`. They still name an evidence anchor, budget,
principal, capability projection, and response schema. They create no durable mission memory unless
the caller explicitly promotes the result.

### 3.3 Objective refinement

An agent may refine a mission objective only through a new mission revision that shows:

- old and new objective;
- reason and supporting evidence;
- changed success/failure criteria;
- changed authority or budgets;
- invalidated plans or investigations;
- whether human approval is required.

Objective drift cannot hide inside a prompt or context pack.

---

## 4. Agent session and session-local symbol table

A mission may be operated across many agent sessions. A session owns presentation convenience, not
truth.

A session binds:

- principal and capability projection;
- mission identity and current anchor;
- view profile and token budget;
- continuation cursors;
- a compact symbol table;
- active subscriptions and watches;
- session-local preferences that do not change policy;
- last acknowledged situation fingerprint;
- parent handoff capsule, if any.

### 4.1 Compact aliases

The symbol table assigns short aliases such as:

```text
@e1  event evt:9f… revision 12
@s2  sensor sen:rear-yard… generation 44
@i1  investigation inv:overnight… revision 3
@o1  operation op:alert… generation 2
@h1  hypothesis hyp:person-crawling… revision 5
```

Aliases reduce token use but are never global identities. Each alias is bound to:

- session ID;
- symbol-table generation;
- global object ID and visible revision;
- evidence anchor interval;
- capability projection;
- expiry and invalidators.

A stale alias returns `ERR-SYMBOL-TABLE-STALE-001` with a safe refresh affordance. Alias allocation
must not reveal that a hidden object exists.

### 4.2 Session restoration

`resume` restores the mission and session from a handoff or durable cursor. It returns a situation
capsule describing changes since the last acknowledged anchor, including invalidated assumptions,
plans, aliases, and outstanding effects. It never assumes the caller remembers prior prose.

---

## 5. SituationCapsule: the primary agent read surface

The **SituationCapsule** is the canonical compact publication an agent receives when it opens,
resumes, or orients a mission. It is not merely a summary and it is not a new source of truth. It
packages the minimum sufficient driver state for one mission, principal, capability projection,
view, and evidence anchor.

The capsule contains these linked objects:

1. **`SituationFrame`** — the task-relative projection of current world facts, beliefs, coverage,
   uncertainty, and mission relevance.
2. **`MeaningfulDelta`** — what changed since the acknowledged anchor, including changed
   conclusions, invalidated assumptions or plans, restored/lost observability, and changed
   obligations or affordances.
3. **Mission and objective frame** — purpose, hard constraints, success/failure/stop predicates,
   deadline, escalation posture, authority, and budget.
4. **Attention frontier** — nondominated mission-relevant items ranked after constitutional clamps,
   with urgency, expected loss, diversity, and domination evidence.
5. **Epistemic map** — `known`, `estimated`, `unknown`, `conflicted`, `stale`, `not_observable`,
   `redacted`, `indeterminate`, and `not_applicable` propositions with separate provenance.
6. **Active investigations and plans** — competing hypotheses, discriminators, assumptions,
   contingencies, preparations, and current decision frontier.
7. **Obligation cockpit** — active effects, waits, transfers, approvals, leases, cleanup,
   reconciliation, and terminal proof predicates.
8. **Resource state** — available and reserved token/byte/model/compute/energy/network/storage/privacy/
   operator-attention budgets, pressure regime, and explicit degradation.
9. **Affordance frontier** — capability-valid safe next operations with decomposed value, cost, risk,
   privacy, reversibility, invalidators, alternatives, and expected terminal evidence.
10. **`ContextPack` plus `SemanticCompressionReceipt`** — the exact selected material, omissions,
    transformations, critical-preservation checks, stop reason, digest, continuation, and priced
    expansion handles.
11. **Session symbol table state** — compact aliases and their generation, without replacing durable
    identities.
12. **Validity and continuity** — fingerprint, expiry, invalidators, re-anchor conditions, and
    continuation cursor.

`SituationFrame` remains a reusable inner type: it answers “what is the mission-relative world
state?” `SituationCapsule` answers the larger driver question: “what is happening, what changed,
what remains unresolved, what resources and obligations matter, and what can I safely do next?”

### 5.1 Capsule invariants

A capsule SHALL:

- use one coherent version universe and one explicit principal/capability/privacy projection;
- keep fact, belief, hypothesis, memory, recommendation, policy, and effect outcome distinct;
- distinguish an empty result from `unknown`, `not_observable`, `redacted`, `stale`, unauthorized,
  budget-exhausted, and `indeterminate`;
- contain every known mission-critical invalidation, contradiction, hard clamp, active obligation,
  and unsafe-retry condition at its anchor;
- preserve immutable proof pointers for consequential statements and stable handles for optional
  hydration;
- state degradation and the resulting lost precision/coverage/freshness rather than simply omitting
  failed subsystems;
- fit the selected registered view or return a resumable continuation with a compression receipt;
- produce the same canonical payload and decision fingerprint for equivalent
  mission/anchor/view/capability inputs.

### 5.2 Decision-impact delta

A row-level delta is insufficient for an agent. The capsule computes an impact projection:

```text
changed evidence/facts
  → changed beliefs and uncertainty
  → changed event or coverage conclusions
  → invalidated assumptions
  → invalidated or newly enabled plans
  → changed obligations, resource commitments, and affordances
```

Examples:

- “rear camera firmware changed” becomes “compatibility certificate expired; rear-zone absence
  claims are uncertified; investigation I4's `no egress` premise is invalid; active plan P2 must be
  recompiled.”
- “alert provider ACK missing” becomes “delivery remains `indeterminate`; retry is unsafe until
  provider lookup; the reconciliation affordance is now nondominated.”
- “rain occlusion cleared” becomes “coverage restored; the waiting investigation can resume with a
  cheaper local detector probe.”

### 5.3 Situation fingerprint

The capsule carries a deterministic fingerprint over mission revision, anchor, capability/privacy
projection, view and compression policy, SituationFrame root, meaningful delta, attention frontier,
active obligations, resource state, and critical invalidations. It supports acknowledgement, delta
calculation, replay, caching, and handoff; it is never a substitute for the underlying evidence.

---
### 5.4 The three-envelope driver model

The capsule presents one coherent **evidence–possibility–control** model:

- **Evidence envelope:** what is positively established now, including certified absences and the
  exact coverage/continuity basis.
- **Possibility envelope:** material alternative worlds and adversarial residuals that have not
  been ruled out. This is not an exhaustive enumeration; it is a decision-preserving frontier with
  explicit selection and domination witnesses.
- **Control envelope:** robust actions, branch-conditional actions, information-gathering probes,
  wait/watch choices, and blocked actions.

From the driver seat, this answers the question a conventional alert feed does not:

> What do we know, what dangerous or decision-changing possibilities remain, and what can be done
> safely before those possibilities are resolved?

The agent should prefer a robust affordance when one achieves the objective across all protected
worlds. When no such action exists, it should choose the highest-value discriminator or an explicit
wait/watch policy. A branch-conditional effect must expose the named worlds, assumptions,
invalidators, residual loss, and evidence required before commitment.


## 6. Epistemic state is a first-class type

Every consequential proposition carries one canonical knowledge state, independently of provenance,
hypothesis disposition, access transform, and operation outcome:

| State | Meaning | Agent implication |
|---|---|---|
| `known` | Established for the named anchor and validity scope by admissible evidence or a proved terminal postcondition | May be used as a premise only within its declared scope and freshness. |
| `estimated` | Supported by a declared derivation/model with explicit uncertainty and operating envelope | May guide bounded reasoning or policy only under its calibration contract. |
| `unknown` | Authorized evidence acquired so far is insufficient | Do not infer false, absent, benign, or failed. |
| `conflicted` | Material admissible evidence supports incompatible propositions or generations | Preserve alternatives and seek discriminating evidence. |
| `stale` | Valid only at an older anchor or generation | Refresh or revalidate before use. |
| `not_observable` | The requested proposition could not have been established in the declared sensor/authorization/model domain | Improve coverage or explicitly accept ignorance. |
| `redacted` | The proposition or supporting evidence exists but is withheld by the current privacy/capability projection | Do not infer absence; request stronger authority only through the ordinary grant path. |
| `indeterminate` | A consequential external outcome may have occurred but is not proved or safely negated | Reconcile before a potentially duplicative effect. |
| `not_applicable` | The proposition has no meaning for this object, scope, or lifecycle state | Exclude it from aggregation rather than treating it as false or missing. |

`refuted`, `resolved`, `superseded`, `disfavored`, and `rejected` are dispositions of hypotheses,
plans, procedures, or proposals—not substitutes for proposition knowledge state. Likewise,
`observed`, `derived`, `predicted`, `remembered`, `operator_asserted`, `vendor_claimed`, and `policy`
are provenance classes, not epistemic states.

### 6.1 Completeness and absence

An absence claim must identify:

- authorized spatial/temporal/entity domain;
- source and projection coverage;
- health and calibration state;
- query strategy and recall certificate;
- budget and stop reason;
- any excluded or uncertain subdomain.

A search returning no rows without this information has epistemic state `unknown`, not
`established absence`.

### 6.2 Contradictions

Contradictions are not flattened into a lower confidence score. They are typed evidence edges that
name:

- challenged statement;
- source and failure domain;
- severity and independence;
- compatible alternative hypotheses;
- whether the contradiction invalidates a plan or only weakens it;
- recommended discriminator.

---

## 7. Registered semantic views and semantic zoom

The agent chooses a **view**, not a bag of output flags. Views are registered in
`architecture/agent_views.json` and `registries/AGENT_VIEWS.md`.

Initial view families:

- `heartbeat`: tiny health/critical-obligation delta for frequent polling;
- `orientation`: primary mission situation frame;
- `investigation`: hypotheses, evidence, unknowns, contradictions, and discriminators;
- `forensic`: broad evidence graph and exact proof pointers;
- `operation_monitor`: one operation, progress, expected proof, and reconciliation state;
- `handoff`: minimum sufficient state for another agent to continue safely;
- `decision_diff`: why a conclusion, priority, or plan changed between anchors;
- `epistemic_map`: coverage of known/unknown/contested/not-observable domains.

### 7.1 Semantic zoom contract

Every compact item advertises zero or more typed expansions, such as:

```text
summary → event revision → hypothesis evidence graph → sensor capsule → source packet/object
summary → blind spot → coverage cells → camera geometry → calibration residuals
summary → operation → plan → preconditions → provider receipt → observed postcondition
```

An expansion names expected bytes, tokens, compute, privacy class, and latency before execution.
The agent can therefore spend context deliberately.

### 7.2 Progressive results

A view may return an initial useful projection and one or more refinements. Each phase states:

- same pinned anchor or explicit rebase;
- phase identity and producer generation;
- completeness class;
- differences from the previous phase;
- stop or failure reason;
- whether any prior conclusion was invalidated.

Refinement failure cannot erase the initial result or silently promote it to final.

---

## 8. Semantic compression and its receipt

FSS intentionally compresses state for agent consumption, but compression is an epistemic effect and
must be inspectable.

Every compact projection includes a `SemanticCompressionReceipt` containing:

- source anchor and authorized domain;
- view policy and target budget;
- selected and omitted object classes;
- aggregation, clustering, deduplication, quantization, and truncation operations;
- completeness status per field/domain;
- decision-critical preservation checks;
- omitted contradictions or invalidations count, which must be zero for a complete decision view;
- output token/byte estimate and actual use;
- expansion handles and estimated costs;
- canonical digest of the uncompressed selection frontier when retained;
- deterministic stop reason.

### 8.1 Loss-aware compression

Compression optimizes a declared loss function. It preferentially preserves:

1. safety/privacy/capability constraints;
2. active consequential effects and indeterminacy;
3. changed or invalidated premises;
4. high expected-loss events;
5. contradictions and observability gaps;
6. mission-blocking unknowns;
7. discriminating evidence and high-value affordances;
8. explanatory details;
9. routine unchanged background.

No token budget may cause FSS to silently omit a known critical alert, capability violation,
indeterminate effect, or invalidated plan premise. If those cannot fit, the response fails with
`ERR-CONTEXT-INCOMPLETE-001` and provides a safe larger/minimal-critical view.

### 8.2 Stable compactness

Equivalent inputs produce canonical ordering, aliases, field selection, and output digests. This
makes agent traces replayable and prevents context churn from hash-order or nondeterministic
summarization.

---

## 9. Universal agent request/response envelope

### 9.1 Contract basis and request envelope

Every operation accepts `AgentRequestEnvelope`. The request carries one `ContractBasis` that pins
the semantic protocol and all schema/ontology/operation/view/capability/error/cost registries used
to interpret the call. It also carries the exact lifecycle identities, anchor/workspace
preconditions, registered view, targets, typed operation payload, resource budget, requested
authority/privacy projection, idempotency key, continuation, expected decision fingerprint,
hydration ceiling, compression policy, and taint provenance.

The agent can therefore cache a compact operation catalog without trusting ambient server version
state. If any registry meaning changes, the basis digest changes and the request must renegotiate or
recompile.

### 9.2 Response envelope

Every machine-facing operation returns one `AgentResponseEnvelope`, regardless of CLI, library,
MCP, TUI, or UI transport.

The envelope contains:

- schema and operation ID;
- request, principal, session, mission, trace, and task identities;
- input and output anchors;
- four-valued outcome plus stable error/refusal class;
- payload schema and payload;
- epistemic status and completeness;
- warnings, contradictions, degradation, and validity interval;
- budgets requested, consumed, and remaining;
- semantic compression receipt, if output was shaped;
- proof/evidence pointers;
- continuation or resnapshot requirement;
- context-specific affordances;
- safe retry and idempotency information;
- decision/output fingerprint.

Human renderers consume this envelope. They may improve readability but cannot invent or omit
semantics needed by machine clients.

### 9.3 Partial success

A response can be useful without being complete. Partial results explicitly state which independent
subqueries succeeded, failed, were unauthorized, became stale, or exhausted budget. Valid portions
remain addressable and are not discarded behind one generic error.

### 9.4 Actionable refusals and errors

Every refusal or error answers:

- what failed and at which boundary;
- what remains valid;
- whether the result is safe to retry;
- required capability or precondition;
- repair, refresh, wait, rebase, narrow-scope, or alternative affordances;
- expected cost of each recovery path;
- whether a consequential effect may already have occurred.

---

## 10. Natural-language request compiler

Natural language is a convenient, tainted input—not an effect language.

`ask`, `investigate`, and other natural-language surfaces compile text into a bounded typed
`AgentQueryPlan` or `AgentIntentDraft`.

The compiler emits:

- parsed objective and operation family;
- resolved global IDs and session aliases;
- temporal/spatial/entity domains;
- evidence anchor and freshness requirement;
- capability and privacy projection;
- completeness and uncertainty requested;
- budgets and result view;
- ambiguity set and chosen/default interpretations;
- estimated cost;
- safe read plan or prepared effect draft;
- original text hash and taint provenance.

### 10.1 Ambiguity protocol

Material ambiguity never silently becomes an effect. The compiler may:

1. choose a documented harmless read-only default and show alternatives;
2. execute multiple bounded interpretations and compare them;
3. return `ERR-QUERY-AMBIGUOUS-001` with discriminating questions;
4. prepare, but never commit, each plausible consequential intent.

### 10.2 Prompt-injection boundary

OCR, audio, camera labels, vendor metadata, notes, imported documents, model prose, and retrieved web
text are data spans. They can be quoted or searched; they cannot add operations, grants, arguments,
or capability scope to the compiled plan.

### 10.3 Typed model questions

Open-vocabulary models receive typed, bounded questions generated from admitted operation schemas,
not arbitrary agent prompts. Returned free text is tainted explanation data; structured evidence
regions/times and receipts carry the usable result.

---

## 11. Affordances: safe next moves as data

An **affordance** is a typed context-specific next operation. It is the main mechanism that makes FSS
self-describing to an agent.

An affordance includes:

- registered operation ID and semantic purpose;
- target handles and input schema;
- expected output view/schema;
- required capabilities, approvals, leases, and privacy scope;
- basis anchor, preconditions, invalidators, expiry, and idempotency class;
- reversibility/compensation and physical consequence class;
- expected evidence or postcondition;
- predicted information gain, decision-loss reduction, coverage gain, or obligation reduction;
- time, token, byte, model-call, CPU/accelerator, energy, network, storage, privacy, and
  operator-attention cost vector;
- uncertainty and sensitivity of those estimates;
- safety/risk vector and worst plausible downside;
- alternatives, including `wait/watch`, `narrow`, `defer`, `request approval`, and `do nothing`;
- deterministic reason it appears in the current frontier;
- stop condition and monitoring plan.

### 11.1 No opaque universal score

FSS applies hard constraints first, removes dominated or forbidden actions, and returns a bounded
Pareto frontier. A displayed scalar priority may summarize one registered mission policy, but the
component vector and sensitivity remain visible.

The agent can ask:

- “best next step under 150 tokens and no model call”;
- “lowest privacy-cost probe that distinguishes raccoon from person”;
- “all nondominated ways to restore rear-yard coverage before midnight”;
- “what would change the preferred alert decision?”;
- “why is waiting better than another camera query?”

### 11.2 Expected value model

A generic advisory objective is:

```text
expected utility
  = expected reduction in mission decision loss
  + expected information gain
  + expected coverage or obligation improvement
  - latency cost
  - compute/energy/network/storage cost
  - privacy exposure
  - operator burden
  - execution and irreversibility risk
```

Every term is decomposed and policy-versioned. Missing calibration increases uncertainty; it does
not magically become zero cost. The objective ranks recommendations only. Consequential authority
still flows through capabilities, hard policy, prepare, revalidation, and commit.

### 11.3 The `wait/watch` affordance

Waiting is explicit rather than an absence of action. It declares:

- evidence expected;
- source/subscription;
- deadline or maximum wait;
- wake predicates;
- opportunity and threat cost;
- fallback on timeout or degradation;
- owned monitoring task and cancellation behavior.

This prevents “wait for more evidence” from becoming indefinite during a real threat.

---

## 12. Investigation: the durable unit of epistemic work

An **investigation** structures reasoning around one decision-relevant question.

It contains:

- question and decision it informs;
- basis anchor and authorized domain;
- candidate hypotheses, including an explicit open-set alternative;
- established facts and assumptions;
- unknown, contested, stale, and not-observable variables;
- positive, negative-domain, and contradictory evidence;
- discriminators: observations whose outcomes separate hypotheses;
- candidate probes and expected-value/cost vectors;
- decision deadline, stopping criteria, and acceptable residual uncertainty;
- selected probes and their receipts;
- current conclusion set and confidence/calibration basis;
- blocked dependencies and escalation path;
- state, revision, and terminal resolution.

### 12.1 Hypothesis discipline

Hypotheses remain separate while evidence permits materially different worlds. Greedy merge or
premature narrative compression is prohibited. Each hypothesis states what it predicts should be
observed by each healthy sensor and what observations would contradict it.

### 12.2 Probe selection

The investigation planner prioritizes discriminating probes, not merely more data. It can choose:

- inspect a specific source crop or packet interval;
- run a cheap detector before an expensive temporal model;
- query a camera expected to see the route;
- wait for a pending independent view;
- request PTZ only when static coverage is insufficient and authority permits;
- compare similar resolved incidents;
- perform a counterfactual branch;
- ask an operator one high-value question;
- declare the domain not observable rather than burn budget fruitlessly.

### 12.3 Stop rules

An investigation ends when a registered condition holds, such as:

- policy action is robust across all remaining hypotheses;
- posterior/set-valued uncertainty crosses a qualified boundary;
- marginal value of further evidence is below cost;
- decision deadline requires an explicit risk-minimizing action;
- required coverage is unavailable;
- authority or privacy forbids remaining probes;
- operator adjudication resolves the question.

The terminal record includes residual uncertainty and negative evidence.

---

## 13. Counterfactual branches and plan comparison

Agents may fork cheap logical branches from a pinned anchor. A branch may contain hypothetical
facts, policy alternatives, sensor placements, calibration updates, or candidate effects.

A branch SHALL:

- preserve its basis anchor and creator;
- distinguish fabricated deltas from observed evidence;
- use deterministic graph/model/reference semantics where available;
- record assumptions and uncertainty;
- emit findings, comparison receipts, and candidate intents only;
- never merge fabricated bytes into live authority state.

### 13.1 Comparison surface

`compare` can evaluate branches or plans over:

- mission success/failure probability or qualified proxy;
- decision robustness across hypotheses;
- coverage and observability;
- false-alert/miss exposure;
- latency and deadline feasibility;
- compute, bandwidth, energy, storage, and provider cost;
- privacy and operator burden;
- reversibility and failure modes;
- required authority and approvals;
- proof quality and expected residual uncertainty.

The output is a `decision_diff` view with decomposed terms and sensitivity—not a prose verdict.

---

## 14. One universal operation grammar

The agent learns fourteen public operations, not every subsystem command:

```text
session.open     negotiate a new mission/session
session.resume   restore an explicit workspace or handoff
session.orient   obtain the primary SituationCapsule
session.follow   wait for meaningful change from an exact cursor
query            answer a bounded typed or compiled natural-language question
investigate      create or advance a durable case and its hypothesis workspace
plan             compile an information/control objective into a witnessed contingent DAG
commit           revalidate and start the exact prepared plan under authority
wait             observe durable work and terminal predicates
cancel           request/drain/reconcile/finalize owned work
explain          answer why, why-not, what-changed, or what-if
handoff          publish minimum sufficient resumable mission state
feedback         record correction, adjudication, outcome, or learning proposal
doctor           diagnose consistency and prepare sealed repair affordances
```

The richer loop described elsewhere—prioritize, inspect, hypothesize, acquire, compare, simulate,
prepare, monitor, reconcile, resolve, and learn—is implemented through typed payloads, targets,
case transitions, plan-step kinds, explain modes, and intent classes under these operations. This
keeps the public grammar memorable while preserving expert precision. Domain nouns—sensor, event,
coverage, calibration, model, archive, privacy, alert—remain typed resources and intent families.

### 14.1 Low-level expert access

Specialized domain commands may remain for operators, laboratory harnesses, and implementation
tests, but they compile to registered operations and schemas. They cannot create an authority or
state-transition path unavailable through the semantic protocol.

### 14.2 Cross-surface invariance

For a fixed principal, mission, anchor, operation, input, and view:

- Rust library, CLI JSON, MCP, TUI, desktop, and mobile UI use the same operation ID;
- input validation, privacy projection, and authority decisions are identical;
- canonical payload and decision digest are identical;
- transports may differ only in framing, continuation, rendering, and media delivery;
- unsupported transport semantics fail explicitly rather than degrade invisibly.

---

## 15. Plan, prepare, commit, monitor, and reconcile

### 15.1 Plan

A plan is a deterministic DAG of reads, probes, computations, approvals, effects, monitors, and
terminal predicates. It records:

- mission objective and basis anchor;
- assumptions and semantic read/write witnesses;
- alternative plans considered;
- expected cost/risk/value vector;
- capabilities and leases needed;
- effect ordering, idempotency, compensation, and reconciliation policy;
- checkpoints, progress potential, and stop rules;
- expected evidence and terminal proof.

### 15.2 Prepare

Preparation freezes semantic intent, resolves current identities, acquires or checks leases,
reserves idempotency, validates capability and policy, and revalidates witnesses. It produces an
immutable prepared operation with expiry. Preparation does not perform the external effect.

### 15.3 Commit

Commit accepts only an exact prepared identity and content digest. It crosses a narrow effect
boundary and returns a durable operation handle. A repeated identical commit is replay-safe; a
content mismatch fails.

### 15.4 Monitor

Monitoring is a registered view over one durable operation/task. It reports:

- current state and last durable checkpoint;
- expected versus observed progress;
- nonnegative potential and drainability;
- outstanding obligations and external effects;
- next expected evidence and deadline;
- degradation or divergence;
- valid cancel, wait, escalate, compensate, or reconcile affordances.

### 15.5 Reconcile

Reconciliation answers what actually happened after timeout, crash, lost ACK, provider ambiguity,
or partial publication. It queries authoritative external state where possible, observes semantic
postconditions, and emits `verified`, `failed`, `compensated`, or `indeterminate`. It runs before any
retry that could duplicate a consequential effect.

---

## 16. Resource economy and pressure-aware cognition

The agent receives one coherent budget ledger rather than subsystem-specific surprises.

Budget dimensions include:

- wall-clock and decision deadline;
- output tokens and bytes;
- evidence hydration bytes;
- source reads and object-store operations;
- model invocations, input pixels/seconds, CPU/accelerator time, and memory;
- graph/search operations;
- network bandwidth and provider cost;
- energy/thermal budget;
- privacy exposure and bystander data;
- human approval and operator-attention cost.

### 16.1 Budget negotiation

An operation can return a preflight estimate and quality frontier:

```text
profile compact:    180 tokens, no model, known blind spots preserved
profile balanced:   900 tokens, cheap graph/search refinement
profile thorough:  3200 tokens, one temporal model and evidence crops
profile forensic:  9000 tokens + source handles, exact evidence graph
```

The agent chooses deliberately or provides a mission policy. FSS never incurs a large hidden model
or remote-media cost merely because a broad natural-language question was asked.

### 16.2 Pressure degradation

Under pressure, FSS degrades through registered semantic ladders, for example:

- reduce optional explanation detail before omitting contradictions;
- reduce sampling cadence for low-attention healthy zones before critical zones;
- delay quality refinement while preserving exact initial retrieval;
- spill verified unpublished objects before discarding source evidence;
- return `not_observable` or `budget_exhausted` before fabricating completeness.

The SituationFrame reports active pressure regime and affected conclusions.

### 16.3 Decision quality per resource

Agent efficiency is measured as decision quality per resource, including:

- evidence-grounded correctness;
- calibration and abstention quality;
- mission loss avoided;
- time to a robust decision;
- tokens and round trips;
- model/compute/energy/network/storage cost;
- privacy exposure;
- operator interventions;
- duplicate or ambiguous effects;
- context rebuilt after resume/handoff.

Raw call count is not a sufficient metric.

---

## 17. Attention frontier

The attention system computes mission-relative candidates from event severity, observability,
change impact, unresolved obligations, deadlines, novelty, model disagreement, infrastructure
health, and memory of prior failure patterns.

Each attention item includes:

- why it matters to the mission;
- supporting and contradictory evidence;
- urgency and deadline;
- consequence if ignored;
- confidence and observability;
- dependencies/shared failure domains;
- top affordances and expected value;
- change since last acknowledgement.

### 17.1 Diversity and domination

The frontier prevents one noisy family from consuming all attention. It applies registered quotas,
submodular diversity, dependency-aware deduplication, and skyline/Pareto filtering. A cluster may be
summarized, but critical members and contradictions stay expandable.

### 17.2 Interruptions

An active agent session receives an interruption only when a registered predicate crosses its
mission policy, such as:

- new high-loss event;
- invalidated critical premise;
- consequential operation becomes indeterminate;
- coverage falls below minimum;
- required approval expires;
- decision deadline approaches;
- privacy or capability violation.

Interruptions carry a minimal situation delta and do not dump unrelated state.

---

## 18. Multi-agent coordination without shared-scratch ambiguity

Multiple agents cooperate through mission branches, typed findings, leases, and immutable handoff
objects—not a mutable shared notebook.

### 18.1 Work claims

An agent can claim a bounded investigation, plan node, evidence domain, or effect authority lease.
The claim contains scope, anchor, expiry, fence, expected deliverable, and cancellation policy.
Readers remain concurrent; conflicting consequential writes are fenced.

### 18.2 Agent finding

A finding contains:

- author, mission, branch, and anchor;
- question or claim;
- epistemic state;
- supporting and contradictory evidence handles;
- assumptions, authorized domain, and coverage;
- method/operation receipts;
- confidence/calibration basis;
- affected investigations/plans/obligations;
- suggested follow-up and cost;
- supersession/withdrawal chain.

A finding is a candidate premise. It does not mutate event truth or policy by publication alone.

### 18.3 Merge and conflicts

Findings and candidate plans merge semantically:

1. identical evidence/claim coalesces with provenance retained;
2. disjoint findings coexist;
3. contradictory findings create a contested node and discriminator work;
4. stale findings require revalidation;
5. effect intents go through the normal witness/lease/prepare/commit path;
6. fabricated branch state never merges into live authority.

### 18.4 Swarm brief

`coordinate` returns a compact brief of:

- agents and claims;
- active branches and questions;
- leases and expiry;
- blocked dependencies;
- duplicate or conflicting work;
- newly published findings;
- critical unowned work;
- recommended partition or handoffs.

Graph critical-path, dominator, SCC/wait-cycle, matching, and assignment algorithms can advise
coordination, with their normal witnesses and no effect authority.

---

## 19. Handoff and resumption

A handoff capsule transfers the minimum sufficient state for another authorized agent to continue
without rereading the world or trusting prose memory.

It contains:

- mission/session identities and exact anchor;
- objective, success/failure/stop criteria, deadline, and budgets;
- acknowledged situation fingerprint;
- compact aliases and their generation;
- active investigations, hypotheses, unknowns, contradictions, and selected probes;
- established findings and assumptions;
- invalidated assumptions and rejected paths;
- active plans, prepared operations, tasks, leases, obligations, and indeterminate effects;
- uncommitted branch state and ownership;
- recent decision-impact delta;
- recommended next affordances with reasons and costs;
- evidence/proof pointers and required capability projection;
- compression receipt and continuation.

### 19.1 Handoff validity

A handoff is accepted only if its mission and capability projection are compatible. `resume` computes
an impact delta from the handoff anchor to current state before presenting any recommendation. A
stale handoff cannot silently revive an expired prepared effect or lease.

### 19.2 No hidden conversational state

An agent must be able to continue from the durable handoff plus canonical repository state. Critical
facts may not exist only in a prior chat transcript.

---

## 20. Accretive learning and Experience Capsules

The system should become easier to operate after every resolved mission without allowing memory to
rewrite evidence or hard policy.

A resolved mission may generate an **Experience Capsule** containing:

- situation signature and deployment scope;
- objective and loss function;
- hypotheses and initial epistemic map;
- observations/probes/actions chosen and their costs;
- operation and evidence receipts;
- outcome and adjudication;
- which signals were predictive, misleading, redundant, missing, or too expensive;
- which assumption failed;
- a cheaper or safer counterfactual path, if demonstrated;
- reusable query, investigation, plan, or runbook template candidates;
- model/adapter/calibration/coverage/firmware generations;
- applicability boundaries;
- evidence strength, confidence, decay, and trauma-guard metadata;
- privacy/retention/deletion class.

### 20.1 Learning proposal versus activation

`learn` has two authority levels:

1. **propose:** derive memory, routing, prompt-template, hard-negative, runbook, or policy-change
   candidates from evidence;
2. **approve/activate:** an authorized curation effect publishes an immutable new generation.

Automatic online adaptation is limited to registered bounded routing policies. Hard safety,
privacy, capability, retention, alert, identity, and deployment policies require explicit
revision/approval.

### 20.2 Positive and negative accretion

FSS retains:

- useful successful patterns;
- false-alarm signatures;
- misses and near misses;
- failed probes and negative expected-value experiments;
- misleading memories and harmful recommendations;
- superseded firmware/model-specific rules;
- anti-patterns generated by trauma guard;
- revival predicates for rules that may become relevant again.

The system learns not only what to do, but what not to repeat and when a once-useful shortcut is no
longer valid.

### 20.3 Measuring accretion

Accretion is demonstrated only when held-out or later missions show improvement in at least one of:

- decision quality or calibration;
- time/tokens/compute/energy/network/privacy/operator burden;
- number of redundant probes;
- resume/handoff reconstruction work;
- false alarms or misses under fixed evaluation;
- diagnosis or reconciliation latency;

without degrading protected metrics or bypassing authority.

---

## 21. Agent-centric explanations

`why` accepts any addressable object or decision:

- why is this event high priority?
- why did the preferred hypothesis change?
- why is coverage uncertified?
- why did this plan become stale?
- why was this affordance recommended or dominated?
- why did FSS abstain?
- why is an alert indeterminate?
- why did an operational memory apply?
- why did the compression omit an item?

The explanation contains:

- exact basis anchor and capability projection;
- causal/evidence path;
- score or utility components;
- contradictions and alternatives;
- counterfactual conditions that would change the result;
- algorithm/model/policy generations and receipts;
- compression and completeness status;
- suggested discriminating inspection.

Explanations are deterministic typed projections where possible. Generated prose is secondary and
cannot add facts.

---

## 22. Security and privacy of the agent substrate

### 22.1 Capability-projected cognition

The SituationFrame, affordance frontier, counts, graph topology, aliases, and absence claims are
computed after capability and privacy projection. A denied object cannot leak through degree,
priority, cost, alias gaps, continuation size, or “something was omitted” metadata.

### 22.2 Least authority

A read-capable agent cannot manufacture effect authority through a plan, natural-language request,
memory, branch, handoff, or another agent's finding. Context cloning narrows or preserves grants.

### 22.3 Context artifacts are private data

Situation capsules, context packs, findings, handoffs, aliases, explanations, experience capsules,
and memory embeddings can reveal routines and property topology. They participate in retention,
export, legal hold, masking, and deletion closure.

### 22.4 Secret exclusion

No agent payload, explanation, proof bundle, memory, or error contains raw credentials, archive
keys, pairing secrets, bearer tokens, or unrestricted device URLs. Handles refer to secret-store
capabilities without revealing values.

### 22.5 Confused-deputy resistance

Every operation binds principal, mission, capability, target scope, anchor, and semantic input
digest. A handoff transfers state but not more authority than the receiver independently holds.

---

## 23. Failure, cancellation, and indeterminacy from the agent's view

The agent should never need to infer lifecycle state from silence.

### 23.1 Cancellation

Cancelling an operation or mission produces a drain receipt that reports:

- children stopped and still draining;
- committed versus uncommitted work;
- staged objects and cleanup/quarantine;
- external effects and reconciliation needs;
- last durable anchor/checkpoint;
- terminal, failed, or indeterminate outcome;
- safe next affordances.

### 23.2 Staleness

When an anchor or premise is stale, FSS identifies the smallest semantic invalidation set. It may
rebase a read-only query automatically under explicit policy; it cannot silently rebase a prepared
consequential operation.

### 23.3 Graceful degradation

A degraded subsystem is represented in the situation model along with impact. For example:

```text
semantic search unavailable
  → exact/lexical search remains
  → similarity affordances are absent
  → no event truth is lost
  → repair operation and expected cost are shown
```

The agent does not have to know which component crashed to understand what conclusions remain safe.

---

## 24. Presentation surfaces

### 24.1 CLI

The primary machine CLI exposes exactly the registered `fss/1` operation universe:

```text
fss session open
fss session resume
fss session orient
fss session follow
fss query
fss investigate
fss plan
fss commit
fss wait
fss cancel
fss explain
fss handoff
fss feedback
fss doctor
```

Typed targets and intent families express `inspect`, evidence hydration, compare/what-if, probe
acquisition, preparation, monitoring, reconciliation, resolution, work claims, and learning review
without creating a second public verb universe. For example, `fss explain --mode what-if`,
`fss query --target evidence-hydration`, `fss plan --intent reconcile`, and
`fss investigate --transition resolve` all retain one registered operation ID.

Every command supports versioned JSON and deterministic human rendering from the same
`AgentResponseEnvelope`. `fss operations`, `fss views`, `fss schema`, `fss capabilities`, and
`fss robot-docs` are discovery projections rather than extra semantic operations.

### 24.2 MCP

MCP exposes the same operation IDs. Read operations may be tools or resources according to protocol
fit; long work is an application-owned durable task. MCP transport qualification is separate from
semantic operation qualification.

### 24.3 TUI, desktop, and mobile

Visual surfaces render:

- mission and attention frontier;
- map/timeline/event/evidence views;
- epistemic state and observability;
- affordance Pareto frontier and cost/risk explanation;
- plan/prepare/commit boundary;
- durable task and reconciliation state;
- handoff and multi-agent coordination.

A button is never a new semantic effect. It invokes a registered operation with the same authority
and digest as the CLI/library.

### 24.4 Robot documentation

`fss capabilities`, `fss operations`, `fss views`, `fss schema`, and `fss robot-docs` expose
machine-readable discovery. An agent can learn the system without reading prose or guessing names.

---

## 25. Crate ownership

The agent substrate is divided by semantic ownership rather than presentation:

| Crate | Owns | Must not own |
|---|---|---|
| `fss-epistemic` | epistemic states, completeness, contradiction contracts | domain evidence or effects |
| `fss-mission` | mission revisions, objective/criteria/budget state | sensor/model execution |
| `fss-agent-session` | session state, aliases, acknowledged fingerprints | global identity or policy |
| `fss-situation` | SituationCapsule, inner SituationFrame, meaningful-delta and decision-impact projection | canonical source mutation |
| `fss-context-pack` | registered views, semantic zoom, compression receipts | effect authority |
| `fss-affordance` | safe next-operation generation and Pareto/value receipts | capability granting or commit |
| `fss-query-plan` | typed NL/query compilation and ambiguity plans | arbitrary prompt execution |
| `fss-investigation` | questions, hypotheses, probes, stop rules, conclusions | canonical event mutation by itself |
| `fss-plan` | semantic plan DAGs and witnesses | direct external side effects |
| `fss-handoff` | handoff capsules and resume validation | authority transfer beyond receiver grants |
| `fss-coordination` | claims, findings, leases, swarm brief | mutable shared scratch truth |
| `fss-memory` | evidence-linked experience and curation candidates | hard policy or event truth |
| `fss-api` | transport-neutral operation/view registry facade | domain-specific alternate semantics |
| `fss-cli` / `fss-mcp` / `fss-ops` / `fss-ui` | framing and rendering | independent operation definitions |

Authority, cognition, effect, and presentation dependency directions in
`architecture/crate_topology.json` remain binding.

---

## 26. Qualification and evaluation

The local `QL-AGENT-001` lane qualifies the agent operating model independently of camera or threat
quality claims.

Required evidence includes:

1. SituationCapsule/inner-SituationFrame completeness, coherence, compression proof, and deterministic fingerprinting.
2. Decision-impact deltas that identify invalidated assumptions/plans/obligations.
3. Semantic compression receipts and critical-information preservation campaigns.
4. Cross-surface operation/view conformance for library, CLI, MCP, and renderer fixtures.
5. Mission pause/resume/crash/handoff with no lost obligations or hidden conversational state.
6. Natural-language compiler ambiguity, taint, injection, capability, and boundedness corpus.
7. Affordance hard-constraint, expiry, Pareto, value/cost, and safe-fallback tests.
8. Investigation hypothesis/discriminator/stop-rule replay.
9. Plan/prepare/commit/watch/reconcile/idempotency and lost-ACK scenarios.
10. Multi-agent branch/finding/lease/conflict/noninterference schedules.
11. Experience-capsule curation, decay, trauma-guard, retirement, and deletion tests.
12. Token, latency, model-call, privacy, and decision-quality evaluation over held-out missions.

### 26.1 Agent benchmark scenarios

- orient after an overnight delta without missing a critical indeterminate alert;
- identify that no-detection is not absence during camera degradation;
- choose the cheapest discriminating probe between wildlife and intrusion;
- recover from stale calibration invalidating an association plan;
- resume after process death while an archive root is staged but unpublished;
- reconcile a lost alert ACK without duplicate dispatch;
- coordinate two agents investigating related cameras without conflicting PTZ;
- hand off an active mission with no re-reading of unchanged evidence;
- use prior false-alarm experience without allowing it to suppress new threat evidence;
- minimize tokens/model calls under a fixed decision-quality and privacy floor.

### 26.2 Metrics

Metrics include:

- mission-level correctness and expected loss;
- factual/epistemic-state accuracy;
- critical invalidation recall;
- calibration and abstention;
- unsafe or duplicate effects;
- context tokens and semantic expansion bytes;
- round trips and time to robust decision;
- model/graph/search calls and compute/energy;
- privacy exposure and operator burden;
- resume/handoff reconstruction cost;
- affordance regret versus an exhaustive bounded oracle;
- accretive improvement on future held-out missions.

---

## 27. Explicit rejections

FSS rejects these agent-interface designs:

- a giant unstructured world-state dump;
- one tool per internal method or vendor endpoint;
- natural-language text as an effect or authorization language;
- a generic “do whatever is best” autonomy tool;
- one opaque suspicion, priority, confidence, or utility scalar;
- free-form model prose without evidence regions/times and execution receipt;
- silent automatic query reinterpretation for consequential operations;
- latest-state reads that mix generations;
- an empty result meaning absence;
- compact summaries without omission/completeness receipts;
- suggested actions without preconditions, cost, risk, expiry, and proof expectations;
- indefinite waiting without deadline and wake predicates;
- progress bars without durable checkpoints or semantic completion predicates;
- session aliases as durable/global identity;
- multi-agent coordination through mutable scratch text;
- handoffs that omit indeterminate effects, leases, assumptions, or invalidations;
- learning that silently changes hard policy or rewrites prior evidence;
- CLI, MCP, and UI surfaces with divergent semantics;
- token minimization that omits decision-critical contradictions or coverage gaps.

---

## 28. First implementation sequence

The agent operating model should be built in this order:

1. freeze epistemic states, mission/session identity, response envelope, and view/operation registries;
2. implement a deterministic in-memory mission ledger and SituationCapsule over synthetic authority
   state;
3. implement semantic compression receipts and critical-preservation oracle;
4. implement aliases, semantic zoom, and decision-impact deltas;
5. implement typed query plans and a non-model reference compiler;
6. implement investigations, hypotheses, discriminators, and stop rules;
7. implement affordance generation with hard constraints and decomposed cost/value vectors;
8. implement read-only universal operations across library and CLI;
9. implement plan/prepare/commit/monitor/reconcile against a simulated effect adapter;
10. implement handoff, resume, findings, leases, and multi-agent schedule exploration;
11. integrate search/graph/model/media/coverage projections one at a time through admission gates;
12. implement MCP/TUI/UI as projections of the qualified facade;
13. implement Experience Capsules and explicit learning curation;
14. optimize context selection and affordance computation only after held-out agent traces identify
    the actual wall.

The first vertical slice is not “list cameras.” It is:

```text
synthetic evidence delta
→ mission
→ orientation SituationCapsule with certified core, material worlds, and robust-control envelope
→ investigation with two hypotheses and one protected adversarial residual
→ typed discriminating probe
→ prepared simulated effect
→ durable monitor and reconciliation
→ resolution
→ Experience Capsule candidate
→ handoff/resume replay
```

---

## 29. Closing synthesis

The agent-facing system should feel like a well-designed cockpit. The agent should not memorize the
wiring diagram, poll every instrument, or infer whether a button is safe. FSS continuously presents:

- one objective;
- one coherent situation;
- one explicit map of knowledge and ignorance;
- one bounded frontier of what matters;
- one inspectable set of safe next moves;
- one universal lifecycle for consequential action;
- one durable chain of proof;
- one accretive memory of what worked, failed, and changed.

That coherence is not a UI layer placed on top of components. It is the synthesis that makes the
components a system.
