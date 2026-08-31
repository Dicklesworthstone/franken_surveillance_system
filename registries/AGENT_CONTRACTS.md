# Agent contract registry

Semantic protocol: `fss/1`. Machine umbrella: `architecture/agent_contracts.json`.

The registry separates knowledge state, provenance class, hypothesis disposition, access transformation, and operation outcome. Stable IDs are never renumbered.

## Semantic narrow waist

Every subsystem reaches the agent compositor through the internal `CognitiveFacet` contract owned
by `fss-agent-core`. Required coordinates are: facet/owner identity; basis anchor and high-water;
scope/validity; knowledge cells; coverage/health; contradictions/unknowns; evidence handles; open
obligations and indeterminate effects; resource state/full cost; affordance seeds; invalidators and
degradation; proof and continuation. Facets are capability/privacy projected before composition and
carry no effect authority. The machine contract is `subsystemProjectionContract` in
`architecture/agent_contracts.json`.

## Knowledge states

Knowledge-state permission is deliberately split. An estimate may support speculative planning, but it cannot authorize an irreversible effect merely by having a high score.

| ID | State | Meaning | May support planning | May authorize irreversible effect | Explicit assumptions required |
|---|---|---|---:|---:|---:|
| `KSTATE-001` | `known` | The proposition is established for the named anchor and validity scope by admissible evidence or a proved terminal postcondition. | yes | yes, subject to capability and policy | no |
| `KSTATE-002` | `estimated` | The proposition is supported by a declared derivation or model with explicit uncertainty and operating-envelope limits. | yes | no | yes |
| `KSTATE-003` | `unknown` | The authorized evidence acquired so far does not establish the proposition. | yes, as an explicit branch or open variable | no | yes |
| `KSTATE-004` | `conflicted` | Material admissible evidence supports incompatible propositions or generations. | yes, only as competing branches | no | yes |
| `KSTATE-005` | `stale` | The proposition was valid only at an older anchor or generation and has not been revalidated. | yes, only as a revalidation candidate | no | yes |
| `KSTATE-006` | `not_observable` | The declared sensor/authorization/model domain could not have established the proposition for the requested interval. | yes, as a protected residual possibility | no | yes |
| `KSTATE-007` | `redacted` | The proposition or its evidence exists but is intentionally withheld by the current privacy/capability projection. | yes, only through non-leaking abstract constraints | no | yes |
| `KSTATE-008` | `indeterminate` | A consequential external outcome may have occurred but is not yet proved or safely negated. | yes, only in reconciliation branches | no | yes |
| `KSTATE-009` | `not_applicable` | The proposition has no meaning for the named object, scope, or lifecycle state. | no | no | no |

## Provenance classes

| ID | Class | Meaning |
|---|---|---|
| `PROV-001` | `observed` | Directly supported by canonical sensor, device, operator, or effect evidence. |
| `PROV-002` | `derived` | Deterministically computed from named canonical inputs under a registered algorithm and generation. |
| `PROV-003` | `predicted` | Counterfactual or forward prediction under an explicit branch/model and assumptions. |
| `PROV-004` | `remembered` | Advisory operational memory or prior episode material that must be revalidated against live evidence. |
| `PROV-005` | `operator_asserted` | A human/operator assertion with identity, time, scope, and later corroboration status. |
| `PROV-006` | `vendor_claimed` | Metadata or state asserted by a device/vendor boundary and not treated as independent physical truth. |
| `PROV-007` | `policy` | A rule, threshold, capability, or privacy decision from an exact policy generation. |

## Hypothesis dispositions

`live` · `supported` · `disfavored` · `refuted` · `resolved` · `superseded`

Hypothesis disposition is not a knowledge state. A hypothesis can be `disfavored` while some of its propositions remain `known`; a `refuted` hypothesis does not turn missing observations into falsehood.

## Public semantic operations

Every operation uses the universal request/response envelopes; the table exposes the typed request payload selected by the sole machine operation registry.

| ID | Operation | Owner | Mode | Default view | Typed request payload | Effectful | Durable | Gate | Status |
|---|---|---|---|---|---|---:|---:|---|---|
| `AOP-001` | `session.open` | `fss-agent-session` | `session_control` | `AVIEW-002` | `fss.agent_mission.v1` | no | yes | `QL-AGENT-001` | `specified` |
| `AOP-002` | `session.resume` | `fss-agent-session` | `session_control` | `AVIEW-006` | `fss.agent_handoff_capsule.v1` | no | yes | `QL-AGENT-001` | `specified` |
| `AOP-003` | `session.orient` | `fss-situation` | `read` | `AVIEW-002` | `fss.agent_query_plan.v1` | no | no | `QL-AGENT-001` | `specified` |
| `AOP-004` | `session.follow` | `fss-context-pack` | `read_wait` | `AVIEW-001` | `fss.agent_query_plan.v1` | no | yes | `QL-AGENT-001` | `specified` |
| `AOP-005` | `query` | `fss-query-plan` | `read_compile` | `AVIEW-003` | `fss.agent_query_plan.v1` | no | no | `QL-AGENT-001` | `specified` |
| `AOP-006` | `investigate` | `fss-investigation` | `cognition_write` | `AVIEW-003` | `fss.investigation_state.v1` | no | yes | `QL-AGENT-001` | `specified` |
| `AOP-007` | `plan` | `fss-agent-plan` | `plan_prepare` | `AVIEW-007` | `fss.agent_objective_contract.v1` | no | yes | `QL-AGENT-001` | `specified` |
| `AOP-008` | `commit` | `fss-effect` | `effect_commit` | `AVIEW-005` | `fss.agent_control_plan.v1` | yes | yes | `QL-AGENT-001` | `specified` |
| `AOP-009` | `wait` | `fss-obligation` | `read_wait` | `AVIEW-005` | `fss.agent_query_plan.v1` | no | yes | `QL-AGENT-001` | `specified` |
| `AOP-010` | `cancel` | `fss-obligation` | `lifecycle_effect` | `AVIEW-005` | `fss.agent_query_plan.v1` | yes | yes | `QL-AGENT-001` | `specified` |
| `AOP-011` | `explain` | `fss-explain` | `read_compute` | `AVIEW-007` | `fss.agent_query_plan.v1` | no | no | `QL-AGENT-001` | `specified` |
| `AOP-012` | `handoff` | `fss-handoff` | `continuity_publish` | `AVIEW-006` | `fss.agent_session_capsule.v1` | no | yes | `QL-AGENT-001` | `specified` |
| `AOP-013` | `feedback` | `fss-learning` | `advisory_write` | `AVIEW-007` | `fss.agent_feedback_proposal.v1` | no | yes | `QL-AGENT-001` | `specified` |
| `AOP-014` | `doctor` | `fss-doctor` | `diagnostic_prepare` | `AVIEW-004` | `fss.agent_query_plan.v1` | no | yes | `QL-AGENT-001` | `specified` |

## Registered views

| ID | View | Owner | Purpose | Target tokens | Maximum tokens | Gate | Status |
|---|---|---|---|---:|---:|---|---|
| `AVIEW-001` | `pulse` | `fss-context-pack` | tiny high-severity meaningful delta, sensor-health, coverage-loss, effect-uncertainty, and obligation heartbeat | 120 | 300 | `QL-AGENT-001` | `specified` |
| `AVIEW-002` | `brief` | `fss-situation` | primary mission SituationCapsule answering what is established, what materially different worlds remain possible, what changed, why it matters, and what is robustly or conditionally safe to do next | 800 | 1600 | `QL-AGENT-001` | `specified` |
| `AVIEW-003` | `case` | `fss-investigation` | investigation question, competing hypotheses, evidence, contradictions, unknowns, discriminators, and stop rule | 3000 | 5000 | `QL-AGENT-001` | `specified` |
| `AVIEW-004` | `forensic` | `fss-context-pack` | broad exact evidence graph, source spans, receipts, alternative derivations, and replay handles | 8000 | 16000 | `QL-AGENT-001` | `specified` |
| `AVIEW-005` | `operation` | `fss-obligation` | one durable plan/effect/task, progress, expected terminal proof, obligations, and reconciliation | 600 | 1200 | `QL-AGENT-001` | `specified` |
| `AVIEW-006` | `handoff` | `fss-handoff` | minimum sufficient state for another agent to resume without rediscovery or hidden staleness | 1800 | 3200 | `QL-AGENT-001` | `specified` |
| `AVIEW-007` | `decision_diff` | `fss-explain` | why a conclusion, priority, hypothesis, plan, or preferred affordance changed | 900 | 1800 | `QL-AGENT-001` | `specified` |
| `AVIEW-008` | `epistemic_map` | `fss-knowledge` | known/estimated/unknown/conflicted/stale/not-observable/redacted/indeterminate map plus certified core, material alternative worlds, adversarial residuals, and discriminators | 1500 | 3000 | `QL-AGENT-001` | `specified` |

## Response priority

1. constitutional safety and privacy clamps
2. effect/obligation state and indeterminacy
3. coverage loss and not-observable domains
4. contradictions and invalidated assumptions
5. mission-critical current state
6. capability-valid next affordances
7. optional detail and narrative

## Semantic object catalog

| Object | Schema |
|---|---|
| `ContractBasis` | `fss.agent_contract_basis.v1` |
| `AgentRequestEnvelope` | `fss.agent_request_envelope.v1` |
| `MissionContract` | `fss.agent_mission.v1` |
| `ObjectiveContract` | `fss.agent_objective_contract.v1` |
| `AgentSession` | `fss.agent_session.v1` |
| `AgentSessionCapsule` | `fss.agent_session_capsule.v1` |
| `KnowledgeCell` | `fss.agent_knowledge_cell.v1` |
| `WorldEnvelope` | `fss.agent_world_envelope.v1` |
| `SituationCapsule` | `fss.situation_capsule.v1` |
| `SituationFrame` | `fss.agent_situation_frame.v1` |
| `MeaningfulDelta` | `fss.agent_meaningful_delta.v1` |
| `AgentQueryPlan` | `fss.agent_query_plan.v1` |
| `InvestigationCase` | `fss.investigation_state.v1` |
| `HypothesisWorkspace` | `fss.agent_hypothesis_workspace.v1` |
| `ContextPack` | `fss.semantic_context_pack.v1` |
| `SemanticCompressionReceipt` | `fss.semantic_compression_receipt.v1` |
| `ActionAffordance` | `fss.agent_affordance.v1` |
| `ControlPlan` | `fss.agent_control_plan.v1` |
| `ExecutionEpisode` | `fss.agent_execution_episode.v1` |
| `ExperienceCapsule` | `fss.experience_capsule.v1` |
| `WorkClaim` | `fss.agent_work_claim.v1` |
| `AgentFinding` | `fss.agent_finding.v1` |
| `FeedbackProposal` | `fss.agent_feedback_proposal.v1` |
| `LearningProposal` | `fss.agent_learning_proposal.v1` |
| `HandoffCapsule` | `fss.agent_handoff_capsule.v1` |
| `AgentCognitiveEnvelope` | `fss.agent_cognitive_envelope.v1` |
| `AgentResponseEnvelope` | `fss.agent_response_envelope.v1` |

## Object composition

- **`ContractBasis`:** pins the exact semantic and registry universe used to interpret an agent artifact.
- **`AgentRequestEnvelope`:** wraps every public operation request with contract basis, lifecycle identity, anchor/workspace preconditions, view, targets, typed payload, budget, requested authority/privacy, continuation, idempotency, hydration/compression policy, and taint.
- **`MissionContract`:** contains one ObjectiveContract and immutable revisions of focus, assumptions, budgets, and terminal criteria.
- **`WorldEnvelope`:** separates the nominal world, certified core and absences, material alternative worlds, adversarial residuals, common invariants, unresolved dimensions, and discriminating affordances.
- **`SituationCapsule`:** contains a SituationFrame with a WorldEnvelope, optional MeaningfulDelta, active investigations/plans/obligations, resource state, a categorized control envelope, ContextPack, and SemanticCompressionReceipt.
- **`InvestigationCase`:** contains or references a HypothesisWorkspace, discriminating probes, stop rules, findings, and residual uncertainty.
- **`ControlPlan`:** contains a witnessed contingent DAG and prepared domain effects; it never confers authority by itself.
- **`ExperienceCapsule`:** summarizes one or more ExecutionEpisodes and can produce advisory FeedbackProposal or LearningProposal objects.
- **`HandoffCapsule`:** publishes the minimum sufficient mission/workspace/case/plan/obligation state as a root-last portable graph.
- **`AgentResponseEnvelope`:** wraps every public operation result; an AgentCognitiveEnvelope or SituationCapsule is a typed payload, never a competing transport contract.

## Request/response rule

Every `AOP-*` operation accepts `fss.agent_request_envelope.v1` and returns
`fss.agent_response_envelope.v1`. `architecture/agent_operations.json` alone names the
operation-specific request payload schema. An incompatible ContractBasis fails closed; transports
may omit unqualified operations but cannot redefine parameters or payload meaning.

## Evidence–possibility–control envelope

Every primary driver publication answers three different questions without collapsing them:

1. **Evidence envelope:** what the current anchor and coverage witnesses positively establish, including certified absences.
2. **Possibility envelope:** which materially different or adversarial worlds remain compatible with evidence, authorization, and observability limits.
3. **Control envelope:** which affordances are robust across the protected possibility envelope, which are conditional on named worlds, which gather information, which wait, and which are blocked.

A high-consequence residual world is never removed because it ranks poorly. It leaves the envelope only when a named witness, policy, or explicit scope change rules it out.

## Resource URI templates

```text
fss://deployment/{deployment}/anchor/{anchor}
fss://deployment/{deployment}/situation/{capsule}
fss://deployment/{deployment}/sensor/{sensor}
fss://deployment/{deployment}/zone/{zone}
fss://deployment/{deployment}/event/{event}/revision/{revision}
fss://deployment/{deployment}/case/{case}/revision/{revision}
fss://deployment/{deployment}/hypothesis/{hypothesis}
fss://deployment/{deployment}/evidence/{digest}
fss://deployment/{deployment}/plan/{plan}
fss://deployment/{deployment}/obligation/{obligation}
fss://mission/{mission}/revision/{revision}
fss://session/{session}/workspace/{workspace}
fss://session/{session}/handoff/{root}
fss://experience/{capsule}
fss://doctor/{bundle}
```
