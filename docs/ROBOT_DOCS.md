# Self-Describing Robot Documentation (`fss/1`)

<!--
GENERATED FILE - DO NOT EDIT DIRECTLY.
Generated deterministically by scripts/generate_robot_docs.py from authoritative machine registries:
- architecture/fss1_public_registry.json
- architecture/agent_operations.json
- architecture/agent_views.json
- architecture/capabilities.json
- architecture/operation_crosswalk.json
- registries/ERRORS.md
- registries/SCHEMAS.md
-->

This document provides the authoritative, self-describing reference for autonomous agent
drivers operating within the Franken Surveillance System under semantic protocol `fss/1`.
Agents orient, query, plan, and coordinate using registered operations and views without
human prose dependence or undocumented endpoints.

## 1. Protocol Identity & Contract Basis

- **Semantic Protocol**: `fss/1`
- **Registry Generation**: `gen:fss1:public-v1`
- **Freeze Digest**: `sha256:9bbec4e6845ea702f676cd22472e5fb0d35ca3b3d97f66cbfccb452182413da8`
- **As Of**: `2026-09-12`
- **Total Operations**: 14
- **Total Views**: 8
- **Total Resource URI Templates**: 15
- **Total Schemas Cataloged**: 26
- **Total Capabilities Mapped**: 12

## 2. Machine Discovery Endpoints

Agents can discover and inspect system capabilities at runtime using deterministic CLI endpoints:

| Endpoint | CLI Invocation | Description |
|---|---|---|
| `capabilities` | `fss capabilities --json` | Report all supported device, model, and agent capabilities in typed JSON |
| `operations` | `fss operations --json` | Report all registered fss/1 operations with request/response schemas and crosswalk targets |
| `robot_docs` | `fss robot-docs guide` | Output complete self-describing robot documentation for autonomous agent drivers |
| `schemas` | `fss schema list --json` | List all authoritative schema identifiers, files, and compatibility rules |
| `views` | `fss views --json` | Report all registered agent views with token budgets and required section keys |

## 3. Registered Operations Catalog

Every operation is bound to a single owning crate, default view, typed request/response
envelope, and strict idempotency/effect semantics:

| ID | Operation | Owner | CLI Command | MCP Tool | Default View | Effectful | Durable | Status |
|---|---|---|---|---|---|---|---|---|
| `AOP-001` | `session.open` | `fss-agent-session` | `fss session open` | `session_open` | `AVIEW-002` | false | true | `specified` |
| `AOP-002` | `session.resume` | `fss-agent-session` | `fss session resume` | `session_resume` | `AVIEW-006` | false | true | `specified` |
| `AOP-003` | `session.orient` | `fss-situation` | `fss session orient` | `session_orient` | `AVIEW-002` | false | false | `specified` |
| `AOP-004` | `session.follow` | `fss-context-pack` | `fss session follow` | `session_follow` | `AVIEW-001` | false | true | `specified` |
| `AOP-005` | `query` | `fss-query-plan` | `fss query` | `query` | `AVIEW-003` | false | false | `specified` |
| `AOP-006` | `investigate` | `fss-investigation` | `fss investigate` | `investigate` | `AVIEW-003` | false | true | `specified` |
| `AOP-007` | `plan` | `fss-agent-plan` | `fss plan` | `plan` | `AVIEW-007` | false | true | `specified` |
| `AOP-008` | `commit` | `fss-effect` | `fss commit` | `commit` | `AVIEW-005` | true | true | `specified` |
| `AOP-009` | `wait` | `fss-obligation` | `fss wait` | `wait` | `AVIEW-005` | false | true | `specified` |
| `AOP-010` | `cancel` | `fss-obligation` | `fss cancel` | `cancel` | `AVIEW-005` | true | true | `specified` |
| `AOP-011` | `explain` | `fss-explain` | `fss explain` | `explain` | `AVIEW-007` | false | false | `specified` |
| `AOP-012` | `handoff` | `fss-handoff` | `fss handoff` | `handoff` | `AVIEW-006` | false | true | `specified` |
| `AOP-013` | `feedback` | `fss-learning` | `fss feedback` | `feedback` | `AVIEW-007` | false | true | `specified` |
| `AOP-014` | `doctor` | `fss-doctor` | `fss doctor` | `doctor` | `AVIEW-004` | false | true | `specified` |

### 3.1 Operation Details & Schemas

#### `AOP-001` — `session.open`

- **Purpose**: negotiate principal, mission, authority, privacy projection, budgets, views, and the initial SituationCapsule
- **Mode**: `session_control`
- **Owner**: `fss-agent-session`
- **CLI Command**: `fss session open`
- **MCP Tool**: `session_open`
- **Library Entry Point**: `fss_agent_session::session_open`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_mission.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.situation_capsule.v1`
- **Default View**: `AVIEW-002`
- **Required Capabilities**: `CAP-AGENT-SESSION-OPEN-001`
- **Retry Classes**: `never_unchanged`, `backoff`, `operator_action_required`, `resume_from_continuation`
- **Primary Error ID**: `ERR-AUTH-DENIED-001`

#### `AOP-002` — `session.resume`

- **Purpose**: restore an explicit workspace/handoff root, compare it with current state, and enumerate stale or invalidated assumptions
- **Mode**: `session_control`
- **Owner**: `fss-agent-session`
- **CLI Command**: `fss session resume`
- **MCP Tool**: `session_resume`
- **Library Entry Point**: `fss_agent_session::session_resume`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_handoff_capsule.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.situation_capsule.v1`
- **Default View**: `AVIEW-006`
- **Required Capabilities**: `CAP-AGENT-SESSION-READ-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `rebase_required`, `operator_action_required`, `resume_from_continuation`
- **Primary Error ID**: `ERR-AGENT-HANDOFF-INVALID-001`

#### `AOP-003` — `session.orient`

- **Purpose**: return the smallest sufficient current SituationCapsule for the mission, authority, and budget
- **Mode**: `read`
- **Owner**: `fss-situation`
- **CLI Command**: `fss session orient`
- **MCP Tool**: `session_orient`
- **Library Entry Point**: `fss_situation::session_orient`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_query_plan.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.situation_capsule.v1`
- **Default View**: `AVIEW-002`
- **Required Capabilities**: `CAP-AGENT-SITUATION-READ-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `rebase_required`, `backoff`, `resume_from_continuation`
- **Primary Error ID**: `ERR-AGENT-CONTEXT-INCOMPLETE-001`

#### `AOP-004` — `session.follow`

- **Purpose**: stream meaningful deltas and obligation progress from an exact continuation cursor
- **Mode**: `read_wait`
- **Owner**: `fss-context-pack`
- **CLI Command**: `fss session follow`
- **MCP Tool**: `session_follow`
- **Library Entry Point**: `fss_context_pack::session_follow`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_query_plan.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.agent_meaningful_delta.v1`, `fss.situation_capsule.v1`
- **Default View**: `AVIEW-001`
- **Required Capabilities**: `CAP-AGENT-SITUATION-READ-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `rebase_required`, `backoff`, `resume_from_continuation`
- **Primary Error ID**: `ERR-AGENT-RESNAPSHOT-001`

#### `AOP-005` — `query`

- **Purpose**: execute a bounded typed or natural-language-compiled read over one anchor with completeness and cost receipts
- **Mode**: `read_compile`
- **Owner**: `fss-query-plan`
- **CLI Command**: `fss query`
- **MCP Tool**: `query`
- **Library Entry Point**: `fss_query_plan::query`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_query_plan.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.agent_cognitive_envelope.v1`
- **Default View**: `AVIEW-003`
- **Required Capabilities**: `CAP-AGENT-QUERY-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `rebase_required`, `backoff`, `resume_from_continuation`
- **Primary Error ID**: `ERR-AGENT-AMBIGUOUS-001`

#### `AOP-006` — `investigate`

- **Purpose**: create or advance a durable case with competing hypotheses, evidence tasks, work claims, discriminators, and stop rules
- **Mode**: `cognition_write`
- **Owner**: `fss-investigation`
- **CLI Command**: `fss investigate`
- **MCP Tool**: `investigate`
- **Library Entry Point**: `fss_investigation::investigate`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.investigation_state.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.investigation_state.v1`, `fss.agent_cognitive_envelope.v1`
- **Default View**: `AVIEW-003`
- **Required Capabilities**: `CAP-AGENT-CASE-WRITE-001`
- **Retry Classes**: `refresh_and_retry`, `rebase_required`, `backoff`, `reconciliation_required`, `operator_action_required`, `resume_from_continuation`
- **Primary Error ID**: `ERR-AGENT-CASE-BUDGET-001`

#### `AOP-007` — `plan`

- **Purpose**: compile a desired outcome or information objective into an immutable witnessed contingent plan without crossing the effect boundary
- **Mode**: `plan_prepare`
- **Owner**: `fss-agent-plan`
- **CLI Command**: `fss plan`
- **MCP Tool**: `plan`
- **Library Entry Point**: `fss_agent_plan::plan`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_objective_contract.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.agent_control_plan.v1`
- **Default View**: `AVIEW-007`
- **Required Capabilities**: `CAP-AGENT-PLAN-PREPARE-001`
- **Retry Classes**: `refresh_and_retry`, `rebase_required`, `backoff`, `operator_action_required`, `resume_from_continuation`
- **Primary Error ID**: `ERR-PRECONDITION-STALE-001`

#### `AOP-008` — `commit`

- **Purpose**: revalidate and start the exact prepared plan under idempotency, leases, fencing, approval, and terminal-proof obligations
- **Mode**: `effect_commit`
- **Owner**: `fss-effect`
- **CLI Command**: `fss commit`
- **MCP Tool**: `commit`
- **Library Entry Point**: `fss_effect::commit`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_control_plan.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.operation_receipt.v1`, `fss.agent_cognitive_envelope.v1`
- **Default View**: `AVIEW-005`
- **Required Capabilities**: `CAP-AGENT-PLAN-COMMIT-001`
- **Retry Classes**: `never_unchanged`, `backoff`, `reconciliation_required`, `operator_action_required`, `resume_from_continuation`
- **Primary Error ID**: `ERR-EFFECT-INDETERMINATE-001`

#### `AOP-009` — `wait`

- **Purpose**: observe cases, plans, effects, transfers, and obligations until a predicate, deadline, or meaningful delta fires
- **Mode**: `read_wait`
- **Owner**: `fss-obligation`
- **CLI Command**: `fss wait`
- **MCP Tool**: `wait`
- **Library Entry Point**: `fss_obligation::wait`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_query_plan.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.agent_cognitive_envelope.v1`, `fss.operation_receipt.v1`
- **Default View**: `AVIEW-005`
- **Required Capabilities**: `CAP-AGENT-SITUATION-READ-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `backoff`, `reconciliation_required`, `resume_from_continuation`
- **Primary Error ID**: `ERR-OP-TIMEOUT-001`

#### `AOP-010` — `cancel`

- **Purpose**: request, drain, reconcile or compensate, and finalize owned work without erasing its durable record
- **Mode**: `lifecycle_effect`
- **Owner**: `fss-obligation`
- **CLI Command**: `fss cancel`
- **MCP Tool**: `cancel`
- **Library Entry Point**: `fss_obligation::cancel`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_query_plan.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.operation_receipt.v1`, `fss.agent_cognitive_envelope.v1`
- **Default View**: `AVIEW-005`
- **Required Capabilities**: `CAP-AGENT-CANCEL-001`
- **Retry Classes**: `never_unchanged`, `backoff`, `reconciliation_required`, `operator_action_required`, `resume_from_continuation`
- **Primary Error ID**: `ERR-QUIESCENCE-001`

#### `AOP-011` — `explain`

- **Purpose**: answer why, why-not, what-changed, or what-if with a minimal evidence/decision subgraph and expansion handles
- **Mode**: `read_compute`
- **Owner**: `fss-explain`
- **CLI Command**: `fss explain`
- **MCP Tool**: `explain`
- **Library Entry Point**: `fss_explain::explain`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_query_plan.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.agent_cognitive_envelope.v1`
- **Default View**: `AVIEW-007`
- **Required Capabilities**: `CAP-AGENT-EXPLAIN-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `rebase_required`, `resume_from_continuation`
- **Primary Error ID**: `ERR-REPLAY-DIVERGED-001`

#### `AOP-012` — `handoff`

- **Purpose**: publish a root-last portable capsule containing mission, workspace, cases, plans, obligations, budgets, authority, uncertainty, and continuations
- **Mode**: `continuity_publish`
- **Owner**: `fss-handoff`
- **CLI Command**: `fss handoff`
- **MCP Tool**: `handoff`
- **Library Entry Point**: `fss_handoff::handoff`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_session_capsule.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.agent_handoff_capsule.v1`
- **Default View**: `AVIEW-006`
- **Required Capabilities**: `CAP-AGENT-HANDOFF-WRITE-001`
- **Retry Classes**: `refresh_and_retry`, `rebase_required`, `backoff`, `reconciliation_required`, `operator_action_required`, `resume_from_continuation`
- **Primary Error ID**: `ERR-AGENT-HANDOFF-INVALID-001`

#### `AOP-013` — `feedback`

- **Purpose**: record a correction, outcome signal, adjudication, or evidence-linked learning proposal without silently changing active truth or policy
- **Mode**: `advisory_write`
- **Owner**: `fss-learning`
- **CLI Command**: `fss feedback`
- **MCP Tool**: `feedback`
- **Library Entry Point**: `fss_learning::feedback`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_feedback_proposal.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.agent_feedback_proposal.v1`, `fss.experience_capsule.v1`
- **Default View**: `AVIEW-007`
- **Required Capabilities**: `CAP-AGENT-FEEDBACK-001`
- **Retry Classes**: `refresh_and_retry`, `rebase_required`, `backoff`, `reconciliation_required`, `operator_action_required`
- **Primary Error ID**: `ERR-AGENT-LEARNING-UNSUPPORTED-001`

#### `AOP-014` — `doctor`

- **Purpose**: diagnose deployment, evidence, cognition, workspace, cases, obligations, and protocol consistency and produce sealed repair affordances
- **Mode**: `diagnostic_prepare`
- **Owner**: `fss-doctor`
- **CLI Command**: `fss doctor`
- **MCP Tool**: `doctor`
- **Library Entry Point**: `fss_doctor::doctor`
- **Request Envelope**: `fss.agent_request_envelope.v1`
- **Request Payload Schema**: `fss.agent_query_plan.v1`
- **Response Envelope**: `fss.agent_response_envelope.v1`
- **Response Payload Schemas**: `fss.agent_cognitive_envelope.v1`, `fss.evidence_bundle.v1`
- **Default View**: `AVIEW-004`
- **Required Capabilities**: `CAP-REPAIR-PREPARE-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `backoff`, `resume_from_continuation`
- **Primary Error ID**: `ERR-CLI-RUNTIME-FAILURE-001`

## 4. Registered Views Catalog

Views are typed, compressed projections of the underlying semantic situation. Every view
declares explicit token budgets and mandatory semantic sections:

| ID | View Name | Owner | Target Tokens | Max Tokens | Required Sections | Purpose |
|---|---|---|---|---|---|---|
| `AVIEW-001` | `pulse` | `fss-context-pack` | 120 | 300 | `criticalChanges`, `coverageChanges`, `effectUncertainty`, `urgentObligations`, `continuity` | tiny high-severity meaningful delta, sensor-health, coverage-loss, effect-uncertainty, and obligation heartbeat |
| `AVIEW-002` | `brief` | `fss-situation` | 800 | 1600 | `now`, `certified`, `possible`, `changed`, `why`, `unknown`, `atRisk`, `controlEnvelope`, `next` | primary mission SituationCapsule answering what is established, what materially different worlds remain possible, what changed, why it matters, and what is robustly or conditionally safe to do next |
| `AVIEW-003` | `case` | `fss-investigation` | 3000 | 5000 | `question`, `hypotheses`, `evidence`, `contradictions`, `unknowns`, `discriminators`, `stopRule` | investigation question, competing hypotheses, evidence, contradictions, unknowns, discriminators, and stop rule |
| `AVIEW-004` | `forensic` | `fss-context-pack` | 8000 | 16000 | `evidenceGraph`, `sourceHandles`, `receipts`, `derivations`, `replay` | broad exact evidence graph, source spans, receipts, alternative derivations, and replay handles |
| `AVIEW-005` | `operation` | `fss-obligation` | 600 | 1200 | `state`, `progress`, `proofExpected`, `obligations`, `reconciliation` | one durable plan/effect/task, progress, expected terminal proof, obligations, and reconciliation |
| `AVIEW-006` | `handoff` | `fss-handoff` | 1800 | 3200 | `mission`, `situation`, `cases`, `plans`, `obligations`, `unknowns`, `budgets`, `authority`, `next` | minimum sufficient state for another agent to resume without rediscovery or hidden staleness |
| `AVIEW-007` | `decision_diff` | `fss-explain` | 900 | 1800 | `basisBefore`, `basisAfter`, `changedEvidence`, `invalidatedAssumptions`, `decisionImpact`, `whatWouldReverse` | why a conclusion, priority, hypothesis, plan, or preferred affordance changed |
| `AVIEW-008` | `epistemic_map` | `fss-knowledge` | 1500 | 3000 | `states`, `certifiedCore`, `certifiedAbsences`, `materialAlternatives`, `adversarialResiduals`, `coverage`, `contradictions`, `gaps`, `redactions`, `nextDiscriminators` | known/estimated/unknown/conflicted/stale/not-observable/redacted/indeterminate map plus certified core, material alternative worlds, adversarial residuals, and discriminators |

## 5. Resource URI Templates

Universal content-addressable and hierarchical URI templates under semantic protocol `fss/1`:

| ID | Resource Name | Owner | URI Template | Payload Schema | Compatibility |
|---|---|---|---|---|---|
| `ARES-001` | `deployment.anchor` | `fss-anchor` | `fss://deployment/{deployment}/anchor/{anchor}` | `fss.evidence_anchor.v1` | `backward_compatible` |
| `ARES-002` | `deployment.situation` | `fss-situation` | `fss://deployment/{deployment}/situation/{capsule}` | `fss.situation_capsule.v1` | `backward_compatible` |
| `ARES-003` | `deployment.sensor` | `fss-sensor` | `fss://deployment/{deployment}/sensor/{sensor}` | `fss.sensor_capsule.v1` | `backward_compatible` |
| `ARES-004` | `deployment.zone` | `fss-zone` | `fss://deployment/{deployment}/zone/{zone}` | `fss.agent_situation_frame.v1` | `backward_compatible` |
| `ARES-005` | `deployment.event_revision` | `fss-event` | `fss://deployment/{deployment}/event/{event}/revision/{revision}` | `fss.event_hypothesis.v1` | `backward_compatible` |
| `ARES-006` | `deployment.case_revision` | `fss-investigation` | `fss://deployment/{deployment}/case/{case}/revision/{revision}` | `fss.investigation_state.v1` | `backward_compatible` |
| `ARES-007` | `deployment.hypothesis` | `fss-investigation` | `fss://deployment/{deployment}/hypothesis/{hypothesis}` | `fss.agent_hypothesis_workspace.v1` | `backward_compatible` |
| `ARES-008` | `deployment.evidence` | `fss-evidence` | `fss://deployment/{deployment}/evidence/{digest}` | `fss.evidence_bundle.v1` | `backward_compatible` |
| `ARES-009` | `deployment.plan` | `fss-agent-plan` | `fss://deployment/{deployment}/plan/{plan}` | `fss.agent_control_plan.v1` | `backward_compatible` |
| `ARES-010` | `deployment.obligation` | `fss-obligation` | `fss://deployment/{deployment}/obligation/{obligation}` | `fss.prepared_effect.v1` | `backward_compatible` |
| `ARES-011` | `mission.revision` | `fss-mission` | `fss://mission/{mission}/revision/{revision}` | `fss.agent_mission.v1` | `backward_compatible` |
| `ARES-012` | `session.workspace` | `fss-agent-session` | `fss://session/{session}/workspace/{workspace}` | `fss.agent_session_capsule.v1` | `backward_compatible` |
| `ARES-013` | `session.handoff` | `fss-handoff` | `fss://session/{session}/handoff/{root}` | `fss.agent_handoff_capsule.v1` | `backward_compatible` |
| `ARES-014` | `experience` | `fss-learning` | `fss://experience/{capsule}` | `fss.experience_capsule.v1` | `backward_compatible` |
| `ARES-015` | `doctor` | `fss-doctor` | `fss://doctor/{bundle}` | `fss.doctor.v1` | `backward_compatible` |

## 6. Schemas Catalog

Core agent interchange and durable publication schemas:

| ID | Schema Identifier | File Path | Authority | Compatibility Rule |
|---|---|---|---|---|
| `SCHEMA-AGENT-COGNITIVE-ENVELOPE-001` | `fss.agent_cognitive_envelope.v1` | `schemas/agent_cognitive_envelope.v1.json` | `semantic response` | anchor, knowledge/provenance status, coverage, omissions, budget, evidence, affordances, and continuity remain explicit |
| `SCHEMA-AGENT-CONTRACT-BASIS-001` | `fss.agent_contract_basis.v1` | `schemas/agent_contract_basis.v1.json` | `semantic compatibility` | protocol, schema/ontology/operation/view/capability/error/cost registry digests, producer release, and accepted nightly remain exact |
| `SCHEMA-AGENT-PLAN-001` | `fss.agent_control_plan.v1` | `schemas/agent_control_plan.v1.json` | `control plan` | step types, witnesses, effect boundaries, contingencies, budgets, and decision digest remain immutable |
| `SCHEMA-AGENT-FEEDBACK-001` | `fss.agent_feedback_proposal.v1` | `schemas/agent_feedback_proposal.v1.json` | `advisory feedback` | correction or outcome signal is evidence-linked and cannot directly mutate active policy |
| `SCHEMA-AGENT-HANDOFF-001` | `fss.agent_handoff_capsule.v1` | `schemas/agent_handoff_capsule.v1.json` | `handoff custody` | mission, situation, cases, plans, obligations, unknowns, authority, budgets, continuation, and expiry remain complete |
| `SCHEMA-AGENT-HYPOTHESIS-001` | `fss.agent_hypothesis_workspace.v1` | `schemas/agent_hypothesis_workspace.v1.json` | `investigation cognition` | competing hypotheses and support, contradiction, missing evidence, predictions, and falsifiers remain addressable |
| `SCHEMA-AGENT-DELTA-001` | `fss.agent_meaningful_delta.v1` | `schemas/agent_meaningful_delta.v1.json` | `follow/continuity` | terminal, contradiction, coverage, plan-invalidation, and effect-uncertainty deltas cannot be coalesced away |
| `SCHEMA-AGENT-MISSION-001` | `fss.agent_mission.v1` | `schemas/agent_mission.v1.json` | `mission/workspace` | mission revisions preserve scope, constraints, budgets, capability projection, and terminal criteria |
| `SCHEMA-AGENT-OBJECTIVE-001` | `fss.agent_objective_contract.v1` | `schemas/agent_objective_contract.v1.json` | `control intent` | hard constraints, budgets, authority, success, failure, stop predicates, and terminal proof are immutable |
| `SCHEMA-AGENT-QUERY-001` | `fss.agent_query_plan.v1` | `schemas/agent_query_plan.v1.json` | `query cognition` | compiled interpretation, targets, authority, privacy, cost, and output view are reviewable and bounded |
| `SCHEMA-AGENT-REQUEST-001` | `fss.agent_request_envelope.v1` | `schemas/agent_request_envelope.v1.json` | `transport request` | contract basis, operation, lifecycle, anchor/workspace preconditions, view, targets, typed payload, budget, authority/privacy request, continuation, idempotency, and taint remain explicit |
| `SCHEMA-AGENT-RESPONSE-001` | `fss.agent_response_envelope.v1` | `schemas/agent_response_envelope.v1.json` | `transport response` | operation, session, anchors, outcome, payload, errors, budgets, proof, continuation, and safe retry remain explicit |
| `SCHEMA-AGENT-WORKSPACE-001` | `fss.agent_session_capsule.v1` | `schemas/agent_session_capsule.v1.json` | `workspace continuity` | workspace revisions are immutable and resume records stale and invalidated state |
| `SCHEMA-AGENT-SITUATION-001` | `fss.agent_situation_frame.v1` | `schemas/agent_situation_frame.v1.json` | `situation projection` | task-relative selection changes only through a new frame and selection witness |
| `SCHEMA-AGENT-WORLD-ENVELOPE-001` | `fss.agent_world_envelope.v1` | `schemas/agent_world_envelope.v1.json` | `agent world model` | nominal estimate, certified core and absences, material alternatives, adversarial residuals, unresolved dimensions, discriminators, and selection witness remain separate and anchor-pinned |
| `SCHEMA-DOCTOR-001` | `fss.doctor.v1` | `CLI output` | `diagnostics` | bounded and secret-free |
| `SCHEMA-EVENT-HYPOTHESIS-001` | `fss.event_hypothesis.v1` | `schemas/event_hypothesis.v1.json` | `authority` | immutable revisions; evidence required after hypothesis |
| `SCHEMA-EVIDENCE-ANCHOR-001` | `fss.evidence_anchor.v1` | `schemas/evidence_anchor.v1.json` | `authority` | no mixed generations; additions require new epoch semantics |
| `SCHEMA-EVIDENCE-BUNDLE-001` | `fss.evidence_bundle.v1` | `schemas/evidence_bundle.v1.json` | `authority/export` | old proof bundles remain replayable or explicitly unsupported |
| `SCHEMA-AGENT-EXPERIENCE-001` | `fss.experience_capsule.v1` | `schemas/experience_capsule.v1.json` | `operational memory` | episode signature, signals, failures, costs, applicability, decay, and privacy remain auditable |
| `SCHEMA-AGENT-INVESTIGATION-001` | `fss.investigation_state.v1` | `schemas/investigation_state.v1.json` | `investigation cognition` | case revisions preserve question, decision, hypotheses, probes, stop rules, and residual uncertainty |
| `SCHEMA-OPERATION-RECEIPT-001` | `fss.operation_receipt.v1` | `schemas/operation_receipt.v1.json` | `effect truth` | state monotonicity; idempotency identity preserved |
| `SCHEMA-PREPARED-EFFECT-001` | `fss.prepared_effect.v1` | `schemas/prepared_effect.v1.json` | `effect truth` | immutable prepared operation; intent, obligation, and predicate preserved |
| `SCHEMA-AGENT-COMPRESSION-001` | `fss.semantic_compression_receipt.v1` | `schemas/semantic_compression_receipt.v1.json` | `context projection` | selected and omitted classes, critical preservation, stop reason, and expansion slots remain explicit |
| `SCHEMA-SENSOR-CAPSULE-001` | `fss.sensor_capsule.v1` | `schemas/sensor_capsule.v1.json` | `authority` | append/supersede; no silent timestamp/source reinterpretation |
| `SCHEMA-AGENT-SITUATION-CAPSULE-001` | `fss.situation_capsule.v1` | `schemas/situation_capsule.v1.json` | `agent driver projection` | frame, meaningful delta, obligations, resources, affordances, context, and compression proof remain one anchor-pinned publication |

## 7. Required Capabilities Matrix

Capabilities required by registered operations across semantic planes:

| ID | Name | Semantic Plane | Description |
|---|---|---|---|
| `CAP-AGENT-CANCEL-001` | `cap_agent_cancel_001` | `lifecycle effect` | Declared agent operating capability |
| `CAP-AGENT-CASE-WRITE-001` | `cap_agent_case_write_001` | `agent cognition` | Declared agent operating capability |
| `CAP-AGENT-EXPLAIN-001` | `cap_agent_explain_001` | `cognition read` | Declared agent operating capability |
| `CAP-AGENT-FEEDBACK-001` | `cap_agent_feedback_001` | `advisory write` | Declared agent operating capability |
| `CAP-AGENT-HANDOFF-WRITE-001` | `cap_agent_handoff_write_001` | `agent continuity write` | Declared agent operating capability |
| `CAP-AGENT-PLAN-COMMIT-001` | `cap_agent_plan_commit_001` | `effect orchestration` | Declared agent operating capability |
| `CAP-AGENT-PLAN-PREPARE-001` | `cap_agent_plan_prepare_001` | `cognition/prepare` | Declared agent operating capability |
| `CAP-AGENT-QUERY-001` | `cap_agent_query_001` | `cognition read` | Declared agent operating capability |
| `CAP-AGENT-SESSION-OPEN-001` | `cap_agent_session_open_001` | `agent control` | Declared agent operating capability |
| `CAP-AGENT-SESSION-READ-001` | `cap_agent_session_read_001` | `agent control` | Declared agent operating capability |
| `CAP-AGENT-SITUATION-READ-001` | `cap_agent_situation_read_001` | `cognition read` | Declared agent operating capability |
| `CAP-REPAIR-PREPARE-001` | `cap_repair_prepare_001` | `authority read` | Declared agent operating capability |

## 8. Stable Error Taxonomy & Recovery Guidance

Key stable error identities and normative recovery guidance for agent drivers:

| Error Identity | Description | Recovery Guidance |
|---|---|---|
| `ERR-AGENT-AFFORDANCE-INVALIDATED-001` | recommended next move lost a precondition, capability, lease, or validity interval | refresh/replan; never execute cached recommendation |
| `ERR-AGENT-AMBIGUOUS-001` | natural-language request has multiple materially different interpretations | return interpretations; choose only a registered safe-read default or request clarification |
| `ERR-AGENT-CASE-BUDGET-001` | investigation cannot discriminate remaining hypotheses within declared budget | return residual uncertainty and explicit next probe/approval options |
| `ERR-AGENT-CONTEXT-INCOMPLETE-001` | requested decision-complete context cannot fit or lacks required evidence | return bounded partial with omissions/expansion handles; never imply completeness |
| `ERR-AGENT-HANDOFF-INVALID-001` | handoff root is incomplete, expired, unauthorized, schema/generation-incompatible, or cannot be safely rebased | reject, migrate, or open a new session with an explicit invalidation report; never silently resume |
| `ERR-AGENT-LEARNING-UNSUPPORTED-001` | learning proposal lacks evidence, applicability, counterexamples, or validation path | retain as rejected/advisory; do not activate |
| `ERR-AGENT-NO-AFFORDANCE-001` | no safe, authorized, useful next action exists under current evidence/budget | explain blocking clamps and return wait/escalate/stop reason |
| `ERR-AGENT-PROTOCOL-001` | presentation attempted an unregistered verb/view or changed semantic meaning | reject and repair registry/transport drift |
| `ERR-AGENT-RESNAPSHOT-001` | continuation cannot advance coherently from its exact basis | request a fresh situation capsule; do not splice generations |
| `ERR-AGENT-RESUME-INDETERMINATE-001` | external effects/obligations prevent a truthful resumed terminal state | resume in reconciliation mode; no effect retry before lookup/proof |
| `ERR-AGENT-SESSION-STALE-001` | session, workspace, or resumed handoff basis no longer satisfies required anchor/generation/freshness semantics | rebase and enumerate every invalidated assumption, alias, grant, lease, plan, continuation, and affordance before proceeding |
| `ERR-AGENT-WORK-CLAIM-CONFLICT-001` | requested multi-agent work scope overlaps an incompatible live claim, lease, or fence | narrow, wait, delegate, release, or supersede with explicit authority; never last-writer-wins |
| `ERR-AUTH-DENIED-001` | principal lacks exact capability | do not retry without new authority |
| `ERR-BUDGET-EXHAUSTED-001` | declared work budget exhausted | return bounded partial/abstention |
| `ERR-CLI-RUNTIME-FAILURE-001` | runtime error occurred during validated command execution | inspect diagnostic and address failure cause |
| `ERR-CLOCK-UNCERTAIN-001` | capture interval too wide for requested operation | degrade/abstain/recalibrate |
| `ERR-EFFECT-INDETERMINATE-001` | dispatch outcome cannot be determined | reconcile before retry |
| `ERR-EVIDENCE-MISSING-001` | canonical root references unavailable required evidence | repair; no adjudication requiring it |
| `ERR-IDEMPOTENCY-CONFLICT-001` | same key used with different request digest | reject permanently |
| `ERR-LEASE-STALE-001` | effect lease fence is not current | re-prepare under fresh lease |
| `ERR-OP-EXECUTION-FAILED-001` | operation execution failed with expected domain error | inspect error details and apply recovery guidance |
| `ERR-OP-TIMEOUT-001` | operation budget or deadline expired before completion | retry with higher budget or backoff |
| `ERR-PRECONDITION-STALE-001` | plan anchor changed before commit | re-plan; never auto-commit changed intent |
| `ERR-QUIESCENCE-001` | region/process failed to drain | block shutdown/upgrade claim; force isolation path |
| `ERR-REPLAY-DIVERGED-001` | semantic decision fingerprint differs from proof | block claim/release |
| `ERR-STREAM-CONTINUITY-001` | gaps/jitter exceed contract | degrade coverage; bounded recovery |

---
*Robot documentation generated deterministically by `scripts/generate_robot_docs.py`.*
