# Self-Describing Robot Documentation (`fss/1`)

> Deterministic, evidence-native semantic control plane for owner-authorized physical sensors.
> This document is mechanically derived from authoritative machine registries.

- **Schema**: `fss.robot_docs.v1`
- **Semantic Protocol**: `fss/1`
- **Registry Generation**: `gen:fss1:public-v1`
- **Freeze Digest**: `sha256:9bbec4e6845ea702f676cd22472e5fb0d35ca3b3d97f66cbfccb452182413da8`
- **As Of**: `2026-09-12`

## Table of Contents

1. [Discovery Endpoints](#1-discovery-endpoints)
2. [Core Protocol Error Taxonomy](#2-core-protocol-error-taxonomy)
3. [Canonical Operations Catalog](#3-canonical-operations-catalog)
4. [Registered Views Catalog](#4-registered-views-catalog)
5. [Resource URI Templates](#5-resource-uri-templates)
6. [Schemas Catalog](#6-schemas-catalog)
7. [Required Capabilities](#7-required-capabilities)
8. [Stable Error Taxonomy & Recovery Guidance](#8-stable-error-taxonomy--recovery-guidance)

---

## 1. Discovery Endpoints

Standard machine introspection entrypoints available on every conforming node:

| Endpoint | CLI Command | Description |
|---|---|---|
| `capabilities` | `fss capabilities --json` | Report capabilities in JSON format. |
| `doctor` | `fss doctor --json [--root &lt;dir&gt;]` | Report system diagnostic doctor results in JSON format. |
| `negative_evidence` | `fss negative-evidence list --json` | Negative evidence ledger management. |
| `status` | `fss status --json` | Report system status in JSON format. |

## 2. Core Protocol Error Taxonomy

Core protocol errors governing session negotiation, contract basis, and presentation:

| Error Identity | Meaning | Recovery Guidance |
|---|---|---|
| `ERR-AGENT-PROTOCOL-001` | presentation attempted an unregistered verb/view or changed semantic meaning | reject and repair registry/transport drift |
| `ERR-AGENT-SESSION-STALE-001` | session, workspace, or resumed handoff basis no longer satisfies required anchor/generation/freshness semantics | rebase and enumerate every invalidated assumption, alias, grant, lease, plan, continuation, and affordance before proceeding |
| `ERR-AGENT-CONTEXT-INCOMPLETE-001` | requested decision-complete context cannot fit or lacks required evidence | return bounded partial with omissions/expansion handles; never imply completeness |
| `ERR-AGENT-RESNAPSHOT-001` | continuation cannot advance coherently from its exact basis | request a fresh situation capsule; do not splice generations |
| `ERR-AGENT-AMBIGUOUS-001` | natural-language request has multiple materially different interpretations | return interpretations; choose only a registered safe-read default or request clarification |

## 3. Canonical Operations Catalog

The complete suite of 14 canonical agent control plane operations under `fss/1`:

| ID | Name | CLI Command | MCP Tool | Library Entry Point | Primary Error |
|---|---|---|---|---|---|
| `AOP-001` | `session.open` | `fss session open` | `session_open` | `fss_agent_session::session_open` | `ERR-AUTH-DENIED-001` |
| `AOP-002` | `session.resume` | `fss session resume` | `session_resume` | `fss_agent_session::session_resume` | `ERR-AGENT-HANDOFF-INVALID-001` |
| `AOP-003` | `session.orient` | `fss session orient` | `session_orient` | `fss_situation::session_orient` | `ERR-AGENT-CONTEXT-INCOMPLETE-001` |
| `AOP-004` | `session.follow` | `fss session follow` | `session_follow` | `fss_context_pack::session_follow` | `ERR-AGENT-RESNAPSHOT-001` |
| `AOP-005` | `query` | `fss query` | `query` | `fss_query_plan::query` | `ERR-AGENT-AMBIGUOUS-001` |
| `AOP-006` | `investigate` | `fss investigate` | `investigate` | `fss_investigation::investigate` | `ERR-AGENT-CASE-BUDGET-001` |
| `AOP-007` | `plan` | `fss plan` | `plan` | `fss_agent_plan::plan` | `ERR-PRECONDITION-STALE-001` |
| `AOP-008` | `commit` | `fss commit` | `commit` | `fss_effect::commit` | `ERR-EFFECT-INDETERMINATE-001` |
| `AOP-009` | `wait` | `fss wait` | `wait` | `fss_obligation::wait` | `ERR-OP-TIMEOUT-001` |
| `AOP-010` | `cancel` | `fss cancel` | `cancel` | `fss_obligation::cancel` | `ERR-QUIESCENCE-001` |
| `AOP-011` | `explain` | `fss explain` | `explain` | `fss_explain::explain` | `ERR-REPLAY-DIVERGED-001` |
| `AOP-012` | `handoff` | `fss handoff` | `handoff` | `fss_handoff::handoff` | `ERR-AGENT-HANDOFF-INVALID-001` |
| `AOP-013` | `feedback` | `fss feedback` | `feedback` | `fss_learning::feedback` | `ERR-AGENT-LEARNING-UNSUPPORTED-001` |
| `AOP-014` | `doctor` | `fss doctor` | `doctor` | `fss_doctor::doctor` | `ERR-CLI-RUNTIME-FAILURE-001` |

### Operation Details

#### `AOP-001`: session.open

- **Purpose**: negotiate principal, mission, authority, privacy projection, budgets, views, and the initial SituationCapsule
- **Execution Mode**: `session_control` | **Owner**: `fss-agent-session` | **Gate**: `QL-AGENT-001`
- **Effectful**: `False` | **Durable**: `True`
- **Default View**: `AVIEW-002`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_mission.v1`
- **Required Capabilities**: `CAP-AGENT-SESSION-OPEN-001`
- **Retry Classes**: `never_unchanged`, `backoff`, `operator_action_required`, `resume_from_continuation`
- **Primary Error**: `ERR-AUTH-DENIED-001`
- **Error Identities**: `ERR-AUTH-DENIED-001`, `ERR-AGENT-SESSION-STALE-001`, `ERR-BUDGET-EXHAUSTED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-002`: session.resume

- **Purpose**: restore an explicit workspace/handoff root, compare it with current state, and enumerate stale or invalidated assumptions
- **Execution Mode**: `session_control` | **Owner**: `fss-agent-session` | **Gate**: `QL-AGENT-001`
- **Effectful**: `False` | **Durable**: `True`
- **Default View**: `AVIEW-006`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_handoff_capsule.v1`
- **Required Capabilities**: `CAP-AGENT-SESSION-READ-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `rebase_required`, `operator_action_required`, `resume_from_continuation`
- **Primary Error**: `ERR-AGENT-HANDOFF-INVALID-001`
- **Error Identities**: `ERR-AGENT-HANDOFF-INVALID-001`, `ERR-AGENT-SESSION-STALE-001`, `ERR-AGENT-RESUME-INDETERMINATE-001`, `ERR-AUTH-DENIED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-003`: session.orient

- **Purpose**: return the smallest sufficient current SituationCapsule for the mission, authority, and budget
- **Execution Mode**: `read` | **Owner**: `fss-situation` | **Gate**: `QL-AGENT-001`
- **Effectful**: `False` | **Durable**: `False`
- **Default View**: `AVIEW-002`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_query_plan.v1`
- **Required Capabilities**: `CAP-AGENT-SITUATION-READ-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `rebase_required`, `backoff`, `resume_from_continuation`
- **Primary Error**: `ERR-AGENT-CONTEXT-INCOMPLETE-001`
- **Error Identities**: `ERR-AGENT-CONTEXT-INCOMPLETE-001`, `ERR-AGENT-SESSION-STALE-001`, `ERR-AUTH-DENIED-001`, `ERR-BUDGET-EXHAUSTED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-004`: session.follow

- **Purpose**: stream meaningful deltas and obligation progress from an exact continuation cursor
- **Execution Mode**: `read_wait` | **Owner**: `fss-context-pack` | **Gate**: `QL-AGENT-001`
- **Effectful**: `False` | **Durable**: `True`
- **Default View**: `AVIEW-001`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_query_plan.v1`
- **Required Capabilities**: `CAP-AGENT-SITUATION-READ-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `rebase_required`, `backoff`, `resume_from_continuation`
- **Primary Error**: `ERR-AGENT-RESNAPSHOT-001`
- **Error Identities**: `ERR-AGENT-RESNAPSHOT-001`, `ERR-AGENT-SESSION-STALE-001`, `ERR-AUTH-DENIED-001`, `ERR-STREAM-CONTINUITY-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-005`: query

- **Purpose**: execute a bounded typed or natural-language-compiled read over one anchor with completeness and cost receipts
- **Execution Mode**: `read_compile` | **Owner**: `fss-query-plan` | **Gate**: `QL-AGENT-001`
- **Effectful**: `False` | **Durable**: `False`
- **Default View**: `AVIEW-003`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_query_plan.v1`
- **Required Capabilities**: `CAP-AGENT-QUERY-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `rebase_required`, `backoff`, `resume_from_continuation`
- **Primary Error**: `ERR-AGENT-AMBIGUOUS-001`
- **Error Identities**: `ERR-AGENT-AMBIGUOUS-001`, `ERR-AGENT-CONTEXT-INCOMPLETE-001`, `ERR-AUTH-DENIED-001`, `ERR-BUDGET-EXHAUSTED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-006`: investigate

- **Purpose**: create or advance a durable case with competing hypotheses, evidence tasks, work claims, discriminators, and stop rules
- **Execution Mode**: `cognition_write` | **Owner**: `fss-investigation` | **Gate**: `QL-AGENT-001`
- **Effectful**: `False` | **Durable**: `True`
- **Default View**: `AVIEW-003`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.investigation_state.v1`
- **Required Capabilities**: `CAP-AGENT-CASE-WRITE-001`
- **Retry Classes**: `refresh_and_retry`, `rebase_required`, `backoff`, `reconciliation_required`, `operator_action_required`, `resume_from_continuation`
- **Primary Error**: `ERR-AGENT-CASE-BUDGET-001`
- **Error Identities**: `ERR-AGENT-CASE-BUDGET-001`, `ERR-AGENT-AMBIGUOUS-001`, `ERR-AUTH-DENIED-001`, `ERR-BUDGET-EXHAUSTED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-007`: plan

- **Purpose**: compile a desired outcome or information objective into an immutable witnessed contingent plan without crossing the effect boundary
- **Execution Mode**: `plan_prepare` | **Owner**: `fss-agent-plan` | **Gate**: `QL-AGENT-001`
- **Effectful**: `False` | **Durable**: `True`
- **Default View**: `AVIEW-007`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_objective_contract.v1`
- **Required Capabilities**: `CAP-AGENT-PLAN-PREPARE-001`
- **Retry Classes**: `refresh_and_retry`, `rebase_required`, `backoff`, `operator_action_required`, `resume_from_continuation`
- **Primary Error**: `ERR-PRECONDITION-STALE-001`
- **Error Identities**: `ERR-PRECONDITION-STALE-001`, `ERR-AGENT-NO-AFFORDANCE-001`, `ERR-AGENT-AFFORDANCE-INVALIDATED-001`, `ERR-AUTH-DENIED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-008`: commit

- **Purpose**: revalidate and start the exact prepared plan under idempotency, leases, fencing, approval, and terminal-proof obligations
- **Execution Mode**: `effect_commit` | **Owner**: `fss-effect` | **Gate**: `QL-AGENT-001`
- **Effectful**: `True` | **Durable**: `True`
- **Default View**: `AVIEW-005`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_control_plan.v1`
- **Required Capabilities**: `CAP-AGENT-PLAN-COMMIT-001`
- **Retry Classes**: `never_unchanged`, `backoff`, `reconciliation_required`, `operator_action_required`, `resume_from_continuation`
- **Primary Error**: `ERR-EFFECT-INDETERMINATE-001`
- **Error Identities**: `ERR-EFFECT-INDETERMINATE-001`, `ERR-IDEMPOTENCY-CONFLICT-001`, `ERR-LEASE-STALE-001`, `ERR-PRECONDITION-STALE-001`, `ERR-AUTH-DENIED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-009`: wait

- **Purpose**: observe cases, plans, effects, transfers, and obligations until a predicate, deadline, or meaningful delta fires
- **Execution Mode**: `read_wait` | **Owner**: `fss-obligation` | **Gate**: `QL-AGENT-001`
- **Effectful**: `False` | **Durable**: `True`
- **Default View**: `AVIEW-005`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_query_plan.v1`
- **Required Capabilities**: `CAP-AGENT-SITUATION-READ-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `backoff`, `reconciliation_required`, `resume_from_continuation`
- **Primary Error**: `ERR-OP-TIMEOUT-001`
- **Error Identities**: `ERR-OP-TIMEOUT-001`, `ERR-LEASE-STALE-001`, `ERR-AUTH-DENIED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-010`: cancel

- **Purpose**: request, drain, reconcile or compensate, and finalize owned work without erasing its durable record
- **Execution Mode**: `lifecycle_effect` | **Owner**: `fss-obligation` | **Gate**: `QL-AGENT-001`
- **Effectful**: `True` | **Durable**: `True`
- **Default View**: `AVIEW-005`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_query_plan.v1`
- **Required Capabilities**: `CAP-AGENT-CANCEL-001`
- **Retry Classes**: `never_unchanged`, `backoff`, `reconciliation_required`, `operator_action_required`, `resume_from_continuation`
- **Primary Error**: `ERR-QUIESCENCE-001`
- **Error Identities**: `ERR-QUIESCENCE-001`, `ERR-LEASE-STALE-001`, `ERR-EFFECT-INDETERMINATE-001`, `ERR-AUTH-DENIED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-011`: explain

- **Purpose**: answer why, why-not, what-changed, or what-if with a minimal evidence/decision subgraph and expansion handles
- **Execution Mode**: `read_compute` | **Owner**: `fss-explain` | **Gate**: `QL-AGENT-001`
- **Effectful**: `False` | **Durable**: `False`
- **Default View**: `AVIEW-007`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_query_plan.v1`
- **Required Capabilities**: `CAP-AGENT-EXPLAIN-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `rebase_required`, `resume_from_continuation`
- **Primary Error**: `ERR-REPLAY-DIVERGED-001`
- **Error Identities**: `ERR-REPLAY-DIVERGED-001`, `ERR-EVIDENCE-MISSING-001`, `ERR-AUTH-DENIED-001`, `ERR-BUDGET-EXHAUSTED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-012`: handoff

- **Purpose**: publish a root-last portable capsule containing mission, workspace, cases, plans, obligations, budgets, authority, uncertainty, and continuations
- **Execution Mode**: `continuity_publish` | **Owner**: `fss-handoff` | **Gate**: `QL-AGENT-001`
- **Effectful**: `False` | **Durable**: `True`
- **Default View**: `AVIEW-006`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_session_capsule.v1`
- **Required Capabilities**: `CAP-AGENT-HANDOFF-WRITE-001`
- **Retry Classes**: `refresh_and_retry`, `rebase_required`, `backoff`, `reconciliation_required`, `operator_action_required`, `resume_from_continuation`
- **Primary Error**: `ERR-AGENT-HANDOFF-INVALID-001`
- **Error Identities**: `ERR-AGENT-HANDOFF-INVALID-001`, `ERR-AGENT-SESSION-STALE-001`, `ERR-AUTH-DENIED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-013`: feedback

- **Purpose**: record a correction, outcome signal, adjudication, or evidence-linked learning proposal without silently changing active truth or policy
- **Execution Mode**: `advisory_write` | **Owner**: `fss-learning` | **Gate**: `QL-AGENT-001`
- **Effectful**: `False` | **Durable**: `True`
- **Default View**: `AVIEW-007`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_feedback_proposal.v1`
- **Required Capabilities**: `CAP-AGENT-FEEDBACK-001`
- **Retry Classes**: `refresh_and_retry`, `rebase_required`, `backoff`, `reconciliation_required`, `operator_action_required`
- **Primary Error**: `ERR-AGENT-LEARNING-UNSUPPORTED-001`
- **Error Identities**: `ERR-AGENT-LEARNING-UNSUPPORTED-001`, `ERR-AUTH-DENIED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`

#### `AOP-014`: doctor

- **Purpose**: diagnose deployment, evidence, cognition, workspace, cases, obligations, and protocol consistency and produce sealed repair affordances
- **Execution Mode**: `diagnostic_prepare` | **Owner**: `fss-doctor` | **Gate**: `QL-AGENT-001`
- **Effectful**: `False` | **Durable**: `True`
- **Default View**: `AVIEW-004`
- **Envelopes**: Request `fss.agent_request_envelope.v1` → Response `fss.agent_response_envelope.v1`
- **Payload Schema**: `fss.agent_query_plan.v1`
- **Required Capabilities**: `CAP-REPAIR-PREPARE-001`
- **Retry Classes**: `safe_read_retry`, `refresh_and_retry`, `backoff`, `resume_from_continuation`
- **Primary Error**: `ERR-CLI-RUNTIME-FAILURE-001`
- **Error Identities**: `ERR-CLI-RUNTIME-FAILURE-001`, `ERR-DOCTOR-ATTENTION-REQUIRED-001`, `ERR-DOCTOR-NOT-A-DEPLOYMENT-001`, `ERR-CLOCK-UNCERTAIN-001`, `ERR-STREAM-CONTINUITY-001`, `ERR-AUTH-DENIED-001`, `ERR-OP-EXECUTION-FAILED-001`
- **Exit Identities**: `EXIT-OK-000`, `EXIT-CLI-RUNTIME-FAILURE-001`, `EXIT-DOCTOR-ATTENTION-REQUIRED-003`, `EXIT-DOCTOR-NOT-A-DEPLOYMENT-004`

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

All authoritative schemas cataloged from `registries/SCHEMAS.md`:

| ID | Schema Identifier | File Path | Authority | Compatibility Rule |
|---|---|---|---|---|
| `SCHEMA-ADAPTER-CERT-001` | `fss.adapter_compatibility_certificate.v1` | `schemas/adapter_compatibility_certificate.v1.json` | `compatibility` | `exact tuple only; invalidator transitions revoke/degrade` |
| `SCHEMA-ADAPTER-IDENTITY-001` | `fss.adapter_identity.v1` | `schemas/adapter_identity.v1.json` | `adapter authority` | `adapter identity binds protocol profile, isolation mode, credentials, and capabilities` |
| `SCHEMA-AGENT-AFFORDANCE-001` | `fss.agent_affordance.v1` | `schemas/agent_affordance.v1.json` | `decision support` | `value, cost, risk, authority, reversibility, invalidators, alternatives, and expected proof remain decomposed` |
| `SCHEMA-AGENT-COGNITIVE-ENVELOPE-001` | `fss.agent_cognitive_envelope.v1` | `schemas/agent_cognitive_envelope.v1.json` | `semantic response` | `anchor, knowledge/provenance status, coverage, omissions, budget, evidence, affordances, and continuity remain explicit` |
| `SCHEMA-AGENT-CONTINUATION-CURSOR-001` | `fss.agent_continuation_cursor.v1` | `schemas/agent_continuation_cursor.v1.json` | `context/hydration projection` | `cursor is exact and root-verified; fenced lifetime and progress cannot be reinterpreted or replayed` |
| `SCHEMA-AGENT-CONTRACT-BASIS-001` | `fss.agent_contract_basis.v1` | `schemas/agent_contract_basis.v1.json` | `semantic compatibility` | `protocol, schema/ontology/operation/view/capability/error/cost registry digests, producer release, and accepted nightly remain exact` |
| `SCHEMA-AGENT-PLAN-001` | `fss.agent_control_plan.v1` | `schemas/agent_control_plan.v1.json` | `control plan` | `step types, witnesses, effect boundaries, contingencies, budgets, and decision digest remain immutable` |
| `SCHEMA-AGENT-EPISODE-001` | `fss.agent_execution_episode.v1` | `schemas/agent_execution_episode.v1.json` | `execution evidence` | `original predictions, receipts, outcome, resource use, residual uncertainty, and attribution remain auditable` |
| `SCHEMA-AGENT-FEEDBACK-001` | `fss.agent_feedback_proposal.v1` | `schemas/agent_feedback_proposal.v1.json` | `advisory feedback` | `correction or outcome signal is evidence-linked and cannot directly mutate active policy` |
| `SCHEMA-AGENT-FINDING-001` | `fss.agent_finding.v1` | `schemas/agent_finding.v1.json` | `multi-agent cognition` | `claim, epistemic state, evidence, assumptions, coverage, method receipts, and withdrawal state remain auditable` |
| `SCHEMA-AGENT-HANDOFF-001` | `fss.agent_handoff_capsule.v1` | `schemas/agent_handoff_capsule.v1.json` | `handoff custody` | `mission, situation, cases, plans, obligations, unknowns, authority, budgets, continuation, and expiry remain complete` |
| `SCHEMA-AGENT-HYPOTHESIS-001` | `fss.agent_hypothesis_workspace.v1` | `schemas/agent_hypothesis_workspace.v1.json` | `investigation cognition` | `competing hypotheses and support, contradiction, missing evidence, predictions, and falsifiers remain addressable` |
| `SCHEMA-AGENT-KNOWLEDGE-001` | `fss.agent_knowledge_cell.v1` | `schemas/agent_knowledge_cell.v1.json` | `epistemic projection` | `knowledge state, provenance, evidence, validity, uncertainty, and decision relevance remain separate` |
| `SCHEMA-AGENT-LEARNING-001` | `fss.agent_learning_proposal.v1` | `schemas/agent_learning_proposal.v1.json` | `advisory learning` | `applicability, evidence, counterexamples, harmful outcomes, validation, expiry, and promotion remain explicit` |
| `SCHEMA-AGENT-DELTA-001` | `fss.agent_meaningful_delta.v1` | `schemas/agent_meaningful_delta.v1.json` | `follow/continuity` | `terminal, contradiction, coverage, plan-invalidation, and effect-uncertainty deltas cannot be coalesced away; superseded by 'SCHEMA-AGENT-DELTA-002' ('fss.agent_meaningful_delta.v2'), which adds the required typed removal 'removedClaimIds'; v1 records stay immutable` |
| `SCHEMA-AGENT-DELTA-002` | `fss.agent_meaningful_delta.v2` | `schemas/agent_meaningful_delta.v2.json` | `follow/continuity` | `terminal, contradiction, coverage, plan-invalidation, and effect-uncertainty deltas cannot be coalesced away; a basis cell absent from the result is a typed removal ('removedClaimIds'), never a changed cell carrying its basis value; supersedes 'SCHEMA-AGENT-DELTA-001'` |
| `SCHEMA-AGENT-MISSION-001` | `fss.agent_mission.v1` | `schemas/agent_mission.v1.json` | `mission/workspace` | `mission revisions preserve scope, constraints, budgets, capability projection, and terminal criteria` |
| `SCHEMA-AGENT-OBJECTIVE-001` | `fss.agent_objective_contract.v1` | `schemas/agent_objective_contract.v1.json` | `control intent` | `hard constraints, budgets, authority, success, failure, stop predicates, and terminal proof are immutable` |
| `SCHEMA-AGENT-OPERATIONS-001` | `fss.agent_operations.v1` | `schemas/agent_operations.v1.json` | `agent operations` | `operation rows stay aligned with the frozen public registry, the markdown mirror, and the typed Rust table; effect authority is mode-typed and row statuses only move with a registry generation bump` |
| `SCHEMA-AGENT-QUERY-001` | `fss.agent_query_plan.v1` | `schemas/agent_query_plan.v1.json` | `query cognition` | `compiled interpretation, targets, authority, privacy, cost, and output view are reviewable and bounded` |
| `SCHEMA-AGENT-REQUEST-001` | `fss.agent_request_envelope.v1` | `schemas/agent_request_envelope.v1.json` | `transport request` | `contract basis, operation, lifecycle, anchor/workspace preconditions, view, targets, typed payload, budget, authority/privacy request, continuation, idempotency, and taint remain explicit` |
| `SCHEMA-AGENT-RESPONSE-001` | `fss.agent_response_envelope.v1` | `schemas/agent_response_envelope.v1.json` | `transport response` | `operation, session, anchors, outcome, payload, errors, budgets, proof, continuation, and safe retry remain explicit` |
| `SCHEMA-AGENT-SESSION-001` | `fss.agent_session.v1` | `schemas/agent_session.v1.json` | `session/runtime` | `session identity, authority, privacy projection, view, continuations, and expiry remain explicit` |
| `SCHEMA-AGENT-WORKSPACE-001` | `fss.agent_session_capsule.v1` | `schemas/agent_session_capsule.v1.json` | `workspace continuity` | `workspace revisions are immutable and resume records stale and invalidated state` |
| `SCHEMA-AGENT-SITUATION-001` | `fss.agent_situation_frame.v1` | `schemas/agent_situation_frame.v1.json` | `situation projection` | `task-relative selection changes only through a new frame and selection witness` |
| `SCHEMA-AGENT-VIEWS-001` | `fss.agent_views.v1` | `schemas/agent_views.v1.json` | `agent views` | `view rows stay aligned with the markdown mirror and the typed Rust table; token bounds are decision-bearing budget discipline (target &lt;= maximum) and statuses only move with a registry generation bump` |
| `SCHEMA-AGENT-WORK-CLAIM-001` | `fss.agent_work_claim.v1` | `schemas/agent_work_claim.v1.json` | `multi-agent coordination` | `scope, basis, owner, lease, progress, result, expiry, and no-effect-authority property remain explicit` |
| `SCHEMA-AGENT-WORLD-ENVELOPE-001` | `fss.agent_world_envelope.v1` | `schemas/agent_world_envelope.v1.json` | `agent world model` | `nominal estimate, certified core and absences, material alternatives, adversarial residuals, unresolved dimensions, discriminators, and selection witness remain separate and anchor-pinned` |
| `SCHEMA-CALIBRATION-CERT-001` | `fss.calibration_certificate.v1` | `schemas/calibration_certificate.v1.json` | `authority` | `generation immutable; invalidation creates new state` |
| `SCHEMA-CANCEL-DRAIN-001` | `fss.cancellation_drain_certificate.v1` | `schemas/cancellation_drain_certificate.v1.json` | `runtime evidence` | `terminal/indeterminate outcome and outstanding effects preserved` |
| `SCHEMA-CAPABILITIES-001` | `fss.capabilities.v1` | `CLI output` | `product boundary` | `additions compatible; changed meaning requires new schema` |
| `SCHEMA-CLI-DIAGNOSTIC-001` | `fss.cli_diagnostic.v1` | `schemas/cli_diagnostic.v1.json` | `authority/diagnostic` | `diagnostic schema immutable; errors follow structured envelope` |
| `SCHEMA-AGENT-CONTEXT-BINDING-001` | `fss.context_expansion_binding.v1` | `schemas/context_expansion_binding.v1.json` | `context/hydration projection` | `one emitted expansion slot maps to one exact descriptor revision, purpose, level, and descriptor-owned full cost` |
| `SCHEMA-AGENT-CONTEXT-BINDING-SET-001` | `fss.context_expansion_binding_set.v1` | `schemas/context_expansion_binding_set.v1.json` | `context/hydration projection` | `every emitted expansion slot is bound exactly once; missing, duplicate, unexpected, stale, or ambient descriptors fail closed` |
| `SCHEMA-COVERAGE-WITNESS-001` | `fss.coverage_witness.v1` | `schemas/coverage_witness.v1.json` | `authority/query` | `absence claims require declared domain and stop reason` |
| `SCHEMA-DECISION-CARD-001` | `fss.decision_card.v1` | `schemas/decision_card.v1.json` | `policy/evidence` | `hard constraints and alternatives retained; no silent rewrite` |
| `SCHEMA-DEVICE-IDENTITY-001` | `fss.device_identity.v1` | `schemas/device_identity.v1.json` | `device authority` | `immutable hardware, firmware, and model generation; generation change produces a new identity` |
| `SCHEMA-DOCTOR-001` | `fss.doctor.v1` | `CLI output` | `diagnostics` | `bounded and secret-free` |
| `SCHEMA-EFFECT-INTENT-001` | `fss.effect_intent.v1` | `schemas/effect_intent.v1.json` | `effect truth` | `immutable intent; operation and idempotency identities preserved` |
| `SCHEMA-EFFECT-RECONCILIATION-001` | `fss.effect_reconciliation.v1` | `schemas/effect_reconciliation.v1.json` | `effect truth` | `four-valued outcome; verified requires independent evidence witness` |
| `SCHEMA-EVENT-HYPOTHESIS-001` | `fss.event_hypothesis.v1` | `schemas/event_hypothesis.v1.json` | `authority` | `immutable revisions; evidence required after hypothesis; enum widening for relation additions (sensor_tamper, sensor_integrity_restoration)` |
| `SCHEMA-EVIDENCE-ANCHOR-001` | `fss.evidence_anchor.v1` | `schemas/evidence_anchor.v1.json` | `authority` | `no mixed generations; additions require new epoch semantics` |
| `SCHEMA-EVIDENCE-BUNDLE-001` | `fss.evidence_bundle.v1` | `schemas/evidence_bundle.v1.json` | `authority/export` | `old proof bundles remain replayable or explicitly unsupported` |
| `SCHEMA-EVIDENCE-DELTA-001` | `fss.evidence_delta_batch.v1` | `schemas/evidence_delta_batch.v1.json` | `authority/version universe` | `basis/new anchors and ordered delta identities preserved` |
| `SCHEMA-EVIDENCE-GRAPH-001` | `fss.evidence_graph.v1` | `schemas/evidence_graph.v1.json` | `derived/evidence` | `causal evidence graph over capsules, identities, model receipts, and revisions; enum widening for relation additions (sensor_tamper, sensor_integrity_restoration)` |
| `SCHEMA-AGENT-EXPERIENCE-001` | `fss.experience_capsule.v1` | `schemas/experience_capsule.v1.json` | `operational memory` | `episode signature, signals, failures, costs, applicability, decay, and privacy remain auditable` |
| `SCHEMA-GRAPH-WITNESS-001` | `fss.graph_algorithm_witness.v1` | `schemas/graph_algorithm_witness.v1.json` | `derived/evidence` | `algorithm/projection/policy identity and output digest preserved` |
| `SCHEMA-AGENT-INVESTIGATION-001` | `fss.investigation_state.v1` | `schemas/investigation_state.v1.json` | `investigation cognition` | `case revisions preserve question, decision, hypotheses, probes, stop rules, and residual uncertainty` |
| `SCHEMA-JPEG-FIXTURE-MANIFEST-001` | `fss.jpeg_fixture_manifest.v1` | `schemas/jpeg_fixture_manifest.v1.json` | `test evidence` | `baseline JPEG fixture suite manifest recording dimensions, subsampling, quality, file sha256, source pixel sha256, and float IDCT reconstruction metrics` |
| `SCHEMA-LICENSE-INVENTORY-001` | `fss.license_inventory.v1` | `schemas/license_inventory.v1.json` | `supply-chain evidence` | `package identity/source/license fields remain auditable` |
| `SCHEMA-MJPEG-FIXTURE-MANIFEST-001` | `fss.mjpeg_fixture_manifest.v1` | `schemas/mjpeg_fixture_manifest.v1.json` | `test evidence` | `MJPEG stream fixture suite manifest recording variant, frame count, file sha256, and per-frame source fixture bindings` |
| `SCHEMA-MODEL-RECEIPT-001` | `fss.model_execution_receipt.v1` | `schemas/model_execution_receipt.v1.json` | `derived/model evidence` | `input/model/plan/backend/numeric/budget/outcome and output identities preserved` |
| `SCHEMA-MODEL-MANIFEST-001` | `fss.model_manifest.v1` | `schemas/model_manifest.v1.json` | `model authority/package` | `immutable model manifest root; model identity, generation, weights, schemas, calibration, and license/provenance preserved` |
| `SCHEMA-MODEL-PACKAGE-001` | `fss.model_package_manifest.v1` | `schemas/model_package_manifest.v1.json` | `model authority/package` | `immutable package root; operator/tensor/preprocess/numeric/license identities preserved` |
| `SCHEMA-NEGATIVE-EVIDENCE-REPORT-001` | `fss.negative_evidence_report.v1` | `schemas/negative_evidence_report.v1.json` | `cli report` | `ledger entries, verification result, epistemic state derived from entry knowledge states, and degradation stay explicit; not an agent response envelope` |
| `SCHEMA-OPERATION-RECEIPT-001` | `fss.operation_receipt.v1` | `schemas/operation_receipt.v1.json` | `effect truth` | `state monotonicity; idempotency identity preserved` |
| `SCHEMA-PREPARED-EFFECT-001` | `fss.prepared_effect.v1` | `schemas/prepared_effect.v1.json` | `effect truth` | `immutable prepared operation; intent, obligation, and predicate preserved` |
| `SCHEMA-PROVIDER-FAILURE-RECEIPT-001` | `fss.provider_failure_receipt.v1` | `schemas/provider_failure_receipt.v1.json` | `provider authority` | `provider-issued failure receipt; nonce and error reason preserved` |
| `SCHEMA-PROVIDER-OBSERVATION-RECEIPT-001` | `fss.provider_observation_receipt.v1` | `schemas/provider_observation_receipt.v1.json` | `provider authority` | `provider-issued observation receipt; verified by lookup, never recomputable` |
| `SCHEMA-QUALIFICATION-ROOT-002` | `fss.qualification_root.v2` | `schemas/release_qualification_root.v2.json` | `aggregate release custody` | `primary/support artifact digests, claim boundary, and signing state immutable` |
| `SCHEMA-RELEASE-BUILD-001` | `fss.release_build_receipt.v1` | `schemas/release_build_receipt.v1.json` | `release custody` | `native target/toolchain/source/lock/manifest/smoke identities immutable` |
| `SCHEMA-RELEASE-RECEIPT-001` | `fss.release_qualification_receipt.v1` | `schemas/release_qualification_receipt.v1.json` | `release custody` | `same source/sibling/toolchain identity required for aggregation` |
| `SCHEMA-RELEASE-STAGE-001` | `fss.release_stage_verification.v1` | `schemas/release_stage_verification.v1.json` | `release custody` | `stage inventory and content digests preserved exactly` |
| `SCHEMA-ROBOT-DOCS-001` | `fss.robot_docs.v1` | `schemas/robot_docs.v1.json` | `documentation/metadata` | `immutable; additions compatible` |
| `SCHEMA-AGENT-COMPRESSION-001` | `fss.semantic_compression_receipt.v1` | `schemas/semantic_compression_receipt.v1.json` | `context projection` | `selected and omitted classes, critical preservation, stop reason, and expansion slots remain explicit` |
| `SCHEMA-AGENT-CONTEXT-001` | `fss.semantic_context_pack.v1` | `schemas/semantic_context_pack.v1.json` | `context projection` | `pack basis, view, items, compression receipt, token count, continuation, digest, and expansion slots are immutable` |
| `SCHEMA-AGENT-HANDLE-001` | `fss.semantic_handle.v1` | `schemas/semantic_handle.v1.json` | `context/hydration projection` | `handle identity is immutable across descriptor revisions; H-level ladder stays contiguous and priced` |
| `SCHEMA-AGENT-HANDLE-REFERENCE-001` | `fss.semantic_handle_reference.v1` | `schemas/semantic_handle_reference.v1.json` | `context/hydration projection` | `immutable subject, exact descriptor revision, contract basis, authority anchor, level, and ladder policy remain inseparable` |
| `SCHEMA-AGENT-HYDRATION-ARTIFACT-001` | `fss.semantic_hydration_artifact.v1` | `schemas/semantic_hydration_artifact.v1.json` | `context/hydration projection` | `payload digest, descriptor digest, and subject digest remain verifiable; tampered payloads are rejected` |
| `SCHEMA-AGENT-HYDRATION-RECEIPT-001` | `fss.semantic_hydration_receipt.v1` | `schemas/semantic_hydration_receipt.v1.json` | `context/hydration projection` | `receipt binds request digest, artifact digest, consumed cost, and exact continuation; no receipt without a delivered artifact` |
| `SCHEMA-AGENT-HYDRATION-REQUEST-001` | `fss.semantic_hydration_request.v1` | `schemas/semantic_hydration_request.v1.json` | `context/hydration projection` | `request binds exact handle reference, level, budget, and contract basis; unknown levels fail closed` |
| `SCHEMA-SENSOR-CAPSULE-001` | `fss.sensor_capsule.v1` | `schemas/sensor_capsule.v1.json` | `authority` | `append/supersede; no silent timestamp/source reinterpretation` |
| `SCHEMA-SENSOR-TAMPER-STATUS-001` | `fss.sensor_tamper_status.v1` | `schemas/sensor_tamper_status.v1.json` | `authority` | `lineage sensor-tamper status published with each event revision; the 'sensor_tamper_status' witness is the canonical digest of every field; an open tamper is carried forward until an evidenced restoration captured strictly after it retires it; changed meaning requires a new schema` |
| `SCHEMA-AGENT-SITUATION-CAPSULE-001` | `fss.situation_capsule.v1` | `schemas/situation_capsule.v1.json` | `agent driver projection` | `frame, meaningful delta, obligations, resources, affordances, context, and compression proof remain one anchor-pinned publication` |
| `SCHEMA-SOURCE-IDENTITY-001` | `fss.source_identity.v1` | `schemas/source_identity.v1.json` | `source custody` | `source identity binds device, adapter, channel, clock basis, and stream generation; unknown versions fail closed` |
| `SCHEMA-SOURCE-MANIFEST-001` | `fss.source_manifest.v1` | `schemas/source_manifest.v1.json` | `source custody` | `clean tracked source identity and executable bits preserved` |
| `SCHEMA-STATUS-001` | `fss.status.v1` | `CLI output` | `product boundary` | `status fields cannot imply unsupported readiness` |
| `SCHEMA-TRANSFER-MANIFEST-001` | `fss.transfer_manifest.v1` | `schemas/transfer_manifest.v1.json` | `authority/transfer` | `root-last; object and closure identities immutable` |
| `SCHEMA-TRANSFER-RECEIPT-001` | `fss.transfer_receipt.v1` | `schemas/transfer_receipt.v1.json` | `transfer evidence` | `path, repair, closure, publication, and retrievability states remain distinct` |

## 7. Required Capabilities

Capabilities required by canonical operations cataloged from `architecture/capabilities.json`:

| ID | Capability | Scope | Semantic Plane | Default Role |
|---|---|---|---|---|
| `CAP-AGENT-CANCEL-001` | request cancellation/drain/reconciliation of owned work | `session/task/plan/obligation` | `lifecycle effect` | owner or delegated supervisor |
| `CAP-AGENT-CASE-WRITE-001` | create/revise investigations, hypotheses, probes, and findings | `mission/case scope` | `agent cognition` | explicit mission role |
| `CAP-AGENT-EXPLAIN-001` | read minimal evidence/decision subgraphs and counterfactuals | `authorized decision/evidence domain` | `cognition read` | agent read role |
| `CAP-AGENT-FEEDBACK-001` | append correction, adjudication, outcome, or learning proposal | `episode/event/case` | `advisory write` | scoped agent/operator role |
| `CAP-AGENT-HANDOFF-WRITE-001` | publish a redacted root-last handoff capsule | `mission/workspace + recipient scope` | `agent continuity write` | explicit delegation |
| `CAP-AGENT-PLAN-COMMIT-001` | submit an exact prepared plan to domain effect authorities | `plan digest + fences` | `effect orchestration` | denied unless explicit; never substitutes for domain effect capabilities |
| `CAP-AGENT-PLAN-PREPARE-001` | compile and seal a witnessed contingent plan | `mission + objective + target domain` | `cognition/prepare` | explicit planner role |
| `CAP-AGENT-QUERY-001` | compile and execute bounded semantic queries | `authorized resources + anchor` | `cognition read` | agent read role |
| `CAP-AGENT-SESSION-OPEN-001` | open a mission-scoped agent session | `deployment + mission + principal` | `agent control` | denied unless negotiated |
| `CAP-AGENT-SESSION-READ-001` | read/resume exact workspace or handoff revisions | `mission/session/workspace root` | `agent control` | session principal |
| `CAP-AGENT-SITUATION-READ-001` | read capability-projected SituationFrames, deltas, and obligations | `deployment/mission/zone/time` | `cognition read` | agent read role |
| `CAP-REPAIR-PREPARE-001` | generate sealed repair plan | `subsystem/object scope` | `authority read` | operator |

## 8. Stable Error Taxonomy & Recovery Guidance

All stable error identities and normative recovery guidance cataloged from `registries/ERRORS.md`:

| ID | Meaning | Retry policy |
|---|---|---|
| `ERR-ADAPTER-CORRUPT-FILE-001` | device adapter registry file is corrupt or missing mandatory fields | repair or restore device adapter registry file |
| `ERR-ADAPTER-DIGEST-MISMATCH-001` | device adapter canonical freeze digest does not match pinned generation digest | recompute canonical device adapter registry digest or bump generation |
| `ERR-ADAPTER-GENERATION-MISMATCH-001` | adapter generation does not match current system generation | fail closed; assign expected generation to device adapter registry |
| `ERR-ADAPTER-INVALID-TIER-001` | adapter tier is invalid or violates promotion rules | fail closed; reject unsupported tier |
| `ERR-ADAPTER-PROTOCOL-001` | adapter response violates typed protocol | terminate adapter generation; retain fixture |
| `ERR-ADAPTER-REGISTRY-DRIFT-001` | adapter registry row drift between machine registry and markdown | synchronize architecture/device_adapters.json and registries/DEVICE_ADAPTERS.md |
| `ERR-ADAPTER-REPLAY-DIVERGED-001` | deterministic replay adapter produced state root or audit hash diverging from reference proof | fail closed; reject diverged replay output and quarantine bundle |
| `ERR-ADAPTER-SEMANTIC-INVARIANT-001` | adapter row violates semantic invariants (tier, state, gate) | fail closed; enforce normative row definitions |
| `ERR-ADAPTER-STABLE-ID-REUSED-001` | adapter stable identifier was reused, renumbered, or resurrected | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-AGENT-AFFORDANCE-INVALIDATED-001` | recommended next move lost a precondition, capability, lease, or validity interval | refresh/replan; never execute cached recommendation |
| `ERR-AGENT-AMBIGUOUS-001` | natural-language request has multiple materially different interpretations | return interpretations; choose only a registered safe-read default or request clarification |
| `ERR-AGENT-BASIS-ALGORITHM-001` | ContractBasis registry digest specifies unsupported algorithm (Blake3 prohibited; Sha256 required) | compute registry digest with canonical SHA-256 algorithm |
| `ERR-AGENT-BASIS-BAD-MAGIC-001` | ContractBasis binary envelope magic header does not match CONTRACT_BASIS_MAGIC | verify binary envelope format or use canonical encoder |
| `ERR-AGENT-BASIS-CHECKSUM-MISMATCH-001` | ContractBasis binary envelope trailing checksum verification failed | recompute checksum or retransmit uncorrupted envelope |
| `ERR-AGENT-BASIS-INVALID-ID-001` | ContractBasis identifier field failed pattern, length, or character set validation | provide identifier matching ^[A-Za-z0-9][A-Za-z0-9:._+/-]*$ within length limit |
| `ERR-AGENT-BASIS-OVERSIZED-001` | ContractBasis binary payload or envelope exceeds maximum permitted byte limit | reduce payload size within configured bound or check framing |
| `ERR-AGENT-BASIS-TRAILING-BYTES-001` | ContractBasis binary envelope contains unexpected trailing bytes after declared payload | strip extraneous trailing bytes and ensure canonical framing |
| `ERR-AGENT-BASIS-TRUNCATED-001` | ContractBasis binary envelope ended prematurely before declared length or minimum envelope size | retransmit complete binary envelope without truncation |
| `ERR-AGENT-BASIS-VERSION-001` | ContractBasis binary envelope format version is unsupported | upgrade client or server to matching format version |
| `ERR-AGENT-CASE-BUDGET-001` | investigation cannot discriminate remaining hypotheses within declared budget | return residual uncertainty and explicit next probe/approval options |
| `ERR-AGENT-CONTEXT-INCOMPLETE-001` | requested decision-complete context cannot fit or lacks required evidence | return bounded partial with omissions/expansion handles; never imply completeness |
| `ERR-AGENT-EVENT-NOT-FOUND-001` | explain named an event identity that no committed 'event_revision' delta publishes at the evaluated anchor | orient to list published events; retry only after the ledger head advances |
| `ERR-AGENT-FOLLOW-ANCHOR-AHEAD-001` | follow named an anchor token past the deployment's committed ledger head or effect-journal records | orient again and follow from the current anchor token; never follow from a position the history has not committed |
| `ERR-AGENT-FOLLOW-ANCHOR-FOREIGN-001` | follow named an anchor token whose site lineage is another deployment's | orient this deployment and follow from the anchor token it emits |
| `ERR-AGENT-FOLLOW-ANCHOR-UNKNOWN-001` | follow named an anchor token whose binding does not match the deployment's committed history at its position (altered token or divergent history) | orient again and follow from the anchor token it emits; never rebase silently onto another history |
| `ERR-AGENT-FOLLOW-CONTINUATION-001` | follow continuation is not a cursor of the exact stream (altered, issued for another anchor, view, or page size, or issued before the head advanced) | follow again without the continuation to receive the first page of the current delta |
| `ERR-AGENT-HANDOFF-INVALID-001` | handoff root is incomplete, expired, unauthorized, schema/generation-incompatible, or cannot be safely rebased | reject, migrate, or open a new session with an explicit invalidation report; never silently resume |
| `ERR-AGENT-HANDOFF-NOT-FOUND-001` | session resume named a handoff identity that no root in the deployment's agent publications holds (never published, or its publication was interrupted before the root became visible) | resume only a handoff identity 'fss handoff' returned for this deployment, or hand off again |
| `ERR-AGENT-HIDDEN-STATE-001` | required mission state exists only in conversation or caller memory | persist typed mission/workspace/case/plan/finding/handoff state before proceeding |
| `ERR-AGENT-LEARNING-UNSUPPORTED-001` | learning proposal lacks evidence, applicability, counterexamples, or validation path | retain as rejected/advisory; do not activate |
| `ERR-AGENT-NO-AFFORDANCE-001` | no safe, authorized, useful next action exists under current evidence/budget | explain blocking clamps and return wait/escalate/stop reason |
| `ERR-AGENT-PROTOCOL-001` | presentation attempted an unregistered verb/view or changed semantic meaning | reject and repair registry/transport drift |
| `ERR-AGENT-RESNAPSHOT-001` | continuation cannot advance coherently from its exact basis | request a fresh situation capsule; do not splice generations |
| `ERR-AGENT-RESUME-INDETERMINATE-001` | external effects/obligations prevent a truthful resumed terminal state | resume in reconciliation mode; no effect retry before lookup/proof |
| `ERR-AGENT-SESSION-NOT-FOUND-001` | session handoff named a session that is unknown, closed, expired, or held by another principal in the deployment's agent-session journal (deliberately indistinguishable) | open a session with 'fss session open' or resume a published handoff; never guess another principal's session |
| `ERR-AGENT-SESSION-STALE-001` | session, workspace, or resumed handoff basis no longer satisfies required anchor/generation/freshness semantics | rebase and enumerate every invalidated assumption, alias, grant, lease, plan, continuation, and affordance before proceeding |
| `ERR-AGENT-SESSION-STORE-INVALID-001` | the deployment's agent-session store failed verification (journal rollback or foreign journal against its pinned root, an incomplete append, an orphaned publication temporary, or a missing mission record) | inspect 'agent/' under the deployment root; the store is never repaired, truncated, or re-pinned implicitly |
| `ERR-AGENT-SESSION-STORE-LOCKED-001` | another session command holds the deployment's agent-session store lock | retry after the other command finishes; the store is never shared by two writers |
| `ERR-AGENT-TRANSPORT-DIVERGED-001` | CLI/MCP/TUI/report semantic payload or digest differs for equivalent input | block affected surface/release and retain differential transcript |
| `ERR-AGENT-WORK-CLAIM-CONFLICT-001` | requested multi-agent work scope overlaps an incompatible live claim, lease, or fence | narrow, wait, delegate, release, or supersede with explicit authority; never last-writer-wins |
| `ERR-AGT-CORRUPT-FILE-001` | agent abstraction registry or markdown documentation file is missing or corrupt | repair or restore agent abstraction registry file |
| `ERR-AGT-DIGEST-MISMATCH-001` | agent abstraction registry digest does not match canonical encoding of metadata and rows | recompute canonical agent abstraction registry digest |
| `ERR-AGT-FREEZE-DIVERGENCE-001` | agent abstraction registry digest diverged from pinned baseline freeze digest | restore frozen agent abstraction registry or bump generation |
| `ERR-AGT-GENERATION-MISMATCH-001` | agent abstraction registry generation diverged from baseline generation | assign expected generation to agent abstraction registry |
| `ERR-AGT-ILLEGAL-AUTHORITY-001` | derived beliefs or non-authority abstraction layer illegally claims authority or authorizes effects | preserve cognition plane boundary; derived layers cannot claim authority or authorize effects |
| `ERR-AGT-INVARIANT-VIOLATION-001` | agent abstraction layer invariant or prohibition violated | enforce layer semantic invariants and constitutional prohibitions |
| `ERR-AGT-MISSING-FIELD-001` | agent abstraction layer row or root metadata lacks a mandatory field or is empty/corrupt | declare all mandatory fields in agent abstraction layer row |
| `ERR-AGT-REGISTRY-DRIFT-001` | agent abstraction registry row drift between machine registry and markdown mirror | synchronize architecture/agent_abstraction_stack.json and registries/AGENT_ABSTRACTIONS.md |
| `ERR-AGT-STABLE-ID-REUSED-001` | agent abstraction layer stable identifier was reused, duplicated, renumbered, or tombstoned | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-ALERT-APPROVAL-STALE-001` | an alert plan or dispatch approval digest does not match the current plan, route, principal, prepared record or deadline; nothing was prepared or sent | rerun without the stale approval and review the reported digests |
| `ERR-ALERT-AUTHORITY-001` | the event is absent, or its current authority, prepared plan or receipt cannot be read and verified against the ledger | inspect or repair the deployment; never dispatch from unverified authority |
| `ERR-ALERT-CLOCK-001` | the admission clock is unavailable or behind the effect journal's last transition | repair the host clock; nothing was committed |
| `ERR-ALERT-DISPATCH-001` | the durable effect journal or live webhook authority refused before any network I/O, or the observation could not be recorded | inspect the journal; a committed operation is never resent automatically |
| `ERR-ALERT-NOT-ELIGIBLE-001` | policy, corroboration or sensor-integrity gates refuse an alert for this event (not corroborated, held, or open tamper) | do not retry; obtain independent corroboration or resolve the integrity risk |
| `ERR-ALERT-ROUTE-INVALID-001` | alert relay route is not admissible (exact IP:PORT, plain absolute path, nonzero plaintext-route approval) | supply an admissible explicit route; no DNS, redirect or TLS downgrade is attempted |
| `ERR-ARCHIVE-UNREACHABLE-001` | remote archive unavailable | local spool obligation; bounded retry |
| `ERR-ARCHIVE-VERIFY-001` | published object failed retrieval/integrity check | quarantine/repair/escalate |
| `ERR-ARITHMETIC-OVERFLOW-001` | arithmetic overflow in timestamp or uncertainty calculation | bound timestamp values within addressable range |
| `ERR-AUTH-DENIED-001` | principal lacks exact capability | do not retry without new authority |
| `ERR-BUDGET-EXHAUSTED-001` | declared work budget exhausted | return bounded partial/abstention |
| `ERR-CALIBRATION-INVALID-001` | certificate expired/invalidated/residual failure | no geometry-dependent negative evidence |
| `ERR-CANONICAL-TRUNCATED-001` | canonical bytes declare more collection elements than the bytes that remain (truncated buffer) | re-fetch the complete canonical bytes; do not retry unchanged |
| `ERR-CAPABILITY-CORRUPT-FILE-001` | capability registry or markdown documentation file is missing or corrupt | repair or restore capability registry file |
| `ERR-CAPABILITY-DIGEST-MISMATCH-001` | capability registry digest does not match canonical encoding of sorted rows | recompute canonical capability registry digest |
| `ERR-CAPABILITY-MISSING-DEFAULT-001` | capability row lacks a default role or default grant policy | declare an explicit default role or default denial in the capability row |
| `ERR-CAPABILITY-REGISTRY-DRIFT-001` | capability registry row drift between architecture JSON and markdown | synchronize architecture/capabilities.json and registries/CAPABILITIES.md |
| `ERR-CAPABILITY-STABLE-ID-REUSED-001` | capability stable identifier was reused or renumbered for a different entity | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-CAPABILITY-UNKNOWN-PLANE-001` | capability specifies an unknown or unregistered semantic plane | assign a recognized semantic plane to the capability row |
| `ERR-CLAIM-ASSUMPTIONS-MISSING-001` | promoted proof or bounded_model claim declares no assumptions, or an assumption lacks a non-empty id and statement | declare every named assumption before promotion; no retry without them |
| `ERR-CLAIM-BOUND-DERIVATION-NOT-RECOMPUTABLE-001` | bounded_model derivation records no usable inputs or arithmetic formula, the formula is not its expression right-hand side, or it does not recompute the derived value | record every input with value and units and the exact arithmetic yielding the derived value |
| `ERR-CLAIM-BOUND-DERIVATION-UNBOUND-001` | bounded_model claim derivation is missing, not on disk, digest-unbound, malformed, stepless, or not bound to the claim id and generation | retain the fss.bound_derivation.v1 derivation bound to the claim before promotion |
| `ERR-CLAIM-BOUND-DIMENSION-MISMATCH-001` | bounded_model derivation formula is dimensionally inconsistent (+ or - of different units, or propagated units differ from the derivation units) | correct the formula or input units; units are never converted implicitly |
| `ERR-CLAIM-BOUND-EXPRESSION-UNBOUND-001` | bounded_model claim bound expression, comparator, or value is missing, non-finite, bound to another claim, or differs from the derivation | bind the exact derived bound expression to the claim |
| `ERR-CLAIM-BOUND-SENSITIVITY-MISSING-001` | bounded_model derivation declares no sensitivity analysis or no invalidators | retain sensitivity analysis and invalidators with the derivation |
| `ERR-CLAIM-BOUND-TIGHTER-THAN-DERIVATION-001` | bounded_model claimed bound is tighter than the analytically derived bound | claim at most the derived bound or retain a derivation supporting the tighter one |
| `ERR-CLAIM-BOUND-UNITS-MISSING-001` | bounded_model claim bound or derivation declares no units, or the claimed units differ from the derivation units | declare identical explicit units in claim and derivation; never convert implicitly |
| `ERR-CLAIM-BOUND-VALUE-OUT-OF-DOMAIN-001` | bounded_model claimed, derived, or input value lies outside its registered unit domain (negative, above 100 percent, above 1 auprc) | correct the value or its unit |
| `ERR-CLAIM-CLASS-EVIDENCE-UNINSPECTED-001` | promoted claim of a class the checker does not realize with evidence inspection (only slo, proof, bounded_model are realized) | realize the class row or keep the claim unpromoted |
| `ERR-CLAIM-CLASS-REGISTRY-INVALID-001` | a registry binding claim ids to classes (architecture/invariants.json) declares an inexact id or one id more than once | give every stable id exactly one row |
| `ERR-CLAIM-CLASS-UNRESOLVED-001` | a promoted proof bundle's claim id is bound to a claim class by no registry (SLO ids by registries/SLOS.md, invariant ids by architecture/invariants.json); a row Class column or the bundle never resolves it | bind the claim id in its owning registry; no retry until one does |
| `ERR-CLAIM-EVIDENCE-DUPLICATE-KEY-001` | a JSON document the claim checker reads (proof bundle, qualification receipt, retained evidence document, or registry, including every architecture/*.json the stable-ID tombstone index reads, which leaves the index unavailable) declares the same key twice in one object, at any nesting level; with a plain parser the last value would silently win | declare every key once; a document that says two things is never read as one of them |
| `ERR-CLAIM-EVIDENCE-FIELD-UNKNOWN-001` | an evidence document the claim checker reads declares a key outside its exact field set: the proof bundle, an artifact entry, an assumption, the theorem, the toolchain identity, the formal model reference, manifest, or model source, the proof check receipt, the bound, the derivation, a derivation input, a sensitivity entry, an slo measurement, or its measurement_window; or a qualification receipt declares a case, whitespace, or format-character variant of a field the checker relies on. Keys are compared byte for byte (no case folding, stripping, or normalization) | remove the key or spell it exactly as the document's field set names it; unknown fields are never ignored |
| `ERR-CLAIM-GENERATION-UNBOUND-001` | promoted proof or bounded_model claim is cited by no claim row declaring its current generation (Generation column), or its citing rows conflict | declare the claim row's current generation and bind the bundle to exactly it |
| `ERR-CLAIM-ID-REUSED-001` | A claim class ID is duplicated, renumbered, or reused across different claim classes | give every stable id exactly one row; never reuse or renumber stable ids |
| `ERR-CLAIM-MISSING-FIELD-001` | A claim class entry in the registry is missing required normative fields (id, meaning, minimum_evidence, requiredEvidence) or a table row lacks required columns | declare all required normative fields for each claim class row |
| `ERR-CLAIM-PROOF-BUNDLE-NOT-FOUND-001` | A claim cites a proof bundle, or a bundle declares an artifact, that does not exist on disk, has forbidden traversal ('..'), is absolute, resolves outside the repository root, is not a regular file, or cannot be verified locally | retain the cited proof bundle at the declared path before promotion |
| `ERR-CLAIM-PROOF-BUNDLE-SCHEMA-INVALID-001` | a proof bundle's schema is missing or not exactly 'fss.proof_bundle.v1', or its bundle_id is present but not an exact token | declare the schema byte for byte and, when present, a bundle_id of printable ASCII with no whitespace |
| `ERR-CLAIM-PROOF-CHECK-RECEIPT-INVALID-001` | proof check receipt is missing, malformed, non-passing, or not bound to the claim, formal model, and formal artifact digest | re-run the formal checker and retain a passing bound receipt |
| `ERR-CLAIM-PROOF-CLAIM-BINDING-MISMATCH-001` | A proof bundle binds no claim ID or a different claim than the one citing it, a promoted claim row has no claim ID, or a claim cites a qualification receipt (which binds no claim) | bind the proof bundle to the exact claim id that cites it |
| `ERR-CLAIM-PROOF-DIGEST-MISMATCH-001` | A proof bundle's content digest or an artifact digest is missing, ambiguous, malformed, or does not match the actual computed cryptographic digest | declare one content digest per artifact and recompute it after any edit |
| `ERR-CLAIM-PROOF-EMPTY-INPUT-001` | An input file is empty (0 bytes or empty text), contains an empty JSON collection, or a required claim surface declares no claim table | provide non-empty inputs; empty files or collections are not evidence |
| `ERR-CLAIM-PROOF-FORMAL-ARTIFACT-MISSING-001` | proof claim formal artifact is absent, not on disk, empty, digest-unbound, or not written in the declared checker language | retain the exact checked formal artifact before promotion |
| `ERR-CLAIM-PROOF-FORMAL-MODEL-UNBOUND-001` | proof claim declares no formal model, or its retained fss.formal_model.v1 manifest or source is missing, unreadable, digest-unbound, or not bound to the claim id | retain the declared formal model bound to the claim id before promotion |
| `ERR-CLAIM-PROOF-INVALID-CLASS-001` | A proof bundle declares no claim class, a claim class not recognized in architecture/claims.json, or no claim-class registry was supplied | declare a claim class registered in architecture/claims.json |
| `ERR-CLAIM-PROOF-LEVEL-EXCEEDED-001` | A claim level (e.g. achieved, qualified, verified) is higher than its retained proof supports, the proof is non-passing, or required evidence for the claim class is missing | retain proof evidence for every claimed level before raising the level |
| `ERR-CLAIM-PROOF-MODEL-GENERATION-MISMATCH-001` | proof claim formal model generation differs from the claim generation, the declared model reference, or the check receipt | re-check the proof at the claim generation; never splice generations |
| `ERR-CLAIM-PROOF-PROHIBITED-PROMOTION-001` | A claim attempts a promotion explicitly prohibited by architecture/claims.json | remove the prohibited promotion; claim only what the retained evidence supports |
| `ERR-CLAIM-PROOF-PROVER-RUN-REQUIRED-001` | promoted proof bundle passed the static pre-filter, but a proof is verified only by a qualification receipt from running the prover, and no such receipt mechanism is defined yet | a user decision: define the prover-run receipt; until then no proof claim is verified |
| `ERR-CLAIM-PROOF-STALE-GENERATION-001` | proof bundle references a stale, superseded, tombstoned, expired, or latest-aliased generation, or a generation other than its claim row's current one | re-qualify at the current generation; never splice generations |
| `ERR-CLAIM-PROOF-TESTS-ONLY-001` | proof claim is backed only by tests (test-runner toolchain, test source, or test results) instead of a formal artifact | demote the claim or supply a machine-checked formal proof |
| `ERR-CLAIM-PROOF-THEOREM-UNBOUND-001` | proof claim theorem statement is missing, bound to another claim, or differs from the statement the check receipt checked | bind the exact theorem statement to the claim and re-check |
| `ERR-CLAIM-PROOF-TOMBSTONE-INDEX-UNAVAILABLE-001` | The stable-ID tombstone index (architecture/stable_id_resolution.json plus the repository stable-ID index) is missing, unreadable, empty, corrupt, or has the wrong schema, so tombstoned identities cannot be refused | restore or rebuild architecture/stable_id_resolution.json and the registry tombstone rows |
| `ERR-CLAIM-PROOF-TOOLCHAIN-UNBOUND-001` | proof claim formal checker identity is missing, unregistered, latest-aliased, or differs between bundle and check receipt | pin the exact registered formal checker and version in bundle and receipt |
| `ERR-CLAIM-PROOF-UNPROVEN-PLACEHOLDER-001` | proof claim formal artifact contains, outside comments and strings, an unproven placeholder (Lean sorry, sorryAx, admit, stop or a confusable lookalike; TLAPS OMITTED in any case) | complete the proof; a placeholder is never a checked proof |
| `ERR-CLAIM-PROOF-UNREADABLE-INPUT-001` | An input file or directory could not be read (including a file over the per-file byte cap, MAX_INPUT_BYTES), decoded, or parsed as valid JSON/Markdown, or is structurally malformed (including a qualification receipt that violates schemas/release_qualification_receipt.v1.json) | make every input readable and within the per-file byte bound |
| `ERR-CLAIM-PROOF-UNRECOGNIZED-STATE-001` | A claim status, bundle status, supported level, retention state, expiry marker, or readiness registry state is outside the closed vocabulary | use a recognized status/level/retention spelling from the closed vocabularies |
| `ERR-CLAIM-PROOF-UNSOUND-ESCAPE-001` | proof claim formal artifact contains a known unsound escape (Lean axiom, compiler trust, lcProof, kernel bypass, metaprogramming, a #-command, an import outside Init/Std/Lean; TLA+ AXIOM, ASSUMPTION or non-sequent ASSUME, or EXTENDS/INSTANCE of a non-standard module) | remove the escape; declare assumptions in the bundle and model |
| `ERR-CLAIM-REGISTRY-DRIFT-001` | The machine-readable claims registry (architecture/claims.json) and its human-readable markdown source (registries/CLAIMS.md) differ in claim class IDs, ordering, meaning, minimum evidence, or row count | synchronize architecture/claims.json and registries/CLAIMS.md |
| `ERR-CLAIM-SLO-ACTUAL-INVALID-001` | slo measurement has no single canonical numeric 'actual': it is missing, non-numeric, boolean, negative, overflowing, or rounded-only (an actual-like key is ERR-CLAIM-EVIDENCE-FIELD-UNKNOWN-001) | retain exactly one finite, non-negative numeric 'actual' in the SLO unit; never report only a rounded value |
| `ERR-CLAIM-SLO-COMPARATOR-OVERRIDE-001` | slo measurement declares a comparator that differs from the comparator of its registries/SLOS.md row | remove the comparator from the measurement; the SLO row alone defines the comparison |
| `ERR-CLAIM-SLO-CONJUNCT-INCOHERENT-001` | the measurements behind one slo claim come from different operations, or their validity windows share no common instant | measure every conjunct of the SLO target on the same operation within overlapping validity windows |
| `ERR-CLAIM-SLO-ENVIRONMENT-UNRETAINED-001` | slo claim retains no single digest-bound fss.environment_manifest.v1 artifact, or the measurement is not bound to that manifest's digest | retain the exact environment manifest and bind the measurement to its digest |
| `ERR-CLAIM-SLO-FRESHNESS-BOUND-UNSET-001` | an operation-cost row listing the slo claim's SLO declares no measurement_max_age_days (the strictest bound over all such rows applies), so the freshness bound is unset | a user decision: set the bound on every such row; the checker never assumes a default |
| `ERR-CLAIM-SLO-GENERATION-UNBOUND-001` | slo bundle or measurement declares no generation, or the measurement declares no operation-cost registry generation | bind the bundle and measurement to one explicit generation and to the operation-cost registry generation measured against |
| `ERR-CLAIM-SLO-MEASUREMENT-NOT-PASSED-001` | slo measurement status is missing or anything other than 'passed' | re-run the measurement; a failed, partial, or unlabelled run never supports an slo claim |
| `ERR-CLAIM-SLO-REGISTRY-INVALID-001` | the SLO registry (registries/SLOS.md) or operation-cost registry (architecture/operation_cost_registry.toml) consulted for an slo claim is missing, unreadable, empty, malformed, or declares no rows or generation | repair the registry under the audited root; slo claims are never checked against a silently skipped registry |
| `ERR-CLAIM-SLO-STATISTIC-MISMATCH-001` | slo measurement's declared statistic is not exactly the statistic its SLO target names (missing, different, not byte-exact, or declared for a target naming none; a statistic-like key is ERR-CLAIM-EVIDENCE-FIELD-UNKNOWN-001) | declare the single canonical 'statistic' exactly as the SLO target names it, or none when it names none |
| `ERR-CLAIM-SLO-TARGET-UNBOUND-001` | slo claim target cannot be resolved to exactly one numeric threshold of its registries/SLOS.md row, the measurement declares no or a different unit, or the measurement restates a target that differs from the authoritative row (a non-canonical target key is ERR-CLAIM-EVIDENCE-FIELD-UNKNOWN-001) | claim only an SLO row with a registered numeric threshold; measure in its exact unit and never restate or relax the target |
| `ERR-CLAIM-SLO-WINDOW-INVALID-001` | slo measurement validity window is missing, unparseable, zone-less, empty, finished before it started, or lies in the future | retain a zone-qualified ISO-8601 measurement window that ended before the evaluation instant |
| `ERR-CLI-DUPLICATE-OPTION-001` | option flag was specified more than once | specify option at most once |
| `ERR-CLI-INVALID-UNICODE-001` | command-line argument contains invalid UTF-8 bytes | encode command-line arguments in UTF-8 |
| `ERR-CLI-MALFORMED-VALUE-001` | option or argument value cannot be parsed into expected domain | provide valid typed value before retry |
| `ERR-CLI-MISSING-VALUE-001` | required option or positional argument value is missing | provide required value before retry |
| `ERR-CLI-RUNTIME-FAILURE-001` | runtime error occurred during validated command execution | inspect diagnostic and address failure cause |
| `ERR-CLI-TRAILING-ARGUMENT-001` | extra argument provided after command grammar is satisfied | remove trailing argument before retry |
| `ERR-CLI-UNEXPECTED-POSITIONAL-001` | positional argument provided to command taking no positionals | remove unexpected positional argument |
| `ERR-CLI-UNKNOWN-COMMAND-001` | command token is not a recognized CLI command or verb | do not retry without valid command name |
| `ERR-CLI-UNKNOWN-OPTION-001` | option flag is unrecognized for binary or active command | do not retry without valid option flag |
| `ERR-CLOCK-BASIS-MISMATCH-001` | comparison or association between incompatible clock bases | convert to common basis or synchronise to UTC |
| `ERR-CLOCK-BASIS-UNKNOWN-NAME-001` | clock basis name is unrecognized | supply a registered clock basis name |
| `ERR-CLOCK-STATE-UNKNOWN-001` | clock synchronization state unknown when synchronised evidence required | obtain synchronisation certificate or abstain |
| `ERR-CLOCK-UNCERTAIN-001` | capture interval too wide for requested operation | degrade/abstain/recalibrate |
| `ERR-CLOCK-UNSYNCHRONISED-001` | clock unsynchronised or drift bound exceeds tolerance | synchronise clock or bound monotonic drift |
| `ERR-CORROBORATE-001` | two-sensor corroboration refused by association, the event/policy contract or the storage owner | inspect the cause; retry only after repair |
| `ERR-CORROBORATE-APPROVAL-STALE-001` | an approval digest matches no corroborated proposal of this exact analysis; nothing was published | rerun without approval and review the current proposal digests |
| `ERR-CORROBORATE-HOMOGRAPHY-INVALID-001` | an owner-supplied image-to-ground homography is non-finite, singular, or maps an observed foot point to or beyond the ground horizon; it is an owner assertion, never a calibration certificate | supply a valid homography for that camera; do not retry unchanged |
| `ERR-CORROBORATE-PLAN-INVALID-001` | two-sensor corroboration plan is outside its bounds (camera names, 1..16 ground zones, time gate 1..60 s, finite positive distance gate, recordings of 1..128 frames) | correct the plan; do not retry unchanged |
| `ERR-CORROBORATE-POSE-INVALID-001` | an owner calibrated camera pose ('--pose') is refused for ground-zone visibility: its intrinsics describe another image size than the decoded frames, or it disagrees with the camera's ground homography over a zone; a pose is an owner assertion, never a calibration certificate | supply a pose consistent with the decoded frames and the homography, or omit it (coverage is then homography-frustum-only); do not retry unchanged |
| `ERR-CORROBORATE-SAME-SENSOR-001` | both recordings come from one sensor (or are one import); one failure domain can never corroborate itself | name recordings from two distinct sensors |
| `ERR-CORROBORATE-TIME-UNALIGNED-001` | the two recordings' conservative capture spans do not overlap: clocks are unaligned or the recordings cover different periods | supply recordings of one period on an aligned time base or abstain |
| `ERR-CORROBORATE-TIME-UNKNOWN-001` | a recording has no operator capture-time hint, so its capture time is unknown and cannot be aligned by assumption | re-import with explicit capture hints or abstain |
| `ERR-CORROBORATE-VISIBILITY-001` | geometric ground-zone visibility could not be assessed: the sampling policy is outside its registered bounds, the owner scene-mesh package was refused (digest, format, references, limits), or a visibility query was degenerate or over its geometry budget; nothing was analysed and no coverage is claimed | correct the policy or supply the exact scene-mesh package and digests; do not retry unchanged |
| `ERR-COVERAGE-001` | a coverage record could not be built, validated, staged or committed (witness domain/predicate/generation mismatch, unknown capture time with a witness, storage refusal) | inspect the cause; retry only after repair; no absence is certified |
| `ERR-COVERAGE-APPROVAL-STALE-001` | a '--retain-coverage' approval digest matches neither the fresh analysis's coverage proposal (which binds the authority anchor it read) nor the coverage already retained for that analysis; nothing was retained | rerun without the approval and review the current coverage approval digest |
| `ERR-COVERAGE-UNKNOWN-001` | effective observability cannot be established | abstain/escalate health alert |
| `ERR-DECODE-001` | media decode failed | preserve source; alternate decoder only if registered |
| `ERR-DECODE-BOUNDS-001` | media exceeds declared bounds | fail closed |
| `ERR-DECODE-H264-RANGE-GAP-001` | a retained source gap lies inside the requested H.264 range; inter prediction cannot bridge omitted bytes | split the range at the gap and start after it at an IDR |
| `ERR-DECODE-H264-RANGE-NOT-IDR-001` | requested H.264 decode range does not begin at an IDR access unit, so its first picture would predict from references outside the range | start the range at an IDR segment |
| `ERR-DECODE-H264-UNSUPPORTED-001` | H.264 stream uses a profile or coding tool outside the admitted set (progressive 8-bit 4:2:0 Baseline, Main and High); no approximate pixels are produced | transcode in the laboratory or wait for a registered decoder; do not retry unchanged |
| `ERR-DECODE-H265-RANGE-GAP-001` | a retained source gap lies inside the requested H.265 range; inter prediction cannot bridge omitted bytes | split the range at the gap and start after it at an IRAP segment |
| `ERR-DECODE-H265-RANGE-NOT-IRAP-001` | requested H.265 decode range does not begin at an IRAP (IDR, CRA or BLA) access unit, so its first picture would predict from references outside the range | start the range at an IRAP segment |
| `ERR-DECODE-H265-UNSUPPORTED-001` | H.265 stream uses a profile, sample format or coding tool outside the admitted set (Main and Main Still Picture, 8-bit 4:2:0; no range extensions, tiles, dependent slices or long-term references); no approximate pixels are produced | transcode in the laboratory or wait for a registered decoder; do not retry unchanged |
| `ERR-DECODE-INTERPRETATION-001` | operator component interpretation contradicts the media (admitted H.264 and H.265 are always YCbCr 4:2:0) | resubmit with the correct explicit interpretation |
| `ERR-DECODE-SOURCE-UNAVAILABLE-001` | requested import, segment or range is absent or its retained custody cannot be recovered | name an existing completed import and an in-range segment; repair custody before retry |
| `ERR-DECODE-UNSUPPORTED-MEDIA-001` | retained import's media format is not admitted by the requested decode operation (single-frame JPEG decode/reopen of an Annex-B or HEVC import, H.264 range decode of a JPEG or HEVC import, or H.265 range decode of a JPEG or H.264 import) | use the format's decode operation; do not retry unchanged |
| `ERR-DELETION-APPROVAL-001` | the approval is not the exact approval of this deletion plan for this principal; nothing was written | approve the printed approval digest of the current plan |
| `ERR-DELETION-BLOCKED-001` | deletion closure blocked by hold/backend/offline copy; realized by 'fss-event delete commit' (FSS-037): the sealed plan names an open or indeterminate effect that references the evidence ('open_effect'), a root that failed verification ('broken_root_unclassified'), a conflicting root claim, an earlier incomplete deletion, or a tombstone batch over the bound; nothing was written (the reference deployment has no hold registry yet) | report exact blockers and obligation; resolve them, plan again, approve the new plan |
| `ERR-DELETION-BOUND-001` | a deletion plan or record exceeded a hard bound | split the deployment's retained history; do not retry unchanged |
| `ERR-DELETION-IMPORT-UNKNOWN-001` | 'delete plan' names no completed, retained import | check the import identity; do not retry unchanged |
| `ERR-DELETION-INCOMPLETE-001` | a deletion commit was interrupted after its record became durable, or a removed name is still present; completion was not claimed and every deleted digest already reads 'deleted' | rerun the same 'delete commit'; it resumes and completes exactly once |
| `ERR-DELETION-PLAN-STALE-001` | no deletion plan recomputed against the current head has the given digest (the deployment changed after planning, or the plan is unknown); nothing was written | plan again and approve the new plan; never commit a changed plan |
| `ERR-DELETION-SCOPE-EMPTY-001` | 'delete plan --sensor-id' or '--event-id' reaches no completed, retained import: no retained import's capsules name the sensor, no committed event has the identity, or every member import is already deleted (fss-x4a.30.86.20); nothing was written | check the sensor or event identity; a deleted member reads 'ERR-EVIDENCE-DELETED-001' by '--import-id' |
| `ERR-DELETION-STORAGE-001` | deployment custody, ledger or publication storage failed during a deletion plan or commit | repair storage ('fss doctor'), then rerun the same command |
| `ERR-DEP-ALLOWLIST-DIGEST-DIVERGED-001` | architecture/dependency_allowlist.toml bytes diverged from the checker's pinned allowlist digest | review the allowlist change and update the pinned digest in scripts/dependency_authority.py in the same commit |
| `ERR-DEP-CONST-DRIFT-001` | dependency constitution drift between machine registry and markdown documentation, or between DEPENDENCY_CONSTITUTION.md and its docs/ copy | synchronize architecture/dependency_constitution.json and docs/DEPENDENCY_CONSTITUTION.md, and keep docs/DEPENDENCY_CONSTITUTION.md byte-identical to DEPENDENCY_CONSTITUTION.md |
| `ERR-DEP-CONST-INVARIANT-001` | dependency constitution semantic invariant violated | enforce constitutional admission rule and production closed-universe invariants |
| `ERR-DEP-CONST-METADATA-VIOLATION-001` | Cargo metadata violates constitutional language or stdlib requirements for DEP-CLASS-F0, or names a workspace member that is not declared in architecture/crate_topology.json and listed explicitly in the root [workspace].members | ensure all workspace crates compile under rust-2024 without foreign links, and declare every member in the crate topology and the explicit workspace member list |
| `ERR-DEP-CORRUPT-FILE-001` | dependency registry or markdown documentation file is missing or corrupt | repair or restore dependency registry file |
| `ERR-DEP-DIGEST-MISMATCH-001` | dependency registry digest does not match canonical encoding of metadata and rows | recompute canonical dependency registry digest |
| `ERR-DEP-EXEC-FAILED-001` | a toolchain command required for DEP-CLASS-F0 verification (rustc -Vv or cargo metadata) could not run, timed out, exited non-zero, or produced unparseable output | restore the pinned toolchain and offline cargo inputs and rerun; an execution failure is never reported as a corrupt file |
| `ERR-DEP-FREEZE-DIVERGENCE-001` | dependency registry digest diverged from pinned baseline freeze digest | restore frozen dependency registry or bump generation |
| `ERR-DEP-GENERATION-MISMATCH-001` | dependency registry generation diverged from baseline generation | assign expected generation to dependency registry |
| `ERR-DEP-MISSING-FIELD-001` | dependency class row or root metadata lacks a mandatory field or is empty/corrupt | declare all mandatory fields in dependency class row |
| `ERR-DEP-PENDING-DECISION-001` | a crate recorded under an open owner decision (dependency_allowlist.toml [pending_owner_decisions], e.g. fss-ndxis) reached a manifest, lockfile, or resolved closure | keep the crate out of the closure until the owner records the decision; it is neither admitted nor rejected meanwhile |
| `ERR-DEP-REGISTRY-DRIFT-001` | dependency registry row drift between machine registry and markdown mirror | synchronize architecture/dependencies.json and registries/DEPENDENCIES.md |
| `ERR-DEP-STABLE-ID-REUSED-001` | dependency class stable identifier was reused, duplicated, renumbered, or tombstoned | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-DEP-TOMBSTONE-INVALID-001` | a dependency or dependency-class tombstone/supersession record is malformed, contradictory, dangling, or missing | record status, successor, and tombstone decision consistently in architecture/dependencies.json and architecture/stable_id_resolution.json |
| `ERR-DEP-TRACE-UNRESOLVED-001` | a dependency registry row's owner, producer, consumer, ContractBasis link, or a dependency checker diagnostic code does not resolve | name existing repository files and allowlist tables that reference the row, and register every emitted code in registries/ERRORS.md |
| `ERR-DEP-UNSTABLE-FEATURE-001` | the repository enables a nightly unstable feature (#![feature(...)] including inside cfg_attr, -Z rustflags in .cargo/config or checked-in env/shell files, a cargo [unstable] table, cargo-features, or a -Z literal in a build script) while no unstable-feature allowlist is registered | remove the feature gate or flag, or register an unstable-feature allowlist with owner and removal plan before enabling it |
| `ERR-DETECTOR-CASCADE-BUDGET-001` | a frame the cheap watch gate selected was not inferred because the explicit '--detector-max-inferences' budget was exhausted; a typed per-frame outcome in the report and a non-supporting evidence record, never a silent drop and never evidence of absence | raise the budget or narrow the range if the frame matters |
| `ERR-DETECTOR-CASCADE-PLAN-001` | detector-cascade policy outside its bounds (frames per track 1..8, max inferences 1..64, association IoU and score threshold at most 1000000 ppm) or a threshold the package refuses; refused before any source is read | correct the cascade options; do not retry unchanged |
| `ERR-DEVICE-UNSUPPORTED-001` | exact product/firmware/app tuple not certified | fail closed or explicit import-only mode |
| `ERR-DOCTOR-ATTENTION-REQUIRED-001` | doctor inspection detected deployment conditions requiring attention | inspect doctor report and follow next affordance |
| `ERR-DOCTOR-NOT-A-DEPLOYMENT-001` | target directory is not a recognized reference deployment root | provide a valid reference deployment root |
| `ERR-EFFECT-INDETERMINATE-001` | dispatch outcome cannot be determined | reconcile before retry |
| `ERR-EVIDENCE-DELETED-001` | the requested import (or its derivative) was deleted under a committed deletion record; availability 'deleted', not missing; a deleted import identity is never re-imported | do not retry; the record names the deletion plan |
| `ERR-EVIDENCE-MISSING-001` | canonical root references unavailable required evidence | repair; no adjudication requiring it |
| `ERR-FIRMWARE-DRIFT-001` | observed device generation differs from registry | disable/move to shadow; no optimistic retry |
| `ERR-FROZEN-DIGEST-MISMATCH-001` | frozen public registry digest does not match canonical encoding of sorted rows | recompute canonical freeze digest over sorted rows |
| `ERR-FROZEN-REGISTRY-DRIFT-001` | public operation or resource was added, removed, renamed, or renumbered without a new registry generation | bump the registry generation and update the frozen public registry |
| `ERR-FROZEN-STABLE-ID-REUSED-001` | stable operation or resource identifier was reused for a different entity | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-FROZEN-TOMBSTONE-RESURRECTED-001` | tombstoned operation or resource was resurrected into active registry | allocate a new identifier; tombstoned entries remain permanently retired |
| `ERR-FROZEN-UNREGISTERED-OP-001` | crosswalk or presentation surface references an unregistered operation | register operation in frozen registry or correct surface reference |
| `ERR-GRAPH-BUDGET-EXHAUSTED-001` | a declared graph budget (operations or output entries) ran out before the exact answer was complete; no partial answer or witness was produced | raise the budget within the registered bound or narrow the projection |
| `ERR-GRAPH-COMPLEXITY-BOUND-001` | an observed graph operation counter exceeded the registered complexity or output bound for the input size, at run time or when a witness is re-checked; no answer is trusted | treat as an implementation defect or tampered witness; do not retry unchanged |
| `ERR-GRAPH-INPUT-INVALID-001` | a graph projection or request is outside the strict graph policy (empty, oversized or control-character node identity, duplicate node, unknown endpoint or root, self-loop, parallel edge, or node/edge limit); nothing was analysed | correct the projection; inputs are refused, never repaired; do not retry unchanged |
| `ERR-GRAPH-MISSING-COMPLEXITY-WITNESS-001` | graph algorithm row lacks declared complexity witness operations | declare dominant operation complexity witness in graph algorithm registry |
| `ERR-GRAPH-MISSING-OUTPUT-WITNESS-001` | graph algorithm row lacks declared output-size witness with bounds | declare output-size witness with bounds or record explicit owner drift |
| `ERR-GRAPH-MISSING-TIE-BREAK-001` | graph algorithm row lacks a deterministic CGSE tie-break rule | specify a deterministic CGSE tie-break policy in graph algorithm registry |
| `ERR-GRAPH-PROJECTION-MISMATCH-001` | graph algorithm projections differ between machine source and registry markdown mirror | reconcile machine source and registry markdown projections |
| `ERR-GRAPH-RESULT-INCONSISTENT-001` | a projection-level answer derived from a graph run disagrees with the projection's structural invariant (for example coverage single points versus the witnessed observers); nothing was reported | treat as an implementation defect; do not retry unchanged |
| `ERR-GRAPH-STABLE-ID-DRIFT-001` | graph algorithm stable identifier renumbered or superseded row not tombstoned | restore stable algorithm identity and retain superseded rows as tombstones |
| `ERR-GRAPH-UNREGISTERED-PROJECTION-001` | graph algorithm specifies an unregistered or nonexistent graph projection ID | update algorithm projection to a registered projection ID from docs/GRAPH_ALGORITHM_ATLAS.md |
| `ERR-HOLD-APPROVAL-STALE-001` | an 'fss-hold --approve' digest no longer names the exact prepared transition over the current authority head; nothing was written | rerun without the approval and approve the printed digest |
| `ERR-HOLD-BOUND-001` | retained hold history or active held-closure bounds are exhausted (registries/evidence_holds.json limits); holds are never evicted | release holds or raise the reviewed bound |
| `ERR-HOLD-CANCELLED-001` | the hold operation was cancelled cooperatively, including before a staged record was appended | retry the same request; approvals stay exact |
| `ERR-HOLD-DELETION-IN-PROGRESS-001` | a deletion of the import is committed but not complete, so preservation can no longer be promised; retention mutations are refused | finish or reconcile the deletion first |
| `ERR-HOLD-REQUEST-001` | an 'fss-hold' request is outside its contract: invalid bounded request, unknown hold on release, identifier already bound to another import or placement, or a released identifier reused; nothing was written | correct the request; identifiers are never reused |
| `ERR-HOLD-STORAGE-001` | hold authority is missing, corrupt, shadowed or inconsistent, or an underlying ledger, spool, import or deletion-history read failed; never treated as no hold | repair the deployment; do not delete while unresolved |
| `ERR-HYDRATION-INVALID-PRIVACY-CLASS-001` | H2 decision artifact privacy class is not 'private:property', the only privacy class fss-core uses; raw or unredacted media included (code 'invalid_privacy_class') | supply the authorized privacy class; do not retry unchanged |
| `ERR-HYDRATION-INVALID-REDACTION-TRANSFORM-001` | H2 redaction transform is not a recognized 'transform:*' token or is incompatible with the artifact kind (code 'invalid_redaction_transform') | apply a recognized transform compatible with the artifact kind |
| `ERR-IDEMPOTENCY-CONFLICT-001` | same key used with different request digest | reject permanently |
| `ERR-INGEST-FORMAT-AMBIGUOUS-001` | an Annex-B file's first NAL unit header is valid as both H.264 and H.265 and no media format was declared; the importer never guesses the codec | re-import with the explicit media format ('annexb' for H.264, 'hevc' for H.265) |
| `ERR-INGEST-FORMAT-CONFLICT-001` | the declared media format contradicts the file's signature (e.g. 'hevc' declared for a stream whose first header is only valid H.264) | declare the format the file actually holds; do not retry unchanged |
| `ERR-INTERNAL-PANIC-001` | boundary converted an internal panic to structured crash receipt | quarantine, preserve support bundle |
| `ERR-KSTATE-CORRUPT-FILE-001` | knowledge state registry or markdown documentation file is missing or corrupt | repair or restore knowledge state registry file |
| `ERR-KSTATE-DIGEST-MISMATCH-001` | knowledge state registry digest does not match canonical encoding of metadata and rows | recompute canonical knowledge state registry digest |
| `ERR-KSTATE-FREEZE-DIVERGENCE-001` | knowledge state registry digest diverged from pinned baseline freeze digest | restore frozen knowledge state registry or bump generation |
| `ERR-KSTATE-GENERATION-MISMATCH-001` | knowledge state registry generation diverged from baseline generation | assign expected generation to knowledge state registry |
| `ERR-KSTATE-ILLEGAL-IRREVERSIBLE-AUTH-001` | non-known knowledge state illegally authorizes irreversible effect | restrict irreversible effect authorization strictly to known state |
| `ERR-KSTATE-MISSING-FIELD-001` | knowledge state row lacks a mandatory field or is empty/corrupt | declare all mandatory fields in knowledge state row |
| `ERR-KSTATE-REGISTRY-DRIFT-001` | knowledge state registry row drift between machine registry and markdown | synchronize architecture/knowledge_states.json and registries/AGENT_CONTRACTS.md |
| `ERR-KSTATE-STABLE-ID-REUSED-001` | knowledge state stable identifier was reused or renumbered for a different entity | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-LAB-ROOT-NOT-EMPTY-001` | laboratory target root directory already contains files | choose an empty or new target root directory |
| `ERR-LEASE-STALE-001` | effect lease fence is not current | re-prepare under fresh lease |
| `ERR-LEDGER-DURABLE-BATCH-ID-CONFLICT-001` | durable ledger batch identity already committed with different content | reject input; stable batch IDs are never reused |
| `ERR-LEDGER-LENGTH-OVERFLOW-001` | journal byte offset or file length exceeds addressable 64-bit bounds | archive or rotate journal; no in-place append possible |
| `ERR-LEDGER-ORACLE-BASIS-FORKED-001` | batch basis anchor is not the committed anchor at its sequence | reject input; foreign lineage, epoch, or state root |
| `ERR-LEDGER-ORACLE-BATCH-ID-CONFLICT-001` | committed batch identity reused with different content | reject input; stable batch IDs are never reused |
| `ERR-LEDGER-ORACLE-BOUND-001` | batch delta count, child count, or text field exceeds the canonical batch bound | reject input; split or repair the producer |
| `ERR-LEDGER-ORACLE-CAPACITY-001` | committed-batch capacity of the oracle is exhausted | archive or rotate before appending |
| `ERR-LEDGER-ORACLE-DIGEST-MISMATCH-001` | declared batch digest does not match batch content | reject input; never retry unchanged |
| `ERR-LEDGER-ORACLE-DUPLICATE-BATCH-001` | exact batch is already committed at the reported sequence | no retry; batch is already canonical |
| `ERR-LEDGER-ORACLE-DUPLICATE-OBJECT-001` | one batch carries more than one delta for the same object | reject input; merge or split deltas |
| `ERR-LEDGER-ORACLE-ENCODING-001` | canonical encoding of a digest input exceeded its encoder bound | reject input; repair the oversized field |
| `ERR-LEDGER-ORACLE-GENERATION-CONFLICT-001` | delta generations do not follow the committed object generation | reject input; re-prepare against the head |
| `ERR-LEDGER-ORACLE-INVALID-CONFIG-001` | ledger oracle limit or site lineage outside its admitted range | repair configuration; do not retry unchanged |
| `ERR-LEDGER-ORACLE-INVALID-SUCCESSOR-001` | successor anchor lineage, epoch, or sequence does not follow its basis | reject input; re-prepare against the head |
| `ERR-LEDGER-ORACLE-NON-CANONICAL-001` | batch deltas or child roots are not in strictly increasing canonical order | reject input; re-prepare canonically |
| `ERR-LEDGER-ORACLE-OBJECT-CAPACITY-001` | batch would exceed the live-object capacity of the oracle | archive or rotate before appending |
| `ERR-LEDGER-ORACLE-READ-ANCHOR-MISMATCH-001` | anchor-pinned read named an anchor that is not committed in this history | resnapshot from a committed anchor of this lineage |
| `ERR-LEDGER-ORACLE-READ-BEYOND-HEAD-001` | anchor-pinned read requested a sequence beyond the committed head | wait for commit or read at a committed anchor |
| `ERR-LEDGER-ORACLE-SEQUENCE-EXHAUSTED-001` | commit sequence space is exhausted | archive or rotate; no in-place append possible |
| `ERR-LEDGER-ORACLE-SEQUENCE-GAP-001` | batch basis is beyond the head; predecessor batches are missing | supply predecessors in canonical order, then retry |
| `ERR-LEDGER-ORACLE-STALE-STAGE-001` | staged batch was validated against a head that has since moved or another history | stage again against the current head |
| `ERR-LEDGER-ORACLE-STATE-ROOT-MISMATCH-001` | declared successor state root does not match the applied deltas | reject input; never retry unchanged |
| `ERR-LEDGER-ORACLE-SUCCESSOR-CONFLICT-001` | another batch already committed on the same basis (first committer wins) | rebase onto the current head and prepare a new batch |
| `ERR-LEDGER-SEALED-NAMESPACE-001` | batch writes the sealed publication-lineage namespace (a lineage or proof-marker family or object) outside record_reference_publication, or the gated writer was handed an unsealed batch | reject input; record publications only through record_reference_publication |
| `ERR-MODEL-GENERATION-001` | mixed or stale model/index generation | rebuild/retry at coherent generation |
| `ERR-MODEL-OUTPUT-001` | malformed/out-of-bounds model output | reject output; terminate/quarantine generation |
| `ERR-MODEL-PACKAGE-CANCELLED-001` | model package load cancelled by its owner before a complete verified package existed | retry when the owner permits; nothing was loaded |
| `ERR-MODEL-PACKAGE-DIGEST-001` | model package bytes differ from the independently pinned whole-archive SHA-256 (tampered, truncated or wrong file); refused before parsing | obtain the exact package; never re-pin to accept unknown bytes |
| `ERR-MODEL-PACKAGE-INVALID-001` | model package archive, manifest, artifact set, package spec, IR graph, weights or head contract is malformed, inconsistent or outside its bounds | rebuild the package with the offline importer; do not retry unchanged |
| `ERR-MODEL-PACKAGE-LICENSE-001` | model package license record refused by the license policy (surveillance-monitoring profile, license-text digest required) | review the license; do not load the package |
| `ERR-MODEL-UNAVAILABLE-001` | model generation not runnable | route to registered fallback or degrade |
| `ERR-NEG-CHECKSUM-MISMATCH-001` | negative evidence binary ledger corrupt magic, checksum, or truncated data | repair corrupt ledger binary or restore from canonical backup |
| `ERR-NEG-CONCURRENT-MODIFICATION-001` | negative evidence ledger changed between read and publish on every bounded attempt | identify the concurrent writer, then retry the append explicitly |
| `ERR-NEG-COVERAGE-GAP-001` | negative evidence evaluated during an uncertified coverage gap | ensure continuous coverage witness; absence during gap is never evidence |
| `ERR-NEG-DUPLICATE-ID-001` | negative evidence ledger contains duplicate stable entry identifier | allocate unique stable entry identifier; never duplicate IDs |
| `ERR-NEG-ENTRY-TOMBSTONED-001` | attempted operation on or with a permanently tombstoned negative entry | do not operate on tombstoned negative-evidence entries |
| `ERR-NEG-INPUT-OVERSIZED-001` | negative evidence entry or field exceeds declared capacity limit | bound entry string length or shared failure domain count |
| `ERR-NEG-LEDGER-EXISTS-001` | negative evidence ledger init target already exists | choose a new path; init never overwrites a ledger |
| `ERR-NEG-LEDGER-FORKED-001` | after the atomic rename the old negative-evidence ledger inode is still linked by another name holding the pre-append ledger | reconcile the fork by hand: keep exactly one name and re-run the append |
| `ERR-NEG-LEDGER-HARD-LINKED-001` | negative evidence ledger file has a link count other than one, so an atomic publish would update only one of its names | keep the ledger under a single name (use a symlink for aliases) before appending |
| `ERR-NEG-LEDGER-LOCKED-001` | negative evidence ledger lock file is held by another writer or was left stale by a crashed writer | retry after the other writer finishes; remove a stale lock only after confirming no writer is running |
| `ERR-NEG-LEDGER-NOT-FOUND-001` | negative evidence ledger file does not exist | create the ledger with 'fss negative-evidence init' before appending |
| `ERR-NEG-LEDGER-TEMP-EXISTS-001` | temporary negative-evidence ledger file already exists before the append created it | remove the stale temporary file or investigate before appending |
| `ERR-NEG-MALFORMED-ENTRY-001` | negative evidence ledger entry bytes carry an unknown tag, an invalid value, or a count beyond its declared bound | restore the ledger from a canonical backup; never guess field values |
| `ERR-NEG-MISSING-COVERAGE-001` | negative evidence entry lacks a certifying coverage witness | provide a valid certifying coverage witness; absence without witness is never evidence |
| `ERR-NEG-MISSING-PROOF-001` | locally certified negative evidence lacks a proof hash, a retained evidence reference, or the evidence its knowledge state requires | supply the proof hash and retained evidence reference, or record the entry as not locally certified |
| `ERR-NEG-NON-CANONICAL-ORDER-001` | negative evidence ledger entries are not in strictly increasing canonical order | sort entries strictly by stable ID |
| `ERR-NEG-REVIVAL-UNMET-001` | candidate retry or promotion attempted without meeting revival condition | satisfy documented revival condition before promoting candidate |
| `ERR-NEG-UNCERTIFIED-COVERAGE-001` | coverage witness does not certify complete negative predicate absence | verify coverage domain and predicate certification |
| `ERR-NEG-UNKNOWN-VERSION-001` | negative evidence binary ledger format version is unknown or unsupported | refuse unknown version; never guess ledger encoding format |
| `ERR-NEG-VALIDATION-FAILED-001` | negative evidence entry semantic validation failed | provide valid required fields conforming to negative evidence contract |
| `ERR-NON-MONOTONE-NARROWING-001` | attempted non-monotone uncertainty narrowing violating FORMAL-010 | preserve monotone widening; retain sync evidence |
| `ERR-OP-CORRUPT-FILE-001` | operation registry, frozen public registry, or markdown documentation file is missing or corrupt | repair or restore the operation registry file |
| `ERR-OP-EXECUTION-FAILED-001` | operation execution failed with expected domain error | inspect error details and apply recovery guidance |
| `ERR-OP-ID-MALFORMED-001` | error identity does not conform to stable ERR pattern | fix error identity to match stable registry format |
| `ERR-OP-INDETERMINATE-001` | tombstone: superseded by 'ERR-EFFECT-INDETERMINATE-001' | historical duplicate preserved for audit; indeterminate outcomes must use Indeterminate variant |
| `ERR-OP-INVALID-OUTCOME-001` | operation outcome state transition or representation is invalid | inspect outcome payload and repair state machine |
| `ERR-OP-MISSING-FIELD-001` | operation row or registry metadata lacks a mandatory field or is empty/corrupt | declare all mandatory fields in the operation row |
| `ERR-OP-NOT-OBSERVABLE-001` | tombstone: superseded by 'ERR-COVERAGE-UNKNOWN-001' | historical duplicate preserved for audit; canonical target is 'ERR-COVERAGE-UNKNOWN-001' |
| `ERR-OP-PRECONDITION-FAILED-001` | tombstone: superseded by 'ERR-PRECONDITION-STALE-001' | historical duplicate preserved for audit; canonical target is 'ERR-PRECONDITION-STALE-001' |
| `ERR-OP-RECONCILIATION-REQUIRED-001` | pending unresolved operation must be reconciled before further mutation | reconcile pending sequence before retry |
| `ERR-OP-REGISTRY-DRIFT-001` | operation registry row drift between machine registry and markdown mirror | synchronize architecture/agent_operations.json and registries/AGENT_OPERATIONS.md |
| `ERR-OP-RUST-DRIFT-001` | typed Rust operation table drifted from or is missing versus the machine registry | regenerate crates/fss-core/src/agent_operation.rs canonical rows from architecture/agent_operations.json |
| `ERR-OP-SEMANTIC-INVARIANT-001` | operation semantic invariant violation: effect/mode contradiction, durability contradiction, or unregistered view/payload/capability/gate/retry spelling | enforce the registered operation mode table and row invariants |
| `ERR-OP-STABLE-ID-REUSED-001` | operation stable identifier was reused, duplicated, or renumbered outside AOP-001..AOP-014 | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-OP-TIMEOUT-001` | operation budget or deadline expired before completion | retry with higher budget or backoff |
| `ERR-OP-UNAUTHORIZED-001` | tombstone: superseded by 'ERR-AUTH-DENIED-001' | historical duplicate preserved for audit; canonical target is 'ERR-AUTH-DENIED-001' |
| `ERR-OPERATION-UNREGISTERED-001` | surveillance operation not registered in time uncertainty budget catalog | register operation tolerance before evaluation |
| `ERR-PACKAGE-DETECT-001` | package detection refused at a named segment by retained custody, decode, preprocessing, model execution or head projection; no partial report | inspect the cause; retry only after repair or with adequate bounds |
| `ERR-PACKAGE-DETECT-CANCELLED-001` | package detection cancelled by its owner; no partial report | rerun the same range |
| `ERR-PACKAGE-DETECT-REQUEST-001` | package detection range, frame count (1..64) or retained media format outside the operation contract; refused before decode | correct the request; do not retry unchanged |
| `ERR-PACKAGE-EVENT-001` | package retention or event publication refused by the tracker, event contract or storage owner | inspect the cause; retry only after repair |
| `ERR-PACKAGE-EVENT-APPROVAL-STALE-001` | the approval digest is not the freshly prepared package-event proposal; nothing was published | prepare again and review the current proposal digest |
| `ERR-PACKAGE-EVENT-CANCELLED-001` | package retention, report, preparation or publication cancelled by its owner; committed provenance may remain, no success is claimed | rerun; exact reruns resume without duplicates |
| `ERR-PACKAGE-EVENT-MISMATCH-001` | retained package-detection custody, its canonical record, or an exported package analysis report disagrees with the rebuild from custody | do not trust the bytes; investigate custody and re-export |
| `ERR-PACKAGE-EVENT-REQUEST-001` | package report/event request outside its contract (label not in the package vocabulary, tracking policy out of bounds, or bytes that are not a package analysis report) | correct the request; do not retry unchanged |
| `ERR-PACKAGE-EVENT-TRACK-001` | the selected package-report track does not exist or was never confirmed | choose a confirmed track from the report output |
| `ERR-PACKAGE-EVENT-UNAVAILABLE-001` | the deployment retains no package detection with this report digest (only 'fss-infer package-detect --retain yes' retains one) | retain the detection first, then rerun |
| `ERR-PRECONDITION-STALE-001` | plan anchor changed before commit | re-plan; never auto-commit changed intent |
| `ERR-PRIVACY-MASK-001` | required redaction could not be applied | fail closed at restricted boundary |
| `ERR-PRIVACY-MASK-APPROVAL-STALE-001` | a 'privacy-mask declare --approve' digest matches neither this declaration over the sensor's current retained policy nor the approval that retained it; nothing was written | rerun without the approval and review the current approval digest |
| `ERR-PRIVACY-MASK-POLICY-001` | a declared privacy mask policy is outside its contract (resolution 1..4096 per dimension, 1..32 non-empty duplicate-free rectangles inside the declared resolution) | correct the declaration; do not retry unchanged |
| `ERR-PRIVACY-MASK-RESOLUTION-001` | decoded frame dimensions differ from the sensor's retained privacy mask resolution; no pixel is served unmasked | declare a policy for the actual stream resolution; do not retry unchanged |
| `ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001` | the request would serve or analyse pixels the sensor's current retained privacy mask does not mask (raw retained source export: 'fss-file extract' of a masked sensor, and 'fss-archive export' of original RTSP packets of a masked sensor or naming no privacy deployment; a decode retained under no or a superseded mask policy; a live, recording, replay or 'check-http' decode naming no sensor; an owner permission grid or frozen background admitting masked pixels; RGB evidence recorded under another binding); no override capability exists | decode again under the current policy, naming the sensor; exclude masked pixels from the permission grid and refreeze the background; raw source of a masked sensor has no export path |
| `ERR-PROV-CORRUPT-FILE-001` | provenance registry or markdown documentation file is missing or corrupt | repair or restore provenance registry file |
| `ERR-PROV-DIGEST-MISMATCH-001` | provenance registry digest does not match canonical encoding of metadata and rows | recompute canonical provenance registry digest |
| `ERR-PROV-FREEZE-DIVERGENCE-001` | provenance registry digest diverged from pinned baseline freeze digest | restore frozen provenance registry or bump generation |
| `ERR-PROV-GENERATION-MISMATCH-001` | provenance registry generation diverged from baseline generation | assign expected generation to provenance registry |
| `ERR-PROV-LAUUNDERING-UNWIRED-001` | evidence-laundering refusal has no non-test caller on any production path | call 'KnowledgeCell::verify_no_evidence_laundering' from at least one non-test production path (fss-2nwxm) |
| `ERR-PROV-MISSING-FIELD-001` | provenance class row lacks a mandatory field or is empty/corrupt | declare all mandatory fields in provenance class row |
| `ERR-PROV-REGISTRY-DRIFT-001` | provenance registry row drift between machine registry and markdown | synchronize architecture/provenance_classes.json and registries/AGENT_CONTRACTS.md |
| `ERR-PROV-SEMANTIC-INVARIANT-001` | provenance semantic invariant violation: non-permissible irreversible authorization, missing anchors, or score flattening | enforce provenance orthogonality and class-specific evidence/authorization gates |
| `ERR-PROV-STABLE-ID-REUSED-001` | provenance class stable identifier was reused or renumbered for a different entity | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-PUBLICATION-LEDGER-ALREADY-LEDGERED-001` | root reachability is already canonical; nothing to prepare | no retry; root is already ledgered |
| `ERR-PUBLICATION-LEDGER-CONFLICT-001` | canonical ledger already names a different root or family for the slot; nothing appended | repair the ledger identity explicitly; never overwrite either record |
| `ERR-PUBLICATION-LEDGER-INDETERMINATE-001` | root is durable and its reachability append became indeterminate | reconcile the ledger append before any retry |
| `ERR-PUBLICATION-LEDGER-INJECTED-CRASH-001` | a root-ledger fault-injection cut point fired after the root became durable | reopen both owners to reconcile |
| `ERR-PUBLICATION-LEDGER-NOT-DURABLE-001` | slot holds no durable root; its reachability is never committed to the ledger | publish durably or reopen to reconcile first |
| `ERR-PUBLICATION-LEDGER-PREPARED-MISMATCH-001` | offered batch is not the reachability batch of the slot's durable root | reject input; prepare against the durable root |
| `ERR-PUBLICATION-LEDGER-RECONCILE-001` | reconciling an indeterminate ledger append failed | repair ledger storage, then reconcile again |
| `ERR-PUBLICATION-LEDGER-RECONCILIATION-REQUIRED-001` | an indeterminate ledger append must be reconciled before root-ledger work | reconcile the pending ledger append |
| `ERR-PUBLICATION-LEDGER-SLOT-IDENTITY-001` | slot cannot be expressed as a stable ledger object or batch identity | reject input; choose a slot within the ledgered slot bound |
| `ERR-PUBLICATION-LEDGER-UNLEDGERED-001` | root is durable but the ledger refused or could not prepare its reachability batch; explicit pending-ledger state | follow the nested cause, then retry the idempotent ledger commit |
| `ERR-PUBLICATION-LOCAL-BOUND-001` | manifest child count or directory entry count exceeds the configured bound | reject input; split the manifest or repair the layout |
| `ERR-PUBLICATION-LOCAL-BROKEN-ROOT-001` | slot holds a root record that failed reopen verification | repair or quarantine the broken record; never overwrite it |
| `ERR-PUBLICATION-LOCAL-CANCELLED-001` | publication was cancelled before the root rename; nothing is visible | retry idempotently when resumed |
| `ERR-PUBLICATION-LOCAL-CAPACITY-001` | configured root or tombstone capacity of the local publisher is exhausted | archive or rotate before publishing |
| `ERR-PUBLICATION-LOCAL-CLEANUP-001` | removing a temporary publication file failed after an earlier error; both errors are carried | repair storage, discard orphaned temps, then retry idempotently |
| `ERR-PUBLICATION-LOCAL-CORRUPT-REFERENCE-001` | a referenced object failed digest verification; root not visible | repair or restage the named object, then retry idempotently |
| `ERR-PUBLICATION-LOCAL-CORRUPT-TOMBSTONE-001` | a durable tombstone record failed verification on open | repair the tombstone store; open fails closed |
| `ERR-PUBLICATION-LOCAL-DELETION-AUTHORITY-001` | tombstone record lacks a deletion authority witness | supply a verified deletion authority witness |
| `ERR-PUBLICATION-LOCAL-ENCODING-001` | canonical encoding of a publication record exceeded its encoder bound | reject input; repair the oversized field |
| `ERR-PUBLICATION-LOCAL-INDETERMINATE-001` | root was renamed into place but its directory fsync failed; durability unknown | reopen to reconcile before any retry |
| `ERR-PUBLICATION-LOCAL-INJECTED-CRASH-001` | a fault-injection cut point fired and the instance behaves as a dead process | reopen to reconcile |
| `ERR-PUBLICATION-LOCAL-INVALID-CONFIG-001` | local publication limits are zero, inconsistent, or above a format maximum | repair configuration; do not retry unchanged |
| `ERR-PUBLICATION-LOCAL-IO-001` | a publication filesystem operation failed before the root rename | bounded retry after repairing storage; nothing is visible |
| `ERR-PUBLICATION-LOCAL-LAYOUT-001` | a publication directory or record path has the wrong file type or is occupied unexpectedly | repair the layout; nothing is overwritten |
| `ERR-PUBLICATION-LOCAL-LOCKED-001` | another owner holds the exclusive publication lock | wait for the owner to close; never share the root |
| `ERR-PUBLICATION-LOCAL-MANIFEST-MISMATCH-001` | manifest root does not match its canonical body or its staged read-back | reject input; rebuild the manifest canonically |
| `ERR-PUBLICATION-LOCAL-ORPHAN-TEMP-001` | an orphaned temporary record from an interrupted publication occupies the path | discard classified orphans, then retry idempotently |
| `ERR-PUBLICATION-LOCAL-POISONED-001` | publisher observed a crash or indeterminate outcome and refuses further work | reopen to reconcile |
| `ERR-PUBLICATION-LOCAL-ROOT-VISIBILITY-INDETERMINATE-001` | root rename was reported failed and rolling back the possibly renamed record failed; visibility unknown, slot marked indeterminate | reopen to reconcile; the slot is refused until its record and indeterminate marker are repaired |
| `ERR-PUBLICATION-LOCAL-SLOT-CONFLICT-001` | slot already holds a different visible root | reject input; publish the new root under a new slot |
| `ERR-PUBLICATION-LOCAL-SLOT-INVALID-001` | publication slot name is empty, too long, or outside the slot grammar | reject input; choose a registered slot name |
| `ERR-PUBLICATION-LOCAL-SPOOL-001` | the staging spool refused an object stage, verify, or read | follow the nested spool failure; no root was made visible |
| `ERR-PUBLICATION-LOCAL-TOMBSTONE-CONFLICT-001` | a different tombstone record is already durable for the object | reject input; tombstones are immutable |
| `ERR-PUBLICATION-LOCAL-TOMBSTONE-REACHABLE-001` | object is reachable from a visible root and cannot be tombstoned locally | run deletion closure through its owner; no silent unpublish |
| `ERR-PUBLICATION-LOCAL-TOMBSTONE-VISIBILITY-INDETERMINATE-001` | tombstone rename was reported failed and rolling back the possibly renamed record failed; visibility unknown | reopen to reconcile; the tombstone is refused until its record and indeterminate marker are repaired |
| `ERR-PUBLICATION-LOCAL-TOMBSTONED-REFERENCE-001` | a referenced object carries a durable tombstone; root not visible | reject input; tombstoned objects are never republished |
| `ERR-PUBLICATION-LOCAL-UNAVAILABLE-001` | custody of a referenced object could not be determined; root not visible | reopen to reconcile storage, then retry idempotently |
| `ERR-PUBLICATION-PARTIAL-001` | child staging incomplete; root not visible | idempotent retry or collect children |
| `ERR-QUIESCENCE-001` | region/process failed to drain | block shutdown/upgrade claim; force isolation path |
| `ERR-REPLAY-DIVERGED-001` | semantic decision fingerprint differs from proof | block claim/release |
| `ERR-RETENTION-NOT-ELAPSED-001` | 'fss-hold expire' names an earliest owner-attested time before the hold's minimum-retention deadline (or an uncertain time); the hold stays active | retry after the deadline with a new attested time |
| `ERR-ROBOT-DOCS-CORRUPT-001` | malformed JSON syntax, duplicate keys, or encoding corruption in robot docs or registry | repair malformed input; ensure canonical encoding |
| `ERR-ROBOT-DOCS-DRIFT-001` | cataloged operations, views, or resources drift across registries | reconcile registry definitions before generating docs |
| `ERR-ROBOT-DOCS-MISSING-001` | generated robot documentation markdown or json artifact missing | generate robot docs with scripts/generate_robot_docs.py |
| `ERR-ROBOT-DOCS-SECRET-DETECTED-001` | suspected secret, credential, token, or local filesystem path detected in registry text | remove sensitive data and sanitize registry text |
| `ERR-ROBOT-DOCS-STALE-001` | robot documentation diverges from authoritative machine registries | regenerate robot docs with scripts/generate_robot_docs.py |
| `ERR-ROBOT-DOCS-UNREGISTERED-001` | documented operation references unregistered capability, schema, or error identity | register referenced entity in authoritative registry before generating docs |
| `ERR-SCHEMA-UNSUPPORTED-001` | input durable schema version unsupported | migrate with registered path or reject |
| `ERR-SECRET-UNAVAILABLE-001` | secret handle cannot be resolved | repair/rotate; bounded retry if provider transient |
| `ERR-SOURCE-EVIDENCE-BYTE-COUNT-MISMATCH-001` | capsule source bytes does not match custody source bytes | align capsule and custody byte count |
| `ERR-SOURCE-EVIDENCE-CAPSULE-REQUIRED-001` | sensor capsule classification requires a sensor capsule payload | provide sensor capsule or change classification |
| `ERR-SOURCE-EVIDENCE-EMPTY-STORAGE-HANDLE-001` | retained source custody storage handle is empty | provide non-empty sanitized storage handle |
| `ERR-SOURCE-EVIDENCE-MISSING-ANCHOR-001` | source evidence record missing authoritative anchor | attach authoritative anchor; do not retry unchanged |
| `ERR-SOURCE-EVIDENCE-NOT-RETAINED-WITH-CAPSULE-BYTES-001` | not-retained source evidence capsule cannot claim non-zero source bytes, non-zero frame count, or non-zero source digest | zero capsule bytes/digest/frames or mark retained |
| `ERR-SOURCE-EVIDENCE-NOT-RETAINED-WITH-WITNESS-001` | source evidence not retained cannot bind a continuity witness | omit witness or retain source evidence |
| `ERR-SOURCE-EVIDENCE-OMISSION-REQUIRED-001` | not-retained source evidence must declare an explicit omission reason | supply explicit omission reason; do not retry unchanged |
| `ERR-SOURCE-EVIDENCE-RAW-WIRE-PACKETS-WITH-CAPSULE-001` | raw wire packets classification cannot carry a sensor capsule payload | omit capsule or change classification |
| `ERR-SOURCE-EVIDENCE-RETAINED-WITH-OMISSION-001` | retained source evidence cannot declare an omission reason | remove omission reason or mark not-retained |
| `ERR-SOURCE-EVIDENCE-STATEMENT-MALFORMED-001` | source evidence statement is empty or exceeds 512 bytes | constrain statement to 1..=512 UTF-8 bytes |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-ABSOLUTE-PATH-001` | retained source custody storage handle contains forbidden absolute path or url | provide relative or content-addressed storage handle |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-DISALLOWED-CHARACTER-001` | retained source custody storage handle contains a character outside ASCII '[A-Za-z0-9._-]' and '/' (including space, control, bidi, format and non-ASCII characters) | supply a handle made only of allow-listed characters |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-EMPTY-SEGMENT-001` | retained source custody storage handle has an empty segment (doubled or trailing '/') | remove the empty segment; do not retry unchanged |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-MALFORMED-001` | tombstoned, no longer emitted: superseded by the EMPTY-SEGMENT, OVER-LENGTH and DISALLOWED-CHARACTER storage handle identities | not applicable; retained so the stable ID is never reused |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-OVER-LENGTH-001` | retained source custody storage handle exceeds 4096 bytes | shorten the storage handle to at most 4096 bytes |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-PERCENT-ENCODING-REFUSED-001` | retained source custody storage handle contains '%'; percent-encoding is refused rather than decoded | supply the literal allow-listed handle without percent-encoding |
| `ERR-SOURCE-EVIDENCE-STORAGE-HANDLE-TRAVERSAL-001` | retained source custody storage handle has a '.' or '..' segment | remove path traversal components from storage handle |
| `ERR-SOURCE-EVIDENCE-UNKNOWN-CLASSIFICATION-001` | unknown source evidence classification string token | supply a registered classification token |
| `ERR-SOURCE-EVIDENCE-UNKNOWN-CUSTODY-TAG-001` | unknown source custody binary wire tag | supply a registered custody tag |
| `ERR-SOURCE-EVIDENCE-UNKNOWN-OMISSION-REASON-001` | unknown omission reason string token | supply a registered omission reason token |
| `ERR-SOURCE-EVIDENCE-UNSUPPORTED-VERSION-001` | unsupported source evidence binary wire format version | encode with current supported format version |
| `ERR-SOURCE-EVIDENCE-WITNESS-EQUALS-SOURCE-DIGEST-001` | continuity witness cannot equal source digest | supply distinct continuity witness |
| `ERR-SOURCE-EVIDENCE-WITNESS-REQUIRED-001` | continuity witness classification requires a continuity witness digest | provide continuity witness or change classification |
| `ERR-STREAM-CONTINUITY-001` | gaps/jitter exceed contract | degrade coverage; bounded recovery |
| `ERR-STREAM-NO-FIRST-FRAME-001` | adapter accepted but no decodable frame before budget | reconnect or fail; never claim coverage |
| `ERR-TIME-INTERVAL-INVERTED-001` | capture or transit interval earliest bound exceeds latest bound | correct interval bounds before evaluation |
| `ERR-VW-CORRUPT-FILE-001` | view registry or markdown documentation file is missing or corrupt | repair or restore the view registry file |
| `ERR-VW-MISSING-FIELD-001` | view row or registry metadata lacks a mandatory field or is empty/corrupt | declare all mandatory fields in the view row |
| `ERR-VW-REGISTRY-DRIFT-001` | view registry row drift between machine registry and markdown mirror | synchronize architecture/agent_views.json and registries/AGENT_VIEWS.md |
| `ERR-VW-RUST-DRIFT-001` | typed Rust view table drifted from or is missing versus the machine registry | regenerate crates/fss-core/src/agent_view.rs canonical rows from architecture/agent_views.json |
| `ERR-VW-SEMANTIC-INVARIANT-001` | view semantic invariant violation: token bound contradiction, unregistered gate/status, or operation default view foreign-key miss | enforce the registered view row invariants and default-view foreign keys |
| `ERR-VW-STABLE-ID-REUSED-001` | view stable identifier was reused, duplicated, or renumbered outside AVIEW-001..008 | allocate a new unique stable identifier; never reuse stable IDs |
| `ERR-WATCH-001` | model-free watch refused by the foreground, tracker, zone gate, event contract or storage owner | inspect the cause; retry only after repair |
| `ERR-WATCH-APPROVAL-STALE-001` | an approval digest matches no candidate proposal of this exact analysis; nothing was published | rerun without approval and review the current proposal digests |
| `ERR-WATCH-LIMIT-001` | watch candidate, detection or active-track bound reached; nothing is silently dropped | narrow the range or zones, or raise thresholds |
| `ERR-WATCH-PLAN-INVALID-001` | model-free watch plan is outside its bounds (range 1..128 frames, 1..16 zones, zone ids, detector/tracker thresholds) | correct the plan; do not retry unchanged |
| `ERR-WATCH-SOURCE-GAP-001` | a retained source gap lies inside the watch range; background and track continuity cannot bridge omitted frames | split the range at the gap |

---
*Robot documentation generated deterministically by `scripts/generate_robot_docs.py`.*
