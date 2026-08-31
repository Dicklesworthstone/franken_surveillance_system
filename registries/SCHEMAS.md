# Schema registry

| ID | Schema | File | Authority | Compatibility rule |
|---|---|---|---|---|
| `SCHEMA-SENSOR-CAPSULE-001` | `fss.sensor_capsule.v1` | `schemas/sensor_capsule.v1.json` | authority | append/supersede; no silent timestamp/source reinterpretation |
| `SCHEMA-EVENT-HYPOTHESIS-001` | `fss.event_hypothesis.v1` | `schemas/event_hypothesis.v1.json` | authority | immutable revisions; evidence required after hypothesis |
| `SCHEMA-EVIDENCE-BUNDLE-001` | `fss.evidence_bundle.v1` | `schemas/evidence_bundle.v1.json` | authority/export | old proof bundles remain replayable or explicitly unsupported |
| `SCHEMA-OPERATION-RECEIPT-001` | `fss.operation_receipt.v1` | `schemas/operation_receipt.v1.json` | effect truth | state monotonicity; idempotency identity preserved |
| `SCHEMA-CALIBRATION-CERT-001` | `fss.calibration_certificate.v1` | `schemas/calibration_certificate.v1.json` | authority | generation immutable; invalidation creates new state |
| `SCHEMA-EVIDENCE-ANCHOR-001` | `fss.evidence_anchor.v1` | `schemas/evidence_anchor.v1.json` | authority | no mixed generations; additions require new epoch semantics |
| `SCHEMA-COVERAGE-WITNESS-001` | `fss.coverage_witness.v1` | `schemas/coverage_witness.v1.json` | authority/query | absence claims require declared domain and stop reason |
| `SCHEMA-TRANSFER-MANIFEST-001` | `fss.transfer_manifest.v1` | `schemas/transfer_manifest.v1.json` | authority/transfer | root-last; object and closure identities immutable |
| `SCHEMA-GRAPH-WITNESS-001` | `fss.graph_algorithm_witness.v1` | `schemas/graph_algorithm_witness.v1.json` | derived/evidence | algorithm/projection/policy identity and output digest preserved |
| `SCHEMA-DECISION-CARD-001` | `fss.decision_card.v1` | `schemas/decision_card.v1.json` | policy/evidence | hard constraints and alternatives retained; no silent rewrite |
| `SCHEMA-RELEASE-RECEIPT-001` | `fss.release_qualification_receipt.v1` | `schemas/release_qualification_receipt.v1.json` | release custody | same source/sibling/toolchain identity required for aggregation |
| `SCHEMA-ADAPTER-CERT-001` | `fss.adapter_compatibility_certificate.v1` | `schemas/adapter_compatibility_certificate.v1.json` | compatibility | exact tuple only; invalidator transitions revoke/degrade |
| `SCHEMA-CANCEL-DRAIN-001` | `fss.cancellation_drain_certificate.v1` | `schemas/cancellation_drain_certificate.v1.json` | runtime evidence | terminal/indeterminate outcome and outstanding effects preserved |
| `SCHEMA-EVIDENCE-DELTA-001` | `fss.evidence_delta_batch.v1` | `schemas/evidence_delta_batch.v1.json` | authority/version universe | basis/new anchors and ordered delta identities preserved |
| `SCHEMA-TRANSFER-RECEIPT-001` | `fss.transfer_receipt.v1` | `schemas/transfer_receipt.v1.json` | transfer evidence | path, repair, closure, publication, and retrievability states remain distinct |
| `SCHEMA-MODEL-PACKAGE-001` | `fss.model_package_manifest.v1` | `schemas/model_package_manifest.v1.json` | model authority/package | immutable package root; operator/tensor/preprocess/numeric/license identities preserved |
| `SCHEMA-MODEL-RECEIPT-001` | `fss.model_execution_receipt.v1` | `schemas/model_execution_receipt.v1.json` | derived/model evidence | input/model/plan/backend/numeric/budget/outcome and output identities preserved |
| `SCHEMA-RELEASE-BUILD-001` | `fss.release_build_receipt.v1` | `schemas/release_build_receipt.v1.json` | release custody | native target/toolchain/source/lock/manifest/smoke identities immutable |
| `SCHEMA-RELEASE-STAGE-001` | `fss.release_stage_verification.v1` | `schemas/release_stage_verification.v1.json` | release custody | stage inventory and content digests preserved exactly |
| `SCHEMA-SOURCE-MANIFEST-001` | `fss.source_manifest.v1` | `schemas/source_manifest.v1.json` | source custody | clean tracked source identity and executable bits preserved |
| `SCHEMA-LICENSE-INVENTORY-001` | `fss.license_inventory.v1` | `schemas/license_inventory.v1.json` | supply-chain evidence | package identity/source/license fields remain auditable |
| `SCHEMA-QUALIFICATION-ROOT-002` | `fss.qualification_root.v2` | `schemas/release_qualification_root.v2.json` | aggregate release custody | primary/support artifact digests, claim boundary, and signing state immutable |
| `SCHEMA-AGENT-CONTRACT-BASIS-001` | `fss.agent_contract_basis.v1` | `schemas/agent_contract_basis.v1.json` | semantic compatibility | protocol, schema/ontology/operation/view/capability/error/cost registry digests, producer release, and accepted nightly remain exact |
| `SCHEMA-AGENT-REQUEST-001` | `fss.agent_request_envelope.v1` | `schemas/agent_request_envelope.v1.json` | transport request | contract basis, operation, lifecycle, anchor/workspace preconditions, view, targets, typed payload, budget, authority/privacy request, continuation, idempotency, and taint remain explicit |
| `SCHEMA-AGENT-MISSION-001` | `fss.agent_mission.v1` | `schemas/agent_mission.v1.json` | mission/workspace | mission revisions preserve scope, constraints, budgets, capability projection, and terminal criteria |
| `SCHEMA-AGENT-SESSION-001` | `fss.agent_session.v1` | `schemas/agent_session.v1.json` | session/runtime | session identity, authority, privacy projection, view, continuations, and expiry remain explicit |
| `SCHEMA-AGENT-WORKSPACE-001` | `fss.agent_session_capsule.v1` | `schemas/agent_session_capsule.v1.json` | workspace continuity | workspace revisions are immutable and resume records stale and invalidated state |
| `SCHEMA-AGENT-KNOWLEDGE-001` | `fss.agent_knowledge_cell.v1` | `schemas/agent_knowledge_cell.v1.json` | epistemic projection | knowledge state, provenance, evidence, validity, uncertainty, and decision relevance remain separate |
| `SCHEMA-AGENT-WORLD-ENVELOPE-001` | `fss.agent_world_envelope.v1` | `schemas/agent_world_envelope.v1.json` | agent world model | nominal estimate, certified core and absences, material alternatives, adversarial residuals, unresolved dimensions, discriminators, and selection witness remain separate and anchor-pinned |
| `SCHEMA-AGENT-SITUATION-001` | `fss.agent_situation_frame.v1` | `schemas/agent_situation_frame.v1.json` | situation projection | task-relative selection changes only through a new frame and selection witness |
| `SCHEMA-AGENT-SITUATION-CAPSULE-001` | `fss.situation_capsule.v1` | `schemas/situation_capsule.v1.json` | agent driver projection | frame, meaningful delta, obligations, resources, affordances, context, and compression proof remain one anchor-pinned publication |
| `SCHEMA-AGENT-DELTA-001` | `fss.agent_meaningful_delta.v1` | `schemas/agent_meaningful_delta.v1.json` | follow/continuity | terminal, contradiction, coverage, plan-invalidation, and effect-uncertainty deltas cannot be coalesced away |
| `SCHEMA-AGENT-HYPOTHESIS-001` | `fss.agent_hypothesis_workspace.v1` | `schemas/agent_hypothesis_workspace.v1.json` | investigation cognition | competing hypotheses and support, contradiction, missing evidence, predictions, and falsifiers remain addressable |
| `SCHEMA-AGENT-INVESTIGATION-001` | `fss.investigation_state.v1` | `schemas/investigation_state.v1.json` | investigation cognition | case revisions preserve question, decision, hypotheses, probes, stop rules, and residual uncertainty |
| `SCHEMA-AGENT-QUERY-001` | `fss.agent_query_plan.v1` | `schemas/agent_query_plan.v1.json` | query cognition | compiled interpretation, targets, authority, privacy, cost, and output view are reviewable and bounded |
| `SCHEMA-AGENT-COMPRESSION-001` | `fss.semantic_compression_receipt.v1` | `schemas/semantic_compression_receipt.v1.json` | context projection | selected and omitted classes, critical preservation, stop reason, and expansion handles remain explicit |
| `SCHEMA-AGENT-CONTEXT-001` | `fss.semantic_context_pack.v1` | `schemas/semantic_context_pack.v1.json` | context projection | pack basis, view, items, compression receipt, token count, continuation, and digest are immutable |
| `SCHEMA-AGENT-AFFORDANCE-001` | `fss.agent_affordance.v1` | `schemas/agent_affordance.v1.json` | decision support | value, cost, risk, authority, reversibility, invalidators, alternatives, and expected proof remain decomposed |
| `SCHEMA-AGENT-OBJECTIVE-001` | `fss.agent_objective_contract.v1` | `schemas/agent_objective_contract.v1.json` | control intent | hard constraints, budgets, authority, success, failure, stop predicates, and terminal proof are immutable |
| `SCHEMA-AGENT-PLAN-001` | `fss.agent_control_plan.v1` | `schemas/agent_control_plan.v1.json` | control plan | step types, witnesses, effect boundaries, contingencies, budgets, and decision digest remain immutable |
| `SCHEMA-AGENT-EPISODE-001` | `fss.agent_execution_episode.v1` | `schemas/agent_execution_episode.v1.json` | execution evidence | original predictions, receipts, outcome, resource use, residual uncertainty, and attribution remain auditable |
| `SCHEMA-AGENT-WORK-CLAIM-001` | `fss.agent_work_claim.v1` | `schemas/agent_work_claim.v1.json` | multi-agent coordination | scope, basis, owner, lease, progress, result, expiry, and no-effect-authority property remain explicit |
| `SCHEMA-AGENT-FINDING-001` | `fss.agent_finding.v1` | `schemas/agent_finding.v1.json` | multi-agent cognition | claim, epistemic state, evidence, assumptions, coverage, method receipts, and withdrawal state remain auditable |
| `SCHEMA-AGENT-FEEDBACK-001` | `fss.agent_feedback_proposal.v1` | `schemas/agent_feedback_proposal.v1.json` | advisory feedback | correction or outcome signal is evidence-linked and cannot directly mutate active policy |
| `SCHEMA-AGENT-LEARNING-001` | `fss.agent_learning_proposal.v1` | `schemas/agent_learning_proposal.v1.json` | advisory learning | applicability, evidence, counterexamples, harmful outcomes, validation, expiry, and promotion remain explicit |
| `SCHEMA-AGENT-EXPERIENCE-001` | `fss.experience_capsule.v1` | `schemas/experience_capsule.v1.json` | operational memory | episode signature, signals, failures, costs, applicability, decay, and privacy remain auditable |
| `SCHEMA-AGENT-HANDOFF-001` | `fss.agent_handoff_capsule.v1` | `schemas/agent_handoff_capsule.v1.json` | handoff custody | mission, situation, cases, plans, obligations, unknowns, authority, budgets, continuation, and expiry remain complete |
| `SCHEMA-AGENT-COGNITIVE-ENVELOPE-001` | `fss.agent_cognitive_envelope.v1` | `schemas/agent_cognitive_envelope.v1.json` | semantic response | anchor, knowledge/provenance status, coverage, omissions, budget, evidence, affordances, and continuity remain explicit |
| `SCHEMA-AGENT-RESPONSE-001` | `fss.agent_response_envelope.v1` | `schemas/agent_response_envelope.v1.json` | transport response | operation, session, anchors, outcome, payload, errors, budgets, proof, continuation, and safe retry remain explicit |
| `SCHEMA-CAPABILITIES-001` | `fss.capabilities.v1` | `CLI output` | product boundary | additions compatible; changed meaning requires new schema |
| `SCHEMA-DOCTOR-001` | `fss.doctor.v1` | `CLI output` | diagnostics | bounded and secret-free |
| `SCHEMA-STATUS-001` | `fss.status.v1` | `CLI output` | product boundary | status fields cannot imply unsupported readiness |

Binary media, ledger, search-segment, graph-run, and release formats additionally require magic, version, bounded lengths, canonical encoding, migration fixtures, corruption tests, and a named format owner before implementation.
