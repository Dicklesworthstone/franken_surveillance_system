# Agent operation registry

Machine source: `architecture/agent_operations.json`. Semantic protocol: `fss/1`.

Every operation accepts `fss.agent_request_envelope.v1` and returns `fss.agent_response_envelope.v1`. The table names the operation-specific typed request payload; response payloads are an allowlisted set in the machine registry.

The current public snapshot is `gen:fss1:public-v2` in
`architecture/fss1_public_registry.json`. Its only operation-contract addition is
`fss.agent_cognitive_envelope.v2` in the `AOP-006` response allowlist, carrying the
actual context pack and compression receipt for an admitted native probe. Stable
operation/resource IDs, requests, defaults and all existing payloads are unchanged.

`architecture/fss1_public_registry.v1.json` preserves the exact public-v1 bytes and
freeze digest. Existing durable sessions, cases, workspaces and follow pages keep
`reference_contract_basis()` and the original native row encoding. The new payload
requires the explicit `probe_contract_basis()` presentation profile: public-v2 plus
`fss.agent_probe_schema_catalog.v1`, which binds the frozen reference schema catalog
and exact V2 cognitive schema bytes. Basis-aware native selectors refuse mixed or
unknown profiles; the default row codec and V1 schema stay frozen. Both generations
have independent immutable pins checked by the registry validators.

| ID | Name | Owner | Mode | Default view | Typed request payload | Effectful | Durable | Gate | Status |
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

Suboperations such as counterfactual comparison, evidence hydration, work claiming, repair planning, reconciliation, resolution, and adjudication are typed targets or intent families under these operations. They do not create a second public verb universe. An effectful operation still requires its domain capability and ordinary prepare/revalidate/idempotency/fencing semantics.

## Operation lifecycle statuses

`specified` · `active` · `preview` · `deprecated` · `superseded` · `tombstone` · `tombstoned`

## Compatibility classes

`backward_compatible`
