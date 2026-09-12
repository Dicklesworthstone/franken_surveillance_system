# Operation crosswalk registry

Machine source: `architecture/operation_crosswalk.json`. Semantic protocol: `fss/1`.

Crosswalk establishing the exact bijective mapping between registered `fss/1` operations and their presentation and interface surfaces across the CLI, library entry points, and MCP tools, together with stable error and exit identities.

Under AGENTS.md, machine output uses the registered `AgentResponseEnvelope` with stable exit and error identities; no transport may invent a parallel vocabulary.

| Operation ID | Operation Name | Owner | CLI Command | Library Entry Point | MCP Tool Name | Primary Error Code | Exit Identity | Status |
|---|---|---|---|---|---|---|---|---|
| `AOP-001` | `session.open` | `fss-agent-session` | `fss session open` | `fss_agent_session::session_open` | `session_open` | `ERR-AUTH-DENIED-001` | `EXIT-OK-000` | `specified` |
| `AOP-002` | `session.resume` | `fss-agent-session` | `fss session resume` | `fss_agent_session::session_resume` | `session_resume` | `ERR-AGENT-HANDOFF-INVALID-001` | `EXIT-OK-000` | `specified` |
| `AOP-003` | `session.orient` | `fss-situation` | `fss session orient` | `fss_situation::session_orient` | `session_orient` | `ERR-AGENT-CONTEXT-INCOMPLETE-001` | `EXIT-OK-000` | `specified` |
| `AOP-004` | `session.follow` | `fss-context-pack` | `fss session follow` | `fss_context_pack::session_follow` | `session_follow` | `ERR-AGENT-RESNAPSHOT-001` | `EXIT-OK-000` | `specified` |
| `AOP-005` | `query` | `fss-query-plan` | `fss query` | `fss_query_plan::query` | `query` | `ERR-AGENT-AMBIGUOUS-001` | `EXIT-OK-000` | `specified` |
| `AOP-006` | `investigate` | `fss-investigation` | `fss investigate` | `fss_investigation::investigate` | `investigate` | `ERR-AGENT-CASE-BUDGET-001` | `EXIT-OK-000` | `specified` |
| `AOP-007` | `plan` | `fss-agent-plan` | `fss plan` | `fss_agent_plan::plan` | `plan` | `ERR-PRECONDITION-STALE-001` | `EXIT-OK-000` | `specified` |
| `AOP-008` | `commit` | `fss-effect` | `fss commit` | `fss_effect::commit` | `commit` | `ERR-EFFECT-INDETERMINATE-001` | `EXIT-OK-000` | `specified` |
| `AOP-009` | `wait` | `fss-obligation` | `fss wait` | `fss_obligation::wait` | `wait` | `ERR-OP-TIMEOUT-001` | `EXIT-OK-000` | `specified` |
| `AOP-010` | `cancel` | `fss-obligation` | `fss cancel` | `fss_obligation::cancel` | `cancel` | `ERR-QUIESCENCE-001` | `EXIT-OK-000` | `specified` |
| `AOP-011` | `explain` | `fss-explain` | `fss explain` | `fss_explain::explain` | `explain` | `ERR-REPLAY-DIVERGED-001` | `EXIT-OK-000` | `specified` |
| `AOP-012` | `handoff` | `fss-handoff` | `fss handoff` | `fss_handoff::handoff` | `handoff` | `ERR-AGENT-HANDOFF-INVALID-001` | `EXIT-OK-000` | `specified` |
| `AOP-013` | `feedback` | `fss-learning` | `fss feedback` | `fss_learning::feedback` | `feedback` | `ERR-AGENT-LEARNING-UNSUPPORTED-001` | `EXIT-OK-000` | `specified` |
| `AOP-014` | `doctor` | `fss-doctor` | `fss doctor` | `fss_doctor::doctor` | `doctor` | `ERR-CLI-RUNTIME-FAILURE-001` | `EXIT-OK-000` | `specified` |

## Presentation and Interface Principles

1. **Total Bijection:** Every registered `fss/1` operation maps to exactly one canonical CLI command, one library entry point, and one MCP tool name. No surface may invent a synonym or unmapped verb.
2. **Unified Envelope:** Every surface returns machine output wrapped in `fss.agent_response_envelope.v1` carrying exact `ContractBasis`, task/obligation state, and stable error/exit identities.
3. **Structured Diagnostics:** Errors produced during parsing or execution map directly to stable machine identifiers registered in `registries/ERRORS.md`.
