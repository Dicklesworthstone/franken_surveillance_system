# Agent view registry

Machine source: `architecture/agent_views.json`.

| ID | Name | Owner | Purpose | Target tokens | Maximum tokens | Gate | Status |
|---|---|---|---|---:|---:|---|---|
| `AVIEW-001` | `pulse` | `fss-context-pack` | tiny high-severity meaningful delta, sensor-health, coverage-loss, effect-uncertainty, and obligation heartbeat | 120 | 300 | `QL-AGENT-001` | `specified` |
| `AVIEW-002` | `brief` | `fss-situation` | primary mission SituationCapsule answering what is established, what materially different worlds remain possible, what changed, why it matters, and what is robustly or conditionally safe to do next | 800 | 1600 | `QL-AGENT-001` | `specified` |
| `AVIEW-003` | `case` | `fss-investigation` | investigation question, competing hypotheses, evidence, contradictions, unknowns, discriminators, and stop rule | 3000 | 5000 | `QL-AGENT-001` | `specified` |
| `AVIEW-004` | `forensic` | `fss-context-pack` | broad exact evidence graph, source spans, receipts, alternative derivations, and replay handles | 8000 | 16000 | `QL-AGENT-001` | `specified` |
| `AVIEW-005` | `operation` | `fss-obligation` | one durable plan/effect/task, progress, expected terminal proof, obligations, and reconciliation | 600 | 1200 | `QL-AGENT-001` | `specified` |
| `AVIEW-006` | `handoff` | `fss-handoff` | minimum sufficient state for another agent to resume without rediscovery or hidden staleness | 1800 | 3200 | `QL-AGENT-001` | `specified` |
| `AVIEW-007` | `decision_diff` | `fss-explain` | why a conclusion, priority, hypothesis, plan, or preferred affordance changed | 900 | 1800 | `QL-AGENT-001` | `specified` |
| `AVIEW-008` | `epistemic_map` | `fss-knowledge` | known/estimated/unknown/conflicted/stale/not-observable/redacted/indeterminate map plus certified core, material alternative worlds, adversarial residuals, and discriminators | 1500 | 3000 | `QL-AGENT-001` | `specified` |

Token values are design targets and admission budgets, not measured current behavior. Every bounded view carries a selection/compression receipt, omitted counts and reasons, completeness/coverage state, and expansion handles.
