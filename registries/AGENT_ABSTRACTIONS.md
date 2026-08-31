# Agent abstraction registry

Stable abstraction identifiers are never renumbered. Machine source: `architecture/agent_abstraction_stack.json`. The public operation and view universes are separately frozen in `architecture/agent_operations.json` and `architecture/agent_views.json`.

## Abstraction tower

| ID | Name | Owner | Agent question | Invariant | Status |
|---|---|---|---|---|---|
| `AGT-LAYER-001` | `runtime_authority_and_custody` | `asupersync/authority/object owners` | What work, authority, budget, identity, time, and object custody exist? | `INV-006` | `normative` |
| `AGT-LAYER-002` | `source_evidence` | `fss-capture/fss-media/fss-chronicle` | What exact packets, files, measurements, continuity, and capture-time intervals exist? | `INV-003` | `normative` |
| `AGT-LAYER-003` | `world_facts_and_coverage` | `fss-chronicle/fss-coverage` | What did the system authoritatively observe or do at one anchor? | `INV-063` | `normative` |
| `AGT-LAYER-004` | `derived_beliefs` | `fss-perception/fss-association/fss-graph` | What entities, tracks, events, relations, and uncertainties are supported? | `INV-069` | `normative` |
| `AGT-LAYER-005` | `situation_capsule` | `fss-situation/fss-context-pack/fss-affordance` | What is established, what materially different worlds remain possible, what changed, and what is robustly or conditionally safe to do next? | `INV-116` | `normative` |
| `AGT-LAYER-006` | `investigation_and_hypotheses` | `fss-investigation` | Which competing explanations remain viable and how can they be discriminated? | `INV-104` | `normative` |
| `AGT-LAYER-007` | `affordance_frontier` | `fss-attention/fss-affordance` | What can be done next, under current capability and budget, and why is it worth doing? | `INV-106` | `normative` |
| `AGT-LAYER-008` | `plan_and_effect` | `fss-agent-plan/fss-effect` | Which witnessed contingent DAG should run and did each effect happen? | `INV-088` | `normative` |
| `AGT-LAYER-009` | `outcome_and_episode` | `fss-episode` | What was predicted, executed, observed, consumed, and left uncertain? | `INV-098` | `normative` |
| `AGT-LAYER-010` | `learning_and_memory` | `fss-learning` | What reusable rule, anti-pattern, fixture, or runbook improvement should be proposed? | `INV-094` | `normative` |
| `AGT-LAYER-011` | `workspace_and_handoff` | `fss-agent-session/fss-handoff` | How can this mission resume or transfer without rediscovery or hidden staleness? | `INV-096` | `normative` |

## Hydration ladder

| Level | Name | Content |
|---|---|---|
| `H0` | `identity` | digest, type, time/spatial bounds, source, availability, cost, and authority |
| `H1` | `semantic_synopsis` | typed facts, knowledge states, provenance, contradictions, quality, and omissions |
| `H2` | `decision_artifact` | authorized redacted keyframes, crops, trajectories, graph neighborhoods, or audio features |
| `H3` | `source_evidence` | authorized original encoded packets, object bytes, exact metadata, or full-resolution media |
| `H4` | `laboratory_expansion` | replay bundle, intermediates, alternate decoders/models, and oracle comparisons |

## Response composition

- **Primary driver publication:** `SituationCapsule`.
- **Inner mission-relative projection:** `SituationFrame`.
- **Bounded materialization:** `ContextPack` plus `SemanticCompressionReceipt`.
- **Generic decision payload:** `AgentCognitiveEnvelope`.
- **Universal lifecycle/transport wrapper:** `AgentResponseEnvelope`.

SituationCapsule is the primary orient/resume publication and contains the mission-relative SituationFrame plus meaningful delta, obligations, resource state, affordances, and context/compression proof. The SituationFrame carries the WorldEnvelope; the SituationCapsule adds the categorized control envelope. AgentCognitiveEnvelope is the general decision-bearing semantic payload. AgentResponseEnvelope adds lifecycle/retry/budget/proof/continuation framing without redefining meaning.

## Evidence–possibility–control projection

- **World model:** `WorldEnvelope` = nominal estimate + certified core/absences + material alternatives/adversarial residuals.
- **Control projection:** `SituationCapsule.controlEnvelope` = robust, conditional, information-gathering, wait/watch, and blocked affordance IDs.
- **Robustness rule:** a consequential action is either robust across every protected material world or explicitly conditional on named worlds, current assumptions, approval, and discriminating evidence.

This makes the abstraction tower operationally closed: evidence defines the possible worlds, possible worlds constrain the control envelope, actions produce new evidence, and the next anchor recomputes the envelope.

## Registered operation references

The abstraction stack admits exactly these public operation IDs in revision 1:

`AOP-001` `AOP-002` `AOP-003` `AOP-004` `AOP-005` `AOP-006` `AOP-007` `AOP-008` `AOP-009` `AOP-010` `AOP-011` `AOP-012` `AOP-013` `AOP-014`

## Registered view references

`AVIEW-001` `AVIEW-002` `AVIEW-003` `AVIEW-004` `AVIEW-005` `AVIEW-006` `AVIEW-007` `AVIEW-008`
