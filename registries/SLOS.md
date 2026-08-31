# SLO registry

All values below are **targets to qualify**, not current results. Exact numbers can be revised only
with an ADR and operation-cost derivation; revisions preserve the old ID as history.

| ID | Target | Scope/condition |
|---|---|---|
| `SLO-INGEST-001` | no acknowledged source segment lost after canonical publish | qualified local storage profile and declared crash model |
| `SLO-LIVE-001` | p95 glass-to-glass live-proxy latency ≤ 750 ms on LAN | qualified camera/codec/profile; excludes vendor-cloud relay unless separately measured |
| `SLO-DETECT-001` | p95 first event hypothesis ≤ 1.5 s after first observable threat evidence | edge-GPU reference profile and target camera count |
| `SLO-ALERT-001` | p95 alert dispatch ≤ 3 s after policy corroboration | healthy configured channel; delivery reported separately |
| `SLO-QUERY-001` | p95 bounded event-status query ≤ 100 ms without model refinement | warm local ledger/index reference scale |
| `SLO-AGENT-001` | initial agent answer ≤ 800 tokens and ≤ 250 ms, refinement resumable | declared query class and warm local projections |
| `SLO-CAL-001` | accepted certificate meets registered reprojection/time residual bounds | declared camera/session class; numbers set by gate fixture |
| `SLO-CONTINUITY-001` | ≥ 99.9% qualified observation-window continuity for wired/reference sensors | excludes configured maintenance; battery/vendor sensors separately classified |
| `SLO-ARCHIVE-001` | every published event root passes scheduled restore sample | declared sample cadence and backend availability |
| `SLO-COST-001` | cognition cost/camera-month stays within deployment budget | derived from exact routing and hardware manifest |
| `SLO-COST-002` | archive cost/object operation stays within provider manifest budget | dated price manifest and retention workload |
| `SLO-QUALITY-001` | maximize event AUPRC subject to registered recall/false-alert floor | sealed security corpus; no universal claim |
| `SLO-RECALL-001` | release-specific lower confidence bound for observable staged threats | threshold fixed before held-out run; value set at `GATE-080` |
| `SLO-FALSE-ALERT-001` | release-specific upper bound on false alerts/property-day | defined benign exposure distribution; value set at `GATE-080` |
| `SLO-QUIESCENCE-001` | zero owned tasks/processes/descriptors after bounded shutdown | all qualified adapters/model/codec hosts |
| `SLO-DELETE-001` | deletion closure reaches terminal proof or explicit blocker by policy deadline | exact backend/hold class |
| `SLO-AGENT-ORIENT-001` | p95 cold mission orientation reaches a useful `SituationCapsule` in ≤ 2 semantic calls and ≤ 1,600 output tokens | warm local authority/projections; exclusions and degraded dimensions remain explicit |
| `SLO-AGENT-FOLLOW-001` | p95 material committed delta available to a subscribed local agent ≤ 250 ms | excludes source capture latency; terminal/coverage/contradiction/effect-uncertainty deltas never coalesced away |
| `SLO-AGENT-COMPRESSION-001` | zero task-critical contradiction, not-observable domain, hard clamp, effect indeterminacy, or urgent obligation omitted in qualified context packs | sealed agent scenario corpus and declared view/token budget |
| `SLO-AGENT-HANDOFF-001` | resumed agent reconstructs mission-critical state with zero hidden conversational prerequisites and explicitly classifies all stale/invalidated items | qualified handoff/resume drift matrix |
| `SLO-AGENT-OBLIGATION-001` | every agent-started durable task/effect is owned and reaches terminal, delegated, or explicitly indeterminate reconciliation state | qualified cancellation/crash/lost-ACK schedules |
| `SLO-AGENT-ACCRETION-001` | promoted memory/procedure improves held-out future task success per resource without worsening unsafe-action, privacy, or evidence-error rate | promotion-specific sealed before/after corpus |
| `SLO-AGENT-DECISION-001` | agent task success/calibration is non-inferior to full-context baseline while total cognitive cost is lower | sealed decision corpus and declared cost vector; safety/coverage clamps fixed first |
| `SLO-AGENT-ROBUSTNESS-001` | zero protected high-consequence residual world removed without a named witness, explicit scope/policy decision, or authorized adjudication; every consequential affordance names its robustness class and unsafe worlds | sealed possible-world and adversarial-coverage corpus |
| `SLO-AGENT-RESUME-001` | p95 local resume/rebase emits stale/invalidated state and first valid affordances within 750 ms | warm mission ledger and bounded workspace size |

The quality SLOs intentionally defer numeric release thresholds until the sealed corpus and
exposure denominator exist. Inventing a percentage before that would be theater.
