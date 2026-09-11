# SLO registry

All values below are **targets to qualify**, not current results. Exact numbers can be revised only
with an ADR and operation-cost derivation; revisions preserve the old ID as history.

| ID | Target | Measurement surface | Status | Proof root |
|---|---|---|---|---|
| `SLO-INGEST-001` | no acknowledged source segment lost after canonical publish | qualified local storage profile and declared crash model | target | - |
| `SLO-LIVE-001` | p95 glass-to-glass live-proxy latency ≤ 750 ms on LAN | qualified camera/codec/profile; excludes vendor-cloud relay unless separately measured | target | - |
| `SLO-DETECT-001` | p95 first event hypothesis ≤ 1.5 s after first observable threat evidence | edge-GPU reference profile and target camera count | target | - |
| `SLO-ALERT-001` | p95 alert dispatch ≤ 3 s after policy corroboration | healthy configured channel; delivery reported separately | target | - |
| `SLO-QUERY-001` | p95 bounded event-status query ≤ 100 ms without model refinement | warm local ledger/index reference scale | target | - |
| `SLO-AGENT-001` | initial agent answer ≤ 800 tokens and ≤ 250 ms, refinement resumable | declared query class and warm local projections | target | - |
| `SLO-CAL-001` | accepted certificate meets registered reprojection/time residual bounds | declared camera/session class; numbers set by gate fixture | target | - |
| `SLO-CONTINUITY-001` | ≥ 99.9% qualified observation-window continuity for wired/reference sensors | excludes configured maintenance; battery/vendor sensors separately classified | target | - |
| `SLO-ARCHIVE-001` | every published event root passes scheduled restore sample | declared sample cadence and backend availability | target | - |
| `SLO-COST-001` | cognition cost/camera-month stays within deployment budget | derived from exact routing and hardware manifest | target | - |
| `SLO-COST-002` | archive cost/object operation stays within provider manifest budget | dated price manifest and retention workload | target | - |
| `SLO-QUALITY-001` | maximize event AUPRC subject to registered recall/false-alert floor | sealed security corpus; no universal claim | target | - |
| `SLO-RECALL-001` | release-specific lower confidence bound for observable staged threats | threshold fixed before held-out run; value set at `GATE-080` | target | - |
| `SLO-FALSE-ALERT-001` | release-specific upper bound on false alerts/property-day | defined benign exposure distribution; value set at `GATE-080` | target | - |
| `SLO-QUIESCENCE-001` | zero owned tasks/processes/descriptors after bounded shutdown | all qualified adapters/model/codec hosts | target | - |
| `SLO-DELETE-001` | deletion closure reaches terminal proof or explicit blocker by policy deadline | exact backend/hold class | target | - |
| `SLO-MODEL-001` | model package import and qualification meet registered operator, conformance, and repair bounds | frozen model package and target platform tuple; oracle comparison verified | target | - |
| `SLO-RECOVERY-001` | authority checkpoint published and verified within bounded replay tail and recovery time | clean anchor and declared delta backlog; excludes uncommitted transaction tail | target | - |
| `SLO-RELEASE-001` | complete release matrix qualified and published root-last with clean sibling closure | controlled native host with full qualification lane pass; excludes unverified targets | target | - |
| `SLO-PRIVACY-001` | tombstone: superseded by `SLO-DELETE-001` | historical deletion-closure reference preserved for audit; canonical target is `SLO-DELETE-001` | tombstone | - |
| `SLO-AGENT-ORIENT-001` | p95 cold mission orientation reaches a useful `SituationCapsule` in ≤ 2 semantic calls and ≤ 1,600 output tokens | warm local authority/projections; exclusions and degraded dimensions remain explicit | target | - |
| `SLO-AGENT-FOLLOW-001` | p95 material committed delta available to a subscribed local agent ≤ 250 ms | excludes source capture latency; terminal/coverage/contradiction/effect-uncertainty deltas never coalesced away | target | - |
| `SLO-AGENT-COMPRESSION-001` | zero task-critical contradiction, not-observable domain, hard clamp, effect indeterminacy, or urgent obligation omitted in qualified context packs | sealed agent scenario corpus and declared view/token budget | target | - |
| `SLO-AGENT-HANDOFF-001` | resumed agent reconstructs mission-critical state with zero hidden conversational prerequisites and explicitly classifies all stale/invalidated items | qualified handoff/resume drift matrix | target | - |
| `SLO-AGENT-OBLIGATION-001` | every agent-started durable task/effect is owned and reaches terminal, delegated, or explicitly indeterminate reconciliation state | qualified cancellation/crash/lost-ACK schedules | target | - |
| `SLO-AGENT-ACCRETION-001` | promoted memory/procedure improves held-out future task success per resource without worsening unsafe-action, privacy, or evidence-error rate | promotion-specific sealed before/after corpus | target | - |
| `SLO-AGENT-DECISION-001` | agent task success/calibration is non-inferior to full-context baseline while total cognitive cost is lower | sealed decision corpus and declared cost vector; safety/coverage clamps fixed first | target | - |
| `SLO-AGENT-ROBUSTNESS-001` | zero protected high-consequence residual world removed without a named witness, explicit scope/policy decision, or authorized adjudication; every consequential affordance names its robustness class and unsafe worlds | sealed possible-world and adversarial-coverage corpus | target | - |
| `SLO-AGENT-RESUME-001` | p95 local resume/rebase emits stale/invalidated state and first valid affordances within 750 ms | warm mission ledger and bounded workspace size | target | - |

The quality SLOs intentionally defer numeric release thresholds until the sealed corpus and
exposure denominator exist. Inventing a percentage before that would be theater.
