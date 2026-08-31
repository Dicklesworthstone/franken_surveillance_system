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

The quality SLOs intentionally defer numeric release thresholds until the sealed corpus and
exposure denominator exist. Inventing a percentage before that would be theater.
