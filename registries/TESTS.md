# Test registry

| ID | Family | Required before |
|---|---|---|
| `TEST-CONTRACT-001` | ID/time/event/effect state-machine unit and property tests | `GATE-010` |
| `TEST-REPLAY-001` | deterministic golden replay and decision fingerprints | `GATE-010` |
| `TEST-SCHEDULE-001` | cancellation/fault schedule exploration | `GATE-020` |
| `TEST-MEDIA-MALFORMED-001` | corrupt/hostile codec/container corpus and output bounds | `GATE-020` |
| `TEST-UVC-001` | modes, reconnect, cancellation, source custody, soak | `GATE-020` |
| `TEST-RTSP-001` | auth, RTP reorder/loss, transport, reconnect, server oddities | `GATE-030` |
| `TEST-ONVIF-001` | exact Profile T/M feature/conformance matrix | `GATE-030` |
| `TEST-LEDGER-CRASH-001` | kill point at every durable transition | `GATE-040` |
| `TEST-ARCHIVE-001` | multipart partials, root-last, restore, retrievability, deletion | `GATE-040` |
| `TEST-MODEL-HOST-001` | OOM, hang, crash, malformed output, cleanup, privacy | `GATE-050` |
| `TEST-MODEL-QUALITY-001` | held-out event quality, slices, calibration, raw results | `GATE-080` |
| `TEST-TIME-001` | offset/drift/jitter/reconnect interval correctness | `GATE-060` |
| `TEST-CALIBRATION-001` | synthetic truth, held-out trajectory, moved camera, crop drift | `GATE-070` |
| `TEST-COVERAGE-001` | blind spot, degraded sensor, observability-conditioned negatives | `GATE-070` |
| `TEST-ASSOCIATION-001` | cross-camera ID precision/recall under occlusion and timing error | `GATE-080` |
| `TEST-INTRUSION-001` | staged tactics including dark/crawl/occlusion/avoidance | `GATE-080` |
| `TEST-BENIGN-001` | resident/delivery/wildlife/weather/foliage hard negatives | `GATE-080` |
| `TEST-TAMPER-001` | cover/move/dazzle/replay/disconnect/jam simulation | `GATE-080` |
| `TEST-VENDOR-001` | exact firmware/app auth/revocation/reconnect/drift/soak | `GATE-090` |
| `TEST-AGENT-001` | bounded deltas, capability denial, idempotency, token budgets | `GATE-110` |
| `TEST-PRIVACY-001` | mask-before-boundary, retention, deletion closure, bundle redaction | `GATE-120` |
| `TEST-RELEASE-001` | install/upgrade/rollback/soak/support bundle/local proof | `GATE-120` |
| `TEST-AGENT-ORIENT-001` | cold-start one-call orientation, semantic zoom, aliasing, and bounded first-useful answer | `GATE-115` |
| `TEST-AGENT-EPISTEMIC-001` | knowledge/provenance/hypothesis separation, contradictions, absence/coverage, stale/redacted/indeterminate preservation | `GATE-115` |
| `TEST-AGENT-COMPRESSION-001` | semantic compression counterfactuals, non-droppable classes, receipts, hydration and continuation | `GATE-115` |
| `TEST-AGENT-VOI-001` | probe/context/affordance value-of-information selection against static and maximal-context baselines | `GATE-115` |
| `TEST-AGENT-CONTROL-001` | query→plan→commit→wait/cancel→verify/reconcile under stale anchors, lost ACKs, crashes, and duplicate requests | `GATE-115` |
| `TEST-AGENT-HANDOFF-001` | root-last handoff/resume under anchor, policy, model, calibration, grant, and obligation drift | `GATE-115` |
| `TEST-AGENT-MULTI-001` | work-claim fencing, immutable findings, disagreement, merge, duplicate-work reduction, and noninterference | `GATE-115` |
| `TEST-AGENT-ACCRETION-001` | held-out future-episode benefit, harmful-memory demotion, expiry/revival, and no silent policy mutation | `GATE-115` |
| `TEST-AGENT-TRANSPORT-001` | Rust API/CLI/MCP/TUI/report semantic transcript and decision-digest equivalence | `GATE-115` |
| `TEST-AGENT-TAINT-001` | prompt/control-text taint, capability projection before retrieval/count/rank, secret exclusion, confused-deputy attacks | `GATE-115` |
| `TEST-AGENT-SITUATION-001` | CognitiveFacet anchor/owner compatibility, cold/warm SituationCapsule coherence, minimum sufficiency, omission counterfactual, stable aliases, and deterministic fingerprint | `GATE-115` |
| `TEST-AGENT-FOLLOW-001` | meaningful-delta coalescing, silence certificates, interruption thresholds, continuation, disconnect, and resume | `GATE-115` |
| `TEST-AGENT-CASE-001` | competing hypotheses, predictions, falsifiers, shared failures, VOI probe selection, stop rules, and residual uncertainty | `GATE-115` |
| `TEST-AGENT-AFFORDANCE-001` | hard-clamp filtering, Pareto frontier, component/sensitivity explanation, invalidation, and no authority laundering | `GATE-115` |
| `TEST-AGENT-WORLD-ENVELOPE-001` | certified-core/absence preservation, material-world frontier, protected adversarial residual retention, robust/conditional action classification, evidence-driven envelope shrink/split/expansion, and unsafe-world revalidation | `GATE-115` |
| `TEST-AGENT-LEARNING-001` | episode attribution, feedback/learning proposals, trauma guard, harmful transfer, expiry, revival, and no silent activation | `GATE-115` |
| `TEST-AGENT-RESOURCE-001` | task quality per tokens/bytes/model/graph work/energy/privacy/operator burden across pressure regimes | `GATE-115` |
