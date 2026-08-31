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
