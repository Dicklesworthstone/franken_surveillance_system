# Roadmap

The roadmap is gate-ordered, not date-promised. A later gate does not reduce the scope of an
earlier one, and passing a gate means retaining the required evidence rather than merging code.

| Gate | Result | Exit evidence |
|---|---|---|
| `GATE-000` | Architecture constitution | stable IDs; import/dependency/algorithm/publication/topology/qualification registries; schemas; risk/cost/claim consistency |
| `GATE-010` | Deterministic reference world | replay adapter, in-memory ledger, synthetic property, golden decisions, fault schedule corpus |
| `GATE-020` | First authoritative sensor | UVC/UAC acquisition with time intervals, original-byte custody, continuity state machine, cancellation proof |
| `GATE-030` | Open IP camera baseline | RTSP plus ONVIF Profile T discovery/stream/settings/events; Profile M metadata when present |
| `GATE-040` | Media and archive substrate | first-party Rust media kernel, ATP object graph, live proxy, local spool, root-last B2/R2 publication, repair/retrievability drill |
| `GATE-050` | Cognition walking skeleton | pure-Rust model package/runtime, quality gate, detector, tracker, immutable receipts, event revisions, replay equivalence |
| `GATE-060` | Cross-camera world model | one-version graph/search high-water marks, certified temporal/matching algorithms, time sync, calibration, association, coverage |
| `GATE-070` | Drone calibration shuttle | manually piloted session, shared marker, reconstruction, joint bundle adjustment, invalidation rules |
| `GATE-080` | Threat-quality gauntlet | staged intrusion corpus, benign hard negatives, event AUPRC, recall/false-alert frontier, calibration, misses ledger |
| `GATE-090` | Proprietary adapter lab | exact firmware/app compatibility for selected Wyze/AOSU workflows; no bypass; revocation and drift handling |
| `GATE-100` | DJI Flip research bridge | authorized live-view or bounded import path; manual-only; current unsupported-SDK boundary remains explicit |
| `GATE-110` | Agent-native product surface | bounded queries, evidence explanations, MCP read path, effect prepare/commit, leases, token budgets |
| `GATE-120` | Operational release candidate | clean sibling closure, DSR native lanes, exact signed assets/SBOM/provenance, download verification, install/rollback, soak, privacy/security proof |

## Parallel workstreams

- **WS-A Constitution:** registries, schemas, ADRs, proof targets, doc-code drift checks.
- **WS-B Acquisition:** replay, UVC, RTSP, ONVIF, vendor hosts, continuity.
- **WS-C Media:** pure-Rust packet/container/codec kernel, source custody, low-latency proxy, analysis surfaces.
- **WS-D Ledger/archive:** EvidenceDeltaBatch/MVCC witnesses, local spool, ATP remote object graphs, repair/retrievability.
- **WS-E Geometry:** clocks, calibration, reconstruction, occupancy, coverage.
- **WS-F Cognition:** pure-Rust model runtime, detection, tracking, association, temporal models, calibration, policy.
- **WS-G Evaluation:** threat corpus, hard negatives, red team, statistics, cost and energy.
- **WS-H Agent/ops:** CLI, MCP, explanations, progressive search, certified graph intelligence, memory, pure-Rust TUI/web observation.
- **WS-I Security/privacy:** secrets, isolation, masks, retention, deletion, identity controls.
- **WS-J Packaging:** exact nightly promotion, clean sibling closure, DSR native lanes, installers, migrations, signed root-last releases, support bundles.

See the comprehensive plan for dependencies and acceptance tests.
