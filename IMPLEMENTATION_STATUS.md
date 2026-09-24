# Implementation status

**As of:** 2026-09-23 (reality check; earlier sections written 2026-09-03)  
**Project state:** pre-release deterministic reference implementation; not production-qualified  
**Release authority:** repository-owned local qualification and retained DSR receipts, not hosted CI

## Executive summary

Franken Surveillance System now has a coherent, dependency-light Rust reference spine from immutable source evidence through canonical authority state, guarded external effects, agent situation projection, meaningful deltas, exact continuation, and progressive semantic hydration. The repository is no longer merely an architecture corpus or crate skeleton.

It is also not a complete surveillance product. Native device adapters, production media/model/graph/storage services, persistent distributed operation, every human and agent surface, complete qualification matrices, and the aggregate release root remain open. Status below distinguishes implemented reference semantics from production completion.

## Media, perception and I/O added since 2026-09-03 (reference, unqualified)

All of this is tested only on generated fixtures (FFmpeg `testsrc` encodes, procedural JPEGs,
synthetic scenes). None of it has been measured on real camera footage.

- **Ingest and capture:** file import with custody for Annex-B/MJPEG/rtpplay (`ingest::file_adapter`,
  `fss-file import`); RTSP negotiation, Digest authentication and interleaved-TCP capture
  (`rtsp::*`, `std::net::TcpStream`); native HTTP MJPEG capture (`ingest::http_camera`); local
  capture archives with checkpoints, recovery, pins and verify/export (`fss-archive`).
- **Media:** RTP H.264/H.265 depacketization (`fss-packet`); baseline JPEG/MJPEG decode, gray and
  YCbCr 4:4:4/4:2:2/4:2:0 (`fss-codec-mjpeg`, `fss-file decode`); fragmented-MP4 remux for AVC/HEVC
  (`fss-container`); H.264 pixel decode for Baseline, Main and High profile (CABAC and CAVLC,
  I/P/B slices in display order, 8x8 transform, scaling matrices, weighted prediction), bit-exact
  against FFmpeg on 31 fixtures (`fss-codec-h264`), wired into retained decode (`fss-file decode`
  on Annex-B imports, ranges starting at an IDR). H.265/HEVC Main-profile pixel decode
  (intra, P/B inter, deblocking, SAO, WPP, slices, scaling lists) is bit-exact against FFmpeg on 39
  fixtures (`fss-codec-h265`), wired into ingest: `fss-file import` retains HEVC Annex-B as
  `hevc` (explicit `--media-format hevc`; auto-detection only for an unambiguous first NAL header,
  otherwise a typed refusal) with H.265 access-unit splitting, and `fss-file decode`,
  `fss-event watch` and `fss-event corroborate` decode IRAP-led ranges (a CRA-led range skips its
  RASL pictures and lists them). Not implemented: HEVC Main 10/RExt,
  tiles, dependent slices, long-term refs; interlaced and 4:2:2/4:4:4/10-bit H.264.
- **Pipeline and evaluation:** `fss-event watch` runs decode -> foreground -> Kalman -> zone
  eventgen over a retained import and publishes approval-gated, unclassified, single-sensor
  candidates. `fss-event corroborate` associates two sensors' ground-zone entries (owner
  homographies, not calibration; operator capture hints; worst-case interval time gate) into
  approval-gated corroborated events, and `fss-event alert` prepares, then commits and sends one
  plaintext webhook per corroborated event under separate exact approvals (2xx = relay acceptance
  only; lost ack = indeterminate; no resend). Proven on synthetic scenes and a loopback relay
  only, not on real cameras or detection quality. `evaluation` scores candidates against labels (AUPRC, recall at a false-alert
  budget, time to detect, not_observable). No real labelled corpus exists yet.
- **Coverage witnesses (fss-fnrgr):** every `fss-event watch` / `fss-event corroborate` report
  proposes a coverage record: one fss-core `CoverageWitness` per (sensor, zone, maximal contiguous
  interval) decoded without gap or skipped segment, past background warm-up (4 frames) and
  confirmation latency, zone inside the frame (ground zones: every corner's image preimage),
  capture time an operator hint and no source gap earlier in the import, bound to the exact
  pipeline generation; every other frame is a typed uncovered interval (zone entries name their
  event). Only `--retain-coverage <approval>` retains it (`coverage_witness` ledger family);
  unknown capture time never yields a witness. Proven on synthetic MJPEG scenes only; the
  witness certifies what the uncalibrated pipeline would have emitted, not detection quality.
- **Models:** scalar executor over the FSS IR (Conv2d, MatMul, pooling, norms, activations) with
  Safetensors weights (`scalar_executor`, `fss-infer`). One trained detector package ships:
  YOLOX-Nano COCO-80 (`models/yolox-nano/`, `MOD-YOLOXNANO-001`, Apache-2.0), imported offline
  from the pinned upstream ONNX by a first-party importer, loaded only through the digest-verified
  package path (`ingest::rgb_package`), and run over retained MJPEG/H.264/H.265 imports by
  `fss-infer package-detect` (H.264/H.265 in real colour: decoded luma and chroma through a
  declared BT.601 limited-range transform whose Y/Cb/Cr planes reassemble FFmpeg's `yuv420p`
  oracle frames). The scalar executor matches the onnxruntime lab oracle within 3e-5 (tolerance
  1e-3) with identical detections on three pinned inputs; it takes ~3 s per 416x416 frame in
  release. **Detection cascade (fss-704tz):** `fss-event watch`/`corroborate`
  `--detector-package ... --detector-max-inferences N` run the package only on frames the
  foreground/Kalman/zone gate selected (entry, confirmation, following frames; explicit budget,
  typed budget exhaustion), associate detections to tracks by IoU and attach uncalibrated class
  evidence (label, score, package digest/generation, frame and capsule digests); candidates stay
  `Unclassified` and single-sensor, the corroboration policy event is unchanged, and coverage
  binds the detector generation. `fss-infer package-detect --retain yes` -> `fss-event report
  --package-report` -> `prepare`/`publish` records unclassified, indeterminate package-track
  events. Proven on a synthetic silhouette scene (one inference per test), not on real footage;
  no quality, recall or calibration is claimed on any deployment data. The other trained weights
  are the OpenCV HOG people SVM (`fss-twin`), with no claimed recall.
  `fss-infer package-detect` (H.264/H.265 as grayscale: retained decode is luma-only). The scalar
  executor matches the onnxruntime lab oracle within 3e-5 (tolerance 1e-3) with identical detections
  on three pinned inputs. `RgbDetectorPackage::load` now defaults to the optimized CPU executor
  (`optimized_executor`, fss-bd99t), certified bit-identical to the scalar reference by in-tree
  differential tests and the conformance test; measured median 193 ms vs 3085 ms scalar per
  416x416 frame on one shared worker (docs/PERF_LEDGER.md PERF-001). The scalar reference stays
  selectable (`load_with_backend`, `fss-infer package-detect --kernels scalar-reference`), and the
  selected kernel generation is bound into the model digest. Single-threaded, x86-64 SSE2
  baseline only; not measured on arm64. No quality, recall or
  calibration is claimed on any deployment data, and `fss-event report` cannot yet consume these
  detections. The other trained weights are the OpenCV HOG people SVM (`fss-twin`), with no claimed
  recall.
- **Perception:** running-variance foreground detection, HOG multiscale scan, Kalman
  constant-velocity tracking with Hungarian assignment, global cross-camera assignment over
  caller-supplied ground-plane points, zone-gated event candidates (`ingest::{foreground, tracker,
  cross_camera, eventgen}`). Event quality (AUPRC, recall at a false-alert budget) is not measured.
- **Effects:** a native plaintext HTTP webhook transport behind durable authorization gates
  (`alert::webhook`), driven by `fss-event alert` for events corroborated by two independent
  sensors (`fss-event corroborate`). Only plaintext relays, no TLS, no retries; a 2xx proves relay
  acceptance only. Sensor independence rests on operator-declared sensor identities.
- **Operations:** `fss doctor --json --root <dir>` inspects a deployment read-only; `fss-lab` runs
  its six scenarios on `ReferenceDeployment` (mock model and simulated alert provider).
- **Agent reads (fss/1, CLI only):** `fss session orient` (AOP-003, alias `fss orient`),
  `fss explain` (AOP-011), and `fss session follow` (AOP-004, alias `fss follow`) answer read-only in the registered `AgentResponseEnvelope`. Every
  orientation emits a content-bound anchor token (site, commit, effect-journal records, and a
  binding over the anchor, ledger root, and effect-journal root); `fss follow --since <token>`
  compiles the situation as of that anchor from the committed ledger and effect-journal prefix
  alone and returns the reference `MeaningfulDelta` engine's delta to the head, paged through an
  exact `follow_stream` continuation (every page carries the full class set; protected items
  first; unknown, foreign, and ahead anchors and altered or wrong-stream continuations are typed
  refusals). Orientations now carry one local-state effect cell per durable operation, so a
  prepared alert surfaces as protected obligation and effect-uncertainty classes. Orient assesses
  every objective zone as `covered`, `not_observable` or `stale` from retained coverage records
  and is `complete` only when every zone is covered over its declared window; then a follow whose
  basis and head are the same committed position returns the engine's silence certificate bound
  to the witnesses. Across a ledger advance no silence is certified yet (the frame binds
  commit-specific statements; drift entry in `architecture/agent_contracts.json`), and without
  coverage the persisting gap stays protected `coverage_loss`. There is no long-lived
  subscription, wake, or MCP transport; follow is one bounded read per call.
- **Agent sessions (fss/1, CLI only):** `fss session open` (AOP-001) opens a durable
  mission-scoped session and its revision-zero workspace at the current orient anchor through the
  existing `DurableSessionStore` (a session journal under `<root>/agent/sessions/` with an
  atomically replaced pinned root; a rollback or foreign journal is refused, never repaired) and
  publishes the mission statement root-last under `<root>/agent/publications/`; an identical open
  is an exact retry. `fss handoff` (AOP-012, alias `fss session handoff`) seals the situation as of the session's
  anchor with the existing handoff sealing code and publishes a root-last handoff record (plus the
  session and workspace revision as `agent_session.v1`/`agent_session_capsule.v1`); a crash at
  any publication cut point leaves the handoff absent or complete. `fss session resume` (AOP-002)
  refuses unknown, tampered, expired, unauthorized, and foreign handoffs, compares the situation
  as of the handoff anchor with the head through the reference `MeaningfulDelta` engine, lists
  every invalidated assumption, action, and anchor-bound fact, and rebases the session and
  workspace onto the head in one atomic journal command. Only agent-plane state is written; the
  authority ledger, effect journal, and deployment spool stay byte-identical. Leases and handoff
  lifetimes run on the deployment evidence clock; there is no authentication (principals are
  audit labels) and no MCP transport. Open drifts: `architecture/agent_contracts.json`.

Architectural deviations to resolve: device and alert I/O use blocking `std::net` rather than
Asupersync (owner decision `fss-x4a.8.1` is open), and the workspace has zero third-party crates.

## Implemented deterministic reference spine

### Canonical authority, evidence, and custody

- Stable typed identities and canonical encoding.
- Content digests and root-closed object manifests.
- Immutable sensor capsules and capture-time uncertainty intervals.
- Coverage witnesses and explicit negative-evidence boundaries.
- Ordered `EvidenceDeltaBatch` authority history and exact `LedgerAnchor` succession.
- Durable reference journal recovery with incomplete-tail policy.
- Child-first, root-last publication into the reference ledger.
- Deterministic virtual acquisition, transport mutation, replay bundles, and mock-model execution.

### Events, policy, and effects

- Evidence-linked event hypotheses with explicit lifecycle state.
- Reference unknown-presence policy that requires independent failure domains before alert preparation.
- Separate alert prepare, commit, provider observation, reconciliation, and terminal publication stages.
- Idempotency identities, operation receipts, obligations, and indeterminate-effect retention.
- Guarded situation projection: only an exact local `Prepared` receipt preserves commit; missing or later operation state exposes status/reconciliation.
- Rejection of forged, structurally inconsistent, stale, or mismatched effect receipts.

### Agent situation and control membrane

- `ContractBasis`, `KnowledgeCell`, `PossibleWorld`, `WorldEnvelope`, `ActionAffordance`, `SituationFrame`, `SituationCapsule`, and root-closed handoff contracts.
- Conservative distinction among known, estimated, unknown, conflicted, stale, not observable, redacted, indeterminate, and not applicable state.
- Retention of protected high-consequence worlds rather than rank-only pruning.
- Categorized control envelope for robust, conditional, information-gathering, wait, blocked, and unavailable affordances.
- Full multidimensional resource state and action cost, including latency, tokens, bytes, model calls, CPU, accelerator, energy, network, storage operations, privacy exposure, and operator attention.
- Proof-bearing semantic context packs and compression receipts with critical-preservation checks and priced expansion handles.
- Deterministic reference situation publications binding situation, control, resources, context, compression, and proof roots.

### Meaningful change and continuation

- Deterministic `MeaningfulDelta` comparison between exact situation publications.
- Protected non-coalescible classes for contradictions, coverage loss, plan invalidation, obligation change, external-effect uncertainty, authority/policy change, and terminal transitions.
- Explicit tracking of known-premise removal and contradiction resolution.
- Separation of resource pressure from material world change.
- Silence certificates proving no decision-relevant change, including across harmless successor commits.
- Exact continuation streams with content-bound entries, page digests, monotone positions, expiry, stream identity, contract basis, anchor, view, and session checks.
- Exposed read-only through `fss session follow` (AOP-004) over real deployments, comparing an as-of-anchor orientation (committed prefix only) with the head's under the registered `meaningfulDeltaComparison` rules, so a harmless successor commit over complete coverage yields a certified silence (`coverage_cli_contract.rs`).
- Used by `fss session resume` (AOP-002) to list what changed and what was invalidated between a handoff anchor and the head.

### Semantic handles and H0–H4 hydration

The FSS-210 deterministic reference slice is implemented:

- immutable `SemanticHandle` identity over the exact subject;
- independently versioned descriptor digests for delivery policy and availability;
- contiguous H0–H4 hydration ladders;
- exact per-level capability and full-vector cost maps;
- distinct privacy class and transform identity;
- typed available, superseded, deleted, expired, corrupt, privacy-transformed, and not-observable states;
- exact `HydrationRequest`, `HydrationArtifact`, `HydrationReceipt`, and `HydrationResponse` contracts;
- deterministic reference descriptor/artifact catalog;
- exact descriptor lookup rather than silent “latest” substitution;
- capability, privacy, H4-purpose, and resource enforcement;
- explicit lower-level downgrade only when permitted;
- proof-root closure and exact progressive continuation;
- tamper, rebinding, cursor-misuse, deletion, expiry, denial, downgrade, and deterministic-replay tests;
- external-consumer coverage of the public `fss-core` API.

FSS-210 remains **in progress**, not complete. Machine schemas/registries, persistent custody and retention proofs, every public surface, fault schedules, aggregate qualification, and GATE-115 evidence remain outstanding.

## Qualification currently represented in the repository

The repository contains executable policy, Rust, agent-reference, manifest, dependency, and release-assembly lanes. The implemented Rust contracts include focused unit, integration, adversarial, durability, replay, effect-fault, situation-projection, meaningful-delta, continuation, compression, and hydration tests.

A passing developer run demonstrates the exact checked tree only. It does not by itself establish production claims, hardware interoperability, model quality, privacy compliance under every deployment, or aggregate release qualification. Those require retained lane receipts and the declared qualification roots.

## Work packages still materially open

### Production runtime and boundaries

- Asupersync-owned production service topology, cancellation/drain evidence, and bounded concurrency across all processes.
- Native camera discovery, transport, codec/media, calibration, archive, drone, notification, and vendor-boundary implementations.
- Persistent FrankenSQLite/FrankenFS/ATP integration beyond the deterministic in-process reference stores.
- Production pure-Rust model runtime, package verification, generation management, batching, calibration, and fallback.
- Certified graph/search kernels and incremental graph intelligence.

### Agent operating system

- Durable mission/objective/session/workspace stores and complete state machines.
- Session-local symbol tables with stale-alias recovery and non-disclosure.
- Attention frontier, investigation/hypothesis workspace, information-value acquisition, contingent planning, execution episodes, outcome attribution, and learning promotion.
- Multi-agent work claims, leases, transfer, duplicate-work prevention, cancellation, and orphan-obligation recovery.
- First-class binding of every context-pack expansion reference to a published semantic-handle descriptor.
- Equivalent typed payloads and decision digests across Rust API, CLI, MCP, TUI, reports, subscriptions, and handoffs.

### Security, privacy, retention, and deletion

- End-to-end capability/privacy projection over every hydration, export, retention, and effect path.
- Persistent retention schedules, legal holds, graph-complete deletion, derivative accounting, and deletion proof.
- Secret-bearing boundary isolation, key management, audit export, incident response, and recovery drills.
- Complete stale/rollback/downgrade and one-version-universe enforcement across deployed binaries and stored objects.

### Qualification and release

- Remaining deterministic reference, property, metamorphic, differential, fault, crash, cancellation, lost-acknowledgement, disconnect, multi-agent, pressure, migration, upgrade, rollback, and full mission rehearsals.
- Complete `TEST-AGENT-*`, adapter, model, graph, storage, security, privacy, and performance families.
- QL-AGENT aggregate thresholds for correctness, calibration, hazardous-action rate, evidence use, handoff continuity, operator burden, and full resource cost.
- GATE-115 agent qualification and the later native platform/release gates.
- Locally produced, root-last GATE-120 release qualification root.

## Requirement-status guidance

- **Implemented reference slice:** deterministic code and focused executable tests exist for the named semantics.
- **In progress:** important acceptance dimensions remain, such as schemas, other surfaces, persistent integration, fault evidence, or aggregate qualification.
- **Qualified:** every required lane has retained proof for the exact source, dependency, toolchain, platform, and artifact identity.
- **Released:** the complete local release root has been published after artifact custody, native matrix, canary, upgrade, rollback, and public verification.

No task should be closed solely because a neighboring type, schema, shared helper, or happy-path demo exists.

## Immediate optimal sequence

1. Finish FSS-210 schema/registry and context-pack binding without weakening immutable-handle semantics.
2. Implement the next session-oriented contract on top of exact continuation and hydration rather than inventing another cursor or expansion dialect.
3. Extend the reference mission rehearsal through typed hydration, handoff, stale descriptor, lost acknowledgement, and cancellation outcomes.
4. Establish cross-surface canonical payload equivalence before multiplying presentation-specific features.
5. Integrate persistent custody/retention and deletion proofs before claiming H3 source-evidence production readiness.
6. Accumulate retained QL-AGENT evidence and only then advance GATE-115 status.

## Known status limitations

- Repository integrity manifests must be regenerated whenever tracked source or documentation changes; a stale manifest is a repository-policy failure, not an ignorable cosmetic difference.
- Hosted workflow results are supplementary and may be queued or cancelled by concurrency. They are not substitutes for local retained receipts.
- The large bead graph encodes complete program acceptance. This document summarizes implementation state and does not override bead dependencies, registries, schemas, ADRs, or qualification gates.
