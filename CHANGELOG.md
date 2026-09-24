# Changelog

All notable changes to Franken Surveillance System are recorded here. The project is pre-release; entries describe implemented and retained repository state, not production qualification unless explicitly stated.

## Unreleased

### Added

- Added the detection cascade and trained-detector event path (`fss-704tz`): `fss-event watch` and `fss-event corroborate` accept `--detector-package FILE --detector-digest sha256:… --detector-max-inferences N` (optional `--detector-frames-per-track`, `--detector-min-iou-ppm`, `--detector-minimum-score-ppm`); the verified package runs only on the frames the foreground/Kalman/zone gate selected (zone entry, confirmation, following matches), within an explicit budget whose exhaustion is typed per frame (`ERR-DETECTOR-CASCADE-BUDGET-001`); detections are associated with tracks by integer IoU and retained as uncalibrated class evidence (`fss.detector_class_evidence.v1`) in the sensor's own failure domain. Candidates stay `Unclassified` and single-sensor; corroborated events keep the policy's own evidence; the cascade identity is bound into candidate identities, analyses and coverage pipeline generations. Without a detector the reports are byte-identical (pinned against the pre-cascade tree). `fss-infer package-detect --retain yes` retains a package detection (`fss.package_detection_record.v1`), and `fss-event report --package-report sha256:… --label NAME` tracks it into a `fss.package_analysis_report.v1` that `prepare`/`publish` turn into unclassified, indeterminate package-track events. Retained H.264/H.265 frames now expose Cb/Cr (per-plane receipt digests; the encoded luma receipts are unchanged) and convert to RGB through a declared BT.601 limited-range Q16 transform, so package-detect and the cascade see real colour (`ycbcr420_bt601_limited_rgb`). Wiring only: synthetic scenes, one inference per test, no quality or calibration claim.
- Added `optimized_executor` (fss-bd99t): a prepared CPU executor for F32 Model IR graphs alongside the unchanged scalar reference. Conv2d runs as packed-weight 4x8 register tiles (1x1 convolutions flattened to one GEMM row, depthwise as row accumulation) with fused bias+SiLU; every kernel keeps the reference's per-element operation order, so outputs are bit-identical (0 ULP), certified by seeded differential tests and by the YOLOX conformance test (identical output bits and post-NMS detections; oracle tolerance unchanged). YOLOX-Nano graph execution: median 193 ms vs 3085 ms scalar on one shared AMD EPYC worker (16.0x; `docs/PERF_LEDGER.md` PERF-001). `RgbDetectorPackage::load` and `fss-infer package-detect` default to it; `load_with_backend` and `--kernels scalar-reference` force the reference. The kernel generation is bound into the model digest (`fss.rgb_inference_model_execution.v1`) and `RgbInference::backend()`/`kernel_generation()`/`backend_descriptor()`, so evidence from the two executors never mixes. `examples/yolox_profile.rs` reproduces the per-op profile and timings.
- Admitted YOLOX-Nano (COCO-80, 416x416, Apache-2.0) as FSS's first trained detector package (`fss-q4ngj`, owner decision `fss-x4a.8.1`): a first-party offline importer (`--example yolox_import`, bounded hand-written ONNX protobuf reader) lowers the pinned upstream ONNX (`sha256:c789161e…0b7d`) onto the unchanged Model IR v1 (nearest Resize and exp as exact compositions; no new operator) into an immutable `FMPK` package (`models/yolox-nano/yolox_nano.fmpk`, `sha256:5b656875…8c74`) with Safetensors weights, package spec, LICENSE and NOTICE; reruns are byte-identical. `ingest::rgb_package` loads it only through whole-archive digest, archive, license-policy, graph and weight verification; `fss-infer package-detect` runs it over retained MJPEG (color), H.264 and H.265 (grayscale) imports into a `fss.package_detection_report.v1` report. Conformance against onnxruntime 1.30.0 (lab oracle, not in the repo) on three pinned inputs: max normalized error 3.0e-5 (tolerance 1e-3) and identical detections. Release scalar inference takes ~3 s per frame. No detection-quality, recall or calibration claim on deployment data; `fss-event report` does not yet consume these detections.
- Wired H.265 into ingest and analysis: `fss-file import` retains HEVC Annex-B as media format `hevc` (`--media-format hevc`; auto-detected only when the first NAL header cannot be H.264, otherwise `ERR-INGEST-FORMAT-AMBIGUOUS-001`) with H.265 7.4.2.4.4 access-unit splitting and exact source spans; `RecordedH265Range` decodes IRAP-led ranges in display order (a CRA/BLA-led range skips and lists its RASL pictures), bit-exact against FFmpeg; `fss-file decode`, `fss-event watch` and `fss-event corroborate` accept `hevc` imports. H.264 import behaviour is unchanged.
- Added `fss-codec-h265`: pure-Rust HEVC Main-profile decode (CABAC, intra, P/B inter with AMVP/merge/TMVP, weighted prediction, deblocking, SAO, WPP, slices, scaling lists, PCM, lossless), bit-exact against FFmpeg on 39 fixtures; not yet wired into ingest.
- Added `fss-event corroborate` and `fss-event alert`: two-sensor corroborated zone entries and one approval-gated plaintext webhook per corroborated event (lost acknowledgement stays indeterminate; never resent).
- Added read-only `fss orient` and `fss explain` (fss/1 session.orient and explain) over a deployment root, schema-validated, with scalable pulse/brief/epistemic_map views.
- Added H.264 Main and High profile decode (CABAC, B slices with display-order output, temporal/spatial direct, weighted prediction, MMCO/long-term references, 8x8 transform, scaling matrices), bit-exact against FFmpeg; retained decode now binds reordered pictures to their coding segments.
- Added bit-exact H.264 Constrained Baseline pixel decode (I and P slices, CAVLC, intra/inter prediction, deblocking, cropping, multiple slices, I_PCM) to `fss-codec-h264`, checked frame by frame against FFmpeg-derived digests on 15 fixtures (`fss-wr7ai`). Not yet wired into ingest; H.265 and Main/High profiles are not implemented.
- Added native media and capture paths (reference, unqualified; generated fixtures only): file import with custody for Annex-B/MJPEG/rtpplay (`fss-file import`), baseline JPEG/MJPEG decode (`fss-file decode`), RTP H.264/H.265 depacketization, RTSP negotiation with Digest authentication over interleaved TCP, HTTP MJPEG capture, local capture archives (`fss-archive`), and fragmented-MP4 remux for AVC/HEVC.
- Added a scalar model executor over the FSS IR with Safetensors weights (`fss-infer`), foreground detection, the OpenCV HOG people SVM, Kalman/Hungarian tracking, global cross-camera assignment, zone-gated event candidates and recorded event publication (`fss-event`). Detection quality has not been measured on real footage.
- Added a native plaintext HTTP webhook alert transport behind durable authorization gates (library only; no command drives it).
- Added `fss doctor --json --root <dir>`, a read-only deployment inspection.

- Added dependency-free semantic-hydration contracts to `fss-core`:
  - immutable `SemanticHandle` identity over exact subject coordinates;
  - independently versioned descriptor digests for availability, retention, privacy, capability, and cost policy;
  - contiguous H0–H4 hydration ladders;
  - exact `HydrationRequest`, `HydrationArtifact`, `HydrationReceipt`, and `HydrationResponse` objects;
  - typed availability for superseded, deleted, expired, corrupt, privacy-transformed, and not-observable subjects;
  - stable hydration failures with deterministic recovery classes;
  - exact evidence-hydration continuation cursors bound to handle, session, basis, anchor, ladder policy, and next level.
- Added a deterministic reference hydration catalog with exact descriptor lookup, idempotent registration, immutable-subject protection, capability/privacy enforcement, full-vector budget checks, explicit downgrade, H4 purpose gating, typed unavailable receipts, proof-root closure, and deterministic continuation issuance.
- Added module-private, adversarial, and external-consumer tests for handle revisioning, ladder gaps, cursor misuse, subject substitution, descriptor mismatch, payload tampering, capability/privacy denial, budget downgrade, deleted/expired outcomes, H4 access, and deterministic replay.
- Added `docs/SEMANTIC_HYDRATION.md` as the normative reference guide for FSS-210’s implemented slice and remaining qualification boundary.
- Added proof-bearing reference situation publications composed from a `SituationCapsule`, categorized control envelope, complete resource state, semantic context pack, compression receipt, and deterministic publication digest.
- Added deterministic `MeaningfulDelta` classification with protected non-coalescible contradiction, coverage-loss, plan-invalidation, obligation, effect-uncertainty, authority, and terminal transitions.
- Added silence certificates for comparisons that prove no decision-relevant change.
- Added exact continuation streams with content-bound entries, page digests, monotone positions, expiry, stream identity, and wrong-stream rejection.
- Added guarded agent projections that require the exact local operation receipt before exposing alert commit. Missing, committed, acknowledged, failed, cancelled, or indeterminate state exposes status/reconciliation rather than blind dispatch.
- Added root-closed reference handoffs and deterministic decision fingerprints for replay comparison.
- Added the complete multidimensional `BudgetVector`, including accelerator time and energy, to canonical action, projection, compression, and continuation digests.

### Fixed

- Restored the fss-core half of the v3 cancellation-proof records (`fss-thzlz`), which a 2026-09-22 bulk merge had dropped while keeping its callers. That had left `fss-reference` uncompilable (`fss-pod9x`).
- Removed duplicate registry rows and a stale duplicate of topology layers L3/L4 introduced by the same bulk merge, and restored the byte-exact staleness check in `scripts/robot_docs_checker.py`, which the merge had weakened.
- `fss capabilities` and `fss status` now report the unqualified reference implementation instead of "design skeleton".

### Changed

- Agent-facing projection now preserves resource pressure as its own semantic dimension instead of laundering it into material world change.
- Meaningful-delta comparison now separates semantic world content from routine successor-anchor movement, permitting certified silence across harmless authority commits.
- Contradiction resolution and removal of a previously known premise are retained as critical decision-impact changes.
- Compression receipts permit explicitly receipted partial semantic classes while continuing to forbid omission of critical items, contradictions, or invalidations.
- Public situation compilation routes through the effect-state guard by default.
- Expansion and continuation semantics are progressively moving from conversational strings toward content-bound, capability-scoped contracts.
- Hosted GitHub execution remains supplementary. Repository-owned local qualification and retained DSR receipts remain the release authority.

### Fixed

- Fixed owner-supplied RTSP Digest retries to accept the parser's typed `AuthRequired` response while preserving exact framing, CSeq, deadline, realm, and replay checks. Removed the obsolete parser-only source-text ban on authentication headers; behavioral authentication and redaction tests remain.
- Removed the superseded hydration test requiring eviction of unexpired consumed cursors; existing cursor-lifecycle regressions retain replay tombstones under capacity pressure and reclaim only expired records.
- Repaired shared CAP e2e logging: retained CAPLOG outcomes and typed skip reasons now reach structured summaries; run-level failures remain separate from recorded step failures. Empty evidence, all-skipped runs, exhausted remote execution, and script aborts fail closed without blaming completed steps. Summary failure IDs derive from retained records at the log cap, and mixed shell/Cargo selections no longer suppress Cargo execution.
- Aligned the MJPEG cancellation-checkpoint CAPLOG expected/observed objects and derived its success verdict through the shared helper; elapsed time remains record metadata rather than part of the compared result.
- Added bit-exact sigmoid/softmax golden regressions and an exp upper-clamp +INFINITY probe to the scalar executor contract; each pin kills a documented surviving mutant (native-exp call-site swaps, loosened clamp, zero-seeded softmax row max). MaxPool MAC accounting now defaults kernel dimensions to 1, matching the kernel, and the pool-budgeting comment states the charged quantity.
- Fixed stable-ID test imports so combined pytest collection preserves the checker module identity and exercises corrupt/empty-index fail-closed checks correctly.
- Fixed stable-ID reference scanning so ordinary lowercase prose phrases (e.g. "first-240") are not forced through strict identifier grammar, while uppercase and normative-family candidates still fail closed.
- Fixed camera registration bindings to preserve typed projection uncertainty and reject invalid component bounds consistently with tracking; corrected radial registration fixtures.
- Prevented a prepared alert plan from being treated as proof that an operation has not already crossed an external boundary.
- Prevented forged or structurally inconsistent local effect receipts from preserving commit authority.
- Prevented unavailable affordances from appearing in the actionable `NEXT` frontier.
- Prevented duplicate or overlapping knowledge evidence, duplicate claims, duplicate obligations, malformed possible-world cores, and predicted claims from becoming irreversible-effect premises.
- Fixed semantic comparison across successor anchors so stable possible worlds do not appear changed solely because their authority anchor advanced.
- Fixed silence-certificate validation so the certificate witness must equal the enclosing delta witness.
- Removed a temporary source-snapshot workflow that violated the repository’s workflow-delegation policy.
- Removed policy-sensitive wording from Rust documentation without changing runtime semantics.

### Qualification state

The deterministic Rust reference implementation is substantially broader than the initial skeleton, but no public production-completeness claim is made. Outstanding work includes JSON Schema and registry agreement for the new contracts, persistent object/retention integration, CLI/MCP/TUI/report equivalence, multi-agent claim and lease semantics, remaining `TEST-AGENT-*` families, QL-AGENT aggregate thresholds, GATE-115, native device/model/graph/storage implementations, and a complete locally qualified release root.

## 0.1.0 - Foundation snapshot

### Added

- Pure-Rust workspace and crate topology for the semantic reference kernel, object store, durable evidence ledger, publication spine, reference acquisition/replay path, and CLI laboratory.
- Canonical identities, hashing, timestamps, evidence anchors, sensor capsules, coverage witnesses, event hypotheses, effect journals, obligations, receipts, and root-last object publication.
- Deterministic virtual camera source generation, delivery mutation, mock-model execution, unknown-presence policy evaluation, alert preparation/dispatch/reconciliation, and replay bundles.
- Repository constitutions, ADRs, machine registries, JSON Schemas, local qualification scripts, dependency audits, release tooling, and layered integrity manifests.
- Agent cognition and control architecture covering missions, sessions, epistemic states, situation frames, possible worlds, affordances, plans, effects, learning, workspaces, and handoffs.

### Security and correctness

- Workspace crates forbid memory-unsafe Rust.
- Negative claims require explicit coverage evidence.
- Model output alone cannot grant effect authority.
- External effects use prepare/commit/watch/reconcile semantics and retain indeterminate outcomes.
- Canonical publication is child-first and root-last.
- Stable identifiers are never silently renumbered or rebound.
