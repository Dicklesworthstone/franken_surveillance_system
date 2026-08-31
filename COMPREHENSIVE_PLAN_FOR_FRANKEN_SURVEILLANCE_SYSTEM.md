# Comprehensive Plan for the Design and Implementation of `franken_surveillance_system` (`fss`)

| Field | Value |
|---|---|
| Document class | Normative architecture and execution plan |
| Initial issue date | 2026-08-30 |
| Last substantive revision | 2026-08-31 |
| Status | Draft 0.3 — mechanism-level Franken substrate, pure-Rust runtime, graph/ATP, and local-release revision |
| Repository | `Dicklesworthstone/franken_surveillance_system` |
| Primary audience | Implementers, reviewers, autonomous coding agents, computer-vision and geometry researchers, media/network engineers, security/privacy reviewers, and operators |
| Normative companions | `DEPENDENCY_CONSTITUTION.md`, `GRAPH_ANALYTICS_AND_SENSOR_MESH.md`, `ATP_AND_DISTRIBUTED_EVIDENCE.md`, `PURE_RUST_MODEL_RUNTIME.md`, `LOCAL_QUALIFICATION_AND_RELEASE.md`, `FRANKENSTACK_DEEP_DIVE.md`, `architecture/*`, `registries/*`, `schemas/*`, `docs/deep-dives/*`, `SECURITY.md`, `PRIVACY.md`, `IMPLEMENTATION_STATUS.md` |

---

## Document control

This plan is intentionally more demanding than a normal camera/NVR roadmap. A home-security system
observes a partially visible physical world through lossy sensors and fallible models. A stream may
be accepted without producing frames; frames may exist without trustworthy time; a detector may
fire without a real event; an event may be real but unobservable from a failed camera; an alert may
be dispatched but not delivered; an archive write may succeed while its evidence root remains
unpublished. A design that collapses these states will look good in a demo and fail exactly when an
operator needs to know what happened.

The plan therefore specifies:

- the semantic truth model and authority boundaries;
- identities, generations, uncertainty, provenance, and evidence classes;
- acquisition, media, geometry, model, event, policy, effect, archive, and agent contracts;
- owner-authorized proprietary interoperability boundaries;
- privacy, retention, redaction, deletion, and identity controls;
- deterministic replay, fault schedules, threat-quality evaluation, and negative evidence;
- typed claims, operation-cost rows, SLOs, risks, work packages, and acceptance gates;
- the exact difference between a design target, implementation, qualification, and release claim.

### Normative language

The terms **MUST**, **MUST NOT**, **REQUIRED**, **SHALL**, **SHALL NOT**, **SHOULD**, **SHOULD
NOT**, **RECOMMENDED**, **MAY**, and **OPTIONAL** are used in their ordinary RFC 2119 sense.

A requirement is implemented only when:

1. its behavior is represented in a stable typed contract or registry;
2. authority, inputs, outputs, success, failure, cancellation, and indeterminacy are explicit;
3. durable compatibility and migration behavior are explicit;
4. deterministic reference tests cover the relevant transitions;
5. adversarial/fault tests cover the relevant failure domain;
6. acceptance evidence is retained and reproducible;
7. documentation, schemas, registries, status, and implementation agree.

### Evidence labels

- **FACT:** established by a checked source or direct repository inspection as of the stated date.
- **DESIGN:** a proposed normative choice for FSS.
- **HYPOTHESIS:** plausible but requires measurement or experimentation.
- **TARGET:** an acceptance objective, not a current result.
- **OPEN:** unresolved design question with an owner and decision gate.

Unlabeled normative prose specifies desired behavior; it does not claim current implementation.

### Stable identifiers

Published IDs are never renumbered. Superseded entries remain as tombstones.

| Prefix | Meaning |
|---|---|
| `INV-` | hard invariant |
| `GOAL-` | project goal |
| `NONGOAL-` | explicit non-goal |
| `CAP-` | capability |
| `EFFECT-` | effect class |
| `ERR-` | stable error |
| `SCHEMA-` | versioned schema |
| `ADR-` | architecture decision |
| `INT-` | Franken/dependency integration gate |
| `WP-` | work package |
| `GATE-` | acceptance gate |
| `TEST-` | required test family |
| `SLO-` | measurable service objective |
| `COST-` | operation-cost row |
| `RISK-` | tracked risk |
| `OPEN-` | unresolved question |
| `LAB-` | authorized interoperability experiment |
| `ADP-` | device adapter generation/family |
| `MOD-` | model candidate/generation family |
| `ALG-` | registered graph algorithm family |
| `PUB-` | coherent publication primitive |
| `DEC-` | adaptive/optimization decision family |
| `DEP-` | dependency admission or prohibition record |
| `REL-` | local qualification/release lane or contract |
| `FMT-` | canonical durable format |
| `TRACE-` | deterministic trace/replay contract |
| `ATP-` | transfer/object-graph protocol contract |

---

# Table of contents

- 0. Reading guide
- 1. Executive summary
- 2. Discovery and ecosystem findings
- 3. Mission, goals, non-goals, and North Star scenarios
- 4. Semantic truth model
- 5. Identity, generations, anchors, and time
- 6. Layered architecture, trust domains, and dependency policy
- 7. Runtime, ownership, cancellation, budgets, and obligations
- 8. Device discovery, authorization, and adapter protocol
- 9. Standards-first camera integrations
- 10. Proprietary camera interoperability lab
- 11. DJI Flip and drone-capture boundary
- 12. Media acquisition, source custody, decoding, and live delivery
- 13. Canonical ledger, object storage, encryption, and archive
- 14. Digital twin, calibration shuttle, geometry, and coverage
- 15. Pure-Rust model runtime and model registry
- 16. Detection, tracking, cross-camera association, and temporal reasoning
- 17. Event semantics, uncertainty, sequential evidence, and policy
- 18. Alerts and other effects
- 19. Search, graph, memory, and explainability
- 20. Agent-native CLI/MCP interfaces
- 21. Security architecture
- 22. Privacy, identity, retention, export, and deletion
- 23. Deterministic replay, fault injection, and formal targets
- 24. Dataset, red-team, statistical evaluation, and AUPRC
- 25. Performance, energy, storage economics, and cost registry
- 26. Observability, doctor, repair, support bundles, and operations
- 27. Crate topology and durable formats
- 28. Implementation work packages and dependency order
- 29. Acceptance gates and release doctrine
- 30. Risks and open questions
- 31. Closed pure-Rust dependency universe
- 32. One version universe and semantic transactions
- 33. Pure-Rust media and streaming kernel
- 34. Certified graph intelligence
- 35. Pure-Rust model runtime
- 36. ATP archive, replication, repair, and deletion
- 37. Decision cards, adaptive policy, and performance proof
- 38. Local DSR qualification and release authority
- Appendix A. Initial canonical data model
- Appendix B. Example end-to-end event flow
- Appendix C. Example calibration flow
- Appendix D. Example agent session
- Appendix E. Operation-cost formulas
- Appendix F. First 200 implementation issues
---

# 0. Reading guide

The most important sentence in this plan is:

> **FSS is not a VLM pointed at a collection of video URLs. It is a semantic, transactional,
> replayable evidence and control plane over an uncertain physical sensor mesh.**

Everything derives from that constraint.

The second most important sentence is:

> **The model is cognition, not authority.**

A model may propose a detection, track, association, scene description, threat explanation, or
next observation. It cannot authenticate a camera, declare source continuity, rewrite canonical
evidence, relax privacy, change retention, identify a person by default, or authorize an effect.

The third is:

> **“Never miss” is an aspiration that becomes measurable only after defining observability,
> threat distribution, exposure, false-alert budget, and statistical confidence.**

The system must optimize hard for rare-event recall, but it must never turn no observed miss in a
small test into an absolute guarantee.

Read in this order:

1. `README.md` for the product thesis.
2. `IMPLEMENTATION_STATUS.md` for the honest current boundary.
3. `FRANKENSTACK_DEEP_DIVE.md` and `docs/deep-dives/INDEX.md` for the mechanism-level inheritance.
4. `docs/DEPENDENCY_CONSTITUTION.md` before adding or proposing any dependency.
5. Sections 3–7 and 31–38 for the constitution.
6. Sections 8–20 for the technical and agent data paths.
7. Sections 21–24 for security/privacy/quality.
8. Sections 28–29 and 38 for execution and release.
9. Registries and schemas before implementing a specific surface.

---

# 1. Executive summary

## 1.1 Goal

Build the best local-first system for turning inexpensive, heterogeneous, owner-authorized cameras
and manually piloted drone footage into a calibrated, economical, privacy-conscious security
sensor mesh that humans and autonomous agents can query and operate safely.

The target product:

- integrates open local standards first and proprietary consumer devices through isolated,
  authorized interoperability adapters;
- preserves original media and timing evidence while producing low-latency proxies and efficient
  analysis surfaces;
- constructs a metric digital twin and calibrated camera/coverage graph using ordinary property
  imagery plus an easy drone or handheld calibration shuttle;
- tracks entities across cameras under geometric and temporal constraints;
- uses a cascade of current open-weight detectors, trackers, multimodal embeddings, video/VLM
  reasoners, and geometry models rather than one monolith;
- distinguishes benign resident/delivery/wildlife/weather behavior from true threats while
  explicitly accounting for unobservable intervals;
- publishes event-level evidence, uncertainty, decision path, and negative evidence;
- archives economically to local storage, Backblaze B2, Cloudflare R2, or compatible backends using
  encrypted content-addressed root-last object graphs;
- exposes bounded, resumable, capability-scoped CLI and MCP surfaces to agents;
- recovers after crashes without duplicating effects or inventing completion;
- improves from operator feedback without silently rewriting truth or safety policy.

## 1.2 Anti-goal

FSS is not a covert-access toolkit, an exploit framework, a public biometric network, an autonomous
weapon or pursuit system, a guarantee of perfect detection, a cloud-required product, a generic smart-home platform, or an excuse to require foreign codec/vendor/model runtimes anywhere in the shipping process topology.

## 1.3 Technology posture

**Non-negotiable production stack:**

- Rust 2024 on the latest **accepted** nightly, pinned exactly after a full promotion gauntlet;
- `#![forbid(unsafe_code)]` in every FSS crate, with no target/feature/test exceptions;
- `asupersync` as the sole asynchronous runtime, ownership tree, cancellation model, budget system,
  deterministic laboratory, and ATP transfer substrate;
- admitted FrankenSQLite mechanisms for the canonical MVCC ledger;
- admitted FrankenFS mechanisms for custody, coherent publication, repair, retrievability, and
  deletion closure;
- Frankensearch/Quill for focused first-party progressive retrieval;
- FrankenGraphDB plus FrankenNetworkX for versioned graph projections, factorized/incremental
  queries, deterministic algorithms, and complexity witnesses;
- Franken Markdown for bounded exact-span knowledge and deterministic evidence reports;
- FrankenTorch as the basis of a focused pure-Rust tensor/operator/kernel/model runtime;
- FastMCP Rust as an optional request-owned presentation adapter;
- Eidetic Engine concepts for provenance-bearing operational memory;
- Doodlestein Self-Releaser receipts as local qualification and release authority;
- a closed dependency universe: FSS, Asupersync, admitted Franken-suite crates, and only a tiny
  machine-registered foundational exception set.

**Explicit production prohibitions:**

- Tokio, async-std, smol, Rayon-owned worker pools, detached threads, or a second cancellation tree;
- Python/PyO3, FFmpeg/libav, OpenCV, ONNX Runtime, libtorch, CUDA runtime bindings, generic model
  servers, browser engines, Node/Electron/Tauri, and proprietary vendor SDKs;
- generic production graph/search/database/message-broker frameworks where a focused first-party
  substrate owns the semantics;
- runtime model/plugin/schema/tokenizer downloads, JIT code generation, or dynamic library/plugin
  loading;
- build-script network access or unlocked release resolution;
- serde-derived canonical durable bytes.

Foreign incumbents remain valuable **pinned laboratory oracles**. FFmpeg/ffprobe, PyTorch/ONNX
Runtime, NetworkX, C SQLite, Tantivy, browsers, and owner-authorized vendor applications can be used
for differential conformance in isolated fixtures. They do not ship and are not fallbacks.

The complete policy is [`DEPENDENCY_CONSTITUTION.md`](docs/DEPENDENCY_CONSTITUTION.md) and
[`architecture/dependency_allowlist.toml`](architecture/dependency_allowlist.toml).

## 1.4 Walking skeleton

The first useful vertical slice is deliberately not a Wyze demo. It is:

1. deterministic replay adapter over synthetic property footage/events;
2. dependency-free semantic state machines and in-memory ledger;
3. source capsule and event schemas;
4. original-byte object custody;
5. cheap pure-Rust detector/tracker reference path with immutable receipts;
6. event hypothesis, policy abstention, and evidence bundle;
7. replay producing the same decision fingerprint under injected faults;
8. UVC camera as first physical sensor.

This proves the architecture without betting the core on a proprietary vendor.

---

# 2. Discovery and ecosystem findings

## 2.1 Research question

The design pass asked:

1. Which consumer cameras/drone paths are actually standards-based, documented, proprietary, or
   unsupported as of 2026-08-30?
2. Which current open-weight model classes are relevant, and what license/deployment constraints
   prevent simply selecting “the latest best model”?
3. Which mechanisms in the user’s Franken projects materially improve correctness, economy, or
   agent operability?
4. What semantic distinctions are essential for rare-event home security?
5. What is the smallest architecture that preserves those distinctions from the first commit?

## 2.2 Device facts that shape the architecture

**FACT:** Insta360 Link is a USB UVC/UAC webcam, not a Wi-Fi security camera. It can serve as a
high-quality standards reference but does not exercise proprietary cloud auth or wireless outdoor
behavior.

**FACT:** Wyze Cam v4’s public product material describes Wi-Fi, H.264, local microSD, app/cloud,
and 2.5K-class video, but no published ONVIF/RTSP contract was found in the checked official
product documentation.

**FACT:** AOSU P1 Max public material describes 4K, wireless/solar, local microSD/base/app and
optional cloud behavior, but no published ONVIF/RTSP contract was found in the checked official
material.

**FACT:** DJI documents live view and transfer through DJI Fly for Flip. The current official
Mobile SDK product list checked for this plan does not include Flip. FSS therefore cannot promise a
native SDK adapter or autonomous control for that product.

**DESIGN:** These findings produce an adapter ladder: replay → UVC/file → RTSP → ONVIF T/M →
documented vendor SDK → authorized lab → import/display bridge. A product is not placed in a more
stable tier because the desired architecture would be easier if it were.

## 2.3 Standards findings

**FACT:** ONVIF Profile T is the preferred modern IP-video profile and includes H.264/H.265,
imaging, motion/tamper events, metadata streaming, and conditional PTZ/audio/HTTPS features.

**FACT:** ONVIF Profile M standardizes analytics metadata and events. Such metadata remains vendor-
derived cognition, not authoritative FSS truth.

**DESIGN:** The ONVIF conformant-products database is the authority for claiming conformance. A
retailer page, package logo, or successful RTSP URL is not Profile T qualification.

## 2.4 Model findings

**FACT:** Current candidate families span distinct tasks and licenses: RF-DETR for fast detection/
segmentation; Grounding DINO and SAM 3 for open-vocabulary/segmentation/tracking; CoTracker3 for
point tracks; Qwen3-VL for multimodal/video reasoning; InternVideo for video representation;
WeMM-Embedding for multimodal retrieval; AV Flamingo for research-only synchronized audio-video;
VGGT/MASt3R-SLAM/CUT3R/Depth Anything for geometry proposals.

**FACT:** Some attractive candidates or checkpoints are noncommercial, restricted, or require
exact license review. Code license and weight license can differ.

**DESIGN:** FSS freezes a model admission protocol, not a champion. Models are immutable
generations behind a process protocol. A research-only oracle may inform evaluation without
becoming a default product dependency.

## 2.5 Cloud archive findings

**FACT:** R2 and B2 expose S3-compatible object-storage paths and low headline storage costs, but
operation, retrieval, egress, minimum-duration, and rounding rules differ and change over time.

**DESIGN:** Provider pricing is a dated runtime manifest. FSS chooses chunk/object sizes and
retention from the actual workload and price manifest. No source constant says “B2 is always
cheapest” or “R2 egress is always free” without an as-of identity.

## 2.6 Franken-stack findings

The source audit now has three levels: `FRANKENSTACK_DEEP_DIVE.md` for the integrated constitution, `docs/deep-dives/` for one-project-at-a-time investigations, and `architecture/franken_imports.json` for machine-enforced mechanism contracts. The decisive imports are:

- Asupersync: region ownership, explicit `Cx` authority, request/drain/finalize cancellation, obligations, deterministic lab/replay, semantic subject service classes, and ATP verified object graphs.
- FrankenSQLite: multi-version anchors, positive and negative semantic witnesses, SSI dangerous structures, semantic merge, flat combining, and bounded regime monitoring.
- FrankenFS: rooted capability I/O, staged/visible/durable/protected publication, COW generations, sealed repair plans, RaptorQ custody, and evidence-dimensional readiness.
- Frankensearch: progressive pinned retrieval, searchable delta versus durable seal, globally ordered ranges and merge=concat, columnar ingest, model-space identity, and pinned-oracle gauntlets.
- Franken Markdown: exact spans, bounded explicit-stack parsing, taint, one representation for deterministic multi-output evidence, and sibling rollback.
- FrankenGraphDB: one version universe, temperature-tiered relations, factorized/WCO execution, Z-set incremental maintenance, branch-per-agent speculation, capability-before-expansion, and plan certificates.
- FrankenNetworkX: CGSE deterministic choices, observable behavior as contract, broad algorithm families, and per-call complexity/decision-path witnesses.
- Dwarf Fortress MCP: evidence anchors, resumable deltas, witnessed absence, semantic plans, delayed-effect truth, obligations, and agent token economy.
- FastMCP Rust: bounded capability-scoped presentation, request-owned children, protocol/version qualification, and no generic authority escape hatch.
- Eidetic Engine: provenance-bearing advisory memory, confidence decay, trauma guard, anti-pattern inversion, and deterministic context packs.
- FrankenTorch and adjacent inference projects: pure-Rust model IR/kernels, scalar oracles, artifact identity, and hardware specialization without foreign production runtimes.
- Doodlestein Self-Releaser: workflow-as-portable-spec, clean source/sibling closure, resumable native targets, exact assets, root-last release publication, and download verification.

The rule is not “depend on everything.” Each imported mechanism has a semantic owner, substitute prohibition, deterministic reference model, soundness boundary, and admission gate.

## 2.7 Synthesis

The target architecture is:

```text
pure deterministic semantic core
  surrounded by capability-scoped effects and hostile-runtime process boundaries
  recording immutable evidence and receipts in a crash-safe ledger/object graph
  maintaining a calibrated multi-version physical world model
  deriving cognition through versioned model pipelines
  exposing bounded evidence-bearing projections to agents and humans
  exercised under replay, faults, red-team tactics, and statistical qualification
```

---

# 3. Mission, goals, non-goals, and North Star scenarios

## 3.1 Mission

Build a world-class, economically scalable, privacy-conscious home/property security sensor mesh
from inexpensive consumer hardware, with enough semantic rigor that agents can observe, reason,
learn, and operate over long horizons without hidden omniscience, ambiguous effects, or fragile
vendor coupling.

## 3.2 Goals

### `GOAL-001` — Heterogeneous owner-authorized interoperability

Integrate standards-based and selected proprietary devices while using normal owner authorization,
exact compatibility identities, least privilege, and safe failure under firmware/app drift.

### `GOAL-002` — Source and timing truth

Preserve original encoded media identities, packet continuity, conservative capture-time intervals,
and derivation receipts so later analysis can be audited or replayed.

### `GOAL-003` — Low-latency live operation

Provide an economical live path for operators and agents without forcing analysis/archive formats
to serve the same latency objective.

### `GOAL-004` — Calibrated sensor mesh

Estimate camera intrinsics/extrinsics/time alignment and property geometry with uncertainty, then
compute coverage, overlap, occlusion, blind spots, and expected transitions.

### `GOAL-005` — Rare-event security quality

Maximize event-level AUPRC and observable-threat recall subject to a practical false-alert budget,
while retaining misses and hard negatives as first-class evidence.

### `GOAL-006` — Explicit observability

Never treat no detection as evidence of absence unless the relevant zone/time was healthy,
continuous, calibrated, and within the declared model operating envelope.

### `GOAL-007` — Explainable event truth

Every event/alert should answer: what was observed, by which independent failure domains, under
what uncertainty, which models/policies contributed, what contradicted it, and what would change
the decision.

### `GOAL-008` — Crash and retry correctness

Recover sessions, streams, event revisions, archive roots, and effects after failure without
duplicating actions or inventing terminal outcomes.

### `GOAL-009` — Privacy by architecture

Keep primary operation local; apply masks before unauthorized boundaries; disable biometrics by
default; minimize retention; and prove deletion closure.

### `GOAL-010` — Economical storage and compute

Measure and control bytes, objects, operations, model calls, GPU seconds, joules, and cost per
camera/property/event rather than optimizing only model accuracy.

### `GOAL-011` — Agent efficiency

Let an agent obtain the smallest sufficient anchored view, receive resumable deltas, inspect
evidence, and perform typed prepared effects with few calls and bounded tokens.

### `GOAL-012` — Deterministic diagnosis

Given a proof bundle and compatible generations, reproduce the semantic event path and decision
fingerprint under the declared deterministic model.

### `GOAL-013` — Honest compatibility and readiness

Represent support as readiness dimensions and exact tuples, not a boolean brand logo.

### `GOAL-014` — Graceful degradation

Continue safe subsets when semantic models, graph/search projections, remote archive, vendor cloud,
GPU, or a sensor fail; surface every degradation and repair path.

### `GOAL-015` — Learn from deployments

Use evidence-linked operator feedback and memories to improve routing, prompts, hard-negative
coverage, and runbooks without silently mutating canonical evidence or hard safety/privacy policy.

### `GOAL-016` — Safe extensibility

Make device, media, model, archive, alert, and agent adapters narrow versioned protocols so new
hardware/models do not enter the trust root.

### `GOAL-017` — Local release authority

A release is authorized by reproducible local qualification over required platforms/devices/models,
with hosted CI as supplemental evidence.

### `GOAL-018` — Research value

Create a realistic benchmark substrate for long-horizon multimodal agents, sequential decision
systems, sensor fusion, calibration, rare-event detection, and robust uncertainty.

## 3.3 Non-goals

- `NONGOAL-001`: accessing any device/account/footage without owner authorization.
- `NONGOAL-002`: publishing credential bypasses, universal tokens, or vendor exploits.
- `NONGOAL-003`: covert monitoring or evasion of recording/owner indicators.
- `NONGOAL-004`: public face search or cross-property identity graphs.
- `NONGOAL-005`: absolute “never miss” or “zero false alarm” claims.
- `NONGOAL-006`: autonomous pursuit, confrontation, weapon deployment, or physical enforcement.
- `NONGOAL-007`: autonomous drone flight in v1.
- `NONGOAL-008`: replacing every NVR, smart-home system, or vendor app immediately.
- `NONGOAL-009`: cloud dependence for core acquisition/cognition/control.
- `NONGOAL-010`: any production dependency on FFmpeg/Python/ONNX/CUDA/proprietary SDK runtimes, whether in-process or hidden behind IPC.
- `NONGOAL-011`: one giant end-to-end neural model as the sole product logic.
- `NONGOAL-012`: graph/search/model outputs as canonical source of truth.
- `NONGOAL-013`: benchmark theater or support claims derived from source presence.
- `NONGOAL-014`: premature custom codecs, filesystems, or consensus protocols without costed need.

## 3.4 North Star acceptance scenarios

### Scenario NS-1 — Sneaky perimeter approach

A staged actor in dark clothing approaches through a weakly lit edge, crouches/crawls, pauses
behind foliage, and crosses between two camera views. FSS retains source evidence, notices degraded
quality, tracks partial observations, uses geometry/time to associate views, requests a bounded
higher-cost verifier, corroborates or explicitly abstains, and delivers an alert with coverage and
uncertainty. The proof bundle replays the semantic decision.

### Scenario NS-2 — Resident takes out trash

A resident exits an authorized door, traverses the usual path, handles bins, and returns while a
raccoon appears nearby. FSS uses continuity, zone transition, short-lived local appearance/session
context, trajectory, object/action evidence, and optional trusted-device context to avoid a high-
severity alert. It does not permanently identify the resident or erase the event.

### Scenario NS-3 — Camera silently fails

A Wi-Fi camera freezes or repeats frames while its app still says online. FSS detects continuity/
scene/timestamp anomaly, removes its cells from effective coverage, raises a sensor-health event,
prevents absence-of-detection from suppressing a threat, and records the blind interval.

### Scenario NS-4 — Vendor firmware drift

An app or firmware update changes authentication, crop, timestamp buffering, or stream format. The
exact tuple no longer matches. The adapter fails closed or enters declared import-only/degraded
mode, preserves current evidence, rolls back where possible, and does not claim continued support.

### Scenario NS-5 — Drone-assisted installation

The operator manually flies DJI Flip or another camera drone through fixed views with a safe
calibration marker. FSS imports/captures authorized footage, reconstructs geometry/trajectory,
solves fixed-camera poses and time offsets, computes coverage/blind spots, and publishes a
certificate or rejects it with residual evidence. No autonomous flight is used.

### Scenario NS-6 — Archive interruption

Network fails halfway through an event archive. Children staged before failure remain unreachable
from any published root. Local spool carries a bounded obligation. Recovery resumes idempotently,
publishes the root last, then performs a retrieval sample. The UI distinguishes local, staged,
published, and verified.

### Scenario NS-7 — Agent investigates overnight activity

An agent requests changes since an anchor, receives a compact ranked set of events and health
changes, asks why one was benign, follows evidence handles, compares similar prior false alarms,
and prepares—but cannot automatically commit—an evidence export or camera movement without the
required capability.

### Scenario NS-8 — Privacy deletion

The operator requests deletion of an event. FSS computes a sealed closure over local/remote source
objects, proxies, thumbnails, indexes, graph edges, model caches, reports, and memories; commits the
plan; records physical/cryptographic deletion or exact blockers; and produces a proof.

---

# 4. Semantic truth model

## 4.1 Three planes

FSS MUST separate three semantic planes in types, persistence, capabilities, and process
boundaries.

### Authority plane

The authority plane contains facts the system is permitted to treat as canonical:

- registered sensor/device/account identities and exact generations;
- credential *references* and scopes, never model-visible secret values;
- configuration, privacy, retention, and policy revisions;
- original source-object manifests or explicit non-retention records;
- capture-time intervals, receive times, packet continuity, decode receipts, and health state;
- immutable operation intents, capabilities, leases, idempotency keys, and receipts;
- immutable event revisions and their evidence edges;
- calibration certificates and invalidation state;
- archive roots, custody, retrievability, export, hold, and deletion state;
- proof-bundle roots, claim types, and release decisions.

Authority is not synonymous with “correct physical truth.” A camera packet can be authentic to a
registered stream and still show a replayed scene. Authority means the provenance and state are
canonical records, not that their semantic interpretation is infallible.

### Cognition plane

The cognition plane contains derived, revisable, and rebuildable products:

- decoded frames, crops, thumbnails, optical flow, quality metrics;
- detections, masks, keypoints, point tracks, object tracks;
- appearance/text/video/audio embeddings;
- camera/scene/trajectory proposals and optimization intermediates;
- cross-camera association hypotheses;
- VLM captions, questions, rationales, and classifications;
- event hypotheses before canonical revision publication;
- vector/lexical indexes, graph materializations, summaries, memories;
- recommended effects, calibration sessions, and hard-negative tests.

Cognition may cite authority and create new authority-plane revisions through a validated publisher.
It cannot mutate authority directly or possess effect capabilities.

### Effect plane

The effect plane contains operations that change external or durable state:

- alert dispatch/acknowledgement;
- PTZ, imaging, spotlight/siren, audio, and device settings;
- archive publication/deletion and retention changes;
- privacy-mask changes;
- evidence export/disclosure;
- activation/rollback of model, adapter, calibration, policy, or index generations;
- repair application;
- future drone flight.

Effects MUST be explicit, capability-scoped, idempotent, preconditioned, receipted, and later
observed/verified. A model output can be an input to a prepared effect; it cannot be the authority
to commit it.

## 4.2 Evidence classes

FSS uses an ordered evidence vocabulary without pretending that higher class means universally
true:

| Class | Meaning | Example |
|---|---|---|
| `assertion` | unverified claim or imported statement | VLM prose, operator note before review |
| `derived` | deterministic/model output tied to exact inputs/generation | detector mask, appearance embedding |
| `observed` | decoded/parsed observation tied to retained source or explicit custody record | frame region, RTP sequence gap |
| `corroborated` | support from independent failure domains or a registered exception | same trajectory across two local cameras |
| `verified` | deterministic/cryptographic/physical postcondition under declared model | digest match, root reachability, readback pose |

Evidence class is attached to an edge or claim, not globally to an object. A cryptographically
verified packet may provide weak evidence that the scene is live.

## 4.3 Observations, hypotheses, events, and alerts

An **observation** is a bounded statement directly tied to sensor/source evidence: pixels changed,
a box/mask exists, a timestamp interval, a camera moved, or packets stopped.

A **hypothesis** explains observations: a person is crawling, two tracks are the same entity, a
camera is replaying old frames, or a resident is taking out trash.

An **event revision** is a canonical immutable snapshot of a hypothesis and its evidence,
uncertainty, contradictions, health context, and decision path.

An **alert** is an effect selected by a versioned policy from an event revision. An alert does not
make the hypothesis true; an eventual operator resolution may confirm, reject, or leave it
indeterminate.

## 4.4 Negative evidence

Negative evidence is first-class and must name its observability preconditions. Examples:

- camera B was healthy and should have seen the predicted transit, but did not;
- the object does not cast motion/occlusion consistent with the scene;
- the expected door did not open;
- a candidate does not persist under an independent detector;
- a model failed on a prior similar black-clothing/crawling scenario;
- firmware generation is uncertified;
- the current zone was occluded, making absence non-evidence.

The negative-evidence ledger records failed approaches, contradictions, near misses, blind spots,
and assumptions. It is used in review and release qualification, not hidden to improve headline
metrics.

## 4.5 Invariants

The machine-readable invariant registry is authoritative. Load-bearing examples:

- `INV-001`: authority, cognition, and effect records are type-distinct.
- `INV-002`: model output is neither authoritative evidence nor direct effect authority.
- `INV-004`: capture time is an interval with a declared basis.
- `INV-005`: adapter acceptance, first frame, and continuity verification differ.
- `INV-011`: object graphs publish root last.
- `INV-013`: model generation is immutable; mixed-generation score spaces are forbidden.
- `INV-016`: degraded observability invalidates absence-of-detection evidence.
- `INV-017`: privacy masking occurs before unauthorized boundary.
- `INV-019`: drone is manual calibration/observation in v1.
- `INV-028`: quality is event-level under realistic class imbalance.
- `INV-030`: an arithmetically impossible SLO is a registry/design failure.

---

# 5. Identity, generations, anchors, and time

## 5.1 Stable identities

FSS identifiers are opaque and stable. They MUST NOT embed mutable names, IP addresses, firmware,
paths, or secrets. Human labels are revisions.

Core identities include:

- property, principal, capability, lease, operation;
- sensor, device generation, adapter generation, stream generation;
- packet/segment/capsule/source object/derivative;
- clock and calibration generation;
- zone, coordinate frame, coverage cell;
- model, model generation, index generation;
- observation, track, association, event, event revision;
- policy and privacy generation;
- archive root, export, deletion, proof bundle.

Content identities use a registered digest algorithm and canonical encoding. The initial schemas
show `algorithm:hex`; the exact preferred algorithm is frozen by an ADR before production.

## 5.2 Device generation

A device generation binds, as applicable:

```text
manufacturer
product/model and hardware revision
serial pseudonym / device certificate fingerprint
firmware version
base-station firmware
mobile app/SDK/API version
account region and relevant feature flags
adapter implementation/build
observed capability manifest
```

A firmware or app change creates a new generation even when marketing model is unchanged.

## 5.3 Stream generation

A stream generation begins on initial start, reconnect that changes continuity assumptions, codec/
resolution/crop/time basis change, or device-generation rollover. It owns sequence space,
negotiated media metadata, clock model, source custody, and continuity state. Sequence reset without
a new generation is invalid.

## 5.4 Model generation

A model generation binds code, weights, license, runtime, preprocessing, frame/audio sampling,
prompt/templates, quantization, precision, device routing, output schema, calibration, and resource
policy. An index generation binds exactly one compatible producer generation.

## 5.5 Version universe and observation anchor

An observation anchor is a compact immutable tuple:

```text
ledger revision
active device/stream generations
clock generation(s)
calibration generation
privacy/retention generation
model/index generations
policy generation
search/graph materialization certificates
build generation
```

A query runs against one coherent universe. If a requested universe is unavailable or a projection
cannot prove consistency, the result is degraded or rejected rather than silently mixing latest
components.

## 5.6 Resumable deltas

A delta from anchor A to B contains:

- created/changed/tombstoned canonical identities;
- stream/health/coverage changes;
- event revisions and active obligations;
- projection certificates and invalidations;
- evidence handles and continuation;
- resnapshot requirement when history/compatibility is unavailable.

Deltas are hash-anchored and bounded. The client can resume without re-reading the entire property.

## 5.7 Time model

A single timestamp is inadequate. Each source item records:

- device-reported time and basis, if present;
- host receive monotonic time;
- mapping to disciplined UTC/property monotonic basis;
- earliest/latest plausible capture time;
- source of uncertainty: exposure, rolling shutter, encoding, buffering, network, vendor relay,
  decode reorder, clock quantization, offset/drift model;
- sequence and discontinuity;
- clock-generation identity.

The interval MUST expand when evidence worsens. It cannot be narrowed by a model without retained
synchronization evidence.

## 5.8 Cross-camera temporal reasoning

Association tests overlap and feasible transit intervals. A 500 ms uncertainty can be harmless for
a person crossing a yard and fatal for a fast drone/vehicle or closely spaced cameras. Each
operation declares its maximum tolerable uncertainty. When exceeded, geometry-dependent negatives
and identity associations abstain or degrade.

## 5.9 Clock calibration

Preferred evidence order:

1. hardware/device timestamp tied to a characterized clock;
2. local NTP/PTP/host monotonic mapping;
3. visible LED pseudorandom temporal code;
4. shared audio chirp where authorized;
5. common motion/flash events;
6. statistical cross-correlation;
7. conservative receive-time bounds.

Each method has a failure model and validation residual. Vendor-cloud live view generally has wider
and time-varying uncertainty than local RTP/UVC.

---

# 6. Layered architecture, trust domains, and dependency policy

## 6.1 Four operational planes

FSS refines the original three semantic planes with an explicit packet plane:

1. **Packet plane:** transport bytes, protocol packets, compressed access units, source timing, and
   continuity. It cannot infer events or authorize effects.
2. **Authority plane:** identities, generations, source custody, `EvidenceDeltaBatch` history,
   calibration/coverage certificates, policies, effects, obligations, and receipts.
3. **Cognition plane:** decoded media, tensors, models, tracks, associations, graph/search
   projections, digital twins, attention, and operational memory. It is rebuildable from named
   authority roots.
4. **Effect plane:** alerts, camera settings/PTZ, retention/deletion/export, activation, repair
   mutation, and any future physical operation. It is narrow, fenced, idempotent, and
   reconciliation-first.

```text
Packet capsules → Authority deltas → Cognition projections
       ↑                │                    │
       └──observed──── Effect plans ←witnesses/intent
```

No plane silently redefines another plane's semantics.

## 6.2 Trust and failure domains

| Domain | Contains | May do | Must not do |
|---|---|---|---|
| FSS semantic core | types, ledger contracts, witnesses, policy, effects, registries | define authority and decisions | parse arbitrary native/plugin code or recover ambient authority |
| Asupersync runtime | regions, `Cx`, budgets, obligations, LabRuntime, ATP | own and schedule work; move immutable object graphs | become a semantic database or effect shortcut |
| Device/protocol | UVC, RTSP/RTP, ONVIF, focused proprietary adapters | authenticate authorized devices and emit packet/capability truth | write event/alert truth or expose generic vendor methods |
| Media | bounded parsers, codecs, containers, live proxy, source maps | preserve/transform media with receipts | replace source evidence or hide discontinuity |
| Model | first-party tensor/operator/kernel runtime and immutable packages | emit typed derived results | download code/models, mutate authority, compare mixed model spaces |
| Graph/search | immutable derived generations and registered algorithms | rank, connect, explain, propose | authorize effects or claim absence without coverage |
| Archive/repair | object graphs, encryption, ATP, replicas, retrievability | stage/verify/publish/repair immutable objects | treat upload ACK as archive completion or carry mutation authority |
| Presentation | CLI, MCP, TUI/UI, reports | expose bounded public projections and prepared effects | gain administrator authority or leak private counts/absence |
| Qualification oracle | pinned foreign tools and real-device labs | compare behavior and produce evidence | ship, become fallback, or define production truth |

Failures are classified at the boundary. A codec/model/graph optimization can fail while source
custody remains truthful. A search generation can lag while authority stays available. A provider
can be indeterminate without making the local root indeterminate.

## 6.3 Closed dependency universe

Production resolution is:

```text
std/core/alloc
+ FSS workspace
+ Asupersync
+ exact admitted Franken-suite revisions
+ tiny DEP-recorded foundational exceptions
```

Every exception names purpose, owner, enabled features, transitive closure, unsafe/build-script/
thread/network behavior, replacement trigger, and evidence. “Widely used,” “fundamental,” and
“convenient” are not sufficient arguments. Cryptography, hashing, compression, TLS, SIMD, CLI,
media, and platform crates prefer existing first-party surfaces and otherwise require separate
admission.

Release qualification proves the dependency graph resolves locked and offline. First-party path
work is captured at exact clean revisions so mutable sibling checkouts cannot leak into a binary.

## 6.4 Pure Rust and memory safety

FSS crates unconditionally forbid unsafe code. Low-level platform or vector primitives, if needed,
belong in separately reviewed first-party substrate crates exposing safe contracts; the FSS
workspace never creates a local exception.

“Out of process” does not turn a foreign runtime into pure Rust. Shipping media, model, graph,
archive, UI, and orchestration semantics must be first-party Rust or the capability remains
unsupported. Foreign tools are laboratory oracles only.

## 6.5 Durable-format boundary

Control/report JSON may use Serde. Canonical evidence, ledger, media index, tensor/model, graph,
search, transfer, repair, and release bytes use hand-written versioned formats with magic, explicit
endianness, hard bounds, canonical ordering, checksums, migration fixtures, and corruption tests.
Rust layout and derive output are never persistence semantics.

## 6.6 No-substitute architecture

The following are explicitly rejected:

- one mutable global “current world” cache;
- a raw message bus as the semantic architecture;
- one VLM prompt that subsumes tracking, timing, policy, and effects;
- a generic graph database as authority;
- source media discarded after proxy transcode;
- upload ACK treated as durable/retrievable archive;
- cache/search miss treated as evidence of absence;
- generic shell, SQL, vendor, codec, model, or drone-control tool surfaces;
- foreign services hidden behind IPC and relabeled first-party;
- a large dependency graph justified by future flexibility;
- hosted CI as release authority;
- benchmark wins without same-binary semantic receipts.

The detailed constitution is [`DEPENDENCY_CONSTITUTION.md`](docs/DEPENDENCY_CONSTITUTION.md).

# 7. Runtime, ownership, cancellation, budgets, and obligations

## 7.1 Region tree

Target ownership:

```text
ProcessRegion
└── PropertyRegion
    ├── LedgerRegion
    ├── ObjectStoreRegion
    ├── ProjectionRegion
    ├── SensorRegion*
    │   ├── AdapterSessionRegion
    │   ├── ReceiveRegion
    │   ├── ContinuityRegion
    │   ├── MediaRegion
    │   ├── AnalysisRegion
    │   └── ArchiveRegion
    ├── EventRegion*
    │   ├── EvidenceWindowRegion
    │   ├── ModelCallRegion*
    │   ├── AssociationRegion
    │   ├── PolicyRegion
    │   └── AlertObligationRegion
    └── OperationsRegion
```

Every child has one owner. A region cannot close while descendants are silently running.

## 7.2 Context authority

An FSS context carries:

- trace/operation/principal/capability;
- deadline, priority, and cancellation reason;
- poll, byte, frame, token, model, GPU-time, object-operation, and memory budgets;
- privacy/retention scope;
- anchor/version universe;
- lease/fence and idempotency identity where effectful;
- deterministic seed/lab controls.

Context cloning narrows or preserves authority; it never broadens it.

## 7.3 Cancellation protocol

1. `request`: mark cancellation, stop new work/effects.
2. `drain`: propagate to children, stop reads, close inputs, settle channels, persist partial
   receipts, and, only in sealed laboratory profiles, terminate and wait for owned oracle process groups.
3. `finalize`: abort/commit staged state as contract permits, reconcile ambiguous effects, release
   resources/secrets/leases, emit quiescence proof.

Hard kill is a last containment mechanism and produces a recovery obligation. It is not represented
as graceful cancellation.

## 7.4 Backpressure

Each edge is bounded. Policies include:

- source packet custody gets highest priority and cannot be blocked indefinitely by inference;
- live proxy can drop/skip derivatives under declared semantics;
- analysis can downsample or route to cheaper models under registered policy;
- archive backlog consumes a bounded encrypted spool and raises degradation before full;
- high-severity candidate evidence can preempt low-value summarization;
- no silent dropping of source/event evidence required by active obligations.

Dropped data emits a continuity/derivation receipt and affects coverage.

## 7.5 Outcome model

Runtime outcomes preserve completed, expected error, cancelled, and panicked. Domain state adds
indeterminate when a remote/physical effect may have occurred. Mapping rules MUST NOT flatten
cancellation or panic into ordinary adapter errors.

## 7.6 Obligations

Examples:

- after stream start, observe first frame and continuity or reach terminal failure;
- after alert commit, reconcile delivery status;
- after PTZ commit, observe pose and later restore or record exception;
- after archive child upload, publish/abort root or collect orphan;
- after deletion commit, prove closure or name blocker;
- after model activation, complete shadow/rollback window;
- after calibration activation, monitor validity landmarks;
- after cancellation, prove quiescence.

Obligations are durable and resume after crash. A process exit cannot erase them.

## 7.7 Deterministic reference runtime

Before Asupersync integration, a single-threaded virtual-time runtime models the same state
transitions. It controls clock, randomness, packet arrival, sealed laboratory-oracle results,
ledger/object faults, model outputs, and alert receipts. This is the semantic oracle for optimized/concurrent
paths.

---

# 8. Device discovery, authorization, and adapter protocol

## 8.1 Adapter goals

An adapter translates one device/vendor surface into typed FSS operations without importing its
failure semantics into the core. It owns:

- discovery/identity/capabilities;
- authorization and token refresh inside secret domain;
- stream/file/event/control operations;
- exact device/firmware/app generation;
- reconnect/rate-limit/cloud behavior;
- sanitized diagnostics and quiescence.

It does not own canonical event semantics, retention, privacy policy, model prompts, archive keys,
or alert authority.

## 8.2 Discovery

Discovery is explicit and bounded:

- configured USB interfaces;
- configured local subnets/interfaces with rate/target limits;
- ONVIF WS-Discovery where authorized;
- exact IP/URL/device identifier;
- owner account enumeration after authentication;
- imported files/buckets.

FSS is not an internet camera scanner. Discovery results are candidates until identity and
authority are confirmed.

## 8.3 Authorization

Supported authority forms may include:

- local device credentials;
- client certificate/pairing token;
- vendor OAuth/session from normal owner login;
- OS-mediated USB/camera permission;
- bucket application key;
- physical import of SD/file content.

The canonical config stores an opaque secret reference. Password/token values never enter model,
trace, report, or fixture paths. Revocation/rotation is a required adapter test.

## 8.4 Adapter protocol messages

Initial conceptual protocol:

- `probe(request) -> DeviceIdentity + CapabilityManifest + evidence`;
- `authorize(secret_handle, requested_scopes) -> AuthReceipt`;
- `start_stream(plan) -> OperationReceipt`;
- `next_capsule(budget) -> SensorCapsule | degradation | terminal`;
- `subscribe_events(plan) -> VendorEventCapsule*`;
- `prepare_control(intent, anchor) -> PreparedPlan`;
- `commit_control(plan_digest, authority) -> OperationReceipt`;
- `readback(control_id) -> Observation`;
- `stop_stream(operation_id) -> quiescence receipt`;
- `doctor(scope) -> sanitized diagnostic bundle`.

All arrays/strings/bytes/concurrency are bounded. Unknown enum/protocol generations are explicit.

## 8.5 Acquisition lifecycle

`Requested → Authenticated → AdapterAccepted → FirstFrameObserved → ContinuityVerified`, with
Degraded, Failed, Cancelled, and Indeterminate branches. Each transition needs a witness:

- auth receipt;
- adapter ACK/request digest;
- decodable source-linked frame;
- continuity window with sequence/time bounds;
- degradation evidence;
- quiescence receipt.

## 8.6 Controls

Device control uses prepare/commit/readback. The plan includes current settings/pose, desired
change, bounds, privacy/coverage impact, restore/timeout, device generation, precondition anchor,
idempotency key, and lease. A timeout after dispatch becomes indeterminate until readback.

## 8.7 Vendor events

Vendor motion/person/package labels are ingested as `derived` evidence tied to the device
generation. They can seed candidate windows but cannot replace FSS source/continuity/model evidence.
Duplicated/backfilled/out-of-order vendor events are normalized with original IDs and times.

## 8.8 Compatibility tuple

A support claim names exact hardware, firmware, base, app/SDK, region/feature flags, adapter build,
platform, and capability dimensions. Unknown tuples fail closed or enter registered degraded mode.

---

# 9. Standards-first camera integrations

## 9.1 Replay and file import

`ADP-REPLAY-001` is first. It can emit packets, frames, metadata, clock models, health, control
receipts, and faults from a deterministic fixture root. It is the oracle for all later adapters.

`ADP-FILE-001` ingests MP4/MKV/images/audio with source digest, explicit capture-time uncertainty,
bounded parsing, and no claim of live continuity. Sidecar metadata/telemetry is independently
identified.

## 9.2 UVC/UAC

UVC is the first physical path because it is local, widely understood, and avoids vendor-cloud
semantics. Requirements:

- enumerate modes and stable device identity;
- choose exact format/resolution/fps/controls;
- preserve kernel/device timestamps and receive intervals;
- handle hotplug, permission, suspend/resume, mode drift;
- capture audio only when explicitly enabled;
- bound buffers and prove cancellation;
- qualify Insta360 Link as a reference fixture without assuming proprietary gimbal controls.

## 9.3 RTSP/RTP

RTSP adapter supports a bounded RFC-aligned subset before extension:

- URI/auth configuration; no URL secret logging;
- OPTIONS/DESCRIBE/SETUP/PLAY/TEARDOWN;
- UDP/TCP interleaved transport as registered;
- SDP bounds and codec negotiation;
- RTP sequence/reorder/loss/marker/time mapping;
- RTCP where available;
- reconnect with new stream generation;
- server timeout/keepalive variants;
- digest/basic auth only under explicit transport security policy;
- malicious server/SDP/RTP corpus.

## 9.4 ONVIF Profile T

The client owns:

- bounded discovery and device identity;
- capabilities and media profiles;
- stream URI retrieval without secret leakage;
- imaging settings and events;
- motion/tamper metadata;
- PTZ and audio only if exact conformant feature present and separately qualified;
- HTTPS/certificate policy;
- time configuration and metadata relation;
- exact product conformance record.

ONVIF conformance does not guarantee implementation quality. Live device oddities are retained in
compatibility evidence.

## 9.5 ONVIF Profile M

Profile M metadata/events enter as vendor cognition. FSS preserves:

- source metadata message and timestamp;
- device/profile generation;
- object/class/geometry fields;
- mapping to FSS observation taxonomy;
- unsupported/unknown fields;
- conflicts with FSS models.

Vendor face/license-plate/body fields do not activate corresponding privacy-sensitive FSS features.

## 9.6 NVR and bridge integrations

A standards NVR can be an acquisition source, but FSS records whether streams are direct,
transcoded, delayed, or generated by the NVR. Multiple cameras behind one NVR share a failure
domain. NVR event labels remain derived.

---

# 10. Proprietary camera interoperability lab

## 10.1 Scope

Wyze Cam v4 and AOSU P1 Max begin as `T3 authorized lab` because the checked public documentation
does not provide an open stream contract. The lab investigates owner-authenticated interfaces
without bypassing authorization or publishing broadly dangerous secrets.

## 10.2 Preferred path order

1. official local standard hidden in exact product docs/conformance registry;
2. official SDK/API with exact product support;
3. local SD/base export;
4. vendor account export/share intent;
5. owner-side app/display capture;
6. sanitized traffic/protocol study;
7. minimal authenticated client;
8. stop at auth bypass/device security weakening/third-party exposure.

## 10.3 Simulator first

Live observations produce sanitized deterministic protocol simulators. Adapter development and CI
run against those. Live devices are used for differential qualification, not as permanent test
dependencies.

## 10.4 Battery/event-driven semantics

Solar/battery cameras may sleep or expose only event clips. The adapter manifest must state:

- continuous, wake-on-motion, scheduled, or import-only;
- pre-roll/post-roll behavior;
- wake latency and missed-event evidence;
- battery/solar state;
- cloud/base dependence;
- inability to observe between events.

FSS coverage explicitly models these duty cycles. It cannot count an asleep event camera as
continuous coverage.

## 10.5 App/display bridge

A display capture bridge is allowed only with accurate provenance. It loses source packet,
timestamp, metadata, and possibly resolution fidelity. It may be valuable for temporary live view,
calibration, or research but cannot claim camera-source archive integrity or continuity without
independent evidence.

## 10.6 Promotion

A proprietary adapter remains lab-only until exact tuple auth/revocation, secret isolation,
continuity, cancellation, malformed input, reconnect, cloud outage, firmware drift, privacy,
support-bundle, soak, and maintenance ownership all pass.

---

# 11. DJI Flip and drone-capture boundary

## 11.1 Initial role

DJI Flip is a manually piloted moving camera and calibration shuttle. FSS seeks access to footage
the owner can legitimately view or transfer through DJI Fly/controller/device storage. It does not
assume Mobile SDK support or autonomous control.

## 11.2 Capture paths

Ordered preference:

1. original recorded files plus official metadata export;
2. QuickTransfer/import with source digest;
3. owner-side live-view capture bridge with declared fidelity/time uncertainty;
4. officially supported SDK path if/when exact product support exists and qualifies.

## 11.3 Flight separation

Video acquisition and flight control are distinct capabilities/processes. `CAP-DRONE-CAPTURE-001`
may exist while `CAP-DRONE-FLIGHT-001` remains disabled. A successful live-view experiment cannot
implicitly create flight authority.

## 11.4 Calibration mission

The operator follows a generated but non-commanding checklist: safe areas, marker/anchor placement,
slow passes, overlap coverage, hovers, loops, and protected-volume edges. FSS records the intended
session but does not command the aircraft in v1.

## 11.5 Telemetry

Officially available telemetry is ingested with exact source and uncertainty. Missing telemetry is
not fabricated; vision-only trajectory/scale proposals use anchors and residuals. Controller/app
screen overlays are OCR-derived evidence, not authoritative telemetry.

## 11.6 Future autonomous flight

Autonomy requires a separate architecture covering geofencing, regulatory/airspace constraints,
obstacle avoidance, people/animal safety, battery/link loss, return-to-home, command authentication,
manual override, simulation, hardware qualification, and liability. It is not a minor adapter
extension and cannot be smuggled through an MCP tool.

---

# 12. Media acquisition, source custody, decoding, and live delivery

## 12.1 Three representations

### Source evidence path

Original encoded packets/files and metadata, when retention permits. This is the replay/forensics
basis. It is chunked/content-addressed and does not wait for models.

### Live operator path

Low-latency remux/transcode/proxy optimized for glass-to-glass latency and adaptive bandwidth. It
is disposable and can drop frames under declared semantics.

### Analysis path

Decoded/color-normalized/scaled/sampled surfaces optimized for models and geometry. Every surface
has a derivation receipt.

The three paths may share work but never identities or truth semantics.

## 12.2 Sensor capsule

A capsule binds sensor/stream generation, sequence, capture interval, receive time, media metadata,
source/proxy digests, frame count, continuity/decode/firmware state, privacy/retention, and
publication root. It is the atomic handoff between acquisition and downstream subsystems.

## 12.3 Source custody

Policy options:

- retain original encrypted ring buffer;
- retain only event windows;
- retain source packet hashes/metadata but not bytes;
- import immutable source file;
- prohibit audio/source in a privacy zone.

Omission is explicit. A downstream model receipt cannot imply unavailable source bytes exist.

## 12.4 Pure-Rust packet, codec, and container kernel

Production owns the narrow media waist in safe Rust:

```text
transport bytes
→ RTSP/RTP/RTCP or UVC packet truth
→ H.264/H.265/MJPEG/audio access-unit parsers
→ container/sample timeline
→ source custody
→ optional decode surface
→ live and analysis derivatives
```

Initial codec priorities follow inexpensive cameras: H.264/AVC, H.265/HEVC, MJPEG/JPEG, and the
small set of audio codecs required by qualified devices. AV1 becomes an archive/proxy target after
its first-party kernel passes admission. Parsers and decoders are independently qualified; a parser
may preserve and index an unsupported profile without claiming decoded-frame support.

Every parser/decoder declares hard byte, nesting, reference-frame, dimensions, bit-depth, memory,
CPU, and output limits. Decoded surfaces use immutable/frozen storage or generation-leased pools;
models and UI views cannot observe a buffer after reuse. Scalar semantics remain the oracle for
safe optimized/SIMD kernels.

FFmpeg/ffprobe and browsers are pinned differential oracles in lab images. They never ship, and
ordinary operation does not invoke them. See
[`docs/STREAMING_AND_MEDIA_KERNEL.md`](docs/STREAMING_AND_MEDIA_KERNEL.md).

## 12.5 Remux before transcode

When source codec/container permits, FSS remuxes for proxy/archive rather than decoding and
re-encoding. Transcode is chosen for compatibility, bitrate, privacy redaction, or analysis, with a
cost/quality receipt.

## 12.6 Live delivery

Candidate live surfaces:

- WebRTC for interactive operator view;
- LL-HLS/CMAF/fMP4 for broad clients and bounded latency;
- local shared-memory/frame transport for same-host analysis;
- RTP/RTSP relay only where security/client semantics justify it.

The live gateway has no vendor credential access. It receives authorized proxy streams and enforces
session auth, bandwidth, privacy, and expiration.

## 12.7 Frame sampling

Sampling is adaptive but bounded:

- health/tamper sampling always-on at cheap cadence;
- motion/change raises candidate cadence;
- detector/tracker consumes selected frames;
- event window expands pre/post via source ring;
- temporal VLM receives sparse keyframes or bounded clip;
- geometry/calibration sessions have separate high-fidelity policy;
- every drop/sample choice is reproducible from policy and source sequence.

## 12.8 Audio

Audio is disabled by default. When enabled:

- zone/purpose/consent/retention are explicit;
- original and derived audio identities are separate;
- speech transcription is privacy-sensitive cognition;
- synchronized audio-video models are separately licensed/admitted;
- audio alone cannot identify a person by default;
- microphone failure does not invalidate video coverage unless policy required audio.

## 12.9 Media SLOs

- no acknowledged/published source capsule lost under qualified crash model;
- p95 LAN live-proxy target from registered capture point;
- bounded first-frame and reconnect times by adapter class;
- no unbounded buffering under downstream slowdown;
- source ingestion survives model/GPU failure;
- quiescence leaves no codec process/descriptor.

---

# 13. Canonical ledger, object storage, encryption, and archive

## 13.1 Canonical ledger responsibilities

The ledger records identities and small canonical state; large media and model artifacts live in
content-addressed object storage. Initial table families appear in Appendix A.

The ledger MUST support:

- MVCC coherent query anchors;
- append-only immutable revisions where history matters;
- unique idempotency and generation constraints;
- first-committer-wins for conflicting plans;
- active obligations and leases;
- source/object reachability;
- migrations and schema generations;
- kill-point recovery;
- deterministic fixture export/import.

## 13.2 Persistence adapters

1. deterministic in-memory reference;
2. deterministic append-only fixture/file adapter for replay;
3. FrankenSQLite production adapter after `INT-FSQL-001`.

Semantic tests run against all applicable adapters. FrankenSQLite is not represented as ready
merely because a dependency can be added.

## 13.3 Object store abstraction

Operations:

- reserve digest/root/namespace/quota;
- stage bytes or stream;
- finalize hash/encryption;
- inspect child;
- publish root;
- open verified range;
- enumerate reachability under capability;
- scrub and retrieval sample;
- prepare/apply deletion or repair.

Backends include local spool, filesystem/object adapter, B2/R2 S3-compatible, and test memory.

## 13.4 Root-last publication

For an event archive:

1. reserve event root identity and ledger intent;
2. stage source chunks and derivatives;
3. compute plaintext/source digests as permitted;
4. encrypt each object with a data key and authenticated metadata;
5. upload/stage children;
6. verify size/digest/metadata and commit child records;
7. build deterministic child manifest;
8. publish root last;
9. commit root reachability and archive location;
10. sample retrieval and schedule future audit.

A remote PUT response is not root publication. Root publication is not retrievability. Receipts
record both.

## 13.5 Encryption

FSS does not invent cryptography. A narrow audited crypto boundary provides:

- per-object or per-event data keys;
- authenticated encryption with versioned algorithm/nonce/AAD format;
- envelope wrapping by local master key/KMS recipient keys;
- key rotation without rewriting plaintext identity;
- optional cryptographic erasure;
- no plaintext key in logs/CLI/process command lines;
- recovery/escrow policy explicit to operator.

Object names should not leak property/event semantics where backend privacy matters. Server-side
encryption can supplement but not replace client-side encryption for remote private media.

## 13.6 Local ring and spool

The edge node maintains:

- bounded original-source ring by sensor/retention class;
- pinned windows for active events/obligations;
- encrypted archive backlog;
- capacity watermarks and degradation actions;
- crash-consistent root/index;
- no eviction of evidence required by active hold/obligation.

When full, the system sheds derived proxies/summaries first, then raises an explicit inability to
retain new source. It never silently overwrites active event evidence.

## 13.7 Archive tiers

Potential policy classes:

- hot local recent source;
- hot remote event evidence;
- standard remote historical events;
- infrequent-access long-term evidence where retrieval economics fit;
- metadata-only historical record after source expiry;
- explicit legal/insurance hold.

Provider selection considers storage, operations, retrieval, egress, minimum duration, durability,
object lock, region, encryption, S3 behavior, and measured upload/restore. Prices are dated data.

## 13.8 Object sizing

Millions of 1-second objects can dominate operation cost. One giant file makes event extraction,
retry, and deletion expensive. The cost registry evaluates segment/chunk sizes against:

- source bitrate and event window;
- first-byte/live latency;
- multipart threshold/parallelism;
- PUT/HEAD/GET/list cost;
- retry amplification;
- privacy/deletion granularity;
- restore seek/range behavior;
- local filesystem overhead;
- deduplication and encryption boundaries.

An adaptive chunking policy is physical-only if it preserves canonical content/reachability;
changes are versioned and measured.

## 13.9 Retrievability and repair

Scheduled audits choose roots/children deterministically or via recorded sampling, fetch ranges,
verify authentication/digests, and optionally replay reports. Failures create obligations. Repair
uses sealed plan/apply and cannot rewrite canonical source identity.

## 13.10 Archive portability

An export manifest is backend-neutral. The operator can mirror or migrate roots without changing
semantic identity. Provider-specific metadata and receipts are children. Migration publishes new
location/custody records; it does not rewrite events.

---

# 14. Digital twin, calibration shuttle, geometry, and coverage

## 14.1 Digital-twin purpose

The twin is an inference and coverage instrument, not decorative 3D. It supplies:

- camera pose/projection and uncertainty;
- property surfaces/volumes and semantic zones;
- occlusion and visibility;
- expected target scale/velocity/path;
- cross-camera transit constraints;
- blind spots and camera criticality;
- calibration drift detection;
- observation planning.

## 14.2 Coordinate frames

Frames include:

- property world;
- camera optical/body/mount;
- drone body/camera/marker;
- local map/floor/zone;
- optional GPS/ENU where evidence supports it.

Transforms are directed, timestamped/generation-bound, and carry covariance or conservative bounds.
Cycles are checked for consistency. A transform graph with large residual cannot be activated.

## 14.3 Intrinsics and imaging model

Per stream/device mode:

- focal/principal point;
- distortion model;
- crop/resize/stabilization/orientation;
- rolling shutter/exposure interval where material;
- zoom/PTZ relation;
- resolution/codec effects on usable detail;
- uncertainty and calibration evidence.

Firmware/settings changes may invalidate intrinsics even when physical camera does not move.

## 14.4 Calibration shuttle

A manually piloted drone or handheld wand carries a known marker/temporal code through each camera
view and overlap zone while its own camera maps the environment. Shared static markers and the
moving marker connect drone reconstruction to fixed-camera 2D observations.

The marker design is optional and safety-constrained. A no-payload path can use static AprilTags/
known dimensions/common landmarks but may have weaker time/scale observability.

## 14.5 Geometry candidates

Candidate learned systems (VGGT, MASt3R-SLAM, CUT3R, depth models) produce proposals. Classical
components include marker detection, feature matching, PnP, essential/fundamental geometry,
triangulation, bundle adjustment, robust loss, loop closure, and scale anchors. Multiple candidates
can be compared against held-out observations.

No learned model confidence can bypass residual/coverage gates.

## 14.6 Joint optimization

The calibration state may optimize:

- fixed camera intrinsics/extrinsics;
- drone trajectory;
- marker/anchor positions;
- per-camera time offset/drift;
- rolling shutter;
- scene points/surfaces;
- metric scale;
- robust outlier assignments.

Initialization and optimization are deterministic under a recorded seed/order where feasible.
Different solvers produce candidate certificates with exact code/config identities.

## 14.7 Certificate acceptance

A certificate includes:

- all input session/source roots;
- sensor modes/generations;
- transforms and uncertainty;
- reprojection/time/loop/scale residual distributions;
- outlier and observability analysis;
- held-out trajectory/marker performance;
- protected-volume coverage lower bound and blind spots;
- valid-from/expiry and invalidators;
- decision fingerprint.

If residuals or observability fail, the system publishes a rejected calibration report, not a
pretty but authoritative twin.

## 14.8 Coverage model

Coverage is computed per protected cell/path under live and static conditions. Inputs:

- geometry and camera FOV;
- occluders and scenario variants;
- minimum target size/contrast/quality;
- day/night/IR mode;
- continuity/duty cycle;
- current obstruction/focus/glare;
- detector operating envelope;
- privacy masks.

Outputs:

- `not_observable`, `weak`, `single`, `multi_independent`, or `degraded`;
- responsible sensor/failure domains;
- expected detection delay and confidence range;
- approach paths/blind regions;
- recommended reposition/additional observation.

## 14.9 Effective versus installed coverage

Installed coverage is the accepted static certificate. Effective coverage is recomputed from live
sensor health, current pose/settings, continuity, image quality, privacy mode, daylight/weather,
and model availability. Event policy uses effective coverage.

## 14.10 Drift

Lightweight landmark/scene checks detect camera movement/crop change/time drift. Drift creates a new
observation and can degrade/invalidate the certificate. Automatic recalibration proposals run in
shadow and need activation gates.

## 14.11 Observation planning

The cognition plane can recommend:

- which camera/PTZ pose would reduce uncertainty;
- where to move/add a cheap camera;
- which drone/handheld calibration path improves geometry;
- which event clip/frame/modality to inspect next.

Recommendations have expected information gain, cost, privacy, and risk. They do not execute
without effect authority.

---

# 15. Pure-Rust model runtime and model registry

## 15.1 Production model boundary

Shipping inference executes through an admitted first-party safe-Rust tensor/operator/kernel stack
based on FrankenTorch mechanisms. There is no required Python environment, ONNX Runtime, libtorch,
CUDA runtime, external model server, or network model registry. Unsupported operators/models fail
import or remain oracle-only.

## 15.2 Canonical model package

A model generation is an immutable ATP object graph binding:

```text
source model digest and provenance
license/use policy
frozen first-party operator IR
canonical constant tensor objects
preprocess and postprocess graphs
input/output schemas and shape constraints
numeric and determinism policy
quantization/calibration contract
kernel-plan compatibility
quality and differential receipts
known divergences/failure slices
repair manifest
```

A mutable model name or repository head is never identity. Activation is a prepared root-last effect
with rollback to the prior generation.

## 15.3 Offline import and lowering

The importer acquires a pinned source package explicitly, verifies it, lowers only supported
operators to the FSS IR, canonicalizes tensors, performs shape/layout/scratch analysis, and runs
pinned foreign framework oracles. Production never interprets arbitrary framework graphs or
executes model-supplied code.

Oracle accounting distinguishes agree, diverge, error-only agreement, unexercised, and intentionally
unsupported behavior. The oracle can be unavailable without affecting production.

## 15.4 Tensor/storage semantics

Tensor identity includes dtype, shape, stride/layout, storage generation, view/alias identity,
device, quantization, and numeric policy. Weights are immutable and structurally shared. Scratch is
invocation-region-owned. A frame/tensor view cannot outlive backing reuse/reallocation.

## 15.5 Static dispatch and safe specialization

Kernel selection is a deterministic function of operator × dtype × layout × shape class × device ×
numeric policy. Every optimized kernel has a scalar reference, a proven input region, a complexity/
scratch bound, a cancellation discipline, and exact or tolerance-certified output semantics.
Offline Forge-style code generation may specialize frozen shapes into safe Rust; runtime JIT or
plugins are forbidden.

## 15.6 CPU-first performance

Cheap deployments must work well on CPUs. The runtime uses packed immutable weights, cache-shaped
tiling, shape specialization, liveness-based scratch arenas, safe SIMD, fused preprocess/layout/
first operators, and share-nothing partitions under Asupersync ownership. Generic framework
features that FSS inference graphs do not use are not on the hot path.

## 15.7 Accelerator posture

GPU/NPU backends are optional first-party Rust capabilities. They define memory/synchronization,
allocation and queue budgets, reset/device-loss behavior, kernel/binary identity, thermal feedback,
and deterministic/tolerance contracts against the CPU reference. Until admitted, CPU remains the
production path. A foreign accelerator runtime is not a fallback.

## 15.8 Invocation receipt

Every invocation pins source evidence, model/preprocess/numeric/kernel/calibration/privacy
generations; reserves input/scratch/output budgets; validates shape/finiteness; publishes an
immutable result root; and emits a decision-path receipt. Cancellation before publication leaves no
visible result; cancellation after publication drains cleanup without retracting the committed
result.

## 15.9 Quantization and embedding spaces

Every quantized variant is a distinct generation with calibration corpus, operator policy, quality
deltas, hardware receipts, and rollback. Embeddings/logits from different generations or
preprocessing spaces never share one unqualified score space.

## 15.10 Shadow, canary, and activation

New packages begin in replay/shadow mode. Paired Decision Cards compare them to the incumbent on
sealed and live canary data. Promotion requires event-level quality, calibration, performance,
privacy, and resource gates; rollback is immediate and root-addressed.

## 15.11 No runtime acquisition

Model weights, tokenizers, vocabularies, calibration tables, and executable graphs are provisioned
as verified local object graphs. Build scripts and live processes do no network acquisition.

## 15.12 Detailed contract

See [`PURE_RUST_MODEL_RUNTIME.md`](docs/PURE_RUST_MODEL_RUNTIME.md) and
[`docs/deep-dives/FRANKENTORCH.md`](docs/deep-dives/FRANKENTORCH.md).

# 16. Detection, tracking, cross-camera association, and temporal reasoning

## 16.1 Cascade rationale

Rare threats require high recall; continuous frontier VLM inference is economically and
operationally unacceptable and can still hallucinate. FSS uses a cascade that preserves candidate
recall while escalating expensive cognition selectively.

## 16.2 Stage 0 — sensor health and tamper

Before interpreting absence or objects, estimate:

- frame repetition/freeze;
- obstruction/cover/dazzle/defocus;
- exposure/darkness/IR transition;
- weather/condensation/insects/webs;
- camera movement/crop/landmark drift;
- decode concealment/corruption;
- timestamp/continuity anomalies;
- scene/display replay indicators.

Output modifies effective coverage and candidate routing.

## 16.3 Stage 1 — candidate generation

Cheap motion/change/background/audio logic aims for high candidate recall. It may include:

- temporal differencing and robust background model;
- optical flow/motion vectors;
- source motion metadata;
- audio anomaly gate;
- region/zone schedule and static exclusions;
- active-track continuation.

Hard negatives such as foliage, rain, headlight shadows, IR insects, and camera auto-exposure are
explicit training/evaluation categories.

## 16.4 Stage 2 — detector and segmentation

Fast deployment-tuned detector/segmenter emits people, animals, vehicles, packages/tools, masks,
and open-set candidates. Requirements:

- high recall operating point;
- score calibration by environment/mode;
- small/partial/dark/crouched/crawling slices;
- no frame class promoted to event;
- detector disagreements retained;
- resolution/model routing cost measured.

RF-DETR is an initial candidate, not a frozen choice.

## 16.5 Stage 3 — within-camera tracking

Tracks include position/mask, velocity, occlusion, covariance, appearance features, detector
history, and source references. A track ID is one probabilistic trajectory in one version universe,
not a person identity.

Tracking handles entry/exit, occlusion, detector misses, camera motion/PTZ, and generation rollover.
Long-lived appearance embeddings have privacy TTLs.

## 16.6 Stage 4 — cross-camera association

Association is a graph hypothesis using:

- overlapping time intervals and feasible transit;
- calibrated zone/3D path;
- target scale/height/direction/speed;
- appearance/shape/carried objects;
- behavior/action context;
- cameras that should/should not observe;
- sensor failure-domain independence;
- contradictions and alternative assignments.

Use multi-hypothesis tracking where ambiguity matters. Do not greedily merge identities and erase
alternatives. Association revisions cite all inputs and model/geometry generations.

## 16.7 Stage 5 — open-vocabulary reasoning

Open-vocabulary detectors/VLMs answer bounded questions such as:

- Is the person crawling, climbing, concealing, carrying a tool, or approaching a window?
- Is this likely a raccoon, cat, person, shadow, reflection, or display replay?
- Did the entity traverse the expected path from camera A to B?
- What evidence contradicts an intrusion explanation?

Prompts include structured scene/track context and request evidence regions/times. The system does
not ask an unconstrained model “is this suspicious?” over hours of video.

## 16.8 Stage 6 — temporal/audio-video reasoning

A temporal model receives a bounded event clip/keyframes, track summaries, audio if authorized,
and explicit questions. It must localize evidence in time and can abstain. Research-only
synchronized audio-video models stay lab-only unless licensing changes.

## 16.9 Stage 7 — independent verifier

Independence is analyzed by training data, architecture, preprocessing, modality, and failure
history. Two sizes of the same VLM may be highly correlated. Deterministic geometry/rules or a
different detector family can provide stronger independence than a larger same-family model.

## 16.10 Stage 8 — fusion and calibration

Fusion operates over calibrated likelihood/evidence intervals and failure domains. It explicitly
models missing data and common cause. Candidate techniques include:

- conformal prediction/risk control for set-valued/abstention guarantees under tested assumptions;
- e-values/e-martingales or sequential tests for anytime evidence accumulation;
- Bayesian/likelihood models with bounded prior sensitivity;
- Dempster-Shafer-like evidence only if semantics/independence are defensible;
- learned meta-model in shadow, bounded by hard rules.

No technique is selected by elegance alone. The deterministic reference is simple and auditable;
adaptive fusion must beat it on sealed evaluation without violating calibration.

## 16.11 Known-safe context

Avoiding false alerts for residents uses multiple weak signals rather than compulsory face ID:

- authorized door transition and path continuity;
- trusted device presence if opted in;
- short-lived appearance/session association;
- routine time/path/action memory;
- operator confirmation;
- absence of forced/tamper cues.

No one contextual signal can permanently whitelist a person or suppress a high-severity event
without policy evidence.

## 16.12 Unknown objects and novelty

Open-set/embedding novelty can escalate unusual objects/behavior. It cannot label novelty as
threat automatically. Novelty baselines are property/mode/model-generation specific and drift-
monitored.

---

# 17. Event semantics, uncertainty, sequential evidence, and policy

## 17.1 Initial event taxonomy

Security event kinds are extensible but stable. Initial classes:

- unknown presence;
- perimeter/zone breach;
- covert approach/crawling/loitering/reconnaissance;
- forced entry or barrier interaction;
- camera/sensor tamper or coverage loss;
- suspicious carried object/tool;
- vehicle approach/entry;
- package/delivery;
- benign resident/guest/service routine;
- wildlife/pet;
- weather/environmental artifact;
- unclassified/indeterminate.

Taxonomy distinguishes observed action from inferred intent. “Person near window” and “attempted
burglary” are not interchangeable labels.

## 17.2 Event revision

An event revision contains:

- event/state/kind/severity candidate;
- time interval, zones, tracks, coordinate references;
- positive, negative, missing, and contradictory evidence;
- sensor health/effective coverage;
- model/geometry/policy/privacy generations;
- calibrated probability/risk intervals or set-valued output;
- alternatives and abstention;
- decision fingerprint and recommended next evidence/effect;
- supersedes relation.

## 17.3 State machine

`Hypothesized → Witnessed → Corroborated → Adjudicated → AlertDelivered → Resolved`, with
Rejected/Indeterminate. State is monotonic within a revision lineage; corrections create new
revisions rather than rewriting history.

Corroboration normally requires independent failure domains. Registered urgent exceptions may
alert from one sensor under a high-sensitivity policy, but the event remains labeled
single-domain/unconfirmed.

## 17.4 Uncertainty

FSS avoids a naked point confidence. It records:

- score/logit and source model generation;
- calibrated interval or set where available;
- data/coverage/calibration uncertainty;
- distribution/OOD indicators;
- alternative hypotheses;
- assumptions and invalidators;
- abstention reason.

A VLM phrase such as “high confidence” has no numeric authority.

## 17.5 Sequential evidence

Events evolve as frames/sensors arrive. Policy can:

- alert immediately for sufficiently severe evidence;
- wait for likely imminent corroboration within a bounded delay;
- request higher frame rate/model/camera view;
- alert with uncertainty when coverage is degraded;
- retain silently for low risk;
- ask operator for confirmation;
- reject with retained evidence.

Sequential thresholds are evaluated for optional stopping and false-alert exposure. Every wait has
a deadline and expected value; “wait for more evidence” cannot become indefinite in a real threat.

## 17.6 Policy layers

1. **Hard safety/privacy rules:** masks, forbidden effects, authorization, evidence minimums.
2. **Deployment policy:** protected zones, schedules, resident context, alert channels, retention.
3. **Calibrated decision policy:** thresholds/sets based on admitted generations and evaluation.
4. **Adaptive routing:** which model/evidence to acquire under cost/latency, bounded by 1–3.

Only layer 4 adapts online automatically by default. Other changes are explicit revisions/effects.

## 17.7 Severity and urgency

Severity and confidence are different. A low-probability but catastrophic fire/forced entry may
warrant an alert; a high-confidence raccoon does not. The policy records expected harm, time
criticality, reversibility, and false-alert cost rather than one suspicion score.

## 17.8 Counterfactual explanation

An event explanation should say:

- strongest observations and independent domains;
- contradictions/missing evidence;
- effective coverage;
- selected alternatives;
- rules/models contributing;
- why alert/abstain/reject;
- what additional evidence would change the decision;
- how decision changes if a sensor/model is removed.

Counterfactuals are recomputed from the versioned decision graph, not invented prose.

---

# 18. Alerts and other effects

## 18.1 Effect protocol

Every effect follows:

```text
intent
→ prepare (validate authority, anchor, policy, cost, privacy, reversibility)
→ prepared plan digest
→ commit exact digest (revalidate, fence, persist)
→ dispatch
→ observe
→ verify terminal postcondition
```

Cancellation can occur before commit without consequence. After commit/dispatch, cancellation
means stop further work and reconcile; it cannot pretend the external effect did not happen.

## 18.2 Alerts

An alert plan specifies:

- event revision and severity;
- recipient/channel/template/privacy projection;
- deduplication and escalation schedule;
- evidence preview/links/expiry;
- expected provider receipt and delivery semantics;
- rate/quiet-hour exceptions;
- correction/retraction path;
- idempotency key.

Dispatch ACK, provider acceptance, delivered/read, and operator acknowledged are distinct.

## 18.3 Alert fatigue

Policy controls:

- event clustering/deduplication;
- update rather than duplicate when evidence evolves;
- false-alert feedback linked to exact revision;
- channel/escalation by severity/urgency;
- sensor-health alerts separated from intrusion alerts;
- rate limits that do not suppress a distinct high-severity event;
- metrics per exposure and category.

## 18.4 PTZ and camera settings

PTZ plans include current/desired pose, privacy/coverage impact, lease, duration, restore pose,
limits, and verification. A move starts or updates pose/calibration generation. Unknown pose or
failed restore degrades coverage.

Settings changes start new stream/device sub-generations as required. Readback is mandatory where
available.

## 18.5 Spotlight/siren

Disabled by default. These are physically consequential and may escalate a situation. If enabled,
use explicit operator policy, bounded duration, local rules, prepare/commit/readback/restore, and
separate quality/safety review. A model cannot activate them directly.

## 18.6 Export

Export plan names exact event/evidence, recipient, purpose, fields, redactions, format, expiry,
access controls, and chain of custody. It publishes a new export root; it does not expose the live
archive namespace.

## 18.7 Retention/deletion/privacy changes

These durable effects have preview of affected objects/coverage/cost, sealed plan, strong approval,
and completion proof. They are never hidden as model “preferences.”

## 18.8 Model/adapter/calibration activation

Activation is an effect because it changes future interpretation. It requires exact generation,
shadow/qualification evidence, compatible indexes/schemas, atomic switch, rollback, and monitoring
obligation.

## 18.9 Drone flight

`EFFECT-DRONE-FLIGHT-001` is forbidden in v1. Capture/import is not flight authority.

---

# 19. Search, graph, memory, and explainability

## 19.1 Derived projection doctrine

Search, graph, and memory accelerate cognition and agent access. They are rebuildable from the
canonical ledger/evidence and carry certificates binding their version universe.

## 19.2 Lexical and structured search

Supports exact IDs, time/zone/kind/state/model/device/error/firmware/calibration/privacy fields,
operator notes, and report spans. Results cite canonical revisions and source spans.

## 19.3 Semantic/multimodal search

Supports text↔image/video event retrieval, similar false alarms, object/scene novelty, and hard-
negative discovery. Each result names embedding/index generation and component scores. Appearance
search is property-local and privacy-scoped; it does not assert identity.

## 19.4 Progressive retrieval

Initial exact/lexical/cheap-vector candidates return quickly. Graph/geometry/high-quality rerank and
evidence hydration refine later. A refinement failure does not erase the labeled initial result.

## 19.5 Certified graph projections and algorithms

FSS maintains separate immutable projections for sensor/network/power topology, spatial visibility,
track association, event/evidence causality, object custody/deletion, and runtime obligations. Each
root names its authority high-water mark, schema, projection/capability policy, and storage
representation.

Graph storage is temperature-tiered: tiny hot adjacency inline, recent deltas in bounded sorted
blocks, cold stable relations in sealed runs, and retained historical roots. Standing predicates
such as active tracks, uncovered cells, likely transition edges, failure cuts, under-replicated
objects, and unresolved obligations update incrementally from `EvidenceDeltaBatch`; periodic full
recomputation is the oracle.

Every planning-relevant algorithm is registered with directedness/multiedge/weight/numeric
semantics, canonical tie-break/output order, complexity contract, budget, stale policy, and
reference implementation. Runs emit `GraphAlgorithmWitness` objects with `n`, `m`, observed
operation counts, decision-path digest, and output digest.

Initial families include dynamic connectivity; articulation/bridge/dominator/cut analysis;
shortest, k-shortest, and temporal paths; bipartite matching, k-best assignment, min-cost flow;
max-flow/Gomory-Hu; SCC/condensation/topological critical path; spanning forests; set cover,
facility location, and submodular active perception; PPR attention; d-separation; canonical graph
hashing; factorized joins; wait-cycle detection; and deletion reachability.

Authorization and privacy are compiled into the projection before expansion so hidden degree,
counts, paths, cuts, or absence cannot leak. Optimized/specialized algorithms replace the ordered
safe-Rust oracle only after adversarial differential, cancellation, snapshot, capability,
complexity, and same-binary performance gates.

See [`docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md`](docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md) and
[`registries/GRAPH_ALGORITHMS.md`](registries/GRAPH_ALGORITHMS.md).

## 19.6 Memory

Eidetic memory stores evidence-linked operational lessons:

- recurring benign routines;
- false-alarm causes;
- model/firmware failure patterns;
- misses/near misses;
- calibration drift;
- useful runbooks/prompts;
- operator preferences within policy.

Memory can influence retrieval/routing/proposals. It cannot rewrite event truth, privacy, identity,
retention, effect authority, or hard thresholds. Feedback and harmful anti-patterns are explicit.

## 19.7 Explanations

Explanations are deterministic projections where possible, rendered through typed report models.
They include evidence IDs and exact source regions/times, not only summaries. Untrusted OCR/audio/
metadata/model text is tainted and never interpreted as instructions.

## 19.8 Attention ranking

For agents/operators, FSS ranks:

- high-severity unresolved events;
- deteriorating coverage/sensor health;
- archive/deletion/alert obligations;
- model/calibration/firmware drift;
- unusual disagreement/abstention;
- recurring false alarms needing remediation;
- expiring holds/keys/certificates.

Ranking explains component scores and respects token/result budgets.

---

# 20. Agent-native CLI/MCP interfaces

## 20.1 Product philosophy

The CLI/library is primary; MCP is an adapter. Every machine surface has a versioned JSON schema,
stable errors, exit codes, bounded output, and continuation. Human prose is not the only contract.

## 20.2 Initial CLI

Design-only skeleton now exposes:

```text
fss capabilities --json
fss doctor --json
fss status --json
```

Target commands:

```text
fss property init|show
fss sensor discover|add|probe|start|stop|health|doctor
fss observe snapshot|delta
fss event list|show|explain|evidence|resolve
fss calibration plan|ingest|solve|verify|activate
fss coverage show|blind-spots|simulate
fss archive status|verify|restore|migrate
fss model list|qualify|shadow|activate|rollback
fss adapter matrix|qualify|shadow|activate
fss privacy show|mask-plan|retention-plan|delete-plan
fss alert prepare|commit|status
fss evidence export-prepare|export-commit
fss lab replay|fault|red-team|bundle
```

## 20.3 MCP read resources/tools

- status and capabilities;
- sensor list/health/coverage;
- anchored observation delta;
- event query/show/explain/evidence handles;
- calibration/geometry/coverage status;
- archive and obligation status;
- search and similar incidents;
- doctor/support bundle plan.

## 20.4 MCP effects

Prepared effects only:

- alert acknowledgement/dispatch under grant;
- PTZ plan/commit;
- retention/privacy/export/deletion plan/commit;
- activation/rollback;
- repair plan/apply.

No generic shell, SQL, filesystem, vendor method, or arbitrary model prompt tool. Drone flight is
absent.

## 20.5 Budgets

Request budgets include time, bytes, rows, tokens, evidence hydration, model calls, accelerator
work, and sealed laboratory-oracle calls when the request runs in a qualification profile. Partial initial results return continuation rather than exceeding budget. Budget
exhaustion is not a generic timeout and carries what completed.

## 20.6 Anchors and races

Read results carry anchor. Prepared effects bind an anchor/precondition digest. If state changes,
commit returns stale-precondition and the agent replans. Multi-agent leases/fences prevent two
controllers from racing PTZ/retention/activation.

## 20.7 Taint and prompt injection

Camera names, OCR, audio transcripts, vendor metadata, operator notes, model output, imported docs,
and web content are untrusted data. They cannot create capabilities or tool calls. Explanations
quote/cite them with taint and source spans.

## 20.8 Token economy

The server shapes compact semantic projections:

- only changed/high-attention entities;
- quantized/summary geometry with handles;
- evidence digests and selected crops rather than full media;
- score components and top contradictions;
- continuation and suggested next queries;
- deterministic schema labels.

Routine monitoring should require hundreds, not tens of thousands, of tokens.

## 20.9 Agent evaluation

FSS becomes an agent benchmark through tasks such as:

- diagnose camera coverage failure;
- investigate ambiguous event under budget;
- design next observation/calibration path;
- reconcile archive/alert indeterminacy;
- reduce false alarms without hurting sealed threat recall;
- manage multiple agents with leases;
- recover from firmware/model drift;
- produce a privacy-minimized evidence export.

The agent is scored on semantic correctness, evidence use, cost, time, effects, recovery, and
calibration—not just final answer.

---

# Part VII — Security, privacy, and scientific qualification

## 21. Security architecture

FSS is itself a high-value target. It holds camera credentials, private footage, maps of a home,
resident routines, alert channels, and potentially actuator authority. A surveillance system that
improves perception while creating a remote-control or data-exfiltration platform is a failure.
Security is therefore an architectural boundary, not a deployment appendix.

## 21.1 Security objectives

| ID | Objective | Required interpretation |
|---|---|---|
| `SEC-001` | Least authority | Every process, adapter, model, agent, and operator receives the smallest capability needed for one declared operation. |
| `SEC-002` | Local survivability | Loss of vendor cloud, WAN, object store, accelerator, or optional remote sink does not erase local evidence or silently disable all detection. |
| `SEC-003` | Credential containment | Raw credentials never enter logs, model prompts, event objects, support bundles, or generic agent context. |
| `SEC-004` | Media isolation | Untrusted packets, bitstreams, metadata, and model files cannot directly mutate canonical state. |
| `SEC-005` | Effect accountability | Every consequential effect has an authorizing principal, capability, precondition, intent digest, receipt, and terminal/indeterminate state. |
| `SEC-006` | Tamper evidence | Canonical manifests, evidence roots, model generations, calibration certificates, and policy generations are content-addressed and hash-linked. |
| `SEC-007` | Bounded attack surface | Parsers, decoders, adapters, and model runtimes enforce byte, time, memory, task, recursion, and output bounds before accepting input. |
| `SEC-008` | Fail-closed control | Authentication, authorization, provenance, model identity, or precondition ambiguity prevents mutation rather than degrading into ambient authority. |
| `SEC-009` | No covert autonomy | FSS does not autonomously pursue, threaten, physically confront, or weaponize against a person. |
| `SEC-010` | Reproducible security state | A support bundle can reconstruct the active versions, policies, grants, network topology declarations, and relevant audit evidence without exposing secrets. |

## 21.2 Network segmentation

Recommended deployment uses at least four logical zones:

1. **Device zone.** Cameras, doorbells, base stations, and drone-controller bridge endpoints.
2. **Ingest zone.** Asupersync-owned adapter/device regions and pure-Rust media gateways allowed
   to initiate narrowly scoped connections to declared devices.
3. **Trusted core zone.** Ledger, policy engine, search, graph, calibration authority, and API.
4. **Model/compute zone.** first-party model execution consuming immutable sensor capsules and publishing
   typed hypotheses.

Default network policy:

- device-zone endpoints cannot initiate connections to the trusted core;
- vendor-cloud access is disabled for standards-native devices unless explicitly required;
- adapters may access only their declared device tuple and vendor endpoints named by policy;
- model execution cannot access device credentials or arbitrary network destinations;
- object-store uploaders receive write-only, prefix-scoped authority where the provider permits;
- public inbound ports are absent by default;
- remote operator access terminates through an explicitly configured authenticated tunnel or
  reverse proxy outside the FSS core.

The repository will eventually ship declarative examples for nftables, Linux network namespaces,
systemd sandboxing, containers, and macOS launchd profiles. Those examples are deployment aids,
not substitutes for application-layer capabilities.

## 21.3 Secret model

A secret is referenced by `SecretHandle`, never copied into normal configuration. Backends MAY
include OS keyrings, encrypted files, hardware-backed stores, or an operator-supplied one-shot
secret channel whose implementation is separately capability-scoped and admitted.
The core contract is:

```text
resolve(secret_handle, adapter_capability, purpose, deadline)
  -> ephemeral secret lease
  -> zeroized/closed at region finalization
```

Required properties:

- purpose-bound and adapter-bound resolution;
- no serialization in operation receipts;
- redacted debug formatting;
- expiry and revocation;
- optional one-shot semantics;
- rotation without changing stable device identity;
- deterministic fake resolver for tests;
- leak canaries in CI and support-bundle tests.

A reverse-engineered vendor adapter MUST NOT ask an agent to paste cookies or passwords into a
prompt. Onboarding is an operator flow that deposits credentials directly into the selected secret
backend.

## 21.4 Pure-Rust process and memory isolation

The production semantic, protocol, media, codec, model, graph, search, archive, CLI/MCP, and UI
paths are first-party safe Rust under Asupersync ownership. FSS does not depend on foreign codec,
Python/model, GPU runtime, browser, or proprietary SDK processes.

Isolation still exists **within** the Rust architecture:

| Component | Isolation/ownership unit | Authority | Failure consequence |
|---|---|---|---|
| Device session | region per adapter/device generation | scoped credentials and network/device resource | stream degraded; source history remains truthful |
| Media stream | region plus bounded packet/decode pools | packet/source objects only | decode/live derivative unavailable; source custody continues where possible |
| Model invocation | region plus immutable package and scratch arena | authorized tensor/capsule views | derived hypothesis absent/failed; no authority mutation |
| Graph/search request | request-owned pinned generation | authorized projection only | bounded partial/stale result; no hidden expansion |
| ATP transfer | transfer region and resumable journal | immutable object roots/destination scope | staged/resumable/failed/indeterminate transfer receipt |
| Effect | durable operation region/obligation | exact prepared capability and fence | reconcile to verified or indeterminate outcome |

Laboratory oracles run in separate pinned, network-restricted environments and consume immutable
corpora. Their compromise or outage cannot affect production availability or authority. Secret and
private media capabilities are never granted merely to make differential testing convenient.

## 21.5 Untrusted media and metadata

Every source byte is hostile until parsed. Defenses include:

- hard maximum dimensions, frame rates, sample rates, channel counts, GOP sizes, metadata sizes,
  and duration claims;
- arithmetic checked before allocation;
- decompression ratio and decoded-pixel budgets;
- timeout/cost quotas for probing and decode;
- no trust in container duration, timestamps, codec profile, or keyframe indexes;
- quarantining malformed and adversarial fixtures;
- process-level resource limits and output byte ceilings;
- sanitization of filenames, camera labels, OCR, subtitles, EXIF, ID3, ONVIF strings, and vendor
  JSON before human or agent presentation;
- refusal to interpret untrusted text as instructions.

The raw source digest and acquisition metadata are retained when policy permits so parser and
model decisions can later be reproduced against the exact bytes.

## 21.6 Supply-chain security

The dependency universe is intentionally narrow. Every admitted external binary, model, firmware
fixture, schema, and data asset has:

- immutable source/revision identity;
- cryptographic digest;
- license and redistribution classification;
- acquisition receipt;
- expected byte length where stable;
- loader/probe verification;
- supported platform and accelerator tuple;
- vulnerability/advisory notes;
- rollback generation.

Build scripts MUST NOT fetch the network. Model acquisition is an explicit command that downloads
to staging, verifies, probes in an isolated worker, and atomically promotes a generation. Release
artifacts use signed checksum/provenance manifests when the publication system supports them.

## 21.7 Authentication and principals

Principals include human operators, local services, adapters, model generations, automation rules,
and agents. Authentication facts are committed before authorization. Uncommitted or partially
verified identity cannot enter a cache key or capability grant.

Capabilities are typed and resource-scoped, for example:

```text
ReadLivePreview { camera_set, max_fps, max_resolution, expires }
ReadEvidence { event_set, redaction_profile, expires }
PrepareAlert { channels, severity_ceiling }
CommitAlert { prepared_intent_digest, expires }
ControlPtz { camera_id, pan_range, tilt_range, zoom_range, lease, fence }
ActivateGeneration { subsystem, candidate_digest, qualification_bundle }
DeleteData { deletion_plan_digest, scope, approval }
```

There is no `AdminEverything` token in normal operation. Break-glass authority, if implemented,
is short-lived, visibly audited, and cannot erase its own audit record.

## 21.8 Multi-agent coordination

Agents are advisory or bounded-effect principals. A lease carries resource identity, owner,
expiry, epoch, and monotonically increasing fence. Effects reject stale fences even if a previous
lease holder resumes after network partition.

Read concurrency is broad. Mutations require one of:

- immutable prepared intent with compare-and-swap preconditions;
- exclusive resource lease;
- commutative append-only event;
- merge proof recognized by the owning subsystem.

An agent cannot infer authority from prose, a retrieved memory, a camera label, or another model's
output. Only an authenticated capability object grants authority.

## 21.9 Physical-effect boundary

FSS V1 observes, alerts, records, and may control passive camera functions under explicit policy.
It MUST NOT autonomously:

- fly a drone;
- unlock/lock doors;
- activate weapons or harmful deterrents;
- chase or physically confront a person;
- impersonate law enforcement;
- contact emergency services without an explicit, separately qualified operator policy;
- expose a resident's location to an untrusted party.

Drone-assisted mapping is human-piloted. Future active robotics would require a separate project,
separate threat model, geofencing, collision safety case, jurisdictional review, and operator
approval surface. It is not an incremental adapter in this plan.

## 21.10 Security gates

Security promotion requires retained evidence for:

- secret-redaction corpus;
- protocol fuzzing and malformed-frame corpus;
- pure-Rust codec/model memory-isolation, resource-limit, malformed-input, and laboratory-oracle separation evidence;
- capability denial matrix;
- stale-lease/fence tests;
- alert replay/idempotency tests;
- support-bundle privacy tests;
- dependency/model manifest verification;
- software-bill-of-material generation;
- downgrade and rollback behavior;
- incident-response rehearsal.

Passing ordinary unit tests is not sufficient evidence for a security claim.

---

## 22. Privacy architecture

Security asks who can access the system. Privacy asks what the system should know, retain, infer,
and disclose even when access is authorized. A home-surveillance project can become socially
harmful through perfectly authenticated overcollection. Privacy constraints therefore shape the
media pipeline, model cascade, indexes, memory, exports, and deletion protocol.

## 22.1 Privacy principles

| ID | Principle | Consequence |
|---|---|---|
| `PRIV-001` | Local-first | Continuous media and identity-bearing features remain local by default. |
| `PRIV-002` | Purpose limitation | Data collected for home security is not silently repurposed for employee monitoring, advertising, neighborhood tracking, or public identification. |
| `PRIV-003` | Minimize before inference | Crop, mask, downsample, suppress audio, or discard irrelevant regions before expensive/identity-bearing inference when operationally possible. |
| `PRIV-004` | No biometric requirement | Household recognition can use opt-in local profiles, device/routine context, or anonymous continuity; face recognition is not required for core threat detection. |
| `PRIV-005` | Boundary-limited identity | Identity/appearance continuity does not cross properties, deployments, or operator-defined privacy domains by default. |
| `PRIV-006` | Derived-data accountability | Embeddings, tracks, thumbnails, captions, indexes, caches, model inputs, and backups are part of retention/deletion scope. |
| `PRIV-007` | Explainable disclosure | Evidence export declares included sources, redactions, transformations, omissions, and chain of custody. |
| `PRIV-008` | No silent policy mutation | Models and agents may propose retention or masking changes; only an authorized committed policy generation applies them. |
| `PRIV-009` | Bystander protection | Public sidewalks, neighboring property, windows, and audio zones receive explicit masks and narrower retention by default. |
| `PRIV-010` | Honest irreversibility | The system distinguishes deletion from cryptographic erasure, provider expiration, replica lag, and unknown third-party copies. |

## 22.2 Data classes

FSS classifies data before storage:

| Class | Examples | Default treatment |
|---|---|---|
| `P0 Operational` | Camera health, firmware tuple, queue depth | Long retention, low privacy sensitivity |
| `P1 Environmental` | Weather, illumination, anonymous motion heatmaps | Retain according to utility; avoid identity reconstruction |
| `P2 Resident-sensitive` | Household routines, recognizable people, interiors | Local encrypted storage; short ordinary retention; strict export |
| `P3 Highly sensitive` | Audio, faces, license plates, access codes, children's areas | Disabled or minimized by default; explicit opt-in and policy |
| `P4 Incident evidence` | Confirmed/suspected intrusion evidence bundle | Legal/operational retention profile with immutable audit and redaction variants |
| `P5 Secrets` | Passwords, tokens, cookies, private keys | Secret store only; never normal media/ledger payload |

A single sensor capsule may contain multiple classes by region or channel. Privacy transforms create
new objects with lineage rather than overwriting source truth.

## 22.3 Audio policy

Audio is off by default in the reference profile. Enabling it requires:

- declared jurisdiction and operator policy;
- visible source/channel inventory;
- retention and access rules;
- model-purpose declaration;
- transcript and embedding deletion coverage;
- redaction/export behavior;
- tests proving disabled audio is not decoded, indexed, or uploaded.

A camera supporting audio does not imply permission to ingest it.

## 22.4 Spatial privacy masks

Masks are versioned geometric policies bound to calibration generation and camera identity.
Types include:

- hard discard before durable storage;
- blur/pixelate in live/operator views;
- suppress model input;
- suppress alert thumbnails while permitting local detection;
- narrow retention/quality zones;
- neighbor/public-space exclusion volumes projected into cameras;
- schedule-conditional interior masks.

Calibration changes can invalidate mask projections. An invalid mask fails closed for export and
remote inference, while local recording policy follows its declared safe fallback. The UI must
show uncertainty margins rather than a falsely exact polygon.

## 22.5 Household familiarity without mandatory face recognition

“Homeowner taking out garbage” should usually be classified harmless without requiring global
biometric identity. Evidence may include:

- authenticated phone/watch/device presence;
- entry/exit sequence from a known door;
- opt-in local appearance profile with short TTL;
- routine and time context;
- direction of travel and object carried;
- resident-confirmed event feedback;
- continuity from an interior/private camera to an exterior camera;
- absence of threat actions.

No single weak signal proves identity. The policy engine reasons over a provenance-bearing bundle
and can select “familiar household activity, identity unresolved.” Face recognition, if later
added, is an isolated optional model class with separate consent, demographic evaluation,
thresholds, and deletion controls.

## 22.6 Retention lattice

Retention is computed from data class, event state, policy generation, evidence hold, and storage
tier. Example reference profile:

- rolling low-resolution buffer: hours to days;
- ordinary full-resolution media: short configurable window;
- no-event embeddings/tracks: shorter than source media unless needed for calibration/evaluation;
- candidate events: retained until adjudication plus bounded grace;
- confirmed incident evidence: explicit case retention;
- calibration imagery/geometry: retained while certificate remains active plus rollback window;
- operational metrics: longer, with identifiers minimized;
- secrets: independent lease/rotation policy.

The plan deliberately avoids hard-coding universal durations. Jurisdiction, household preference,
storage economics, and security risk differ. What is universal is that every object receives a
machine-evaluable retention reason and deletion dependencies.

## 22.7 Deletion closure

Deletion is a graph operation, not `rm one video`. A deletion plan discovers:

- source capsules and renditions;
- thumbnails/crops/redactions;
- tracks, embeddings, captions, hypotheses, and event references;
- lexical/vector indexes and caches;
- graph projections and learned memories;
- local replicas, object-store copies, manifests, repair symbols, and export variants;
- pending uploads and retry queues;
- model training/evaluation datasets derived from the source;
- legal/evidence holds that block deletion.

The plan returns a sealed dependency graph, estimated cost, blocked nodes, and claimed guarantees.
Commit revalidates the graph root and policy. Completion may be:

- `VerifiedDeleted` for every controlled replica;
- `CryptographicallyErased` when key destruction is the declared mechanism;
- `ProviderExpirationPending` with deadline/receipt;
- `BlockedByHold`;
- `IndeterminateThirdPartyCopy`;
- `Failed` with resumable obligations.

FSS never calls an object deleted merely because a local index row disappeared.

## 22.8 Cloud and remote inference

Remote transfer is opt-in per data class and purpose. The transform pipeline may produce a
privacy-minimized derivative: masked crop, downsampled clip, geometry without texture, or anonymous
embedding. The receipt records exactly what bytes left the local trust domain, provider,
region/endpoint, encryption context, retention expectation, and response artifacts.

A model execution profile must declare whether any inputs leave the machine. An “open-weights model” served by a
third-party API is still remote processing and must not inherit local-model permissions.

## 22.9 Evidence export

Exports are immutable derived bundles with:

- selected source object digests;
- transformation graph;
- redaction profile and calibration generation;
- operator and purpose;
- timestamps with uncertainty;
- model and policy generations;
- included/excluded channels;
- checksums and root manifest;
- chain-of-custody events;
- verification command;
- expiry/revocation metadata where relevant.

Export preparation is read-only. Commit creates bytes only after authorization and revalidation.
A redacted export does not destroy the original; each variant has independent access and retention.

## 22.10 Privacy evaluation

Required tests include:

- pixels outside allowed regions never reach a configured remote sink;
- audio-disabled mode never emits audio-derived artifacts;
- mask invalidation after calibration drift;
- deletion closure across every registered derived type;
- support bundle and log secret/PII scans;
- resident/bystander split in evaluation datasets;
- no cross-property re-identification by default;
- export transformation reproducibility;
- policy rollback without orphaned new-generation artifacts;
- model execution cannot request unredacted source without capability.

---

## 23. Deterministic replay, verification, and formal targets

Physical reality cannot be replayed, but FSS decisions over captured evidence can. Deterministic
replay is the bridge between field failures and engineering truth.

## 23.1 Replay unit

A canonical replay bundle contains:

- immutable source capsules or synthetic generators;
- acquisition-time intervals and clock evidence;
- device/firmware/adapter generations;
- calibration and geometry generations;
- model manifests, weights digests, runtime/accelerator tuple, and preprocessing config;
- policy, threshold, and privacy generations;
- scheduler seed and virtual-time trace where applicable;
- injected fault schedule;
- expected state transitions or oracle classifications;
- platform manifest and known nondeterminism declarations.

A replay is exact only within its declared deterministic boundary. GPU kernels or vendor codecs
that cannot promise bit identity must publish tolerance/equivalence rules and deterministic CPU or
fixture oracles for critical semantics.

## 23.2 Lab runtime

Asupersync `LabRuntime` owns virtual time, task scheduling, cancellation, region closure, and fault
hooks for pure/core and cooperative boundary simulations. The test harness can explore:

- stream start racing cancellation;
- reservation after deadline but before commit;
- adapter disconnect during keyframe/GOP;
- clock correction while associating tracks;
- object upload completion racing shutdown;
- model result arriving after generation rollback;
- policy activation racing an event decision;
- alert provider ACK lost after external side effect;
- deletion commit racing a derived-index publication;
- lease expiry and stale controller resumption.

Schedule traces are canonicalized where independence permits. DPOR-style exploration prioritizes
new dependency/race shapes rather than enumerating redundant interleavings.

## 23.3 Fault taxonomy

| Fault family | Examples |
|---|---|
| Network | Loss, duplication, reordering, MTU split, half-open connection, DNS drift, TLS expiry |
| Device | Reboot, firmware change, keyframe starvation, timestamp reset, bitrate change, lens obstruction |
| Media | Truncated container, invalid NAL, huge metadata, corrupt keyframe, discontinuity, variable FPS |
| Clock | Offset, skew, step, monotonic reset at process boundary, NTP uncertainty, stale time sample |
| Storage | ENOSPC, torn staging file, fsync failure, permission change, object-store 5xx, partial multipart upload |
| Database | Kill before/after commit marker, checksum mismatch, migration interruption, stale reader generation |
| Model | OOM, timeout, malformed tensor, NaN, unsupported operator, executor panic, nondeterministic output |
| Policy | Missing feature, stale calibration, contradictory evidence, threshold migration failure |
| Alert | Provider timeout, duplicate ACK, ambiguous HTTP result, callback spoof, channel outage |
| Privacy | Mask unavailable, deletion blocked, remote sink misconfigured, export transform failure |
| Operator | Cancel, rollback, credential revoke, incorrect label, conflicting multi-agent request |

Every fault belongs to a stable error/result class. Unknown failure is allowed as a classification,
but must preserve evidence and not be flattened to success.

## 23.4 Oracles

The system uses several oracle classes:

1. **Reference protocol/device oracle.** Real standards-compliant camera or recorded packet trace.
2. **Incumbent laboratory oracle.** Pinned FFmpeg/browser/vendor application for decode or behavior
   comparison, isolated from the target architecture.
3. **Independent model oracle.** Larger/research-only model used to label disagreements, never
   presumed correct.
4. **Human adjudication oracle.** Multi-reviewer labels with uncertainty and disagreement.
5. **Metamorphic oracle.** Transformations whose semantic result should remain invariant or change
   predictably.
6. **Formal/state-machine oracle.** Impossible transitions, conservation of obligations, root-last
   publication, lease fencing, and deletion closure.

An oracle disagreement is classified, not averaged away. The divergence registry records whether
FSS is wrong, the oracle is wrong, both are underspecified, or the case remains unresolved.

## 23.5 Metamorphic relations

Required relations include:

- chunking a stream at different packet/frame boundaries does not alter decoded frame sequence;
- adding irrelevant metadata does not alter event semantics;
- monotonically widening timestamp uncertainty cannot increase association confidence;
- removing a corroborating camera cannot increase evidence completeness;
- applying a privacy mask cannot create detections outside the unmasked support;
- equivalent calibration coordinate transforms preserve world-space relations;
- reordering independent camera capsules preserves fused event result and deterministic tie order;
- retrying a committed idempotency key does not duplicate external effects;
- archive reconstruction from manifest/object set reproduces content digests;
- model quantization may change scores within registered tolerance but not silently change schema or
  class vocabulary;
- deleting a source removes or tombstones every derived index reference according to plan;
- lowering compute budget yields an explicit degraded path, not fabricated confidence.

## 23.6 Formal-model targets

The initial formal directory is scaffolding. Promotion targets are:

| ID | Property | Candidate formalism |
|---|---|---|
| `FORMAL-001` | Region closure leaves no live obligations | TLA+ state machine + executable invariant checks |
| `FORMAL-002` | Root manifest is never visible before all referenced objects are durable | TLA+ publication protocol |
| `FORMAL-003` | One idempotency key creates at most one committed alert effect | TLA+ effect coordinator |
| `FORMAL-004` | Stale lease fences cannot mutate PTZ/policy/activation state | TLA+ lease/fence model |
| `FORMAL-005` | Event belief intervals remain valid under evidence fusion rules | Lean 4 algebraic core or exhaustive finite model |
| `FORMAL-006` | Deletion completion implies no reachable controlled derivative remains | Graph closure theorem + executable checker |
| `FORMAL-007` | Generation activation is atomic for readers | TLA+ / MVCC publication model |
| `FORMAL-008` | Cancellation never publishes an uncommitted staged artifact | TLA+ two-phase effect model |
| `FORMAL-009` | Privacy mask generation dominates remote-transfer authorization | State-machine/model checker |
| `FORMAL-010` | Time uncertainty composition is conservative | Lean 4 interval lemmas |

Formal proof is not used as theater. Each model must name its abstraction gap and be connected to
runtime event schemas and conformance tests.

## 23.7 Proof bundles

A release claim points to a machine-readable proof bundle containing:

- claim ID and exact wording;
- implementation commit and dirty-state declaration;
- platform/device/model matrix;
- test commands and exit status;
- artifact digests;
- corpus/holdout identity;
- metric estimates and confidence intervals;
- known failures and exclusions;
- negative evidence ledger references;
- reproduction instructions;
- signer/provenance.

Documentation checks reject a claim whose required bundle is missing, expired, incompatible with
current generation, or outside measured scope.

## 23.8 Negative evidence ledger

Failed approaches are durable assets. Examples:

- a vendor API that only works under one stale firmware;
- a detector that improves frame AP but lowers event recall;
- a cross-camera embedder that re-identifies residents across privacy domains;
- a geometry model that looks plausible but drifts under low parallax;
- a codec optimization that changes timestamps;
- a cloud layout that reduces storage cost but makes incident retrieval too slow;
- an alert threshold tuned to the test property;
- an autonomous-drone shortcut rejected on control/safety grounds.

Each entry records hypothesis, exact setup, expected result, observed result, confidence, and
revival conditions. Agents search this ledger before repeating work.

---

## 24. Dataset constitution, red-team corpus, and statistical qualification

The North Star is event-level performance in difficult real conditions, not frame-level benchmark
scores. FSS needs a private, consented, reproducible qualification corpus plus public/synthetic
components that can be distributed safely.

## 24.1 Unit of evaluation

An **episode** is a bounded real or simulated occurrence with:

- property/deployment identity;
- session/time range;
- participating sensors and observability intervals;
- ground-truth event graph;
- actor/object roles without unnecessary identity;
- threat/non-threat adjudication and uncertainty;
- onset, detectability onset, end, and response-relevant milestones;
- occlusions, lighting, weather, camera failures, and privacy masks;
- expected alert policy outcome;
- annotation provenance and reviewer disagreement.

Frames are supporting evidence. They are not independent examples.

## 24.2 Split discipline

Random neighboring-frame splits are forbidden. Train/development/qualification/holdout partitions
must separate at least by session and preferably by property, household, camera layout, and actor.
The sealed release holdout is not used for threshold tuning, prompt tuning, adapter debugging, or
model selection.

Published metrics declare:

- property count and environment diversity;
- episode counts by scenario;
- actor and household separation policy;
- camera/device distribution;
- time/weather/lighting distribution;
- missing-sensor and degraded-mode distribution;
- annotation agreement;
- excluded/unknown episodes;
- whether any component was synthetically generated.

## 24.3 Scenario taxonomy

### Hard negatives

- resident takes garbage/recycling out;
- resident arrives late wearing dark clothing;
- child crawls or plays near camera;
- pet, raccoon, deer, bird, insect, spider web;
- delivery, mail, utility, maintenance, invited guest;
- wind-blown foliage, shadows, headlights, rain, snow, fog, lens droplets;
- moving vehicle reflections;
- camera auto-exposure/night-mode transition;
- robot vacuum/lawn equipment;
- neighbor or pedestrian in public mask zone;
- resident tests door/window or carries tools;
- drone used for authorized calibration;
- device reboot, timestamp jump, duplicate clip, replayed vendor notification.

### Threat/staged-positive classes

- unauthorized approach and boundary crossing;
- door/window tampering and forced-entry attempt;
- concealment, crawling, low posture, dark clothing, face obscuration;
- route exploiting camera blind spots;
- loitering with escalating boundary interaction;
- package theft;
- fence/gate crossing;
- camera obstruction, rotation, disconnection, or replay attack;
- coordinated multi-person approach;
- entry followed by movement across cameras;
- vehicle-assisted intrusion where observable;
- insider-like use of a compromised credential, represented as policy anomaly rather than visual
  stereotype.

All threat episodes are safely staged, synthetic, or obtained under lawful consent. The corpus does
not encourage harmful intrusion tactics beyond what is necessary for defensive testing.

## 24.4 Observability labels

Every episode interval is labeled as one of:

- `Observable`: sufficient sensor evidence exists in principle;
- `PartiallyObservable`: evidence exists but key discriminants are missing;
- `NotObservable`: the sensor mesh could not perceive the event;
- `SensorFailed`: expected coverage absent due to failure;
- `GroundTruthUncertain`.

“Never miss” is evaluated only with respect to declared observable threat episodes. Not-observable
cases drive coverage improvement and sensor-health alerts; they are not mislabeled model false
negatives or silently excluded.

## 24.5 Annotation graph

Annotations include more than a binary label:

- object/actor tracks with uncertain intervals;
- entry/exit zones and world-space path where available;
- actions and interactions;
- ownership/familiarity evidence where consented;
- occlusion and visibility;
- harmless explanations;
- threat indicators and counterevidence;
- sensor-quality failures;
- event hierarchy and causal links;
- policy-expected action;
- reviewer confidence and disagreement.

This supports diagnosis: a miss may originate in detection, tracking, time alignment, geometry,
cross-camera association, temporal reasoning, policy, or alert delivery.

## 24.6 Primary metrics

| Metric | Why it is primary |
|---|---|
| Event AUPRC | Reflects rare-event precision/recall tradeoff without being dominated by true negatives |
| Threat recall lower confidence bound at fixed false alerts/property-day | Captures the operational safety/annoyance frontier |
| Time-to-detect from detectability onset | Measures response usefulness rather than eventual recognition |
| Missed observable threat episodes | Direct count with root-cause classification |
| False alert episodes/property-day | Human burden at deployment unit |
| Selective risk/coverage curve | Rewards explicit uncertainty and abstention where escalation is possible |
| Calibration error / Brier or log score | Tests whether confidence means what it says |
| Cross-camera association ID metrics | Isolates continuity quality |
| Sensor-coverage and health detection recall | Prevents perception failure from masquerading as normal quiet |
| Compute/energy/egress per camera-day | Ensures economic scalability |

Frame AP, segmentation IoU, tracking HOTA, caption scores, depth errors, and reconstruction metrics
are subsystem diagnostics, not the product success criterion.

## 24.7 Fixed operating points

The release report must include at least:

- recall at `0.01`, `0.05`, `0.1`, `0.5`, and `1.0` false alerts/property-day where statistically
  supported;
- false alerts/property-day at target recall levels;
- 95% confidence intervals or conservative credible intervals clustered by property/session;
- results by observable threat subtype and hard-negative subtype;
- performance with each sensor ablated;
- performance under declared compute tiers;
- calibration/coverage strata;
- known zero-count cells rather than interpolation.

A single best threshold selected after seeing the holdout is prohibited.

## 24.8 Statistical method

Recommended baseline:

- cluster bootstrap by property, then session/episode within property;
- stratified reporting for threat categories and deployment archetypes;
- paired bootstrap for candidate-vs-incumbent comparisons;
- exact or conservative binomial bounds for zero/small miss counts;
- pre-registered operating points and superiority/non-inferiority margins;
- multiple-comparison control for broad model sweeps;
- uncertainty propagated from unresolved labels rather than forced consensus;
- sequential/e-value methods for long-running field monitoring where valid.

An observed zero misses does not imply zero miss probability. The report states the bound supported
by exposure and the assumptions behind it.

## 24.9 Model and policy promotion

A candidate generation is promoted only when:

1. all required deterministic/conformance gates pass;
2. no privacy/license/format regression exists;
3. event-level metrics meet predeclared margins on the sealed evaluation lane;
4. subgroup/scenario regressions are reviewed rather than hidden by aggregate gains;
5. resource cost fits a registered profile;
6. shadow deployment shows no unexplained drift;
7. rollback is tested;
8. negative evidence is recorded;
9. the qualification bundle binds exact bytes and configuration.

A larger model does not bypass this process.

## 24.10 Field learning without test leakage

Operator feedback enters an append-only adjudication stream. It can:

- correct an event label;
- explain a familiar routine;
- identify sensor/calibration failure;
- propose a household-specific policy memory;
- mark an alert useful/harmful;
- nominate a clip for a future consented training set.

Online memories may affect local policy after explicit promotion, but release qualification remains
on sealed data. Field examples are versioned into future corpus generations with provenance and
property-level split controls.

## 24.11 Red-team cadence

Before each major release:

- run the sealed threat/hard-negative gauntlet;
- run sensor failure and timestamp adversaries;
- run model prompt/metadata injection cases;
- run mask/export/deletion privacy cases;
- run multi-agent effect races;
- run vendor firmware drift fixtures;
- run deliberate unknown/not-observable cases;
- inspect the highest-confidence wrong alerts and misses;
- publish a bounded negative-evidence summary.

The purpose is to find reasons not to make a claim.

---

# Part VIII — Economics, operations, implementation, and release

## 25. Performance and economic model

FSS is intended to turn inexpensive commodity sensors into a system whose intelligence comes from
software. It fails that mission if each camera requires a permanent frontier GPU, unbounded cloud
egress, or wasteful full-resolution inference. Performance is therefore expressed as end-to-end
cost per protected property and per camera-day, not isolated model throughput.

## 25.1 Workload model

A deployment profile declares:

```text
C = number of cameras
R_i = source bitrate of camera i
F_i = source frames per second
A_i = fraction of time admitted by cheap activity gate
V_i = fraction admitted to visual detector
T_i = fraction admitted to temporal verifier
G_i = fraction admitted to geometry/depth work
D = ordinary media retention duration
E = candidate/incident retention exposure
U = cloud-upload fraction after local policy
```

Raw ingest bytes per day are approximately:

```text
raw_bytes_day = sum_i(R_i * 86_400 / 8)
```

but decode, inference, archive, and egress costs are governed by the admitted fractions and
rendition policy rather than raw input alone.

## 25.2 Compute cascade

The default cognitive path is progressive:

1. packet/stream health without decode where possible;
2. low-cost motion/change/background model;
3. sparse decode/keyframe or low-resolution rendition;
4. detector/segmenter and tracker;
5. cross-camera association and geometry checks;
6. temporal action/event verifier;
7. expensive VLM/reconstruction only for ambiguous or high-value cases;
8. human/agent review on selected evidence.

Each stage emits a typed reason for escalation. A model cannot consume all frames merely because
capacity is available. The operation-cost registry defines maximum decode pixels, frames, model
calls, GPU milliseconds, temporary bytes, and deadline for each plan.

## 25.3 Resource profiles

Reference profiles are semantic contracts rather than branded hardware promises:

| Profile | Intended deployment | Contract |
|---|---|---|
| `edge_cpu` | Mini PC/NAS, few cameras | Health, low-rate motion, recording, basic detection; bounded backlog and explicit temporal-verifier degradation |
| `edge_igpu` | Consumer integrated GPU/NPU | Multi-camera low-res detection/tracking with burst verification |
| `single_gpu_value` | One affordable discrete GPU | Default serious home deployment; full cascade over several cameras within measured duty cycle |
| `single_gpu_large` | High-memory prosumer GPU | Larger temporal/VLM/geometry models and faster calibration |
| `hybrid_burst` | Local edge plus opt-in remote/on-demand worker | Local always-on safety path; privacy-minimized burst work with explicit egress receipts |
| `replay_lab` | Workstation/cluster | Deterministic qualification, model sweeps, reconstruction, not the operational cost baseline |

Every release publishes tested camera count, resolution, FPS, activity distribution, latency,
queue age, dropped/degraded work, watts where measurable, and model generations for each claimed
profile.

## 25.4 Backpressure and load shedding

Backpressure is semantic. Under pressure FSS follows a declared ladder:

1. preserve source custody and sensor-health monitoring;
2. preserve active high-severity event obligations;
3. reduce preview quality/frequency;
4. skip redundant low-value frames using deterministic sampling;
5. defer archival renditions while retaining committed source chunks;
6. switch to cheaper qualified model generation;
7. narrow noncritical search/index enrichment;
8. declare degraded coverage and alert the operator before dropping safety-critical evidence.

No queue grows without a bound. Every dropped/deferred unit has reason, priority, source interval,
and accounting. Queue age, not utilization alone, drives admission.

## 25.5 Media mechanical sympathy

The media path should minimize copies and transcoding:

- retain original compressed packets/chunks when codec/container policy permits;
- parse once and derive multiple consumers through shared immutable spans;
- align chunks to useful keyframe/random-access boundaries without trusting malicious indexes;
- use scatter/gather and bounded buffer pools;
- cache decoded low-resolution frames only across explicitly compatible consumers;
- batch tensor preprocessing by shape/model generation while respecting latency;
- exploit hardware decode/encode only through qualified first-party Rust backends with scalar/CPU references;
- avoid re-encoding merely to change a manifest;
- separate live low-latency rendition from archival high-compression rendition;
- publish root manifests last so retries can reuse already durable objects.

Zero-copy is a hypothesis to measure, not a slogan. Copy elimination that weakens lifetime,
isolation, or cancellation semantics is rejected.

## 25.6 Archive object economics

Tiny objects amplify request cost and metadata overhead; huge objects amplify recovery, upload
retry, and incident-seek latency. The archive planner selects chunk duration/size from:

- codec keyframe structure;
- source reliability;
- local crash window;
- provider request pricing;
- expected incident retrieval range;
- multipart thresholds;
- deduplication opportunity;
- encryption and repair granularity;
- deletion precision.

Provider prices are external time-varying inputs. They live in a dated signed pricing manifest,
not hard-coded logic. The planner reports separate storage, operation, retrieval/egress, and local
compute estimates. A provider marked “cheap storage” is not assumed cheap for frequent retrieval.

## 25.7 Retention and compression policy

FSS stores semantically useful tiers:

- source-quality short rolling window;
- continuously retained low-rate overview where configured;
- event-adjacent source-quality windows;
- thumbnails/crops/track summaries for fast search;
- geometry/calibration artifacts;
- immutable incident bundle;
- optional repair/protection symbols.

Compression choice depends on measured decode compatibility, random access, quality needed for
recognition, and long-term support. The source stream may already be efficient; blind transcode can
waste energy and destroy forensic detail. Any lossy archival rendition is linked to the source
object and carries objective/subjective quality evidence appropriate to its purpose.

## 25.8 Energy and thermal behavior

The benchmark harness records:

- wall power or platform energy counters where available;
- GPU/CPU utilization and clocks;
- thermal throttling;
- fan/noise-relevant duty cycle where practical;
- idle baseline;
- joules per admitted camera-minute and per verified event;
- energy effect of model cascade stages;
- overnight/seasonal profile.

A configuration that meets latency for ten minutes and throttles after two hours does not pass the
soak gate.

## 25.9 Performance SLOs

SLO values are profile-specific and start as targets. Required dimensions include:

- stream acquisition startup p50/p95/p99;
- source-to-live-view latency;
- detectability-onset to candidate and alert latency;
- maximum queue age by priority;
- archive durability lag;
- incident retrieval time;
- cancellation-to-quiescence where worker responsiveness is bounded;
- adapter reconnect convergence;
- model-generation rollback time;
- calibration update duration;
- per-camera memory and disk write amplification;
- object-store request/byte cost;
- false degradation declarations and missed degradation.

No aggregate “real time” claim is permitted without these distributions and workload identity.

## 25.10 Benchmark discipline

Performance changes use keep gates:

1. profile the real end-to-end workload;
2. preserve semantic golden/differential results;
3. compare identical input, model, device, policy, and quality;
4. report warm/cold state, variance, and sample count;
5. attribute improvement to a changed operation-cost term;
6. retain negative results;
7. test under cancellation, faults, and sustained load;
8. reject optimizations that merely shift work outside the measured interval.

The performance ledger records wins. The negative-evidence ledger records losses and no-effects.

---

## 26. Observability, diagnostics, repair, installation, and operations

FSS must remain understandable when a camera silently changes firmware at 3 a.m., a model executor
starts returning NaNs, storage fills, or an alert result is ambiguous. Operator experience is part
of correctness.

## 26.1 Observability model

Telemetry is typed and bounded:

- counters/gauges/histograms for health and cost;
- structured events for state transitions;
- traces across source capsule, model plan, event, policy decision, and effect;
- obligation inventory;
- generation/compatibility matrix;
- bounded recent-event rings for diagnostics;
- no raw secret or unrestricted media in logs.

Metric labels use stable low-cardinality identities or buckets. Raw event/camera IDs belong in
queryable ledger fields, not unbounded metric labels.

## 26.2 Health is multidimensional

A single green/red status is insufficient. Health reports dimensions:

- device reachability and authentication;
- packet continuity and keyframe cadence;
- timestamp quality;
- image usefulness/obstruction/exposure;
- adapter compatibility confidence;
- calibration freshness and mask validity;
- model runtime readiness and generation;
- queue pressure and degraded mode;
- local durability and free space;
- remote archive obligations;
- alert-channel qualification;
- privacy/deletion obligations;
- policy and schema compatibility.

A camera can be reachable but security-useless. FSS says so.

## 26.3 `doctor`

`fss doctor --json` is read-only. It returns:

- active deployment/profile summary;
- exact versions/generations;
- failed/degraded checks with evidence handles;
- suspected root causes;
- bounded next commands;
- proposed repair-plan handles;
- whether claims/SLO coverage remain valid.

Doctor never rotates credentials, restarts services, deletes data, changes thresholds, or repairs
state implicitly.

## 26.4 Repair plan/apply

Repair is two-phase:

```text
fss repair plan <scope> --json
  -> sealed plan: observations, proposed mutations, risks, rollback, cost, expiry

fss repair apply <plan-digest> --json
  -> revalidate preconditions
  -> reserve obligations
  -> execute bounded effects
  -> publish receipt and rollback state
```

Example repairs:

- rebuild a derived index;
- reconcile orphaned staging objects;
- retry or abort multipart upload;
- rotate an adapter session;
- roll back model/adapter generation;
- recalculate calibration after approved evidence;
- restore a manifest from protected objects;
- complete deletion closure;
- requalify an alert provider.

No repair rewrites immutable evidence history.

## 26.5 Support bundles

A support bundle includes machine- and human-readable material:

- sanitized config and topology;
- version/generation manifests;
- selected structured events and traces;
- health/obligation snapshots;
- reproduction commands;
- crash/backtrace data;
- schema and policy digests;
- optional operator-selected media samples with visible privacy warning;
- bundle manifest and checksums.

Default bundles contain no credentials and no full media. Bundle generation itself is a prepared
export effect when sensitive data is selected.

## 26.6 Installation

The reference distribution aims for:

- one verified installer or package per supported platform;
- checksum and provenance verification before replacement;
- staged binary/config migration;
- `doctor` and version/schema smoke test;
- explicit model/device onboarding afterward;
- no hidden model download during build;
- no requirement for a daemon to inspect capabilities/status;
- rollback to the prior binary/config generation.

Containers MAY package laboratory or deployment tooling, but cannot hide a foreign production runtime, host camera/accelerator constraints, or become the only supported route.

## 26.7 Configuration

Precedence is explicit and reported:

1. command-line override;
2. deployment config;
3. user config;
4. environment secret handles/limited overrides;
5. built-in safe defaults.

Configuration is typed, versioned, migratable, and split by concern: deployment, devices,
privacy, retention, models, policy, alerts, storage, and agent surface. Unknown security-relevant
fields fail closed. `fss config explain <path>` reports the winning source and validation.

## 26.8 Upgrade and migration

Upgrade protocol:

1. verify release bytes/provenance;
2. run compatibility preflight against current schemas, device tuples, model generations, and free
   space;
3. create rollback checkpoint and migration plan;
4. stop admission of new mutating operations;
5. drain owned regions/obligations or record indeterminate external effects;
6. stage migrations;
7. run deterministic validation and smoke replay;
8. atomically activate;
9. observe canary period;
10. retain rollback generation until gate expiry.

Migrations are forward-defined. Destructive or lossy migrations require explicit policy and backup
proof. A binary version change never silently activates a new model or alert threshold.

## 26.9 Backup and disaster recovery

Canonical recovery requires more than object-store video. Backup scope includes:

- ledger and transaction log/checkpoints;
- manifests and schemas;
- secret-store recovery mechanism without copying plaintext secrets;
- calibration/geometry and policy generations;
- model/adapter manifests or reacquisition receipts;
- object inventory and protection metadata;
- audit/effect/obligation state;
- deletion/hold metadata.

Recovery rehearsal proves a clean host can restore a bounded deployment, verify object roots,
rebuild derived indexes, resume obligations safely, and avoid duplicate alerts. RPO/RTO are profile
claims backed by drills.

## 26.10 Soak and canary

Release candidates run:

- multi-day continuous ingest;
- planned device and network interruptions;
- disk pressure and archive backlog;
- model invocation cancellation/memory pressure;
- clock correction;
- adapter credential expiry;
- repeated upgrade/rollback;
- alert-channel qualification without contacting unintended recipients;
- deletion and retention lifecycle;
- thermal/power measurement;
- support bundle generation.

Canaries activate one deployment or camera subset with automatic rollback triggers derived from
semantic regressions, not only process crashes.

## 26.11 Incident response

Operational incidents have typed classes: data exposure, credential compromise, missed threat,
false emergency, tamper, archive loss, model regression, vendor drift, and privacy-policy failure.
The response flow preserves evidence, revokes relevant grants, freezes affected generations,
creates a reproducible bundle, and separates containment from later repair. Audit records cannot be
edited to make the incident disappear.

---

## 27. Target crate topology, dependency DAG, and durable formats

The bootstrap repository remains intentionally small. The target workspace is fine-grained enough
to expose semantic owners, but crates are created only with a real contract and vertical test—not
as empty architecture theater.

## 27.1 Target crate families

| Layer | Crates | Responsibility |
|---|---|---|
| Foundation | `fss-types`, `fss-error`, `fss-schema`, `fss-numeric`, `fss-identity` | stable IDs/generations/anchors, bounded values, exact numerics, canonical formats |
| Runtime/fabric | `fss-runtime`, `fss-capability`, `fss-subject`, `fss-obligation`, `fss-lab`, `fss-decision` | Asupersync integration, authority/budgets, service classes, obligations, replay, Decision Cards |
| Device | `fss-device-core`, `fss-device-uvc`, `fss-device-rtsp`, `fss-device-onvif`, `fss-device-vendor`, `fss-drone-capture` | discovery, authentication, packet acquisition, controls, exact compatibility tuples |
| Media | `fss-packet`, `fss-container`, `fss-codec-core`, `fss-codec-jpeg`, `fss-codec-avc`, `fss-codec-hevc`, `fss-audio`, `fss-live` | packet truth, bounded parsers/decoders/encoders, containers, live derivatives |
| Authority/storage | `fss-ledger`, `fss-witness`, `fss-object`, `fss-publication`, `fss-checkpoint`, `fss-privacy` | one version universe, semantic transactions, custody, root-last publication, deletion |
| Transfer/archive | `fss-transfer`, `fss-archive`, `fss-provider-s3`, `fss-repair`, `fss-retrievability` | ATP object graphs, focused provider protocols, RaptorQ, replica/retrieval proof |
| Geometry | `fss-time`, `fss-calibration`, `fss-geometry`, `fss-twin`, `fss-coverage` | clock intervals, covariance-bearing calibration, reconstruction, visibility/observability |
| Models | `fss-tensor`, `fss-operator`, `fss-kernel-cpu`, `fss-model-ir`, `fss-model-import`, `fss-model-runtime`, `fss-model-registry`, optional first-party accelerator crates | pure-Rust frozen inference graphs, kernels, packages, conformance, activation |
| Cognition | `fss-quality`, `fss-detect`, `fss-track`, `fss-associate`, `fss-temporal`, `fss-fusion`, `fss-event`, `fss-policy` | progressive derived perception, uncertainty, event transactions and policy |
| Knowledge/graph | `fss-search`, `fss-graph`, `fss-graph-query`, `fss-graph-algorithms`, `fss-forge`, `fss-memory`, `fss-explain` | immutable projections, incremental/factorized queries, certified algorithms, context packs |
| Effects | `fss-plan`, `fss-effect`, `fss-alert`, `fss-export` | prepared/revalidated/idempotent external operations and reconciliation |
| Presentation | `fss-api`, `fss-cli`, `fss-mcp`, `fss-report`, `fss-ops`, optional `fss-ui` | bounded human/agent views, deterministic reports, pure-Rust UI/TUI |
| Qualification/release | `fss-reference`, `fss-fixtures`, `fss-gauntlet`, `fss-bench`, `fss-release` | simple oracles, adversarial corpora, same-binary experiments, DSR proof roots |

## 27.2 Dependency direction

Foundation knows no device/media/model/effect concepts. Runtime/fabric may depend only on foundation
and Asupersync. Device/media/model/graph/storage foundations are peers and communicate through
foundation contracts, not cyclic concrete imports. Cognition consumes immutable views and emits
derived deltas. Effects consume prepared semantic plans; no detector, graph, search, UI, or adapter
can import alert/deletion authority.

Presentation depends downward. Qualification can depend across the workspace but never enters a
production feature. Oracle-only code and fixtures are excluded from release closure.

## 27.3 Closed dependency doctrine

The machine policy is [`architecture/dependency_allowlist.toml`](architecture/dependency_allowlist.toml).
The default external exception set is only Serde/Serde JSON/Thiserror, and only for their declared
control/report/error roles. Even these are not canonical durable formats. Every first-party sibling
is pinned to an exact clean revision in a DSR release snapshot.

## 27.4 Canonical durable formats

Every format has a `FMT-*` owner and:

- magic and version;
- explicit integer/float/numeric policy and endianness;
- section table or self-delimiting bounded records;
- canonical ordering and duplicate rules;
- per-section/object checksum plus root identity;
- hard counts, sizes, nesting, and allocation bounds;
- strict and optionally hardened-recovery modes;
- migration/read compatibility contract;
- corruption/fuzz/metamorphic fixtures;
- independent reconstruction command.

No persistent bytes are Rust layout, bincode default, or Serde derive output.

## 27.5 Core object families

- `EvidenceDeltaBatch` and authority checkpoints;
- sensor capsules, packet maps, and media segment graphs;
- effect plans/receipts and durable obligations;
- graph/search generations and algorithm witnesses;
- model packages, tensor objects, kernel plans, and invocation receipts;
- calibration/twin/coverage generations;
- event/evidence graphs and context packs;
- ATP transfer journals/receipts and repair/retrievability evidence;
- export/deletion/proof/release bundles.

## 27.6 Ledger versus object graph

The ledger stores typed identity, state transitions, indexes, small records, and root references.
Large immutable media/tensor/graph/index/proof objects live in content-identified object graphs. A
transaction never embeds arbitrary video bytes, and an object-store listing never substitutes for
ledger truth.

## 27.7 One version universe

All derived systems consume `EvidenceDeltaBatch` and publish exact high-water marks. See
[`docs/ONE_VERSION_UNIVERSE.md`](docs/ONE_VERSION_UNIVERSE.md).

## 28. Implementation work packages

Phases sequence the work; they do not reduce the target scope. Each work package has one owning
subsystem, explicit inputs, deliverables, dependencies, and exit evidence. Work may proceed in
parallel only where the dependency graph permits.

## 28.1 WP-000 — Constitutional bootstrap

**Purpose:** make architecture enforceable before implementation complexity arrives.

**Deliverables:**

- authoritative comprehensive plan and README;
- invariant, capability, effect, error, schema, claim, model, adapter, SLO, risk, and test
  registries;
- machine-readable architecture mirrors;
- dependency allowlist and graph checker;
- claim/evidence policy checker;
- stable JSON skeleton CLI;
- repository status doctrine and negative-evidence ledger;
- issue/bead epic graph derived from this plan.

**Exit evidence:** all repository policy checks pass; every public claim is classified; bootstrap
CLI schemas are stable; no implementation claim is made from skeleton code.

## 28.2 WP-010 — Deterministic reference world and replay spine

**Purpose:** create an end-to-end environment in which every later subsystem can be tested without
real cameras or GPUs.

**Deliverables:**

- virtual camera producing deterministic encoded/decoded fixtures;
- packet loss/reorder/disconnect/clock fault controls;
- sensor capsule and anchor construction;
- in-memory canonical ledger and content-addressed object spool;
- replay bundle reader/writer;
- virtual pure-Rust model executor with scripted hypotheses;
- simple event/policy/alert sink state machines;
- trace canonicalization and reproduction command.

**Exit evidence:** same seed/input produces byte-identical canonical outputs; cancellation at every
instrumented yield point leaves no unowned obligation; crash cut points recover to a classified
state.

## 28.3 WP-020 — Asupersync runtime integration

**Purpose:** replace skeleton state-machine examples with production region/capability patterns.

**Deliverables:**

- `fss-runtime` and `fss-capability`;
- session/stream/model/effect region hierarchy;
- budgets and pressure propagation;
- reserve/commit channels and durable obligations;
- supervised first-party subsystem regions and laboratory-oracle protocol;
- bounded shutdown and escalation registry;
- lab-runtime adapters.

**Dependencies:** WP-000, WP-010, compatible Asupersync APIs.

**Exit evidence:** native cancellation suites, parked subsystem tasks, deadline/pressure tests,
leak/obligation oracles, deterministic schedule replay.

## 28.4 WP-030 — Canonical ledger and object spool

**Purpose:** make every meaningful state and byte recoverable before adding real adapters.

**Deliverables:**

- storage traits and deterministic in-memory oracle;
- FrankenSQLite integration after API qualification;
- transactional event/effect/adapter/model/calibration tables;
- local staged object writes with checksums and root-last manifests;
- reconciliation and garbage-collection plans;
- schema/migration registry;
- crash matrix.

**Dependencies:** WP-020; compatible FrankenSQLite gate.

**Exit evidence:** kill-point matrix, torn/stale object fixtures, concurrent reader/generation tests,
rebuild of all derived projections, deterministic backup/restore drill.

## 28.5 WP-040 — UVC/UAC reference adapter

**Purpose:** prove the adapter and media contracts on a standards-native local device such as a USB
webcam before proprietary clouds.

**Deliverables:**

- enumeration and exact device-mode identity;
- negotiated resolution/FPS/format;
- capture session lifecycle and cancellation;
- timestamp evidence;
- audio disabled-by-default behavior;
- deterministic fixture capture/import;
- health and disconnect/reconnect model.

**Dependencies:** WP-020, WP-030.

**Exit evidence:** supported platform matrix, unplug/replug/cancel tests, sustained capture, no audio
artifact in disabled mode, exact capsule replay.

## 28.6 WP-050 — RTSP/RTP/ONVIF standards lane

**Purpose:** establish the primary inexpensive IP-camera integration path.

**Deliverables:**

- WS-Discovery/onboarding under explicit subnet scope;
- ONVIF device/media/PTZ/event capability negotiation;
- preferred Profile T stream handling and Profile M analytics metadata where available;
- RTSP session, RTP/RTCP, transport fallback, authentication, keyframe/discontinuity evidence;
- device conformance tuple and quirk registry;
- optional PTZ prepare/commit with leases/fences;
- standards fixtures and real-device matrix.

**Dependencies:** WP-020–040.

**Exit evidence:** multiple independent conformant devices, packet-fault suite, vendor quirk
classification, interoperability evidence without per-device semantic forks.

## 28.7 WP-060 — Pure-Rust media and live plane

**Purpose:** own packet, compressed-stream, container, source-custody, decode, live-proxy, and
analysis semantics without a required foreign runtime.

**Deliverables:**

- exact packet replay and timing format;
- RTSP/RTP/RTCP and UVC packet truth;
- bounded H.264/H.265/MJPEG/audio parsers and configuration epochs;
- deterministic narrow container/remux writers;
- first full JPEG/MJPEG decode vertical slice, then admitted AVC/HEVC profiles;
- immutable/generation-leased frame storage;
- low-resolution analysis path and bounded live fan-out;
- safe scalar and optimized/SIMD transform kernels;
- malformed media gauntlet and FFmpeg/browser oracle comparators;
- registered pressure-degradation ladder.

**Dependencies:** WP-040 or WP-050; WP-020, WP-030.

**Exit evidence:** parser/decode/container differential reports, cancellation/corruption/pressure
campaigns, source-to-tensor lineage, live-latency distributions, no foreign runtime in production
closure.

## 28.8 WP-070 — ATP archive, retention, repair, and retrievability

**Purpose:** publish encrypted immutable object graphs economically and prove they remain
reconstructable.

**Deliverables:**

- ATP manifest/chunk/journal/receipt integration;
- local object-store oracle and focused safe-Rust S3-compatible provider protocols;
- capability-scoped credentials and conditional/multipart operations;
- RaptorQ repair objects and post-repair digest verification;
- multipath/hedge scheduler with Decision Cards and safe fallback;
- dated provider-price manifest and object/chunk planner;
- replication/retrievability policy and challenge receipts;
- retention/hold/expiry obligations;
- graph-complete deletion including repair/replica/index/cache/journal paths;
- incident retrieval and independent reconstruction tooling.

**Dependencies:** WP-030, WP-060, admitted Asupersync ATP/repair primitives.

**Exit evidence:** loss/reorder/corruption/resume/multipath/root-last matrix, remote sandbox/restore,
retrievability failure-repair loop, deletion closure adversarial corpus, no broad cloud SDK or foreign
network runtime.

## 28.9 WP-080 — Pure-Rust model package and execution runtime

**Purpose:** admit current open-weight models through a focused first-party Rust runtime rather than
coupling production to Python, ONNX, libtorch, CUDA, or a model server.

**Deliverables:**

- typed tensor/storage/view/alias/version substrate;
- frozen first-party operator IR and deterministic importer;
- canonical tensor/model package formats and ATP publication;
- scalar reference operators and safe CPU kernel library;
- shape/layout/liveness planning, fusions, packed weights, safe SIMD, and static specialization;
- exact/tolerance numeric policy and invocation receipts;
- pinned foreign framework differential oracle harnesses;
- quantization as immutable generations;
- optional first-party accelerator contract, CPU fallback mandatory;
- license/use policy, event-quality qualification, shadow/canary/activation/rollback;
- no runtime model acquisition.

**Dependencies:** WP-020, WP-030, WP-060; admitted FrankenTorch mechanisms.

**Exit evidence:** reproducible model packages, operator/model agree-diverge-error-only-unexercised
reports, adversarial numeric/shape/alias/cancellation/memory tests, event-level held-out evidence,
and release dependency proof containing no foreign production runtime.

## 28.10 WP-090 — Detection, segmentation, and tracking cascade

**Purpose:** produce high-recall candidate trajectories economically.

**Deliverables:**

- activity gating and deterministic frame sampling;
- detector/segmenter registry integration;
- tracker and occlusion handling;
- quality/visibility evidence;
- open-vocabulary verifier;
- per-camera track lifecycle;
- subsystem evaluation and profiler;
- graceful compute-tier degradation.

**Dependencies:** WP-060, WP-080.

**Exit evidence:** held-out subsystem corpus, candidate-recall target, track metrics, cost budgets,
night/weather/animal/low-posture strata, no aggregate threat claim yet.

## 28.11 WP-100 — Event, policy, and effect spine

**Purpose:** convert observations into calibrated event hypotheses and safe alert actions.

**Deliverables:**

- event revision/evidence graph;
- belief intervals and contradiction representation;
- familiar/harmless/threat/unknown policy states;
- temporal verifier integration;
- abstention and escalation;
- prepared alert and idempotent delivery reconciliation;
- operator adjudication flow;
- explanation and counterfactual surface.

**Dependencies:** WP-090, WP-030, WP-020.

**Exit evidence:** scripted episode suite, lost-ACK and retry tests, calibrated confidence checks,
no adapter/model score directly becomes an alert.

## 28.12 WP-110 — Time synchronization and calibration

**Purpose:** establish conservative spatiotemporal registration across cheap unsynchronized
cameras.

**Deliverables:**

- clock offset/skew interval model;
- visual/time synchronization observations;
- intrinsics/distortion estimation;
- cross-camera correspondence and extrinsics;
- calibration certificate/residual/covariance;
- active validity monitors and invalidators;
- privacy-mask reprojection;
- manual landmark/measurement fallback.

**Dependencies:** WP-060, WP-030; models from WP-080 as optional methods.

**Exit evidence:** known-rig fixtures, perturbation/drift tests, interval conservatism,
certificate rollback, mask fail-closed behavior.

## 28.13 WP-120 — Drone-assisted digital twin and coverage

**Purpose:** let an operator fly a drone/camera through the property and derive a useful,
uncertainty-aware digital twin and sensor coverage model.

**Deliverables:**

- human-piloted capture mission manifest;
- drone video/telemetry import and time alignment;
- trajectory/reconstruction backend registry;
- point cloud/voxel/mesh/semantic scene generations;
- scale/orientation anchors;
- fixed-camera localization into twin;
- visibility/occlusion/quality coverage map;
- calibration route planner and operator guidance;
- geometry privacy transformations.

**Dependencies:** WP-080, WP-110; compatible capture path.

**Exit evidence:** measured property/mock-site reconstruction, held-out landmarks, uncertainty and
failure detection, no autonomous flight control, coverage prediction validated against observations.

## 28.14 WP-130 — Cross-camera association and fused sensor mesh

**Purpose:** maintain event continuity across cameras without creating a universal biometric
tracking system.

**Deliverables:**

- geometry/time-gated association graph;
- appearance embeddings with privacy-domain and TTL rules;
- trajectory/path plausibility;
- uncertainty-preserving merge/split;
- anonymous continuity IDs;
- multi-camera evidence queries;
- association-specific adjudication and metrics.

**Dependencies:** WP-090, WP-110, optionally WP-120.

**Exit evidence:** property/session-separated evaluation, cross-domain denial tests, sensor ablation,
identity switch analysis, contradiction retention.

## 28.15 WP-140 — Threat and hard-negative gauntlet

**Purpose:** qualify the complete security product rather than disconnected models.

**Deliverables:**

- consented/synthetic episode constitution;
- observability labels;
- hard-negative and threat taxonomy;
- sealed holdout workflow;
- event AUPRC and fixed false-alert operating points;
- cluster-bootstrap/e-value statistical tooling;
- root-cause attribution;
- red-team cadence and proof bundles.

**Dependencies:** WP-100, WP-130, sensor/geometry lanes.

**Exit evidence:** predeclared report with confidence bounds, zero hidden exclusions, negative
results, and repeatable qualification command.

## 28.16 WP-150 — Proprietary camera interoperability lab

**Purpose:** support owner-authorized consumer devices whose vendors do not expose a stable local
standard, without contaminating the core.

**Deliverables:**

- legal/ethical lab charter and owner-authorization assertion;
- firmware/app/account/region tuple identity;
- traffic/session fixture capture with secret sanitization;
- protocol-state inference and differential oracle against official app;
- Wyze/AOSU candidate adapters or explicit unsupported findings;
- shadow qualification and automatic drift quarantine;
- safe onboarding and revocation;
- no public credential/secret fixture leakage.

**Dependencies:** WP-050 contract, WP-060, WP-020, WP-030.

**Exit evidence:** exact tuple matrix, sustained owner-account operation, firmware-drift behavior,
credential isolation, public claim restricted to qualified tuples.

## 28.17 WP-160 — DJI Flip capture bridge

**Purpose:** ingest authorized live/recorded DJI Flip imagery when a supportable path exists, while
keeping flight manual and acknowledging SDK constraints.

**Deliverables:**

- official media-file import first;
- phone/controller screen/capture bridge experiment;
- telemetry extraction where available;
- authorization/session identity;
- latency/quality/timestamp evaluation;
- explicit unsupported outcomes when the official SDK/product surface is insufficient;
- no brittle route promoted without a conformance bundle.

**Dependencies:** WP-060, WP-110/120; findings from current DJI support matrix.

**Exit evidence:** repeatable capture on exact mobile/controller/firmware tuple or an honest
negative-evidence report. No autonomous control.

## 28.18 WP-170 — One-version search, certified graph intelligence, and operational memory

**Purpose:** make high-value investigation and planning fast, deterministic, explainable, and
bounded without turning derived systems into authority.

**Deliverables:**

- `EvidenceDeltaBatch` consumer/high-water protocol;
- Quill immutable generations plus searchable bounded delta;
- temperature-tiered graph projections and incremental standing predicates;
- factorized graph-relational planner and full-recompute oracle;
- registered algorithm families, canonical tie-breaks, and `GraphAlgorithmWitness` receipts;
- adversarial graph corpus and NetworkX/ordered-Rust differential accounting;
- capability projection before search/graph expansion;
- branch-per-agent counterfactual overlays that emit candidate intent only;
- typed evidence-backed memories, decay/trauma guard, audited curation/revival;
- deterministic token-budgeted context packs and explanations;
- optional offline Forge-style safe-Rust specialization.

**Dependencies:** WP-030, WP-080–130; admitted FrankenSearch/GraphDB/NetworkX/Eidetic mechanisms.

**Exit evidence:** incremental/full/rebuild equivalence, tie and complexity witness locks, branch and
capability noninterference, deterministic packs, held-out retrieval quality, and same-binary proof
before any optimized path replaces reference.

## 28.19 WP-180 — CLI, MCP, and operator experience

**Purpose:** expose the system efficiently to humans and agents without leaking ambient authority.

**Deliverables:**

- complete CLI with stable JSON/JSONL and shell completions;
- read-first FastMCP Rust server;
- prepared bounded effects;
- anchor/continuation/budget contracts;
- live/event/coverage operator UI;
- first-party Rust operator surfaces for terminal, desktop, and constrained mobile incident review;
- capabilities/doctor/robot docs;
- session/lease audit.

**Dependencies:** API facade and owning subsystems.

**Exit evidence:** protocol/schema snapshots, cancellation, multi-agent races, token budgets,
accessibility/mobile tests, no generic command surfaces.

## 28.20 WP-190 — Security, privacy, local qualification, and release

**Purpose:** make the system deployable and releasable without weakening the architecture or
requiring GitHub-hosted capacity.

**Deliverables:**

- closed dependency, zero-unsafe, build-script, offline-resolution, and runtime-download enforcement;
- secret store and capability noninterference tests;
- privacy masks, retention, holds, export, and graph-complete deletion;
- deterministic doctor/repair/support/proof bundles;
- latest-nightly probe and accepted-pin promotion lane;
- repository-local `scripts/qualify.sh` as one qualification contract;
- DSR clean snapshot, exact sibling closure, native host/lane matrix, disk-backed staging;
- resumable target builds with no partial release root;
- exact assets, checksums, minisign/Ed25519 signatures, SBOM, provenance, license inventory;
- installer clean-install/upgrade/rollback/uninstall canaries;
- upload followed by download-and-verify;
- workflow YAML as local portable specification only.

**Dependencies:** all earlier WPs and DSR integration.

**Exit evidence:** security/privacy gauntlets, offline dependency resolution, clean-snapshot
rebuilds, native platform receipts, interruption/resume tests, exact asset and signing separation,
GitHub-hosted-runner absence test, and public claims mechanically derived from proof roots.

## 29. Acceptance gates and release doctrine

A gate is a retained evidence decision, not “the code seems done.” Gates may fail, pass narrowly,
or pass with exclusions. Later gates do not retroactively widen earlier evidence.

## 29.1 Gate matrix

| Gate | Name | Minimum evidence |
|---|---|---|
| `GATE-000` | Architecture constitution | Registries/mirrors agree; dependency and claim checks pass; threat/privacy model reviewed |
| `GATE-010` | Deterministic walking skeleton | Virtual source→capsule→event→prepared alert→receipt replay; crash/cancel matrix |
| `GATE-020` | UVC reference acquisition | Real standards device on supported platform; sustained capture; exact replay; disconnect/cancel |
| `GATE-030` | RTSP/ONVIF reference mesh | Multiple independent devices; discovery/auth/media/events/PTZ boundaries; packet fault suite |
| `GATE-040` | Media and archive durability | Differential media corpus; live SLO; root-last upload; restore/retrieval/deletion interactions |
| `GATE-050` | Pure-Rust model runtime and perception | Reproducible model packages; operator/model conformance; numeric/memory/cancellation/rollback; candidate-recall and cost profile; no foreign production runtime |
| `GATE-060` | Event and alert correctness | Evidence graph, calibrated policy, prepare/commit, idempotency, lost-ACK reconciliation |
| `GATE-070` | Calibration/digital twin | Time/intrinsics/extrinsics certificates; drift invalidation; measured reconstruction and coverage |
| `GATE-080` | Threat gauntlet | Sealed event-level evaluation, fixed operating points, confidence bounds, hard negatives |
| `GATE-090` | Proprietary adapters | Exact device/firmware/account/region tuples; shadow qualification; drift quarantine |
| `GATE-100` | DJI Flip capture | Supported repeatable capture/import tuple or explicit unsupported report; manual flight only |
| `GATE-110` | Agent/operator surface | Stable CLI/MCP schemas, token budgets, leases/fences, capability denial, mobile review |
| `GATE-120` | Release candidate | Security/privacy/DR/soak/perf/provenance proof bundle and honest generated status |

## 29.2 GATE-000 detailed criteria

- every invariant has an owner and at least one planned test;
- goals and non-goals are not contradictory;
- trust/failure domains are explicit;
- current device/model claims are source-cited and dated;
- dependency graph is acyclic and allowed;
- model licenses are classified;
- all durable schemas have version/error/size doctrine;
- public README distinguishes plan, skeleton, experimental, and qualified behavior;
- drone autonomy is absent;
- privacy/deletion closure and not-observable semantics are normative.

## 29.3 GATE-010 detailed criteria

- complete deterministic replay bundle round trip;
- operation IDs/digests stable across runs;
- every injected kill/cancel point yields terminal or indeterminate classified obligations;
- duplicate prepared/committed alert intents do not duplicate effect;
- source bytes, model result, event revision, and effect receipt are linked by digest;
- doctor identifies staged/orphaned/indeterminate states;
- no network, GPU, vendor account, or wall clock required.

## 29.4 GATE-020/030 acquisition criteria

- exact device/platform/firmware tuple recorded;
- capability negotiation not hard-coded assumption;
- timestamp/discontinuity evidence retained;
- bounded startup, reconnect, and shutdown distributions;
- malformed/oversized metadata rejected;
- credential redaction tests;
- continuous soak without unbounded memory/queue growth;
- source-quality verification and obstruction/health events;
- standards conformance scoped to measured operations, not profile marketing alone.

## 29.5 GATE-040 media/archive criteria

- source custody and every rendition lineage verified;
- incumbent/reference differential corpus classified;
- decoder/encoder worker crash cannot corrupt canonical publication;
- archive manifests never reference unavailable committed objects;
- upload retries reuse immutable objects and idempotency;
- restore produces exact digests;
- provider outage leaves local safety path operational within declared limits;
- retrieval and cost evidence meets profile;
- deletion plan finds remote/staged/derived objects.

## 29.6 GATE-050/060 cognition criteria

- no model output bypasses schema and policy;
- exact weights/runtime/preprocess identity retained;
- held-out candidate recall and event metrics reported separately;
- confidence calibration and abstention evaluated;
- contradicting evidence preserved;
- operator feedback append-only and provenance-bearing;
- alert side effects use prepared intent, grant, idempotency, and reconciliation;
- ambiguous provider result remains indeterminate;
- rollback returns active system to prior qualified generation.

## 29.7 GATE-070 geometry criteria

- intrinsic/extrinsic/time parameters include uncertainty;
- known-rig and synthetic truth residuals meet targets;
- calibration degrades rather than silently extrapolating after invalidator;
- privacy masks remain conservative under uncertainty;
- digital twin coordinate/scale anchors reproducible;
- coverage predictions checked against observed detection/visibility;
- human can inspect evidence and manually correct with a new generation;
- no plausible-looking unqualified geometry is presented as metric truth.

## 29.8 GATE-080 threat criteria

- sealed property/session-separated holdout;
- all exclusions and observability states reported;
- event AUPRC plus fixed false-alert operating points;
- confidence bounds clustered at deployment unit;
- hard-negative categories and threat subtypes shown;
- sensor/compute ablation;
- latency, energy, and cost alongside quality;
- highest-confidence errors reviewed;
- no absolute “never miss” language beyond measured bound and observable scope.

## 29.9 GATE-090/100 interoperability criteria

- exact supported tuples and onboarding requirements;
- official app/device behavior retained as oracle where lawful/practical;
- no secrets in fixtures/logs/repository;
- drift detector and automatic quarantine;
- unsupported firmware/account/region fails explicitly;
- account/device lockout risk bounded;
- adapter does not weaken core security/privacy;
- reverse engineering is owner-authorized interoperability, not third-party access;
- DJI lane does not imply official SDK support or flight control.

## 29.10 GATE-110 agent/operator criteria

- all read responses anchored and bounded;
- continuation works without inconsistent pagination;
- effects require typed capability and prepared intent;
- stale anchor/lease/fence rejected;
- untrusted OCR/metadata cannot inject tool calls;
- token and evidence hydration budgets measured;
- agent benchmark tasks reproducible;
- UI exposes uncertainty, degradation, privacy transforms, and evidence provenance;
- accessibility and mobile incident workflow pass.

## 29.11 GATE-120 release criteria

- source snapshot is clean and immutable;
- every Asupersync/Franken-suite dependency is an exact clean revision in the release closure;
- resolution is locked and offline after provisioning;
- every FSS crate forbids unsafe and the dependency report contains only admitted packages;
- the exact accepted nightly/compiler/components are recorded;
- required local DSR lanes pass on controlled native hosts;
- required device/model/media/graph claim-specific lanes pass;
- completed partial targets may be retained but no release root exists before the full matrix passes;
- exact asset enumeration, checksums, Ed25519/minisign signatures, SBOM, provenance, source and
  qualification manifests agree;
- signing authority is separate from builders;
- installer/upgrade/rollback/uninstall canaries pass;
- uploaded artifacts are downloaded and independently verified;
- workflows contain no unique release logic and GitHub-hosted runner absence is irrelevant;
- public claims are mechanically derived from retained proof-bundle roots and expiry rules.

## 29.12 Claim lifecycle

Claims move through:

```text
Proposed → MeasuredInLab → ShadowQualified → NarrowlyQualified → Released
                         ↘ Rejected / Superseded / Expired
```

A claim expires when any load-bearing generation changes: device firmware, adapter, model,
preprocessing, policy threshold, calibration method, schema, runtime, platform, or corpus contract.
Some changes can use delta qualification; the registry must justify it.

## 29.13 Versioning and latest-nightly promotion

Software, schemas, durable formats, model packages, adapter tuples, calibration generations, and
policy generations version independently but are cross-bound in receipts. “Latest nightly” is not
an ambient mutable input: a probe records the candidate, all required gates run, drift is
classified, and a dedicated reviewed commit promotes that exact toolchain. Releases use the pin;
they never auto-upgrade the compiler.

## 29.14 Release channels

- **Reference:** deterministic oracles and architecture surfaces; not a deployment claim.
- **Lab:** replay, oracle, and authorized real-device experimentation; no production safety claim.
- **Canary:** limited deployments with automatic rollback and exact evidence scope.
- **Stable:** only dimensions and device/model/platform tuples proven by local DSR receipts.

A channel is not aggregate readiness. Every release lists excluded and degraded surfaces.
GitHub Releases can distribute bytes, but local DSR qualification decides whether a release root is
publishable. See [`LOCAL_QUALIFICATION_AND_RELEASE.md`](docs/LOCAL_QUALIFICATION_AND_RELEASE.md).

## 30. Risk register and open questions

Risks are not reasons to avoid building the project. They are hypotheses requiring mitigation and
evidence.

## 30.1 Technical risks

| ID | Risk | Mitigation/evidence |
|---|---|---|
| `RISK-001` | Proprietary camera protocols drift frequently | Exact tuple registry, official-app differential fixtures, shadow mode, automatic quarantine, standards-first priority |
| `RISK-002` | DJI Flip lacks a supportable low-latency SDK path | Recorded-file import first, capture bridge experiment, explicit unsupported outcome, no architecture dependence |
| `RISK-003` | Cheap cameras provide poor/unstable timestamps | Interval clocks, visual synchronization, drift monitors, association confidence reduction |
| `RISK-004` | Night/IR/weather imagery defeats ordinary detectors | Dedicated strata, open-vocabulary/temporal verification, sensor quality, optional complementary sensors |
| `RISK-005` | Cross-camera association creates privacy-invasive re-identification | Property/privacy domains, TTL embeddings, geometry/time gates, no global identities, denial tests |
| `RISK-006` | 3D reconstruction looks convincing but is metrically wrong | Certificates, scale anchors, covariance/residuals, held-out landmarks, fail/abstain states |
| `RISK-007` | Model cascade misses threats filtered by cheap stage | Candidate-recall gate, periodic sentinel sampling, ensemble/health checks, fixed miss accounting |
| `RISK-008` | Full-resolution continuous inference is economically impossible | Progressive cascade, hardware profiles, admitted-fraction accounting, load shedding |
| `RISK-009` | Pure-Rust codec/model scope is large and may delay capabilities | Focused profiles/operators, reference-first sequencing, foreign tools as lab oracles only, explicit unsupported matrices, no silent production fallback |
| `RISK-010` | Object store outage or pricing changes break operation | Local spool/safety path, provider abstraction, dated prices, bounded backlog and migration |
| `RISK-011` | Franken dependencies are not API-ready | Qualification gates, traits with in-memory/reference adapters, no semantic substitute architecture |
| `RISK-012` | Event labels are subjective/rare | Annotation graph, disagreement, staged corpus, deployment-level statistics, field feedback |
| `RISK-013` | Zero observed misses causes overconfidence | Confidence bounds, observability denominator, negative-evidence language, continued exposure |
| `RISK-014` | Alert provider ambiguity creates duplicates or missing alerts | Prepared effects, idempotency, provider receipts, reconciliation and indeterminate state |
| `RISK-015` | Calibration/privacy masks drift after physical movement | Online validity monitors, invalidation, conservative mask margins, operator alert |
| `RISK-016` | Camera vendor terms/accounts resist interoperability | Owner-authorized scope, no bypass of third-party access, lab isolation, supported standards alternatives |
| `RISK-017` | Local hardware heterogeneity makes performance claims brittle | Exact platform manifests, profile claims, CPU oracle, measured channel matrices |
| `RISK-018` | Search/memory feeds stale harmful assumptions into policy | Canonical truth separation, provenance/confidence/decay, explicit promotion, anti-pattern feedback |
| `RISK-019` | Support artifacts leak sensitive footage/secrets | Sanitized default, explicit export plan, automated scans, bundle manifest |
| `RISK-020` | Dataset leakage from neighboring frames/properties inflates metrics | Property/session splits, sealed holdout, corpus identity, threshold preregistration |

## 30.2 Operational and social risks

| ID | Risk | Mitigation/evidence |
|---|---|---|
| `RISK-021` | System normalizes excessive household/bystander surveillance | Local-first minimization, masks, short retention, no required biometrics, visible policy |
| `RISK-022` | Residents/guests do not understand collection | Deployment consent/onboarding materials and visible sensor/data inventory |
| `RISK-023` | False alarms create panic or dangerous escalation | Calibrated severity, evidence-rich alerts, operator confirmation policies, no autonomous confrontation |
| `RISK-024` | Missed event creates false sense of certainty | Coverage/not-observable states, health alerts, honest performance bounds, layered physical security |
| `RISK-025` | Evidence export is misleading after transforms | Transformation graph, source digests, redaction manifest, chain of custody |
| `RISK-026` | Cloud/remote model silently receives sensitive data | Explicit remote capability, transfer receipt, local default, sink-level privacy tests |
| `RISK-027` | Project is repurposed for oppressive tracking | Scope doctrine, no cross-property identity/default biometrics, capability design, documentation and licensing choices |
| `RISK-028` | Children/interior spaces receive disproportionate collection | P3 defaults, masks, audio off, narrow access/retention, consent profiles |
| `RISK-029` | Operator cannot maintain a complex system | One-shot CLI, doctor, generated status, safe defaults, standards-first onboarding, repair plans |
| `RISK-030` | Vendor account compromise propagates into trusted core | per-adapter secret/capability isolation, network zones, no vendor authority over core policy |

## 30.3 Research questions

| ID | Question | Initial experiment |
|---|---|---|
| `OPEN-001` | What is the cheapest cascade that preserves required observable-threat recall? | Pareto sweep over gating/detector/temporal stages on sealed development properties |
| `OPEN-002` | How much can camera auto-registration rely on an ordinary handheld/drone video route? | Known-rig indoor/outdoor capture with varied parallax, light, rolling shutter |
| `OPEN-003` | Which geometry representation best serves security reasoning: sparse map, Gaussian/NeRF-like field, point cloud, voxel, mesh, or hybrid? | Evaluate coverage/association/query tasks, not visual appearance alone |
| `OPEN-004` | Can visual clock synchronization remain reliable across cheap auto-exposure cameras? | Flash/moving target/natural event fixtures with clock truth and drift |
| `OPEN-005` | How should belief from correlated models/cameras be fused without double counting? | Dependency-aware evidence graph versus naïve Bayesian/logit fusion calibration |
| `OPEN-006` | What sentinel sampling rate catches activity-gate misses economically? | Inject subthreshold/camouflaged/slow-motion episodes and optimize recall-energy frontier |
| `OPEN-007` | Can anonymous household familiarity outperform face recognition for harmless-routine suppression? | Compare device/trajectory/routine continuity bundles under privacy constraints |
| `OPEN-008` | Which event representation generalizes across properties while supporting local customization? | Typed action/zone graph plus learned temporal encoder on property-held-out data |
| `OPEN-009` | How much value do ONVIF Profile M analytics add versus raw video inference? | Device matrix comparing metadata quality, latency, and disagreement |
| `OPEN-010` | Can source compressed-domain features reduce decode cost safely? | Motion vectors/bitstream metadata as candidate gate with recall guard |
| `OPEN-011` | What archive chunk size minimizes total request/recovery/deletion cost? | Provider-price simulation plus real incident retrieval traces |
| `OPEN-012` | Can RaptorQ protection economically improve long-retention incident evidence? | Failure/corruption model and repair benchmark over object/chunk groups |
| `OPEN-013` | How should confidence adapt under sensor loss without causing alert storms? | Sensor-ablation episodes with calibrated selective policy |
| `OPEN-014` | What exact DJI Flip capture path is supportable on current mobile/controller tuples? | Official SDK/product matrix plus authorized capture experiments |
| `OPEN-015` | How can model license restrictions be enforced mechanically in profiles/releases? | Manifest policy checker and packaging exclusion tests |
| `OPEN-016` | What is the minimum operator interaction for reliable privacy masks and scale anchors? | Guided onboarding usability study over representative properties |
| `OPEN-017` | Can event explanations be compact enough for agents without hiding contradictions? | Token-budget benchmark with answer/evidence correctness scoring |
| `OPEN-018` | Which parts of cross-camera association admit formal conservative bounds? | Interval time/geometry gates and finite hypothesis graph proofs |
| `OPEN-019` | How should field feedback decay or invert harmful household rules? | Eidetic-style confidence/trauma model evaluated on longitudinal false alerts |
| `OPEN-020` | What release evidence is strong enough to justify a “never miss” colloquial goal? | Translate exposure into explicit upper miss-probability bounds and prohibited wording |

## 30.4 Decision rule for open questions

An open question becomes an ADR only after:

- competing hypotheses and failure modes are written;
- a representative measurement or proof plan exists;
- privacy/security/license costs are included;
- result is retained even if negative;
- chosen design names conditions under which it should be revisited.

“Latest model looks best” is not a decision rule.

---

# Part IX — Deep Franken-substrate constitution

## 31. Closed pure-Rust dependency universe

FSS's dependency policy is architectural, not packaging hygiene. Every external crate or process can
introduce hidden threads, alternate cancellation, unbounded parsers, ambient configuration,
nondeterministic serialization, native code, build-time downloads, and security update channels.
The production universe is therefore closed and machine-checked.

The only default external exception candidates are Serde and Serde JSON for bounded control/report data-shape boilerplate. They do not define canonical bytes. Cryptography, hashing,
compression, TLS, SIMD, media, model, graph, UI, CLI, and platform capabilities first use admitted
first-party substrates; any direct exception requires a `DEP-*` record and ADR.

FSS crates always forbid unsafe. A needed unsafe/platform primitive can exist only in a separately
audited first-party substrate crate with a safe public contract and its own release evidence. A
required foreign service is still a foreign production runtime and is forbidden.

See [`DEPENDENCY_CONSTITUTION.md`](docs/DEPENDENCY_CONSTITUTION.md).

## 32. One version universe and semantic transactions

Every canonical change is an immutable ordered `EvidenceDeltaBatch`. Graph/search/model-result
caches, subscriptions, checkpoints, replicas, and speculative branches consume the same stream and
publish exact high-water marks. No query can silently combine “latest” rows from unrelated
versions.

Prepared event/effect/activation/deletion decisions carry positive and negative hierarchical
witnesses. A narrow deterministic combiner validates fences, semantic conflicts, object closure,
and policy epochs, then publishes the root. Expensive work never runs at the commit point.
Refinement may prove disjointness; running out of refinement budget creates a conservative conflict.

Branches apply hypothetical deltas over a pinned anchor. Merge means producing a candidate live
intent, never copying fabricated branch bytes into authority.

See [`docs/ONE_VERSION_UNIVERSE.md`](docs/ONE_VERSION_UNIVERSE.md) and
[`schemas/evidence_delta_batch.v1.json`](schemas/evidence_delta_batch.v1.json).

## 33. Pure-Rust media and streaming kernel

Packet truth, compressed stream parsing, containers, source custody, decoding, proxy generation,
and analysis transforms are first-party Rust. Source bytes and timing/discontinuity evidence are
preserved independently of live/analysis derivatives. Parsers, decoders, and encoders have separate
profile matrices and resource limits.

Performance comes from share-nothing stream workers, scatter/gather immutable spans, columnar
indexes, generation-leased pools, cache-shaped safe kernels, fused transforms, and registered
pressure degradation—not unsafe shortcuts or hidden native runtimes. Zero-copy is used only when
backing ownership/lifetime is proven and same-binary evidence shows the copy matters.

See [`docs/STREAMING_AND_MEDIA_KERNEL.md`](docs/STREAMING_AND_MEDIA_KERNEL.md).

## 34. Certified graph intelligence

Graph operations are part of the planning kernel. FSS registers exact semantics and witnesses for
connectivity, paths, temporal reachability, cuts/dominators, matching/flow, SCC/DAG planning,
coverage selection, active perception, attention, causal queries, factorized joins, wait cycles,
and deletion closure.

Every answer pins an authorized immutable projection and emits a decision/complexity witness.
Equal answers use canonical tie-breaks. Incremental standing predicates are checked against full
recomputation. Graph storage can migrate among temperature tiers, but the reference semantics remain
ordered safe-Rust structures.

See [`docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md`](docs/GRAPH_INTELLIGENCE_ARCHITECTURE.md) and
[`registries/GRAPH_ALGORITHMS.md`](registries/GRAPH_ALGORITHMS.md).

## 35. Pure-Rust model runtime

Open-weight models are imported offline into immutable canonical packages containing a frozen
first-party operator IR, tensor objects, preprocessing/postprocessing, numeric policy, licenses,
quality/conformance evidence, and repair metadata. Production executes through safe scalar/reference
and optimized CPU kernels; optional accelerators remain first-party and receipt-bearing.

A package can be rejected for unsupported operators. FSS does not interpret arbitrary framework
code or download model assets at runtime. Quantization, preprocessing, and accelerator changes are
new generations. Foreign frameworks are differential oracles only.

See [`PURE_RUST_MODEL_RUNTIME.md`](docs/PURE_RUST_MODEL_RUNTIME.md).

## 36. ATP archive, replication, repair, and deletion

ATP moves immutable object graphs with manifests, chunks, repair symbols, resumable journals,
post-repair digest verification, and root-last publication. Path racing/hedging is allowed under
hard privacy/integrity/cost clamps; losing paths drain.

“Archived” means required replicas and retrievability evidence exist. Repair uses immutable plan,
lease/fence, staged reconstruction, canonical digest, durable source publication, then parity
refresh. Deletion traverses the complete declared object/repair/replica/index/cache/journal graph and
publishes a tombstone root.

ATP never transports mutation authority. See
[`docs/ATP_ARCHIVE_AND_REPLICATION.md`](docs/ATP_ARCHIVE_AND_REPLICATION.md).

## 37. Decision cards, adaptive policy, and performance proof

Every adaptive choice is a `DecisionCard` naming feasible arms, hard clamps, objective/loss,
evidence/uncertainty, selected arm, tie-break, safe fallback, rollback, and outcome. New policies run
shadow-first. Missing/reset/uncertain adaptation uses the safe static arm.

Performance uses same-binary A/A and A/B experiments with identical input root, output digest,
compiler/host/profile, and receipt. Timing begins only after semantic equivalence. Failed
optimizations and misleading policies are durable negative evidence.

See [`docs/DECISION_CARDS_AND_EXPERIMENTS.md`](docs/DECISION_CARDS_AND_EXPERIMENTS.md).

## 38. Local DSR qualification and release authority

The release begins from a clean snapshot with exact sibling revisions, accepted nightly, locked
offline closure, and controlled native host lanes. `scripts/qualify.sh` is the repository semantic
entrypoint; workflows call it and contain no unique authority.

Partial target artifacts can survive resume but are never blessed. The signed release manifest is
published only after every required target/lane and cross-target invariant passes. Exact assets,
checksums, signatures, SBOM, provenance, source/dependency and qualification manifests are uploaded,
then downloaded and reverified. Signing authority is separate from builders.

The project requires no GitHub-hosted runner. See
[`LOCAL_QUALIFICATION_AND_RELEASE.md`](docs/LOCAL_QUALIFICATION_AND_RELEASE.md) and
[`docs/deep-dives/DOODLESTEIN_SELF_RELEASER.md`](docs/deep-dives/DOODLESTEIN_SELF_RELEASER.md).

---

# Appendices

## Appendix A — Initial canonical data model

This is a conceptual schema, not a promise of exact SQL spelling. Durable IDs are content- or
generation-aware newtypes. Large bytes live in objects; the ledger stores their identities and
state transitions.

### A.1 Deployment and principals

```text
deployments(
  deployment_id, stable_name, created_at, active_policy_generation,
  active_privacy_generation, active_retention_generation, status
)

principals(
  principal_id, kind, display_name, auth_generation, status, created_at
)

capability_grants(
  grant_id, principal_id, capability_kind, resource_scope, constraints,
  issued_at, expires_at, revoked_at, issuer_id, grant_digest
)

leases(
  lease_id, resource_id, owner_principal_id, epoch, fence, acquired_at,
  expires_at, released_at, terminal_reason
)
```

### A.2 Devices, adapters, and sessions

```text
devices(
  device_id, deployment_id, manufacturer, model, hardware_revision,
  serial_hash, privacy_domain, location_label, status
)

device_generations(
  device_generation_id, device_id, firmware, app_or_sdk_tuple,
  region_account_class, capability_digest, first_seen, last_seen
)

adapter_generations(
  adapter_generation_id, adapter_kind, source_commit, artifact_digest,
  protocol_schema_version, qualification_bundle_id, status
)

adapter_sessions(
  session_id, device_generation_id, adapter_generation_id, started_at,
  ended_at, outcome, clock_model_id, trace_id
)
```

### A.3 Time and sensor capsules

```text
clock_models(
  clock_model_id, source_clock, reference_clock, offset_interval,
  skew_interval, evidence_root, valid_from, valid_to, status
)

sensor_capsules(
  capsule_id, device_generation_id, adapter_session_id, sequence,
  source_time_interval, reference_time_interval, media_descriptor,
  source_object_digest, acquisition_evidence_root, discontinuity_flags,
  privacy_class, committed_at
)

renditions(
  rendition_id, parent_capsule_id, parent_object_digest, transform_generation,
  output_object_digest, media_descriptor, privacy_transform_id,
  source_time_interval, committed_at
)
```

### A.4 Models and results

```text
model_generations(
  model_generation_id, model_class, manifest_digest, source_revision,
  weights_root, license_class, runtime_tuple, input_schema, output_schema,
  qualification_bundle_id, status
)

model_jobs(
  model_job_id, plan_digest, model_generation_id, input_root,
  budget, admitted_at, started_at, completed_at, outcome, cost_receipt
)

model_results(
  model_result_id, model_job_id, input_root, output_schema_version,
  result_object_digest, summary, uncertainty, published_at
)
```

### A.5 Calibration, geometry, and coverage

```text
calibration_generations(
  calibration_generation_id, deployment_id, evidence_root, method_generation,
  coordinate_frame_root, parameter_object_digest, covariance_object_digest,
  residual_summary, valid_from, invalidated_at, invalidation_reason,
  qualification_bundle_id
)

sensor_poses(
  calibration_generation_id, device_generation_id, transform,
  covariance, intrinsics_id, validity_region
)

digital_twin_generations(
  twin_generation_id, deployment_id, parent_generation_id, evidence_root,
  representation_kind, geometry_object_root, scale_anchor_root,
  uncertainty_summary, status
)

coverage_generations(
  coverage_generation_id, twin_generation_id, calibration_generation_id,
  policy_generation_id, coverage_object_root, blind_spot_summary,
  validated_evidence_root, status
)
```

### A.6 Tracks, events, policy, and feedback

```text
track_revisions(
  track_revision_id, track_id, prior_revision_id, device_generation_id,
  time_interval, geometry_support, appearance_handle, class_belief,
  evidence_root, terminal_state
)

association_revisions(
  association_revision_id, association_id, prior_revision_id,
  member_track_revisions, privacy_domain, time_geometry_evidence,
  appearance_evidence, belief_interval, contradictions, status
)

event_revisions(
  event_revision_id, event_id, prior_revision_id, event_kind,
  time_interval, world_region, actor_object_roles, evidence_graph_root,
  threat_belief, harmless_belief, observability, policy_generation_id,
  decision_state, explanation_root, created_at
)

adjudications(
  adjudication_id, event_revision_id, principal_id, label, confidence,
  reason, evidence_additions, created_at
)

policy_memories(
  memory_id, deployment_id, kind, content_digest, evidence_root,
  confidence, maturity, helpful_count, harmful_count, supersedes,
  valid_from, retired_at
)
```

### A.7 Effects, alerts, archives, privacy, and proof

```text
prepared_effects(
  prepared_effect_id, effect_kind, principal_id, grant_id, anchor,
  intent_digest, precondition_digest, idempotency_key, budget,
  prepared_at, expires_at, state
)

effect_receipts(
  receipt_id, prepared_effect_id, attempt, provider_generation,
  request_digest, response_digest, observed_ack, reconciliation_evidence,
  state, created_at
)

archive_manifests(
  archive_manifest_id, object_root, retention_class, encryption_context_id,
  provider_generation, staged_at, published_at, status
)

retention_obligations(
  obligation_id, object_or_graph_root, policy_generation_id, action,
  due_at, hold_set, state, receipt_root
)

deletion_plans(
  deletion_plan_id, requested_scope, graph_root, blocked_nodes,
  expected_guarantees, prepared_by, prepared_at, expires_at, state
)

privacy_transforms(
  privacy_transform_id, policy_generation_id, kind, input_scope,
  transform_parameters_digest, calibration_generation_id, status
)

proof_bundles(
  proof_bundle_id, claim_id, implementation_commit, corpus_root,
  platform_matrix_root, command_root, artifact_root, metric_root,
  negative_evidence_root, generated_at, expires_at, status
)
```

All mutation tables retain append-only history or explicit supersession. Physical compaction may
occur only after preserving the logical audit contract.

---

## Appendix B — End-to-end event trace

This example illustrates semantic stages without claiming implementation.

1. Camera `rear_yard` negotiates a qualified Profile T stream under adapter generation `A17`.
2. Adapter session `S42` publishes packet evidence with source-clock uncertainty.
3. Media kernel validates and commits sensor capsule `C1001`; low-resolution rendition `R77` is
   linked to exact source bytes.
4. Activity gate observes slow low-contrast motion and admits sentinel frames despite weak ordinary
   motion score.
5. Detector produces a low-confidence person/crawling candidate; tracker creates track revision
   `T8.1` with occlusion evidence.
6. Time/calibration authority projects the trajectory near a rear boundary with uncertainty.
7. A second camera observes a compatible trajectory after the expected travel interval.
8. Association engine proposes anonymous continuity `X3.1`, retaining an alternate “two actors”
   hypothesis.
9. Temporal verifier finds crawling plus fence interaction; household familiarity evidence is
   absent; weather/animal hypotheses lose support but are not deleted.
10. Event revision `E9.1` is `Candidate`, threat interval `[0.55, 0.78]`, observability
    `PartiallyObservable` because one camera is rain-obscured.
11. Policy requests a higher-resolution crop and additional frames, not an alert yet.
12. New evidence shows hand interaction with a locked gate and a face-obscuring hood; sensor-health
    model confirms the dark region is not camera failure.
13. Event `E9.2` reaches the predeclared high-severity operating point, with contradictions and
    missing identity explicit.
14. Alert coordinator prepares intent `P5` bound to `E9.2`, policy/calibration/model generations,
    recipient channels, redacted evidence, idempotency key, and expiry.
15. Capability check and current-anchor revalidation pass; the effect commits.
16. Push provider times out after request transmission. The receipt is `Indeterminate`, not failed.
17. Callback/reconciliation later proves provider message identity; receipt becomes
    `VerifiedDelivered` without a duplicate send.
18. Operator marks the event a staged test. An append-only adjudication lowers future local policy
    confidence for that exact pattern only after an explicit memory-promotion review.
19. Source/evidence objects follow test-retention policy; no-event derived artifacts are deleted
    through closure.
20. The complete trace replays with exact generations and explains each escalation and cost.

---

## Appendix C — Drone-assisted calibration workflow

1. Operator creates `calibration mission prepare` with property privacy boundaries, sensors,
   intended route classes, and recording policy.
2. FSS verifies cameras are healthy, storage is available, masks/consent are configured, and no
   active incident conflicts.
3. Operator manually flies DJI Flip or another capture device. FSS may display visual guidance but
   sends no flight-control commands.
4. Fixed cameras and drone/handheld capture produce synchronized evidence with clock intervals.
5. Registration pipeline detects the moving calibration target/device where visible and extracts
   scene correspondences.
6. Geometry backends propose trajectory, sparse/dense scene, intrinsics, and fixed-camera poses.
7. Scale/orientation anchors come from known measurements, telemetry where trustworthy, or manual
   landmarks.
8. Solver produces residuals, covariance/uncertainty, disconnected components, and failure flags.
9. Held-out observations test reprojection and coverage predictions.
10. Privacy masks are reprojected with uncertainty margins and reviewed.
11. `calibration certificate prepare` packages methods, exact model generations, evidence root,
    parameters, residuals, supported regions, and invalidators.
12. Operator commits the certificate. Readers atomically switch to the new generation; prior
    generation remains available for rollback.
13. Online monitors compare future cross-camera tracks and static landmarks. Movement/zoom/focus,
    temperature, firmware, or residual drift can invalidate only affected sensors or the complete
    certificate.
14. Invalid calibration removes metric-world claims and remote/export permissions dependent on
    exact masks; 2D local detection may continue in an explicit degraded mode.

---

## Appendix D — Example agent interaction

```text
agent: fss observe attention --deployment home --budget-tokens 900 --json
fss:   anchor=A19; two items:
       1. rear-yard camera image usefulness degraded by rain droplets
       2. event E9.2 high severity, alert delivery indeterminate

agent: fss event explain E9.2 --anchor A19 --include contradictions --json
fss:   returns evidence graph summary, model/policy generations, uncertainty,
       redacted crop handles, and suggested query for provider reconciliation

agent: fss alert status --event E9.2 --json
fss:   prepared effect P5; one provider attempt; request transmitted;
       callback absent; state=Indeterminate; safe next action=reconcile, not resend

agent: fss alert reconcile-plan P5 --json
fss:   sealed read/provider-query plan Q2; cost and expiry; requires AlertReconcile grant

agent: fss alert reconcile-commit Q2 --json
fss:   provider message ID verified; receipt=VerifiedDelivered; no new notification sent

agent: fss repair plan camera:rear-yard --reason image_usefulness --json
fss:   proposes lens inspection checklist and temporary coverage degradation;
       no remote camera mutation; includes blind-region consequences
```

The agent never receives raw credentials, arbitrary SQL, generic vendor methods, or drone flight
authority. It operates over semantic resources and prepared effects.

---

## Appendix E — Operation-cost examples

### E.1 Live preview

```text
cost.live_preview =
  packets_read
+ optional_decode_pixels
+ optional_encode_pixels
+ bytes_to_client
+ retained_buffer_bytes
+ deadline_and_queue_reservation
```

A client requesting 4K/30 when policy allows 720p/5 receives a bounded refusal or negotiated plan,
not silent server overload.

### E.2 Event verification

```text
cost.verify_event =
  capsule_fetch_bytes
+ decoded_pixels
+ detector_invocations
+ tracker_steps
+ association_edges_considered
+ temporal_model_tokens_or_frames
+ geometry_queries
+ evidence_objects_written
```

Each stage has a ceiling. Escalation explains which uncertainty it expects to reduce.

### E.3 Archive

```text
cost.archive_month =
  retained_gb_month * dated_storage_rate
+ class_a_operations * dated_class_a_rate
+ class_b_operations * dated_class_b_rate
+ retrieval_gb * dated_egress_rate
+ local_transcode_joules * energy_rate
```

Provider request names differ; the pricing manifest maps them to FSS cost classes and validity
date.

### E.4 Calibration

```text
cost.calibration =
  capture_minutes
+ decode_pixels
+ feature/correspondence work
+ reconstruction iterations
+ geometry_bytes
+ held_out_validation
+ operator_review_minutes
```

A plan can select fast sparse calibration before optional dense reconstruction.

---

## Appendix F — First 200 implementation issues

These issue titles are deliberately granular enough to seed Beads/GitHub tracking. The second hundred operationalizes the deeper Franken imports, pure-Rust media/model kernels, one-version universe, certified graph layer, ATP, and local DSR release doctrine. Dependencies follow the work-package graph.

1. `FSS-001` Freeze stable ID and generation newtypes.
2. `FSS-002` Implement canonical digest parsing/formatting.
3. `FSS-003` Implement conservative time-interval arithmetic.
4. `FSS-004` Define four-valued operation outcomes and stable errors.
5. `FSS-005` Define source/device/adapter identity schemas.
6. `FSS-006` Define sensor capsule v1 binary/JSON contract.
7. `FSS-007` Define event revision and evidence graph schemas.
8. `FSS-008` Define prepared-effect/receipt schemas.
9. `FSS-009` Implement architecture/registry consistency checker.
10. `FSS-010` Implement dependency DAG checker.
11. `FSS-011` Implement claim/proof-bundle checker.
12. `FSS-012` Add negative-evidence ledger schema and CLI.
13. `FSS-013` Build deterministic virtual clock/source.
14. `FSS-014` Build virtual encoded-camera fixture generator.
15. `FSS-015` Build packet loss/reorder/duplication fault injector.
16. `FSS-016` Implement in-memory canonical ledger oracle.
17. `FSS-017` Implement content-addressed staging spool.
18. `FSS-018` Implement root-last local manifest publication.
19. `FSS-019` Implement replay bundle v1 reader/writer.
20. `FSS-020` Implement deterministic mock model executor.
21. `FSS-021` Integrate Asupersync `Cx` and region hierarchy.
22. `FSS-022` Implement typed budgets and pressure propagation.
23. `FSS-023` Implement obligation registry and leak oracle.
24. `FSS-024` Implement sealed laboratory-oracle process ownership, drain, taint, and production-absence proof harness.
25. `FSS-025` Implement capability grants and resource scopes.
26. `FSS-026` Implement leases, epochs, and fencing.
27. `FSS-027` Implement two-phase effect coordinator.
28. `FSS-028` Model effect idempotency in TLA+.
29. `FSS-029` Model root-last publication in TLA+.
30. `FSS-030` Create crash/cancellation cut-point harness.
31. `FSS-031` Define FrankenSQLite storage integration trait.
32. `FSS-032` Qualify required FrankenSQLite APIs.
33. `FSS-033` Implement ledger schema/migrations.
34. `FSS-034` Implement derived-index rebuild cursor.
35. `FSS-035` Implement backup/restore manifest.
36. `FSS-036` Implement retention/hold obligation tables.
37. `FSS-037` Implement deletion reachability planner.
38. `FSS-038` Implement UVC device enumeration.
39. `FSS-039` Implement UVC mode negotiation.
40. `FSS-040` Implement UVC capture session lifecycle.
41. `FSS-041` Prove audio-disabled UVC path produces no artifacts.
42. `FSS-042` Build UVC unplug/replug soak suite.
43. `FSS-043` Implement scoped ONVIF discovery.
44. `FSS-044` Implement ONVIF capability negotiation.
45. `FSS-045` Implement Profile T media configuration.
46. `FSS-046` Implement Profile M analytics metadata ingestion.
47. `FSS-047` Implement RTSP authentication/session state.
48. `FSS-048` Implement RTP/RTCP sequence/timing evidence.
49. `FSS-049` Implement transport fallback and reconnect.
50. `FSS-050` Implement PTZ prepare/commit with leases.
51. `FSS-051` Build ONVIF/RTSP protocol fixture corpus.
52. `FSS-052` Define pure-Rust media kernel contracts and limits.
53. `FSS-053` Implement bounded pure-Rust media probe engine.
54. `FSS-054` Implement bounded pure-Rust decode engine with scalar reference semantics.
55. `FSS-055` Implement bounded pure-Rust encode/rendition kernels.
56. `FSS-056` Implement keyframe-aware chunker.
57. `FSS-057` Implement live preview bounded fan-out.
58. `FSS-058` Implement decoded-frame/tensor buffer accounting.
59. `FSS-059` Build malformed media gauntlet.
60. `FSS-060` Build decode/timestamp differential oracle.
61. `FSS-061` Define object-store provider trait.
62. `FSS-062` Implement local object-store oracle.
63. `FSS-063` Implement Asupersync-owned S3-compatible staged uploader.
64. `FSS-064` Implement multipart idempotency/reconciliation.
65. `FSS-065` Implement encryption-context manifest.
66. `FSS-066` Implement dated provider-pricing manifest.
67. `FSS-067` Implement archive cost/chunk planner.
68. `FSS-068` Implement incident retrieval/verification.
69. `FSS-069` Run remote archive restore/fault matrix.
70. `FSS-070` Define immutable model manifest v1.
71. `FSS-071` Implement offline model-package import, staging, and verifier.
72. `FSS-072` Implement pure-Rust model invocation/receipt protocol.
73. `FSS-073` Implement model invocation quotas and memory-pressure handling.
74. `FSS-074` Implement qualification/shadow/activation/rollback.
75. `FSS-075` Add model license/profile policy checker.
76. `FSS-076` Integrate first detector/segmenter candidate.
77. `FSS-077` Integrate first tracker candidate.
78. `FSS-078` Implement deterministic activity/sentinel gate.
79. `FSS-079` Implement open-vocabulary verification lane.
80. `FSS-080` Build perception held-out evaluation harness.
81. `FSS-081` Implement event evidence graph/revision store.
82. `FSS-082` Implement belief interval and contradiction types.
83. `FSS-083` Implement temporal verifier orchestration.
84. `FSS-084` Implement policy abstention/escalation states.
85. `FSS-085` Implement prepared alert and provider adapter.
86. `FSS-086` Build lost-ACK/duplicate-alert reconciliation suite.
87. `FSS-087` Implement operator adjudication and immutable feedback.
88. `FSS-088` Implement clock offset/skew estimator interface.
89. `FSS-089` Implement intrinsics/distortion certificate.
90. `FSS-090` Implement cross-camera extrinsics solver interface.
91. `FSS-091` Implement calibration invalidators and rollback.
92. `FSS-092` Implement privacy-mask reprojection with margins.
93. `FSS-093` Define drone/manual capture mission manifest.
94. `FSS-094` Implement recorded DJI media/telemetry importer.
95. `FSS-095` Evaluate authorized DJI Flip live capture routes.
96. `FSS-096` Integrate first reconstruction backend in lab.
97. `FSS-097` Implement sensor localization into digital twin.
98. `FSS-098` Implement visibility/coverage map and validation.
99. `FSS-099` Implement geometry/time-gated cross-camera association.
100. `FSS-100` Build sealed event-level threat/hard-negative release gauntlet.
101. `FSS-101` Freeze `EvidenceDeltaBatch` v1 canonical ordering and anchor semantics.
102. `FSS-102` Implement single-thread reference delta ledger and replay cursor.
103. `FSS-103` Implement positive, negative, and hierarchical witness types.
104. `FSS-104` Implement deterministic commit combiner and semantic conflict oracle.
105. `FSS-105` Implement intent-replay/structural/commutative merge certificate ladder.
106. `FSS-106` Build negative-read phantom and SSI write-skew schedule corpus.
107. `FSS-107` Implement derived high-water protocol for graph/search/model caches.
108. `FSS-108` Implement counterfactual branch overlay and live-intent recompilation.
109. `FSS-109` Implement canonical durable-format framework with magic/limits/checksums.
110. `FSS-110` Enforce no Serde-derived canonical durable bytes.
111. `FSS-111` Implement RTSP parser/session state machine in safe Rust.
112. `FSS-112` Implement RTP/RTCP sequence, wrap, jitter, loss, and sender-report model.
113. `FSS-113` Implement bounded H.264 access-unit/SPS/PPS parser.
114. `FSS-114` Implement bounded H.265 access-unit/VPS/SPS/PPS parser.
115. `FSS-115` Implement deterministic fragmented MP4/CMAF writer and reader.
116. `FSS-116` Implement canonical packet replay object format.
117. `FSS-117` Implement safe JPEG/MJPEG reference decoder vertical slice.
118. `FSS-118` Build FFmpeg/ffprobe lab-only media differential runner.
119. `FSS-119` Implement generation-leased immutable frame pools.
120. `FSS-120` Prove source-to-tensor span/transform lineage.
121. `FSS-121` Implement registered media pressure degradation ladder.
122. `FSS-122` Implement scalar image resize/color/normalize reference kernels.
123. `FSS-123` Implement safe SIMD image transform candidates with same-binary gates.
124. `FSS-124` Implement first admitted H.264 profile decoder subset.
125. `FSS-125` Add malformed compressed-stream adversarial corpus and minimizer.
126. `FSS-126` Implement ATP transfer receipt and resumable journal v1.
127. `FSS-127` Implement ATP object-graph closure verifier.
128. `FSS-128` Implement RaptorQ post-repair canonical digest gate.
129. `FSS-129` Implement multipath transfer race and loser-drain protocol.
130. `FSS-130` Implement focused safe-Rust S3-compatible multipart/conditional protocol.
131. `FSS-131` Implement archive replication-state and retrievability challenge ledger.
132. `FSS-132` Build remote eventual-consistency/partial-list provider simulator.
133. `FSS-133` Implement graph-complete archive deletion traversal.
134. `FSS-134` Implement archive Decision Cards for path, repair, and object sizing.
135. `FSS-135` Prove independent reconstruction of archive roots from manifests.
136. `FSS-136` Implement tensor dtype/shape/stride/storage/view/version core.
137. `FSS-137` Define frozen first-party model operator IR v1.
138. `FSS-138` Implement deterministic model package importer and canonical tensors.
139. `FSS-139` Implement scalar operator executor for first detector graph.
140. `FSS-140` Implement shape/layout/liveness scratch planner.
141. `FSS-141` Implement static kernel dispatch and decision-path receipts.
142. `FSS-142` Implement packed-weight and tiled CPU matrix kernels in safe Rust.
143. `FSS-143` Implement model preprocess/postprocess fusion laws and reference tests.
144. `FSS-144` Build PyTorch/ONNX lab-only operator/model differential harness.
145. `FSS-145` Classify model oracle results as agree/diverge/error-only/unexercised.
146. `FSS-146` Implement quantized model generation and calibration receipts.
147. `FSS-147` Add model package RaptorQ protection and ATP activation.
148. `FSS-148` Implement shadow/canary/rollback Decision Cards for model generations.
149. `FSS-149` Prove production release closure contains no foreign model runtime.
150. `FSS-150` Implement CPU thermal/pressure-aware model scheduler with hard floors.
151. `FSS-151` Define immutable graph projection and generational-handle core.
152. `FSS-152` Implement O(1) Arc-shared graph snapshot views and invalidation tests.
153. `FSS-153` Implement canonical graph serialization and hash verification.
154. `FSS-154` Implement dynamic connectivity reference/optimized lanes.
155. `FSS-155` Implement articulation, bridge, dominator, and cut-analysis family.
156. `FSS-156` Implement shortest/k-shortest/temporal path family.
157. `FSS-157` Implement matching, k-best assignment, and min-cost-flow association.
158. `FSS-158` Implement max-flow and Gomory-Hu failure-analysis family.
159. `FSS-159` Implement SCC/condensation/topological/critical-path family.
160. `FSS-160` Implement set-cover/submodular active-perception family.
161. `FSS-161` Implement d-separation/shared-failure-domain analysis.
162. `FSS-162` Implement factorized graph-relational query reference planner.
163. `FSS-163` Implement incremental retract/add standing predicates.
164. `FSS-164` Build full-recompute versus incremental graph equivalence fuzzer.
165. `FSS-165` Implement graph algorithm complexity/output witness v1.
166. `FSS-166` Build adversarial graph-family generator and NetworkX oracle runner.
167. `FSS-167` Enforce capability projection before graph/search expansion.
168. `FSS-168` Implement offline Forge-style safe-Rust specialization proof path.
169. `FSS-169` Implement Quill absolute doc-range/searchable-delta reference slice.
170. `FSS-170` Implement search absence/coverage certificates.
171. `FSS-171` Implement typed operational memory rows and evidence edges.
172. `FSS-172` Implement memory confidence decay, trauma guard, and anti-pattern inversion.
173. `FSS-173` Implement immutable curation/supersession/retirement/revival transitions.
174. `FSS-174` Implement deterministic context pack with score ledger and pack hash.
175. `FSS-175` Prove memory text cannot grant capabilities or rewrite policy.
176. `FSS-176` Define MCP/CLI/library operation registry crosswalk.
177. `FSS-177` Implement request-owned MCP regions and bounded outputs.
178. `FSS-178` Implement durable application-owned task projection over MCP.
179. `FSS-179` Implement protocol taint/secret/redaction conformance suite.
180. `FSS-180` Prohibit generic shell/SQL/vendor/codec/model/drone MCP escape hatches.
181. `FSS-181` Implement dependency-closure scanner against allowlist v2.
182. `FSS-182` Enforce FSS unsafe prohibition across targets/features/examples/tests.
183. `FSS-183` Enforce no network access in build scripts and sealed qualification.
184. `FSS-184` Implement candidate-latest-nightly probe and promotion report.
185. `FSS-185` Implement DSR clean-snapshot and exact sibling-closure manifest.
186. `FSS-186` Implement disk-backed host capacity and quarantine checks.
187. `FSS-187` Implement local qualification lane receipt schema and aggregator.
188. `FSS-188` Implement interrupted target-matrix resume without partial blessing.
189. `FSS-189` Implement exact release asset enumeration and extra-file refusal.
190. `FSS-190` Implement SBOM/provenance/source/license/qualification cross-check.
191. `FSS-191` Separate build and minisign/Ed25519 signing authorities.
192. `FSS-192` Implement upload then download-and-verify release publication.
193. `FSS-193` Convert workflow YAML to repository-script-only portable specifications.
194. `FSS-194` Test complete qualification/release with GitHub-hosted runners unavailable.
195. `FSS-195` Implement public claim scope/evidence/exclusion/expiry evaluator.
196. `FSS-196` Implement same-binary A/A and A/B experiment receipt framework.
197. `FSS-197` Implement Decision Card hard-clamp/shadow/fallback/rollback property tests.
198. `FSS-198` Expand operation cost registry to all hot and consequential paths.
199. `FSS-199` Build integrated one-version media→model→graph→event→ATP replay scenario.
200. `FSS-200` Run the first full local DSR release rehearsal and retain negative evidence.

The next tranche begins with search/graph/memory, full CLI/MCP/UI, proprietary adapter candidates,
privacy deletion/export completion, installers, proof bundles, and GATE-120 operations.

---

# Closing statement

FSS is not fundamentally a camera aggregator and not fundamentally a vision model. It is a
semantic evidence system for a partially observed physical world. Its value comes from preserving
identity, time, uncertainty, provenance, ownership, cost, privacy, and effect state across every
boundary—from a cheap consumer camera packet to an operator-visible security decision.

The intended leapfrog is the composition:

```text
inexpensive heterogeneous sensors
+ conservative time and geometry
+ immutable source custody
+ progressive open-weight cognition
+ event-level evidence graphs
+ household-specific but auditable learning
+ capability-scoped effects
+ deterministic replay and adversarial qualification
+ honest economic and privacy accounting
= a trustworthy fused security mesh
```

Anything less may make an attractive demo. This plan is designed to make a system that can survive
long-horizon agents, hostile inputs, firmware drift, model churn, false-alarm pressure, crashes,
and the responsibility of observing a real home.
