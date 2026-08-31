<div align="center">

# Franken Surveillance System (`fss`)

**An evidence-native, local-first, agent-operable sensor mesh for owner-authorized cameras and drones.**

*Cheap consumer hardware. Explicit uncertainty. Cross-camera geometry. Open-weight cognition. Crash-safe evidence. No ambient authority.*

![Status](https://img.shields.io/badge/status-architecture%20constitution-yellow)
![Rust](https://img.shields.io/badge/Rust-nightly%202026--08--30-orange)
![Unsafe](https://img.shields.io/badge/core%20unsafe-forbidden-brightgreen)
![Runtime](https://img.shields.io/badge/runtime-Asupersync-blueviolet)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

> [!IMPORTANT]
> This repository currently contains the **normative architecture, registries, schemas, and a
> dependency-free Rust contract skeleton**. It does not yet acquire camera feeds, control a drone,
> run models, upload archives, or deliver security alerts. The distinction is intentional and
> machine-readable in [`IMPLEMENTATION_STATUS.md`](IMPLEMENTATION_STATUS.md).

## The thesis

Consumer security hardware is cheap and increasingly capable, but each product is an island. A
battery camera may expose only a proprietary mobile app. A USB gimbal camera may be standards-compliant but physically tethered. A drone may provide an excellent moving viewpoint while its
vendor SDK excludes that exact model. Existing NVRs can record streams, but they generally do not
create a calibrated, provenance-carrying world model that an autonomous agent can query safely.

FSS aims to turn this pile of mismatched devices into one coherent system:

```text
owner-authorized cameras, microphones, and drone footage
                         │
              bounded adapter processes
                         │
     original packets + time uncertainty + health receipts
                         │
        ┌────────────────┴────────────────┐
        │                                 │
 low-latency operator path       immutable evidence path
 WebRTC/CMAF proxy               content-addressed objects
        │                                 │
        └──────────────┬──────────────────┘
                       │
       calibrated tracks + 3D scene + coverage model
                       │
    fast detector → tracker → cross-camera association
         → temporal VLM → independent verifier
                       │
       event hypothesis with calibrated uncertainty
                       │
       versioned policy, corroboration, and abstention
                       │
        human/agent alert with replayable evidence
```

The radical part is not “use a VLM on camera footage.” It is the substrate beneath that VLM:

- **Three planes:** authoritative observation, derived cognition, and consequential effects are
  type-distinct. A model output is never silently promoted to fact or authority.
- **One evidence universe:** original encoded media, packet continuity, clock uncertainty,
  transforms, tracks, model receipts, policies, and alerts share stable content identities.
- **Honest state machines:** “login worked,” “adapter accepted,” “first frame arrived,” “stream is
  continuous,” “intruder hypothesized,” “event corroborated,” and “alert delivered” are different
  states.
- **Digital-twin calibration:** a manually piloted drone can act as a calibration shuttle carrying
  a known visual/temporal marker, giving the fixed cameras and the drone reconstruction shared
  observations for joint bundle adjustment.
- **Event-level epistemology:** quality is measured under realistic class imbalance using event
  AUPRC, recall at a false-alert budget, time-to-detect, calibration, abstention, and miss upper
  bounds—not frame accuracy or one successful demo.
- **Proof-carrying operations:** archives publish root-last, effects use prepare/commit/observe/
  verify, adapter compatibility is exact to device/firmware/app generations, and public claims are
  generated from retained qualification artifacts.
- **Agent-native access:** compact hash-anchored deltas, bounded evidence views, explanations,
  read-first MCP tools, explicit capabilities, idempotency, budgets, and cancellation-safe work.

## What “Franken” means here

FSS is designed as a composition of the strongest mechanisms in the surrounding Franken stack,
not as a collection of logos or mandatory coupling:

| Project | Load-bearing import into FSS |
|---|---|
| [`asupersync`](https://github.com/Dicklesworthstone/asupersync) | `Cx` authority, region ownership, request→drain→finalize cancellation, four-valued outcomes, obligations, deterministic scheduling, ATP |
| [`frankensqlite`](https://github.com/Dicklesworthstone/frankensqlite) | canonical transactional ledger, MVCC snapshots, crash recovery, typed readiness claims |
| [`frankenfs`](https://github.com/Dicklesworthstone/frankenfs) | staged/root-last publication, content custody, repair evidence, fault-injected I/O |
| [`frankensearch`](https://github.com/Dicklesworthstone/frankensearch) | progressive hybrid retrieval, immutable model identity, derived indexes, explanations, pinned-oracle gauntlets |
| [`franken_markdown`](https://github.com/Dicklesworthstone/franken_markdown) | deterministic evidence reports, exact source spans, taint, staged multi-output rendering |
| [`frankengraphdb`](https://github.com/Dicklesworthstone/frankengraphdb) | one version universe, typed claims, operation-cost registry, graph certificates, no substitute architecture doctrine |
| [`dwarf_fortress_mcp`](https://github.com/Dicklesworthstone/dwarf_fortress_mcp) | semantic control plane for a partially observed world, observation anchors, delayed-effect truth, registries, agent token economy |
| [`fastmcp_rust`](https://github.com/Dicklesworthstone/fastmcp_rust) | capability-scoped tools, budgets, request-owned children, explicit qualification boundaries |
| [`eidetic_engine_cli`](https://github.com/Dicklesworthstone/eidetic_engine_cli) | provenance-bearing memory for false alarms, misses, drift, operator feedback, anti-patterns, and deterministic context packs |

The exact imports, integration gates, and non-imports are documented in
[`FRANKENSTACK_DEEP_DIVE.md`](FRANKENSTACK_DEEP_DIVE.md).

## Device posture

FSS deliberately starts from standards and replay before proprietary adapters:

| Tier | Surface | Initial examples | Policy |
|---|---|---|---|
| 0 | Deterministic replay | synthetic packet/frame/event fixtures | First implementation and oracle |
| 1 | Open local standards | UVC/UAC, RTSP, ONVIF Profile T; Profile M metadata | Preferred production path |
| 2 | Documented vendor API | products with supported local/cloud SDKs | Version-pinned and sandboxed |
| 3 | Authorized interoperability lab | Wyze Cam v4, AOSU P1 Max, DJI Flip capture bridge | Owner devices/accounts only; no auth bypass; compatibility is firmware-specific |
| 4 | Import-only | SD-card/exported clips when live access is unavailable | Useful but not represented as live coverage |

Three motivating products illustrate why this tiering matters:

- **Insta360 Link** is a USB UVC/UAC webcam rather than a Wi-Fi security camera, so it is a useful
  standards-based reference sensor.
- **Wyze Cam v4** and **AOSU P1 Max** advertise app, local-storage, and/or cloud workflows but do not
  publish an ONVIF/RTSP contract in their product documentation. They therefore begin in the
  interoperability lab, not in the README’s list of working integrations.
- **DJI Flip** provides live view through DJI Fly, but it is absent from the current Mobile SDK
  supported-product list. FSS treats it as a manually piloted calibration/capture experiment until
  an exact supported interface is qualified.

See [`DEVICE_ADAPTER_MATRIX.md`](DEVICE_ADAPTER_MATRIX.md) for the evidence and readiness matrix.

## Architecture in one page

FSS separates three planes and five trust domains.

### Three semantic planes

1. **Authority plane** — sensor identities, credentials references, policies, original media
   identities, clock bounds, receipts, manifests, redaction state, and immutable event revisions.
2. **Cognition plane** — decoded frames, detections, tracks, embeddings, geometry, hypotheses,
   rankings, memories, and explanations. Everything here is derived and rebuildable.
3. **Effect plane** — alerts, PTZ, exports, retention changes, archive deletion, camera settings,
   and calibration-capture plans. Effects require explicit capabilities and receipts.

### Five trust domains

1. **Pure safe-Rust semantic core.** No network, filesystem, clock, model runtime, codec, or secret
   access without an explicit capability.
2. **Franken substrate.** Asupersync and qualified Franken storage/search/graph components.
3. **Media boundary.** Pinned FFmpeg or equivalent subprocesses, sandboxed and supervised; never
   linked into the semantic trust root.
4. **Model boundary.** Version-pinned model hosts with immutable weights, schemas, resource
   envelopes, license metadata, and input/output receipts.
5. **Vendor boundary.** The smallest possible adapter host with scoped credentials and no access to
   the canonical database, model prompts, or unrelated devices.

### Target crate topology

```text
Foundation:    fss-types  fss-error  fss-schema  fss-crypto
Runtime:       fss-runtime  fss-capability
Device:        fss-device-core  fss-device-uvc  fss-device-rtsp
               fss-device-onvif  fss-device-vendor-lab  fss-drone-capture
Media:         fss-media-core  fss-media-worker-proto  fss-live
Storage:       fss-ledger  fss-object  fss-archive  fss-durability
Geometry:      fss-time  fss-calibration  fss-geometry
               fss-digital-twin  fss-coverage
Models:        fss-model-registry  fss-model-host-proto  fss-perception
               fss-association  fss-temporal
Events/effects:fss-event-core  fss-policy  fss-effect  fss-alert
Knowledge:     fss-search  fss-graph  fss-memory
Interfaces:    fss-api  fss-cli  fss-mcp  fss-web  fss-ops
Verification:  fss-lab  fss-gauntlet
```

The checked-in workspace is intentionally much smaller: `fss-core` establishes the first semantic
contracts and `fss-cli` reports the honest design-only status.

## Detection is a cascade, not a monolith

A frontier VLM is too expensive, too nondeterministic, and too weakly calibrated to inspect every
frame or authorize alerts alone. The target cognition cascade is:

1. sensor health, blur, darkness, obstruction, glare, and replay/tamper checks;
2. cheap motion/change/audio gates with explicit negative evidence;
3. fast detector and segmenter specialized on the deployment;
4. within-camera tracking and trajectory features;
5. cross-camera association constrained by calibrated geometry and time intervals;
6. open-vocabulary search for unusual objects or behavior;
7. temporal VLM reasoning over a bounded event window;
8. an independent verifier with a different failure profile;
9. conformal/sequential calibration and policy adjudication;
10. alert, abstain, request another view, or retain silently.

Every stage emits a receipt tied to exact model code, weights, preprocessing, inputs, hardware,
seeds, and configuration. A later model may disagree with an earlier model; it may not erase it.

The initial candidate registry includes permissively licensed production candidates and clearly
separated research-only or policy-review candidates. No model is a dependency of the Rust core.
See [`MODEL_REGISTRY.md`](MODEL_REGISTRY.md).

## Digital twin and calibration shuttle

The target setup experience is designed to avoid asking a homeowner to survey their property like
a photogrammetrist:

1. place several printable or illuminated calibration markers around the protected area;
2. start fixed-camera capture and a synchronized calibration session;
3. manually fly a lightweight drone through each camera’s field of view and through overlap zones;
4. reconstruct the property and the drone trajectory from drone footage;
5. detect the shared markers or calibrated marker carried by the drone in fixed-camera footage;
6. jointly solve camera intrinsics, extrinsics, time offsets, rolling-shutter terms, scale, and
   trajectory with robust bundle adjustment;
7. compute coverage, occlusion, blind spots, and expected cross-camera transit intervals;
8. publish a calibration certificate with residuals, covariance, evidence, validity, and
   invalidators.

The canonical twin is metric geometry plus uncertainty and semantic zones. NeRF or Gaussian-splat
renderings are useful derived visualizations, not the source of truth. A moved camera, firmware
crop change, zoom change, major seasonal scene change, or residual drift invalidates or degrades
its certificate. See [`DIGITAL_TWIN_AND_CALIBRATION.md`](DIGITAL_TWIN_AND_CALIBRATION.md).

## The quality objective

“Never miss a true intruder” is the right motivating aspiration and the wrong release claim. FSS
turns it into testable obligations:

- event-level AUPRC over a declared threat distribution;
- recall lower bound at a declared false-alerts-per-property-day budget;
- time-to-detect and time-to-deliver distributions;
- probability calibration and selective-risk curves;
- distinct results for darkness, occlusion, crawling, black clothing, weather, foliage, wildlife,
  delivery workers, residents, children, and camera tampering;
- coverage-conditioned miss accounting, including explicit “not observable” cases;
- red-team intrusion scenarios with retained negative evidence;
- conformal or anytime-valid bounds where their assumptions hold;
- a release-visible ledger of every miss, near miss, false alarm, and broken assumption.

A missing or degraded sensor is not a negative observation. FSS must say “coverage unknown” rather
than quietly lowering the event score.

## Archive economics

FSS preserves evidence without paying to transcode and upload everything at maximum quality:

- short encrypted local ring buffers retain original encoded packets;
- low-latency proxies are derived and disposable;
- analysis frames are sampled according to event demand;
- event manifests reference immutable source ranges rather than copying clips repeatedly;
- old non-event footage can be summarized, thinned, or expired under explicit policy;
- high-value evidence is client-side encrypted and published to S3-compatible B2 or R2 through a
  root-last object graph;
- object sizes are selected from a dated provider cost manifest so millions of tiny fragments do
  not turn cheap storage into expensive operations;
- periodic retrievability audits prove that manifests, keys, and children still compose.

Provider prices are data, not source constants. The repository records dated reference prices only
for planning and requires a fresh price manifest before recommending a backend.

## Agent interface

FSS is designed for both humans and agents, but the agent surface is read-first. Representative
future tools include:

```text
fss.status
fss.sensor.list
fss.sensor.health
fss.observe.delta
fss.events.query
fss.event.explain
fss.event.evidence
fss.calibration.status
fss.coverage.blind_spots
fss.archive.verify
fss.doctor.bundle

fss.alert.acknowledge                 # effect
fss.camera.ptz.prepare / commit       # effect
fss.retention.prepare / commit        # effect
fss.evidence.export.prepare / commit  # effect
```

There is no generic shell tool, arbitrary vendor API proxy, or “control everything” capability.
Each effect has a typed authority, idempotency key, precondition anchor, lease fence, budget,
cancellation behavior, and later verification predicate.

## Repository map

| Path | Purpose |
|---|---|
| [`COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md`](COMPREHENSIVE_PLAN_FOR_FRANKEN_SURVEILLANCE_SYSTEM.md) | Normative architecture and execution plan |
| [`FRANKENSTACK_DEEP_DIVE.md`](FRANKENSTACK_DEEP_DIVE.md) | Project-by-project substrate study and integration gates |
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Compact system architecture reference |
| [`DEVICE_ADAPTER_MATRIX.md`](DEVICE_ADAPTER_MATRIX.md) | Exact device/firmware/interface readiness model |
| [`MODEL_REGISTRY.md`](MODEL_REGISTRY.md) | Candidate model classes, licenses, roles, and admission gates |
| [`DIGITAL_TWIN_AND_CALIBRATION.md`](DIGITAL_TWIN_AND_CALIBRATION.md) | Calibration shuttle and geometry doctrine |
| [`DATA_FORMATS.md`](DATA_FORMATS.md) | Capsules, event revisions, receipts, certificates, and archive roots |
| [`SECURITY.md`](SECURITY.md) / [`PRIVACY.md`](PRIVACY.md) | Authority, secret, isolation, redaction, retention, and identity boundaries |
| [`registries/`](registries/) | Human-readable stable registries |
| [`architecture/`](architecture/) | Machine-readable invariants, claims, imports, dependencies, and costs |
| [`schemas/`](schemas/) | Initial JSON schemas |
| [`crates/`](crates/) | Dependency-free semantic contract skeleton |
| [`scripts/qualify.sh`](scripts/qualify.sh) | Local release authority gate |
| [`scripts/publish_to_github.sh`](scripts/publish_to_github.sh) | Create/push the public GitHub repository with `gh` |
| [`docs/NEGATIVE_EVIDENCE.md`](docs/NEGATIVE_EVIDENCE.md) / [`docs/PERF_LEDGER.md`](docs/PERF_LEDGER.md) | Failed hypotheses and measured performance evidence |
| [`docs/adr/`](docs/adr/) | Load-bearing architecture decisions |
| [`docs/PRICING_REFERENCE_2026-08-30.md`](docs/PRICING_REFERENCE_2026-08-30.md) | Dated object-storage research input |
| [`MANIFEST.sha256`](MANIFEST.sha256) | SHA-256 integrity manifest for this repository snapshot |

## Inspect the skeleton

```bash
python3 scripts/check-policy.py
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo run -p fss-cli -- capabilities --json
cargo run -p fss-cli -- doctor --json
```

The policy check works without Rust. The Rust commands require the pinned toolchain. A passing
skeleton build does **not** qualify any camera, model, archive, or alert behavior.

## Non-goals

FSS is not:

- a way to access devices, accounts, or footage without the owner’s authorization;
- a credential bypass toolkit or a collection of vendor exploits;
- a covert-monitoring product;
- a public face-recognition or cross-property identity network;
- a guarantee that no intrusion can ever be missed;
- an autonomous armed or confrontational response system;
- an autonomous-drone flight controller in its first release;
- a cloud-required product;
- a generic smart-home platform;
- an excuse to place unsafe codec, vendor SDK, or Python model runtimes inside the trust root;
- a benchmark leaderboard without replayable evidence.

## Current status

The project is at **Gate GATE-000: architecture constitution**.

Implemented now:

- stable normative plan and registries;
- machine-readable invariants, claim classes, dependency policy, readiness dimensions, and cost
  rows;
- JSON schemas for sensor capsules, event hypotheses, evidence bundles, operation receipts, and
  calibration certificates;
- a dependency-free safe-Rust semantic contract skeleton;
- a policy validator and local qualification wrapper;
- a publication script for creating the public repository.

Not implemented now:

- camera/drone adapters;
- FFmpeg supervision or live proxying;
- canonical persistence;
- model inference;
- calibration or 3D reconstruction;
- event fusion or alerts;
- cloud archive transport;
- MCP server or UI.

That gap is not hidden. It is the ordered work described by the comprehensive plan.

## License

MIT. Device firmware, vendor applications, model weights, codecs, datasets, and cloud services keep
their own licenses and terms. FSS’s model and adapter registries treat those identities as part of
runtime correctness, not paperwork to resolve after implementation.
