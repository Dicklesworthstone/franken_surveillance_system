# Model registry and admission doctrine

**Evidence snapshot:** 2026-08-31; architecture revision 2026-08-31
**Current production models:** none
**Core rule:** model packages execute only through the qualified first-party Rust runtime; model outputs remain derived evidence and never authorize an effect

## 1. Why a registry instead of “the best model”

The best model changes quickly, licenses differ by checkpoint, preprocessing silently changes
semantics, and surveillance quality is deployment-specific. FSS therefore admits immutable model
packages through a gauntlet rather than naming one permanent winner. Upstream PyTorch/ONNX code and
weights are import evidence, not production execution dependencies.

A model generation includes:

- upstream repository/model-card identity and revision;
- code and weight digests;
- license and use restrictions;
- preprocessing/tokenization/frame sampling/audio transform;
- canonical FrankenTorch operator graph, backend/CPU-feature policy, and optional separately qualified accelerator policy;
- quantization and precision;
- input/output schema;
- deterministic settings and known nondeterminism;
- resource and latency envelope;
- training-data disclosures and privacy risks when known;
- evaluation corpus and calibration generation;
- removal/rebuild procedure.

Two checkpoints with the same marketing name are different generations if any of these change.

### 1.1 Production runtime contract

The production path is defined by [`architecture/model_runtime_registry.json`](architecture/model_runtime_registry.json)
and [`docs/PURE_RUST_MODEL_RUNTIME.md`](docs/PURE_RUST_MODEL_RUNTIME.md):

1. import upstream artifacts offline into canonical tensor objects and a frozen first-party operator IR;
2. reject unknown operators, dynamic code, runtime downloads, unbounded shapes, and ambiguous preprocessing;
3. execute under Asupersync ownership with a deterministic memory plan and typed resource budget;
4. preserve scalar reference semantics and exact or tolerance-certified optimized kernels;
5. publish a model package root last, then emit a receipt for every invocation;
6. treat quantization, lowering, packing, calibration, prompt vocabulary, and preprocessing as package-generation changes;
7. keep PyTorch, ONNX Runtime, OpenCV, CUDA framework stacks, and vendor inference services in fixture-only laboratory lanes.

A checkpoint that cannot yet be lowered and executed safely in first-party Rust is **unsupported**.
It does not acquire a hidden Python/ONNX fallback.

## 2. Candidate roles

| Registry ID | Candidate | Role in FSS | Public license signal | Initial disposition |
|---|---|---|---|---|
| `MOD-RFDETR-001` | RF-DETR Apache-designated models | fast detection/instance segmentation, fine-tuned hard-negative baseline | Apache-2.0 for core package/designated weights; Plus models differ | first-party import target after operator and quality gates |
| `MOD-GDINO-001` | Grounding DINO | open-vocabulary detector and verifier | upstream/code/weight review required per exact revision | candidate oracle/secondary detector |
| `MOD-SAM3-001` | Meta SAM 3/3.1 | text/exemplar-conditioned segmentation and video tracking | exact checkpoint license review required | high-value candidate, not pre-approved |
| `MOD-COTRACKER3-001` | CoTracker3 | point tracking through occlusion; calibration support | exact code/checkpoint review required | geometry/tracking candidate |
| `MOD-QWEN3VL8B-001` | Qwen3-VL-8B-Instruct | bounded temporal/spatial VLM reasoning | model card reports Apache-2.0 | high-value import target; unsupported until full operator/resource gates pass |
| `MOD-INTERNVIDEO25-001` | InternVideo2.5 / InternVideo-Next family | video representation and long-context verifier | repo code Apache-2.0; checkpoint-specific review | research/production candidate by exact model |
| `MOD-WEMM9B-001` | Tencent WeMM-Embedding-9B | text/image/video retrieval embeddings | model card reports Apache-2.0 | search/association candidate; no audio |
| `MOD-AVF-001` | NVIDIA Nemotron-Labs Audio-Visual Flamingo | synchronized audio-video research oracle | NVIDIA OneWay noncommercial | research-only; prohibited default product model |
| `MOD-VGGT-001` | Meta/Oxford VGGT | camera pose, depth, point maps/tracks, reconstruction bootstrap | commercial checkpoint has restrictions; original differs | geometry oracle/candidate after policy review |
| `MOD-MAST3RSLAM-001` | MASt3R-SLAM | dense real-time reconstruction prior | checkpoint/dependency licenses require review | research geometry oracle |
| `MOD-CUT3R-001` | CUT3R | persistent online RGB 3D state | license/dependency review required | research geometry oracle |
| `MOD-DAV2S-001` | Depth Anything V2 Small | monocular depth proposal | Small is Apache-2.0; larger weights differ | production candidate for proposal only |

This table records candidates, not endorsements or measured FSS results.

## 3. Cognition cascade contracts

### Stage A — sensor quality and tamper

Inputs: source/decoded receipts, frames, camera settings, continuity.
Outputs: blur, darkness, glare, obstruction, defocus, moved-camera likelihood, replay indicators,
usable-region mask, and uncertainty.
Failure consequence: coverage degrades; no negative observation is accepted.

### Stage B — cheap candidate generation

Inputs: adjacent frames/audio windows and static-scene model.
Outputs: change regions, motion vectors, audio anomaly candidates, retained pre/post window request.
This stage is intentionally over-sensitive and measured for candidate recall.

### Stage C — detector/segmenter

Inputs: bounded frames and deployment class prompts.
Outputs: boxes/masks/classes/logits/features with preprocessing and model receipt.
Rules: no frame-level class is an event; score scales are model-generation specific.

### Stage D — tracking

Inputs: observations and geometry.
Outputs: track states, occlusion, motion, uncertainty, appearance features with TTL.
Rules: track identity is local and probabilistic; it is not a person identity.

### Stage E — cross-camera association

Inputs: tracks, capture intervals, calibration, zone topology, expected transit distributions.
Outputs: association hypotheses with supporting/contradicting edges.
Rules: geometry may veto impossible matches; appearance alone cannot create persistent identity.

### Stage F — temporal/open-vocabulary reasoning

Inputs: selected event frames/clips, track summaries, scene/zone context, negative evidence.
Outputs: structured questions/answers, object/action hypotheses, evidence citations, abstention.
Rules: free-form text is non-authoritative; prompts and outputs are retained/sanitized.

### Stage G — independent verification

Uses a different model family, modality, or deterministic rule to reduce correlated errors. A
larger version of the same model with the same preprocessing is not automatically independent.

### Stage H — calibration and policy

Maps raw outputs into calibrated intervals under a declared distribution, combines sequential
evidence, considers coverage/health, and chooses alert/retain/ask/abstain. Hard privacy/effect rules
are not learned online.

## 4. Admission gates

An upstream checkpoint becomes a production FSS package only after deterministic lowering into the
admitted pure-Rust operator universe. It must pass:

1. **Identity gate:** immutable artifacts, exact digests, and no runtime “latest” downloads.
2. **License gate:** code, weights, datasets, dependencies, and deployment use reviewed for the
   exact package generation.
3. **Schema gate:** bounded typed input/output; unknown shapes, operators, or malformed output fail
   closed.
4. **Pure-Rust lowering gate:** every required operator has admitted shape/dtype/layout/alias/numeric
   semantics and a scalar reference; no Python/ONNX/libtorch/vendor fallback path exists.
5. **Capability gate:** the executor receives only explicit tensor/object roots, budgets, clocks,
   and cancellation authority; it has no ambient network, filesystem, credentials, or effect
   capability.
6. **Resource gate:** worst-case tensor and scratch memory, CPU/optional admitted accelerator work,
   input/output size, work units, and cancellation responsiveness are bounded.
7. **Determinism gate:** exact nondeterminism is characterized and the canonical result/decision
   fingerprint is stable wherever the package contract requires it.
8. **Quality gate:** held-out property-security corpus, event metrics, subgroup slices, confidence
   intervals, and negative evidence.
9. **Calibration gate:** reliability, selective-risk, sequential, and conformal assumptions tested
   for the exact package, deployment class, and policy generation.
10. **Adversarial gate:** darkness, dark clothing, crawling, partial body, masks, backlighting,
    weather, foliage, animals, reflections, displays/replay, camera motion, malformed media, and
    resource pressure.
11. **Drift gate:** deployment telemetry detects score, input, quality, and observability shift
    without exposing unnecessary private media.
12. **Upgrade gate:** shadow evaluation, package-generation isolation, root-last activation,
    rollback, and index/cache-space separation.
13. **Removal gate:** package execution can be revoked and every dependent index, embedding, cache,
    receipt, and active policy reference can be enumerated and rebuilt or retired.

## 5. Evaluation metrics

Frame mAP is useful for a detector and insufficient for the product. FSS records:

- event AUPRC and PR curve;
- recall lower confidence bound at fixed false alerts/property-day;
- false alarms by benign category;
- miss rate by threat tactic and observability class;
- time from first observable evidence to hypothesis/corroboration/alert/delivery;
- expected calibration error, Brier/log loss where meaningful;
- selective risk versus abstention/extra-evidence rate;
- cross-camera association precision/recall and ID switches;
- tamper detection delay;
- model executor failure/malformed-output rate;
- CPU/accelerator work-seconds, joules, decoded pixels, and cost per analyzed camera-hour;
- sensitivity to time/calibration uncertainty;
- confidence intervals and raw sample manifests.

## 6. Dataset constitution

The security corpus is versioned and split by property/session, not random neighboring frames.
Otherwise nearly identical frames leak into train and test. It contains:

- routine residents, guests, deliveries, service workers, children, pets, wildlife;
- trash/recycling, package pickup, yard work, vehicles, shadows, lights;
- wind/rain/snow/fog/IR insects/spider webs/foliage;
- staged entry, loitering, reconnaissance, crawling, black clothing, face concealment, unusual
  routes, fence climbing, camera avoidance, carrying objects;
- tamper: cover, move, dazzle, unplug, network jam simulation, replay/display attack;
- sensor failures and explicit not-observable intervals;
- synthetic and simulation augmentations clearly separated from real measurements.

Consent and privacy metadata travel with every sample. The held-out test root is sealed before
model/prompt/threshold tuning. Repeated access creates a new benchmark generation rather than
pretending the old holdout remains untouched.

## 7. Online learning boundary

FSS may adapt reversible cognition parameters—candidate sampling, cache sizes, model routing, or a
shadow threshold proposal—inside hard bounds. It may not autonomously change:

- privacy masks or recording zones;
- retention duration;
- biometric enrollment;
- effect capabilities;
- the definition of a high-severity event;
- release gates;
- the protected-area geometry;
- minimum corroboration rules.

Operator feedback creates evidence-linked proposals and memories. Activation is explicit and
versioned.

## 8. Research-only models

Research-only or noncommercial models can be valuable as shadow oracles. Their outputs must be
marked `research_oracle`, cannot serve the default product path, cannot train a replacement unless
license permits, and cannot silently contaminate production thresholds or labels. The evidence
bundle records their use.
