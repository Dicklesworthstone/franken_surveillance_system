# Pure-Rust model runtime and perception-kernel constitution

**Document class:** normative model import, execution, optimization, and qualification plan
**Revision:** 1
**Date:** 2026-08-31
**Primary source DNA:** FrankenTorch, Frankensearch, Asupersync, FrankenFS, FrankenSQLite

---

## 0. Thesis

The first FSS plan correctly isolated model execution from canonical truth, but it left too much
room for a conventional Python/ONNX/CUDA service to become the de facto production brain. That
would violate the user’s core constraint and reintroduce the exact opaque runtime, allocator,
thread-pool, dependency, and failure semantics that the Franken stack exists to replace.

The production target is therefore:

> **All qualified FSS model execution is implemented in Rust on a typed, deterministic,
> receipt-producing runtime built from FrankenTorch and FSS-owned inference kernels. Python,
> PyTorch, ONNX Runtime, CUDA framework stacks, and OpenCV are laboratory oracles only.**

The runtime is CPU-first and safe-Rust-first. Accelerators are admitted incrementally behind the
same operator and output contracts. The scalar/reference path is never removed; it remains the
semantic oracle and degraded-mode fallback.

## 1. Model-runtime invariants

### `MODEL-INV-001` — immutable model generation

A model generation binds:

- source repository and exact revision;
- original weight-file identities;
- imported canonical tensor identities;
- architecture/config/tokenizer/vocabulary;
- preprocessing and postprocessing programs;
- operator semantics and numeric policy;
- quantization/calibration assets;
- runtime/kernel generation;
- license and deployment restrictions;
- resource envelope;
- qualification corpus/results.

Any change creates a new generation. “Same model name” is not identity.

### `MODEL-INV-002` — one preprocessing program

Resize, crop, color conversion, normalization, letterboxing, frame sampling, temporal windowing,
audio resampling, tokenization, and mask handling are versioned operators in the model graph. A
Python reference script cannot remain an undocumented side channel.

### `MODEL-INV-003` — typed tensor semantics

Shape, dtype, device, layout, strides, alias/view relation, quantization parameters, and semantic
axes are explicit. A tensor with identical bytes but a different layout or normalization is a
different input.

### `MODEL-INV-004` — deterministic reference execution

For a fixed input root, model generation, runtime policy, and deterministic mode, the reference
path produces the same structured output and receipt digest. Nondeterministic accelerator paths
must declare tolerance/distribution and cannot be the sole qualification oracle.

### `MODEL-INV-005` — outputs are derived evidence

Model logits, embeddings, masks, tracks, captions, and classifications are derived records tied to
exact inputs and model execution receipts. They never become source evidence or effect authority.

### `MODEL-INV-006` — no mixed score spaces

Embeddings/logits/calibration scores from different model, preprocessing, quantization, or runtime
semantic generations cannot share an index, threshold, or fusion calibration without an explicit
cross-generation transformation qualified on held-out data.

### `MODEL-INV-007` — no runtime download or code execution

Weights, tokenizer data, kernels, shaders, and configs are imported offline, verified, sealed, and
activated through a prepared effect. Model files cannot carry arbitrary code or request package
installation.

### `MODEL-INV-008` — resource envelopes are hard

Each job reserves bounded input bytes, decoded pixels, tokens, activation memory, scratch memory,
operator work, deadline, and output bytes. Exceeding a bound yields a typed failure/abstention,
not host-wide OOM or unbounded queueing.

### `MODEL-INV-009` — optimization is semantics-preserving

Kernel fusion, SIMD, tiling, batching, quantization, sparsity, caching, and accelerators must match
the registered reference semantics within the declared numeric policy. A quality regression is not
accepted because throughput improved.

### `MODEL-INV-010` — oracle quarantine

Laboratory PyTorch/ONNX/CUDA/OpenCV processes receive fixture/model data only, have no production
credentials or effect capability, and produce signed/digested conformance artifacts. Production
cannot invoke them by fallback.

## 2. Runtime architecture

```text
Model registry / activation authority
        │
        ▼
fss-model-contracts
  typed graph, tensors, preprocessing, output schemas
        │
        ├──────────────► scalar/reference interpreter
        │                        │
        ▼                        ▼
frankentorch operator graph  conformance oracle/digests
        │
        ├── safe CPU kernels: scalar → portable SIMD → tiled/fused
        ├── quantized kernels and calibrated numeric policies
        ├── bounded temporal/state caches
        └── optional isolated accelerator host(s)
                 │
                 ▼
      structured ModelExecutionReceipt
```

### 2.1 `fss-model-contracts`

Owns model identities, tensor descriptors, operator registry, preprocessing graph, output schemas,
resource envelopes, determinism mode, numeric policy, and job/result state machines. It performs no
I/O or inference.

### 2.2 FrankenTorch substrate

FSS imports the deeper FrankenTorch mechanisms:

- zero-dependency typed tensor/value substrate;
- explicit operator schemas and dispatch;
- CPU kernel layer;
- deterministic graph/autograd execution and provenance-complete evidence where gradients are
  needed for calibration/fine-tuning;
- device identity/compatibility guards;
- deterministic serialization/state dictionaries;
- differential and forensic conformance harnesses;
- alias/versioning rules that prevent unsafe in-place mutation;
- packetized qualification rather than aggregate source-presence claims.

Inference does not require autograd, but the Deterministic Autograd Contract is valuable for
controlled calibration, attribution, and future local adaptation. Training/fine-tuning is never
allowed to mutate an active model generation in place.

### 2.3 `fss-model-runtime`

Compiles a sealed model graph into an execution plan:

- validates shapes/dtypes/layouts and operator support;
- performs constant folding and dead-output elimination;
- selects reference or qualified optimized kernels;
- plans lifetimes and buffer reuse;
- reserves memory/work budgets;
- emits a deterministic plan fingerprint;
- executes with Asupersync-owned job lifecycle;
- returns structured output or a four-valued outcome plus semantic failure state.

### 2.4 Accelerator hosts

Accelerator access is separated from canonical/model registry authority. An accelerator host gets:

- one sealed execution plan/model generation;
- bounded input buffers;
- no device/vendor credentials;
- no filesystem beyond model/cache capabilities;
- no alert/camera/drone capabilities;
- deadline, memory, and process-tree limits;
- an output schema and expected digest/tolerance policy.

The CPU reference can replay suspicious outputs. An accelerator crash cannot corrupt canonical
evidence.

## 3. Model import pipeline

Open-weight model repositories are inputs, not runtime dependencies. Import proceeds:

1. **Acquire in a laboratory workspace.** Record repository, revision, files, checksums, license,
   model card, tokenizer/config, and any custom-code requirement.
2. **Reject arbitrary code.** If the model requires `trust_remote_code`, extract and independently
   specify the required architecture/operators; never execute it in production.
3. **Parse weights with a bounded importer.** Safetensors or another admitted format is parsed in
   pure Rust, with size/shape/count limits and no code execution.
4. **Canonicalize tensors.** Record names, semantic axes, dtype, shape, layout, and digest. Unknown
   or duplicate keys fail closed.
5. **Compile architecture.** Map the architecture to the FSS/FrankenTorch operator registry. Missing
   operators create explicit import gaps.
6. **Freeze preprocessing/tokenization.** Convert reference code into versioned data and Rust
   operators with fixtures.
7. **Create reference outputs.** Run the isolated upstream oracle over a diverse fixture corpus.
8. **Differential execution.** Compare operator-by-operator and end-to-end outputs; localize drift.
9. **Measure resource envelope.** Peak memory, work, latency distributions, output bounds, and
   failure behavior across profiles.
10. **Qualify held-out task quality.** Event-level metrics and calibration remain separate from
    numeric parity.
11. **Seal model generation.** Publish weights, graph, tokenizer, preprocessing, licenses,
    receipts, and proof bundle root-last.
12. **Shadow and activate.** Production activation is a prepared, reversible effect.

No step downloads “latest” files during startup.

## 4. Operator registry

Each operator record contains:

```text
operator_id and semantic version
input/output tensor contracts
shape and broadcasting rules
dtype promotion policy
layout/stride/view semantics
numeric formula and reduction order
NaN/Inf/overflow behavior
quantization semantics
reference implementation
optimized kernel families
cancellation/budget granularity
complexity and memory model
oracle fixtures and tolerances
known unsupported regimes
```

Initial high-value families:

- tensor creation/view/reshape/transpose/slice/concat/split;
- elementwise arithmetic and activation functions;
- reductions, softmax/log-softmax, normalization;
- matrix multiplication and batched GEMM;
- convolution/depthwise convolution/pooling;
- interpolation, grid sampling, ROI operations;
- attention, rotary position encoding, KV/state cache;
- embeddings/tokenization primitives;
- image color/resize/normalize/letterbox;
- NMS, top-k, box/mask transforms;
- audio framing/resampling/spectral features where required;
- quantize/dequantize and integer kernels.

The operator registry is narrow at first: support every operation required by the selected model
family, not every theoretical framework surface before the vertical slice works. But gaps are
tracked rather than papered over with an external runtime.

## 5. Tensor and memory model

### 5.1 Strong tensor identity

A tensor descriptor includes:

```text
storage identity
offset
shape
strides
layout class
dtype/device
semantic axes
read/write/alias capability
version counter
quantization metadata
```

Views share storage and carry version/alias semantics. In-place mutation of a value needed by an
active plan or receipt is rejected or copy-on-write according to policy.

### 5.2 Arena and lifetime planning

Inference graphs have mostly known lifetimes. The planner:

- computes liveness intervals;
- reuses compatible buffers deterministically;
- separates persistent weights/state from ephemeral activations;
- bins by size/alignment/layout;
- caps fragmentation;
- reserves worst-case scratch before execution;
- avoids allocation in inner kernels;
- reports peak bytes by class;
- falls back to a simpler plan when proof or memory limits fail.

Plan identity includes the memory schedule. An OOM before execution is preferable to partial
unbounded execution.

### 5.3 Frame-pyramid sharing

FSS should decode each source window once into a canonical color/time representation, then build a
shared image pyramid. Detector, tracker, segmentation, optical flow, and VLM crops reuse declared
levels/ROIs rather than independently resizing the full frame. The pyramid is derived, bounded, and
keyed by source/preprocessing generation.

### 5.4 Temporal state

Trackers and video models maintain state under an explicit `TemporalStateId` bound to model,
stream, calibration, and preprocessing generations. State cannot cross a discontinuity, time gap,
model activation, stream-profile change, or privacy-policy boundary without a registered migration.

## 6. Safe high-performance CPU execution

### 6.1 Scalar reference

Every kernel family starts with a clear safe scalar implementation. It is slow but complete,
deterministic, fuzzable, and usable for tiny inputs/degraded operation.

### 6.2 Portable SIMD

Nightly `std::simd` kernels specialize common dtypes and contiguous/strided cases without unsafe
intrinsics. Runtime dispatch is deterministic and recorded. SIMD tails, alignment, denormals,
rounding, and reduction order have fixtures.

### 6.3 Cache-shaped tiling

Matrix/convolution/attention kernels choose tiles from a registered CPU/profile policy. Tiling aims
to keep weight/activation panels in cache and avoid framework-style materialization. Autotuning is
performed offline or under bounded deterministic experiments; production selects from qualified
plans.

### 6.4 Fusion

The compiler fuses patterns such as:

- bias + activation;
- convolution + normalization + activation;
- matmul + bias + activation;
- attention projections/rotary/cache operations;
- dequantize + matmul + requantize;
- resize + normalize + layout transform;
- box decode + threshold + top-k.

Fusion is admitted only when the fused result matches the unfused reference under the numeric
policy and reduces measured end-to-end cost. It must not erase intermediate evidence required for
explanation/diagnostics unless an instrumented arm remains available.

### 6.5 Parallelism

Asupersync owns task-level parallelism and budgets. CPU kernels may use an owned bounded worker
facility integrated with the same region/cancellation model; Rayon or hidden library pools are
forbidden. Parallel reductions have a deterministic tree in deterministic mode.

### 6.6 Shape specialization

Security workloads have stable camera profiles, model shapes, and batch ceilings. FSS can compile
monomorphic execution paths for known shapes/layouts, removing dynamic dispatch and validation from
hot loops while retaining a generic checked path for import/testing.

## 7. Quantization and numeric policy

Quantization is a model generation, not a compiler flag. A quantized generation includes:

- scheme per tensor/operator;
- scale/zero-point/group size and calibration corpus;
- accumulator/output dtype and saturation policy;
- packed weight format and version;
- kernel compatibility;
- numeric parity report;
- held-out event-quality impact;
- platform-specific performance/energy results.

Candidates include weight-only 8/4-bit for VLMs, integer detector kernels, and reduced-precision
activations where hardware and quality justify them. No quantization is activated on throughput
alone. Event AUPRC, rare-class recall, calibration, track stability, and hard-negative behavior are
release gates.

Mixed precision is explicit. NaN/Inf detection, underflow-sensitive normalization, and high-risk
postprocessing can remain higher precision.

## 8. Perception cascade architecture

The runtime is not asked to run the largest model on every frame. It executes a proof-oriented
cascade:

1. **Sensor health/quality sentinel** — cheap blur/occlusion/freeze/exposure/continuity analysis.
2. **Deterministic activity gate** — background/flow/change candidates with one-sided recall bias.
3. **Fast detector/segmenter** — person/vehicle/animal/object/region candidates.
4. **Within-camera tracker** — stateful association and motion uncertainty.
5. **Geometry/time gate** — world-space plausibility and coverage context.
6. **Cross-camera graph association** — tracklet candidates and alternatives.
7. **Open-vocabulary verifier** — crop/window-level semantic questions.
8. **Temporal/audio-visual verifier** — only for events whose expected value justifies cost.
9. **Independent or differently biased verifier** — reduces shared-mode errors.
10. **Calibrated fusion/policy** — produces an event revision or abstains/escalates.

Each stage records candidates retained/dropped, stop reason, cost, and expected uncertainty
reduction. A cheap stage may reduce compute only if its false-negative bound is demonstrated on the
release threat distribution.

## 9. Dynamic batching and deadlines

Jobs are grouped only when:

- model/preprocessing/runtime generation matches;
- shape/layout policy permits;
- privacy/capability classes can share a worker/cache;
- deadline slack remains;
- batching reduces total cost without violating tail SLO;
- cancellation ownership remains clear.

The scheduler uses deadline-aware bounded queues and reserves activation memory before forming the
batch. Urgent events can bypass background enrichment. A batch receipt retains per-item identities,
outcomes, and work attribution.

Adaptive batch size is bounded by hard min/max and fails to a safe baseline on stale telemetry.

## 10. Model execution state machine

```text
Requested
  -> Admitted
  -> InputsVerified
  -> PlanSelected
  -> ResourcesReserved
  -> Executing
  -> OutputsValidated
  -> ResultPublished
  -> ReceiptSealed
```

Terminal/semantic alternatives:

- `Rejected`: model/capability/schema/resource mismatch before execution;
- `Abstained`: valid execution but model/policy cannot support a conclusion;
- `Cancelled`: request drained without valid publication;
- `Failed`: expected runtime/kernel/import failure;
- `Panicked`: internal failure; process may be restarted and inputs replayed;
- `Quarantined`: output violated schema/numeric/invariant checks;
- `Indeterminate`: result publication may have occurred but reconciliation is unresolved.

A partial tensor buffer is never a valid result.

## 11. Execution receipt

`ModelExecutionReceipt` includes:

```text
job/input/model/runtime/preprocess identities
operator-plan and memory-plan fingerprints
kernel/backend selections
numeric/determinism policy
input/output tensor descriptors and digests
started/finished time intervals
CPU/accelerator identity
work/bytes/peak-memory/energy observations
batch identity and attribution
cancellation checkpoints
warnings, saturation/NaN/overflow events
structured output schema and digest
reference/differential status
terminal outcome and reason
```

The receipt schema is `schemas/model_execution_receipt.v1.json`.

## 12. Differential conformance

### 12.1 Operator-level

For each operator:

- generated valid shapes/layouts/dtypes;
- boundary sizes and empty/scalar cases;
- noncontiguous views/aliasing;
- extreme values, NaN/Inf, overflow/saturation;
- reference PyTorch/NumPy output from isolated lab;
- scalar Rust output;
- optimized Rust outputs;
- gradients where applicable;
- metamorphic properties;
- cross-platform digest/tolerance.

### 12.2 End-to-end model

A sealed corpus covers ordinary and adversarial media: darkness, IR, compression, blur, tiny/crawling
subjects, occlusion, all-black clothing, unusual pose, reflections, animals, weather, camera motion,
clock gaps, and privacy masks. Numeric parity is reported separately from task quality.

### 12.3 Forensics

Any divergence records:

- first differing operator/tensor;
- input/weight slices sufficient to reproduce;
- reference and Rust outputs;
- numeric policy/tolerance;
- platform/kernel;
- decision whether expected, bug, or unsupported;
- linked issue and negative evidence.

## 13. Model selection and registry

“Latest best model” is not a runtime lookup. Candidate acquisition is periodic research. The
registry evaluates models by profile:

- task/event quality and rare-class recall;
- calibration/abstention;
- cross-camera/temporal usefulness;
- supported operators and import difficulty;
- CPU/GPU latency distributions;
- memory and energy;
- license/distribution constraints;
- robustness/adversarial behavior;
- output schema/explainability;
- reproducibility and long-term availability.

A smaller detector/tracker can be more accretive than a larger VLM if it preserves candidate recall
and allows expensive verification to focus. FSS may maintain several specialized generations, but
fusion names each one and its failure domain.

## 14. Local adaptation and learning

Active production weights are immutable. Household-specific improvement occurs through:

1. append-only operator adjudication and evidence-linked feedback;
2. hard-negative/positive dataset curation;
3. threshold/calibration policy generations;
4. optional offline fine-tuning in a separate experiment branch;
5. deterministic training/import receipts;
6. held-out evaluation and shadow deployment;
7. explicit activation/rollback.

A memory saying “usually a raccoon” can affect retrieval or request a verifier; it cannot edit
weights or lower high-risk policy in place. Harmful feedback becomes an anti-pattern and can trigger
requalification.

## 15. Accelerator strategy

### Phase A — safe CPU baseline

Scalar and portable-SIMD CPU execution on Apple Silicon and x86-64. This is the first production
runtime and the universal fallback.

### Phase B — architecture-specific safe kernels

Use safe portable SIMD and shape-specialized tiling. Any architecture-specific intrinsic/ABI need
is isolated behind an exception crate and same-output gate.

### Phase C — isolated Apple/NVIDIA accelerator host

Implement the narrow operator set required by selected models, not a general framework. The host
runs in a supervised process and returns receipts. Exact driver/OS/GPU identities are part of the
qualification tuple. CPU replay samples detect drift.

### Phase D — distributed model executors

ATP moves immutable model-job/result graphs. Worker selection considers capability, model cache,
load, deadline, privacy, and transfer cost. No remote worker gains camera/effect authority.

## 16. Security

- Weight/config/tokenizer files are untrusted bounded inputs.
- No custom Python code, dynamic libraries, shell hooks, or arbitrary tokenizer plugins.
- Model output is schema-validated and tainted as derived.
- Prompt/OCR text cannot become tool calls or capabilities.
- Workers have no production credentials beyond exact data/model capabilities.
- Shared caches are partitioned by model and privacy/capability class.
- Output size/tokens/masks/boxes are bounded before allocation/materialization.
- Adversarial media, decompression, and numeric bombs are part of qualification.
- Model licenses and restricted uses are enforced by activation policy.

## 17. Performance evidence

Every optimization experiment uses one binary with runtime-selected arms and identical:

- model/input roots;
- output schema;
- numeric policy;
- semantic digest/tolerance check;
- receipt schema;
- workload order and warmup policy.

Required artifacts:

- A/A null;
- baseline and candidate percentile distributions;
- CPU/GPU/OS/toolchain identity;
- peak memory and allocation counts;
- energy where measurable;
- output divergence and task-quality deltas;
- attribution to one optimization lever;
- keep/revert decision;
- negative results ledger.

Throughput without tail latency and quality is insufficient. A high average FPS that delays urgent
events behind batches is a regression.

## 18. Admission gates

### `INT-FT-001` — substrate

- typed tensor/layout/view/version semantics;
- deterministic serialization;
- scalar operator references;
- bounded parser/importer;
- no unsafe in ordinary crates;
- no Python/runtime dependency.

### `INT-FT-002` — first detector/tracker vertical slice

- complete operator graph imported;
- operator and end-to-end differential corpus;
- preprocessing byte/float parity;
- bounded CPU execution and cancellation;
- structured receipts;
- held-out event/candidate recall;
- model license and artifact custody.

### `INT-FT-003` — optimized CPU

- same-binary semantic equivalence;
- SIMD/tile/fusion proofs;
- cross-platform determinism/tolerance;
- performance and energy wins;
- no hidden pool/runtime.

### `INT-FT-004` — quantized generation

- numeric and event-quality gates;
- calibrated thresholds for that generation;
- explicit packed format and kernels;
- rollback.

### `INT-FT-005` — accelerator

- exact driver/device/OS tuple;
- process isolation and cleanup;
- resource/OOM/hang/cancellation faults;
- CPU differential replay;
- no effect authority;
- stable tail/quality benefit.

## 19. Integration sequence

1. Freeze model/tensor/operator/job/receipt schemas.
2. Implement safe scalar preprocessing and tensor primitives.
3. Import the smallest high-recall detector required by the walking skeleton.
4. Add operator-by-operator PyTorch oracle fixtures in the lab only.
5. Add deterministic memory planning and bounded execution.
6. Add structured detector output and event-candidate evaluation.
7. Add portable SIMD, tiling, and fusion one measured lever at a time.
8. Add tracker/segmentation and shared image pyramid.
9. Add quantized generations where quality holds.
10. Add temporal/VLM operators incrementally.
11. Add accelerator host only after CPU semantics and receipts are mature.
12. Add offline adaptation/training only after immutable activation and dataset governance.

## 20. Rejected designs

- Python or ONNX Runtime as the shipping model service;
- `trust_remote_code` in production;
- a black-box VLM API that returns prose without exact input/model receipt;
- one global model server with ambient filesystem/network/credential access;
- downloading weights on first use;
- mixing embedding generations;
- dynamic batching without deadline/memory reservation;
- hidden OpenMP/Rayon/thread pools;
- quantization selected only by benchmark speed;
- accelerator output that cannot be replayed on CPU;
- in-place mutation of active weights or temporal state across discontinuities;
- model confidence as a calibrated event probability without held-out calibration;
- “supports model X” based on loading weights or running one sample.

The pure-Rust runtime is not a purity tax. Owning tensor, preprocessing, scheduling, memory, and
receipt semantics is what makes aggressive optimization and trustworthy failure handling possible
at the same time.
