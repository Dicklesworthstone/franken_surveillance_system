# Deep dive: `frankentorch` as the pure-Rust model execution substrate

**Document class:** normative import analysis
**Status:** target architecture; individual operator/model paths require admission
**FSS semantic owner:** `fss-tensor`, `fss-model-runtime`, `fss-kernel-cpu`, `fss-model-conformance`, `fss-accelerator`
**Primary source:** <https://github.com/Dicklesworthstone/frankentorch>

## 1. Why the first design was not strict enough

Calling Python, ONNX Runtime, CUDA libraries, or a vendor inference server from a Rust supervisor does not create a pure-Rust system. It narrows crash propagation, but it still imports a second memory-safety model, runtime, dependency universe, scheduler, serialization stack, model interpretation, and supply-chain boundary into the production product.

FSS therefore adopts a stronger doctrine:

> Shipping model execution is implemented through admitted pure-Rust first-party kernels and formats. Foreign runtimes may be pinned differential oracles in an isolated laboratory; they are not a production fallback and cannot be required for normal operation.

`frankentorch` provides the architectural starting point: typed tensor metadata, operator dispatch, CPU kernels, deterministic graph execution, serialization, conformance harnesses, and proof-carrying artifacts.

## 2. Narrow-waist model format

FSS does not attempt to support every framework graph directly in the hot path. A model is imported offline into a canonical FSS model package:

```text
model_manifest
operator_graph
constant_tensor_objects
input_and_output_schemas
preprocess_and_postprocess_graphs
numeric_policy
shape_constraints
quantization_contract
model_identity
source_license_and_provenance
oracle_receipts
repair_manifest
activation_compatibility
```

The import tool verifies the source package, lowers supported operators into a frozen first-party IR, canonicalizes constants, emits deterministic bytes, and compares outputs against pinned oracles. Unsupported operators fail import. Production never dynamically downloads or JIT-compiles arbitrary model code.

## 3. Tensor and storage semantics

`fss-tensor` inherits FrankenTorch's strong separation of:

- dtype;
- shape;
- stride/layout;
- storage identity;
- view/alias identity;
- device;
- quantization parameters;
- mutability/version counter;
- numeric policy.

A tensor view cannot outlive or silently reinterpret its backing generation. Immutable constants use structural sharing. Mutable scratch is region-owned and cannot escape an invocation. In-place operators are admitted only where alias/version semantics are explicit and differential tests prove them.

## 4. Operator dispatch and specialization

The dispatch layer selects an implementation by:

```text
operator_id × dtype × layout × shape_class × device_class × numeric_policy
```

There is no ambient plugin lookup. Kernels are statically registered and carry:

- reference scalar implementation;
- optimized implementation identities;
- exact or tolerance equivalence contract;
- supported shape/layout region;
- complexity and scratch-space bounds;
- cancellation/checkpoint discipline;
- determinism class;
- benchmark and conformance receipts.

A specialization outside its admitted region is not selected.

## 5. CPU-first, safe-Rust mechanical sympathy

The default execution target is optimized CPU inference, because cheap deployments may have only x86-64 or Apple Silicon CPUs. The strategy is:

- fuse preprocess, normalization, layout conversion, and first operators where semantics permit;
- use cache-shaped tiling and packed weights;
- compile shape-specialized kernels for frozen model dimensions;
- exploit safe portable SIMD and first-party vector primitives;
- minimize intermediate materialization through liveness analysis and arena planning;
- share immutable weights across invocations;
- use per-core/share-nothing work partitions;
- reserve scratch and output publication before execution;
- schedule through Asupersync-owned CPU work, not a foreign pool;
- record exact kernel/ISA/quantization identities in receipts.

`unsafe` remains forbidden in FSS crates. Any needed low-level primitive must be supplied by a separately audited first-party crate with a safe contract; FSS does not create ad hoc exceptions.

## 6. Quantization as a model generation

Quantization is not a transparent runtime toggle. Each quantized model is a distinct immutable generation with:

- calibration corpus identity;
- source floating model identity;
- operator-by-operator quantization policy;
- scale/zero-point/group metadata;
- clipping and accumulation policy;
- quality deltas with confidence intervals;
- hardware performance receipts;
- known failure slices;
- rollback target.

Embeddings/logits from different generations never share one unqualified score space.

## 7. Accelerator posture

GPU/NPU support is optional and first-party. An accelerator backend must define:

- memory ownership and synchronization semantics;
- deterministic or tolerance-certified execution class;
- device-loss and reset behavior;
- allocation and queue budgets;
- kernel/source/binary identities;
- CPU reference comparison;
- thermal and power feedback;
- cancellation boundary;
- no hidden network or dynamic code acquisition.

Until a backend passes its gates, FSS uses CPU inference. A foreign CUDA/Metal/DirectML/ONNX runtime is not a production fallback. It may remain a laboratory oracle or performance comparison arm.

## 8. Model invocation protocol inside one process

Even in one Rust process, model execution is treated as a registered effectful computation:

1. pin evidence, model, preprocessing, calibration, and policy generations;
2. reserve input/scratch/output budgets;
3. materialize a bounded tensor view or decode request;
4. execute with checkpoints between bounded kernel regions;
5. validate output shape, finiteness, and registered invariants;
6. publish the immutable result root;
7. emit a receipt with kernel decision path and numeric class;
8. release scratch and resolve obligations.

Cancellation before publication yields no visible result. Cancellation after publication retains the committed result and drains remaining cleanup.

## 9. Progressive model cascade

FSS uses different model classes for different decision stages rather than one enormous VLM:

- image quality/tamper kernels;
- motion/background models;
- object detector and segmenter;
- pose/action cues;
- appearance embeddings;
- temporal encoder;
- audio event model;
- open-vocabulary image/text encoder;
- multimodal verifier;
- geometry/depth/reconstruction models.

Each stage consumes a pinned candidate set and emits typed results. Later stages can refine, reject, or add uncertainty but cannot erase source provenance.

## 10. Deterministic model packages and RaptorQ custody

Model packages are immutable object graphs. The manifest names all tensor chunks, graphs, vocabularies, preprocess assets, licenses, conformance receipts, and repair symbols. Import and activation are child-first/root-last. ATP moves packages by content identity; receivers verify graph closure and post-repair hashes before activation.

A model package can be reconstructed from its manifest and repair objects. Silent partial activation is impossible.

## 11. Differential conformance

Foreign frameworks are valuable as oracles precisely because they are not trusted production dependencies. For each imported model/operator family, the gauntlet records:

- pinned framework/runtime/container identity;
- exact source model digest;
- generated and real input corpus;
- output comparison policy;
- exact/tolerance divergences;
- metamorphic relations;
- shape/layout/error behavior;
- performance distribution;
- unsupported cases;
- reproducible command.

Outcomes are classified as agree, diverge, error-only agreement, unexercised, or intentionally unsupported. Source presence is not conformance.

## 12. Numeric policy

Every model declares:

- supported dtypes and accumulation types;
- rounding mode;
- denormal policy;
- NaN/Inf behavior;
- reduction ordering;
- deterministic seed behavior;
- exact or tolerance comparison;
- architecture-specific drift envelope.

Alert policy cannot compare raw scores from a new model generation until calibration establishes a valid mapping.

## 13. Failure modes a superficial import would create

1. **Rust supervisor, foreign core.** The product remains dependent on Python/C++ runtimes.
2. **Dynamic operator execution.** A model package smuggles code or unsupported behavior.
3. **Mixed model spaces.** Old/new embeddings are compared directly.
4. **Silent accelerator drift.** GPU output changes decisions without a receipt.
5. **Zero-copy alias bug.** A view survives backing reallocation or mutable reuse.
6. **Nondeterministic reduction.** Replay changes event scores.
7. **Quantization as toggle.** Quality changes without a new generation.
8. **Model download at runtime.** Production meaning changes with network state.
9. **Generic tensor generality tax.** FSS pays for framework features its frozen inference workloads never use.
10. **Benchmark without semantics.** A faster kernel changes outputs or error behavior.

## 14. Admission evidence

A model/operator/backend enters production only after:

1. canonical package bytes reproduce from pinned inputs;
2. all operators have scalar reference semantics and bounded input domains;
3. differential corpus results meet the registered exact/tolerance contract;
4. metamorphic and adversarial tests cover shapes, layouts, aliases, NaNs, extreme values, and malformed packages;
5. cancellation at every registered boundary publishes no partial result;
6. memory/scratch budgets are enforced under pressure;
7. same-binary A/A and optimized/reference experiments prove semantic equivalence before timing;
8. CPU fallback is qualified for every required model;
9. accelerator loss/reset cannot corrupt authoritative state;
10. model-space identity prevents mixed embeddings/logits/calibration;
11. package transfer, repair, corruption, truncation, and rollback preserve root identity;
12. held-out event-level quality meets the registered deployment gate;
13. no production code path requires Python, FFmpeg, ONNX Runtime, CUDA libraries, or a vendor model server;
14. local DSR builds reproduce the package/runtime closure on every supported target.

## 15. Final import rule

FSS imports FrankenTorch's **typed tensor substrate, static dispatch, deterministic execution, serialization discipline, and oracle-driven conformance**. It specializes aggressively for frozen inference graphs and cheap hardware. The objective is not a general framework inside FSS; it is a tiny, world-class, safe, deterministic model runtime whose entire semantic and dependency surface is owned.
