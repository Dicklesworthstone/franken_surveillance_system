# Offline ONNX graph import

This implements part of **FSS-138 / WP-080** (deterministic model import), not the
complete model qualification or activation gate. The library converts an explicitly
supplied, digest-pinned source into the existing frozen Model IR and native tensors.
It does not run ONNX Runtime, Python, a foreign model server, or model-supplied code.

## Entry point

`fss_model_ir::import_onnx(source, expected_sha256, generation, limits, cancelled)`
returns `ImportedOnnx`, with the original borrowed source, verified source digest,
validated native graph, embedded/generated parameters, runtime input names, and charged import
work. `generation` is the existing `fss_core::Generation` newtype, not an untyped ID.
The caller acquires source bytes through its own authorized, bounded I/O boundary;
this API performs no I/O or network acquisition.

Pass `imported.graph()` and the tensors in `imported.parameters()`, together with
exact runtime input bindings, to the existing `ScalarExecutor::run`. Supply a finite
`ExecBudget` and the owning `ScalarExecCx`; conversion does not reserve inference
work. Missing, duplicate, wrong-shape or wrong-generation bindings still refuse.
Keep the original source digest and conversion inputs with the result's provenance.
A numerical result is not a durable model publication or a quality certificate.

For image inference, convert each imported parameter with `to_vec::<f32>()` and pass
the resulting name/value map and graph to `RgbInferenceModel::new`. Its existing
`RgbModelSpec` remains mandatory: no resize, normalization, channel interpretation,
mask policy or source clock is inferred from a model name. The integration tests
exercise the complete native JPEG decode -> source mask -> RGB resize -> imported
convolution/Sigmoid path, including changed private pixels producing identical
masked inputs and outputs while retaining distinct source identities.

See `crates/fss-reference/tests/onnx_import_execution.rs` for executable examples,
including hand-computed dense and convolution/pooling results.

## Admitted source profile

- ONNX IR versions 7 through 9, with exactly the default-domain opset 13 import.
- F32 runtime inputs/outputs and finite embedded F32 initializers. Raw little-endian
  data and packed/unpacked `float_data` are supported, including signed zero.
- Static positive dimensions, at most rank eight. Source-ordered acyclic graphs;
  declared outputs and intermediate value information must match native inference.
- Add, Sub, Mul, Div, Relu, Sigmoid, Tanh, MatMul, Gemm, Softmax, Conv, MaxPool, Transpose,
  Concat, Identity and Flatten. Identity/Flatten lower to checked native Reshape
  nodes without changing the frozen operator set or canonical Model IR v1 encoding.
- MatMul requires rank-two-or-higher inputs. Conv is 2-D; declared `kernel_shape`
  must agree with the actual weight tensor. Explicit strides, dilation, pads and
  groups use native validation. `auto_pad`, when present, must be `NOTSET`.
- MaxPool is 2-D, single-output, with zero padding, no dilation other than one,
  no ceil mode, and default storage order. Concat requires an explicit axis.
  Softmax uses opset 13's last-axis default, without the older flattening behavior.

Unknown features refuse rather than being skipped or approximated. In particular,
arbitrary Reshape shape inputs, Constant nodes, BatchNormalization, Resize,
other opsets/domains/dtypes, symbolic or zero-sized shapes, sparse data, external
weight files, custom functions, training graphs and model activation are not
implemented by this profile. Initializers that are also graph inputs refuse rather
than silently freezing an overridable weight. An unused initializer cannot be made
executable merely by mentioning it in value-info metadata.

## Gemm and dense model heads

The importer admits [ONNX Gemm-13](https://onnx.ai/onnx/operators/onnx__Gemm.html#gemm-13)
and lowers it into the existing Transpose, MatMul, Mul and Add operators. Both matrix
inputs must have rank two. Transposition is applied when the corresponding signed
INT attribute is nonzero; omitted flags are zero. Finite F32 `alpha` and `beta`
default to one. The native execution order is:

```text
product = MatMul(transA ? transpose(A) : A, transB ? transpose(B) : B)
Y = alpha * product + beta * C
```

An omitted `C`, including an empty trailing input name, takes the no-bias path and
does not create a beta parameter or Add node. A present `C` must broadcast into the
fixed matrix-product shape `[M, N]`: scalar, singleton, row, column and matching
matrix forms are admitted. It cannot enlarge that output through general
multidirectional broadcasting. Unknown, duplicate, mistyped or nonfinite attributes
and incompatible matrix dimensions refuse.

Scaling follows matrix multiplication; alpha is not folded into either matrix.
This preserves the specified F32 evaluation order and its rounding behavior. Exact
source initializers remain unchanged, including signed zero. Generated multiplier
scalars are returned in `parameters()` under collision-free names with the requested
generation. Bind the complete returned parameter map when executing the graph.

Without bias, Gemm produces 2–4 native nodes and one scalar; with bias, it produces
4–6 nodes and two scalars. Both source and expanded node counts use `limits.nodes`.
Generated intermediates, names and scalar bytes also consume the existing tensor,
parameter and work limits. All source tensor names, including later outputs and
annotations, are reserved before expansion so generated helpers cannot satisfy a
missing input or an invalid forward reference. The frozen operator set, Model IR
v1 encoding and previously imported graph bytes are unchanged.

This is an offline library conversion capability. It does not add an ONNX CLI
provisioning command or activate a trained model.

## Native graph and weight artifact export

`export_onnx_artifacts(&imported, OnnxExportLimits::default(), &cancelled)` completes
the conversion to the existing native file formats. It returns canonical Model IR
bytes, deterministic F32 Safetensors bytes, their SHA-256 identities, the exact
borrowed original ONNX source and its independently verified digest. Every embedded
and generated parameter is included, so Gemm's alpha/beta scalars survive export.
The caller supplies the preprocessing, detection-head and license contract when
assembling a package; this API has no filesystem or activation effects.

Safetensors names and offsets are sorted deterministically. Quotes, backslashes and
non-ASCII names are JSON-escaped without renaming or aliases. Parameter values retain
their exact little-endian F32 bits, including negative zero and subnormals. Empty
parameter sets produce valid containers. A parameter named `__metadata__` refuses
because that name is reserved by Safetensors; it is never silently changed. The
weights header records the source digest and importer identity.

The separate `onnx_importer_identity()` record uses `fss.onnx_importer.v1` and hashes
the exact ONNX parser, Gemm lowering, artifact exporter and canonical encoder source.
Existing Model IR bytes, operator IDs and the operator-table freeze remain unchanged.

| Export limit | Hard maximum |
|---|---:|
| Canonical graph artifact | 16 MiB |
| Complete Safetensors artifact, including header | 16 MiB |
| Safetensors JSON header | 256 KiB |
| Embedded plus generated parameter tensors | 256 |
| Original ONNX plus graph plus complete weights | 64 MiB |

Exact graph/header/data sizes and the aggregate source-bearing payload are checked
before output allocation. Parameter traversal does not allocate another full copy
of the parameters. The work allowance includes the original import's charged work,
both encoding passes and hashing the new artifacts; it defaults to 268,435,456 units.
Cancellation is checked through header, parameter and hash traversal. These are
payload/work bounds, not a peak process-memory or elapsed-time claim. Any refusal
returns no partial artifact bundle.

## Bounds and failure behavior

`OnnxLimits` bounds source bytes, nodes, tensor count, aggregate parameter bytes,
per-tensor bytes, and deterministic import work. Hard maxima are 16 MiB source,
512 nodes, 4096 declared/intermediate tensors, 16 MiB embedded parameters and
64 MiB per logical tensor. Work units are conversion accounting, not measured MACs
or peak process memory. Cancellation is checked during source hashing (64 KiB
chunks), protobuf traversal, parameter conversion and graph lowering.

Malformed wire data, duplicate singular fields/names, truncation, oversized lengths,
invalid shapes, source-digest mismatch, nonfinite parameters, cancellation and work
exhaustion return typed errors without an executable partial graph. Existing native
shape checks, parameter binding rules and inference resource/cancellation contracts
remain in force after successful conversion.

## Native validation

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-model-ir
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --test onnx_import_execution
rustfmt +nightly-2026-08-31 --check --edition 2024 --config skip_children=true \
  crates/fss-model-ir/src/onnx.rs crates/fss-model-ir/src/onnx/gemm.rs \
  crates/fss-model-ir/tests/onnx_gemm_execution.rs \
  crates/fss-reference/tests/onnx_import_execution.rs
```

The ONNX-specific tests cover source preservation, numeric execution, signed zero,
raw/packed parameters, Conv kernel declarations, shape-only lowering, Softmax axis
semantics, duplicate/overridable/unused parameters, intermediate shape mismatch,
nonfinite data, exact resource limits, generation fencing, cancellation, every
truncated prefix of a valid model, and bounded generated malformed wire inputs.

The full native `fss-model-ir` suite passes 139 tests on the pinned compiler. Its
`onnx_gemm_execution` target includes the exact, unmodified production scalar
executor source and executes Gemm graphs without compiling unrelated asynchronous
runtime code. Fourteen new cases cover dense-head replay, 25 transpose-flag pairs,
seven bias forms, optional inputs, exact F32 evaluation order, synthetic-name
collisions, expansion quotas, every import cancellation checkpoint, truncation and
native execution budgets. A literal 264-byte legacy Add graph remains byte-exact
(`sha256:de1ba6db69e22279ecd4bc351ed26a6ebd3db705d456ac14752d9aceb2c57521`).
This focused execution target does not establish full `fss-reference` validation.

The new `onnx_artifact_export` target passes 14 tests: 12 focused export cases and
two included production-executor smoke cases. It reloads the actual exported graph
and weights with the canonical decoder and the unchanged production Safetensors
parser, then executes the decoded graph through the unchanged production scalar
executor. The parser uses a small type-only test host for its existing error, limit
and float-policy types; its parsing and numeric conversion code is not duplicated.
The fixed untrained RGB fixture `[1,3,1,1] -> Flatten -> batched MatMul -> Add`
produces a `[1,1,6]` dense head with exact expected values. Further cases exercise
generated Gemm scalars, a Conv/Pool/Transpose/Gemm/Softmax graph, exact F32 bits,
escaping, deterministic spans, source metadata provenance, no-weight graphs,
reserved-name refusal, exact output/work boundaries and cancellation. These fixtures
establish numerical plumbing, not detector quality.

Scoped formatting and narrow library/Gemm/export-target Clippy checks pass. Strict
all-target Clippy remains blocked by two pre-existing `chunks_exact_to_as_chunks`
lints in the initializer parser and an unused import in `quotas_family.rs`; those
findings are separate from the passing native semantic tests.

These fixtures establish the tested conversion and native execution contracts only.
They do not qualify a trained detector, establish framework-wide numerical parity,
authorize redistribution of model weights, publish/activate a model, or claim event
quality, calibrated threat probabilities or absence of activity. CLI provisioning,
a broader exporter/model corpus, license-backed packages and local DSR qualification
remain separate work. The existing Safetensors and canonical-graph import paths are
unchanged.
