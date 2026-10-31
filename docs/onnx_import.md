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
- Embedded INT64 initializers, Constant values and bounded static shape programs
  may supply compile-time shape, axis, slice and partition controls. They never
  become runtime integer inputs or exported weights.
- Static positive dimensions, at most rank eight. Source-ordered acyclic graphs;
  declared outputs and intermediate value information must match native inference.
- Add, Sub, Mul, Div, Relu, Sigmoid, Tanh, MatMul, Gemm, Softmax, Conv, MaxPool, Transpose,
  Concat, Constant, Reshape, Squeeze, Unsqueeze, Slice, Split, Resize, Identity and Flatten.
  Shape and constant-only INT64 Gather are admitted for the bounded shape programs below.
  Identity/Flatten lower to checked native Reshape
  nodes without changing the frozen operator set or canonical Model IR v1 encoding.
- MatMul requires rank-two-or-higher inputs. Conv is 2-D; declared `kernel_shape`
  must agree with the actual weight tensor. Explicit strides, dilation, pads and
  groups use native validation. `auto_pad`, when present, must be `NOTSET`.
- MaxPool is 2-D, single-output, with explicit nonnegative padding smaller than
  each corresponding kernel dimension, no dilation other than one, no ceil mode,
  and default storage order. Concat requires an explicit axis.
  Softmax uses opset 13's last-axis default, without the older flattening behavior.

Unknown features refuse rather than being skipped or approximated. In particular,
runtime or data-dependent shape inputs/computation, negative Slice strides, BatchNormalization,
noninteger/downsampling/non-nearest Resize,
other opsets/domains/dtypes, symbolic or zero-sized shapes, sparse data, external
weight files, custom functions, training graphs and model activation are not
implemented by this profile. Initializers that are also graph inputs refuse rather
than silently freezing an overridable weight. An unused initializer cannot be made
executable merely by mentioning it in value-info metadata.

## Static shape programs for detector heads

The importer can evaluate a source-authored shape program from already-admitted
static dimensions. This lets a detector flatten its feature maps and calculate
channel partitions using its original graph, without requiring a foreign graph
simplifier or adding integer execution to the frozen runtime IR.

| Source operation | Admitted compile-time behavior |
|---|---|
| [Shape-13](https://onnx.ai/onnx/operators/onnx__Shape.html#shape-13) | Read the exact shape of an already-known tensor into an INT64 vector. No attributes; `start` and `end` belong to later schemas. |
| [Gather-13](https://onnx.ai/onnx/operators/onnx__Gather.html#gather-13) | Index an INT64 vector with an INT64 scalar or vector, preserving order, duplicates and negative indices. Axis is zero or minus one. |
| [Squeeze-13](https://onnx.ai/onnx/operators/onnx__Squeeze.html#squeeze-13) / [Unsqueeze-13](https://onnx.ai/onnx/operators/onnx__Unsqueeze.html#unsqueeze-13) | Convert scalar/vector layouts using constant axis vectors. Omitted Squeeze axes remove singleton dimensions; an explicitly empty vector is a no-op. |
| [Concat-13](https://onnx.ai/onnx/operators/onnx__Concat.html#concat-13) | Join INT64 vectors, including empty vectors, with an explicit zero or minus-one axis. Scalars are not silently promoted to vectors. |
| Add, Sub, Mul, [Div-13](https://onnx.ai/onnx/operators/onnx__Div.html#div-13) | Checked INT64 arithmetic with scalar/vector multidirectional broadcasting. Division truncates toward zero; division by zero and signed overflow refuse. |
| Identity | Copy a bounded INT64 control without changing its scalar/vector shape. |

Every control remains rank zero or one and contains at most eight values. A scalar
and a length-one vector remain distinct. No runtime tensor values are read, no
floating-point conversion rounds large integers, and no runtime INT64 graph or
integer output is emitted. Dynamic controls, symbolic dimensions, mixed dtypes,
rank-two integer controls, unsupported attributes and out-of-range indices refuse.
Reshape, Slice, Split and Resize continue to enforce their own existing admission
rules when consuming the computed controls.

Every evaluated result consumes the same cumulative parameter/control byte quota,
per-tensor size limit and named-value limit as an embedded constant. Source operator
and work limits still apply, and cancellation is checked through evaluation and
output admission. Controls remain quota-charged after removal from exported weights.
Shape-only use of an initializer removes its unused payload from runtime parameters;
a simultaneous data use keeps it bound. Original runtime inputs retain their exact
binding, dtype, shape and generation checks even when only their shape is consulted.
Unknown/forward names, duplicate output bindings, false type witnesses and unused
controls refuse rather than being repaired or silently ignored.

The retained synthetic fixture
`crates/fss-model-ir/tests/fixtures/onnx/detector_shape_program.onnx` is 1,416 bytes,
SHA-256 `96c73cc29267c78d4a78e603a20dcc70cf44163b78222c966c963868d1825f18`.
It executes a convolution over `[1,3,2,4]`, derives its flattening dimensions through
Shape/Gather/Mul/Add/Unsqueeze/Concat, and derives box/class Split lengths through
Div/Sub/Unsqueeze/Concat. Its `[1,8,6]` output contains four box fields and two sigmoid
class scores. Seven ordinary native data operators and two F32 weight tensors remain;
no shape-program node or integer tensor is required at inference. The independent
affine/sigmoid oracle runs through the production scalar executor before export and
after canonical graph and real Safetensors reload. This untrained numerical fixture
does not establish detector quality or full package/CLI qualification.

## Detector branches and spatial pyramid pooling

Static [Split-13](https://onnx.ai/onnx/operators/onnx__Split.html#split-13) accepts
one through eight named F32 outputs from a rank-one-through-eight tensor. Its axis
defaults to zero and may be negative. An embedded INT64 vector supplies positive
partition lengths that must sum exactly to the input's selected dimension. With
that optional input omitted, or an empty optional input name, the dimension must
divide exactly into equal parts. Zero-sized outputs, dynamic lengths, the older
`split` attribute and the later `num_outputs` attribute refuse.

Each output lowers to a native Slice over the original input. Output declaration
order and F32 bits, including signed zero and subnormals, are preserved; no runtime
integer operator or generated weight is needed. The control vector remains covered
by the aggregate parameter allowance even though it is removed from execution
weights. Every expanded branch consumes the common node, tensor and work limits,
and cancellation applies during expansion. Other ONNX operators retain the existing
single-output restriction, including MaxPool's optional index output.

The [MaxPool-12](https://onnx.ai/onnx/operators/onnx__MaxPool.html#maxpool-12) schema
used by opset 13 now admits explicit padding through the existing native pooling
operator. It excludes positions outside the input from the maximum. Because every
pad is smaller than its kernel dimension and output sizing uses floor mode, every
admitted window contains a real input sample; the executor's empty-window fallback
is unreachable. This matters for negative feature maps: padding must not introduce
zeros that can become the maximum. Asymmetric pads and spatial strides follow
native shape validation. Automatic padding, ceil mode, dilated pooling and indices
remain outside this profile.

The retained untrained numerical fixture
`crates/fss-model-ir/tests/fixtures/onnx/detector_split_pool.onnx` is 1,190 bytes with
SHA-256 `8df7f45bdab665b2c105b0c5ee77be79a0748c6a4ee4b1082f6c79213c79cad5`.
It executes a `[1,3,4,4]` convolution, an uneven three-way channel split, three
successive padded pooling stages, branch concatenation, another convolution and a
transpose/reshape to a `[1,16,6]` head. A second graph output exposes one branch
directly. Independent coordinate and arithmetic oracles check both outputs before
export and after the actual canonical graph and Safetensors loaders reconstruct
the model. The same importer is used by the existing
[`fss-infer import-onnx`](ONNX_PACKAGE_IMPORT.md) provisioning path. Package admission
additionally requires its preprocessing, named-output, head and license contracts;
that complete CLI integration was not executed for this fixture. These numerical
fixtures establish conversion and execution behavior, not trained detector quality.

## Nearest-neighbor feature-map upsampling

The importer admits static [Resize-13](https://onnx.ai/onnx/operators/onnx__Resize.html#resize-13)
for NCHW rank-four tensors, preserving batch/channel sizes and enlarging each spatial
axis by an integer factor from 1 through 64. This covers nearest-neighbor feature-map
upsampling in detector necks. Exactly one nonempty embedded F32 `scales` vector or
INT64 `sizes` vector supplies four values. An omitted ROI or empty F32 ROI is accepted;
nonempty ROI, dynamic sizes/scales, fractional factors and downsampling refuse.
Empty optional input names and empty control tensors remain compile-time values.

Two precise coordinate profiles are admitted: `asymmetric` with nearest mode `floor`,
and `half_pixel` with `round_prefer_floor` (the opset-13 defaults). In the latter,
writing an output coordinate as `q*s+r` places the transformed source coordinate
strictly between `q-0.5` and `q+0.5`; nearest rounding therefore selects `q`. Both
profiles repeat exactly the same samples. Other coordinate/rounding combinations,
linear/cubic interpolation and `exclude_outside=1` refuse. Exporter-supplied finite
`cubic_coeff_a` and `extrapolation_value` attributes are validated but have no effect
under these admitted nearest profiles.

Each Resize lowers to Reshape, two Concat nodes and a final Reshape in the existing
frozen IR. Repetition preserves exact F32 bits, including signed zero and subnormals.
Output size is checked before helper expansion; every helper consumes the common
node, tensor and work quotas and reserves names against all source values. No new
operator ID or runtime image-resampling kernel is introduced. The importer identity
includes this lowering source, and the original ONNX source is retained unchanged.
Controls used only for resizing are removed from execution weights; a scale vector
also consumed by a runtime node remains present and is exported.

`onnx_resize_execution` checks 100 scale/size/coordinate-profile combinations against
an independent coordinate-formula oracle after actual graph/Safetensors reload and
production scalar execution. A Conv-to-Resize-to-dense-head case checks detector-style
layout; other cases cover exporter Constant nodes, shared data/control values, namespace
collisions, unsupported modes, malformed controls, exact work bounds and cancellation.

## Static tensor controls and detector heads

The importer lowers [Reshape-13](https://onnx.ai/onnx/operators/onnx__Reshape.html#reshape-13),
[Squeeze-13](https://onnx.ai/onnx/operators/onnx__Squeeze.html#squeeze-13),
[Unsqueeze-13](https://onnx.ai/onnx/operators/onnx__Unsqueeze.html#unsqueeze-13), and
[Slice-13](https://onnx.ai/onnx/operators/onnx__Slice.html#slice-13) into the existing
native layout operators. Their control inputs must be exact embedded INT64 vectors
with at most eight entries. Raw little-endian and packed/unpacked integer fields
are supported. Source-order checking, declared type/shape witnesses and the existing
native graph validator all remain in force.

[Constant-13](https://onnx.ai/onnx/operators/onnx__Constant.html#constant-13) admits
embedded finite F32 and INT64 tensors, including its scalar/list attribute forms.
The output name defines the graph value; a name inside a TensorProto attribute is
metadata. F32 data constants keep their exact bits, including signed zero and
subnormals, and can be returned directly as a model output. The existing native
requirement for at least one computation node still applies, so a graph made only
of constants refuses. INT64 constants can only serve the admitted static controls;
using one as arithmetic data or a model output refuses.

Reshape supports a zero entry copying the corresponding input dimension, one inferred
`-1` dimension, and an empty shape vector producing a scalar when the input has one
element. Squeeze with omitted axes removes every singleton dimension; an explicitly
empty axes vector removes none. Negative axes are normalized against the input rank
for Squeeze and the output rank for Unsqueeze. Duplicated, out-of-range or incompatible
axes refuse. Opset 13 has no Reshape `allowzero` attribute; it is not silently accepted.

Slice accepts optional axes and steps, including empty optional input-name slots.
It normalizes negative axes and endpoints, clamps endpoints to the static dimension,
and supports positive strides up to `i64::MAX`. Negative strides and empty runtime
results explicitly refuse. There is no reverse-slice approximation or dynamic
shape execution. An empty INT64 vector is valid control data for scalar Reshape;
zero-sized runtime tensors remain unsupported.

All embedded controls consume the same aggregate parameter-byte allowance as actual
F32 weights, even when compilation removes them. Control names also consume tensor
and source-node quotas; parsing, copies and lowering consume the cumulative work
allowance and check cancellation. Control-only values are omitted from native graph
inputs and Safetensors. A constant used as runtime data remains a parameter.

The retained numerical fixture `tests/fixtures/onnx/static_conv_head.onnx` is 1,075 bytes
with SHA-256 `a6b486241551c8a3ce5032b42da918f332b4b3c00140d2956c151307e3c13f8a`.
It runs `[1,3,2,2] -> Conv -> Reshape -> Transpose -> Slice -> Squeeze -> Unsqueeze`,
producing a `[1,2,6]` head. Independent hand-computed expected values are checked both
before export and after the actual canonical-graph/Safetensors loaders reconstruct
the model. Its constants are untrained numerical test data. This extends the graph
profile accepted by the existing [`fss-infer import-onnx`](ONNX_PACKAGE_IMPORT.md)
provisioning command; it does not qualify a trained detector.

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

The existing [`fss-infer import-onnx`](ONNX_PACKAGE_IMPORT.md) command packages these
admitted graphs with explicit preprocessing, head and license contracts. Importing
does not activate a trained model.

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
the exact ONNX parser, constants, static shape programs, structural, Split, Resize and Gemm lowering,
artifact exporter and canonical encoder source.
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
512 nodes, 4096 declared/intermediate tensors, 16 MiB embedded controls/parameters and
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

The full native `fss-model-ir` suite passes 186 tests on the pinned compiler. Its
`onnx_gemm_execution` target includes the exact, unmodified production scalar
executor source and executes Gemm graphs without compiling unrelated asynchronous
runtime code. Fourteen new cases cover dense-head replay, 25 transpose-flag pairs,
seven bias forms, optional inputs, exact F32 evaluation order, synthetic-name
collisions, expansion quotas, every import cancellation checkpoint, truncation and
native execution budgets. A literal 264-byte legacy Add graph remains byte-exact
(`sha256:de1ba6db69e22279ecd4bc351ed26a6ebd3db705d456ac14752d9aceb2c57521`).
This focused execution target does not establish full `fss-reference` validation.

The `onnx_artifact_export` target passes 15 tests: 13 focused export cases and
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

The `onnx_structure_execution` target passes 19 tests: 17 structural conversion
cases and two included production-executor smoke cases. It covers the convolution
head fixture, direct F32 Constant outputs, all supported raw/typed constant encodings,
negative and empty axes, scalar shapes, clamped extreme Slice endpoints/steps,
invalid runtime integer/empty tensors, duplicate/forward/unused controls, hostile
protobuf fields, shared quotas, truncation and cancellation. Two additional library
tests exercise empty control vectors and their runtime exclusion.

The `onnx_detector_blocks_execution` target passes 16 tests: 14 Split/pooling cases
and two included production-executor smoke cases. It tests every axis of several
rank-one-through-eight layouts, equal and uneven partitions, all eight outputs,
source-output ordering, exact sample bits, 42 pooling geometry combinations,
negative features, extreme finite values and signed-zero ties. The retained detector
fixture and independent arithmetic checks run both before export and after real
artifact reload. Invalid partitions, duplicate outputs, wrong shape witnesses,
forward/dynamic controls, unsupported multi-output operators, expansion limits,
cancellation and every truncated prefix of the 1,190-byte fixture refuse.

The `onnx_shape_program_execution` target passes 19 tests: 17 shape-program cases
and two included production-executor smoke cases. It covers every input rank from
scalar through eight, exact F32 bit preservation, negative/repeated Gather indices,
scalar/vector distinctions, INT64 arithmetic above 2^53, signed division, empty
controls, metadata-only and mixed parameter uses, wrong runtime bindings, namespace
and declaration failures, exact control-byte/tensor/node/work boundaries, every
cancellation checkpoint and every truncated prefix of the retained fixture.

Scoped formatting and strict library plus shape-program/detector-target Clippy
checks pass without allowances. The preceding full model-IR run passed 186 tests;
the complete package regression has not been rerun after the shape-program addition.
The final Split/pooling 16-test rerun also passed after its test-helper fixes.
The unchanged unused import in `quotas_family.rs` still prevents a strict all-target
Clippy claim; it does not affect the passing native semantic tests.

These fixtures establish the tested conversion and native execution contracts only.
They do not qualify a trained detector, establish framework-wide numerical parity,
authorize redistribution of model weights, publish/activate a model, or claim event
quality, calibrated threat probabilities or absence of activity. The package command's
validation scope is documented separately. A broader exporter/model corpus, model
qualification and local DSR qualification remain separate work. The existing
Safetensors and canonical-graph import paths are unchanged.
