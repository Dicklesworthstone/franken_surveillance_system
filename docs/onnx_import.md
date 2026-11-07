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
  may supply compile-time shape, axis, slice, partition, repetition and selection controls. They never
  become runtime integer inputs or exported weights.
- Static positive dimensions, at most rank eight. Source-ordered acyclic graphs;
  declared outputs and intermediate value information must match native inference.
- Add, Sub, Mul, Div, Relu, LeakyRelu, Clip, Sigmoid, HardSigmoid, Tanh, MatMul, Gemm, Softmax, Conv,
  BatchNormalization, InstanceNormalization, MaxPool, AveragePool, GlobalAveragePool, Transpose,
  Concat, Constant, Reshape, Squeeze, Unsqueeze, Slice, Split, Resize, Pad, Expand, Tile,
  Gather, ReduceMean, Identity and Flatten.
  Shape and INT64 Gather also support the bounded shape programs below; F32 data
  selection uses the separate static Gather profile described below.
  Identity/Flatten lower to checked native Reshape
  nodes without changing the frozen operator set or canonical Model IR v1 encoding.
- MatMul requires rank-two-or-higher inputs. Conv is 2-D; declared `kernel_shape`
  must agree with the actual weight tensor. Explicit strides, dilation, pads and
  groups use native validation. Static `auto_pad` modes `VALID`, `SAME_UPPER`, and
  `SAME_LOWER` lower to exact explicit native padding as described below.
- MaxPool is 2-D, single-output, with explicit nonnegative padding smaller than
  each corresponding kernel dimension, no dilation other than one, no ceil mode,
  and default storage order. Concat requires an explicit axis.
  Softmax uses opset 13's last-axis default, without the older flattening behavior.
- AveragePool is 2-D with explicit padding, positive strides, floor output sizing,
  and either include-padding or exclude-padding means. GlobalAveragePool reduces
  all spatial dimensions of a rank-three-through-eight input to singleton dimensions.
  Both use the bounded native lowering described below.

Unknown features refuse rather than being skipped or approximated. In particular,
runtime or data-dependent shape inputs/computation, negative Slice strides,
cubic or dynamic Resize and unsupported linear coordinate modes,
other opsets/domains/dtypes, symbolic or zero-sized shapes, sparse data, external
weight files, custom functions, training graphs and model activation are not
implemented by this profile. Initializers that are also graph inputs refuse rather
than silently freezing an overridable weight. An unused initializer cannot be made
executable merely by mentioning it in value-info metadata.

## Bounded clipping and ReLU6

The importer admits [Clip-13](https://onnx.ai/onnx/operators/onnx__Clip.html#clip-13)
for static F32 data from scalars through rank eight. Its optional minimum and
maximum are F32 scalars (rank zero), supplied by initializers, Constant nodes
or earlier runtime values. Missing inputs and empty optional input names omit
the corresponding bound. Clip-13 attributes are not accepted: older attribute
based Clip encodings belong to a different opset. A minimum of zero and maximum
of six provides the ReLU6 activation used by exported mobile model graphs.

For finite runtime operands, the result is exactly the input clamped first to
the minimum and then to the maximum. An inverted interval returns the maximum,
as the source operator specifies. Numeric ties select the bound, preserving its
signed-zero bits; when both bounds compare equal, the maximum wins. An unbounded
Clip is an identity Reshape and retains every finite input bit.

The lowering uses the existing Reshape, Sub, Mul, Add, Concat and MaxPool
operators. It compares values directly rather than subtracting a bound from an
input, so opposite finite extrema cannot overflow a temporary. A negative-zero
tensor broadcasts each bound without changing either signed zero. Negation and
a second maximum implement the upper clamp. The expansion is constant in size:
one node with no bounds, seven with a minimum, ten with a maximum, or thirteen
with both bounds. A bounded Clip adds one four-byte scalar; the largest temporary
contains twice the input element count. The full node, tensor, helper-name and
parameter allowances are checked before expansion. Normal import cancellation,
work charging and execution budgets still apply.

This is a finite F32 numerical profile. Low-level executor APIs do not promise
to reject nonfinite runtime bindings; callers must provide finite operands.
The camera model publication path already requires finite frozen parameters and
uses finite image-derived inputs. A runtime scalar bound at the importer API
does not create an additional live input in an activated camera model: package
construction must resolve every non-image binding through its existing contract.

The authored regression suite in
`crates/fss-model-ir/tests/onnx_clip_execution.rs`
exercises the production scalar and optimized executors and canonical
graph/Safetensors reload. It covers optional and runtime bounds, inverted
intervals, ranks, signed zeros, subnormals, extrema, graph composition, helper
collisions and resource/cancellation refusals. The implementation and tests
were source-reviewed; native execution of this new suite remains unverified
because the development workspace became unavailable after compiler resource
failures. These fixtures do not qualify a trained detector.

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-model-ir --test onnx_clip_execution
```

## Hard sigmoid and exported HardSwish compositions

[HardSigmoid-6](https://onnx.ai/onnx/operators/onnx__HardSigmoid.html#hardsigmoid-6)
is the HardSigmoid version selected by opset 13. The importer accepts static F32
tensors from scalars through rank eight, with optional finite F32 alpha and beta
attributes. Their defaults preserve the exact F32 values of `0.2` and `0.5`.
Execution first rounds alpha times the input to F32, then separately adds beta
and rounds to F32, then clamps to zero through one. Zero saturation and
zero-valued ties produce canonical positive zero. Signed-zero coefficient bits
remain in the exported weights and importer provenance.

Admission requires that both `f32::MAX * abs(alpha)` and that rounded F32
product plus `abs(beta)` remain finite. This proves that every finite input
has finite affine intermediates. Default coefficients, positive or negative
one-sixth slopes, zero slopes and many other finite pairs are supported.
A pair that could overflow an intermediate refuses, even if the final
saturation would conceal that overflow. Unknown attributes and non-FLOAT
coefficient attributes refuse.

The implementation uses two native affine nodes and the shared two-sided Clip
lowering: fifteen nodes, five scalar parameters occupying twenty bytes, and
temporaries no larger than twice the input element count. The complete cost is
reserved before any generated value. The new module participates in the
source-bound importer identity; Model IR v1 and operator IDs remain unchanged.

An exported HardSwish graph represented by HardSigmoid with alpha one-sixth and
beta one-half followed by Mul now executes through the native path. The raw
HardSwish operator belongs to newer opsets and remains outside this opset-13
profile. The implementation does not rewrite or approximate an unsupported
source operator.

Twelve authored cases in `onnx_hard_sigmoid_execution` exercise both production
CPU executors and real canonical graph/Safetensors reload. They cover every
finite exponent, admitted coefficient extremes and the overflow admission
boundary, a multiply/add rounding witness, zero bits, complete gated
convolution/dense graphs, private-name collisions and exact resource,
cancellation and source-digest checks. As with the Clip suite above, native
compilation, formatting and execution remain pending while the workspace is
unavailable; the source review is not a trained-model qualification.

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-model-ir --test onnx_hard_sigmoid_execution
```

## Exact leaky activations

The importer admits [LeakyRelu-6](https://onnx.ai/onnx/operators/onnx__LeakyRelu.html#leakyrelu-6),
the operator version selected by opset 13, for static F32 tensors from scalars
through rank eight. It accepts an omitted alpha (exact F32 `0.01`) or a finite
F32 alpha in `[0, 1]`, including either signed zero. Other slopes refuse:
the bounded lowering must preserve the full admitted finite input range,
without overflowing an intermediate whose result would later be discarded.

For every admitted finite input, the source branch is `alpha * x` when
`x < 0`, and the unchanged input otherwise. The lowering flattens the tensor,
multiplies by one generated scalar, stacks the original and scaled values,
and selects their maximum with the existing two-row MaxPool. It restores the
original shape afterward. The original value is first in each pool window;
both CPU executors retain that first value on numeric ties. This preserves
negative zero inputs and exact subnormal rounding without epsilon comparisons.
Alpha one uses a single identity Reshape with no generated parameter.

A nonidentity activation adds five native nodes and one four-byte scalar.
Its largest temporary has twice the input element count. Checked tensor,
aggregate node, parameter and value bounds apply before expansion, with
the existing cumulative work and cancellation checks during conversion.
All source names are reserved before private helpers are allocated. Model IR
v1 encodings and frozen operator IDs remain unchanged; new conversions bind
the LeakyRelu lowering source in the importer identity.

The nine authored cases in `onnx_leaky_relu_execution` run the production scalar
and optimized executors before and after real canonical graph/Safetensors reload.
They cover all admitted ranks, 4,080 values across every finite F32 exponent
and nine slopes, signed zeros, subnormal ties, extrema, Conv/Gemm composition,
initializer inputs, helper-name collisions, refusals and resource/cancellation
boundaries. They establish a focused numerical contract when executed; they
do not qualify a trained detector or expand the supported ONNX profile.

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-model-ir --test onnx_leaky_relu_execution
```

## Static expansion and tiling

[Expand-13](https://onnx.ai/onnx/operators/onnx__Expand.html#expand-13) and
[Tile-13](https://onnx.ai/onnx/operators/onnx__Tile.html#tile-13) accept static F32
data from scalars through rank eight. Their second input must be a rank-one
INT64 constant with at most eight values, supplied by an initializer, Constant
node or the bounded static shape programs below. Controls remain charged to
the aggregate parameter allowance and are removed from runtime weights.

Expand right-aligns input and requested dimensions, accepting equal dimensions
or a dimension of one. Each result dimension is the larger one. The requested
shape can have lower rank than the input and need not be the result shape:
input `[3,1]` with target `[2,1,6]` produces `[2,3,6]`, while input `[2,3]`
with target `[1]` remains `[2,3]`. Tile requires exactly one repeat count per
input axis and repeats complete source blocks along those axes. An empty
control vector is admitted for scalar Tile and for an identity Expand.

Every control value must be positive. Zero-sized results, negative dimensions
or repeats, dynamic controls, malformed control rank/type, incompatible Expand
dimensions and conflicting output declarations refuse. Checked dimension and
byte arithmetic applies before graph expansion.

The lowering uses only existing Reshape and two-input Concat operators, so data
bits survive unchanged, including signed zeros, subnormals and finite extrema.
Binary prefix construction needs `floor(log2(r)) + popcount(r) - 1` Concat
nodes for an axis with repeat factor `r`. Rank alignment adds one Reshape;
an overall identity uses one Reshape. Large repeat factors therefore do not
create a per-copy input list or generated constant tensor. Each intermediate
contains no more elements than the final result. The complete node and named
value expansion is checked before helpers are created, and ordinary inference
work/allocation budgets still cover all intermediates. Reserved source names,
generation bindings, import work and cancellation checks remain enforced.
The importer identity includes this lowering source; native operator IDs and
canonical Model IR encodings remain unchanged.

The `onnx_broadcast_execution` target runs both production CPU executors before
and after canonical graph and actual Safetensors reload. Its ten authored tests
cover literal block tiling, an independent coordinate oracle across all admitted
ranks, scalar and lower-target-rank expansion, shape-program/anchor composition,
exact finite boundary bits, logarithmic expansion, name collisions, malformed
controls, and exact import/execution quota and cancellation boundaries.

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-model-ir --test onnx_broadcast_execution
```

## Static attention selection and pooled features

The importer adds [Gather-13](https://onnx.ai/onnx/operators/onnx__Gather.html#gather-13)
over F32 data and [ReduceMean-13](https://onnx.ai/onnx/operators/onnx__ReduceMean.html#reducemean-13)
over static axes. Together with the existing batched MatMul, Transpose, Softmax
and elementwise operations, these express packed Q/K/V selection, attention,
token or channel pooling, and fixed feature selection before a dense head.
They add no native operator, dynamic integer executor or foreign runtime.

Gather accepts positive F32 data shapes of rank one through eight and an
embedded INT64 scalar or vector containing one through eight indices. Constant
nodes and the existing static shape programs may produce those indices. Axis
defaults to zero and accepts negative axes; each index must be within the
selected axis, with negative values counting from its end. A scalar index
removes the selected dimension, while a length-one vector keeps that dimension.
Repeated indices and arbitrary index order remain intact. Empty indices,
runtime indices, other control dtypes or ranks and out-of-range values refuse.
The existing INT64-only shape-program Gather keeps its separate semantics.

Selection lowers to one Slice per consecutive ascending index run, followed
by Concat when necessary. Scalar selection adds a Reshape. At most nine native
nodes are needed for the admitted vector; helper count does not grow with the
size of a selected token or feature block. No generated F32 weight is required.
These operators copy data without numerical changes, preserving signed zeros,
subnormals and finite extrema.

ReduceMean accepts static positive F32 shapes from scalars through rank eight.
Its `axes` attribute may contain distinct positive or negative axes. Omitted
or empty axes means all dimensions, as in the opset-13 reference; the later
input-axes and `noop_with_empty_axes` forms are not admitted. `keepdims`
defaults to one; zero removes reduced dimensions. Duplicate axes, invalid
attribute types, unsupported attributes and conflicting output shapes refuse.
An explicitly empty INTS attribute is accepted both as an absent repeated-field
payload with its type discriminator and as an empty packed field. Scalar/list
mixtures and missing or conflicting type discriminators still refuse.

The native numerical contract is an ordered F32 accumulation from positive
zero followed by a separate F32 division. Reduced coordinates are visited in
their original row-major order, independently of attribute axis order. The
lowering puts kept dimensions before reduced dimensions, reshapes to a matrix,
and multiplies by a generated column of exact ones. The divisor is the positive
reduction width represented exactly in F32 under the existing tensor ceiling.
Two through five native nodes and two parameters suffice. Generated parameter
storage is `4 * reduction_width + 4` bytes, so the separate parameter quota
can refuse a mean even when its input tensor fits.

**This is not a higher-precision or overflow-repair mean.** A finite input can
overflow the F32 sum before division; the low-level native tensor then retains
that nonfinite result. No finite replacement or empty feature set is invented.
Different reduction orders, wider accumulators or an upstream overflow repair
may produce different results. Scalar and singleton reductions retain the same
arithmetic, including positive zero from a negative-zero-only sum. Existing
consumer nonfinite-output checks remain necessary.

Both lowerings preflight complete node, named-value and parameter expansion.
Every temporary has no more elements than the admitted input or output, and
the ordinary cumulative inference work/allocation budget covers the complete
lowered graph. Source names are reserved before helpers are created. Static
controls remain quota-charged after removal from exported weights; generated
mean parameters are generation-bound and exported normally. Cancellation is
checked during import and parameter generation. The importer identity includes
both implementation sources without changing frozen Model IR IDs or encoding.

The thirteen native cases in `onnx_attention_execution` use the real scalar
and optimized executors, canonical graph reload and the production Safetensors
parser. They include a two-batch, two-head Q/K/V projection and selection,
batched attention, residual, pooled features and dense head. Exact layout and
ordered-mean oracles are separate from a binary64 oracle with a declared bound
for the small ordinary attention fixtures. Additional cases cover scalar/vector
selection, all admitted ranks, static control/data dispatch, rounding and
overflow, constant helper counts, namespace collisions, resource limits,
generation mismatch and cancellation. The empty-attribute case also checks both
protobuf encodings through graph/weight reload while preserving their distinct
source provenance.

**Native validation:** all thirteen attention contracts pass on pinned nightly
`2026-08-31` with locked offline dependencies, together with all ten broadcast
and nine leaky-activation contracts. The restored workspace exposed and repaired
the parser's refusal of normally encoded empty INTS attributes; it also corrected
the practical-token fixture's parameter-byte expectation to include the two Gemm
scalars. These are native arithmetic, artifact and refusal checks; trained
detector, embedding quality and full RF-DETR import qualification remain open.

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-model-ir \
  --test onnx_attention_execution -- \
  --test-threads=1 --skip scalar_executor:: --skip optimized_executor::
```

## Static constant padding and cropping

The importer admits [Pad-13](https://onnx.ai/onnx/operators/onnx__Pad.html#pad-13)
for static F32 tensors of rank one through four, including padding or cropping
batch and channel axes. `mode` must be absent or `"constant"`. The second input
must be an embedded INT64 vector containing exactly twice the input rank in the
order `[begin_axis_0, ..., begin_axis_n, end_axis_0, ..., end_axis_n]`.
Initializers, Constant nodes and the bounded static shape programs below may
supply this control; its existing eight-element ceiling remains unchanged.

Positive values add constant borders and negative values remove samples from
the corresponding side. All cropping happens before padding, and every retained
axis must contain at least one source sample. An entirely cropped axis refuses
with `Unsupported`, even when padding on the opposite side would make the final
shape positive. For example, input `[1,2,3,4]`, pads `[-1,2]` and fill `9` produce
`[2,3,4,9,9]`; pads `[2,-1]` produce `[9,9,1,2,3]`.

The optional third input is a finite embedded F32 **scalar**, not a length-one
vector. An omitted input or empty optional input name selects positive zero;
an empty tensor is not a scalar and refuses. Explicit negative zero and subnormal
fill values retain their exact F32 bits. A fill also consumed as ordinary model
data remains an exported parameter, while control-only values are removed from
the runtime graph without changing the retained original ONNX bytes.

Conversion emits at most one positive-stride Slice for cropping, followed by one
Concat per padded axis with generated constant border tensors. A no-op Pad emits
a Reshape; crop-only Pad needs no generated parameters. These existing native
operators move data without floating-point arithmetic, so source sample bits are
preserved. No frozen operator ID, runtime dependency or package format changes.
Cropping first also keeps every intermediate tensor within the final output's
size. Checked output and generated-parameter byte counts, node and tensor counts,
shared work limits, cancellation and reserved helper names apply before and
during expansion. Signed pad magnitude and shape overflow produce typed refusals.

Dynamic pads or fill, reflect/edge modes, scalar data, ranks above four, non-F32
data, later-schema axes inputs and zero-sized retained axes are outside this
profile. Malformed control rank/type/length, conflicting declared shapes and
unsupported attributes also refuse conversion.

The `onnx_pad_execution` target exercises the production scalar executor before
and after canonical Model IR and Safetensors export/reload. Literal mixed-sign
examples and an independent output-to-input coordinate oracle cover all four
ranks, default and explicit fills, negative zero, subnormals and a Pad-to-Conv
block. Additional cases cover static shape controls, a scalar's simultaneous
control/data use, helper-name collisions, crop-first resource bounds, exact
quota boundaries and cancellation at every import checkpoint. The importer
identity includes this lowering source. Native results and their scope are
recorded in `IMPLEMENTATION_STATUS.md`.

## Instance and grouped feature normalization

The importer admits [InstanceNormalization-6](https://onnx.ai/onnx/operators/onnx__InstanceNormalization.html#instancenormalization-6),
the schema selected by opset 13. It computes fresh spatial population statistics
independently for every batch/channel pair of a positive static F32 tensor
`[N,C,D1,...,Dk]`, with rank three through eight. Scale and bias must each be a
F32 vector of exactly `C` elements. Initializers, Constant outputs, runtime inputs
and earlier runtime-node outputs retain their normal source bindings; runtime
affine values are never silently frozen.

One source node becomes exactly five existing native nodes: LayerNorm over
`D1,...,Dk` with elementwise affine disabled, two channel-vector Reshapes to
`[1,C,1,...,1]`, Mul by scale, and Add of bias. No weights are synthesized or repeated
over image positions. Two distinct constant affine vectors occupy `8*C` bytes
together, regardless of spatial area. The two reshapes contain only `C` elements,
and every other intermediate has the same element count as the input. A static
Shape/Reshape program can therefore group channels, normalize each group with this
operation, restore the original shape and apply channel-wise affine parameters.
The authored grouped-feature fixture exercises one, two and four groups; this is
a composition of admitted opset-13 operators, not admission of a later ONNX
GroupNormalization schema or qualification of a complete trained model.

The source FLOAT epsilon is preserved exactly when widened to the native F64
attribute. Omission means `f64::from(1e-5_f32)`, which differs from the native
LayerNorm's F64 default. This profile requires finite, strictly positive epsilon.
Zero and negative epsilon refuse; a non-FLOAT epsilon, unknown attributes, incorrect
input/output arity, non-vector affine tensors, mismatched channel lengths, integer
data and ranks outside the stated profile refuse before artifact emission.

The numeric contract is the existing native LayerNorm contract: ordered F64 mean
and centered population-variance accumulation over each spatial row, an F64 square
root after adding epsilon, and normalized values rounded to F32. Scaling and bias
then run as separate F32 Mul and Add operations. This supports finite extreme F32
samples without the avoidable overflow of an F32 statistics accumulator, but does
not assert bit parity with every framework's normalization kernel. A runtime NaN
or infinity produces the existing canonical NaN row; other batch/channel rows
remain independent. Overflow during subsequent F32 affine arithmetic remains
nonfinite, and the retained inference owner's nonfinite-output checks remain in
force.

The importer preflights all five native nodes, five newly known output values and
four generated names together. Ordinary tensor, parameter, work, name-reservation,
generation and cancellation checks apply to every emitted operation. Source names
cannot capture generated helpers or repair forward references. Original ONNX bytes
remain intact; the new lowering module participates in the source-bound importer
identity. Native operator IDs, canonical Model IR v1 and production dependencies
are unchanged.

**Validation status (2026-11-07): this new InstanceNormalization slice is authored
and awaits native compile, rustfmt, Clippy and execution.** The execution environment
disconnected before its first build; the 71 passing earlier model tests and earlier
strict Clippy check do not cover this addition. Twelve new contracts in
`onnx_batch_normalization_execution::instance` use the actual scalar and optimized
executors and real canonical graph/Safetensors reload, together with the eight
existing BatchNormalization contracts in the shared host. They cover literal
batch/channel isolation; every spatial rank; exact epsilon defaults and extrema;
runtime and Constant affine values; independent pairwise-difference population
variance oracles; grouped normalization; Conv → InstanceNormalization → bilinear
Resize → pooled dense features; constant helper/storage bounds; malformed profiles;
exact quotas and every import cancellation point; future-name collisions; nonfinite
rows; and actual execution budgets, generations and cancellation. This authored
coverage is not a reported native pass. Run it when execution is restored:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-model-ir \
  --test onnx_batch_normalization_execution -- --test-threads=1 \
  --skip scalar_executor:: --skip optimized_executor::
```

## Static automatic spatial padding

Conv, MaxPool and AveragePool accept `auto_pad: "VALID"`, `"SAME_UPPER"`, and
`"SAME_LOWER"` for their admitted static two-dimensional profiles. Conversion
resolves these into the existing native `padding` attribute; inference does not
need another operator or a dynamic padding implementation. The definitions are
the opset-13 selections of [Conv-11](https://onnx.ai/onnx/operators/onnx__Conv.html#conv-11),
[MaxPool-12](https://onnx.ai/onnx/operators/onnx__MaxPool.html#maxpool-12), and
[AveragePool-11](https://onnx.ai/onnx/operators/onnx__AveragePool.html#averagepool-11).

`VALID` inserts no padding. Both `SAME` modes produce `ceil(input / stride)`
outputs along each spatial axis. Conv accounts for the effective kernel
`dilation * (kernel - 1) + 1`. Any odd extra padding goes at the end for
`SAME_UPPER`, or at the beginning for `SAME_LOWER`. For a 4×4 input, 3×3 kernel
and stride two, the explicit top/left/bottom/right pads are `[0,0,1,1]` and
`[1,1,0,0]`, respectively. Strides wider than the effective kernel can require
zero padding; no negative pad or artificial crop is introduced.

An automatic mode combined with explicit `pads` is refused, including an
all-zero `pads` declaration. Absent `auto_pad` and `NOTSET` keep the existing
explicit-padding behavior and canonical native graph representation. Unknown
modes, malformed attributes, nonpositive strides/dilations, arithmetic overflow,
unsupported ranks, and a declared output shape inconsistent with the computed
shape refuse conversion. Existing size, work and cancellation ceilings apply.

This does not widen the pooling numeric profile: MaxPool still skips padded
positions, including for entirely negative input, and admits only unit dilation
and floor output sizing. AveragePool keeps its explicit include/exclude-padding
denominator and floor sizing. Both preserve the rule that every admitted pooling
window contains a real sample. Existing grouped/dilated Conv, bias, parameter
bits and scalar accumulation order remain intact.

The `onnx_padding_execution` target compares real native execution with an
independent spatial oracle, then repeats execution after canonical graph and
Safetensors export/reload. It also covers incompatible declarations, resource
bounds and cancellation. The importer identity includes the padding resolver;
the original model bytes remain retained, and existing package/IR formats do not
change. Test results and their scope are recorded in `IMPLEMENTATION_STATUS.md`.

## Spatial and global average pooling

The importer admits [AveragePool-11](https://onnx.ai/onnx/operators/onnx__AveragePool.html#averagepool-11)
and [GlobalAveragePool-1](https://onnx.ai/onnx/operators/onnx__GlobalAveragePool.html#globalaveragepool-1),
the schemas selected by opset 13. This supports average downsampling and global
context heads in an original convolutional graph, including a subsequent Flatten,
Gemm or activation, through the existing native execution and packaging path.

AveragePool requires static F32 `N,C,H,W` input and a positive two-element
`kernel_shape`. `strides` defaults to `[1,1]`; `pads` defaults to four zeros in
top, left, bottom, right order. Each explicit pad must be nonnegative and smaller
than its corresponding kernel dimension. The padded extent must contain a kernel.
Output dimensions use floor sizing, so these conditions guarantee that every
admitted window contains a real input sample. `count_include_pad=0`, the default,
divides each window's sum by its real sample count. Setting it to one divides by
the full kernel area, including padded positions. Asymmetric padding and spatial
strides apply independently. `auto_pad` can select the static automatic modes
above; `ceil_mode` must be absent or zero. Ceil mode, dilation attributes from
later AveragePool schemas and malformed attribute types explicitly refuse.

GlobalAveragePool accepts rank three through eight in `N,C,D1,...` layout and
has no attributes. It produces the same rank, batch count and channel count,
with every spatial dimension equal to one. Non-2-D spatial inputs temporarily
reshape to `N,C,product(D1,...),1`; a final native Reshape restores the declared
output rank. No batch or channel values are mixed into a spatial mean.

Both operations lower to a depthwise Conv2d with exactly one-valued weights,
followed by Div. The native scalar numerical contract is a row-major F32 spatial
sum from a zero accumulator, the convolution's existing zero-bias addition, then
F32 division. A scalar denominator suffices for global pooling, unpadded windows
and include-padding means. Exclude-padding means with nonzero pads use a static
`[1,1,Hout,Wout]` denominator tensor, broadcast across batches and channels. Every
denominator is a strictly positive integer represented exactly as F32. The importer
does not replace division with reciprocal weights or widen accumulation: those
changes can lose subnormal values, avoid an intermediate overflow, or alter
rounding. Runtime nonfinite-result handling remains the ordinary native executor
behavior. Other backends may choose a different floating-point reduction order.

Generated weights contain `C * kernel_height * kernel_width` F32 values; the
denominator contains either one value or `Hout * Wout` values. Their complete
aggregate byte cost is checked against the remaining parameter allowance before
allocation, together with per-tensor, generated-node and named-value bounds. This
means a large global reduction can refuse when its generated weights exceed the
16 MiB aggregate parameter ceiling. Parameter construction checks cancellation
throughout and charges generation and tensor materialization work. The native
convolution, division and any reshapes keep their existing inference budgets and
generation checks. All helpers use collision-free names reserved against the
complete source graph. The frozen operator IDs and Model IR v1 encoding are
unchanged, and importer provenance includes the pooling-lowering source.

The retained untrained fixture
`crates/fss-model-ir/tests/fixtures/onnx/detector_average_pool.onnx` is 830 bytes,
SHA-256 `408633ceb55af769ac529ed31046fd7da77df505b9e5780a38ab7f99e9866905`.
It executes a `[1,3,4,5]` convolution, padded/strided average downsampling, global
average pooling, Flatten, Gemm, Sigmoid and a `[1,1,6]` head reshape. A second
output exposes the four-channel pooled context. The test reconstructs the exact
source bytes and checks independent coordinate, affine and sigmoid oracles before
export and after the real canonical graph and Safetensors loaders reconstruct
the model. Separate tests cover both padding denominators over 84 window profiles,
ranks three through eight, subnormal preservation, F32 reduction order and
intermediate overflow, exact cumulative quotas, name collisions, source identity,
every pooling import cancellation checkpoint and native execution limits. These
numerical checks do not establish trained detector quality or full package/CLI
qualification. Run the focused suite with:

```sh
cargo test -p fss-model-ir --test onnx_pooling_execution
```

## Unfused inference batch normalization

The importer admits the one-output inference form of
[BatchNormalization-9](https://onnx.ai/onnx/operators/onnx__BatchNormalization.html#batchnormalization-9),
the schema selected by opset 13. This allows a convolutional backbone or detector
export to retain its original normalization nodes without an external graph
simplifier or a new native operator ID. Input data has rank one through eight and
layout `N,C,D1,...`. For rank-one data, the schema assumes one channel. Scale, bias,
mean and variance must each be an embedded finite F32 vector of exactly `C` values,
from an initializer or an earlier Constant node. Channel counts are bounded by
the existing tensor and aggregate parameter limits, not the eight-value limit
for shape controls. Runtime channel parameters and data-derived statistics refuse.

Each normalization becomes four ordered native F32 nodes:
`centered = X - mean`, `normalized = centered / denominator`,
`scaled = normalized * scale`, and `Y = scaled + bias`. The constant denominator is
`sqrt(variance + epsilon)`, with the addition and square root each rounded to F32
at import. Epsilon defaults to `1e-5_f32`; this profile requires finite nonnegative
epsilon and variance, and a strictly positive finite variance-plus-epsilon sum.
Zero epsilon is admitted when every variance is positive. Nonfinite source values
and overflow in the constant sum refuse. Negative statistics and zero denominators
refuse before a model artifact can be emitted. Finite FLOAT momentum is validated
but has no effect on one-output inference. Training outputs and attributes from
other schemas, including `training_mode`, `spatial` and `is_test`, refuse.

Scale, bias and mean use immutable channel-shaped views for right-aligned
broadcasting across batch and spatial axes. Import reshaping shares source storage
and adds no runtime layout kernels or repeated spatial weights. The four arithmetic
nodes retain their ordinary inference work and allocation charges. The importer
does not replace division with a reciprocal, combine scale and denominator, combine
bias and mean, or fuse a preceding convolution. Each of those transformations can
change F32 rounding or intermediate overflow. Existing scalar execution behavior
for runtime nonfinite results is unchanged; a zero or tiny scale cannot silently
erase a prior overflowing subtraction.

Every generated denominator and shaped parameter consumes the cumulative logical
parameter byte quota, named-value quota and work allowance. With four distinct
source vectors, one rank-three-or-higher node consumes `32*C` parameter bytes in
total for source and generated vectors/views; rank-one/two nodes reuse the three
already-broadcastable source vectors and consume `20*C`. Shared source vectors are
admitted once, while every generated value is charged. These are logical import
reservations, not a claim about resident memory. Four native nodes and three temporary data values also
consume the common expansion limits. The importer checks cancellation for every
denominator channel and throughout name reservation and graph admission. Removing
compile-only source parameters from exported weights does not refund those quotas.
A parameter also used by another data node or returned as a graph output keeps its
original name, shape, generation and F32 bits. The original ONNX bytes and digest
remain available unchanged, and importer identity includes the new lowering source.

The retained synthetic fixture
`crates/fss-model-ir/tests/fixtures/onnx/detector_batch_normalization.onnx` is 857 bytes,
SHA-256 `d720a592cbecf7b95acac0bcdaf2cbabf401279f5fedc0166ad57669a983df1a`.
It runs a `[1,3,2,4]` convolution, unfused normalization, ReLU, reshape/transpose,
box/class split, sigmoid and concatenation into a `[1,8,6]` head. A second graph
output exposes normalization before the activation. Twelve native data nodes and
six F32 parameter tensors remain. Independent affine and sigmoid formulae check
both outputs before export and after actual canonical graph/Safetensors reload.

`cargo test -p fss-model-ir --test onnx_batch_normalization_execution` also checks
66 rank/channel/epsilon profiles against an independently rounded scalar oracle;
shared Constant parameters and signed-zero bits; subnormal statistics; arithmetic
order and overflow; namespace collisions; malformed, dynamic and training refusals;
exact node/tensor/parameter/work ceilings; every import cancellation checkpoint;
and native execution budgets, cancellation and generation checks. The InstanceNormalization
extension adds actual optimized execution to this shared host; that expanded target
awaits native validation as described below. It does not compile the
asynchronous reference crate, run complete package/CLI qualification, or establish
trained detector accuracy. The existing package importer automatically receives
this source profile through `import_onnx`, with its separate licensing,
preprocessing, named-output, head and admission contracts still required.

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
Reshape, Slice, Split, Resize, Pad, Expand and Tile enforce their own admission
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
native shape validation. Automatic padding uses the static resolver described above. Ceil mode,
dilated pooling and indices remain outside this profile.

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

## Nearest-neighbor spatial resampling

The importer admits static [Resize-13](https://onnx.ai/onnx/operators/onnx__Resize.html#resize-13)
for NCHW rank-four tensors, preserving batch/channel sizes while enlarging or shrinking
the spatial axes. Exactly one nonempty embedded F32 `scales` vector or INT64 `sizes`
vector supplies four values. Spatial scales must be finite and positive, at most 64,
and produce positive output dimensions; sizes must be positive and enlarge neither
axis by more than 64. Fractional factors, downsampling and opposite resize directions
on the two axes are supported. An omitted ROI or empty F32 ROI is accepted; nonempty
ROI and dynamic sizes/scales refuse. Empty optional input names and empty control
tensors remain compile-time values.

Two precise coordinate profiles are admitted: `asymmetric` with nearest mode `floor`,
and `half_pixel` with `round_prefer_floor` (the opset-13 defaults). The source F32 scale
is retained exactly: output length is `floor(input_length * scale)`, and coordinates
use that original scale, not a ratio reconstructed from the rounded output length.
For a sizes control, coordinates instead use the exact ratio `output_length / input_length`.
Checked integer rational arithmetic applies the coordinate transform and nearest
rounding without losing ties. `asymmetric/floor` selects `floor(x / scale)`;
`half_pixel/round_prefer_floor` rounds `(x + 0.5) / scale - 0.5` to the nearest integer,
with exact halfway cases selecting the lower index. Selected indices are clamped to
the input axis. Other nearest coordinate/rounding combinations and
`exclude_outside=1` refuse. Linear interpolation has the separate profile below;
cubic interpolation remains unsupported. Exporter-supplied finite
`cubic_coeff_a` and `extrapolation_value` attributes are validated but have no effect
under these admitted nearest profiles.

When both spatial scales are integers, the existing Reshape, two Concat nodes and final
Reshape remain byte-for-byte the same canonical graph. Other cases lower arithmetic
runs of selected indices to positive-stride Slice operators and join/repeat those runs
with Concat. A 480-by-640 to 240-by-320 nearest resize therefore needs two strided Slice
nodes. Integer axes in a mixed resize use a compact Reshape/Concat expansion; a shrinking
axis is applied first so the intermediate stays within the input/output byte envelope.
All paths preserve exact F32 bits, including signed zero and subnormals.

Each noninteger-scale axis admits at most 4096 output coordinates, with `Limit` returned
above that ceiling. This also applies to a sizes ratio that is not an integer; the
unchanged integer path does not acquire this new bound. Coordinate planning and every
helper consume the common work, node and tensor quotas. Complicated selection patterns
can reach the 512-node ceiling below 4096 coordinates. Output bytes are checked before
helper expansion, every intermediate retains the normal tensor byte limit, and helper
names are reserved against all source values. No new operator ID or runtime resampling
kernel is introduced. The importer identity includes the lowering and coordinate-planning
sources, and the original ONNX source is retained unchanged. Controls used only for resizing are removed
from execution weights; a scale vector also consumed by a runtime node remains present
and is exported.

`onnx_resize_execution` checks integer, fractional, shrinking and mixed-direction
scale/size/profile combinations against an independent coordinate-formula oracle after
actual graph/Safetensors reload and production scalar execution. Literal expected pixels
pin source-scale versus size-ratio differences, halfway rounding and adjacent F32 scales.
A Conv-to-Resize-to-dense-head case checks detector-style layout; other cases cover
exporter Constant nodes, shared data/control values, namespace collisions, preserved
integer canonical bytes, compact downsampling, resource boundaries and cancellation.

The dependency-free production coordinate planner also has a standalone native target.
It exhausts small size ratios using independent source-center distances, checks F32
scales against coordinate formulas and literal boundary pixels, expands the actual run
plans, and exercises exact admission/cancellation boundaries:

```sh
rustc +nightly-2026-08-31 --edition 2024 --test \
  crates/fss-model-ir/tests/resize_coordinates_standalone.rs \
  -o /tmp/fss-resize-coordinates
/tmp/fss-resize-coordinates
```

This target compiles the unchanged production planner. Complete graph lowering,
serialization and scalar execution are exercised by
`cargo test --locked -p fss-model-ir --test onnx_resize_execution`.

**Verification record (2026-11-06):** all six standalone coordinate-planner tests
passed with the pinned compiler before the execution environment became unavailable.
They cover all input lengths 1–24 and output lengths 1–64 under both profiles,
21 F32 scales over input lengths 1–32, literal ties, expanded run plans, limits,
and every planning cancellation checkpoint. The first complete model Cargo build
was killed in unchanged `fss-core`, before model diagnostics. The restored build
environment has now run all 17 tests in `onnx_resize_execution`, including full
graph/export/reload/scalar execution. One input fixture was explicitly typed F32
after native execution detected an inferred F64 tensor; production lowering was
unchanged.

After the outage, the source was recovered from recorded edits and complete review
snapshots. The tiny module/identity edits match their recorded final Git blob
identifiers, and the old integer lowering matches the original source. The recovered
production tree and corrected fixture now pass the complete native Model IR package
(278 tests before Pad was added), using pinned nightly `2026-08-31` and the unchanged
locked dependencies. These package results do not establish model-quality or
deployment qualification.

## Linear spatial resampling

Static NCHW `Resize-13` with an explicit `mode="linear"` admits bilinear feature-map
resampling using the same constant scales/sizes, preserved batch/channel dimensions,
optional empty ROI, source ordering and shape checks as nearest resampling.
Each output spatial dimension is at most **4,096**, including identity and integer
scales. All ordinary import ceilings still apply. This extends feature and decoder
graphs that interpolate intermediate activations before pooling or prediction.

The coordinate modes follow the [ONNX Resize-13 specification](https://onnx.ai/onnx/operators/onnx__Resize.html#resize-13).
Here `x` is an output coordinate, `I` the input length, `O` the integer output length,
and `s` the exact supplied scale (or the exact `O/I` ratio for a sizes control).

| Coordinate mode | Source coordinate |
|---|---|
| `half_pixel` | `(x + 0.5) / s - 0.5` |
| `pytorch_half_pixel` | The half-pixel formula when `O > 1`; otherwise zero |
| `align_corners` | `x * (I - 1) / (O - 1)` when `O > 1`; otherwise zero |
| `asymmetric` | `x / s` |

Coordinates clamp to `[0, I-1]`. The importer retains an original F32 scale exactly,
including when it produces the same integer output size as a different sizes ratio.
All coordinate and neighbor calculations use checked rational integer arithmetic.
The two complementary interpolation coefficients round separately, directly to
nearest-even F32 using integer arithmetic. A small period used to group indices is
only a planning hint: every selected source index still comes from its exact
coordinate, including decimal F32 factors near short rational ratios.

The lowering interpolates one spatial axis at a time. When one axis shrinks and
the other grows, the shrinking axis runs first; otherwise width runs before height.
For each interpolated axis the frozen arithmetic is a separate F32 multiplication
of each neighbor by its coefficient, followed by F32 addition. There is no fused
multiply-add or dense interpolation matrix. An axis whose coordinates are all exact
samples needs only selection, and a complete identity becomes one Reshape with no
generated weights. Those copy-only cases retain exact source bits, including
negative zero and subnormals. General interpolation follows the declared F32
operations; it is not a bitwise guarantee for backends with different rounding,
precision or operation order.

Neighbor selections use existing positive-stride Slice, Concat and Reshape
operators. Consecutive arithmetic runs and repeated samples share helpers.
When cheaper, the planner selects up to 64 residue classes, then interleaves them
with singleton dimensions and Concat/Reshape. These are compact index selections,
not materialized selection matrices. Mul and Add apply one-dimensional broadcast
coefficient vectors of shape `[1,1,O,1]` or `[1,1,1,O]`.

Generated coefficient storage is at most `8 * (output_height + output_width)` bytes,
independent of batch, channels and input area: at most 65,536 bytes for both axes.
For example, 80×80 to 160×160 interpolation uses 2,560 coefficient bytes, while
480×640 to 360×480 uses 6,720. Every intermediate tensor stays within the larger
input/output element count because of the axis order. Total execution allocations
and arithmetic across all helpers still consume the ordinary inference budget;
the per-tensor bound is not a claim about peak process memory.

The complete lowered node, named-value and generated-parameter costs are checked
before runtime tensors and helper names are constructed. Irregular selections can
exceed the unchanged 512-node global ceiling and refuse even below the coordinate
ceiling. Consumed source controls remain quota-charged alongside coefficients.
Bounded coordinate planning, coefficient creation and graph append operations retain
work and cancellation checks. Every helper and coefficient name is reserved against
all source names, including later source values.

`nearest_mode` has no numerical effect for linear interpolation, but any supplied
value must still be one of the four Resize-13 enum values and have the proper type.
Finite `cubic_coeff_a` and `extrapolation_value` attributes are validated but unused.
Cubic interpolation, nonempty ROI, `exclude_outside=1`, crop/extrapolation modes,
`tf_half_pixel_for_nn`, later-opset antialias/axes attributes and unknown attributes
remain explicit refusals. No native operator ID, canonical graph version, production
runtime dependency or model-activation authority changes. The new lowering/planner
sources participate in the source-bound importer identity; original ONNX bytes remain
intact.

**Validation status (2026-11-07): the published linear Resize implementation passed
native execution.** At source commit `edc1bb01247c341939a0fadbafdcb67f11537320`,
the pinned nightly completed 71 focused tests with zero failures: 25 Resize execution
cases (15 nearest and 10 linear), six nearest-coordinate cases, eight linear-coordinate
cases, 13 attention cases, 10 broadcast cases and nine leaky-activation cases. The
linear lowering required no semantic repair. These results precede the separate,
not-yet-executed InstanceNormalization addition documented above.

The ten cases in `onnx_resize_execution::linear` ran both unchanged production CPU
executors before and after real canonical graph/Safetensors reload.
They cover literal coordinate/singleton profiles, direct four-neighbor binary64
oracles across batches/channels and mixed axes, original scale versus size ratios,
exact copy-only bits, practical coefficient/helper bounds, all quota/cancellation
boundaries, source-name collisions, and a Conv → Resize → AveragePool → Gemm model.
The existing 15 focused nearest cases remain, including their historical integer
canonical-byte contract; the old linear-refusal fixture is replaced by these tests.
The standalone linear target adds six planner contracts and includes two production
coefficient-rounding tests, without replacing artifact or native executor coverage.

Reproduce the focused Resize checks with:

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-model-ir \
  --test onnx_resize_execution --test resize_linear_coordinates_standalone -- \
  --skip scalar_executor:: --skip optimized_executor::
rustc +nightly-2026-08-31 --edition 2024 --test \
  crates/fss-model-ir/tests/resize_linear_coordinates_standalone.rs \
  -o /tmp/fss-linear-resize-coordinates
/tmp/fss-linear-resize-coordinates
```

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
the exact ONNX parser, constants, static shape programs, structural, Split, Resize, Pad, Gemm and LeakyRelu lowering,
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

The execution counts below retain their earlier validation scope. They do not
include the fractional Resize additions; its dated verification record is above.

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
