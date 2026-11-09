# Explicit ONNX package wiring fixture

`tiny_detector.onnx` is an authored, self-contained ONNX IR 8 / opset 13 graph with finite
embedded F32 tensors. It is test data, not a trained detector or a quality oracle.

The graph has one RGB input `image` shaped `[1,3,1,1]`. `Flatten` with default axis 1 creates
`flat` `[1,3]`; `MatMul` with 18 zero weights shaped `[1,3,6]` creates `raw` `[1,1,6]`;
`Add` with bias `[0,0,1,1,0.9,0.1]` creates `head` `[1,1,6]`. The two scores select class 0
under the supplied recipe's explicit 0.5 threshold; the pixel-corner box covers the model grid.
This makes native retained-JPEG/package integration independent of the chosen image pixels.

`recipe.json` declares every preprocessing, head, generation, provenance and license choice.
The exact local license and notice are retained in the resulting FMPK alongside the original
ONNX. The source's producer text and graph name identify it as an FSS numerical fixture.
Tests independently pin all files, reopen the complete archive and verify source closure.

A complementary input-dependent RGB graph in
`crates/fss-model-ir/tests/fixtures/onnx/rgb_dense_head.onnx` exercises numerical batched
execution after canonical-graph/Safetensors export, with explicit nonzero weights.

## Channel-normalization fixture

`normalization_detector.onnx` is a separate, pixel-dependent ONNX IR 8 / opset-13 fixture
(484 bytes, SHA-256 `4ab4d26e5635ff624d1230095ae640b56e0173188f69a23b5ab62b70d701ea5c`).
Its `image` input has shape `[1,3,2,2]`. One Identity branch exposes `model_pixels` under its
own output name. A second branch evaluates GlobalAveragePool, Flatten, MatMul and Add,
producing `head` `[1,1,6]`. This proves the conversion rewires both image-consuming branches.

The three rows of its `[1,3,6]` F32 weights are:

```text
[0, 0, 0, 0, 0.125, 0]
[0, 0, 0, 0, 0, 0.125]
[0, 0, 0, 0, 0.0625, -0.0625]
```

The `[1,1,6]` bias is `[0,0,2,2,0.6,0.4]`. All three normalized channel means affect
the scores; the four box fields describe the complete 2x2 model grid. Decimal initializers
are rounded to their F32 representations. The source carries the producer text
`FSS numerical fixture, not trained detector` and graph name
`fixture:onnx-normalized-detector`.

`recipe_v2.json` declares BGR, unit scaling, means `[0.1,0.2,0.3]` and standard deviations
`[0.25,0.5,0.75]` in that BGR order. The source graph itself has no such preprocessing.
The independent native tests first construct normalized pixels from explicit RGB bytes,
then compute row-major spatial means and the declared matrix/bias. They compare exact F32
bits after graph and Safetensors export/reload. Package tests additionally cover native head
projection and privacy substitution before normalization. This remains numerical wiring
evidence, with no claim of detector quality or suitability for surveillance.

## Raw DFL detector fixture

`raw_dfl_detector.onnx` is an original, pixel-dependent ONNX IR 8 / opset-13 numerical
fixture (1900 bytes, SHA-256
`142825f5bcd12d5d830bed123306820af1b73772d9a319ab6cc5c25acb40d76b`). It contains no trained
weights or external tensors. Its producer is `FSS raw DFL numerical fixture, not trained
detector`; its graph name is `fixture:onnx-raw-dfl-detector`.

Construction: the F32 `image` input `[1,3,4,4]` passes through GlobalAveragePool and Flatten
to `embedding` `[1,3]`, then MatMul with `weights` `[1,3,90]`, Add with `bias` `[1,1,90]`,
and Reshape with the INT64 control `head_shape = [1,5,18]`. Both `raw_head` `[1,5,18]`
and `embedding` are declared outputs. The original ONNX contains no head decoder.

For row `r` in `0..5`, side `s` in `0..4` (left, top, right, bottom), and spatial RGB means
`m[0..3]`, the first sixteen fields contain four contiguous groups of four bin logits:

```text
raw[r, 4*s + 0] = 0
raw[r, 4*s + 1] = 0.5 * m[s % 3]
raw[r, 4*s + 2] = 0
raw[r, 4*s + 3] = -0.25 * m[(s + 1) % 3]
raw[r, 16] = [0.85, 0.75, 0.65, 0.55, 0.45][r] + 0.05 * m[0]
raw[r, 17] = 0.1 + 0.05 * m[2]
```

To construct the matrix, initialize all 270 weights and 90 biases to zero, then place each
coefficient at `weights[channel, r*18 + field]` and each constant at `bias[r*18 + field]`
according to those equations. Coefficients and biases are stored as F32; MatMul accumulates
channels in RGB order before Add applies the bias. The source has finite embedded F32
initializers and one embedded INT64 shape control.

`recipe_v3.json` supplies explicit RGB/unit preprocessing with zero means and unit standard
deviations, then declares four DFL bins, raw row layout, and ordered strides `[2,4]` over the
4x4 input. The first level has four cells and the second has one. Conversion retains the
original raw output and appends `decoded_head` `[1,5,6]` with pixel corners and the unchanged
two score fields. Zero RGB makes every side uniform, giving exactly 1.5 bins; nonzero RGB
changes both geometry and scores. The package tests check exact uniform-case corners, source
retention, score-bit preservation, existing NMS, and privacy replacement/footprint screening.
This fixture demonstrates the declared numerical pipeline and makes no model-quality claim.

## Separate boxes and class scores fixture

`split_head_detector.onnx` is an original ONNX IR 8 / opset-13 numerical fixture
(1060 bytes, SHA-256
`9f38352f183e7f2f4748e254a29d121e3f3531c9137dce2750095b009e7d1f29`).
Its embedded finite F32 weights are authored test data, not trained
weights. The producer is `FSS split-head numerical fixture, not trained detector`;
the graph name is `fixture:onnx-split-head-detector`.

The input `image` is `[1,3,2,2]`. GlobalAveragePool and Flatten produce the declared
`embedding` output `[1,3]`. Two independent branches use MatMul, Add and Reshape:

| Branch | Matrix | Bias | INT64 reshape control | Declared output |
|---|---|---|---|---|
| Boxes | `[1,3,8]` | `[1,1,8]` | `[1,2,4]` | `boxes`, rows layout |
| Scores | `[1,3,6]` | `[1,1,6]` | `[1,3,2]` | `scores`, channels layout |

Initialize both matrices to zero, then set the following nonzero coefficients,
where `w[channel,field]` indexes the trailing two dimensions:

```text
box_weights[0,0] =  0.0625
box_weights[1,4] = -0.0625
box_weights[2,2] =  0.03125
score_weights[0,0] =  0.0625
score_weights[0,5] = -0.0625
score_weights[1,1] = -0.0625
score_weights[1,4] =  0.0625
score_weights[2,2] =  0.03125
score_weights[2,3] = -0.03125
box_bias   = [0.25, 0.5, 0.5, 1.0, 0.75, 0.5, 0.5, 1.0]
score_bias = [0.125, 0.875, 0.99, 0.99, 0.875, 0.125]
```

MatMul accumulates the three channel products in order; Add then applies the bias.
All decimal values are stored as F32. The score order is class0/row0, class0/row1,
class1/row0, class1/row1, class2/row0, class2/row1. Both reshape controls use embedded
little-endian INT64 values; all learned-data tensors use embedded little-endian F32.

`recipe_v4.json` declares unit-scaled BGR input, zero means, unit standard deviations,
and public RGB replacement `[51,102,153]` for denied pixels. It assembles the box rows
with class columns `[2,0]` into `assembled_head` `[1,2,6]`, preserving all three
source outputs. Labels are explicitly `fixture-class-two`, then `fixture-class-zero`.
Coordinates mean normalized center/size and scores mean probabilities. Zero RGB yields
one left-half box for label zero and one right-half box for label one, both with score
0.875. The higher-valued source column one is deliberately excluded; no automatic
background convention is used.

The exact fixture passed native import, BGR transformation, split-head assembly, actual
scalar and optimized execution, and canonical-graph/Safetensors reload on the pinned
toolchain. Independent zero and nonzero pixel/matrix equations check all original and
assembled outputs. This case is part of the passing 31-case native integration target,
including ten split-head cases; it does not establish model quality.

The additional full package/CLI tests are authored for exact source/archive reopening,
class-map identity, one-time logit handling, privacy replacement/footprint refusal,
strict recipe admission and exact recipe-byte receipts. Those tests remain unexecuted
because the full reference dependency build was killed in Asupersync. Pinned rustfmt
and strict recipe/schema validation passed; native fixture execution does not replace
the pending full-package integration gate.
