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
