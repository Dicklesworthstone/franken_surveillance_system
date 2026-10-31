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
