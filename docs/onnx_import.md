# Offline ONNX graph import

This implements part of **FSS-138 / WP-080** (deterministic model import), not the
complete model qualification or activation gate. The library converts an explicitly
supplied, digest-pinned source into the existing frozen Model IR and native tensors.
It does not run ONNX Runtime, Python, a foreign model server, or model-supplied code.

## Entry point

`fss_model_ir::import_onnx(source, expected_sha256, generation, limits, cancelled)`
returns `ImportedOnnx`, with the original borrowed source, verified source digest,
validated native graph, embedded parameters, runtime input names, and charged import
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
- Add, Sub, Mul, Div, Relu, Sigmoid, Tanh, MatMul, Softmax, Conv, MaxPool, Transpose,
  Concat, Identity and Flatten. Identity/Flatten lower to checked native Reshape
  nodes without changing the frozen operator set or canonical Model IR v1 encoding.
- MatMul requires rank-two-or-higher inputs. Conv is 2-D; declared `kernel_shape`
  must agree with the actual weight tensor. Explicit strides, dilation, pads and
  groups use native validation. `auto_pad`, when present, must be `NOTSET`.
- MaxPool is 2-D, single-output, with zero padding, no dilation other than one,
  no ceil mode, and default storage order. Concat requires an explicit axis.
  Softmax uses opset 13's last-axis default, without the older flattening behavior.

Unknown features refuse rather than being skipped or approximated. In particular,
Gemm, arbitrary Reshape shape inputs, Constant nodes, BatchNormalization, Resize,
other opsets/domains/dtypes, symbolic or zero-sized shapes, sparse data, external
weight files, custom functions, training graphs and model activation are not
implemented by this profile. Initializers that are also graph inputs refuse rather
than silently freezing an overridable weight. An unused initializer cannot be made
executable merely by mentioning it in value-info metadata.

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
  crates/fss-model-ir/src/onnx.rs crates/fss-reference/tests/onnx_import_execution.rs
```

The ONNX-specific tests cover source preservation, numeric execution, signed zero,
raw/packed parameters, Conv kernel declarations, shape-only lowering, Softmax axis
semantics, duplicate/overridable/unused parameters, intermediate shape mismatch,
nonfinite data, exact resource limits, generation fencing, cancellation, every
truncated prefix of a valid model, and bounded generated malformed wire inputs.

These fixtures establish the tested conversion and native execution contracts only.
They do not qualify a trained detector, establish framework-wide numerical parity,
authorize redistribution of model weights, publish/activate a model, or claim event
quality, calibrated threat probabilities or absence of activity. CLI provisioning,
a broader exporter/model corpus, license-backed packages and local DSR qualification
remain separate work. The existing Safetensors and canonical-graph import paths are
unchanged.
