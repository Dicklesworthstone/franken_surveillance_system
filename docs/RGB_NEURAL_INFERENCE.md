# Native RGB neural inference from explicit source weights

`fss_reference::ingest::rgb_inference` connects native JPEG color decoding to
source-space privacy projection, existing RGB resizing/letterboxing, and the
existing F32 scalar Model IR executor. It does not use mock labels or substitute
luminance for color. `model_import::rgb` loads exact Safetensors parameters into
this lane without changing the existing luma recorded-model format.

This delivers numerical graph execution, not a bundled trained person detector.
A model's operator subset, preprocessing, head interpretation, license and
held-out quality still require separate admission. There is no generic ONNX or
Python graph converter, model download, accelerator runtime, camera driver,
tracker mutation, canonical publication or alert dispatch in this module.

## Two model construction paths

`RgbInferenceModel::new` accepts a validated/authored `ModelIrGraph`, a complete
`BTreeMap<String, Vec<f32>>` of named parameter values, `RgbModelSpec`, and the
caller-owned `ScalarExecCx`. The single image port must be exactly
`[1, 3, target_height, target_width]`. Every other input has an exact F32 parameter
binding with the declared shape. Missing, extra, malformed and nonfinite inputs
are refused; weights are never randomized, guessed, downloaded or zero-filled.

For a weight file, use `model_import::rgb::ImportedRgbModel::build` with:

- canonical FSS graph bytes and an independently expected digest;
- original Safetensors bytes and an independently expected digest;
- an explicit graph-port to tensor-name mapping, or empty for name equality;
- RGB preprocessing, an explicit F32/F16/BF16 conversion policy and resource limits;
- the existing `ImportBudget`, `ReplayCx`, and `ScalarExecCx` owners.

The existing bounded Safetensors parser validates the entire header and contiguous
data region, including duplicate keys, shapes, offsets, holes, overlaps and hidden
suffixes. Every source tensor must be referenced. Multiple graph ports may share
one source tensor only through explicit mappings, with expanded bytes counted for
every binding. F16 and BF16 are admitted only with `ExpandFloat16`; their finite
values expand exactly into F32. Nonfinite values always fail.

`ImportedRgbModel` retains the complete original graph/weight byte slices by
borrowing them from their owner, plus exact digests, bindings, conversion policy,
expanded-byte count and source/recipe/model identity. `model()` returns the frozen
model for immediate execution. This borrowing is not disk custody. Keep or publish
those original source objects through the existing authorized storage interfaces.

The original luma import and recorded-model formats are not widened or reinterpreted.
Adding the public RGB import module changes the source-bound luma importer profile;
old source-profile-pinned import bundles therefore need re-import from their retained
original sources. This is not a claim that old-profile verification is unchanged.

## Execution

The primary path is:

```text
ImportedRgbModel::model() or RgbInferenceModel
  -> run_jpeg(complete JPEG, explicit interpretation, source binding, mask, limits,
              decoder budget, scalar context)
  -> native RGB reconstruction
  -> denied decoded-pixel values replaced with the frozen masked_rgb constant
  -> existing nearest/bilinear RGB resize and optional letterbox
  -> NCHW F32 normalization
  -> exact frozen graph and parameter tensors
  -> existing ScalarExecutor
  -> complete finite output tensors plus source/transform/implementation digests
```

`run_decoded` takes an actual opaque `DecodedRgb` from the native decoder instead
of decoding again. Its JPEG decode limits apply only to `run_jpeg`; the previously
completed decode remains governed by its original receipt and caller ownership.

`RgbSourceBinding` preserves original exposure, camera, clock, uncertain capture
interval, calibration, coded image domain, complete encoded digest and exact
source-grid 0/1 mask digest. These are owner-supplied declarations, not grants or
independent camera authentication. No capture interval is replaced with wall time.

Privacy masking precedes interpolation, normalization and model evaluation.
Changing denied decoded-pixel values cannot alter the masked model input. The
unrestricted decode hash stays distinct from the masked-input hash, so privacy
projection does not erase original source lineage. This guarantee is about
reconstructed pixels, not a claim that lossy JPEG coefficients encode independent
pixels. Fully masked images produce the configured fill; their numerical outputs
do not establish scene absence, coverage or permission to disclose.

The exact `ResizeGeometry` is returned. Its existing `source_box()` method reverses
model-image scaling and letterboxing, clips padding, and refuses padding-only or
empty boxes. There is no automatic interpretation of graph outputs as detections;
model-head decoding and any calibrated class semantics remain separate.

## Limits, ownership and identity

The model contract bounds canonical graph plus F32 parameter bytes to 16 MiB,
1024 graph nodes, 257 inputs including the image, 256 outputs, and a 4,194,304-pixel
RGB target. The complete output-value set is bounded separately to 16 MiB. The
source-weight path also enforces its existing caller-narrowable import ceilings.

`RgbRunLimits` separates native decode limits, mask/resize work and logical buffer
limits, executor operations/cumulative tensor allocation, and complete output
bytes. The latter are separate accounting domains, not a single peak-process-
memory or real-time throughput guarantee. Limits never authorize truncation.

The decoder and scalar contexts are supplied by the caller. Share the decoder's
cancellation flag with its owning task; scalar cancellation is additionally
checked before/after decoding and throughout masking, resize and graph execution.
No thread, async runtime, network access or background task is created here.

Model identity binds graph, exact parameter bits, preprocessing, mask fill, and
source implementation profiles. Run identity also binds original source/mask,
actual RGB decode, masked image, normalized input and complete output tensors.
Changing numerical budgets does not change a successful result identity. Errors
return no partial numerical result and mutate no ledger, tracker or active model.
These are local derivation identities, not new durable schemas or release proof.

## Validation and remaining qualification

Fifteen authored Rust tests exercise actual JPEG -> RGB -> Conv2d -> Sigmoid,
chroma sensitivity, masking noninterference, full denial, inverse letterboxing,
exact model parameters/identity, source and resource failures, cancellation,
Safetensors F32/F16/BF16 loading, explicit name maps, and import retries.
The numeric convolution weights are explicit fixtures, not trained detection
weights and not a perception-quality evaluation.

Rust compilation, tests, rustfmt and Clippy were not run: the authoring environment
has no Rust toolchain. Independent Python transcriptions were compared against
installed PyTorch over 200 resize/convolution/activation cases, with maximum
normalized resize difference below 5e-7, exact tested convolution agreement, and
sigmoid difference below 6e-8. Another 200 masked-pixel perturbation cases produced
identical projected inputs. These checks do not substitute for Rust execution,
full-repository qualification, pretrained-model evaluation or real-camera testing.
