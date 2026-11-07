# Import an ONNX detector for native inference

`fss-infer import-onnx` converts an explicitly pinned local ONNX model into the existing
RGB detector FMPK format. The resulting package is consumed directly by
`fss-infer package-detect`, including its sentinel sampling options, and by the existing
package-based recording workflows. Importing does not install or activate a model.

This closes the provisioning path between the bounded general ONNX importer and the
existing detector-package loader. The specialized, pinned opset-11 YOLOX-Nano converter
remains a separate importer; this command does not reinterpret that model as opset 13.

## Inputs and command

All four inputs are local, bounded regular files. Supply independently checked SHA-256
identities for the ONNX source, recipe, upstream license text and attribution notice:

```sh
fss-infer import-onnx \
  --source detector.onnx --source-digest sha256:SOURCE_HEX \
  --recipe detector-recipe.json --recipe-digest sha256:RECIPE_HEX \
  --license LICENSE --license-digest sha256:LICENSE_HEX \
  --notice NOTICE --notice-digest sha256:NOTICE_HEX \
  --output detector.fmpk
```

Replace the digest placeholders with the complete 64 hexadecimal digits. Use the upstream
release identity to establish the source pin; calculating a digest alone does not establish
authenticity or permission to use a model. An empty notice file is permitted when appropriate
for the upstream license, but it still has an explicit digest.

The command validates all inputs and reopens the complete package through
`RgbDetectorPackage::load` before opening the output. It creates a new file, uses mode 0600
on Unix, synchronizes it, and refuses to overwrite any existing file or symlink. A filesystem
failure during the final write can leave a partial new file; the command reports failure.
No deployment directory is needed or modified.

On success, stdout contains one `fss.onnx_rgb_package_import.v1` JSON object naming the exact
source, recipe, package, manifest, model, head-contract and importer digests, archive bytes
and cumulative conversion work. `activated` and `calibrated` are both false. Use its package
digest with the existing inference command:

```sh
fss-infer package-detect \
  --root deployment --site site:example \
  --import-id sha256:RETAINED_IMPORT_HEX --first-segment 0 --frames 1 \
  --interpretation ycbcr \
  --package detector.fmpk --package-digest sha256:PACKAGE_HEX
```

The source recording must already be retained through the existing file or camera import
workflow. The imported package follows the existing privacy masking, RGB conversion,
head decoding, source linkage, retention and event rules.

## Complete explicit recipe

The following recipe accompanies the tiny numerical fixture at
`crates/fss-reference/tests/fixtures/onnx_package/`. It illustrates every required field;
its constants are test data, not a trained object detector. Real models require their
own exact preprocessing, decoded head, labels, immutable generations and license decision.

```json
{
  "format": "fss.onnx_rgb_package_recipe.v1",
  "model_id": "MOD-ONNXFIXTURE-001",
  "model_generation": "model:onnx-detector-fixture:g1",
  "tensor_generation": 1,
  "preprocess": {
    "image_input": "image",
    "height": 1,
    "width": 1,
    "resize": "nearest",
    "letterbox_pad": 0,
    "masked_rgb": [0, 0, 0],
    "scale_to_unit": false
  },
  "head": {
    "output_port": "head",
    "layout": "rows",
    "boxes": "pixel-corners",
    "class_score": "probability",
    "objectness": "none",
    "classes": "best",
    "minimum_score_ppm": 500000,
    "nms_iou_ppm": 450000,
    "maximum_rows": 1,
    "maximum_candidates": 4,
    "maximum_detections": 4
  },
  "labels": ["fixture-object", "fixture-other"],
  "source": {
    "upstream": "fixture:fss/native-onnx-detector",
    "revision": "v1",
    "producer": "FSS test-only numerical fixture"
  },
  "license": {
    "id": "MIT",
    "use_approved": true,
    "restrictions": []
  }
}
```

Every shown field is required. Unknown or duplicate keys, trailing input, invalid UTF-8,
wrong types and out-of-range integers are refused. `source.producer` is an explicit operator
description; the importer does not authenticate upstream producer metadata. The complete
original ONNX metadata remains in the retained source artifact.

| Setting | Admitted values and meaning |
| --- | --- |
| `tensor_generation` | Nonzero native graph/tensor generation; separate from the immutable deployment model generation. |
| Image input | Exactly one runtime input, F32 `[1,3,height,width]`; every other input has a complete parameter binding. |
| `resize` | `nearest` or `bilinear`, with centered aspect-preserving letterboxing. |
| `scale_to_unit` | `true` maps RGB bytes to `[0,1]`; `false` keeps `0..255`. Recipe v1 adds no mean/std or channel reversal; v2 requires those choices explicitly. |
| `masked_rgb` | Three public byte constants replacing denied source pixels before interpolation. |
| `layout` | `rows` for `[1,rows,fields]`, or `channels` for `[1,fields,rows]`. |
| `boxes` | `pixel-corners`, `pixel-center-size`, `normalized-corners`, or `normalized-center-size`. Boxes must already be decoded. |
| `class_score` | `probability` or `logit`; the existing head contract determines score arithmetic. |
| `objectness` | `none`, `probability`, or `logit`. A present objectness field follows the four box fields. |
| `classes` | `best` or `multi-label`, preserving the existing complete candidate/NMS bounds. |
| Labels | Ordered, unique, nonempty class names. Head width must equal `4 + objectness + labels`. |
| License | Explicit approval and restrictions are checked by the existing surveillance-monitoring license policy. Setting a flag does not override that policy. |

The selected head must be an actual declared graph output with batch one, rank three,
matching field count and a row count within the explicit ceiling. Incompatible metadata
is refused during packaging, before any source recording is read.

## BGR and per-channel normalization: recipe v2

Models that expect BGR input or per-channel mean/std normalization can use the same native
package and detection commands. Set `format` to `fss.onnx_rgb_package_recipe.v2` and add
exactly these three required fields to `preprocess`: `channel_order`, `mean`, and
`standard_deviation`. Every other recipe field keeps its v1 meaning. For example:

```json
{
  "image_input": "image",
  "height": 2,
  "width": 2,
  "resize": "nearest",
  "letterbox_pad": 0,
  "masked_rgb": [0, 0, 0],
  "scale_to_unit": true,
  "channel_order": "bgr",
  "mean": [0.1, 0.2, 0.3],
  "standard_deviation": [0.25, 0.5, 0.75]
}
```

This is the complete `preprocess` object for the pixel-dependent numerical fixture
`crates/fss-reference/tests/fixtures/onnx_package/normalization_detector.onnx`; its complete
recipe is `recipe_v2.json` in that directory. These numbers demonstrate arithmetic and
do not specify preprocessing for a trained detector. Supply the exact conventions from
your model's training/export contract.

The operation order is fixed:

1. Replace denied **source RGB pixels** with `masked_rgb` before interpolation.
2. Apply the existing RGB resize and centered letterbox, including `letterbox_pad`.
3. Apply the existing optional scale: `F32(pixel) * (1.0_f32 / 255.0_f32)` when enabled.
4. Preserve RGB for `channel_order: "rgb"`, or select B, G, R for `"bgr"`.
5. For each model-input channel, evaluate **`(x - mean[channel]) / standard_deviation[channel]`**
   with separate F32 subtraction and division.

Mean and standard deviation follow the **model's selected channel order** and the units
chosen by `scale_to_unit`. With the example above, the first pair `(0.1, 0.25)` applies to
blue after unit scaling; the third pair applies to red. Mask colors always remain RGB bytes.
Letterbox padding receives the same channel ordering and normalization as image pixels.

Only the two declared channel orders are supported. Arrays must contain exactly three JSON
numbers; decimal and exponent forms round directly to F32. Strings and booleans do not count
as numbers. Means must be finite, and standard deviations must be finite and strictly positive
after rounding, including refusal of negative zero and positive decimals that underflow to
zero. Packaging refuses normalization that overflows at either end of the selected RGB
input interval. The source model's own numerical behavior remains subject to the existing
finite-output checks.

The converter freezes BGR selection as three native Slice nodes plus Concat, and normalization
as Sub followed by Div with two exact `[1,3,1,1]` parameter tensors. It rewires every source
node consuming the declared image input, preserving branches and auxiliary outputs. It does
not fold normalization into convolution weights or replace division with reciprocal weights.
A source graph that directly exposes its image input as a graph output is refused for this
transform because the unchanged input/output name would alias raw and normalized values;
an ordinary Identity node producing a separately named output is supported.

The added operators, values, parameter bytes and conversion work count against the same
cumulative import limits, including source shape controls already consumed during import.
RGB normalization adds two nodes; BGR normalization adds six. Both add 24 parameter bytes.
No native operator, package wire format or inference runtime dependency is added.

The strict v1 recipe remains accepted and follows its original graph path. It rejects v2-only
fields. V2 requires all three new fields even for identity normalization; choose RGB,
`mean: [0,0,0]`, `standard_deviation: [1,1,1]` explicitly when that is the model contract.
The schemas are `schemas/onnx_rgb_package_recipe.v1.json` and
`schemas/onnx_rgb_package_recipe.v2.json`.

## Raw anchor-free DFL distance heads: recipe v3

Some model exports retain a distribution over distances to each box side, instead
of four decoded box coordinates. Recipe `fss.onnx_rgb_package_recipe.v3` adds an
explicit static decoder for that profile. It retains every v2 preprocessing
choice and adds one required top-level object:

```json
"head_decode": {
  "kind": "anchor-free-dfl",
  "raw_output": "raw_head",
  "raw_layout": "rows",
  "bins": 16,
  "strides": [8, 16, 32]
}
```

This is an illustrative grid declaration, not a convention inferred from a model
name. `head.output_port` must name a **new, distinct** decoded output. Set the
existing `head.layout` to `rows` and `head.boxes` to `pixel-corners`. Every other
score, objectness, label, threshold, NMS and detection-limit choice keeps its
existing explicit meaning. V1 and v2 reject `head_decode`; v3 requires it and all
v2 channel-normalization choices, even when normalization is the identity.

### Exact tensor and grid contract

Let `B` be `bins`, `S` the label count plus one if objectness is present, and `N`
the sum of all declared feature-grid cell counts.

| Tensor | Shape and field order |
|---|---|
| Raw `rows` | `[1, N, 4*B + S]` |
| Raw `channels` | `[1, 4*B + S, N]` |
| New decoded output | `[1, N, 4 + S]` |
| Raw coordinate groups | `B` left logits, `B` top logits, `B` right logits, `B` bottom logits |
| Score tail | Optional objectness followed by the ordered class values, preserved unchanged |
| Decoded coordinates | `x_min, y_min, x_max, y_max` in model-input pixels |

There are 2–32 bins and 1–8 unique positive integer strides, each at most 4,096.
The model input height and width must be positive, at most 4,096, and divisible
by every stride, with at most 4,194,304 pixels. Counts and strides use plain JSON
integer literals; decimal-string, fractional and exponent spellings refuse. For
stride `s`, the level contributes `(height/s)*(width/s)`
rows, with at most 32,768 rows overall and no more than `head.maximum_rows`.
Levels follow the **declared stride order**, with `y` outermost and `x`
innermost within each level. Strides are never silently sorted.

A cell's pixel center is `((x + 0.5)*s, (y + 0.5)*s)`. These exact half-cell
centers and per-row strides become immutable F32 parameters. Missing levels,
different row counts, unsupported layouts, duplicate strides, empty/malformed
names or an occupied decoded-output name refuse conversion. The raw port must
be an actual declared output of the admitted source graph. All other source
outputs remain intact.

### Native arithmetic and score handling

For each of the four coordinate groups, the graph evaluates a native Softmax
across the `B` logits, then a native MatMul against the constant bin indices
`[0, 1, ..., B-1]`. This computes the expected distance in feature-cell units.
The graph then performs separate F32 operations in this order:

```text
distance_pixels = expected_bin * stride
x_min = center_x - left_distance_pixels
y_min = center_y - top_distance_pixels
x_max = center_x + right_distance_pixels
y_max = center_y + bottom_distance_pixels
```

The multiplication precedes the final subtraction/addition; the converter does
not reassociate these expressions. The bin reduction follows the existing
native MatMul's F32 order. Tests use exact uniform controls and an independent
higher-precision softmax/distance oracle. This establishes the admitted native
arithmetic, not bitwise equivalence to every external tensor backend.

The expectation interpretation follows the DFL integral described in the
[Generalized Focal Loss paper](https://arxiv.org/abs/2006.04388) and the
[official DFL module reference](https://docs.ultralytics.com/reference/nn/modules/block/#ultralytics.nn.modules.block.DFL).
This conversion admits the explicitly declared tensor/grid profile above; it
is not a general claim that every model from either architecture imports.

The decoder does **not** apply sigmoid to scores, invent objectness, reorder
labels, perform NMS or apply a threshold. It copies the complete score tail.
The existing `head.class_score` and `head.objectness` select probability versus
logit interpretation once, and the existing package detector performs source
projection, privacy handling, candidate limits and NMS. Models whose scores
already contain sigmoid should continue to declare `probability`.

### Packaging, provenance and bounds

Image privacy replacement, resize, unit scaling and v2 normalization run before
the source graph. The DFL decoder runs after its selected raw output. Existing
native Transpose, Slice, Reshape, Softmax, MatMul, Mul, Sub, Add and Concat
operators express the complete conversion; no new operator, foreign runtime,
network access or FMPK wire format is introduced.

The original ONNX bytes, original output names and source parameter bits remain
retained. The additional decoded output, all grid/bin constants and exact
arithmetic become part of the graph/weights/model identity. A new conversion
uses the current source-bound importer identity. Existing packages remain
readable under their existing contract.

All generated nodes, tensor names, parameters and work share the original
import ceilings, including source controls consumed during import and any
preceding normalization. Grid counts and allocation sizes are checked before
construction. Insufficient quotas or cancellation return no partial converted
graph or successful package. The decoded row count must fit the existing
`head.maximum_rows`; all package/license/backend verification still completes
before a new output file is opened.

The original numerical fixture `raw_dfl_detector.onnx` and `recipe_v3.json` use
4×4 model input, four bins, strides `[2,4]`, five raw rows and two class scores.
Its raw logits and scores depend on authored nonzero RGB weights. It is an
arithmetic and integration fixture, not a trained detector or quality claim.
The schema is `schemas/onnx_rgb_package_recipe.v3.json`.

Unsupported raw anchors, learned/custom grid offsets, nonuniform bin centers,
rotated boxes, dynamic grids, batches other than one and unrelated YOLO head
parameterizations remain explicit refusals. Already-decoded boxes continue to
use v1 or v2 recipes without a DFL conversion.

## Admitted model profile and bounds

The command uses the existing ONNX IR 7–9, default-domain opset-13 static finite F32 profile.
Supported operators and their restrictions are specified in [onnx_import.md](onnx_import.md):
Add, Sub, Mul, Div, Relu, LeakyRelu, Sigmoid, Tanh, MatMul, Gemm, Softmax, Conv, BatchNormalization,
MaxPool, AveragePool, GlobalAveragePool, Transpose,
Concat, Constant, Reshape, Squeeze, Unsqueeze, Slice, Split, Resize, Expand, Tile,
Gather, ReduceMean, Identity and Flatten.
Bounded static Shape/Gather/INT64 control programs can supply layout and partition controls;
their values are evaluated during import and never require runtime integer execution.
Runtime/data-dependent shapes, external tensors, custom operators, raw detector-head
profiles outside the explicit v3 DFL contract and unsupported operators refuse explicitly. The command does
not claim that an arbitrary ONNX detector can be imported.

LeakyRelu accepts the default F32 alpha `0.01` or a finite alpha in `[0, 1]`.
Its exact native lowering adds five nodes and one scalar, with a temporary
containing twice the input elements; alpha one uses a single Reshape. Existing
import limits still apply. See [exact leaky activations](onnx_import.md#exact-leaky-activations)
for signed-zero, rounding, admitted-rank and source-identity semantics.

Static Expand and Tile accept rank-one INT64 shape/repetition controls from
constants or bounded shape programs. Expand uses multidirectional broadcasting,
including lower-rank targets; Tile repeats complete axis blocks with one positive
repeat count per input axis. Both preserve exact F32 bits through existing
Reshape/Concat operators and use logarithmic helper counts, subject to the
ordinary graph, tensor, work and inference allocation limits. Zero-sized results
and runtime controls refuse. See [static expansion and tiling](onnx_import.md#static-expansion-and-tiling).

Static F32 Gather and ReduceMean add packed attention selection and pooled
feature heads. Gather accepts bounded constant scalar/vector indices and copies
selected samples exactly. ReduceMean uses deterministic row-major F32
accumulation followed by division; finite inputs can overflow the intermediate
sum, and this is not a higher-precision ONNX mean guarantee. Both use existing
native operators, bounded helpers and ordinary resource limits. All thirteen
attention contracts now pass in the restored workspace, including real scalar
and optimized execution, graph/weight reload and empty-axis protobuf encodings.
This does not establish a trained model's quality or deployment qualification. See
[static attention selection and pooled features](onnx_import.md#static-attention-selection-and-pooled-features)
for the numerical and shape profile, controls, artifact identity and validation scope.

Conv, MaxPool and AveragePool can use static `VALID`, `SAME_UPPER` or `SAME_LOWER`
automatic padding. The importer freezes the exact spatial pads into the native
graph, including Conv dilation and the declared odd-pad placement. An automatic
mode combined with explicit `pads` refuses. The existing pooling restrictions,
output-shape checks and import limits remain in force; see
[automatic spatial padding](onnx_import.md#static-automatic-spatial-padding).

Default source and parameter limits are 16 MiB each. Export additionally limits the canonical
graph to 16 MiB, complete Safetensors to 16 MiB, its JSON header to 256 KiB and the parameter
count to 256. Original source plus exported graph and weights are bounded together. Each
license/notice file is at most 256 KiB; the recipe is at most 1 MiB. The complete FMPK must
fit the existing 32 MiB RGB-package ceiling, including the retained original source.

Import work defaults to 134,217,728 units; the export ceiling of 268,435,456 units includes
work already spent importing. The existing package verifier has a separate default
4,294,967,296-unit allowance. `--import-work-units`, `--export-work-units`,
`--verification-work-units` and `--max-package-bytes` set these explicitly. These are
deterministic operation allowances, not hardware MAC counts, peak RSS or wall-clock promises.

## Source retention and compatibility

The existing FMPK archive contains six artifacts:

- `source.onnx`: the exact input bytes, including original metadata;
- `graph.fssir`: the unchanged canonical Model IR v1 format;
- `weights.safetensors`: all exact finite F32 initializers and generated lowering parameters;
- `package_spec.bin`: the existing RGB preprocessing/head/provenance contract;
- `LICENSE` and `NOTICE`: the exact supplied attribution documents.

The existing manifest binds every artifact, the immutable model generation, license decision
inputs and the explicitly uncalibrated calibration generation. A separate source-bound
importer identity includes the ONNX parser/lowering/export/canonical-encoding sources and
the package assembler. A v2 transformation is represented by the frozen graph and exact
parameter bytes, so changing channel order, mean or standard deviation changes the derived
model identity. The original ONNX source remains byte-for-byte intact. Existing package wire
versions, already-provisioned packages and the specialized YOLOX importer remain unchanged;
new conversions bind the current source-derived importer identity.

Native artifact tests reopen the canonical graph, read exported weights with the actual
production Safetensors parser, and run the actual production scalar executor. They cover
Gemm-generated parameters, escaped Unicode tensor names, exact F32 bits, batched dense-head
execution, empty parameter sets, byte/work ceilings and cancellation. Package and CLI tests
add archive round trips, shape/license/pin refusals, exclusive output creation and the
existing retained-JPEG detector path. Their execution status is recorded separately in
`IMPLEMENTATION_STATUS.md`; authored tests are not a claim of runtime qualification.

`onnx_preprocess_execution` additionally runs actual native RGB resizing, canonical graph
decoding, Safetensors parsing and scalar execution against an independent pixel/head oracle
for RGB/BGR and raw/unit inputs. Its fixture has nonzero weights, uses every normalized
channel, and exposes a second image-consuming branch. Package tests reopen a complete v2
archive, retain original-source provenance, execute and project its detector head, and check
that denied RGB pixels are replaced before normalization. CLI tests exercise both strict
recipe versions and exclusive package output creation.
