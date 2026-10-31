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
| `scale_to_unit` | `true` maps RGB bytes to `[0,1]`; `false` keeps `0..255`. No implicit mean/std or channel reversal. |
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

## Admitted model profile and bounds

The command uses the existing ONNX IR 7–9, default-domain opset-13 static finite F32 profile.
Supported operators and their restrictions are specified in [onnx_import.md](onnx_import.md):
Add, Sub, Mul, Div, Relu, Sigmoid, Tanh, MatMul, Gemm, Softmax, Conv, MaxPool, Transpose,
Concat, Constant, Reshape, Squeeze, Unsqueeze, Slice, Split, Resize, Identity and Flatten.
Bounded static Shape/Gather/INT64 control programs can supply layout and partition controls;
their values are evaluated during import and never require runtime integer execution.
Runtime/data-dependent shapes, external tensors, custom operators, arbitrary raw
detector-head decoding and unsupported operators refuse explicitly. The command does
not claim that an arbitrary ONNX detector can be imported.

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
the package assembler. Existing package versions, graph bytes, model identities and the
specialized YOLOX importer are unchanged.

Native artifact tests reopen the canonical graph, read exported weights with the actual
production Safetensors parser, and run the actual production scalar executor. They cover
Gemm-generated parameters, escaped Unicode tensor names, exact F32 bits, batched dense-head
execution, empty parameter sets, byte/work ceilings and cancellation. Package and CLI tests
add archive round trips, shape/license/pin refusals, exclusive output creation and the
existing retained-JPEG detector path. Their execution status is recorded separately in
`IMPLEMENTATION_STATUS.md`; authored tests are not a claim of runtime qualification.
