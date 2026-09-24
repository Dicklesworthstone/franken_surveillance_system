# YOLOX-Nano (COCO-80, 416x416) — `MOD-YOLOXNANO-001`

FSS's first trained detector, admitted by delegated owner decision (bead `fss-x4a.8.1`, implemented in
`fss-q4ngj`). It is a **conformance-qualified package**: the first-party scalar executor reproduces the
upstream ONNX graph (as evaluated by onnxruntime in the laboratory) within a stated tolerance, and
post-processing yields the same detections. There is **no detection-quality, recall, calibration or
adversarial claim on any FSS deployment data**; scores are uncalibrated COCO proposals.

## Files

| File | SHA-256 | Notes |
|---|---|---|
| `yolox_nano.fmpk` | `5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74` | immutable `FMPK` v1 package, 3,746,286 bytes |
| `LICENSE` | `577c03d505ec80f667ebf96ebd0cc4f6825c817ca1088ee348c48aaabd51bd92` | upstream Apache-2.0 text, byte-identical to YOLOX `LICENSE` at 0.1.1rc0 |
| `NOTICE` | `d7341e09f37ea810b278ed1a15c1004b4347dfe287ce8deecfc423809deb1cea` | attribution + description of modifications (Apache-2.0 §4(b)) |

The upstream ONNX file is **not** committed. Its identity is pinned everywhere it matters:
`https://github.com/Megvii-BaseDetection/YOLOX/releases/download/0.1.1rc0/yolox_nano.onnx`,
`sha256:c789161ed43c8269fcd4e67c67eeeb4e80c622da2eb296a20bc6007bd18a0b7d` (3,659,407 bytes,
producer `pytorch 1.7`, ONNX opset 11). The importer refuses any other bytes. Nothing is ever
downloaded at runtime; the package is loaded only from an operator-supplied file whose whole-archive
SHA-256 the caller pins (`RgbDetectorPackage::load`, `fss-infer package-detect --package-digest`).

## Package contents (`yolox_nano.fmpk`)

| Artifact | Bytes | SHA-256 | Role |
|---|---:|---|---|
| `weights.safetensors` | 3,678,231 | `c49c68ef608bfe748ce655c5a30ab4e047c09adbe651653cccf7ca6b61a382f9` | 229 F32 tensors, 915,111 values (226 upstream conv weights/biases + decode grid, stride, -1) |
| `graph.fssir` | 53,290 | `7c33baabc82bc169a76fb39d1ec5a50e1c6c36a62667bc9268b62c8f80ac1850` | canonical FSS Model IR v1, 286 nodes, outputs `raw_head` and `decoded_head` [1,3549,85] |
| `package_spec.bin` | 1,538 | `257e8a5e3acb48d09114c3d4aa9217738efb18c3531ee694ca058982e44d0662` | `fss.rgb_detector_package_spec.v1`: preprocessing, head, 80 COCO labels, source ONNX digest, importer identity |
| `LICENSE`, `NOTICE` | | as above | license text (manifest `text_digest`) and attribution |

Manifest: model `MOD-YOLOXNANO-001`, generation `model:yolox-nano:coco80:416:onnx-0.1.1rc0:fss-ir-v1:f32:g1`,
license `Apache-2.0` (use approved by the owner decision, no restrictions), input schema
`fss.rgb_nchw_f32.1x3x416x416.raw255`, output schema `fss.yolox_decoded_head.1x3549x85`, calibration
generation `cal:uncalibrated:none`. Importer identity:
`sha256:f4f248d187146819e52a7a04b7ef408dfe01b4372fec6f11e80db8e8026a7aee` (SHA-256 over the
`fss.yolox_importer.v1` canonical record of the three importer source files).

Loading verifies, in order: whole-archive digest (before parsing), archive checksum, every artifact
digest and the manifest/artifact correspondence, the license policy (surveillance-monitoring profile,
license-text digest required), the graph through the canonical IR decoder, and the weights through the
existing bounded Safetensors importer. A one-byte change anywhere is refused
(`ERR-MODEL-PACKAGE-DIGEST-001`; re-pinning tampered bytes is refused by the archive checksums).

## Operator mapping (ONNX -> FSS IR v1)

No new IR operator was added: every upstream operator maps to an existing frozen v1 operator or an
exact composition, so the pinned operator-table freeze digest (`fss.model_ir.operator_table.v1`,
bound into every model receipt) is unchanged and no IR generation bump is needed.

| ONNX | count | FSS IR |
|---|---:|---|
| `Conv` (BatchNorm already folded by the upstream PyTorch export; the source has no `BatchNormalization`) | 113 | `OP-CONV2D-001` (groups, pads, strides) |
| `Sigmoid` + `Mul(x, Sigmoid(x))` | 104 pairs | `OP-SILU-001` (same function, binary64 reference then one rounding) |
| `Sigmoid` (objectness/class heads) | 6 | `OP-SIGMOID-001` |
| `Slice` (Focus space-to-depth, step 2) | 8 | `OP-SLICE-001` |
| `Concat`, `Add`, `MaxPool` (SPP 5/9/13), `Reshape`, `Transpose` | 18, 7, 3, 3, 1 | `OP-CONCAT-001`, `OP-ADD-001`, `OP-MAXPOOL2D-001`, `OP-RESHAPE-001` (static dims), `OP-TRANSPOSE-001` |
| `Resize` (nearest, asymmetric, floor, scale 2) | 2 | exact composition: Reshape `[N,C,H,1,W,1]` -> Concat x2 (axis 5) -> Concat x2 (axis 3) -> Reshape, i.e. `out[y][x] = in[floor(y/2)][floor(x/2)]` |

Additions around the upstream graph: an RGB-to-BGR reorder (three channel Slices + Concat; the
upstream weights expect OpenCV BGR order) and the YOLOX grid decode as a second output:
`xy = (raw_xy + grid) * stride`, `wh = exp(raw_wh) * stride`, with `exp(t) = sigmoid(t) / sigmoid(-t)`
(exact identity; IR v1 has no Exp). The unmodified upstream head stays available as `raw_head`.
Hand-computed tests pin each composition (`tests/yolox_nano_conformance.rs`).

## Pre- and post-processing (frozen in `package_spec.bin`)

- Input: decoded RGB -> source privacy mask (masked pixels become 114) -> aspect-preserving, **centered**
  letterbox to 416x416 with pad 114, half-pixel bilinear resampling, raw 0..255 as F32 (no
  normalization, as upstream for these weights). Upstream's demo pads **top-left** and resizes with
  OpenCV `INTER_LINEAR` on u8; FSS boxes are mapped back through the exact letterbox geometry, so
  placement does not bias boxes, but FSS end-to-end detections are not claimed identical to the
  upstream demo script — conformance is on identical model-input tensors.
- Head: rows `[cx, cy, w, h, objectness, 80 class probabilities]` in model pixels (`decoded_head`);
  score = objectness x class (F32); multi-label; inclusive threshold 0.30 (the upstream demo's
  visualization threshold; its 0.10 NMS pre-filter selects the same survivors); class-aware NMS
  suppressing when IoU > 0.45 on outward-rounded 1/256-pixel **source** boxes (upstream uses a
  `+1`-pixel area convention in model space); rows limited to 3549, candidates 4096, survivors 256
  (exceeding a limit refuses rather than truncates).
- Retained H.264/H.265 frames are converted from their decoded luma and chroma through the declared
  BT.601 limited-range transform (recorded as `ycbcr420_bt601_limited_rgb`; the codecs do not expose
  the VUI colour description, so the matrix is a declared choice); JPEG/MJPEG frames are decoded to
  color by the native JPEG color decoder (full-range JFIF).

## Conformance receipt

Oracle: onnxruntime 1.30.0 (onnx 1.23.0, numpy 2.5.3, CPython 3.12.14, x86_64, CPU provider,
1 thread), outside the repository, on the exact FSS-preprocessed input tensors (SHA-256 pinned per
case). Cases: a procedural color pattern (416x416), the repository JPEG
`tests/fixtures/media/jpeg/rgb_64x48_colorbars_420.jpg` decoded by the native color decoder and
letterboxed, and a procedural person silhouette (360x640, letterboxed). Fixture:
`crates/fss-reference/tests/fixtures/yolox_nano/conformance.txt`
(`sha256:23b5e2ee81e3daadee1a79f5e52fe1689a3f3cdd8e841e22331622983efa9a4f`, 134 KiB): per case 1,024
strided samples of `raw_head` and of the oracle's decode, all 85 values of the 16 rows with the
largest objectness logits (exact F32 bits), and the expected detections at 0.30 and 0.05.

| Measure | Result |
|---|---|
| max \|raw error\| | 2.34e-5 |
| max \|decoded error\| | 1.43e-3 model pixels |
| max error / max(1, \|oracle\|) | 3.0e-5 (tolerance 1e-3) |
| detections at 0.30 / 0.05 | identical counts, rows and classes on all three cases (6/13, 3/5, 1/1); boxes within 0.5 source px, scores within 1e-3 |
| silhouette | `person` 0.884 (oracle 0.884) |

Tolerance justification: ONNX Runtime accumulates convolutions in blocked, FMA-fused GEMM order and
uses its own vectorized logistic; the FSS reference accumulates sequentially without FMA and evaluates
SiLU/sigmoid with deterministic polynomial exponentials. Through ~60 layers these legitimately differ
by accumulated F32 rounding (observed 3e-5 normalized). The 1e-3 bound (normalized by max(1, |value|)
because head values include near-zero offsets and logits) leaves ~30x headroom while still catching
any wrong operator, layout, weight or channel order (those produce O(1) errors). Decision-relevant
agreement is asserted separately and exactly: same detections. The oracle also reports threshold and
NMS margins (smallest 1.3e-4 score margin at 0.05 on the pattern case, 8.7e-4 IoU margin) so a future
numerics change that crosses a decision boundary fails loudly rather than silently.

Timing (not asserted): release build, scalar reference executor, 360x640 input -> 416x416, on a shared
`rch` worker (vmi1149989, fully reserved at the time): **2.7–3.1 s per inference** (5 runs), 1.217e9
charged work units, 107.5 MB tensor accounting, identical output digest every run. Debug-build tests
take ~55 s per inference.

## Reproduce (offline laboratory; nothing here runs in production)

```bash
# 1. Acquire the source once, outside the repository, and verify it.
curl -sSL -o "$LAB/yolox_nano.onnx" \
  https://github.com/Megvii-BaseDetection/YOLOX/releases/download/0.1.1rc0/yolox_nano.onnx
sha256sum "$LAB/yolox_nano.onnx"   # c789161ed43c8269fcd4e67c67eeeb4e80c622da2eb296a20bc6007bd18a0b7d

# 2. Convert (first-party Rust importer; deterministic, rerun gives identical bytes).
#    The rch workflow used an ignored in-tree copy: model-cache/yolox_nano.onnx -> qualification-artifacts/.
cargo run --release -p fss-reference --example yolox_import -- "$LAB/yolox_nano.onnx" "$LAB/yolox_nano.fmpk"
sha256sum "$LAB/yolox_nano.fmpk"   # 5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74

# 3. Dump the exact FSS model inputs, then evaluate the oracle in a uv venv outside the repo.
cargo run --release -p fss-reference --example yolox_lab -- inputs "$LAB/inputs"
uv venv "$LAB/venv" --python 3.12
VIRTUAL_ENV="$LAB/venv" uv pip install onnxruntime==1.30.0 onnx==1.23.0 numpy==2.5.3
"$LAB/venv/bin/python" scripts/yolox_nano_oracle.py "$LAB/yolox_nano.onnx" "$LAB/inputs" "$LAB/conformance.txt"

# 4. Conformance and timing.
cargo test --release -p fss-reference --test yolox_nano_conformance -- --nocapture
cargo run --release -p fss-reference --example yolox_lab -- bench models/yolox-nano/yolox_nano.fmpk \
  sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74 5
```

Run over a retained import (see `fss-infer package-detect --help`):

```bash
fss-infer package-detect --root DEPLOYMENT --site SITE --import-id sha256:IMPORT \
  --first-segment 0 --frames 4 --interpretation ycbcr \
  --package models/yolox-nano/yolox_nano.fmpk \
  --package-digest sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74 \
  --report-out /outside/the/deployment/report.json
```

## Known gaps

- No quality, recall, calibration, subgroup, adversarial or drift evaluation on FSS data (registry
  gates 8–11 not passed); COCO scores are not threat probabilities.
- `fss-event report` consumes package detections only after `fss-infer package-detect --retain yes`
  (`--package-report`, a separate `fss.package_analysis_report.v1`, not an `AnalysisReport`), and
  `fss-event read` does not reopen package events. The video colour matrix is fixed (BT.601 limited
  range); content coded with BT.709 or full range is converted with a declared-wrong matrix.
- The scalar executor retains every intermediate tensor (~108 MB accounting) and takes seconds per
  frame; no optimized kernels, memory planning or accelerator exist for this package yet.
