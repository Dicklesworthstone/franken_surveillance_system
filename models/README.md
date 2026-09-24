# Models

Immutable, digest-pinned model packages and laboratory notes. Nothing in this tree is downloaded or
activated at runtime; a package is loaded only from an operator-supplied file whose SHA-256 the caller
pins, through the verified package path. See [`MODEL_REGISTRY.md`](../MODEL_REGISTRY.md).

| Directory | Content | Status |
|---|---|---|
| [`yolox-nano/`](yolox-nano/README.md) | `MOD-YOLOXNANO-001`, YOLOX-Nano COCO-80 416x416 (Apache-2.0) as an `FMPK` v1 package | conformance-qualified against the upstream ONNX (onnxruntime lab oracle); no quality or calibration claim |
| [`lab/`](lab/README.md) | qualification doctrine for future candidates | notes only |

Large source artifacts (upstream ONNX/PyTorch files, lab venvs, oracle outputs) stay outside the
repository; only converted packages, their license/notice texts and small conformance fixtures are
committed.
