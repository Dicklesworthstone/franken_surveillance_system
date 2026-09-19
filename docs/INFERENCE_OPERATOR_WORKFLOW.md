# Retained recording to model execution

`fss-infer` connects the recorded-file workflow to actual pure-Rust model execution. It runs
an exact locally supplied model on a retained JPEG/MJPEG segment, persists the model and its
outputs, and can reopen or independently replay the run without the original model file.
It does not download a model, run ONNX, activate a production model generation, infer object
labels from tensor positions, or authorize alerts. The output is explicitly uncalibrated.

First use the [file importer](FILE_IMPORT_WORKFLOW.md) to retain the recording. The `run`
command decodes the chosen segment through the canonical JPEG decoder before inference;
a separate `fss-file decode` invocation is not required. Annex-B is not decoded by this path.

## Freeze the local model

Create a `RecordedModel` through the [recorded model library](RECORDED_MODEL_EXECUTION.md),
using a validated canonical Model IR graph and exact F32 parameter values. Write
`model.encoded()` to a local file and retain the independently expected `model.digest()`.
A converted trained graph must use the existing scalar executor's admitted operators and
one full-resolution F32 NCHW luma input; other inputs must be explicit parameter tensors.
Weight provenance, licenses, calibration and activation remain the operator's separate
admission process. No pretrained model or claimed detection accuracy is bundled here.

## Run

```sh
cargo run -p fss-cli --bin fss-infer -- run \
  --root ./camera-evidence --site site:home \
  --import-id sha256:YOUR_IMPORT_DIGEST --segment 0 --interpretation ycbcr \
  --model ./approved-local-model.fssmodel --model-digest sha256:YOUR_MODEL_DIGEST \
  --decode-work-units 100000000 --max-macs 100000000 --max-tensor-bytes 67108864 \
  --output ./run.tensors --receipt-out ./run.receipt
```

Replace placeholders with exact 64-character lowercase hexadecimal digests. Choose `gray`
for grayscale JPEG or `ycbcr` for the source's JPEG YCbCr contract. The model itself freezes
normalization, dimensions and weights; the CLI cannot silently override them. Missing weights,
shape/dtype/generation mismatches, bad digests and nonfinite results fail closed.

The output reports `run_identity`, `model_digest`, `frame_root`, final `authority_sequence`,
`executed_macs`, `allocated_tensor_bytes`, output digest and number of output ports.
`model_outputs=uncalibrated`, `absence_certifiable=false` and `effects_authorized=false` are
explicit. Interpret a tensor only according to the separately admitted model's output contract.
Successful identical invocations reuse authority identities, but execute and charge work again.

## Reopen and reproduce

```sh
cargo run -p fss-cli --bin fss-infer -- read \
  --root ./camera-evidence --site site:home \
  --import-id sha256:YOUR_IMPORT_DIGEST --segment 0 --interpretation ycbcr \
  --run-id sha256:YOUR_RUN_DIGEST --output ./restored.tensors --model-out ./restored.fssmodel

cargo run -p fss-cli --bin fss-infer -- replay \
  --root ./camera-evidence --site site:home \
  --import-id sha256:YOUR_IMPORT_DIGEST --segment 0 --interpretation ycbcr \
  --run-id sha256:YOUR_RUN_DIGEST --max-macs 100000000 --max-tensor-bytes 67108864
```

Both commands retrieve the model object from retained custody. `read` verifies source,
normalized-input, output and publication consistency without executing graph operators.
`replay` additionally reruns the exact model and compares every output bit and executor
accounting field. Neither modifies authority. A new unrelated ledger commit does not change
the run's completion anchor. An unavailable source/root or incompatible execution profile
is not silently replaced by newer data or implementation behavior.

## Failure and export boundaries

Only an existing non-symlink reference deployment is accepted. `--principal` is an audit label
for a local filesystem-authorized operator process, not remote authentication. There is no
network/model download, device-control, policy-mutation or notification capability here.
Model reads are bounded to 16 MiB and checked against the required digest before decoding work.
Recorded source and JPEG bounds use the existing default retained-media ceilings.

The MAC/tensor-byte settings bound the scalar executor, not total process memory or runtime.
The tensor ceiling is positive and at most 256 MiB; source reads, serialized buffers and
clones are additional. These counters are not latency, energy or accelerator measurements.

A successful frame decode may remain if inference subsequently fails. A completed model run
may remain if export or stdout subsequently fails. Nonzero exit status must not be ignored.
A root lacking the final model-run delta is incomplete; an exact successful retry can finish it.
Exports use new-file-only writes outside the deployment. Existing files and symlinks are not
overwritten, and Unix exports use owner-only permissions. Writes are file-fsynced; they are
not a new atomic export-root protocol. Partial exports can remain after I/O errors. Multiple
requested exports are sequential and not an all-or-nothing transaction.

## Tests and readiness

The CLI test fixture is a small explicitly authored arithmetic graph, not a trained detector.
It verifies the plumbing without asserting model quality. Cross-process tests exercise run,
restart after input/model-file removal, exact model recovery, independent replay, idempotency,
wrong-digest refusal, budget exhaustion and export safety. Run these on the pinned toolchain:

```sh
cargo test -p fss-model-ir decode::tests
cargo test -p fss-reference ingest::inference::tests
cargo test -p fss-cli --bin fss-infer
cargo test -p fss-cli --test inference_cli_contract
```

These tests were added but not executed in the editing environment. Full model admission,
trained detector output decoding, tracking, live sensor operation and release qualification
remain open. The internal format definitions and identity rules are documented in the linked
recorded model execution contract; this utility does not invent an alternate agent envelope.
