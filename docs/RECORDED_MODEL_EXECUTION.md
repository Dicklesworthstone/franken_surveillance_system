# Recorded model execution

The recorded-media composition now connects an already retained, decoded JPEG frame to the
existing pure-Rust `ScalarExecutor`, with exact graph, parameter and preprocessing identities.
This is an operator-authorized reference execution bridge, not model-registry admission,
activation, calibrated detection, identity recognition, or an alert policy.

## Library path

Use `fss_reference::ingest::inference::{RecordedModel, RecordedInference}`.
`RecordedModel::publish` accepts a validated `fss_model_ir::ModelIrGraph`, one named image input,
an explicit normalization flag, and a `BTreeMap<String, Vec<f32>>` containing every other
input port's parameter values. These may be converted trained parameters; the bridge never
supplies random/default/missing weights. Save `model.encoded()` and `model.digest()` together.
`RecordedModel::decode(bytes, expected_digest)` restores that exact input object.

The image port must be F32 `[1,1,H,W]`, matching the retained luma dimensions exactly. With
normalization enabled preprocessing computes `f32(pixel) * (1.0_f32 / 255.0_f32)` using the
existing `PreprocessProgram`; otherwise it uses the 0..255 values. There is no hidden resize,
channel expansion, color interpretation, orientation or fallback. All parameter/input/output
ports share the model's immutable generation. Nonfinite parameters and results are refused.
The bridge checks parameter count and shape; the existing executor enforces its closed operator
subset, shape inference, F32 numeric semantics, MAC budget and tensor-byte budget.

Call `RecordedInference::run_and_publish(deployment, source_request, model, budget, exec_cx, cx)`
only after the selected frame has been decoded and retained. It binds the exact source capsule
through the decoded-frame root, executes actual graph operations, and retains the frozen model,
normalized input tensor, output tensors and receipt. A final `model_invocation_receipt` delta
uses the cognition plane. No source, coverage, policy or effect authority is inferred from it.

`RecordedInference::open(deployment, run_identity, source_request, cx)` reads the completed run
and its stored model without the original recording or model file. It verifies the final delta,
root, source, normalized input and output representation. This proves retained consistency, not
independent numerical reproduction. `verify_by_replay` reruns the stored model and compares
exact outputs, operation counts and executor allocation accounting without changing storage.

Successful identical runs are ledger-idempotent. Budget ceilings do not change successful run
identity. Different source capsules, weights, normalization or executor source profiles do.
Each retry actually re-executes and therefore consumes work again; this is not free caching.
Parent cancellation is checked at composition boundaries; the explicit scalar context owns
in-executor cancellation. There are no worker threads or a second asynchronous runtime.
A cancelled or failed execution returns no partial results. Staged objects can remain on
publication failure. A root without the final model-run delta is incomplete; an exact retry
can finish it. Cancellation after final commit cannot erase completion.

## Bounded binary formats and ownership

These internal v1 operator formats are owned by `fss-reference::ingest::inference`. They are
not replacements for public agent envelopes or the production ModelPackage admission schema.
They use `CanonicalEncoder`/`CanonicalDecoder` with explicit magic/version, bounded lengths,
SHA-256 content addresses and strict suffix exhaustion. There is no serde-native layout.

* Model object (`fss.recorded_model.v1`, magic `FSSRMDL1`, version 1): exact graph digest and
  graph bytes in the existing frozen `fss.model_ir.v1` format; image input name; Boolean
  normalization; sorted unique parameter names and length-prefixed F32 bit patterns. Scalars
  use big-endian u32 bits; signed zero is preserved in parameters. At most 16 MiB total and
  256 parameter ports. Every non-image graph input must appear exactly once.
* Tensor set (magic `FSSRTEN1`, version 1): model generation; sorted unique tensor names;
  F32 dtype tag; rank/dimensions; count; big-endian F32 bit patterns. At most 16 MiB and 256
  outputs. The decoder checks exact declared names, shapes and counts before allocating.
* Run receipt (`fss.recorded_model_run.v1`, magic `FSSMRUN1`, version 1): model, decoded-frame,
  decode-receipt, source decode-completion anchor, executor-profile, normalized-input and
  output identities; successful MACs, tensor bytes and node count. At most 4096 bytes.

The execution source profile hashes the bridge, scalar/preprocess implementation and tensor
kernels/shape inference. It is not a compiled-binary or toolchain qualification certificate.
Changed profiles fail closed instead of replaying under a silently substituted implementation.
The current loader accepts v1 only; other versions require a future explicit reader/migration.
No existing graph bytes, manifest or model registry is rewritten.

The result root contains model/input/output objects and references the already retained source
frame graph. The final delta binds that exact root. Owner-supplied execution ceilings bound the
executor's cumulative tensor accounting, with a 256 MiB hard ceiling; serialization, source
read buffers and cloned values are additional memory, not included in that numeric counter.
MACs are reference operation counts, not measured CPU time, energy or throughput.

## Qualification boundary

Numerical fixtures use simple known arithmetic parameters to exercise real execution; they do
not claim to be trained detectors. Tests cover model loading, real numerical outputs, restart,
replay, idempotency, budget refusal, nonfinite outputs, cancellation, incomplete publication and
cross-capsule rebinding. They require execution with the pinned Rust toolchain. Production
model licenses, calibration, complete operator support, native platforms and aggregate release
qualification remain separate requirements.
