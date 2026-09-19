# Offline recorded-model weight import

`ingest::model_import::ImportedModel::build` converts a supplied canonical FSS Model IR
and exact Safetensors weights into the existing `RecordedModel` format. The result can
be passed to retained inference and the recording-analysis pipeline. This closes a
weight-loading boundary; it is not an ONNX/architecture compiler, trained-model download,
model-registry admission, license decision, calibration, or activation mechanism.

## Exact parameter contract

The caller independently supplies SHA-256 digests of both original files, the image
port, raw-vs-unit luma scaling and source-float policy. Empty bindings mean exact names;
otherwise every graph parameter port needs an explicit graph-port -> source-name mapping.
Every source tensor must be referenced. Missing and extra parameters, shape mismatches
(including different shapes with the same element count), unsupported dtypes and nonfinite
values refuse the complete import. Explicit repeated source bindings permit tied weights;
the converted byte accounting includes every bound graph parameter.

The default policy is F32-only and preserves finite bits, including signed zeros and
subnormals. `ExpandFloat16` additionally permits F16 and BF16 with exact integer-bit
expansion to F32. All finite values of those formats are exactly representable in F32;
there is no quantization, lossy cast, shape transform or hidden precision fallback.
Integer, F64, quantized and other formats remain unsupported. The supplied graph still
must satisfy the existing recorded-model contract: one full-resolution `[1,1,H,W]` luma
input and F32 parameters/outputs. No resize, color conversion or learned preprocessing
is inferred from a model name.

The source reader follows the upstream [Safetensors format](https://github.com/safetensors/safetensors#format):
little-endian u64 header length, bounded UTF-8 JSON, relative half-open data offsets and
little-endian tensor values. Its specialized parser has no recursive/general JSON tree.
It rejects duplicate keys (also escaped aliases), unknown tensor fields, invalid Unicode,
non-integer sizes, malformed metadata, holes, overlaps and unindexed trailing bytes.
Scalar and zero-sized tensors are explicit. Optional metadata must be string-to-string;
it is retained as untrusted original data and never executed or interpreted as authority.

## Original evidence and reproducible bundles

`ImportedModel::encoded` is the internal `FSSIMPT1` / `fss.recorded_model_import.v1`
canonical envelope. It contains the complete original graph and Safetensors file, exact
resolved mapping, float/scaling policy, source-bound importer identity, and resulting
canonical recorded model. Its digest is distinct from the numeric model digest. Different
original headers/metadata can yield the same numeric model but different import bundles.
No source filename, ambient timestamp or implicit latest-model lookup affects these bytes.

`ImportedModel::verify` checks the expected bundle digest, rebuilds from the original
inputs, and compares the complete bundle byte-for-byte. A rehashed substituted model is
not accepted merely because the container is internally well-formed. A bundle from another
importer source profile requires its compatible importer; it is not silently reinterpreted.
The numeric executor and recorded-model byte format remain unchanged, so adding this
converter does not itself invalidate previously retained inference identities.

The bundle is an offline audit artifact, not a durable deployment publication. Keep it
alongside the original license/source/quality evidence. Passing only its `.model()` into
inference does not imply that the deployment retained the import bundle or admitted the
model. Activation, production package admission and original-source authenticity require
their separate guarded owners.

## Bounds and cancellation

Each source file is at most 16 MiB; the header at most 256 KiB; there are at most 256 source
tensors/graph parameters, rank at most 16, and tensor names at most 256 UTF-8 bytes. Metadata
has at most 128 entries of bounded strings. Expanded F32 parameter bytes are limited to
16 MiB, subject also to the existing complete recorded-model 16 MiB ceiling. A complete
source-bearing bundle is at most 64 MiB. Callers can narrow these limits; nothing truncates.

`ImportBudget` cumulatively charges input verification/parse bytes, 16 units per parameter
element (including explicit aliases), model encoding bytes and complete bundle bytes.
Verification also charges reading the bundle before reconstruction. Charges are deterministic
admission reservations, not hardware operation/latency measurements, and are not refunded
on failure. The exact bundle size is checked before source-bearing output allocation.
Source parsing/graph canonicalization are bounded stages; value conversion polls the owner
at most 1024 elements apart. No partial model escapes cancellation or another refusal.
In-memory copies and metadata are additional to parameter accounting; these limits are not
a claim that whole-process peak memory equals the parameter-byte ceiling.

## Checks and scope

The Rust tests cover real parameter execution, exact existing-model bytes, mapping and
shape failures, F16/BF16 opt-in, nonfinite parameters, JSON/offset attacks, Unicode,
scalar/empty tensors, all source truncations, exact resource bounds, cancellation,
self-contained reconstruction, forged embedded models and source metadata distinctions.
The committed 152-byte arithmetic fixture was generated and read by Safetensors 0.7.0;
it is not trained detection data.

An independent literal conversion check matched NumPy 2.3.5 on all 63,488 finite F16
patterns and PyTorch 2.10.0 on all 65,280 finite BF16 patterns. Upstream writer layouts
were checked for F32, F16 and BF16. These validate the translated conversion algorithm
and fixture format, not compiled Rust. Rust/Cargo are unavailable in the editing
environment: the Rust tests, formatting and pinned-toolchain qualification were not run.
No requirement is marked qualified on source presence alone.
