# Source-closed RGB evidence and exact replay

`fss_reference::ingest::rgb_evidence` retains the inputs needed to reproduce the
native RGB perception path after its original Rust objects and caller buffers
are gone. It composes the existing Safetensors importer, JPEG RGB decoder,
privacy projection, resizer, scalar executor and dense-head postprocessor.
It does not implement another neural runtime, tracker or authority ledger.

## Capture from actual completed work

Call `RgbEvidence::capture` with the original `ImportedRgbModel`, exact head
contract, complete original JPEG, opaque completed `RgbDetectionRun` and the
source-specific `RgbFrameAdmission`. The constructor checks model/head/run/source
bindings and independently hashes the supplied original JPEG and permission mask.
It retains original graph bytes and the whole Safetensors file, including metadata,
source precision and explicitly resolved name mappings. No weights are guessed or
reconstructed from an output tensor. Caller-built models without original source
weights are not silently made into imported models by this API.

The immutable recipe freezes preprocessing, mask fill, interpolation, padding,
class labels, tensor layout, objectness/logit semantics, thresholds, limits,
source/camera/clock/calibration identities and the availability declaration. It
also retains the original importer, model/head, inference, masked-input,
model-input, tensor-output and detection-result fingerprints.

`identity()` is the SHA-256 of that recipe, which transitively binds all original
sources. It is **not** the hash of the portable envelope. Keep this identity
independently when transferring the bytes. A digest binds content; it does not
establish the camera's authenticity, health, authorization or physical visibility.

## Portable envelope and distrustful restore

`encode` produces `FSSRGBE1`, followed by five little-endian u64-length-prefixed
parts: canonical recipe, original graph, original Safetensors, original JPEG and
source permission mask. There is no path, executable model code, URL, compression,
implicit default, object lookup or hidden external attachment. The hard envelope
ceiling is 64 MiB; graph, weights and JPEG are each bounded to 16 MiB. The mask
ceiling is 4,194,304 bytes. Owner limits may narrow these bounds, never truncate.

`decode` checks complete framing, expected recipe identity, canonical round trip,
all original-source hashes, bounded metadata and mask values. A restored
`RgbEvidence` is only a bound set of source bytes and expected results. It exposes
no deserialized `RgbInference` and makes no claim that stored outputs are true.

Only `replay` returns `ReplayedRgbEvidence`: it re-imports the original weights,
decodes the original JPEG, applies the original permissions and preprocessing,
executes the original graph and projects its actual head output. Every retained
fingerprint must match. A self-consistent envelope whose claimed result digest is
forged therefore still fails replay. A source-pinned implementation/model/head
change can refuse older expected results; no latest-model substitution or silent
migration is attempted. Retain old sources and explicitly qualify migrations.

Replay returns owned computation results, the reconstructed head contract and
the exact original availability declaration. These can be supplied to the existing
`RgbZoneTracker` in original order under the separately retained episode/zone
settings. A single frame does not reconstruct temporal history or certify that
no frame was skipped. Availability remains an original owner declaration, not
newly computed camera-health evidence. Predictions, event authority and alerts
are not reconstructed by trusting a stored boolean or model score.

## Resources and failure boundaries

`RgbEvidenceBudget` prices copying, hashing and bounded recipe work. Import,
JPEG, neural preprocessing/execution and detector budgets remain separate and
explicit in `replay`. Successful allowances do not alter numerical identities.
Errors return no partial evidence or inference and do not mutate an existing
tracker or ledger. Consumed work is not refunded. Source bytes remain available
to retry under a new authorized allowance. Both replay and scalar contexts are
checked; the decoder's cancellation flag should belong to the same owner.

These APIs are memory-only and do not themselves establish disk custody. The
complete envelope owns its source bytes, but dropping it without authorized
persistence still loses them. There is no model download, pretrained detector,
model activation, biometric identity, continuous-coverage proof or effect grant.

## Validation status

Seven Rust contracts were authored for actual JPEG/convolution replay after
old objects are dropped, exact original-source retention, corrupted components,
self-consistent forged result claims, every envelope truncation, suffix/length
attacks, original availability/clock uncertainty, resource refusal, cancellation
and budget-independent identities. Fixture coefficients are numerical controls,
not trained weights. Rust compilation, these tests, rustfmt and Clippy have not
run in the authoring environment, which has no Rust toolchain.
