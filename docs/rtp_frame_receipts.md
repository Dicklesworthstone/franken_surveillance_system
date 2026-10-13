# Portable retained-RTP frame receipts

`recovery::checked_decode::receipt` adds optional source-to-pixels receipts to the existing
current-custody decoder. Frames and receipts are delivered together, only after current
custody, privacy, receipt-budget and cancellation checks. The default snapshot decoder,
checked decoder and canonical import reports are unchanged. The additive `receipts` and
`verify-receipts` operator commands are documented in `rtp_receipt_streams.md`.

## API

After an authorized `inspect_rtp_import`, call `RecoveredRtpImport::decode_h264_receipted`
with the existing `RetainedRtpDecodeRequest`, `RtpCustodyDecodeLimits`, a separate
`RtpFrameReceiptLimits`, the deployment and `ReplayCx`. Drive `step` until its terminal
result. `ReceiptedRtpDecodeStep::Frame` carries the existing masked frame and a private-field
`RetainedRtpFrameReceipt`; progress retains the original receiver and decoder consequences.

The receipt exposes canonical `bytes`, their SHA-256 `digest`, the interpretation `recipe`
digest, and served Y/Cb/Cr/concatenated-I420 digests. Retaining those bytes is an explicit caller
operation. No ledger rows or files are written implicitly. The receipt-stream API and CLI
can export a bounded, complete collection and verify it against fresh native reproduction.

## Reproduction, not deserialized authority

Reopen the original retained root, select the same exact parameter pair and receiver/decoder
request, and reproduce the corresponding frame. Call its freshly generated receipt's
`verify_saved(saved_bytes, expected_digest)`. Both the exact bytes and the independently
expected digest must agree. A modified, rehashed, truncated or substituted saved claim is
not an alternative source of decode authority. There is deliberately no constructor that
accepts arbitrary serialized claims as verified frame receipts.

A fresh process-local ingress handle does not change receipt bytes. Stable source generation,
SSRC, source-record offsets, native decoder epoch and picture group remain represented.

## Versioned canonical encoding

The receipt domain is `fss.retained_rtp_h264_frame_receipt.v1`; fields use the existing
network-order canonical encoder and explicit version 1. The encoding binds:

- the receiver/decoder recipe, retained root, complete recording digest and byte length;
- canonical sensor/stream identities, source generation, SSRC and exact SPS/PPS digests;
- picture group, decoder recovery epoch, sender RTP timestamp and explicit grouping boundary;
- the original conservative capture interval, dimensions and retained privacy binding/generation;
- digests of every served masked plane and packed I420;
- every contributing NAL digest and original record/copy/synthesized-FU-header range.

The recipe domain is `fss.retained_rtp_h264_frame_recipe.v1`. It includes the existing H.264
decoder semantics identity, packet mapping/modes, exact parameters, recorded framing limits,
and every selected reorder/reconstruction/syntax/assembly/native-decode/recovery/output limit.
The process-local ingress, custody-read allowance and receipt allowance are omitted: they
are admission resources, not pixel interpretation. The complete retained root remains the
prediction-dependency closure; a list of the current picture's NALs is not claimed to list
all reference pictures.

The decoder identity is a versioned semantic label, not a compiled binary hash or a release
signature. These receipts are reference derivation records, not production qualification,
display authorization, a privacy-policy grant, continuous disk integrity, or future custody.
An individual successful frame never certifies complete recording coverage. Earlier skipped
groups, source refusals and recovery remain in the decoder's terminal accounting.

## Bounds and failure behavior

Receipt admission defaults to 1 MiB per receipt and 16 MiB cumulative; hard ceilings are
8 MiB and 256 MiB. Exact encoded length is computed before pixel hashing and encoding, with
bounded NAL/span counts. The cumulative reservation is retained on subsequent failure and
never renewed by IDR recovery. Plane hashing uses the existing SHA-256 implementation and
streams I420 instead of allocating a concatenated image. Cancellation checkpoints remain
inside metadata work and before pair delivery.

On any receipt/custody/privacy/cancellation failure, the consumer drops its decoder and queued
output. Only delivered frame/receipt pairs count as frames. Read and receipt costs remain
separate. Previously delivered pairs are historical observations, not promises that future
reads will succeed.

## Validation status

Eight real-fixture integration tests cover fresh-ingress reproduction, recipe sensitivity,
saved-receipt tampering/substitution, masked plane identities, per-receipt/cumulative budgets,
cancellation and recovery history. They run through `scripts/check_rtp_decode.sh tests` along
with the existing native receiver, decoder, custody and CLI contracts. The format lane includes
the new sources. An independent byte-layout size check matched the encoded-size calculation
for six optional-mask/span layouts; that is not a substitute for native Rust execution.

Those eight frame-receipt tests subsequently passed in the pinned native workflow for
90c303c (run 38470832776); that run still failed one separate deletion fixture and formatting.
The receipt-stream increment fixes that fixture through the real deletion owner rather than
lowering its reserved-family guard. See `rtp_receipt_streams.md` for the additional executed
stream and CLI checks and the exact local-source qualification boundary. No broader bead or
release gate is closed here.
