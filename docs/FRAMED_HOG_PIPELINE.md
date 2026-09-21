# Stream-bound native learned perception

`fss_twin::screening::tracking::hog::jpeg::stream::FramedJpegHogPipeline`
connects the existing incremental MJPEG framer to native JPEG decoding, independent
health screening, the frozen HOG model, anonymous image tracking, and resumable zone
analysis. It preserves the original stream identity, generation, frame ordinal,
compressed-byte range and encoded hash through every accepted downstream stage.

This is a synchronous, bounded reference integration supporting the detector and
within-camera tracking work packages (FSS-076/FSS-077). It does not implement a new
network client, runtime, decoder, tracker, effect channel or canonical durable format.
It does not close those work packages or promote production qualification.

## Use and ownership

Construct a fresh `JpegHogPipeline` with the desired immutable model, scale schedule,
health policy and zone pipeline. Move it into `FramedJpegHogPipeline::new` with the
independently admitted `StreamBasis`; the screening generation must already match.
Pass a `FramedQuery` from the existing framer and a `ScreeningStamp` to `observe`.
The stamp's sequence must equal the frame ordinal, and its generation must match the
frozen stream. Capture intervals remain separately supplied in `FrameCapture`.
Frame ordinals and receive times never become camera timestamps.

`Err` from `observe` means this input was not accepted: the preceding source receipt
and completion remain intact. A successful `Pending` means the image was accepted.
Its `source_receipt()` stays available, `completion()` is absent, and another frame
is refused until `resume` finishes the outstanding inference/tracking/zone stage.
Do not re-ingest a pending exposure. Complete retries return the same existing
analysis roots without new work, source consumption or trajectory aging.

Keep the original `FramedJpeg` bytes in the caller's custody. This wrapper retains a
source receipt, not a second compressed-byte copy or a disk archive. Persist the
original source, required derived objects and receipts using the existing custody
and publication contracts before treating them as retained evidence. There is no
mutable escape to replace or bypass the wrapped owner. Its health watchdog remains
available through `poll` during inference pressure.

## Refusals, gaps and output

Changed stream identities/generations, mismatched encoded bindings, repeated or
regressed ordinals, overlapping source ranges, and relabelled started owners are
refused. A native JPEG failure does not consume the stream cursor. Gapped ordinals
still reach the existing health-history gate and cannot bridge an ordinary observed
trajectory or sampled dwell. Byte gaps, complete framing and complete analysis are
not whole-stream continuity or negative-evidence witnesses.

`FramedHogCompletion` binds every `StreamFrameReceipt` field and the four existing
`JpegHogCompletion` roots in a domain-separated fingerprint. It is a local derivation
receipt, not source authentication, an archive publication, calibrated person
probability, identity, coverage, absence or effect authority. The existing scan keeps
masked, below-threshold and suppressed windows; the wrapper changes none of those
semantics. Missing or degraded independent health is not cleared by a model margin.

The extra boundary costs one construction work unit and 1,024 health-budget units
per offered frame that reaches source validation. The latter prepays the fixed-size
256-byte completion fingerprint, even when completion happens on a later resume.
Pending and already-complete retries add no wrapper work or allocation. Existing
per-stage budgets, resource ceilings and cancellation behavior remain in force.

## Validation and handoff

Fifteen authored Rust tests cover chunk equivalence; source and stamp rebinding;
ordinal/range replay; native decode failure; cancellation; inference, tracking and
post-tracking zone pressure; stale completion hiding; independent source-root
binding; health-history gaps; initialization; watchdog access; and a fixed-width
receipt golden with every input field checked. Synthetic coefficients and enlarged
JPEG fixtures test integration, not pedestrian-detection quality.

Authoring-environment checks: exact parent Git-blob reproduction, whitespace and
lexical delimiter checks, independent Python receipt encoding/golden/field binding,
and exact affected-file hashes. These are NOT Rust execution evidence. Compilation,
the 15 Rust tests, rustfmt, Clippy, full `scripts/qualify.sh`, hardware behavior and
native release qualification remain UNRUN here because cargo/rustc are unavailable.

Next qualification: run the focused `framed_hog_pipeline_contract` integration test,
the `jpeg::stream::tests` unit tests, existing JPEG/HOG/screening suites, then the
repository's required local qualification lanes. Keep source custody external and
all qualification claims unchanged until retained evidence supports advancement.
