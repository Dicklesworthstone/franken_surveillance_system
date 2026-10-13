# Motion analysis from retained RTP evidence

`ingest::pixel_change::rtp::RtpMotionAnalyzer` connects the existing current-custody AVC
receipt decoder to the same integer pixel-difference kernel used for JPEG and file video.
It is a streaming candidate-generation primitive, not a person detector, event decision,
coverage witness, or authorization to alert. Original capture uncertainty is unchanged.

Open an independently authorized, completed `RecoveredRtpImport`, construct `RtpMotionRequest`
with exact decode parameters, explicit `PixelChangeConfig` thresholds and a cumulative
comparison allowance, and drive `step` with the deployment and `ReplayCx` until `Ended`.
Each observation links the exact frame receipt and, only for an actual comparison, the
predecessor receipt. Source group (coding order) and output index (display order) are distinct.
Fresh process-local ingress handles do not affect canonical observation digests.

The analyzer owns the decoder: no API accepts arbitrary pixels or a caller-assembled
frame/receipt pair. Only masked luma reaches the shared kernel. The existing source recovery,
parameter selection, source-generation fencing, privacy enforcement, canonical deletion
checks and graph readback remain in force. Changed policy or missing custody terminates the
attempt, including when a prior baseline is cached. The caller still authorizes deployment
access; a measurement is not a new permission or published decode.

A first frame is an unmeasured baseline. Lost references, skipped dependent groups and native
recovery retire that baseline. The first recovered frame explicitly carries `source_gap`
and no statistics or predecessor comparison. Native B-picture display reordering does not
invent a source gap. A below-threshold comparison means only that the selected masked images
did not meet the caller's integer thresholds; it does not certify physical absence.

One previous luma plane (at most 4 MiB) is retained in addition to bounded decoder state.
Comparison work, custody-read bytes, receipt bytes and progress steps are independently
accounted and never replenished by recovery. Comparison refusal admits no partial observation;
work charged before cancellation remains consumed. Any analyzer error drops its decoder and
baseline. Repeated terminal calls cannot restart or reset an allowance.

`stats().complete()` requires native complete drain, no refused/skipped groups or analyzer
errors, and an observation for every native output. Recovered partial recordings may produce
useful observations but cannot report complete analysis. These operations write no deployment
objects or ledger deltas, change no policy, and initiate no network or effect operations.

Eleven native fixture tests cover scalar equivalence, exact receipt linkage, cold reproduction,
threshold identity, masks, B-picture display order, loss/recovery, cancellation, missing source,
policy drift and independent comparison/receipt limits. They passed on the exact `ae78cbc`
source tree plus this increment using pinned nightly-2026-08-31. This is focused Linux native
execution, not release qualification or a physical-camera quality claim.
