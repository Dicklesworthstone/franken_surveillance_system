# Native neural detection from retained RTP evidence

`ingest::rtpdump::detect::RtpPackageDetector` connects the existing receipted current-custody
AVC decoder to a verified `RgbDetectorPackage`. It runs the first-party video RGB transform,
package preprocessing/executor and detector-head projection, without substituting a second
model runtime or accepting caller-assembled pixels/receipts. Every admitted native frame is
considered; motion does not silently discard frames.

## Library contract

Open an independently authorized completed `RecoveredRtpImport`, load a package against an
independently selected archive SHA-256 using the existing license/package owner, and construct
`RtpDetectionRequest` with exact native parameters. `RtpPackageDetector::new` and `step` take
both the existing `ReplayCx` and `ScalarExecCx`. Drive the request to `Ended`; any error ends
it and discards queued output. No model download, activation, threshold calibration, source
publication or effect is implicit.

A complete result couples the native frame receipt, complete inference, complete head report
and canonical result digest. Original sensor, stream, source group, recovery epoch, display
position, RTP timestamp and conservative capture interval remain separate. RTP time never
becomes a trusted clock. The exposure identity is the native frame receipt, not an invented
sensor capsule. The recipe binds package, selected kernel/model, head/threshold, color transform
and per-frame execution policy. Fresh process-local ingress handles do not affect identities.

The retained sensor mask applies to Y/Cb/Cr before conversion and is re-applied to RGB using
the shared declared RGB fill. The permission grid denies masked pixels. Existing preprocessing
and detector projection exclude private input and reject proposals intersecting denied pixels.
Only numerical outputs and source-space uncalibrated proposals are returned, never raw planes.
Zero proposals do not mean physical absence; this composition is not a tracker or event engine.

## Resources and failure semantics

Native decode, source readback, receipt bytes, color pixels, inference attempts, preprocessing,
executor MACs, tensor allocations and head projection retain separate lifetime accounting.
The analysis admits whole per-frame preprocessing/executor allowances before new work. It
refunds only capacity proven unused after successful inference; a failure keeps the full
reservation. Postprocessing work uses the existing cumulative budget. Recovery never resets
any lifetime allowance. An exhausted budget fails, rather than sampling or certifying a prefix.

Lost source references and recovery remain in native progress/refusal counters. Recovered
frames can still be analyzed independently, but a successful later inference never erases a
gap. Complete analysis requires complete native drain and a delivered result for every native
frame, with no source refusals, skipped groups or analysis failure. Native frames and completed
inference frames are reported separately. Failed inference/projection is not an empty result.

Source graph readback and privacy binding are enforced by the existing checked decoder before
native frame delivery. The authority anchor is checked again before returning neural results.
This is point-in-time source verification, not continuous disk integrity during computation,
future availability, calibrated detector accuracy, coverage, or permission to alert. Whole-graph
readback and scalar CPU inference remain a bounded forensic/reference profile.

## Validation

Twelve real-fixture native tests execute the committed YOLOX-Nano package and actual H.264
source. They cover exact equivalence with the independent composition of existing color,
inference and head owners; cold receipt/result reproduction; explicit threshold identity;
all-plane privacy; cumulative allowances; failed executor/projection/receipt work; cancellation
from both owners; missing source and policy drift; recovered gaps and malformed tails.

The initial twelve-test run passed on the pinned nightly-2026-08-31 and verified ae78cbc
archive plus this module. The current ac2f355 source, including RTSP supervision, is used for
follow-up integration checks. These checks do not qualify unexecuted platforms, release gates,
or the detector's physical-camera precision/recall. Existing broader formatting drift remains.
