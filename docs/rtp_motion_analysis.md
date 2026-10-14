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

Twelve native fixture tests cover scalar equivalence, exact receipt linkage, cold reproduction,
threshold identity, masks, B-picture display order, loss/recovery, cancellation, missing source,
policy drift, non-refillable comparisons across recovery and independent comparison/receipt
limits. They passed on the exact `ae78cbc` source tree plus this increment using pinned
nightly-2026-08-31. This is focused Linux native execution, not release qualification or a
physical-camera quality claim.

## Operator command

```sh
fss-decode-rtp motion --root DEPLOYMENT --site SITE --source-root sha256:ROOT \
  --custody current --pixel-delta 20 --minimum-changed-pixels 100 \
  --minimum-changed-ppm 1000 --max-comparisons 64000000 --report-out motion.jsonl
```

The example thresholds illustrate syntax, not camera-specific calibration. `--pixel-delta`,
`--minimum-changed-pixels`, explicit `--custody current` and `--report-out` are required.
`--minimum-changed-ppm` defaults to zero and combines with the count threshold, not instead
of it. `--max-comparisons 0` admits an initial baseline but refuses the first actual comparison.
Existing source, native decode, receipt, custody and progress ceilings still apply. Specify
both `--sps` and `--pps` when the source has no unique parameter pair; the same exact selected
native parameters and limits are required to reproduce frame-receipt identities.

Reports are streamed JSON Lines, with one header, bounded observation/refusal rows, and a
terminal summary. Each observation includes its canonical digest, current/predecessor native
frame-receipt digests, interpretation recipe, display position, original source group, decoder
epoch, sender timestamp, conservative capture interval, privacy binding and threshold identity.
A reset has `comparison: null`, not a false motion candidate. Comparable pairs include integer
changed counts/fraction inputs, absolute differences, half-open changed-pixel bounds and the
threshold decision. Those bounds are not object detections. Receiver refusals and native
reference-chain recovery remain explicit; successful recovery cannot erase earlier gaps.

The report is an explicit private operator export, never a ledger publication. It must be a
new file outside the deployment under an existing protected parent. It reuses the same pinned
parent, create-only 0600 Unix file, identity and synchronization owner as PGM/receipt exports.
The command accepts no pixel `--output`, creates no parent or missing deployment, never
appends to or overwrites a report, and returns no unmasked planes. Readback of the complete
source dependency graph remains conservative and potentially expensive; this is a bounded
forensic/candidate-analysis profile, not long-recording real-time throughput qualification.

`--max-report-bytes` defaults to 16 MiB, with a 64 MiB hard ceiling. Each row is at most 4 KiB
and admitted whole before writing; short writes, repeated interruptions and cancellation are
bounded. At most one report row is assembled in addition to decoder/previous-frame state.
The command reports computed observations, measured/candidate pairs, baseline resets,
comparison work, custody-read bytes, receipt bytes and native progress separately. Computed
observations are not a promise that the report writer accepted all rows after an output failure.

Only a fully drained, refusal-free analysis and successful file/parent synchronization return
zero with `motion_complete=true`, `motion_report_complete=true` and `motion_report_sha256`.
The digest identifies this report's bytes, not a signature or evidence authority. Ordinary
analysis failures attempt an explicit incomplete summary and retain earlier historical rows;
quota, cancellation, I/O or sync failures may instead leave a partial file. A missing summary
or nonzero exit is never a completed quiet scan. No error path emits a successful report digest.
The native decoder may have completed while analysis or output did not; the separate counters
preserve that distinction. Re-running requires a new destination and fresh admission.

Seven real-process CLI contracts and five parser/writer tests passed, including exact library
observation equality, deterministic cold reports, private mode, unchanged authority, masking,
gap recovery, malformed tails, path refusal and comparison/report/native quotas. The combined
current-source native regression run also exercised the existing raw/retained RTP, receipt
stream, file-video motion and CLI export paths. These utilities are not the agent effect API,
and no source recording, active threshold policy, alert, event or coverage claim is changed.

## Validation scope

The combined execution passed 131 distinct focused native tests: 77 reference integration
tests, 48 CLI tests and six shared pixel-change kernel tests. Twenty-four are new here
(12 native analyzer, seven real-process CLI and five CLI parser/writer tests). Execution used
the complete current source archive, including concurrent provenance modules, plus these
changes, not a partial dependency overlay. Targeted CLI Clippy exited successfully with no
new motion warnings; an existing receipt-command argument-count warning remains. New motion
Rust files and the touched parent command pass pinned rustfmt checks. Existing wider
formatting differences, unexecuted repository-wide targets and native platform/release
qualification remain separate; no qualification gate was lowered or marked complete.

Five concurrent RTSP supervision commits reached `d8f5ca7` after this test snapshot. They do
not overlap these files and are preserved as the CLI increment's parent; the test counts
above do not qualify that subsequently combined RTSP implementation.
