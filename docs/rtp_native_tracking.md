# Source-witnessed native RTP tracking

## Implemented reference boundary

`fss_reference::ingest::rtpdump::track::RtpPackageTracker` connects a verified retained
RTP import to native H.264 decoding, current-custody privacy projection, an immutable
verified neural package and the existing checked global-assignment tracker. There is
no substituted decoder, injected detection report or new runtime. The owner is a
read-only library entrypoint, not a new CLI command, event publisher or live daemon.

This is a bounded single-recording, single-selected-class reference path. It does not
claim field tracking accuracy, physical identity, trustworthy per-picture capture
time, cross-camera association, continuous coverage, absence, or effect authority.

## Calling the owner

Start with a current `RecoveredRtpImport`, a verified `RgbDetectorPackage`, the exact
retained H.264 parameter pair and the existing `RtpDetectionRequest`. Construct a
`RtpTrackingRequest` with an explicit zero-based `class_index`, `TrackerConfig` and
`RtpTrackingLimits`, then call `RtpPackageTracker::new` with the current deployment,
`ReplayCx` and `ScalarExecCx`. Invalid class indices and tracker admission fail before
opening the source owner. Model labels come from `package.spec().labels`.

Repeatedly call `step` under an outer bounded operation budget. Consume all three
variants separately:

- `Progress` preserves the original source event and decoder consequence. It is not a
  tracking observation and must not be discarded when interpreting completeness.
- `Frame` contains the full unchanged native detection result plus actual assignments.
  Each `detection_index` addresses the complete original report, not a class-filtered
  intermediate vector. Other classes remain in that report and are not silently lost.
- `Ended` contains cumulative accounting. Only `stats.complete()` means every delivered
  detector frame was tracked without native incompleteness or an outer failure. This
  still says nothing about physical absence or detection recall.

A step error is terminal. Repeated calls return the same terminal accounting; they
cannot resume the owner with a fresh allowance. A partial prefix is not a completed scan.

## Observation and continuity semantics

`Tentative` and `Confirmed` are the numerical track lifecycle, not calibrated confidence
or person identity. Only tracks assigned an actual detection are exposed as observations.
Lost/coasting predictions contribute to active-track accounting but receive no source
observation, speculative box, or evidence of physical presence.

The numerical time unit is **one observed-frame step**. Sender RTP timestamps and a
recording-level capture hint do not justify inventing a per-picture wall clock or speed
in metres per second. A time-calibrated downstream consumer must establish its own
explicit valid clock and geometry basis.

A decoder refusal, fence, waiting-for-IDR transition or decoder epoch change resets
association. So do skipped display indices and changed image/privacy projection.
The first usable picture after initial damage explicitly reports `SourceGap`, rather
than looking like an ordinary clean baseline. Backward/repeated display order or a
reversed decoder epoch refuses instead of inventing a new session.

An anonymous identity binds the source root, exact tracking recipe, association epoch
and numerical local ID. Local IDs may restart after a reset, but full identities do not
alias the old epoch. Each complete frame digest links its predecessor even across the
reset, preserving analysis history rather than pretending the earlier interval vanished.

## Bounds, authority and reproducibility

Native decode, source readback, inference and postprocessing keep their existing
independent allowances. Tracking additionally limits complete frames, selected detections,
active capacity and conservative assignment work. The work reservation is
`tracks^2 * (tracks + detections)` for a nonempty solve, with zero prior tracks after
reset. It is a conservative numerical admission, not a measured CPU-time claim.

Resets never replenish lifetime counters. Capacity or numerical refusal does not commit
partial tracks; reserved work remains accounted for. Cancellation is checked at admission
and again before releasing a complete track result. Both explicit contexts drain on
cancellation, and changed deployment authority or missing original custody refuses rather
than returning an empty result.

The recipe includes the detector recipe, class, numerical policy, ceilings and exact
tracking/assignment implementation bytes. It is distinct from original custody and native
decode receipts. Changing tracking interpretation changes derived identities without
rewriting source evidence. Result digests alone do not constitute durable publication.

## Reproduction and remaining work

Run `bash scripts/check_rtp_tracking.sh` for the pinned, locked, offline core and native
contracts. Native tests load the committed YOLOX-Nano package and real retained H.264
fixtures; core tests separately exercise actual nonempty assignment and failure schedules.
The hosted workflow calls the same script and keeps per-commit runs from being cancelled
by unrelated concurrent pushes. Hosted results are supplementary, not release authority.

The suite contains ten tracking-core tests, seven native tracking integration tests and
the existing native detection contracts. Test definitions are not a pass claim; inspect
the exact run/commit result. Physical camera qualification, calibrated time, crossing and
occlusion accuracy, native tracking CLI presentation, retained track publication and
long-running/cross-camera operation remain separate work.
