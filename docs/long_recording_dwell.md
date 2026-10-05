# Whole-recording sampled dwell

`fss-event watch --stream-dwell` scans a bounded MJPEG recording in one forward pass, keeping
the foreground model, Kalman tracker and sampled-occupancy state between frames. It removes
the ordinary watch path's 128-frame analysis-window restriction for this explicit mode.
A qualifying episode may begin before frame 128 and reach its duration threshold after frame
256 without becoming three unrelated tracks or three duplicate events.

This is an implemented, **unqualified** extension of the FSS-083 temporal-perception slice.
It is not a live daemon or a general temporal model. It creates no effect or alert authority.

## Run an existing retained recording

The recording must be a completed MJPEG/JPEG import with explicit capture-time hints. Those
hints remain owner assertions, not independently calibrated time. For example, request a
20-second conservative endpoint span with at least five actual matched observations:

```sh
fss-event watch \
  --root /path/to/deployment --site site:home \
  --import-id "${IMPORT_ID:?supply the completed MJPEG import identity}" \
  --interpretation gray \
  --zone porch:100,80,400,300 \
  --stream-dwell \
  --segment-count 3000 \
  --dwell-for-ns 20000000000 \
  --dwell-max-gap-ns 200000000 \
  --dwell-min-observations 5
```

Use `ycbcr` instead of `gray` for an explicitly YCbCr JPEG source. The image-coordinate zone
must fit the decoded frame. `--first-segment` selects a range start. With no segment count,
the complete remaining recording is selected only when it fits the 65,536-segment ceiling;
nothing is silently truncated. A separate invocation starts a new analysis: it does not resume
an in-flight tracker or import state from a caller-provided checkpoint.

The bare `--stream-dwell` flag requires the existing explicit dwell-duration and sampling-gap
options. It is echoed in every approval command. Existing foreground thresholds, tracker
configuration, JPEG work/image limits, `--tolerate-decode-refusals`, `--approve`, and
`--report-out` remain available. The default entry and short-dwell paths remain unchanged.

This first whole-range implementation **admits MJPEG only**. H.264/HEVC inter-picture ranges
retain their existing decoders and limits; they are not split arbitrarily or relabelled MJPEG.
Detector-package options are refused before deployment I/O, not ignored or replaced by motion
scores. `--retain-coverage` remains refused in dwell mode: no dwell-absence certificate exists.

## Temporal semantics

Only confirmed tracks with a current actual match may accumulate occupancy. The rounded center
must lie strictly inside the zone, conservatively excluding integer boundary samples. Neither
that rounding rule nor Kalman filtering is a bound on physical localization error.

The minimum elapsed span is the last sample's earliest capture minus the first sample's latest
capture, floored at zero. The sampling-gap test uses next latest minus previous earliest.
The comparisons cover the full signed-128 timestamp range without narrowing to signed-64
arithmetic. At least the configured observation count must also be reached. The first trigger
and final sample are retained, and staying inside produces one episode rather than one event
per frame.

An actual miss or out-of-zone sample ends the episode even when the tracker retains its ID.
An excessive sampling gap also separates episodes. Explicit source/decode discontinuities
reset both the tracker and foreground model and advance a tracker epoch, so local IDs cannot
bridge the break. Unknown capture time is refused before decoding. Omitted source bytes make
index-derived timing unreliable for the entire import; a source gap makes subsequent timing
unreliable. These samples cannot contribute to a dwell episode. Regressing capture bounds
within an uninterrupted, timing-admitted run refuse the complete result.

The sensor's current privacy mask is applied before foreground detection and tracking. A zone
with any masked pixel contributes no episode. Changing the mask generation invalidates an
unpublished proposal, even if its earlier source bytes remain available. A static or inaccurate
foreground track is not a person identity; repeated images or other sensor-health problems
still need the separate health/verifier owner. Sampled occupancy is not proof of continuous
presence between frames, loitering intent, threat, detection quality, or absence.

## Whole-scan budgets

Every aggregate counter applies to the entire invocation. It is never refilled at a frame,
chunk, track or episode boundary. Raising a ceiling may admit more work but does not change
a successful result's semantic identity.

| Option | Default | What is counted |
|---|---:|---|
| `--dwell-read-bytes` | 536,870,912 | Verified source-chunk bytes fetched by the forward source cursor |
| `--dwell-pixel-budget` | 1,073,741,824 | Sum of decoded luma samples, charged before foreground processing |
| `--dwell-assignment-work` | 1,073,741,824 | Sum of the existing checked tracker solver's admission bound |
| `--dwell-trace-bytes` | 8,388,608 | Complete length-framed per-source-position metadata trace |
| `--work-units` | Existing JPEG default | Native JPEG decoding work across the full range |

Source-read ceiling is at most 512 MiB, pixel/assignment ceilings at most 68,719,476,736 each,
and trace ceiling at most 8 MiB; all must be positive. Aggregate options without
`--stream-dwell` are refused. At most 64 active tracks/detections, 16 zones, 128 grouped decode
refusals and 32 total qualifying episodes are admitted. Exceeding any ceiling refuses the
complete analysis rather than dropping an episode or emitting a partial negative report.

The reader caches one verified source chunk and assembles one compressed frame at a time.
Decoded pixel buffers are released after the frame is processed; foreground model state and a
bounded identity/geometry trace remain. A chunk shared by many adjacent frames is not repeatedly
fetched by the source cursor. Metadata/capsule reads and the existing spool, ledger and
publication machinery have their own bounds: the new counters are **not** a total-system I/O,
RAM, latency or energy accounting claim. No throughput benchmark is claimed.

## Approval, evidence, and restart

The complete report is `fss.long_dwell_report.v1`. It records source/rule/analysis identities,
authority basis, privacy binding, per-scan resource counters, explicit decode refusals,
unreliable timing and every qualifying episode's first/trigger/final source positions. Exact
nanosecond durations are decimal strings. Complete JSON is capped at 1 MiB and approval-command
hints at 8 KiB before publication.

Review each `publish_command`, then execute the exact command or repeat the request with its
`--approve sha256:PROPOSAL`. Approval binds the current actor, site, event revision and complete
provenance. Entry-mode and short-dwell approvals cannot authorize this mode. Changing the rule,
source, selected range, zone, perception recipe, tolerance mode or privacy changes the proposal.
Resource ceilings alone are not policy changes when the full successful result stays identical.

Before staging, publication validates all supplied approvals, the durable authority head,
retained import identity and current privacy binding. It retains a shared analysis graph
root-last, then each approved episode's provenance, then its event through the existing guarded
event publisher. Every event remains **Unclassified, Indeterminate, probability [0,1], Hold**.
No original entry event is published as a side effect; no alert is prepared or sent.

The shared analysis contains the complete replay recipe and ordered per-frame trace (capsule,
capture bounds, masked luma digest, foreground geometry, tracker state and explicit refusals),
not just a hash of an unavailable command. Per-episode summaries reference that shared root and
the original retained import graph. Long episodes therefore do not exceed the event schema's
fixed evidence-item count or copy the full trace once per frame. No pixel array or raw media is
embedded in the JSON report.

After a crash or lost response, re-analysis uses retained source, not the original input path.
Exact completed events return `already_published` without another event append. A stop after
provenance but before event commitment leaves a resumable root, not a false completed event.
Source deletion or a new privacy generation can instead refuse the retry. A later report-file
or stdout failure does not roll back already committed events. Opening the existing deployment
still has its normal lock/restart-reconciliation semantics and is not claimed mutation-free.

## Implementation and validation boundary

New derived digest domains are `fss.long_dwell_analysis.v1`, `fss.long_dwell_frame.v1`,
`fss.long_dwell_episode.v1`, and `fss.long_dwell_approval.v1`. They do not change existing watch,
dwell, capsule, event or coverage bytes. The analysis/episode object-manifest kinds are
`recorded-long-dwell-analysis-v1` and `recorded-long-dwell-episode-v1`. Central schema/domain
registration and retained native qualification remain pending; no registry, formatting or
release-gate pass is claimed by this document.

```sh
cargo test -p fss-reference --lib streaming_dwell
cargo test -p fss-reference --lib long_dwell
cargo test -p fss-cli --test watch_stream_dwell_cli
cargo test -p fss-cli --test watch_dwell_cli
```

Eight streaming-core tests include exhaustive equivalence to the existing batch oracle and
4,096-sample episodes under multiple caller chunkings. Twelve real-import library tests cover
300-frame native decoding/tracking, source assembly, all aggregate ceilings, actual misses,
unknown timing, privacy invalidation, source gaps, decode refusal and interrupted publication.
Seven real-process CLI tests cover long preview/approval/cold retry, invalid modes before I/O,
whole-scan budget refusal, changed-rule/short-mode approvals, unknown time and complete report
export after removing the original input file.

**Rust compilation, these Rust tests, and rustfmt were not run in the authoring environment,**
which has no Rust toolchain. Executed independent Python models matched on 16,565 temporal cases
and 5,000 source-assembly cases, seed 20261005. Those comparisons are not execution of this Rust
implementation. Native long H.264/HEVC, a trained cascade in this mode, durable incremental
checkpoints, cross-camera dwell, live operation and real-footage quality evaluation remain open.
