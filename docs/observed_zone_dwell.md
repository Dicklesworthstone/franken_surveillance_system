# Observed zone dwell in retained recordings

`fss-event watch` can now propose sustained **sampled occupancy** instead of only the first
zone entry. This is a temporal perception rule over the existing retained decoder, privacy
projection, foreground detector, Kalman tracker and source-custody path. It is an implemented,
unqualified slice of FSS-083 (`fss-x4a.16.3`), not completion of the general temporal verifier.

## Run the rule

Use a completed import with explicit operator capture-time hints and a correctly declared
component interpretation. The example asks for at least two seconds between the conservative
endpoints, no more than 200 ms worst-case separation between adjacent observations, and at least
five actually matched samples:

```sh
fss-event watch \
  --root /path/to/deployment --site site:home \
  --import-id "${IMPORT_ID:?supply the retained import identity}" \
  --interpretation ycbcr \
  --zone porch:100,80,400,300 \
  --segment-count 128 \
  --dwell-for-ns 2000000000 \
  --dwell-max-gap-ns 200000000 \
  --dwell-min-observations 5
```

Zones are image-pixel rectangles, not calibrated ground polygons. Use `gray` for explicitly
grayscale JPEG/MJPEG; retained AVC/HEVC use `ycbcr`. Existing decoder, range and budget refusals
apply unchanged. A range contains at most 128 segments, so the source frame rate and available
range must make the requested duration possible. This command does not persist dwell state
between ranges or run a live daemon.

`--dwell-for-ns` and `--dwell-max-gap-ns` must be supplied together. Both are positive integer
nanoseconds, at most one day. `--dwell-min-observations` defaults to two and must be 2..128.
A count alone, a missing companion option, an out-of-range rule, or duplicate options are
refused before deployment I/O. `--retain-coverage` is refused in dwell mode: the existing
zone-entry coverage record does not certify the absence of dwell.

Without these options, the original entry-mode path, report and coverage behavior are unchanged.
The existing binary synopsis still describes entry mode; this document specifies the additional
options. No new binary, dependency, model package or automatic alert policy is introduced.

## What qualifies

One episode consists only of consecutive decoded samples in which the same confirmed track
was actually matched and its rounded center is conservatively inside the same owner zone.
Tentative pre-confirmation samples and coasting predictions never add time or sample count.
The integer center must be strictly inside the zone, placing its whole half-pixel rounding cell
inside the integer boundary. This is a rounding bound, not a bound on Kalman or physical error.

For first capture interval `[a,b]` and current interval `[c,d]`, the guaranteed minimum endpoint
separation is `max(0, c-b)`. The rule never uses a midpoint, nominal frame count, receive time or
filesystem time as elapsed capture time. The next sample is admitted only when its latest bound
minus the preceding sample's earliest bound is within `--dwell-max-gap-ns`. Comparisons preserve
the entire signed-128 timestamp range; separations use unsigned-128 arithmetic without narrowing.

Each episode records its first sample, first threshold-crossing sample and final sample.
The threshold must satisfy both elapsed duration and sample count. Staying inside does not emit
one event per frame. Leaving and re-entering can yield separate episodes. A missing actual
match, excluded boundary sample, unknown timing, source/decode/tracking discontinuity, or
excessive sample gap ends an episode. Regressing interval bounds within an uninterrupted run
refuse the complete result, rather than turning a clock problem into a negative finding.

## Source truth, privacy and the detector cascade

Unknown capture-time imports are refused before decode. Hints remain operator assumptions, not
clock calibration. A source gap after segment zero makes subsequent index-derived capture hints
unreliable. Any nonempty omitted-byte span conservatively excludes the entire import's timing
from dwell accounting, including otherwise decodable samples; the report counts excluded frames.
This is intentionally more conservative than assuming how many frames the omitted bytes held.

The existing `--tolerate-decode-refusals` path may resume the decoder at its existing supported
boundaries. Refusals and tracking restarts remain in the report and canonical selection trace;
an episode never bridges them. A privacy policy is applied before foreground/tracking. A zone
with any masked pixel produces no dwell episode, and a changed privacy generation invalidates
an earlier unpublished proposal even if its old pixels remain in custody.

Existing optional detector-package flags remain available. The watch cascade executes once with
its existing whole-run inference allowance. Only class annotations from actually selected frames
inside a qualifying episode are attached. There is no additional inference at the dwell trigger,
no budget refill per episode, and no assumption that a missing class annotation is a negative
classification. Cascade identity and outcome digest are bound into the complete analysis.
Class scores do not decide dwell duration, corroboration or alert authority.

## Optional native sensor-health screening

The short-range library API `DwellReport::analyze_with_health` accepts an explicit
`Option<RecordedHealthPolicy>` after `WatchOptions`. `ConservativeV1` selects the existing
conservative temporal screen; `ConservativeOpticalV1(OpticalThresholds)` adds explicit integer
blur/glare thresholds. The original `DwellReport::analyze` method passes `None` and preserves
the original analysis, event, proposal and report bytes.

Screening runs through the existing native watch owner on the same privacy-projected decoded
frames used for foreground detection. Complete qualifying degradation runs and every track
touching them are withdrawn before dwell selection, including support observed before a temporal
finding reached its threshold. Recovery resets both background and tracking; a later episode
must satisfy confirmation and dwell thresholds using fresh matched samples. The dwell rule never
bridges an excluded run or counts rejected samples as evidence of absence.

A separate surviving episode may still be proposed. Its provenance retains the **complete**
health summary, exact selected policy, baseline conservative policy and every measured source
capsule, including negative findings outside that episode. The summary is a non-supporting
`Derived / RequiredBy` evidence dependency. Changing an optical threshold changes analysis and
approval identities even when the observed findings remain the same.

`DwellReport::sensor_health()` exposes the exact receipt. When screening is enabled, the JSON
report adds `sensor_health`; with `None`, the field is absent and the report bytes remain
unchanged. These are bounded visual diagnostics under the selected policy. A clear receipt does
not certify physical sensor health, calibrated detection quality or continuous occupancy.
This native short-range API does not extend optical screening to whole-recording or live-stream
dwell owners.

## Approve and retain

The report is `fss.recorded_dwell_report.v1`. Every candidate contains an event ID, proposal
digest, exact `publish_command`, source-capsule and luma digests, matched sample records, and the
first/trigger/final segment numbers. All nanosecond times and separations are JSON decimal strings
so clients do not lose precision through floating-point number decoding.

Review the hypothesis and execute its exact command, or repeat the same request with
`--approve sha256:PROPOSAL`. Ordinary entry approvals cannot authorize dwell, and changing the
rule, source, zone, analysis or privacy generation produces another proposal. Before staging,
the library rechecks the original deployment and principal, current durable authority head,
exact retained import and manifest, hashes of original source bytes and all contributing
capsules, and current privacy generation. These checks also apply to already-published retries;
metadata membership cannot substitute for intact source custody. The library validates all
supplied approvals, stages source-closed provenance, publishes the root, and calls
the existing guarded event publisher. A report export failure or stdout failure after that
commit does not roll back the event.

The event is always `Unclassified`, `Indeterminate`, single-sensor, probability interval `[0,1]`,
and policy `Hold`. Actual samples and optional detector records remain derived evidence from one
failure domain. The original entry events are not published as a side effect. No effect-journal
prepare, network request, alert dispatch or automatic retention change occurs.

Exact retries return `already_published` without a second event or authority append. Stopping
after provenance retention but before the event commit leaves no false completed event; an exact
rerun can reuse the retained root and complete publication. Source deletion or changed privacy
can instead refuse the rerun. The existing deployment open/recovery behavior still applies;
analysis itself writes no authority, but opening a deployment is not universally mutation-free.

## Meaning and limits

A qualifying span means **these matched samples meet this declared temporal rule**. It does not
prove occupancy between frames, identify a person, infer loitering intent, establish a threat,
calibrate detection quality or authorize an alert. A background model may absorb stationary
objects, and an inaccurate track may associate different physical objects. Those limitations
require real-footage evaluation and stronger perception, not stronger wording in this report.

Zero candidates never certify absence. The rule emits no CoverageWitness or silence certificate.
Dwell is not yet composed across cameras, persisted across analysis windows, or driven by a live
stream. At most 32 episodes are returned across the request; overflowing that limit refuses the
complete result rather than silently dropping episodes. Complete JSON is capped at 2 MiB and
rerun hints at 8 KiB. Existing decode, source-read and publication limits remain in force.

## Canonical records and compatibility

The new records use `CanonicalEncoder` with these separate, byte-exact domains. They do not
change existing watch, capsule, event or coverage encodings. New incompatible meanings must use
new domain versions; these are derived records, never new effect authority.

| Domain | Bound content |
|---|---|
| `fss.recorded_dwell_rule.v1` | Fixed conservative policy string, minimum duration, maximum sample gap, minimum observations |
| `fss.recorded_dwell_analysis.v1` | Rule bytes, site, privacy-bound watch plan, import root, ordered frame identities/times/reliability, decoder refusals, restarts, optional cascade identity/outcome and complete track/zone selection trace |
| `fss.recorded_dwell_analysis.v2` | Screened analysis: v1 field order with the complete health-summary digest and exact selected policy digest immediately after the import root and before the frame count; the watch plan also binds the selected screening policy |
| `fss.recorded_dwell_observation.v1` | Import, privacy-bound and optionally health-screened plan, zone, track, segment, capsule/luma digests, exact capture interval and rounded track box |
| `fss.recorded_dwell_candidate.v1` | Complete analysis digest, zone/track, first/trigger/final segments and ordered observation/class record digests |
| `fss.recorded_dwell_approval.v1` | Exact event revision digest and source-closed provenance manifest root |

These domains are registered in [the central digest-domain registry](../registries/DIGEST_DOMAINS.md).
The screened analysis uses `SCHEMA-DOMAIN-RECORDED-DWELL-ANALYSIS-002`; the existing v1 analysis
remains the exact format for `None`. The optional `sensor_health` JSON member extends
`fss.recorded_dwell_report.v1` without changing unscreened output. Registration does not claim
release qualification.

## Executable checks

```sh
cargo test -p fss-reference --lib zone_dwell
cargo test -p fss-reference --lib recorded_dwell
cargo test -p fss-reference --test recorded_dwell_health_contract
cargo test -p fss-cli --test watch_dwell_cli
```

Eleven temporal-kernel tests cover conservative duration, worst-case sampling gaps, threshold
counts, re-entry, missed/unknown samples, explicit discontinuities, signed extremes, timestamp
regression and bounded output. Nine library tests exercise real synthetic MJPEG imports through
the real decoder/tracker/publisher, including default-entry equivalence, privacy invalidation,
source gaps, wrong approvals, cold retry and cancellation after provenance. Six process tests
exercise the actual watch command, preview/publication/retry, changed approvals, unknown timing,
pre-I/O argument refusal and complete report export after the original input file is removed.

The eight native health-contract tests use real retained synthetic MJPEG and the native
decoder/tracker/publisher. They cover unscreened compatibility, exact threshold binding,
blur/glare recovery, complete frozen-run and track-prefix withdrawal, retained policy/summary
and capsule closure, immutable retry, privacy/principal/root changes, damaged source custody,
and cancellation before analysis or event completion.

The new native implementation was formatted with the pinned nightly toolchain. Native test
execution remains pending in this editing session: the executor failed during the
reference-library Cargo check before the test target could run. Native compilation and test
completion are unverified; no Rust compilation or test pass is claimed for this change. Earlier temporal-kernel work compared an independent Python streaming model with
a separately partitioned interval oracle on 41,386 exhaustive/seeded cases (seed 83005), all
matching; that historical comparison is not execution of this Rust implementation. No
real-camera detection accuracy, performance or production qualification is claimed.
