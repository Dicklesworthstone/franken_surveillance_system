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

## Approve and retain

The report is `fss.recorded_dwell_report.v1`. Every candidate contains an event ID, proposal
digest, exact `publish_command`, source-capsule and luma digests, matched sample records, and the
first/trigger/final segment numbers. All nanosecond times and separations are JSON decimal strings
so clients do not lose precision through floating-point number decoding.

Review the hypothesis and execute its exact command, or repeat the same request with
`--approve sha256:PROPOSAL`. Ordinary entry approvals cannot authorize dwell, and changing the
rule, source, zone, analysis or privacy generation produces another proposal. Before staging,
the library rechecks the current durable authority head, retained import and mask, and validates
all supplied approvals. It then stages source-closed provenance, publishes the root, and calls
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
| `fss.recorded_dwell_observation.v1` | Import, privacy-bound plan, zone, track, segment, capsule/luma digests, exact capture interval and rounded track box |
| `fss.recorded_dwell_candidate.v1` | Complete analysis digest, zone/track, first/trigger/final segments and ordered observation/class record digests |
| `fss.recorded_dwell_approval.v1` | Exact event revision digest and source-closed provenance manifest root |

Global schema/digest-domain registry integration and retained qualification evidence for these
new records remain pending. The records above are specified here; no central-registry or
release-qualification pass is claimed.

## Executable checks

```sh
cargo test -p fss-reference --lib zone_dwell
cargo test -p fss-reference --lib recorded_dwell
cargo test -p fss-cli --test watch_dwell_cli
```

Eleven temporal-kernel tests cover conservative duration, worst-case sampling gaps, threshold
counts, re-entry, missed/unknown samples, explicit discontinuities, signed extremes, timestamp
regression and bounded output. Nine library tests exercise real synthetic MJPEG imports through
the real decoder/tracker/publisher, including default-entry equivalence, privacy invalidation,
source gaps, wrong approvals, cold retry and cancellation after provenance. Six process tests
exercise the actual watch command, preview/publication/retry, changed approvals, unknown timing,
pre-I/O argument refusal and complete report export after the original input file is removed.

The Rust tests, compilation and rustfmt were not run in the editing environment, which lacked a
Rust toolchain. An independent Python streaming model was compared with a separately partitioned
interval oracle on 41,386 exhaustive/seeded cases (seed 83005), all matching. That comparison is
not an execution or compilation of this Rust implementation. No real-camera detection accuracy,
performance or production qualification is claimed.
