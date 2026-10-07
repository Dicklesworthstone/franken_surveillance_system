# Whole-recording visual-degradation gate

`fss-event watch --stream-dwell --sensor-health conservative-v1` adds an explicit visual
screen before whole-recording foreground/tracking analysis. It closes a consequential gap:
a repeated frozen image can otherwise keep a foreground track matched long enough to satisfy
a sampled-dwell rule. The opt-in screen preserves diagnostic candidates but refuses their
publication when the recording has a visual-degradation finding or incomplete screening.

This is a reference implementation of the plan's Stage 0 / temporal-admission boundary, not a
qualified physical tamper detector, coverage certificate, or completion of the temporal verifier.
The whole-recording mode still admits only retained MJPEG/JPEG, with explicit capture hints.
See [the whole-recording workflow](long_recording_dwell.md) for source and decoder limits.

## Operator workflow

For a completed grayscale MJPEG import with capture hints:

```sh
fss-event watch \
  --root /path/to/deployment --site site:home \
  --import-id "${IMPORT_ID:?supply the completed MJPEG import identity}" \
  --interpretation gray \
  --zone porch:100,80,400,300 \
  --stream-dwell --segment-count 3000 \
  --dwell-for-ns 20000000000 --dwell-max-gap-ns 200000000 \
  --dwell-min-observations 5 \
  --sensor-health conservative-v1
```

Use `ycbcr` for an explicitly YCbCr JPEG source. The source frame rate and selected range must
make the requested duration possible; the command does not infer a clock or extend the range.
The only admitted screening policy is exactly `conservative-v1`. A different name, duplicate
option, missing value, or health option with short non-stream dwell is rejected before deployment
I/O. Ordinary entry `watch` and `corroborate` also accept the option, using the bounded recorded
screen described below. Whole-recording dwell keeps the whole-scan gate described here.

## Bounded entry-watch and corroboration screening

Add `--sensor-health conservative-v1` to an ordinary `fss-event watch` or `fss-event corroborate`
command to apply the same fixed measurements before interpreting candidates and coverage. The
existing 128-frame bound applies, including to each corroboration recording. This path supports
the codecs already admitted by recorded watch; it does not replace the MJPEG-only streaming
dwell decoder. A short `--dwell-for-ns` request without `--stream-dwell` remains unsupported
with this option and is refused before opening the deployment.

The recorded report adds `sensor_health` to watch, to each corroboration camera, and to each
coverage record. It reports the exact policy, summary digest, frames and luma samples screened,
affected source segments, and bounded per-frame observations with capsule/luma/measurement
digests and findings. A report with no finding says `clear_screen_not_health_evidence`; a report
with a finding says `suspected_degradation`. Neither result certifies physical sensor health or
absence of tampering. Decode refusals and source gaps retain their separate coverage reasons.

Recorded screening withdraws each complete qualifying suspect run, including frames before
its threshold was first satisfied. Those source positions become `sensor_health_degraded`
uncovered intervals. A candidate whose observation history touches a suspect run is withheld
as a whole. Its other source positions remain excluded as `sensor_health_dependent_track`:
withdrawing an earlier positive entry must never turn it into absence evidence.
Tracking/background state restarts after findings, preventing later clear pixels from continuing
a suspect track. Unaffected intervals can retain their existing conditional pipeline witnesses;
no witness may cross either exclusion. This differs from streaming dwell, whose entire scan is
blocked if any finding or incomplete screening occurs.

AVC/HEVC measurements follow decoded display order while retaining each original source segment
identity. Source indices can legitimately reorder; that does not restart the visual screen or
refuse the recording. When this order cannot support an index-based contiguous capture claim,
coverage carries `capture_order_uncertain` and withholds all witnesses for that recording.
Candidates and source-linked measurements remain available.

Recorded coverage uses `FSSCOV01` version 7 to retain the complete source-bound screening
receipt and exact confirmation requirement. Validation rederives decoder and health recovery
boundaries; background warm-up and confirmation context that reaches a suspect or discarded-track
frame cannot become a witness. Calibrated coverage guards preserve these exclusions. Unscreened
coverage versions 1–6 retain their existing encodings.

Recorded screening stays opt-in. Unscreened report bytes and approvals preserve their existing
identities. Screened analyses, proposals and coverage records bind their policy and measurements;
an approval from the other mode is stale. Each coverage record wraps the summary in a source-bound
receipt that pins the import, sensor, base analysis, pipeline and known reset boundaries, with a
separate `coverage_receipt_digest`. A transplanted summary or invented temporal reset cannot
validate as that source's receipt. Exact rerun commands include the option, and
post-publication coverage reanalysis applies the same screen. Each corroboration camera is
screened independently: degraded pixels from one camera cannot act as independent event support
or erase the other camera's diagnostics. Preview writes no event or coverage authority; normal
exact approval is required to retain either, and no alert is sent by these analysis commands.

The real-process regression target for this path is:

```sh
cargo test -p fss-cli --test recorded_health_cli_contract
```

The eight added tests exercise frozen imagery, sustained darkness/brightness, contrast loss,
late degradation withdrawing an earlier entry without creating false absence, source-decode
gaps, approval separation, safe coverage retention, independent camera screening, complete
report export and cold retry from retained source. The new recorded tests have not been run:
the execution service disconnected before compilation. These fixtures target synthetic semantic
behavior and make no real-camera accuracy, threat-recall, performance or release claim.

## Whole-recording dwell report

The report retains the existing outer format and adds a `sensor_health` object:

| Status | Meaning | Publication |
|---|---|---|
| `no_findings` | Every requested position was screened under the admitted source/timing continuity, with no heuristic finding | Still requires exact approval and ordinary source/privacy revalidation |
| `suspected_degradation` | At least one finding; `complete` separately reports whether screening was complete | Blocked for the entire scan |
| `incomplete` | No visual finding, but source/decode/timing continuity was insufficient | Blocked for the entire scan |

A diagnostic preview can exit successfully while `publication_blocked` is true. Exit zero means
that the requested diagnostic completed, not that the sensor is healthy. Every finding run,
candidate and source/decode refusal remains visible. Blocked candidates have `publish_command`
set to null; presenting their proposal digest to `publish` still refuses before staging any
object or appending an event. The whole scan is gated, not just the frame on which a finding
first appeared. A later clear frame cannot erase an earlier finding.

For an admissible proposal, review and execute its exact `publish_command`. The command includes
`--sensor-health conservative-v1`; changing or dropping screening produces a different analysis
and proposal and cannot reuse that approval. Screening is an opt-in operation policy, not a new
standing deployment access-control policy. An authorized operator can still explicitly request
the existing unscreened mode and review its different proposal; that result carries no health
screening claim.

## What is measured

This uses the existing `sensor_health` conservative-v1 policy without changing its thresholds:

| Finding | Exact reference condition |
|---|---|
| `persistent_dark_field` | At least 99.5% of luma samples are at or below 20, for three consecutive frames |
| `persistent_bright_field` | At least 99.5% are at or above 235, for three consecutive frames |
| `exact_frame_repetition` | Eight consecutive distinct source positions have identical decoded luma bytes |
| `contrast_collapse` | After observing p95-minus-p05 contrast of at least 32, three consecutive frames have contrast at most 2 |

In the whole-recording streaming-dwell report, diagnostic finding ranges begin where the
threshold was first satisfied, not at a claimed physical failure onset. This diagnostic convention
is separate from recorded entry screening's complete qualifying-prefix withdrawal. Each maximal consecutive run names its finding, first/last source segment, affected-frame
count and first/last canonical measurement digests. Complete per-frame measurements are embedded
in the analysis trace, including their predecessor, capsule, luma, capture and policy bindings.
Overlapping finding kinds have separate runs; interrupted findings are not merged across gaps.

The sensor's retained privacy policy is applied before either the screen or perception sees
pixels. Changing only a masked region therefore cannot make frozen visible pixels appear fresh.
The screen does not read unmasked pixels, export a frame, or override privacy. Large fixed-fill
masks can themselves contribute to conservative clipping/repetition findings; these remain
non-diagnostic warnings, not an inference about what was behind the mask.

Source/decode breaks reset temporal comparisons, not the whole-scan budget or replay set. A
missing frame or unreliable source timing prevents a complete screen. Unknown-time imports are
refused by the existing dwell admission. Tolerating a decoder refusal permits a diagnostic of
the remainder; it does not turn that remainder into a complete screening result.

## Cost, custody and restart

The screen consumes the same already-decoded, already-masked luma buffer as foreground tracking.
It does not perform a second decode or another source-chunk scan. The foreground and screening
sample counters are separate; each is bounded across the whole invocation by
`--dwell-pixel-budget`. Their sum, codec work, hashing, metadata I/O and publication work are not
misrepresented as a single pixel-processing counter. Screening polls cancellation at every row.

The existing 65,536-position ceiling applies to the whole scan. The screen retains a bounded
source-position replay set, counters and the preceding measurement, never prior pixel arrays.
At most 128 finding runs are returned. The full observation records consume the same
`--dwell-trace-bytes` allowance as all other frame metadata, so a screened range can hit that
ceiling sooner. Exceeding a bound refuses the entire analysis rather than dropping findings or
returning an empty negative report. The complete JSON bound remains one MiB.

Analysis and preview append no authority. `measurements_embedded_in_analysis` means the in-memory
canonical analysis contains those bytes; it does not claim that a preview's proposed root is
already ledgered. A blocked preview can be exported as the normal metadata report, and the
original retained source permits a repeat analysis. No automatic diagnostic publication or
hidden evidence-hold effect is introduced.

When an admissible candidate is explicitly approved, the shared analysis graph also retains the
exact screening-policy bytes and complete measurement trace before episode and event publication.
Cold retry re-analyzes retained source, not the removed original input file. Exact completed
proposals remain idempotent. A changed privacy generation or unavailable source refuses rather
than reusing the old screen. Existing deployment-open recovery behavior is unchanged and is not
claimed mutation-free. No effect-journal preparation, network call or alert occurs here.

## Whole-recording dwell encoding and compatibility

`HealthObservation::canonical_bytes` exposes the original `fss.sensor_health.observation.v1`
encoding; its digest and policy bytes are unchanged. `HealthScreen::new` retains its original
128-frame cap. The new `with_frame_limit` constructor explicitly admits 1..65,536 frames with
one cumulative sample allowance; a sufficient resource ceiling changes no measurement identity.

Unscreened long-dwell records and JSON keep their original bytes. For the opt-in extension only,
each successfully decoded frame appends canonical `text("sensor_health")` followed by
`bytes(observation.canonical_bytes())`. The outer analysis appends the same tag, the exact policy
bytes, and the complete summary: completeness flag, frame/sample counts, ordered finding runs
with their positions/counts/endpoint digests. The policy object is an additional shared-manifest
child. This makes screened and unscreened roots and approvals distinct. A closed reader must
understand this tagged extension or refuse it, never ignore trailing records. No existing
unscreened encoding is rewritten and no new standalone digest-domain name is introduced.
The inherited long-dwell central-format registration and native qualification remain pending.

## Limits and checks

A static scene can legitimately repeat. Lighting, compression, masks and ordinary camera behavior
can produce these findings. A complete `no_findings` result cannot prove sensor health, physical
occupancy between frames, lack of tampering, or absence. Periodic replay that changes frames,
subtle obstruction/defocus and adversarial imagery need stronger models and real-footage testing.
Streaming-dwell events remain unclassified, indeterminate, single-sensor and held for review.

```sh
cargo test -p fss-reference --lib sensor_health
cargo test -p fss-reference --lib long_dwell
cargo test -p fss-cli --test watch_stream_health_cli
cargo test -p fss-cli --test watch_stream_dwell_cli
```

The original streaming-dwell implementation added six long-screen kernel tests, three
finding-summary tests, eight real-import library tests and six real-process CLI tests. They cover all four finding kinds, freeze beyond
short windows, masked-only changes, row cancellation, aggregate limits, source/decode gaps,
approval isolation, privacy invalidation, complete report export and cold publication retry.
That implementation's original validation note records that its Rust tests, compilation and
rustfmt were not run in the authoring environment because it lacked the Rust toolchain. An independent Python arithmetic/sequence sanity check matched a
separate sorted-sample/history oracle on 567 cases and 20,720 frame observations (seed 20261005).
That check is not execution or compilation of the Rust code. No camera-quality, performance,
central-gate or release qualification is claimed.
