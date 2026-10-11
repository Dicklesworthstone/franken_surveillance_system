# Retained historical sensor-health diagnostics

Whole-recording screening can now leave a durable diagnosis even when it produces no event
candidate, or when a suspected visual degradation blocks event publication. This is a
reference workflow over a finite retained recording. It does not monitor a camera's present
connection or declare a current outage.

## Screen, then retain the exact result

Start with an existing authorized deployment and a retained file-import identity. The native
whole-recording path accepts the same bounded MJPEG, AVC and HEVC profiles as watch. Capture
time remains the importer's explicit assumption; it is not inferred from processing time.

```sh
fss-event watch --root /srv/fss --site site:home \
  --import-id "$IMPORT_ID" --interpretation ycbcr \
  --zone porch:32,32,640,480 --stream-watch \
  --sensor-health conservative-v1
```

The existing `sensor_health` summary reports persistent dark or bright fields, exact frame
repetition, contrast collapse, incomplete screening and the relevant finding runs. The
additional `historical_health` object contains the receipt digest, its source provenance
root, a separate approval digest, the complete compact receipt and an exact `retain_command`.
The preview writes no diagnostic or event authority.

Run that printed command to retain the diagnostic. It repeats the exact scan and adds
`--retain-health sha256:APPROVAL`. Retention works with zero event candidates and with findings
that block event publication. `--stream-dwell` supports the same independent path when its
duration and sample-gap rule are specified. Short-range watch and short dwell do not admit
this retention flag.

Health retention and event publication use separate invocations. A diagnostic approval cannot
approve an event, an event approval cannot retain a diagnostic, and neither is an alert grant.
Changing the source range, native recipe, resource reservations, privacy binding or approving
principal changes the retention approval or causes source revalidation to refuse. The
ordinary event health gate is unchanged.

Successful retention reports `retained`. A retry revalidates the original retained material,
preserves its original authority anchor and reports `already_retained`. A damaged retained
trace is not silently repaired from the transient scan. Cancellation can leave a verified
root before the final diagnostic commit; an exact retry can finish that prefix without
inventing an event or an effect.

## Retain either camera from a corroboration run

Whole-recording corroboration exposes the same independent diagnostic path:

```sh
fss-event corroborate --root /srv/fss --site site:home \
  --camera "east:$EAST_IMPORT" --camera "west:$WEST_IMPORT" \
  --ground east:1,0,0,0,1,0,0,0,1 --ground west:1,0,0,0,1,0,0,0,1 \
  --zone porch:32,32,640,480 --interpretation ycbcr \
  --time-gate-ns 1000000000 --distance-gate 16 \
  --stream-corroborate --sensor-health conservative-v1
```

Use the site's actual owner-declared homographies, ground zone and association gates; the
identity matrices above only illustrate command syntax. The `historical_health` array has
one entry per camera, with a camera label, receipt digest, exact approval, retention status
and `retain_command`. Camera labels are resolved through the source import identity.

Run one entry's printed command to retain exactly that camera's receipt. The other entry
remains a separate proposal. Either receipt can be retained when there are no ground entries
or matching pairs, and when suspected degradation blocks event publication. Retaining the
second camera later preserves the first receipt and its findings. `--retain-health` requires
whole-recording screening and cannot be combined with `--approve`.

Each camera's diagnostic binds its raw masked scan recipe, interpretation, source and privacy
custody, decoder/work ceilings and health policy. Ground homographies, ground-zone association,
common-cause declarations, trained event annotations and camera display labels have their own
corroboration owner; they do not turn the two historical health results into a corroborated
physical diagnosis. Cold health verification reruns the selected raw camera recipe without a
trained model file or the other camera's loose recording.

With `--tolerate-decode-refusals`, a camera whose entire admitted range refuses decoding still
produces an `incomplete` diagnostic. Both its camera summary and receipt explicitly label the
requested-source-capsule-hint fallback. It has zero screened frames, unreliable screening time
and no association samples; event publication remains blocked. Native verification can
reproduce that exact incomplete result without claiming that any frame was screened.

## Inspect after restart

Copy the `record_digest` from the preview or retained result:

```sh
fss-event health read --root /srv/fss --site site:home \
  --diagnostic-digest "$RECORD_DIGEST"
```

This reads the committed receipt, provenance manifest, source references and historical
screening/privacy policy metadata. It does not read media or the full native trace, decode
frames, rerun perception, or certify source availability. Its status is
`inspected_not_replayed`; `native_replayed`, `source_and_trace_verified` and
`current_privacy_revalidated` are false. Missing selected metadata and known current deletion
authority refuse the cold read. A subsequent privacy declaration does not erase an older
historical result.

The output includes an exact `verification_command` with the selected receipt, provenance
root and caller bounds. Native verification is separately explicit:

```sh
fss-event health verify --root /srv/fss --site site:home \
  --diagnostic-digest "$RECORD_DIGEST" \
  --expected-provenance-root "$PROVENANCE_ROOT" --execute-perception yes
```

Verification uses retained originals and the exact original native scan recipe. It checks
current privacy, reads the retained trace, reruns the existing decoder, foreground/tracker
and conservative screen, compares the complete receipt and trace, and revalidates source
custody before returning `native_replay_matched`. It needs no loose recording, saved JSON
report or trained model file. It verifies the health derivation; trained class annotations
and event hypotheses have their own replay owner.

Wrong provenance pins, changed privacy, missing or damaged source/trace custody, cancellation,
insufficient budgets and divergence refuse without a success report. Existing deployment
open still owns its normal restart recovery. The read and verify commands themselves append
no diagnostic, event or effect.

## Bounds and exact recipes

The receipt binds the source import and completion anchor, sensor and stream, requested
segment range, component interpretation, zone and foreground/tracker recipe, optional dwell
rule, refusal mode, full native decoder/read limits, whole-scan reservations, screening policy,
privacy generation, trace digest/length, actual work counters and bounded finding runs.

`--max-metadata-bytes` bounds the selected diagnostic metadata, deletion-plan and trace reads
(64 MiB by default; at most 256 MiB). Source import opening, privacy lookup and native media
access retain their existing bounded owners. The option is not a claim that all deployment
opening or source I/O spends that one allowance. `--max-report-bytes` bounds the complete
JSON including the verification command (1 MiB by default; at most 16 MiB). Output is never
silently truncated; an optional `--report-out` creates a new file outside the deployment.

Native admission additionally exposes `--source-read-bytes`, `--pixel-budget`,
`--assignment-work`, `--trace-bytes`, `--decode-work`, `--max-dimension`, `--max-pixels` and
`--max-segment-bytes`. Every retained reservation must fit its current allowance before
execution. A smaller allowance refuses the original recipe rather than changing it. The
default CLI profile admits both the native library and watch CLI defaults; explicit dimension
and pixel overrides apply across codecs and remain in the exact verification command.
Reported bounds show the separate JPEG, AVC and HEVC ceilings.

## Operator and agent visibility

Normal orientation reads a bounded inventory of committed diagnostic metadata and projects
literal retained results through derived knowledge cells and exact evidence handles. New
diagnostics appear in meaningful changes as `SensorHealth`. Suspected degradation, incomplete
screening and deleted diagnostic dependencies remain explicit historical limitations.

Each receipt has its own identity. A later `no_findings` result does not replace or clear an
older suspected or incomplete result, even for the same sensor. Committed deletion produces
an unavailable historical entry or an explicit deleted dependency; it cannot become a clean
screen. Full finding runs can be inspected through the priced `fss-event health read` handle.
The projection neither reads media nor claims native replay.

Capture scope is a hull of actual screened source-capsule hints, with gaps and unreliable
timing explicit. If no frame can be screened under the opted-in decode-refusal mode, the
diagnostic uses the requested source-capsule hint hull, labels that fallback explicitly, and
reports zero screened frames, incomplete screening and unreliable screening time. Neither
kind of hull certifies continuous coverage.

This implements a retained reference slice of sensor-health reporting. Live connection-loss
supervision, camera movement attribution, authorized restoration, measured field accuracy
and production qualification remain separate work. `no_findings` is not a health certificate;
a successful replay establishes reproducibility, not physical tampering or absence.
