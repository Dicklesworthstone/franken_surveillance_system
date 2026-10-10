# Whole-recording two-camera corroboration

`fss-event corroborate --stream-corroborate` runs foreground detection and tracking over both
complete retained recordings, then associates their ground-zone entries. Each camera keeps its
own foreground model and tracker throughout its scan, so entries after the ordinary mode's
128-frame limit remain observable.

The native MJPEG, H.264 and H.265 paths process frames in display order. The two recordings can
have different lengths. Each complete recording must contain at most 65,536 retained segments;
an oversized input is refused. This operation starts from each recording's beginning and does
not restore an arbitrary codec or tracker snapshot.

## Analyze a pair of recordings

Both imports need explicit operator capture-time hints and distinct sensor identities. The
original input files are unnecessary once each import's retained custody is complete.

```sh
fss-event corroborate \
  --root /path/to/deployment --site site:home \
  --camera "east:${EAST_IMPORT:?supply the east import identity}" \
  --camera "west:${WEST_IMPORT:?supply the west import identity}" \
  --ground east:1,0,0,0,1,0,0,0,1 \
  --ground west:-1,0,96,0,1,0,0,0,1 \
  --zone door:56,0,40,48 \
  --interpretation gray \
  --time-gate-ns 10000000 --distance-gate 16 \
  --stream-corroborate \
  --report-out /path/to/review/door-corroboration.json
```

The example homographies describe a synthetic 96-pixel-wide mirrored camera pair. Supply the
actual owner-declared image-to-ground transforms, zone coordinates and association gates for
the selected recordings. A homography is an explicit geometric assumption, not a verified
camera calibration. For native H.264/H.265 and YCbCr JPEG inputs, use `--interpretation ycbcr`.

The mode supports the existing foreground thresholds, tracker settings, decoder limits,
`--tolerate-decode-refusals`, `--sensor-health conservative-v1`, failure-domain declarations,
report export and exact event approvals. Detector-package, pose, calibration, scene-mesh,
visibility and coverage-retention options are refused before deployment I/O. Those contracts
remain available through ordinary corroboration; this streaming mode owns positive ground
observations and their association.

## What supports an entry and an association

Each confirmed **actual matched** track sample supplies the bottom-centre foot point of its
filtered image box. The declared homography projects that point to ground coordinates. The
first eligible sample inside a ground zone becomes an entry for that tracker epoch, track and
zone. Tracking outside a ground zone continues, so a later ground-zone entry can be found.
Predicted positions during missed detections do not establish entries.

Source gaps and tolerated decode refusals reset the tracker epoch. Inter-coded decoding resumes
only at a supported random-access boundary. The report preserves exclusions and restarts;
tracks cannot bridge them. Index-derived times that become unreliable after a source gap do
not support association. Unknown capture time is refused, and capture hints remain labelled
operator assumptions.

Association applies the existing ground-distance gate and worst-case separation of the two
capture intervals before global assignment. A midpoint that looks close cannot admit a pair
whose uncertainty exceeds the time gate. A candidate remains an unclassified event with its
source and uncertainty attached; the first observation inside a zone does not establish the
exact physical crossing time.

Owner-declared common causes use the ordinary syntax:

```sh
--failure-domain network:home-lan=east,west
--failure-domain power:shared-ups=east,west
```

Connected cameras count as one effective supporting domain. Both positive observations are
retained, but their policy result remains witnessed activity with `Hold`. Disjoint declared
domains are not a measurement of physical independence, and undeclared dependencies remain
unknown.

## Privacy, health and whole-scan budgets

Current per-sensor privacy masks apply before perception. Masked ground zones cannot support
entries. Each camera's exact privacy generation is included in the analysis identity and
rechecked before publication, together with its retained sources and analyzed capsules.

Optional conservative sensor-health screening evaluates both complete camera scans. A suspect
or incomplete screen blocks publication while keeping the diagnostic result available. A clear
screen does not establish camera health or detection quality.

The four aggregate limits apply **separately to each camera's entire scan**:

| Option | Default per camera | Scope |
|---|---:|---|
| `--stream-read-bytes` | 536,870,912 | Decoder source reads, including configuration and recovery probes |
| `--stream-pixel-budget` | 1,073,741,824 | Decoded luma samples processed by foreground analysis |
| `--stream-assignment-work` | 1,073,741,824 | In-camera tracker assignment work |
| `--stream-trace-bytes` | 8,388,608 | Complete bounded scan identity and geometry trace |

Reservations do not refill at frame, chunk or recovery boundaries. The total two-camera
reservation is twice the chosen per-camera ceiling; cross-camera association has its own bounded
work allowance. Metadata, source revalidation and publication retain their separate owner
bounds. This is not an accounting claim for all operating-system I/O or memory.

Exhaustion refuses the analysis before event publication. All aggregate limits participate in
the new mode's identity, even when changing a limit does not change the observed entries.

## Review, publish and restart

Without `--approve`, the complete `fss.long_corroboration_report.v1` projection is read-only.
Review each candidate's proposal and rerun its exact `publish_command`. A comma-separated
`--approve sha256:PROPOSAL[,sha256:PROPOSAL...]` publishes only the matching candidates.

The complete report is bounded before publication. A new analysis or privacy binding requires
a new approval; ordinary short-recording corroboration approvals cannot authorize this mode.
Publication revalidates both cameras, retains the provenance graph root-last, and uses the
existing guarded event publisher. Exact completed retries do not append another event. Cold
retry recomputes from retained source, and damaged or deleted custody is refused.

Each published camera analysis also retains the complete owner recipe under the reported
`plan_digest`: both imports and homographies, ground zones, perception thresholds, all codec
and scan limits, recovery mode, common-cause declarations, decoder identities and health
policy. The recipe is bounded to 128 KiB and belongs to the event's source closure. The typed
`LongCorroborationRecipe::from_retained_bytes` API verifies an independently pinned digest and
recovers those exact inputs; `analyze` reruns them against current retained source and privacy
authority. Unknown semantics, changed bytes or trailing data are refused. A remembered command
is therefore unnecessary to recover the published computation's owner settings. Replaying a
recipe does not authorize event publication, and an exact publication retry refuses damaged
recipe custody even when an earlier event already exists.

The policy can report an alert-preparation affordance for an admitted corroborated event.
Preparing or dispatching an alert remains its own separately approved operation. An empty
result has no absence-certification meaning, and this mode publishes no coverage witness.

Focused native regression targets:

```sh
cargo test -p fss-cli --test corroborate_stream_cli
```

Synthetic fixtures exercise the pipeline and evidence contracts. They do not qualify live
camera throughput, deployment detection accuracy, a continuous service, or a release.

## Read and verify a published event

Use `fss-event read --root DIR --site SITE --event-id ID` to inspect an original published
whole-recording candidate after restart. The response explicitly distinguishes inspection from
native replay and supplies exact revision/provenance pins and a verification command.
`fss-event verify` reruns the retained computation and compares the complete analysis and event.
See [cold event recovery](long_event_replay.md) for recipe scope, bounds and validation status.
