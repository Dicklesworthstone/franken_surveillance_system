# Retained calibration residual monitoring

`fss-event calibration monitor` measures one adopted camera’s frozen pose against native
features from an exact retained localization package. It reports `pass_under_policy`,
`contradicted`, or `indeterminate`. The report concerns the original recorded exposure and its
capture interval. Passing does not establish current or continuous physical camera validity.

This connects the existing `fss-twin::calibration_monitor` to retained source custody, native
JPEG/AVC/HEVC replay, original calibration metadata, per-camera adoption and explicit derived
publication. It does not fit a replacement pose or consume a calibration-withdrawal approval.
A contradiction can justify reviewing a separate owner withdrawal; it is not itself proof of
physical camera movement. Incorrect map points, interpretation or matching can also contradict
a frozen pose.

## Prepare exact inputs

Start with an existing `fss-event calibrate` calibration and adopt its camera with
`fss-event calibration adopt`. Keep its canonical calibration file and the original camera
input text. For correspondence calibration this is the original
`fss.site_camera_observations.v1` file. For JPEG calibration this is the original
`fss.site_camera_frame.v1` metadata file. Its digest is already pinned by the v1 or v2
calibration; the monitor cannot accept replacement metadata or a caller-invented image domain.
No calibration wire version changes.

Use `fss-file localize` with `--retain-result yes` for the independent observation. Its existing
explicit source, geometry and perception options still apply. Keep all three printed pins:
`localization_identity`, `localization_root` and `localization_receipt`. The selected recording
must be from the adopted sensor, with the exact calibration twin and atlas packages, matching
native descriptor generation, image grid, image domain and frozen camera intrinsics.

The monitor requires an undistorted pinhole calibration (`distortion = [0, 0]`). The retained
localization may use native pinhole pixels or explicit raw-lens rectification into that exact
grid. For original JPEG calibration the original component interpretation is also enforced.
The package’s current v1 flat-source restriction applies; partitioned imports are refused by
the existing localization owner. Neither command opens network camera connections.

## Review measured residuals

Use the exact current adoption receipt printed by `calibration show`:

```sh
fss-event calibration monitor \
  --root /srv/fss/site --site site:home \
  --calibration /srv/owner/site.calibration \
  --calibration-digest sha256:CALIBRATION_DIGEST \
  --camera-handle 21 --adoption-digest sha256:ADOPTION_RECEIPT_DIGEST \
  --camera-input /srv/owner/east.observations \
  --localization-id sha256:LOCALIZATION_ID \
  --localization-root sha256:LOCALIZATION_ROOT \
  --localization-receipt sha256:LOCALIZATION_RECEIPT
```

The uppercase digest strings are placeholders for complete 64-digit SHA-256 values. Preview
runs native decoding and feature extraction, verifies the complete previously retained
localization receipt, and rematches its actual query features against the frozen pose. Its
fitted localization pose is never used as the monitoring baseline. There is no deployment
write, including on refusal. The optional `--report-out FILE` is an explicit report export.

The JSON `fss.calibration_monitor_report.v1` includes exact calibration/adoption/source/map
pins, privacy binding, capture interval, match and inlier counts, image span, per-landmark
reprojection residuals, work accounting and the review approval. No pixels or descriptors are
included. The fixed v1 policy requires at least eight matched and in-image projected landmarks,
at least eight inliers, an inlier fraction of 0.7, and at least 0.08 image-width and image-height
span. Inliers must be within 3 pixels; inlier RMS must be at most 1.5 pixels. Insufficient
support, projection or span produces `indeterminate`, never a pass. Sufficient distributed
support that fails the residual/fraction policy produces `contradicted`.

The original calibration exposure and pixels are rejected as monitoring evidence. The same
holds for atlas reference exposures and exact reference pixels, including source luma before
rectification. An unavailable package, changed privacy binding, damaged source, mismatched
sensor/model/domain, reused fit/reference input, withdrawn or superseded adoption, cancellation
or exhausted budget is a refusal. It cannot become an observed pass or silently fall back to
owner-supplied correspondences.

The default native decode allowance is 100,000,000 units and geometry/read allowance is
2,000,000,000 units. Set positive `--work-units` and `--geometry-work-units` to explicit
execution ceilings. Native extraction and matching remain bounded to at most 512 features.
A caller’s larger execution allowance cannot change the frozen recipe or monitoring policy.

## Retain and reproduce

Review the measured report and run its exact `approve_command`. This reruns the native
observation, compares its exact approval, then retains a separate derived root. The root
contains the canonical observation, the original calibration bytes, original camera input,
exact adopted receipt, approval material and the localization package’s complete replay graph.
The observation is scoped to the site lineage and ledger epoch; unrelated ledger appends do
not change the approval. A wrong approval refuses before staging. Exact retries validate the
existing bytes and do not create a second observation or repair damaged custody.

The retained report prints a `replay_command`, equivalent to:

```sh
fss-event calibration monitor-replay \
  --root /srv/fss/site --site site:home \
  --monitor-id sha256:MONITOR_ID \
  --expected-root sha256:MONITOR_ROOT \
  --expected-receipt sha256:MONITOR_RECEIPT
```

Cold replay needs none of the original external files. It checks the exact retained recipe,
manifest, authority reachability and approval, then reopens the original native source and map
packages and compares the complete recomputed observation. Adoption is checked against the
exact ledger prefix immediately before that monitor’s verified publication. The adoption had
to be current and unwithdrawn at that point. A later owner withdrawal or newer calibration does
not prevent auditing the observation that motivated the change. A proposal staged before
withdrawal but published afterward cannot acquire historical admission: its actual publication
prefix contains the withdrawal and replay refuses it.

The replay report explicitly sets `adoption_check` to `monitor_publication_prefix` and gives
that prefix’s sequence and state root. It reports no new withdrawal recommendation. Replaying
an old passing or contradictory observation neither restores its adoption nor changes the
current replacement. New monitor previews, approvals and retention retries still require the
exact current unwithdrawn adoption.

Replay performs no publication or repair. Current source and privacy custody continue to
govern access; a later mask change still refuses the old source interpretation, and authorized
source deletion can make reproduction unavailable. Historical adoption verification grants no
current camera validity or coverage authority and cannot undo a retained owner withdrawal.

## Withdraw owner authority separately

A contradicted report’s recommendation contains the exact camera, adoption, `residual_drift`
reason and same-sensor source capsule. If the owner decides to withdraw this adoption, preview
that separate action:

```sh
fss-event calibration invalidate \
  --root /srv/fss/site --site site:home \
  --camera-handle 21 --adoption-digest sha256:ADOPTION_RECEIPT_DIGEST \
  --reason residual_drift --evidence sha256:SOURCE_CAPSULE_DIGEST
```

Review and explicitly approve that command’s separate withdrawal digest. The monitor’s
approval cannot authorize a withdrawal. Once withdrawn, existing currency guards refuse new
coverage and corroboration use until an independently reviewed newer calibration recovers the
camera. Monitoring itself neither activates geometry nor invalidates adoption automatically.

## Validation scope

Production native replay supplies the actual monitoring observations. The focused contract
suite in `recorded_twin_localization/monitor.rs` uses the real retained JPEG, codec, extractor,
atlas matcher, publication owner and cold deployment reopen, with controlled synthetic adopted
geometry. It checks a passing pose, a deliberately contradictory frozen pose, insufficient
projection, exact approval/retry/replay, withdrawal and newer recovery followed by historical
replay, refusal of publication after withdrawal, current privacy enforcement, fit reuse, changed
inputs and cancellation before staging. Those synthetic fixtures are not evidence of accuracy on an
owner’s real site. Deployment validation still needs representative independent site footage.
