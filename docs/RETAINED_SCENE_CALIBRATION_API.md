# Retained calibration for native scene geometry

`fss_reference::ingest::scene_calibration` resolves already adopted site
calibrations into an immutable owner suitable for native scene reconstruction.
It consumes the existing FSSCAL01/FSSCAL02 format, calibration adoption history
and withdrawal history. It does not solve another calibration or publish one.

## Resolve the complete selected camera set

`resolve_scene_calibration` takes an existing `ReferenceDeployment`, a
`SceneCalibrationRequest`, the exact imported `PropertyTwin`, a shared
`WorkBudget`, and `ReplayCx`.

The request includes the exact calibration bytes, the calibration's semantic
identity, and one `SceneCalibrationBinding` per selected camera. Each binding
supplies the original calibrated handle, the sensor selected by the retained
source, the expected current adoption digest, and the original camera input.
For a correspondence calibration this is the original observation text; for a
frame calibration it is the original JPEG metadata. The existing calibration
codec verifies those bytes and recovers their image domain and dimensions.

The FSSCAL identity is its domain-separated trailing identity. It is distinct
from SHA-256 of the complete file, which the owner also computes and exposes.
Callers that accept external paths should pin both identities and read every
input under explicit authority and finite byte limits.

Resolution requires all of the following:

- The calibration's twin package and original source scene match the imported
  twin exactly.
- Camera handles and physical sensors are nonzero/valid and unique in the
  complete selection.
- The original camera input is byte-for-byte the one pinned by the calibration.
- Atlas package/provenance and selected original image, metadata and luma
  identities are nonzero SHA-256 values; generic FSSCAL algorithm tags are
  never relabeled as SHA-256 image provenance.
- Every camera has an exact current, unwithdrawn retained adoption. The receipt
  agrees on calibration, camera name/handle, both intrinsics and extrinsics
  generations, sensor and twin.
- No other retained camera handle binds the same physical sensor.
- Calibrated distortion is zero and the refined intrinsics/pose form a valid
  native pinhole camera.

A missing current adoption refuses this explicit profile. Historical receipts,
an owner assertion, or a numerically plausible pose do not replace it.

## Use the verified geometry

`RetainedSceneCalibration::camera` and `cameras` expose read-only
`SceneCalibrationCamera` records. These retain the calibrated pose/intrinsics,
full original camera record, original image basis and exact adopted receipt.
`record()` on the enclosing owner retains the complete calibration's atlas,
control-point, solve, covariance and frame-policy provenance.

The CLI library's `SceneRig::from_retained_calibration` projects this owner into
the existing native `TrackingCamera` representation. Its additional declarations
contain the source-scene object mapping, property handles, image/clock/privacy
handles and use interval. These are owner declarations: calibration adoption
does not measure a clock offset, establish an expiry or prove that a camera
has not moved. The numeric calibration handle identifies the retained per-camera
adoption; the semantic rig binds the full owner identity and both generations.

Actual retained images must still match the adopted sensor and the original
calibration image domain and dimensions. This first profile consumes images
already in that pinhole domain. A source with the same dimensions but a different
crop, lens or rectification identity is not interchangeable.

The local adjustment covariance remains available in its original parameter
order. It is conditional on the calibration model and controls and does not
contain cross-camera covariance blocks. It is never converted into a
`ProjectionError` or absolute accuracy guarantee; native camera `error` remains
`None`.

## Revalidate before releasing results

After all source-dependent reconstruction and serialization,
`RetainedSceneCalibration::revalidate` checks the entire current adoption and
withdrawal history again and requires the same selected receipts and bindings.
The caller must also revalidate every original source and current privacy mask.

Unrelated ledger descendants, including ordinary retained JPEG derivatives, are
allowed. Another site/epoch, an older or divergent prefix, supersession,
withdrawal, or missing/corrupt authority custody refuses the complete result.
The resolution anchor remains explicit; it is not a physical validity interval.
The immutable selection digest does not change merely because unrelated ledger
records were appended.

## Complete bounded accounting

| Resource | Bound |
|---|---:|
| Selected cameras | 1–16 |
| Calibration file | 4 MiB |
| Each original camera input | 1 MiB |
| Complete calibration and original inputs | 20 MiB |
| Authority batches / deltas traversed | 65,536 each |
| Cumulative authority-read reservations, including revalidation | 64 MiB |

Input validation, canonical decoding, complete authority traversal, bounded
custody reads and geometry projection share the caller's `WorkBudget`. Every
custody read checks explicit authority before and after I/O. Read reservations
are spent before the read; failed reads and repeated revalidation never refill
the allowance. The owner exposes admitted input bytes, actual verified authority
bytes and cumulative reserved authority bytes separately.

This owner establishes the retained adoption dependency of an analysis. It
does not establish physical field accuracy, activate new calibration, identify
an entity, grant source access or authorize an effect.
