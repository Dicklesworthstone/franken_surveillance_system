# Health-gated native JPEG tracking

`fss_twin::screening::tracking::ScreenedImageTracker` connects the existing native
foreground extractor and Hungarian image tracker to the independent sensor-health
screen. Its input is a complete foreground/screen pair, `ScreenedJpeg`, or
`FramedScreenedJpeg`. It does not identify people, classify objects, establish
coverage, publish durable events, or authorize alerts. These are anonymous,
conditional image-space proposals, not proof of physical identity.

This implements a functional integration slice relevant to FSS-077, not its
model/device/controlled-host qualification. Compilation, Rust tests, rustfmt,
clippy, live-camera operation and deployment performance were **not run** in the
authoring environment, which lacked cargo/rustc. Independent lexical checks,
source-preservation checks and hash checks do not replace those runs.

## Admission and retry contract

The wrapper reuses the exact foreground component conversion used by
`ImageTracker::update_foreground`; it does not introduce another detector,
matching algorithm or interpretation of missing pixels. Every retained component
and every underlying assignment decision remains available.

Only `NoFaultObserved` health can retain an `Available` foreground input. A freeze
suspicion, degradation or recovery window withholds measurement assimilation.
`NotObservable` yields an unobservable tracking input. Health cannot clear a
widespread foreground disturbance. Live hypotheses may coast or expire under their
explicit retention limits; neither state is a new observation or proof of exit.

Camera, clock, calibration, dimensions, detector/background policy, permission mask,
screening policy, stream generation and input lane are pinned. A framed lane also
pins the original stream source. A change requires a new explicit episode.
Skipping successful health reports or original sequence numbers is disclosed as a
health-history gap; that input does not assimilate measurements across the gap.
The next contiguous clean input may resume conditional association within the
underlying track's remaining horizon. Joining an existing monitor history similarly
withholds the first input. Restarting a monitor does not silently reset an episode.

A foreground refusal or missing background is an explicit error, not an empty
successful detection. Every failed tracking call preserves both tracker receipt
heads and consumes no exposure. Keep the immutable completed screen and retry only
tracking with a sufficient budget. Do not send the same exposure through the already
advanced health monitor again. Decode, health and tracking retain separate budgets.

Before screening the next frame, set
`ScreeningStamp.owner_requests_analysis = tracker.requires_analysis()` (or combine
it with other owner reasons). This keeps an analysis floor for active/coasting
hypotheses. **Never call `acknowledge_analysis` merely because tracking succeeded.**
Only the downstream executor's actual retained semantic result earns that credit.
The wrapper exposes its underlying tracker read-only for existing motion helpers.

## Operator replay

From the repository root:

```sh
cargo run -p fss-twin --example screened_jpeg_frames -- /path/to/manifest.txt
```

This is an owner-operated, read-only example, not a registered `fss/1` command or a
live service. It accepts bounded baseline grayscale or Y/Cb/Cr JPEG files through
the first-party decoder. The manifest explicitly asserts full-range pinhole
interpretation. It does not silently calibrate lens distortion, rotate images,
infer timestamps from file names, fetch weights or start a network connection.
For distorted-camera inputs, use the library's explicit rectification plan rather
than asserting this replay's pinhole model.

All seven setting groups must occur once, before frame rows. Blank lines and
whole-line `#` comments are permitted. Fields are whitespace-separated, in this
order; names below are descriptions, not inferred defaults:

```text
FSS_SCREENED_JPEG_REPLAY_1
sensor CAMERA CLOCK STREAM_GENERATION RECEIVE_CLOCK_START_NS IMAGE_DOMAIN_SHA256 CALIBRATION_SHA256 EPISODE_SHA256
image WIDTH HEIGHT FX FY CX CY MAXIMUM_RADIUS grayscale|ycbcr
background SELECTION_EVIDENCE_SHA256 VALID_FROM_NS VALID_UNTIL_NS MAXIMUM_SPREAD
foreground MINIMUM_CHANGE MINIMUM_AREA MAXIMUM_REGIONS WIDESPREAD_PER_MILLE
health MINIMUM_VISIBLE DARK_LUMA BRIGHT_LUMA EXTREME_PER_MILLE FLAT_RANGE REPEAT_FRAMES REPEAT_DURATION_NS STALL_AFTER_NS MAXIMUM_CAPTURE_UNCERTAINTY_NS RECOVERY_FRAMES MINIMUM_ANALYSIS_INTERVAL_NS SENTINEL_INTERVAL_NS ACTIVITY_HOLD_NS
tracking MAXIMUM_TRACKS MAXIMUM_DETECTIONS MAXIMUM_EXPOSURES MINIMUM_OBSERVATIONS MAXIMUM_MISSES MAXIMUM_GAP_NS MAXIMUM_SPEED GATE_PADDING MISS_COST AMBIGUITY_MARGIN
budgets DECODE_UNITS GEOMETRY_UNITS FOREGROUND_UNITS HEALTH_UNITS TRACKING_UNITS MAXIMUM_JPEG_BYTES
reference EXPOSURE_SHA256 CAPTURE_LO_NS CAPTURE_HI_NS - - JPEG_PATH JPEG_SHA256 MASK_PATH MASK_SHA256
query EXPOSURE_SHA256 CAPTURE_LO_NS CAPTURE_HI_NS ORIGINAL_SEQUENCE RECEIVED_AT_NS JPEG_PATH JPEG_SHA256 MASK_PATH MASK_SHA256
```

Supply 3–31 genuinely selected reference exposures, then at least one query; the
whole manifest is bounded to 128 rows and 65,536 bytes. All hashes must be nonzero
lowercase SHA-256 values. Exposure IDs are distinct source identities, not file
content hashes. Identical encoded bytes across independent exposures remain
possible and are considered by freeze screening.

Masks have exactly `WIDTH * HEIGHT` bytes, each 0 or 1. Paths are relative to the
manifest directory, cannot contain parent/root components, and must resolve to
regular files below that directory. Operate on an owner-controlled directory that
is not concurrently rewritten. Both mask and encoded content hashes are checked.
A frame is at most 16 MiB and 4,194,304 pixels; retained reference planes together
are bounded to four times that pixel ceiling. The five work budgets are total
allowances for the entire replay, not silently replenished per-frame allowances.
Geometry includes setup, reference rectification and baseline construction.

Output is newline-delimited JSON. `replay_basis` binds the exact manifest;
`screened_frame` retains source, capture and receive timing, health flags, analysis
admission and foreground refusal/omission counts. `screened_tracking` retains
receipt lineage, decisions, candidate costs/ambiguity, live track observations and
expiry reasons. A coasting track's `last_capture` and `last_exposure` remain the
last actual measurement, not the current frame. The health record is flushed
before tracking, so a refused tracking input does not erase its completed screen.
`tracking_refused` is explicit and exits nonzero. A complete prefix is never
reported as a complete replay: only a successful full run emits `complete`.
No semantic model is executed or acknowledged; the final semantic completion
count is zero, even when analysis is due.

### Existing-fixture smoke input

This creates an isolated laboratory replay using the repository's existing JPEG
fixtures. Repeated fixture bytes and synthetic source identities here are test
inputs, **not independent physical-camera evidence or deployment calibration**.
Run from the repository root. No external Python package is required.

```sh
python3 - <<'PY'
from pathlib import Path
from hashlib import sha256
import shutil
import tempfile
root = Path(tempfile.mkdtemp(prefix="fss-screened-jpeg-"))
fixtures = Path("crates/fss-codec-mjpeg/tests/fixtures")
for name in ("background.jpg", "gray.jpg"):
    shutil.copyfile(fixtures / name, root / name)
(root / "allowed.mask").write_bytes(bytes([1]) * (17 * 13))
h = lambda name: sha256((root / name).read_bytes()).hexdigest()
id = lambda label: sha256(("laboratory-fixture/" + label).encode()).hexdigest()
lines = ["FSS_SCREENED_JPEG_REPLAY_1",
    f"sensor 1 2 1 0 {id('domain')} {id('calibration')} {id('episode')}",
    "image 17 13 20 20 8.5 6.5 1 grayscale",
    f"background {id('reference-selection')} 0 1000 0",
    "foreground 10 1 64 1000",
    "health 16 10 245 900 2 3 20 100 5 1 5 40 10",
    "tracking 64 64 128 2 8 1000 100 8 100 0",
    "budgets 100000000 100000000 100000000 100000000 100000000 1048576"]
for n in range(1, 7):
    role, name = ("reference", "background.jpg") if n <= 3 else ("query", "gray.jpg")
    order = "- -" if n <= 3 else f"{n - 3} {n * 10}"
    lines.append(f"{role} {id('exposure-' + str(n))} {n*10} {n*10} {order} "
                 f"{name} {h(name)} allowed.mask {h('allowed.mask')}")
manifest = root / "manifest.txt"
manifest.write_text("\n".join(lines) + "\n")
print(f"cargo run -p fss-twin --example screened_jpeg_frames -- {manifest}")
PY
```

## Verification commands

```sh
cargo test -p fss-twin --test screened_tracking_contract
cargo test -p fss-twin --test screened_jpeg_tracking_contract
cargo test -p fss-twin --example screened_jpeg_frames
cargo test -p fss-twin --test image_foreground_tracking --test mjpeg_screening_contract
cargo check -p fss-twin --all-targets
```

The added contracts exercise real luma extraction, real compressed JPEG fixtures,
framed byte-range lineage, health weakening, complete components, explicit stage
failures, source/mask/policy/lane refusal, discontinuities, freeze/recovery,
no implicit semantic acknowledgement, cancellation and exact retries. The luma
suite cuts every tracking work-budget boundary and checks both state heads.
The example adds manifest validation contracts. Run repository qualification
separately on its controlled host; none of this documentation asserts its result.
