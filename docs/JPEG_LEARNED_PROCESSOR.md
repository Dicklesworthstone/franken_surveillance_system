# Resumable native JPEG learned-event processor

`fss_twin::screening::tracking::hog::jpeg::JpegHogPipeline` composes the
existing native JPEG decoder/rectifier, independent screening monitor, learned
HOG scanner, anonymous tracker and image-zone monitor into one bounded owner.
It executes real model arithmetic over actual decoded pixels; it does not supply
mock detections or a second tracker. Model weights must be explicitly provisioned
and verified through `HogModel::from_f32_le`.

The processor runs the requested whole-image learned scan even when foreground
comparison finds no change. A stationary learned candidate can therefore reach
sampled dwell. Model margins do not clear health faults: the existing
`HogZonePipeline` still requires the exact source/mask/health/stream basis before
assimilating a measurement. Missing background or exhausted foreground work
remains degraded, not silently treated as a healthy empty scene.

## Ownership and use

Construct an empty `ImageZonePipeline` with the exact rectified coordinate basis,
tracking policy, zone polygons and zone policy. Move it, a verified `HogModel`,
and a `JpegHogConfig` into `JpegHogPipeline::new`. The configuration fixes the
stream generation, receive-clock start, independent screening policy, complete
scale schedule and scanner policy. The scanner validates its full numerical and
policy contract before producing a result; invalid settings never consume a
tracking exposure.

`observe` accepts the existing `JpegScreeningQuery`, optional `JpegBackground`,
`RectificationPlan`, and six separate budgets: decoder, rectification, foreground,
health, inference, and tracking/zones. They should all share the operation owner's
cancellation flag. Decode/health work is not spent out of the model allowance.
No new source is accepted while the preceding one has unfinished computation.

The input supplies original encoded bytes and their hash, source exposure,
permission mask and its hash, camera, capture-clock interval, receive-clock
stamp, stream generation and decoder interpretation. Neither frame ordinal nor
receive time becomes capture time. The decoder and calibration contracts remain
unchanged. An active trajectory automatically requests the existing next-frame
analysis floor, without acknowledging semantic completion.

## Explicit stage machine

```
AwaitingImage -> Inference -> Tracking -> Zones -> Complete
                   |             |          |
                   +-------------+----------+-- Pending: retain and resume
```

The implementation has one commit boundary per existing owner, not a fictional
transaction across all subsystems:

* Before native decoding/screening accepts the source, `observe` returns an outer
  error and leaves the preceding completed image/results unchanged.
* After screening succeeds, `image()` retains the actual `ScreenedJpeg` even if
  scanning runs out of work or is cancelled. `Pending { stage: Inference }` means
  `resume` must scan that same retained image, not send it through screening again.
* Once scanning completes, `scan()` retains **every** window, margin, mask omission
  and suppression link. A tracking refusal returns `Pending { stage: Tracking }`;
  `resume` uses that immutable scan and needs no more inference allowance.
* If tracking consumes the exposure but zone work fails, the accepted tracking
  receipt remains available and the stage becomes `Zones`. `resume` only finishes
  the existing zone computation; it never rescans, ingests or ages the track again.
* `Complete` returns exact image, scan, tracking and zone roots. Repeating `resume`
  returns the same roots without work or mutation. It does not grant durable custody.

`tracking_report()` and `zone_report()` expose only the current input's completed
stages. They never substitute a preceding input's zone result during inference or
tracking refusal. `zones()` exposes the underlying read-only history explicitly;
that owner's last trajectory can predate a pending image.

A resource refusal can be resumed with a sufficient allowance. A permanent basis,
model/profile or privacy mismatch is not fixed by blindly retrying: retain the
pending image/scan and begin a separately admitted new episode after resolving the
cause. The processor provides no implicit reset or discard operation that could
hide an unfinished source. Prior completed images must be retained elsewhere by
the caller before accepting later input if their custody policy requires it.

## Health while computation is delayed

`poll(owner_now_ns)` keeps the independent input-silence watchdog usable during
inference or downstream pressure. A stall is local missing-input evidence, not
proof of physical camera failure or absence. The watchdog updates no model or
trajectory. Its supplied monotonic time must not regress; subsequent input stamps
must respect that clock.

The owner does not call `acknowledge_analysis` automatically. A completed hash is
not proof that a durable result was published or that an alert reached anyone.
Source retention, result publication, effect authorization and alert delivery
remain their separate existing contracts.

## Scope and verification

This is a synchronous in-process processor over complete JPEGs, not a live camera
transport, daemon, persistent checkpoint, full neural detector or qualified
person/intrusion model. It owns one current screened image and complete scan, plus
the bounded existing tracker/zone state. It does not introduce runtime/network
access, dependencies, hidden threads, model downloads or physical effects.

Nine Rust contracts were authored for native JPEG/source linkage, exact stage
retries, downstream budget boundaries, cancellation, corrupt new input, independent
health under foreground pressure, stationary sampled dwell, watchdog availability
and privacy drift. Synthetic coefficients and explicitly enlarged tiny JPEG
fixtures isolate execution semantics; neither is evidence of pedestrian accuracy.

```sh
cargo test -p fss-twin --test jpeg_hog_pipeline_contract
cargo test -p fss-twin --test hog_zone_contract
cargo test -p fss-twin --test mjpeg_screening_contract
cargo check -p fss-twin --all-targets
```

Rust compilation/tests, rustfmt, Clippy, real-camera operation, performance and
controlled-host qualification were NOT RUN in the authoring environment, which
has no Rust toolchain. Source/API, lexical and exact hash checks do not substitute
for those runs. No FSS-076/FSS-077 or release-gate completion is claimed.
