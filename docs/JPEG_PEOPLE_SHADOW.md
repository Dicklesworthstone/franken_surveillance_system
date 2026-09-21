# Native JPEG people-candidate replay

`jpeg_people_shadow` is an owner-operated executable that composes the existing
native JPEG decoder, pinhole rectification, frozen background, independent health
screening, actual pretrained HOG coefficients, anonymous tracking and image-zone
observations. It closes the local operator gap between separately callable
libraries and a complete, inspectable image-sequence run.

```sh
cargo run -p fss-twin --example jpeg_people_shadow -- /absolute/path/replay.txt
```

This is read-only **replay/shadow**, not a production model activation, live camera
service, canonical event publication or alert dispatcher. Only local regular files
beneath the manifest directory are read. No Python/OpenCV runtime, external model
server, network request or synthesized model is used. The explicit model selection
loads the pinned candidate described in `PRETRAINED_HOG_CANDIDATE.md`.

## Manifest

The header and all ten setting groups are required. Setting and zone rows precede
frame rows. Values below are illustrative operator assumptions, **not calibrated
security defaults**. Replace each `<...>` placeholder with a real retained identity
or local relative path. IDs are nonzero, 64-character lowercase SHA-256 strings.

```text
FSS_JPEG_PEOPLE_SHADOW_1
sensor 1 2 1 0 <camera-domain> <calibration> <episode>
image 320 240 400 400 160 120 1 grayscale
background <reference-selection-evidence> 0 1000000000000 8
foreground 20 4 128 900
health 64 10 245 950 2 5 2000000000 3000000000 10000000 3 100000000 2000000000 1000000000
tracking 64 64 128 2 8 2000000000 500 8 1000 0
budgets 1000000000 1000000000 1000000000 1000000000 1000000000 1000000000 16777216 16777216
scan 8 8 0.5 500000 4096 512 320x240,256x192,192x144
zone_policy <zone-selection-evidence> 1000000000
model opencv-people-shadow-1
zone 1 2 3000000000 20,20 300,20 300,220 20,220
reference <exposure-1> 100000000 101000000 - - ref1.jpg <jpeg-1-sha> frame.mask <mask-sha>
reference <exposure-2> 200000000 201000000 - - ref2.jpg <jpeg-2-sha> frame.mask <mask-sha>
reference <exposure-3> 300000000 301000000 - - ref3.jpg <jpeg-3-sha> frame.mask <mask-sha>
query <exposure-4> 400000000 401000000 1 450000000 query1.jpg <jpeg-4-sha> frame.mask <mask-sha>
query <exposure-5> 500000000 501000000 2 550000000 query2.jpg <jpeg-5-sha> frame.mask <mask-sha>
```

Group field order, excluding each group name:

| Group | Ordered fields |
|---|---|
| `sensor` | camera, source clock, stream generation, monitor start receive time (ns), camera image domain, calibration, tracking episode |
| `image` | width, height, fx, fy, cx, cy, maximum normalized radius, `grayscale` or `ycbcr` |
| `background` | selection-evidence identity, validity earliest/latest capture time (ns), maximum luma spread |
| `foreground` | minimum luma change, minimum region area, maximum regions, widespread-change per mille |
| `health` | minimum visible pixels, dark luma, bright luma, extreme per mille, flat range, repeat frames, repeat duration ns, stall ns, maximum capture uncertainty ns, recovery frames, minimum analysis interval ns, sentinel interval ns, activity hold ns |
| `tracking` | maximum tracks, maximum detections, maximum exposures, minimum observations, maximum misses, maximum gap ns, maximum speed, gate padding, miss cost, ambiguity margin |
| `budgets` | decode units, geometry units, foreground units, health units, inference units, downstream units, maximum JPEG bytes, maximum output bytes |
| `scan` | x/y stride, minimum margin, suppression IoU millionths, maximum windows, maximum pre-suppression candidates, comma-separated `WIDTHxHEIGHT` grids |
| `zone_policy` | selection-evidence identity, maximum sample gap ns |
| `model` | exactly `opencv-people-shadow-1` |

A zone row is `zone ID MARGIN DWELL_NS_OR_DASH X,Y X,Y X,Y ...`. Polygons must
satisfy the existing strict-convexity, winding, image-boundary and uniqueness
contracts. There are 1–16 zones with 3–32 vertices each. Coordinates describe the
rectified image, not a metric property boundary. Dwell is a sampled span, never
proof of continuous presence. Tracking speed/gate/miss-cost interpretation is
defined by `fss_twin::image_tracking::ImageTrackingPolicy`; consult that API
when selecting those assumptions.

The image row explicitly assumes an already pinhole image mode with identical
source/target intrinsics. It is not a calibration certificate and does not silently
correct a distorted lens. Use the library `JpegHogPipeline` with a separately
compiled validated plan for other modes.

Every mask is a tightly packed width*height byte array containing only 0 or 1.
No missing-mask or all-visible default exists. JPEG and mask digests are checked
before native decoding. Repeat image bytes may be intentional, but exposure IDs
must be unique across all rows. Original positive query sequence numbers must
increase and receive timestamps must not regress. Reference rows have no query
sequence or receive time; they require literal `- -`.

The manifest is bounded to 64 KiB and 128 total frame rows, with 3–31 selected
references followed by at least one query. Grids are bounded to 4096 per axis and
the existing foreground pixel ceiling; the complete reference set is additionally
bounded. At least one scheduled HOG window is required. Scan limits apply to the
complete schedule and to candidates **before** suppression, not top-k survivors.
JPEG input is limited to 16 MiB per frame and JSONL output to 64 MiB per session;
lower owner-specified limits apply. Relative paths are canonicalized beneath the
manifest directory. This is a trusted operator replay interface, not protection
against hostile concurrent filesystem replacement.

## Complete output and failure behavior

Output is JSON Lines. `shadow_basis` binds the exact manifest, episode, model,
weights and provenance and explicitly disclaims qualification/effect authority.
Each accepted query emits `source_screen` and its foreground result. A successful
inference emits a `scan`, every `scale`, and **every** scheduled `window`. The window
record retains the raw margin, original-image bounds and a selected, suppressed,
below-threshold or unobservable state; suppression names its responsible window.

Current tracking output includes every assignment and association candidate,
active/coasting track, and explicit expired track. Current zone output includes
every track/zone cell and event. Event endpoints preserve original exposure,
clock, capture interval, pixel/input and detection identities. Neither model class
names nor anonymous track IDs identify a person or establish an intrusion.

`frame_complete` binds all four existing image/scan/tracking/zone roots. A terminal
`complete` is emitted only after every query and output record succeeds. Prefixes
without that terminal record, partial JSON lines and nonzero exit status are not
complete runs. Keep the local source files and manifest with the output: printed
hashes alone are neither media custody nor durable canonical publication.

All six work allowances are **whole-session totals**, including initialization and
selected reference processing; they never reset or refill automatically per frame.
A downstream refusal emits the accepted source and all already completed current
stages, then `pending` and a nonzero exit. No next query is consumed. A new process
can replay the original manifest with explicitly changed budgets; it cannot claim
to resume a lost in-memory owner. Integrators holding `JpegHogPipeline` in-process
can instead use its existing exact-stage `resume` API without re-decoding or
assimilating an exposure twice. The CLI does not invent another checkpoint format.

Quiet foreground does not skip learned scanning. Sensor freezes, history gaps,
privacy denial and unavailable measurements retain their original restrictions;
model scores cannot clear them. No semantic-analysis custody acknowledgement or
alert is manufactured. Low scores, missing scales, suppression, track expiry and
successful empty outputs never establish scene absence.

## Validation boundary

```sh
cargo test -p fss-twin --example jpeg_people_shadow
cargo test -p fss-twin --test pretrained_hog_contract
cargo test -p fss-twin --test jpeg_hog_pipeline_contract
```

Seven executable contracts use the native JPEG path and the actual pretrained
coefficients, covering complete quiet-frame replay, private windows, freezes,
retained source after inference-budget refusal, output quota failure, invalid
configuration/order/path and changed source bytes. The checked-in 80x144 JPEG is
procedural texture, not a person or a real-camera qualification corpus. Its low
test margin gate deliberately tests plumbing rather than model quality.

Rust compilation, these Rust tests, rustfmt and Clippy were not available in the
authoring environment. Lexical nesting and format-string checks are supplementary,
not a compiled build. This executable does not close held-out detector quality,
score calibration, live-device integration, canonical event or delivery gates.
