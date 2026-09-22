# Source-verified cold HTTP RGB replay

`fss_reference::ingest::http_replay::rgb::HttpRgbReplay` connects the exact
retained HTTP replay cursor to the existing `RgbJpegZonePipeline`. It performs
native JPEG decoding, privacy projection, frozen neural execution, detector-head
projection, anonymous image-space association and zone updates. It does not load
models, open sockets, substitute detection boxes, or publish canonical events.

## Use

Open the existing publisher and load `HttpWireArchive` against an independently
retained exact `HttpWirePin`. Construct a fresh `HttpWireReplay` and a ready
`RgbJpegZonePipeline` using the selected frozen model/head and historical temporal
owner. `HttpRgbReplay::attach` consumes both; refusal returns both unchanged.
No tracker state is implicitly cleared to make a replay succeed.

`step(HttpReplayAccess)` advances only the source owner. `AwaitingContext` means
an original mapped JPEG is held. Supply the existing `HttpRgbContext`: exact
response head, part ordinal, component interpretation, original coded-grid mask,
and independent `RgbFrameAdmission`. Its exposure must equal `http_rgb_exposure`
on this frame. Its compressed hash and mask are checked; capture time, calibration
and availability are never invented from replay position or HTTP receive time.

Call `analyze` with explicit source access, native RGB limits/budgets and scalar
execution context. Every original payload span is freshly verified before neural
execution. Once a stage is accepted, `resume` takes no replacement image, mask,
model or admission. It revalidates original source custody and resumes only the
unfinished stage. Complete source and analysis backpressure the next frame.

`ResultReady` supplies an opaque key containing the exact pin, source identity and
all four completed native-stage identities. `take_result` verifies the original
source again and transfers the mapped JPEG and complete analysis together. The
key is an in-process transfer contract, not a new durable format or capability.
A corrupt/deleted original, revoked disclosure or work refusal leaves both frame
and computation recoverable. No accepted inference or temporal update is repeated
merely because final transfer failed.

Inspect `processing_result`, `phase`, `completion` and `completed` after a late
refusal: computation may already have succeeded. `retire` transfers every original
parser remainder, pending native stage and completed result without I/O. A held
result taken out of the processor before source transfer failed remains explicit
in `HttpRgbReplayRetirement::held`.

The framing driver's `PrefixExhausted` remains distinct from `Complete`, including
for close-delimited input with no durable socket-EOF witness. Analysis does not
upgrade incomplete acquisition into recording completion, scene observability,
trained-model accuracy, identity recognition, durable effects or alert authority.

## Regression coverage and execution limits

`cargo test -p fss-reference --test http_rgb_replay` defines nine contracts:
real TCP acquisition/root-last publication followed by cold native neural replay;
length/chunked and replay-buffer equivalence; context/mask mismatch; retained
projection resumption; current disclosure/work refusal; corrupt originals during
result transfer; post-computation cancellation; stale completion keys; rejected
attachment ownership; and deleted originals during pending projection.

The fixtures execute synthetic JPEGs and a small numeric convolution model; they
are not a trained-detector benchmark. Rust compilation, this test target, rustfmt,
Clippy and native qualification were not run in the editing environment because
no Rust toolchain is installed. No release/qualification gate is advanced.
