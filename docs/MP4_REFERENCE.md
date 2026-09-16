# Source-linked fragmented MP4 reference

FSS-115 / WP-060: `fss-container` adds a native safe-Rust, single-track AVC
fragmented MP4 derivative. This is reference source, not a qualified media
service, general MP4 implementation, H.264 decoder, or CMAF compliance claim.
It depends only on the first-party `fss-packet` interface.

## Remux without transcoding

`AvcMuxer` consumes borrowed `AvcPictureGroup`s from the packet/AVC receiver.
It emits an immutable initialization segment (`ftyp` + `moov`) and `moof` +
`mdat` fragments. The track uses `avc1`, exact out-of-band SPS/PPS and four-byte
NAL lengths. All admitted NAL bodies remain byte-identical. In-band parameter
sets move to `avcC`; every such move has an explicit mapping into the exact
initialization bytes. Other mappings preserve original RTP spans, including
synthesized FU-header provenance. MP4 bytes alone do not replace the source
custody graph, boundary classifications or companion mapping receipts.

This first subset admits progressive Baseline/Main/High 8-bit 4:2:0 groups.
Each fragment must start with an observed IDR. Non-IDR intra pictures do not
qualify. Unverified EOF tails, missing initial macroblocks, declared
input discontinuities, mixed owner epochs and changed exact parameters fail
closed. These gates do not prove that entropy-coded pictures are complete or
decodable; original assembly evidence remains visible in the sample receipts.

## Explicit time and transactional state

The caller supplies positive track time scale, decode times, durations and
signed composition offsets. The writer never guesses decode time from RTP
sampling timestamps, arrival time, VUI, frame numbers or a nominal frame rate.
`tfdt` is version one; `trun` carries signed version-one composition offsets.
Presentation/decode arithmetic is checked. Decode times must be contiguous
inside a fragment; gaps between independent IDR-led fragments are explicit
receipt intervals, never filled with fabricated frames.

Sample, NAL, source-span, initialization and fragment-byte bounds are checked
before copying media. Bounded allocations are fallible. Refusals leave fragment
sequence, previous end time and source cursor unchanged; input pictures remain
owned by the caller. Source overlap/replay is rejected even under new timestamps.
Sequence numbers do not wrap to zero. This synchronous bounded component has
no retained media queue, worker, file, socket or implicit publication authority.

## Reproduction and limits of evidence

```sh
cargo test --locked -p fss-container
python scripts/check_mp4_fixtures.py
bash scripts/qualify.sh --lane rust
```

The Rust contracts compare initialization/header bytes against an independent
Python layout oracle and check all emitted NAL/source ranges. The laboratory
script remuxes the two existing synthetic bitstreams, checks golden bytes, and
compares decoded frame hashes with the originals using FFmpeg. Normal runs do
not rewrite goldens; `--regenerate` is an explicit laboratory maintenance action.

The authoring environment executed the Python/FFmpeg checks: both MP4 clips
were readable, dimensions/counts matched, and all ten decoded frames matched
the original bitstreams. Exact hashes and the laboratory tool version are in
`crates/fss-container/tests/fixtures/expected.json`. **Rust compilation, Rust
tests, Rustfmt and Clippy were unavailable and are not represented as passed.**
The workspace/lockfile add only this first-party path package; native locked
resolution remains part of the unexecuted Rust lane.

One timestamp divergence is deliberately retained: FFmpeg 7.1's MOV demuxer
adds `-min(CTS, 0)` to presentation times when composition offsets are negative.
For the High/B-picture fixture that is 3,600 ticks (40 ms at 90 kHz). Raw `trun`
offsets match caller timing exactly; the oracle's normalized PTS are recorded
separately. No wire timestamp is changed to hide that behavior. Cross-player
absolute timing qualification remains open. The primary implementation reference
is FFmpeg 7.1 `libavformat/mov.c`, `mov_update_dts_shift` / `mov_read_trun`.

The format layout follows the W3C ISO BMFF byte-stream requirements for init,
movie-fragment-relative addressing, `tfdt`, and complete sample byte ranges:
https://w3c.github.io/mse-byte-stream-format-isobmff/ . Foreign encoders/decoders
remain laboratory tools, not production dependencies or runtime fallbacks.
