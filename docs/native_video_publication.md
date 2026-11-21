# Durable native video frames

`fss-video` composes the retained AVC/HEVC decoders and `PublishedVideoFrame` owner. It does not change the existing `fss-file decode` behavior or receipt formats. `publish` retains native masked I420 and the exact native receipt, with a cognition-completion batch for each frame. `read` checks completed custody without decoding. `verify` additionally replays the entire original range and compares the selected output's receipt and all three planes.

## Explicit publication

Use a completed retained import and the exact current sensor privacy-policy digest, or `none` only when no policy is declared:

```sh
fss-video publish --root /absolute/deployment --site site:home \
  --import-id sha256:IMPORT --codec avc --privacy-policy none \
  --read-originals yes --retain-derived yes --first-segment 0 --segment-count 3
```

All commands first return a pure JSON preview. Repeat the exact command with `--approve sha256:APPROVAL` from that preview. The approval binds command, paths, import, codec, privacy, range, export format and all resource settings. It is not authentication: the local operator process and protected deployment remain the trust boundary. AVC starts at an IDR; HEVC starts at a valid IRAP. Display positions and source access-unit positions are reported separately, and skipped HEVC RASL segments stay explicit.

Output is bounded JSONL (`fss.native_video_cli.v1`). Each `frame` record gives its stable `frame_root`, source identity, original range, output position, native receipt/pixel digests, privacy policy and completion sequence. A successful `terminal` record is the only whole-call completion marker. Frames commit separately. A later decode, budget or output error preserves the completed prefix; repeating the same publication revalidates existing frames instead of duplicating cognition or repairing damage.

## Cold reads and independent recomputation

```sh
fss-video read --root /absolute/deployment --site site:home \
  --import-id sha256:IMPORT --frame-root sha256:FRAME --codec avc \
  --privacy-policy none --read-originals yes
```

Use `verify` instead of `read` to re-run the original native computation. Verification drains the whole original range even after matching the selected display output. A later error or exhausted decode budget refuses verification. Checksums establish retained consistency; replay establishes agreement with this native decoder, not independent detector or camera accuracy.

Read and verify use one immutable retained-source owner. They can run while capture holds the exclusive publication owner, without acquiring its writer lock, initializing a deployment, recovering journals or appending frame/effect authority. The current site, source capsules, publication closure, original source, derived pixels and privacy policy remain subject to their native custody checks.

The complete JSONL response stays buffered until the opening snapshot's metadata and every selected payload have been revalidated, followed by a final authority check. This includes `started`, `frame` and `terminal` rows. A held writer is supported; an authority advance during the read, including a privacy change or an unrelated committed batch, refuses that snapshot. Retry against a stable committed authority position. Changed or missing source, pixels, publication metadata, tombstones or journal tails are refused without repair. These reads do not hold an authority lease after validation.

Linux reads can explicitly export `--output /absolute/new-file --pixel-format pgm|i420|rgb`. The output must be outside the deployment, with an existing parent and absent destination. A held parent-directory descriptor and create-new file avoid overwrite/redirection; output is owner-readable only. PGM contains luma, I420 contains packed Y/Cb/Cr, RGB uses the native transform and preserves mask fills. File creation starts after final source, pixel, privacy and authority validation. A failure before that boundary leaves no export or success rows. A later export I/O failure may leave a partial file, which is never erased automatically; a stdout I/O failure may leave a partial response. Cold access still requires the entire retained source and the exact current privacy policy; loose input files and cameras are not required.

## Bounds and limits

One request admits at most 1024 source access units, 4096 pixels per dimension and 4,194,304 luma samples. Decoder work is one cumulative native `encoded_bytes_plus_coded_luma_capacity.v1` allowance, including buffered/refused work. Publication also charges a cumulative derived allowance for every admitted frame (including reuse): all planes, receipt bytes and a conservative 4096-byte manifest reserve. Defaults are 8 billion decoder units and 64 MiB derived bytes; maximum derived allowance is 256 MiB. These are admission ceilings, not measured peak RAM or physical disk usage.

Original-source bounds apply to each native read/verification pass; publication intentionally re-verifies original custody and does not claim a one-pass source reader. Read and verify additionally have one nonrenewing aggregate allowance:

| Option | Default | Maximum |
| --- | ---: | ---: |
| `--max-read-bytes` | 1,073,741,824 (1 GiB) | 4,294,967,296 (4 GiB) |
| `--max-read-objects` | 1,000,000 | 4,000,000 |

The same allowance covers opening deployment metadata, source and pixel verification, all native replay reads, metadata revalidation and final payload/publication/authority rereads. Object counts measure payload-read attempts rather than filesystem syscalls. Repeated verification consumes the remaining allowance; it does not refill it. The immutable snapshot also retains its native metadata bounds. Both aggregate limits and the immutable-read policy are bound into the read/verify approval, so changing them requires a new pure preview and exact approval.

These two options are admitted only for read and verify. Explicit publication retains its existing exclusive owner, approval encoding, incremental frame commits and derived-byte accounting. The native frame roots and receipt encodings are unchanged.

Timeout defaults to 30 seconds, maximum 600 seconds, and is checked at bounded read admissions and between native operations. It does not preempt synchronous codec or filesystem calls. This command creates no deployment, camera connection, event classification, alert, continuous-coverage claim or absence certificate.

## Focused verification

```sh
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --test video_publication_contract
cargo +nightly-2026-08-31 test --locked --offline -p fss-reference --test video_publication_read_source_contract
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --bin fss-video
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --test video_publication_cli
cargo +nightly-2026-08-31 test --locked --offline -p fss-cli --test video_selection_cli
```

The immutable-read regressions cover an active writer, owner mismatch, exact aggregate allowances through final rereads, late source/pixel damage, cancellation, privacy changes, approved-limit isolation and torn-tail refusal without recovery. The process contracts also retain both-codec replay, whole-range drain and protected-export checks. These are reference contracts, not camera, detection-quality or release qualification.
