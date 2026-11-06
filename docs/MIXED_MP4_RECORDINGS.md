# MP4 recordings with indexed samples followed by fragments

The native `fss-container` MP4 reader accepts a complete initial movie indexed by
`moov` sample tables followed by `moof`/`trun` fragments. This admits recordings made
with an initial indexed GOP instead of an empty initialization movie. Both AVC and HEVC
use the existing source-preserving `AvcMp4::parse*` entrypoints; `parse_inband*` retains
its additional `avc3`/`hev1` configuration rules.

The existing file adapter calls these entrypoints for sniffing and import as `mp4avc`
or `mp4hevc`. No new import format, decoder, production dependency, or custody encoding
is introduced. The container tests exercise parsing, extraction, and native decoding;
they do not themselves establish complete retained-store or device qualification.

## Admission and recovery

Initial indexed samples and later fragment samples form one decode-order selection.
Original sample ranges, decode ticks, composition offsets, durations, and sync assertions
remain separate from decoded pixels. Edit lists and track matrices remain source metadata;
media ticks are not capture-time or UTC evidence.

- The indexed tables must describe complete, nonoverlapping source bytes. The admitted
  profile requires a known `mdhd` duration to equal the initial indexed decode-duration sum.
- Fragments require `mvex` and valid selected-track `trex` defaults. A missing `tfdt`
  continues from the previous decode end, including the end of the indexed prefix.
  An explicit forward gap remains a gap; backwards decode time refuses the whole parse.
- Selected video may inherit its byte base from preceding track fragments under the
  bounded [cross-track addressing profile](IMPLICIT_MP4_FRAGMENT_OFFSETS.md). Only
  required predecessor extents are interpreted; video timing remains independent.
- Sample limits, table entries, box visits, NAL work, and extraction output limits cover
  the complete selection. Indexed and fragmented byte ranges cannot overlap each other.
- Strict parsing refuses incomplete boxes and sample ranges. A complete indexed prefix
  declaring possible fragments is accepted even if recording stopped before the first
  fragment. Empty initialization-only content remains insufficient.
- The recovery entrypoints additionally retain that complete indexed prefix when the
  first later fragment is torn. Later fragments survive only with complete media boxes.
  `truncated_tail()` records the unread suffix; discarded tail metadata is not validated.
  Incomplete indexed bytes and malformed timelines, defaults, or offsets in the retained
  portion still refuse.

The format follows the movie-extension model in ISO/IEC 14496-12, clause 8.8 and its
movie-fragment introduction: fragment information extends the initial movie.
[FFmpeg's own MOV/MP4 muxer](https://www.ffmpeg.org/ffmpeg-formats.html#mov_002c-mp4_002c-ismv)
can produce this layout with `frag_keyframe` without `empty_moov`.

## Frozen laboratory recordings

The new recordings remux the existing generated `testsrc2` video and sine-wave audio;
they contain no footage of people or property. The HEVC laboratory fixture then applies
the one explicit metadata adjustment described below. The original encodes and their provenance
are in [interleaved_av.md](../crates/fss-container/tests/fixtures/interleaved_av.md).
FFmpeg is a fixture-generation oracle only and is never invoked by the native tests or
production reader.

Generated using `ffmpeg version 6.1.1-3ubuntu5`, from the repository root:

```sh
ffmpeg -hide_banner -loglevel error -y \
  -i crates/fss-container/tests/fixtures/interleaved_av.mp4 \
  -map 0 -c copy -movflags frag_keyframe \
  crates/fss-container/tests/fixtures/mixed_av.mp4
ffmpeg -hide_banner -loglevel error -y \
  -i crates/fss-container/tests/fixtures/hevc_av.mp4 \
  -map 0 -c copy -movflags frag_keyframe \
  crates/fss-container/tests/fixtures/hevc_mixed_av.mp4
```

| Fixture | Bytes | Indexed video samples | Later video samples | SHA-256 |
| --- | ---: | ---: | ---: | --- |
| `mixed_av.mp4` | 7,545 | 5 | 5 | `7302e4839ecbf322ea614bcf9a75496e3cf4b0f17e4845017de09f2919e6f7e7` |
| `hevc_mixed_av.mp4` | 6,470 | 3 | 7 | `6559942bcf718bc7de53b44f2f134266d5a9f26c11ddd3eef7098097c7b8370d` |

The raw HEVC remux produced by the command above has SHA-256
`01550857c8e27ec3d6a8c8aead61c30f15f84dc0f508067169c1f89f7c89d037`.
[FFmpeg 6.1.1's writer](https://github.com/FFmpeg/FFmpeg/blob/n6.1.1/libavformat/movenc.c)
uses `calc_samples_pts_duration` for `mdhd`. This open-GOP recording declares 10,240 ticks
there, while its three indexed decode deltas total 6,144 ticks and the first fragment's
`tfdt` is 6,144. That declaration is outside FSS's existing admitted indexed-duration
profile; the production parser continues to refuse it with `Timeline`.

The retained HEVC laboratory fixture changes only the four-byte video `mdhd.duration`
field at absolute byte range `[280, 284)` from 10,240 to 6,144. This is an explicit fixture
adjustment, not a claim that every other duration convention is standards-invalid. No
media bytes, composition offsets, sample durations, fragment timestamps, or source ranges
change. Run this after the HEVC remux command to reproduce the checked-in fixture:

```python
from hashlib import sha256
from pathlib import Path

path = Path("crates/fss-container/tests/fixtures/hevc_mixed_av.mp4")
source = path.read_bytes()
assert sha256(source).hexdigest() == "01550857c8e27ec3d6a8c8aead61c30f15f84dc0f508067169c1f89f7c89d037"
assert source[260:264] == b"mdhd" and source[264] == 0
assert int.from_bytes(source[280:284], "big") == 10240
adjusted = bytearray(source)
adjusted[280:284] = (6144).to_bytes(4, "big")
assert sha256(adjusted).hexdigest() == "6559942bcf718bc7de53b44f2f134266d5a9f26c11ddd3eef7098097c7b8370d"
path.write_bytes(adjusted)
```

A regression restores the original field, verifies the original complete-file digest,
and requires both strict and import-style recovery parsing to refuse it. The production
reader never performs this laboratory adjustment or silently rewrites source metadata.

The AVC top-level boxes are `ftyp` at 0, `moov` at 36, initial `mdat` at 1561,
`moof` at 4421, fragment `mdat` at 4745, and `mfra` at 7435. The HEVC equivalents
begin at 0, 32, 1596, 3199, 3563, and 6360. Both files retain an unselected AAC track.
FFprobe's exact video sample positions are frozen in `tests/mixed_mp4.rs`.

All ten AVC and HEVC frames independently decoded by FFmpeg match the existing
`indexed_avc_i420.sha256` and `hevc_av_i420.sha256` frame hashes. The native tests require
those same hashes, exact original sample payloads and media ticks, and identical Annex-B
extraction. Container edit metadata can differ after remuxing; it is not normalized or
used to infer an absolute capture clock.

## Focused verification

```sh
cargo test -p fss-container --test mixed_mp4
cargo test -p fss-container
```

The mixed-recording tests also cover implicit decode continuation, explicit gaps,
backwards timestamps, an inconsistent indexed duration, source overlap across the two
layouts, combined budgets, cancellation at every parser checkpoint, every truncated
prefix of both fixtures, initialization-only refusal, missing or malformed extension
declarations, and an `avc3` selection spanning the indexed/fragment transition. Native
random-access decoding checks the later AVC IDR and HEVC CRA, including skipped HEVC
RASL pictures.
