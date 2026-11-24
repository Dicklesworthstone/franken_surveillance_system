# Native MJPEG AVI recording import

The ordinary `fss-file import` path accepts a finite classic RIFF AVI recording
containing one MJPEG video stream. It retains the original file, extracts the
original JPEG chunk ranges, and exposes those frames to the existing native JPEG
decode, watch, detector, dwell, health and replay paths. No external media tool is
required for import or decoding.

```sh
cargo run -p fss-cli --bin fss-file -- import \
  --root ./camera-evidence --site site:home \
  --input ./recording.avi --sensor sensor:driveway --stream stream:main \
  --receive-time-ns 1000000000
```

Auto detection uses RIFF/AVI bytes, not the filename. An explicit
`--media-format avimjpeg` selects the same parser. Successful imports report
`media_format=avimjpeg`; save the reported `import_identity` for later operations.

```sh
cargo run -p fss-cli --bin fss-file -- verify \
  --root ./camera-evidence --site site:home \
  --import-id sha256:YOUR_IMPORT_DIGEST

cargo run -p fss-cli --bin fss-file -- decode \
  --root ./camera-evidence --site site:home \
  --import-id sha256:YOUR_IMPORT_DIGEST --segment 0 \
  --interpretation gray --output ./first-frame.pgm
```

After a decode is published, `read-decoded` reopens the retained pixels and
`verify-decoded` replays the native decoder. `extract --segment N` exports the
original encoded JPEG. These operations work after the loose AVI is removed.
The existing budgets, deletion authority, source digest checks and publication
rules still apply.

## Admitted recording profile

| Field or structure | Accepted behavior |
| --- | --- |
| RIFF form | One complete `RIFF AVI `; declared length must equal the original file length |
| Lists | One `hdrl` before one `movi`; direct samples or one level of `rec ` lists |
| Streams | Exactly one video stream, `vids` / `MJPG`; declared audio streams remain opaque source bytes |
| Video header | 56-byte `strh`, positive `dwScale` and `dwRate`, variable-size samples, no initial-frame offset or stream flags |
| Geometry | 40-byte MJPG `BITMAPINFOHEADER`, one plane, 24-bit declaration, positive dimensions up to 65,535 |
| Video payload | One complete JPEG in each selected `##dc` chunk; SOF dimensions must match the stream header |
| Ordering | Physical video-chunk order; `AVIF_MUSTUSEINDEX` refuses |
| Timing | Exact rational `dwScale / dwRate` seconds per sample; `dwStart + sample_index` is the media presentation tick |
| Frame count | Nonzero stream count, main-header count and selected chunk count must agree |
| Presentation geometry | Main/stream dimensions agree; zero/default or identity `rcFrame`; optional progressive square-pixel full-frame `vprp` |
| Word padding | Preserved exactly, including nonzero padding bytes |

Interleaved audio, legacy indexes, unselected chunks and metadata are retained
under the complete original-source digest. Their bytes are not decoded or
interpreted as observations. Structural regions between selected JPEG ranges are
recorded as `avi_structure` omissions; that label describes bytes not selected as
video frames, not bytes missing from retained custody.

OpenDML/AVIX continuation files, multiple video streams, zero-length dropped
frames, palette changes, index-directed ordering, spatial transforms, interlaced field layouts (including AVI1 field polarity) and
codec-private data refuse. An AVI with a different video codec is not admitted.
JPEG admission and pixel decoding remain separate: a supported container cannot
make an unsupported JPEG coding mode decodable. Native decode requires each
JPEG to contain its own required quantization and Huffman tables; import does not
prove table closure or synthesize default tables for abbreviated MJPEG. There is no recovery that guesses
frame boundaries or silently drops corrupt video chunks.

The layout and timing rules follow Microsoft's
[AVI RIFF file reference](https://learn.microsoft.com/en-us/windows/win32/directshow/avi-riff-file-reference)
and [AVISTREAMHEADER fields](https://learn.microsoft.com/en-us/previous-versions/ms779638(v=vs.85)).

## Timing and custody

Container timing supplies relative media time, not a camera capture clock.
Without the complete capture-hint tuple, every capsule retains the existing
unknown-clock receive interval and `absence_certifiable=false`.

If `--capture-start-ns`, `--capture-uncertainty-ns` and `--assumed-fps` are supplied,
the start remains an explicit operator assumption. AVI's exact stream fraction
determines offsets relative to the first selected frame; `--assumed-fps` does not
replace it. For a `30000/1001` stream, the first three frame offsets round to
0, 33,366,667 and 66,733,333 nanoseconds. No live continuity or camera-absence
claim follows from this finite file.

Parsing and complete JPEG framing checks finish before retained publication.
The importer uses the existing root-last atomic publication and idempotent retry
path. Cold reopening verifies original bytes including audio, RIFF headers and
padding; frame extraction uses exact ranges within those bytes. The native JPEG
decoder publishes the same pixel/capsule provenance used for JPEG streams.

## Bounds and regression coverage

The core parser uses the existing `DemuxLimits` source, track, chunk, sample,
table-entry and metadata ceilings. For AVI, metadata bytes include every byte
outside selected JPEG payloads, including opaque audio and indexes. Container
limits apply alongside the file import's source, segment and MJPEG frame/input
limits. The file adapter permits up to 65,536 RIFF chunks and 32 MiB of non-video
bytes within those existing source limits. Cancellation checkpoints run at chunk,
sample and bounded JPEG marker-scan boundaries.

`avi_mjpeg_contract` covers both audio/video stream orderings, direct and record
lists, exact sample ranges, fractional timing, all truncation prefixes, unsupported
ordering and damaged profile fields, independent resource bounds, and cancellation.
`avi_file_ingest_contract` exercises automatic and explicit import, idempotent
retries, cold source verification and pixel decode after source removal, exact
fractional capture-hint offsets, and failure before mutation for ambiguous JPEG
framing or contradictory geometry. The `file_cli_contract` AVI case exercises the
ordinary command through import, cold verification, extraction and decoded replay.
