# Standard AVC FLV file ingest

FSS can import a finite standard AVC FLV recording directly into the ordinary retained
source workflow. The original FLV bytes remain the custody source. Native decoding,
privacy masks, detector packages, watch analysis, dwell/sentinel analysis, localization
and retained video publication use the existing AVC consumers.

## Import and read

Use automatic format detection or the explicit `flvavc` hint:

~~~sh
fss-file import \
  --root /absolute/path/to/deployment \
  --site site:example \
  --input /absolute/path/to/recording.flv \
  --sensor sensor:entry \
  --stream stream:entry-main \
  --receive-time-ns 1795219200000000000 \
  --media-format flvavc
~~~

Use the returned `import_identity` for inspection, original-source verification or an
IDR-led decoded range:

~~~sh
fss-file inspect \
  --root /absolute/path/to/deployment --site site:example \
  --import-id sha256:IMPORT_DIGEST

fss-file verify \
  --root /absolute/path/to/deployment --site site:example \
  --import-id sha256:IMPORT_DIGEST

fss-file decode \
  --root /absolute/path/to/deployment --site site:example \
  --import-id sha256:IMPORT_DIGEST \
  --segment 0 --segment-count 10 --interpretation ycbcr
~~~

Select a range that exists and begins with an actual AVC IDR picture. A predicted
picture cannot initialize a decoder. The original input pathname is unnecessary
after a completed import: inspection and decoding use retained chunks and source
capsules. Original-source verification hashes the entire retained FLV file,
including audio and script bytes that are outside the selected video stream.

The separate `fss-probe --parameters` operation still inspects only an initialization
prefix. A successful prefix probe does not imply successful full-file admission.

## Admitted profile

The demuxer accepts the ordinary FLV version 1 header and unfiltered video, audio
and script tags with zero stream IDs and exact previous-tag-size back-references.
A video-present header is required; audio tags also require the header's audio bit.
Audio and script payloads remain opaque retained structure and are never decoded or
treated as timing authority.

The first video tag must provide an AVC sequence header. Its SPS/PPS and optional
SPS-extension NAL ranges point into the original FLV bytes. Repeated sequence headers
must have exactly the same configuration bytes. In-band parameter NALs must also
match the retained configuration; parameter changes require a different import
profile and are refused here.

Each selected sample is the original length-prefixed AVC body of one video tag,
with exact tag and NAL ranges. The reader admits one-, two- and four-byte NAL lengths.
Video tags must use the ordinary key/inter frame assertions, and the keyframe
assertion must agree with IDR NAL presence. Parsing does not establish native
decoder conformance or prove that a tag represents exactly one decoded picture;
the retained decoder independently enforces its complete-picture contract.

There is no extended-FLV heuristic resynchronization, vendor tag interpretation,
encrypted/filtered video, HEVC, timestamp-wrap inference or torn-tag recovery.
Malformed or unsupported input refuses the entire import before source publication.

## Time and custody

The public `fss_container::demux::FlvVideo` index preserves the original unsigned
millisecond decoding timestamps and signed 24-bit composition offsets. Presentation
coordinates can therefore be negative or reordered. Video decoding timestamps must
increase strictly; duplicate, reversing and wrapped timestamps are refused.

A sample's optional duration is the difference to the next observed video decoding
timestamp. The final sample has no duration. An end-of-sequence marker or script
metadata cannot supply the missing duration. Variable observed decoding intervals
are preserved without normalizing them to a fixed frame rate.

The importer reuses the existing container-capsule path. With an explicit capture
hint, each capsule's nominal offset is its FLV presentation coordinate relative to
the earliest selected presentation coordinate. The hint's assumed frame rate does
not replace observed FLV timing. This remains an `operator_assumption` with estimated
clock basis. Without a hint, capture time stays `unknown`; media timestamps do not
become UTC, receive time does not become exposure time, and file custody never
certifies physical absence.

Samples and typed `flv_` structure spans account for every original byte exactly
once. Parameter spans use `flv_avc_parameter_set:nal_length_bytes=N`. The existing
chunk, manifest, completion, current deletion, authority and privacy checks remain
in force before retained data or pixels are served.

The movie-time selector and movie export retain their existing MP4/Matroska profiles.
This increment enables ordinary source-range decoding and analysis; it does not
invent an FLV movie timeline or a final-frame presentation interval.

## Bounds and refusal

The native parser uses `DemuxLimits` for source bytes, metadata, header/tag count,
samples, table entries and NAL count. For FLV, `maximum_boxes` counts the file header
plus every tag, and `maximum_metadata_bytes` counts every byte outside selected
video sample bodies, including opaque audio and script payloads. The packet owner
also caps each tag payload at 4 MiB and the FLV header at 4096 bytes.

The file adapter uses its existing source/sample bounds and the demuxer's default
4096 header/tag ceiling and 8 MiB metadata ceiling. Native callers may narrow limits;
invalid or exceeded bounds refuse without returning a partial index. Cancellation
is checked at bounded framing, sample and NAL stages and before returning the index.

`ERR-INGEST-FLV-REFUSED-001` identifies complete FLV admission refusal. Keep the original
source intact; repair or independently remux a copy into a supported profile.
Do not reinterpret a refusal as a partially imported recording or silently drop tags.

## Verification scope

The complete native container unit target passed **170 tests**, including seven new
FLV demux contracts and the eleven existing FLV parameter-probe tests, with the pinned
nightly compiler before the execution environment disconnected. The new contracts use
a first-party FLV wrapper around the existing real encoded AVC fixture, check exact
sample/NAL/parameter source spans and signed timestamps, and cover variable cadence,
configuration drift, malformed framing, every truncated prefix, independent bounds
and every parser cancellation checkpoint.

Six native reference integration contracts and two real-process CLI contracts are
authored for cold original custody, frozen independent AVC pixel hashes, explicit
capture assumptions, current privacy masks, IDR admission, detector execution and
atomic/typed refusal, including cancellation during initial format admission. They
have not yet executed in this session. The component
result does not qualify the complete reference/CLI graph, physical cameras, detection
quality or production deployment.
