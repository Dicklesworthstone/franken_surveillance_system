# Bounded media probing

This document specifies the bounded pure-Rust media probe engine for **FSS-053** (`fss-x4a.12.2`), covering container-family probing and native AVC/HEVC configuration metadata extraction across Annex-B, MP4 (`iso-bmff`), Matroska/WebM, and FLV. Downstream beads (`FSS-054`, `TEST-MEDIA-MALFORMED-001`, and `GATE-040`) remain separately tracked and are not closed by probing alone, and probing does not establish camera or decoder support.

## Command

```sh
fss-probe < source-prefix
fss-probe --bytes 189 < source.ts
fss-probe --parameters < source.264
fss-probe --parameters --bytes 4096 --units 16 < source.265
fss-probe --parameters < initialization.mp4
fss-probe --parameters < recording.mkv
fss-probe --parameters < recording.flv
```

The command reads only stdin and writes one diagnostic line. There is no network access, source retention, decoding, model execution or automatic fallback. The original family-only invocation remains available.

| Mode | Default byte allowance | Result |
| --- | --- | --- |
| Family | 189 | Container-family signature, payload domain and ISO-BMFF major brand when present |
| `--parameters` | 4096 | First complete admitted Annex-B tuple, MP4 initialization, Matroska Tracks or FLV AVC sequence header, signalled dimensions/profile/level/depth, original parameter spans and inspection counts |

`--bytes` accepts 1 through 4096 for family mode and 12 through 4096 for parameter mode. `--units` is available only with `--parameters` and accepts 1 through 64. Invalid or repeated options refuse before reading stdin. Short reads are accumulated within the original allowance. Interrupted reads have a fixed retry ceiling, and output failures return an error status.

A successful AVC result has this shape:

```text
parameters container=annex-b codec=h264 scope=configuration-prefix coded_width=160 coded_height=128 display_width=160 display_height=128 bit_depth=8 profile=66 level=11 vps=none sps=START..END pps=START..END inspected_bytes=N inspected_units=N bytes=N
```

The numerical spans and counts come from the actual input. Spans are half-open byte offsets in that input, excluding Annex-B delimiters and trailing zero bytes. Source bytes are not printed. Non-alphanumeric ISO-BMFF brand bytes, except `.`, `_` and `-`, are percent-escaped so untrusted metadata cannot inject output lines or fields.

MP4 output reports `container=iso-bmff` and adds `track_id=N`; Matroska reports `container=matroska` and adds `track_number=N`. Their parameter spans point directly into the original `avcC` or `hvcC` record, excluding NAL length fields. The native `VideoParameters` API keeps the MP4 `track_id: Option<u32>` and exposes the separate Matroska `track_number: Option<u64>` without narrowing its identifier. Existing Annex-B results retain `container=annex-b` and have neither container track identifier.

## Two different claims

Family recognition is allocation-free and examines at most the lesser of the supplied head, the caller's byte allowance and the hard 4096-byte ceiling. It reports the required prefix size when the allowance is insufficient. In particular, MPEG-TS recognition requires sync bytes at offsets 0 and 188; the second byte is never inspected outside the allowance. The default now includes both bytes. The first sync byte by itself cannot prove a transport stream.

ISO-BMFF recognition preserves the major brand from the appropriate ordinary or extended-size header. Impossible short `ftyp` sizes refuse. Independent overlapping signatures return `Contradictory`. The `00 00 00 01` extended-size word overlaps the Annex-B delimiter by construction; an explicit extended `ftyp` header resolves that particular ambiguity. A three-byte Annex-B prefix conflicting with an ordinary `ftyp` header remains contradictory.

Parameter recognition is a separate operation in `fss_container::probe::parameters`. It reuses `fss_packet::avc::{parse_sps, parse_pps}` and `fss_packet::hevc::HevcConfiguration` instead of duplicating codec syntax. Supported reference scope is:

- AVC Baseline/Main/High, 8-bit 4:2:0, with an SPS followed by a matching PPS.
- HEVC Main/Main10, single layer, 4:2:0, with a bound VPS/SPS/PPS tuple.

Only admitted base-layer HEVC parameter headers select HEVC. An ambiguous PPS-like header before an AVC SPS does not select AVC. Ordinary leading AVC slice and HEVC IRAP headers therefore cannot manufacture a mixed-codec contradiction. Repeated identical parameter sets before tuple completion retain the first source binding; distinct competing candidates or mixed codec declarations refuse. Once the first complete tuple is accepted, subsequent configuration changes are outside this result's scope.

HEVC parsing retains the native owner's **configuration-prefix** boundary: VPS profile/tier/level, SPS dimensions/crop/depth and PPS binding are interpreted, while the remaining parameter syntax is not certified. Neither AVC nor HEVC success certifies picture decoding, full profile/level conformance, sample timing, frame rate, source custody, live continuity, coverage or physical scene truth. Coded dimensions and cropped display dimensions remain separate fields.

## MP4 initialization within the prefix

An ISO-BMFF prefix may supply parameters through `ftyp` followed by a complete first `moov`. The probe visits the track headers, media handlers and sample descriptions before selecting one video track. It admits one `avc1` AVC or `hvc1` HEVC description with a complete, internally bound parameter tuple. Other declared media-handler tracks may coexist; multiple video tracks, duplicate track identifiers, duplicate required boxes or competing parameter candidates refuse. An incomplete later track inside that `moov` cannot be hidden by an earlier valid video configuration.

Configuration-record framing and original NAL ranges come from the existing demux owner's `avcC`/`hvcC` parsers. Native SPS/PPS/VPS interpretation supplies the reported geometry, profile, level and depth. The record's profile/tier/level, chroma and depth declarations must agree with the admitted native parameters where those fields are present. A truncated native parameter inside a complete MP4 configuration is malformed metadata: more bytes after that box cannot repair it.

| Initialization feature | Probe behavior |
| --- | --- |
| Ordinary or extended-size boxes | Admitted within parent and prefix bounds |
| Top-level size-zero box | Requires observed EOF; an exhausted allowance cannot close it |
| Nested size-zero box | Refused |
| AVC `avc1`, HEVC `hvc1` | Admitted with complete supported tuples |
| `avc3`, `hev1`, other video entries | Unsupported in this initialization-only operation |
| `encv`, `sinf`, compressed `cmov` | Unsupported |
| Multiple video tracks/descriptions | Contradictory; no implicit track preference |
| `moov` after media outside the prefix | Incomplete or byte-limited; no seeking |
| `mdat`, fragments or another initialization after the completed first `moov` | Outside the reported configuration-prefix scope |

The prefix may end exactly at the declared `moov` boundary without EOF: its box size closes that metadata. Sample tables, samples, later parameter changes, data-reference targets and media availability are not validated, and no external reference is followed. Track matrices and sample-entry display transforms are not applied to native SPS dimensions. This result is useful for inspecting initialization and planning later admitted work; it does not certify a complete or playable MP4.

In addition to the caller's byte, NAL and geometry ceilings, MP4 traversal has hard limits of 128 visited box headers and 16 declared tracks. Traversal follows a fixed initialization hierarchy, with no unbounded recursion. The complete selected configuration record is checked before a result is returned; its SEI NAL arrays consume the NAL allowance even though they do not supply reported parameters.

## Matroska Tracks within the prefix

A Matroska prefix may supply parameters through a complete EBML header, a Segment header and the complete first Tracks element before any Cluster. Known-size and unknown-size Segments are admitted. Tracks must have a declared complete extent within the byte allowance; neither media frames nor the Segment's remaining bytes are needed to close this metadata result. The existing demux owner's EBML header and track grammar are reused, including its admitted `matroska` and `webm` DocType values, reader-version bounds, required track fields and checksums.

Exactly one video track must declare `V_MPEG4/ISO/AVC` or `V_MPEGH/ISO/HEVC` with a complete CodecPrivate `avcC` or `hvcC` record. Audio and other nonvideo tracks may coexist. Every entry's track number/type, child extents and applicable metadata CRCs are examined before returning, so a later duplicate identifier or malformed declared structure cannot be hidden by an earlier configuration. Multiple video tracks are unsupported in this operation, which has no implicit track preference. Duplicate required fields are contradictory; duplicate or zero track numbers and corrupt metadata are malformed.

Matroska and MP4 share the native configuration-record interpretation and original parameter bindings. HEVC parameter arrays must declare complete VPS/SPS/PPS content; incomplete arrays that would require later in-band state are unsupported. The reported coded and cropped dimensions come from native SPS interpretation. Matroska PixelWidth/PixelHeight must satisfy the existing track grammar, but container display dimensions, pixel cropping, aspect-ratio transforms and timing do not override or expand this codec-prefix result.

| Matroska initialization feature | Probe behavior |
| --- | --- |
| Known-size or unknown-size Segment | Admitted without waiting for the media tail |
| Complete first Tracks at the exact byte allowance | Admitted without observing EOF |
| Unknown-size Tracks, TrackEntry or other Segment metadata | Unsupported |
| ContentEncodings or TrackOperation on the selected video | Unsupported |
| CRC in complete EBML/Tracks/TrackEntry and selected-video Video metadata | Verified by the existing demux grammar |
| Leading CRC of a skipped Segment-level master | Verified over that complete master's bytes |
| Segment-level CRC | Unsupported; a bounded prefix cannot verify the unread media covered by it |
| Cluster reached before Tracks | Unsupported; the probe does not seek through media |
| Samples, another Tracks or changed parameters after the completed first Tracks | Outside the reported configuration-prefix scope |

Traversal is bounded by 128 visited element headers and 16 declared tracks, in addition to the caller's original byte/NAL/geometry limits. Nested track parsing has a fixed hierarchy. A parsed initialization child extending beyond a complete parent is malformed even when more source bytes follow; an incomplete first Tracks within an unfinished prefix remains insufficient or byte-limited. No external resource is followed, no frame is decoded, and success does not certify a complete or playable Matroska recording.

## FLV AVC initialization within the prefix

An FLV prefix may supply AVC parameters through a complete version-1 header and
the first video tag. The probe reuses the packet owner's borrowed FLV header,
tag and AVC video views, then the same bounded `avcC` interpretation used by MP4
and Matroska. The first video tag must be an ordinary, unfiltered AVC sequence
header with keyframe signalling and a zero composition offset. FLV output reports
`container=flv`; original SPS/PPS spans point directly into that tag's configuration
record, excluding NAL length fields. No track identifier is invented.

Complete leading audio and script tags may be skipped. Tag extents, stream IDs,
reserved flags and previous-tag sizes are checked even for skipped tags; audio
tags require the header's audio declaration. Script and audio payloads are not
interpreted. A media/video tag before initialization refuses instead of searching
for a later sequence header. Enhanced/vendor codecs, filtered tags, HEVC-in-FLV
and unsupported AVC packet forms remain outside this profile.

Traversal is bounded by 128 tags and the caller's original byte, NAL and geometry
ceilings. A complete sequence-header tag closes the result without observing EOF.
Later media, parameter changes and corruption are outside that accepted prefix;
no timestamp, frame-rate, source-continuity, decoder or playable-file claim follows.
Malformed native parameters inside a complete tag cannot be repaired by appending
bytes. Cancellation is checked at tag boundaries and by the shared configuration
parser before a result is released.

## EOF, bounds and ownership

The native parameter API takes an explicit `end_of_source` observation. A caller may set it only after observing EOF; exhausting an allowance is not EOF. A final undelimited Annex-B NAL is incomplete until either its next delimiter or actual EOF is observed. If an entire source is longer than the allowed prefix, its EOF cannot close the clipped prefix. The CLI never reads an extra byte just to decide whether EOF occurred. Consequently, an undelimited tuple ending exactly at `--bytes` needs a larger allowance to observe EOF, or a following delimiter within the allowance. MP4 uses its declared complete box boundaries, except that top-level size-zero boxes still require EOF. Matroska uses the complete declared Tracks boundary inside its Segment. FLV uses the complete declared AVC sequence-header tag and its previous-tag-size field.

`ParameterLimits` independently limits head bytes, NAL count, coded width, coded height and coded luma samples. Defaults are 4096 bytes, 64 NAL units, 8192 by 8192 coded dimensions and 67,108,864 luma samples. Dimensions are metadata bounds; probing allocates no pixel buffers. Native parser allocations are confined to the bounded parameter bytes. Invalid limits fail closed rather than widening or clamping policy.

Delimiter scanning is linear in the inspected prefix. Cancellation is checked on entry, between boxes/elements/tags and units, every 128 delimiter-scan bytes and before/after native parsing; a final cancellation withholds the result. The caller supplies that cancellation observation. The stdin CLI does not install a separate cancellation runtime or signal handler.

`VideoParameters` borrows the exact parameter bytes through `ParameterSource`; Rust prevents those backing bytes being mutated or reused while the result is live. Debug output exposes ranges, not payloads. This lifetime binding is not a durable custody record: an ingest owner must still bind stream/configuration generations and retained source evidence before using metadata in its own publication protocol.

The cost boundary is the admitted source prefix plus at most 64 bounded native NAL inspections and one successful configuration parse, with the additional fixed container traversal bounds above. `inspected_bytes` is the consumed prefix extent, including a terminating Annex-B delimiter, the completed MP4 `moov` the completed Matroska Tracks or the completed FLV sequence-header tag; skipped bounded container metadata remains within that extent. `inspected_units` counts complete units considered. These are inspection accounting, not measured CPU-time or decoding-cost claims.

## Exit statuses

| Exit | Meaning |
| --- | --- |
| 0 | The requested family or configuration-prefix metadata was identified |
| 2 | Invalid options/policy, I/O failure or bounded metadata allocation failure |
| 10 | The available prefix lacks enough information or a complete tuple |
| 11 | The requested container/codec/parameter syntax is unsupported |
| 12 | Conflicting signatures or parameter candidates prevent a coherent result |
| 13 | Native parameter parsing refused malformed/corrupt/mismatched input |
| 14 | Byte, unit, geometry or native syntax allowance was reached |
| 15 | Parameter cancellation, reserved in the CLI mapping for native cancellation outcomes |

Refusal of parameter extraction does not retract a separately established family signature. Neither result upgrades a source into a complete, retained or decodable stream.

## Focused verification

```sh
cargo test --locked --offline -p fss-container --lib probe::
cargo test --locked --offline -p fss-cli --bin fss-probe
```

The focused contracts cover retained AVC baseline/cropped fixtures, retained HEVC Main/Main10 metadata, exact source ranges, budget-tail noninterference, one-byte-short and one-unit-short refusals, geometry ceilings, EOF-versus-budget behavior, all cancellation checkpoints, contradictory candidates, cross-codec header aliases, native corruption/unsupported refusal, three-/four-byte Annex-B delimiters, trailing zero bytes, short/interrupted stdin reads, escaped brands and failed stdout writes. Native execution and broader qualification remain separately evidenced; the presence of these tests is not a passing qualification claim.

MP4 contracts additionally use retained baseline/cropped initializations and fragmented AVC/HEVC audio-plus-video fixtures, plus the independently retained HEVC Main/Main10 tuples. They exercise complete-moov release, exact original configuration spans, late-moov refusal, hidden/competing tracks, unsupported and encrypted entries, ordinary/extended/size-zero boxes, internal truncation, record-versus-native metadata contradictions, box/track ceilings and cancellation at every observed checkpoint. All fixture bytes are checked in; no foreign decoder or media tool runs in these tests.

Matroska contracts use retained AVC/HEVC audio-plus-video files and an unknown-size live Segment, plus independently retained Main10/cropped parameter tuples. They cover complete-Tracks release, full-width track numbers, exact source spans, altered-tail noninterference, malformed later tracks, checksums, transformed-track refusal, unknown metadata sizes, parent-boundary crossings, record contradictions, element/track ceilings and cancellation at every observed checkpoint. CLI tests exercise successful metadata output, byte/unit exhaustion, EOF distinctions and exact input consumption on all three retained Matroska files.

FLV contracts wrap retained AVC configuration records in the native FLV framing.
They cover exact source spans and cropped dimensions, leading audio/script tags,
every truncated prefix, malformed framing and reserved bits, unsupported first-video
forms, independent byte/NAL/geometry/tag ceilings, all cancellation checkpoints,
deterministic byte mutations and accepted-prefix tail noninterference.

**Executed component verification (2026-11-15; predates the FLV increment):** the pinned nightly-2026-08-31 toolchain compiled the core, packet and container libraries and both affected unit-test targets directly with `rustc` in Rust 2024 mode. The complete container library unit target passed **117 tests**, including all 12 new Matroska contracts and the existing MP4/Annex-B/demux regressions; the `fss-probe` unit target passed **16 tests**. A separately compiled `fss-probe` binary also passed 15 subprocess checks across the retained AVC, HEVC and live Matroska fixtures: successful metadata, exact prefix boundaries, short observed EOF and byte/NAL exhaustion. Pinned `rustfmt` and `git diff --check` also passed. These component results do not establish full Cargo/workspace CI or media qualification.

**FLV component verification (2026-11-20):** the pinned nightly-2026-08-31 toolchain rebuilt the current core, packet and container components directly with `rustc` in Rust 2024 mode. The full container unit target passed **163 tests**, including all 11 FLV parameter-probe contracts; the `fss-probe` unit target passed **16 tests**, and the actual CLI passed **13 FLV subprocess checks** for successful metadata, exact bounds, short EOF, malformed framing and unsupported forms. After adding the complete-file AVC FLV demuxer described below, the full container unit target passed **170 tests**. These are executed component results on source based at `7e336b8e457e11cffaf132b2176f78cf3da48371`; later unrelated core changes and the broader reference/Cargo workspace were not executed. The recovered demux source received independent source and byte-integrity review after the executor disconnected; no full-workspace or media qualification claim is made.

## Complete-file AVC FLV indexing

The native `fss_container::demux::FlvVideo` reader now indexes a complete standard
FLV v1 AVC file independently of the bounded parameter-prefix probe. It retains
the original header and every tag as a complete source tiling, exact sample and
NAL ranges, original AVC configuration ranges, raw decoding timestamps and signed
composition offsets. Audio and script tags remain opaque retained source bytes.

The reader requires complete tag framing and matching previous-tag sizes, one
stable AVC configuration, strictly increasing observed decoding coordinates and
agreement between each sender keyframe flag and IDR NAL presence. A change of
configuration, filtered/vendor tag, truncated tail, timestamp wrap or unsupported
video form refuses the whole index. Independent source, tag, metadata, sample and
NAL limits and cooperative cancellation bound traversal. No partial index escapes
on refusal.

A sample's `duration_ms` is only the positive difference to the next observed
decoding coordinate; the final sample remains `None`. Neither those deltas nor an
end-of-sequence tag establish exposure duration, capture continuity, UTC or scene
coverage. Indexing performs no decoding, capture, ledger write or authority grant.
Retained ingestion and native pixel decoding are separate consumers.

Seven focused contracts cover exact source tiling and NAL custody, signed
composition offsets and unknown final duration, every truncated prefix,
configuration/framing/timestamp contradictions, independent limit exhaustion and
cancellation, unsupported forms, and deterministic mutations.

## Qualification

`scripts/qualify.sh --lane media` runs `scripts/lanes/media.sh`, which drives the built `fss-probe` binary directly against both family and `--parameters` fixtures (exit statuses `0`, `10`, `11`, `12`, `14`), executes `fss-container --lib probe::`, `fss-container --test fss_053_media_probe_contract`, and `fss-cli --bin fss-probe`, and runs the `FSS-115` fragmented MP4/CMAF suites. The dedicated E2E contract entrypoint is `scripts/e2e/fss_053_media_probe.sh`.
