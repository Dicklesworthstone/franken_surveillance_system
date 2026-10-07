#![forbid(unsafe_code)]
//! Source-preserving Matroska/WebM demultiplexing of one AVC or HEVC video track.
//!
//! The admitted profile is an EBML header with DocType `matroska` or `webm`, then exactly one
//! Segment (known or unknown size) that ends the file, holding one Info and one Tracks element
//! before the first Cluster. The selected track is `V_MPEG4/ISO/AVC` or `V_MPEGH/ISO/HEVC`, and
//! its CodecPrivate is the `avcC`/`hvcC` record, parsed by the same code as MP4.
//!
//! Selected-track frames come from unlaced SimpleBlocks or BlockGroup Blocks. Each is one
//! length-prefixed sample, validated exactly like an MP4 sample. Refused: content encodings
//! (header stripping, compression, encryption), track operations, lacing, invisible frames,
//! codec-state changes and EncryptedBlock. Every CRC-32 element is verified.
//!
//! Block timestamps are presentation times on the Segment's TimestampScale, never a capture
//! clock. Other tracks' blocks and every non-frame byte are structure, never decoded. No decoder,
//! filesystem or effect runs.

use super::reader::{BoxRef, Reader};
use super::tables::{avc_configuration, hevc_configuration};
use super::{DemuxError, DemuxLimits, VideoCodec, validate_sample};
use std::ops::Range;

const EBML: u32 = 0x1A45_DFA3;
const SEGMENT: u32 = 0x1853_8067;
const SEEK_HEAD: u32 = 0x114D_9B74;
const INFO: u32 = 0x1549_A966;
const TRACKS: u32 = 0x1654_AE6B;
const CLUSTER: u32 = 0x1F43_B675;
const CUES: u32 = 0x1C53_BB6B;
const ATTACHMENTS: u32 = 0x1941_A469;
const CHAPTERS: u32 = 0x1043_A770;
const TAGS: u32 = 0x1254_C367;
const VOID: u32 = 0xEC;
const CRC32: u32 = 0xBF;

const DOC_TYPE: u32 = 0x4282;
const TIMESTAMP_SCALE: u32 = 0x2A_D7B1;
const TRACK_ENTRY: u32 = 0xAE;
const TRACK_NUMBER: u32 = 0xD7;
const TRACK_TYPE: u32 = 0x83;
const CODEC_ID: u32 = 0x86;
const CODEC_PRIVATE: u32 = 0x63A2;
const VIDEO: u32 = 0xE0;
const CONTENT_ENCODINGS: u32 = 0x6D80;
const TRACK_OPERATION: u32 = 0xE2;
const PIXEL_WIDTH: u32 = 0xB0;
const PIXEL_HEIGHT: u32 = 0xBA;
const CLUSTER_TIMESTAMP: u32 = 0xE7;
const SIMPLE_BLOCK: u32 = 0xA3;
const BLOCK_GROUP: u32 = 0xA0;
const BLOCK: u32 = 0xA1;
const REFERENCE_BLOCK: u32 = 0xFB;

/// TimestampScale when Info omits it: one millisecond per tick.
const DEFAULT_TIMESTAMP_SCALE: u64 = 1_000_000;

/// One selected-track frame in decode (file) order. Offsets address the original file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatroskaSample {
    /// Zero-based selected-track frame number, not a physical capture sequence.
    pub index: usize,
    /// Exact length-prefixed frame bytes: the block payload after its header.
    pub source: Range<usize>,
    /// Cluster timestamp plus the block's signed offset, in TimestampScale ticks: a
    /// presentation time, not a capture clock.
    pub timestamp: i64,
    /// Container keyframe assertion (SimpleBlock keyframe flag, or a BlockGroup without a
    /// ReferenceBlock), not proof of a decodable picture.
    pub keyframe: bool,
    /// A random-access picture NAL was present in the validated frame: an H.264 IDR slice or an
    /// H.265 IRAP slice segment.
    pub contains_idr: bool,
}

/// One top-level region with its exact byte extent: the EBML header, the Segment header (ID and
/// size), or one Segment child. In file order they tile the source exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MatroskaElement {
    /// EBML element ID, length marker included.
    pub id: u32,
    /// Stable lower-case name, for example `ebml_header`, `tracks` or `cluster`.
    pub name: &'static str,
    /// Exact byte range, header included.
    pub range: Range<usize>,
}

/// A track listed in Tracks. Nonselected tracks are not decoded or exported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MatroskaTrack {
    /// Block track number.
    pub number: u64,
    /// TrackType: 1 video, 2 audio, 17 subtitle, and so on.
    pub track_type: u64,
}

/// An immutable, fully checked selection borrowing its exact original source.
#[derive(Debug)]
pub struct MatroskaVideo<'a> {
    source: &'a [u8],
    doc_type: &'static str,
    codec: VideoCodec,
    track: u64,
    tracks: Vec<MatroskaTrack>,
    timestamp_scale: u64,
    dimensions: [u16; 2],
    length_bytes: usize,
    parameter_sets: Vec<Range<usize>>,
    samples: Vec<MatroskaSample>,
    elements: Vec<MatroskaElement>,
    tail: Option<usize>,
    elements_visited: usize,
    blocks_visited: usize,
    nals_inspected: usize,
}

impl<'a> MatroskaVideo<'a> {
    /// Parse an exact source buffer. More than one video track requires an explicit track number.
    pub fn parse(
        source: &'a [u8],
        track: Option<u64>,
        limits: DemuxLimits,
    ) -> Result<Self, DemuxError> {
        Self::parse_with_checkpoint(source, track, limits, &mut || Ok(()))
    }

    /// Same parser with cooperative checkpoints at element, block, NAL and CRC boundaries.
    pub fn parse_with_checkpoint(
        source: &'a [u8],
        track: Option<u64>,
        limits: DemuxLimits,
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<Self, DemuxError> {
        Self::parse_inner(source, track, limits, check, false)
    }

    /// Like [`Self::parse_with_checkpoint`], but a file its writer never finished (power loss, a
    /// crashed recorder) is admitted up to its last complete top-level element or, within a
    /// final Cluster without a CRC-32, its last complete block. A Cluster whose CRC-32 can no
    /// longer be verified is dropped whole; the header, Info and Tracks must be complete.
    /// [`Self::truncated_tail`] reports where the unread tail starts. Only running out of bytes
    /// is recovered: any malformed or refused element still refuses the whole file.
    pub fn parse_recovering_tail(
        source: &'a [u8],
        track: Option<u64>,
        limits: DemuxLimits,
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<Self, DemuxError> {
        Self::parse_inner(source, track, limits, check, true)
    }

    fn parse_inner(
        source: &'a [u8],
        track: Option<u64>,
        limits: DemuxLimits,
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
        recover: bool,
    ) -> Result<Self, DemuxError> {
        limits.validate()?;
        if source.len() > limits.maximum_input_bytes {
            return Err(DemuxError::Limit);
        }
        let mut r = Reader::new(source, limits, check);
        visit(&mut r)?;
        let (id, data, size) = header(source, 0, source.len())?;
        if id != EBML {
            return Err(DemuxError::Unsupported);
        }
        let header_end = end_of(data, size.ok_or(DemuxError::Layout)?, source.len())?;
        let doc_type = ebml_header(&mut r, data..header_end)?;
        visit(&mut r)?;
        let (id, segment_data, size) = header(source, header_end, source.len())?;
        if id != SEGMENT {
            return Err(DemuxError::MissingBox(SEGMENT.to_be_bytes()));
        }
        // One Segment ends the file: trailing bytes or a second Segment are refused. A declared
        // end beyond the file is a truncation.
        let mut tail = None;
        if let Some(size) = size {
            let end = segment_data.checked_add(size).ok_or(DemuxError::Limit)?;
            if end < source.len() {
                return Err(DemuxError::Layout);
            }
            if end > source.len() {
                if !recover {
                    return Err(DemuxError::Truncated);
                }
                tail = Some(source.len());
            }
        }
        let (level_one, cut) = segment_children(&mut r, segment_data..source.len(), recover)?;
        // A cut Cluster keeps its complete children only when no CRC-32 binds them.
        let mut partial = None;
        if let Some(cut) = cut {
            tail = Some(cut.at);
            if let Some(cluster) = cut.cluster {
                let (kids, stop) = complete_children(&mut r, cluster.data.clone())?;
                if kids.iter().skip(1).any(|k| k.id == CRC32) {
                    return Err(DemuxError::Layout);
                }
                if kids.first().is_some_and(|k| k.id != CRC32) {
                    tail = Some(stop);
                    partial = Some((cluster.start..stop, kids));
                }
            }
        }
        let mut elements = vec![
            MatroskaElement {
                id: EBML,
                name: "ebml_header",
                range: 0..header_end,
            },
            MatroskaElement {
                id: SEGMENT,
                name: "segment_header",
                range: header_end..segment_data,
            },
        ];
        for element in &level_one {
            elements.push(MatroskaElement {
                id: element.id,
                name: level_one_name(element.id).ok_or(DemuxError::Unsupported)?,
                range: element.start..element.data.end,
            });
        }
        if let Some((range, _)) = &partial {
            elements.push(MatroskaElement {
                id: CLUSTER,
                name: "cluster",
                range: range.clone(),
            });
        }
        let media = level_one
            .iter()
            .filter(|e| e.id == CLUSTER)
            .map(|e| e.data.end - e.start)
            .chain(partial.as_ref().map(|(range, _)| range.len()))
            .try_fold(0_usize, |n, len| {
                n.checked_add(len).ok_or(DemuxError::Limit)
            })?;
        if tail.unwrap_or(source.len()) - media > limits.maximum_metadata_bytes {
            return Err(DemuxError::Limit);
        }
        let first_cluster = level_one
            .iter()
            .position(|e| e.id == CLUSTER)
            .or(partial.as_ref().map(|_| level_one.len()))
            .ok_or(DemuxError::MissingBox(CLUSTER.to_be_bytes()))?;
        let (info_at, info) = single(&level_one, INFO)?;
        let (tracks_at, tracks_element) = single(&level_one, TRACKS)?;
        if info_at > first_cluster || tracks_at > first_cluster {
            return Err(DemuxError::Unsupported);
        }
        let timestamp_scale = info_timestamp_scale(&mut r, info)?;
        let selection = select_track(&mut r, tracks_element, track)?;
        let config = BoxRef {
            kind: match selection.codec {
                VideoCodec::Avc => *b"avcC",
                VideoCodec::Hevc => *b"hvcC",
            },
            start: selection.private.start,
            body: selection.private.data.clone(),
        };
        let (length_bytes, parameter_sets) = match selection.codec {
            VideoCodec::Avc => avc_configuration(&mut r, &config)?,
            VideoCodec::Hevc => hevc_configuration(&mut r, &config)?,
        };
        let frames = Frames {
            track: selection.number,
            codec: selection.codec,
            length_bytes,
            parameter_sets: &parameter_sets,
        };
        let mut samples = Vec::new();
        for cluster in level_one.iter().filter(|e| e.id == CLUSTER) {
            let kids = children(&mut r, cluster.data.clone(), true)?;
            cluster_frames(&mut r, kids, true, &frames, &mut samples)?;
        }
        if let Some((_, kids)) = partial {
            cluster_frames(&mut r, kids, false, &frames, &mut samples)?;
        }
        if samples.is_empty() {
            return Err(DemuxError::Layout);
        }
        r.checkpoint()?;
        Ok(Self {
            source,
            doc_type,
            codec: selection.codec,
            track: selection.number,
            tracks: selection.tracks,
            timestamp_scale,
            dimensions: selection.dimensions,
            length_bytes,
            parameter_sets,
            samples,
            elements,
            tail,
            elements_visited: r.boxes,
            blocks_visited: r.entries,
            nals_inspected: r.nals,
        })
    }
    /// Exact borrowed original container bytes, not normalized media.
    pub fn source(&self) -> &'a [u8] {
        self.source
    }
    /// EBML DocType: `matroska` or `webm`.
    pub const fn doc_type(&self) -> &'static str {
        self.doc_type
    }
    /// Video coding of the selected track.
    pub const fn codec(&self) -> VideoCodec {
        self.codec
    }
    /// Selected track number.
    pub const fn track_number(&self) -> u64 {
        self.track
    }
    /// Every listed track, selected or not.
    pub fn tracks(&self) -> &[MatroskaTrack] {
        &self.tracks
    }
    /// Nanoseconds per block-timestamp tick; not a UTC or sensor clock.
    pub const fn timestamp_scale_ns(&self) -> u64 {
        self.timestamp_scale
    }
    /// Track PixelWidth and PixelHeight, not decoder-verified dimensions.
    pub const fn dimensions(&self) -> [u16; 2] {
        self.dimensions
    }
    /// Complete selected-track frame index in decode (file) order.
    pub fn samples(&self) -> &[MatroskaSample] {
        &self.samples
    }
    /// Bytes of each frame NAL length field (1, 2 or 4), from the CodecPrivate record.
    pub const fn nal_length_bytes(&self) -> usize {
        self.length_bytes
    }
    /// Exact original byte ranges of CodecPrivate's parameter-set NAL units, in record order,
    /// which is also ascending file order. Excludes their length fields.
    pub fn parameter_sets(&self) -> &[Range<usize>] {
        &self.parameter_sets
    }
    /// Top-level regions tiling the source up to [`Self::truncated_tail`] (or its end), in file
    /// order. A recovered final Cluster's region ends after its last kept child.
    pub fn elements(&self) -> &[MatroskaElement] {
        &self.elements
    }
    /// Start of the unread tail of a file its writer never finished: always `None` from the
    /// strict parsers. Equal to the file length when only the declared Segment size shows the
    /// truncation.
    pub const fn truncated_tail(&self) -> Option<usize> {
        self.tail
    }
    /// Exact parser counters: metadata elements visited, cluster and block-group children
    /// visited, inspected NALs.
    pub const fn work(&self) -> [usize; 3] {
        [
            self.elements_visited,
            self.blocks_visited,
            self.nals_inspected,
        ]
    }
}

/// A parsed element: its ID, the first byte of its header, and its data.
#[derive(Clone, Debug)]
struct Element {
    id: u32,
    start: usize,
    data: Range<usize>,
}

/// Counts one metadata element against `maximum_boxes`.
fn visit(r: &mut Reader<'_, '_>) -> Result<(), DemuxError> {
    r.checkpoint()?;
    r.boxes = r
        .boxes
        .checked_add(1)
        .filter(|n| *n <= r.limits.maximum_boxes)
        .ok_or(DemuxError::Limit)?;
    Ok(())
}

/// An EBML variable-length integer at `at`, read no further than `bytes`: its width and its value
/// (the length marker kept for element IDs, removed for sizes and track numbers).
fn vint(
    bytes: &[u8],
    at: usize,
    max_width: usize,
    keep_marker: bool,
) -> Result<(usize, u64), DemuxError> {
    let first = *bytes.get(at).ok_or(DemuxError::Truncated)?;
    let width = first.leading_zeros() as usize + 1;
    if first == 0 || width > max_width {
        return Err(DemuxError::Layout);
    }
    let end = at.checked_add(width).ok_or(DemuxError::Limit)?;
    let raw = bytes.get(at..end).ok_or(DemuxError::Truncated)?;
    let value = raw.iter().fold(0_u64, |v, &b| (v << 8) | u64::from(b));
    if keep_marker {
        Ok((width, value))
    } else {
        Ok((width, value & ((1_u64 << (7 * width)) - 1)))
    }
}

/// The element header at `at`, bounded by `limit`: ID, data start, and size (`None` when the
/// size is the reserved all-ones "unknown" value).
fn header(
    bytes: &[u8],
    at: usize,
    limit: usize,
) -> Result<(u32, usize, Option<usize>), DemuxError> {
    let window = bytes.get(..limit).ok_or(DemuxError::Layout)?;
    let (id_width, id) = vint(window, at, 4, true)?;
    let (size_width, size) = vint(window, at + id_width, 8, false)?;
    let data = at + id_width + size_width;
    if size == (1_u64 << (7 * size_width)) - 1 {
        return Ok((id as u32, data, None));
    }
    let size = usize::try_from(size).map_err(|_| DemuxError::Limit)?;
    Ok((id as u32, data, Some(size)))
}

fn end_of(data: usize, size: usize, limit: usize) -> Result<usize, DemuxError> {
    data.checked_add(size)
        .filter(|end| *end <= limit)
        .ok_or(DemuxError::Truncated)
}

/// Known-size children of a master element's data. A CRC-32 child is admitted only first, and
/// is verified over the rest of the data. `blocks` counts the children as cluster entries
/// rather than metadata elements.
fn children(
    r: &mut Reader<'_, '_>,
    data: Range<usize>,
    blocks: bool,
) -> Result<Vec<Element>, DemuxError> {
    let mut result = Vec::new();
    let mut at = data.start;
    while at < data.end {
        if blocks {
            r.entries(1)?;
        } else {
            visit(r)?;
        }
        let (id, start, size) = header(r.bytes, at, data.end)?;
        // Only a Segment or Cluster may have an unknown size.
        let end = end_of(start, size.ok_or(DemuxError::Unsupported)?, data.end)?;
        result.push(Element {
            id,
            start: at,
            data: start..end,
        });
        at = end;
    }
    verify_crc(r, &result, data.end)?;
    Ok(result)
}

/// Where a recovered file stops: the first incomplete top-level element's start and, when it is
/// a Cluster with a complete header, that Cluster with its data running to the end of the file.
struct Cut {
    at: usize,
    cluster: Option<Element>,
}

/// Segment children in file order. An unknown-size Cluster ends at the next top-level element
/// or the end of the Segment; any other unknown size is refused. With `recover`, running out of
/// bytes ends the list at the incomplete element instead of refusing.
fn segment_children(
    r: &mut Reader<'_, '_>,
    data: Range<usize>,
    recover: bool,
) -> Result<(Vec<Element>, Option<Cut>), DemuxError> {
    let mut result = Vec::new();
    let mut cut = None;
    let mut at = data.start;
    while at < data.end {
        visit(r)?;
        let (id, start, size) = match header(r.bytes, at, data.end) {
            Ok(parsed) => parsed,
            Err(DemuxError::Truncated) if recover => {
                cut = Some(Cut { at, cluster: None });
                break;
            }
            Err(error) => return Err(error),
        };
        if level_one_name(id).is_none() {
            return Err(DemuxError::Unsupported);
        }
        let end = match size {
            Some(size) => end_of(start, size, data.end),
            None if id == CLUSTER => unknown_cluster_end(r, start, data.end),
            None => return Err(DemuxError::Unsupported),
        };
        let end = match end {
            Ok(end) => end,
            Err(DemuxError::Truncated) if recover => {
                cut = Some(Cut {
                    at,
                    cluster: (id == CLUSTER).then_some(Element {
                        id,
                        start: at,
                        data: start..data.end,
                    }),
                });
                break;
            }
            Err(error) => return Err(error),
        };
        result.push(Element {
            id,
            start: at,
            data: start..end,
        });
        at = end;
    }
    verify_crc(r, &result, data.end)?;
    // An unopened element's leading CRC-32 still binds its bytes.
    for element in result.iter().filter(|e| !matches!(e.id, VOID | CRC32)) {
        if element.data.is_empty() {
            continue;
        }
        let (id, start, size) = header(r.bytes, element.data.start, element.data.end)?;
        if id == CRC32 {
            let end = end_of(start, size.ok_or(DemuxError::Layout)?, element.data.end)?;
            let crc = Element {
                id,
                start: element.data.start,
                data: start..end,
            };
            verify_crc(r, std::slice::from_ref(&crc), element.data.end)?;
        }
    }
    Ok((result, cut))
}

/// The complete children of a cut Cluster's data, and where the first incomplete one starts.
/// CRC-32 placement is the caller's to judge.
fn complete_children(
    r: &mut Reader<'_, '_>,
    data: Range<usize>,
) -> Result<(Vec<Element>, usize), DemuxError> {
    let mut result = Vec::new();
    let mut at = data.start;
    while at < data.end {
        r.entries(1)?;
        let parsed = header(r.bytes, at, data.end).and_then(|(id, start, size)| {
            let end = end_of(start, size.ok_or(DemuxError::Unsupported)?, data.end)?;
            Ok(Element {
                id,
                start: at,
                data: start..end,
            })
        });
        match parsed {
            Ok(element) => {
                at = element.data.end;
                result.push(element);
            }
            Err(DemuxError::Truncated) => break,
            Err(error) => return Err(error),
        }
    }
    Ok((result, at))
}

fn unknown_cluster_end(
    r: &mut Reader<'_, '_>,
    mut at: usize,
    limit: usize,
) -> Result<usize, DemuxError> {
    while at < limit {
        r.checkpoint()?;
        let (id, start, size) = header(r.bytes, at, limit)?;
        if level_one_name(id).is_some_and(|_| !matches!(id, VOID | CRC32))
            || matches!(id, EBML | SEGMENT)
        {
            break;
        }
        at = end_of(start, size.ok_or(DemuxError::Unsupported)?, limit)?;
    }
    Ok(at)
}

const fn level_one_name(id: u32) -> Option<&'static str> {
    Some(match id {
        SEEK_HEAD => "seek_head",
        INFO => "info",
        TRACKS => "tracks",
        CLUSTER => "cluster",
        CUES => "cues",
        ATTACHMENTS => "attachments",
        CHAPTERS => "chapters",
        TAGS => "tags",
        VOID => "void",
        CRC32 => "crc32",
        _ => return None,
    })
}

/// The only element with `id`, and its position.
fn single(elements: &[Element], id: u32) -> Result<(usize, &Element), DemuxError> {
    let mut found = elements.iter().enumerate().filter(|(_, e)| e.id == id);
    let first = found
        .next()
        .ok_or(DemuxError::MissingBox(id.to_be_bytes()))?;
    if found.next().is_some() {
        return Err(DemuxError::DuplicateBox(id.to_be_bytes()));
    }
    Ok(first)
}

fn set_once<T>(slot: &mut Option<T>, id: u32, value: T) -> Result<(), DemuxError> {
    if slot.is_some() {
        return Err(DemuxError::DuplicateBox(id.to_be_bytes()));
    }
    *slot = Some(value);
    Ok(())
}

/// An unsigned integer element; empty data denotes `default`.
fn uint(b: &[u8], default: u64) -> Result<u64, DemuxError> {
    if b.is_empty() {
        return Ok(default);
    }
    if b.len() > 8 {
        return Err(DemuxError::Layout);
    }
    Ok(b.iter().fold(0_u64, |v, &x| (v << 8) | u64::from(x)))
}

/// A string element without its trailing NUL padding.
fn text(b: &[u8]) -> &[u8] {
    let end = b.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
    &b[..end]
}

/// EBML header: reader version 1, IDs of at most 4 bytes, sizes of at most 8, and a Matroska or
/// WebM DocType readable by a version-4 reader.
fn ebml_header(r: &mut Reader<'_, '_>, data: Range<usize>) -> Result<&'static str, DemuxError> {
    let mut doc_type = None;
    for child in children(r, data, false)? {
        let b = &r.bytes[child.data.clone()];
        let admitted = match child.id {
            // EBMLReadVersion
            0x42F7 => uint(b, 1)? == 1,
            // EBMLMaxIDLength, EBMLMaxSizeLength
            0x42F2 => (1..=4).contains(&uint(b, 4)?),
            0x42F3 => (1..=8).contains(&uint(b, 8)?),
            // DocTypeReadVersion
            0x4285 => (1..=4).contains(&uint(b, 1)?),
            DOC_TYPE => {
                let name = match text(b) {
                    b"matroska" => "matroska",
                    b"webm" => "webm",
                    _ => return Err(DemuxError::Unsupported),
                };
                set_once(&mut doc_type, DOC_TYPE, name)?;
                true
            }
            // EBMLVersion, DocTypeVersion, DocTypeExtension
            0x4286 | 0x4287 | 0x4281 | VOID | CRC32 => true,
            _ => false,
        };
        if !admitted {
            return Err(DemuxError::Unsupported);
        }
    }
    doc_type.ok_or(DemuxError::MissingBox(DOC_TYPE.to_be_bytes()))
}

fn info_timestamp_scale(r: &mut Reader<'_, '_>, info: &Element) -> Result<u64, DemuxError> {
    let mut scale = None;
    for child in children(r, info.data.clone(), false)? {
        if child.id == TIMESTAMP_SCALE {
            let value = uint(&r.bytes[child.data.clone()], DEFAULT_TIMESTAMP_SCALE)?;
            set_once(&mut scale, TIMESTAMP_SCALE, value)?;
        }
    }
    match scale.unwrap_or(DEFAULT_TIMESTAMP_SCALE) {
        0 => Err(DemuxError::Timeline),
        scale => Ok(scale),
    }
}

struct Selection {
    number: u64,
    codec: VideoCodec,
    private: Element,
    dimensions: [u16; 2],
    tracks: Vec<MatroskaTrack>,
}

/// Lists every TrackEntry and selects one video track: the only one, or `track`.
fn select_track(
    r: &mut Reader<'_, '_>,
    tracks: &Element,
    track: Option<u64>,
) -> Result<Selection, DemuxError> {
    let mut listed = Vec::new();
    let mut selected = None;
    let mut videos = 0;
    for entry in children(r, tracks.data.clone(), false)? {
        match entry.id {
            TRACK_ENTRY => {}
            VOID | CRC32 => continue,
            _ => return Err(DemuxError::Unsupported),
        }
        if listed.len() == r.limits.maximum_tracks {
            return Err(DemuxError::Limit);
        }
        let (mut number, mut kind, mut codec, mut private, mut video) =
            (None, None, None, None, None);
        let mut transformed = false;
        for child in children(r, entry.data.clone(), false)? {
            let b = &r.bytes[child.data.clone()];
            match child.id {
                TRACK_NUMBER => set_once(&mut number, child.id, uint(b, 0)?)?,
                TRACK_TYPE => set_once(&mut kind, child.id, uint(b, 0)?)?,
                CODEC_ID => set_once(&mut codec, child.id, text(b))?,
                CODEC_PRIVATE => set_once(&mut private, child.id, child.clone())?,
                VIDEO => set_once(&mut video, child.id, child.clone())?,
                CONTENT_ENCODINGS | TRACK_OPERATION => transformed = true,
                _ => {}
            }
        }
        let number = number.ok_or(DemuxError::MissingBox(TRACK_NUMBER.to_be_bytes()))?;
        let kind = kind.ok_or(DemuxError::MissingBox(TRACK_TYPE.to_be_bytes()))?;
        if number == 0 || listed.iter().any(|t: &MatroskaTrack| t.number == number) {
            return Err(DemuxError::Layout);
        }
        listed.push(MatroskaTrack {
            number,
            track_type: kind,
        });
        if kind != 1 {
            continue;
        }
        videos += 1;
        if track.is_some_and(|wanted| wanted != number) {
            continue;
        }
        // Content encodings rewrite frame bytes; a track operation combines tracks.
        if transformed {
            return Err(DemuxError::Unsupported);
        }
        let codec = match codec.ok_or(DemuxError::MissingBox(CODEC_ID.to_be_bytes()))? {
            b"V_MPEG4/ISO/AVC" => VideoCodec::Avc,
            b"V_MPEGH/ISO/HEVC" => VideoCodec::Hevc,
            _ => return Err(DemuxError::Unsupported),
        };
        let private = private.ok_or(DemuxError::MissingBox(CODEC_PRIVATE.to_be_bytes()))?;
        let video = video.ok_or(DemuxError::MissingBox(VIDEO.to_be_bytes()))?;
        let (mut width, mut height) = (None, None);
        for child in children(r, video.data.clone(), false)? {
            let b = &r.bytes[child.data.clone()];
            match child.id {
                PIXEL_WIDTH => set_once(&mut width, child.id, uint(b, 0)?)?,
                PIXEL_HEIGHT => set_once(&mut height, child.id, uint(b, 0)?)?,
                _ => {}
            }
        }
        let dimension = |value: Option<u64>, id: u32| {
            let value = value.ok_or(DemuxError::MissingBox(id.to_be_bytes()))?;
            u16::try_from(value)
                .ok()
                .filter(|v| *v != 0)
                .ok_or(DemuxError::Layout)
        };
        selected = Some((
            number,
            codec,
            private,
            [
                dimension(width, PIXEL_WIDTH)?,
                dimension(height, PIXEL_HEIGHT)?,
            ],
        ));
    }
    if track.is_none() && videos != 1 {
        return Err(DemuxError::TrackSelection);
    }
    let (number, codec, private, dimensions) = selected.ok_or(DemuxError::TrackSelection)?;
    Ok(Selection {
        number,
        codec,
        private,
        dimensions,
        tracks: listed,
    })
}

/// What a selected-track frame is validated against.
struct Frames<'p> {
    track: u64,
    codec: VideoCodec,
    length_bytes: usize,
    parameter_sets: &'p [Range<usize>],
}

/// Block header: track number, signed timestamp offset, flags, and the frame bytes after it.
fn block_header(
    bytes: &[u8],
    data: &Range<usize>,
) -> Result<(u64, i16, u8, Range<usize>), DemuxError> {
    let window = bytes.get(..data.end).ok_or(DemuxError::Layout)?;
    let (width, track) = vint(window, data.start, 8, false)?;
    let at = data.start + width;
    let fields = window.get(at..at + 3).ok_or(DemuxError::Truncated)?;
    let offset = i16::from_be_bytes([fields[0], fields[1]]);
    Ok((track, offset, fields[2], at + 3..data.end))
}

/// Selected-track frames of one Cluster's children. A complete Cluster must carry its
/// Timestamp; a recovered, cut one may end before it, but never has a block without it.
fn cluster_frames(
    r: &mut Reader<'_, '_>,
    kids: Vec<Element>,
    complete: bool,
    frames: &Frames<'_>,
    samples: &mut Vec<MatroskaSample>,
) -> Result<(), DemuxError> {
    let mut base = None;
    for child in kids {
        let (block, keyframe) = match child.id {
            CLUSTER_TIMESTAMP => {
                let value = uint(&r.bytes[child.data.clone()], 0)?;
                let value = i64::try_from(value).map_err(|_| DemuxError::Timeline)?;
                set_once(&mut base, child.id, value)?;
                continue;
            }
            SIMPLE_BLOCK => {
                let flags = block_header(r.bytes, &child.data)?.2;
                (child.data, flags & 0x80 != 0)
            }
            BLOCK_GROUP => {
                let mut block = None;
                let mut referenced = false;
                for part in children(r, child.data.clone(), true)? {
                    match part.id {
                        BLOCK => set_once(&mut block, part.id, part.data)?,
                        REFERENCE_BLOCK => referenced = true,
                        // CodecState replaces the decoder configuration mid-stream.
                        0xA4 => return Err(DemuxError::Unsupported),
                        // BlockDuration, ReferencePriority, DiscardPadding, BlockAdditions.
                        0x9B | 0xFA | 0x75A2 | 0x75A1 | VOID | CRC32 => {}
                        _ => return Err(DemuxError::Unsupported),
                    }
                }
                (
                    block.ok_or(DemuxError::MissingBox(BLOCK.to_be_bytes()))?,
                    !referenced,
                )
            }
            // Position, PrevSize, SilentTracks.
            0xA7 | 0xAB | 0x5854 | VOID | CRC32 => continue,
            // EncryptedBlock and anything unknown.
            _ => return Err(DemuxError::Unsupported),
        };
        let (track, offset, flags, frame) = block_header(r.bytes, &block)?;
        if track != frames.track {
            continue;
        }
        // Lacing packs several frames into one block; an invisible frame is never shown.
        if flags & 0x0e != 0 {
            return Err(DemuxError::Unsupported);
        }
        let base = base.ok_or(DemuxError::MissingBox(CLUSTER_TIMESTAMP.to_be_bytes()))?;
        let timestamp = base
            .checked_add(i64::from(offset))
            .ok_or(DemuxError::Timeline)?;
        if samples.len() == r.limits.maximum_samples {
            return Err(DemuxError::Limit);
        }
        let contains_idr = validate_sample(
            r,
            r.bytes,
            frames.codec,
            frames.length_bytes,
            frames.parameter_sets,
            frame.clone(),
        )?;
        samples.push(MatroskaSample {
            index: samples.len(),
            source: frame,
            timestamp,
            keyframe,
            contains_idr,
        });
    }
    if complete && base.is_none() {
        return Err(DemuxError::MissingBox(CLUSTER_TIMESTAMP.to_be_bytes()));
    }
    Ok(())
}

const CRC_TABLE: [u32; 256] = {
    let mut table = [0_u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
};

/// Continues an inverted IEEE 802.3 CRC-32 register over `bytes`.
fn crc32_update(mut crc: u32, bytes: &[u8]) -> u32 {
    for &b in bytes {
        crc = CRC_TABLE[((crc ^ u32::from(b)) & 0xff) as usize] ^ (crc >> 8);
    }
    crc
}

/// IEEE 802.3 CRC-32 (reflected, initial and final inversion), as EBML CRC-32 elements use,
/// with a checkpoint per MiB.
fn crc32(r: &mut Reader<'_, '_>, bytes: &[u8]) -> Result<u32, DemuxError> {
    let mut crc = !0_u32;
    for chunk in bytes.chunks(1 << 20) {
        r.checkpoint()?;
        crc = crc32_update(crc, chunk);
    }
    Ok(!crc)
}

/// A CRC-32 element is admitted only as its parent's first child; its little-endian value must
/// equal the CRC-32 of every following byte of the parent's data.
fn verify_crc(
    r: &mut Reader<'_, '_>,
    siblings: &[Element],
    parent_end: usize,
) -> Result<(), DemuxError> {
    for (position, element) in siblings.iter().enumerate() {
        if element.id != CRC32 {
            continue;
        }
        if position != 0 || element.data.len() != 4 {
            return Err(DemuxError::Layout);
        }
        let bytes = r.bytes;
        let stored = &bytes[element.data.clone()];
        let stored = u32::from_le_bytes([stored[0], stored[1], stored[2], stored[3]]);
        if crc32(r, &bytes[element.data.end..parent_end])? != stored {
            return Err(DemuxError::Layout);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
