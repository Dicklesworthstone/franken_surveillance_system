#![forbid(unsafe_code)]
//! Source-preserving indexed AVC MP4 demultiplexing (FSS-115).
//!
//! The admitted profile is self-contained, nonfragmented ISO BMFF with one selected `avc1`
//! video sample description. Decode/composition ticks, edit lists and the track matrix are
//! preserved, not interpreted as capture time or silently applied to an elementary stream.
//! Other tracks are explicitly outside the selection. No decoder, filesystem or effect runs.

use std::ops::Range;
mod reader;
use reader::{Reader, full, one, optional};
mod tables;
use tables::*;

/// Hard source byte ceiling, independent of media-decode limits.
pub const MAX_MP4_INPUT_BYTES: usize = 512 * 1024 * 1024;
/// Hard count of samples in the selected track.
pub const MAX_MP4_SAMPLES: usize = 65_536;
/// Hard output ceiling; expansion is checked before allocating Annex-B bytes.
pub const MAX_ANNEX_B_BYTES: usize = 256 * 1024 * 1024;

/// Owner-narrowable aggregate parser and extraction bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DemuxLimits {
    /// Entire source file bytes.
    pub maximum_input_bytes: usize,
    /// Sum of top-level non-mdat boxes, including their headers.
    pub maximum_metadata_bytes: usize,
    /// Box headers visited across the complete parse.
    pub maximum_boxes: usize,
    /// Tracks listed, selected or not.
    pub maximum_tracks: usize,
    /// Selected video samples.
    pub maximum_samples: usize,
    /// Sum of declared entries across all selected sample/configuration/edit tables.
    pub maximum_table_entries: usize,
    /// Configuration and selected-track NAL units, across the complete parse.
    pub maximum_nals: usize,
    /// Complete extracted elementary stream, including synthesized start codes.
    pub maximum_output_bytes: usize,
}
impl Default for DemuxLimits {
    fn default() -> Self {
        Self {
            maximum_input_bytes: 128 * 1024 * 1024,
            maximum_metadata_bytes: 8 * 1024 * 1024,
            maximum_boxes: 4096,
            maximum_tracks: 16,
            maximum_samples: MAX_MP4_SAMPLES,
            maximum_table_entries: 1_048_576,
            maximum_nals: 262_144,
            maximum_output_bytes: 128 * 1024 * 1024,
        }
    }
}
impl DemuxLimits {
    /// Invalid limits refuse rather than silently widen or clamp the request.
    pub fn validate(self) -> Result<(), DemuxError> {
        if !(8..=MAX_MP4_INPUT_BYTES).contains(&self.maximum_input_bytes)
            || !(8..=32 * 1024 * 1024).contains(&self.maximum_metadata_bytes)
            || !(1..=65_536).contains(&self.maximum_boxes)
            || !(1..=64).contains(&self.maximum_tracks)
            || !(1..=MAX_MP4_SAMPLES).contains(&self.maximum_samples)
            || !(1..=1_048_576).contains(&self.maximum_table_entries)
            || !(1..=262_144).contains(&self.maximum_nals)
            || !(1..=MAX_ANNEX_B_BYTES).contains(&self.maximum_output_bytes)
        {
            return Err(DemuxError::Limit);
        }
        Ok(())
    }
}

/// Non-disclosing refusal. Errors never return a partial index or partial extraction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DemuxError {
    /// A bounded byte field extends beyond its containing box.
    Truncated,
    /// Invalid box, offset, overlap, count, data reference or sample-table relationship.
    Layout,
    /// A required box is missing.
    MissingBox([u8; 4]),
    /// A singleton box was supplied more than once.
    DuplicateBox([u8; 4]),
    /// Unsupported version, codec, encryption, fragmentation or external media reference.
    Unsupported,
    /// A selected track is absent, or more than one video track requires explicit selection.
    TrackSelection,
    /// Invalid time scale, time-table count, duration or arithmetic.
    Timeline,
    /// Invalid configuration or length-prefixed NAL framing, or changed avc1 parameter sets.
    Nal,
    /// Extraction must begin at a declared sync sample containing an IDR NAL.
    RandomAccessRequired,
    /// A caller ceiling, allocation or checked arithmetic bound was exceeded.
    Limit,
    /// Explicit owner checkpoint requested cancellation.
    Cancelled,
}
impl std::fmt::Display for DemuxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "indexed AVC MP4 demux refusal: {self:?}")
    }
}
impl std::error::Error for DemuxError {}

/// One original media sample in decode order. All offsets address the original MP4 file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AvcSample {
    /// Zero-based selected-track sample number, not a physical capture sequence.
    pub index: usize,
    /// Original length-prefixed sample bytes.
    pub source: Range<usize>,
    /// Decode time in the selected media's time scale.
    pub decode_time: u64,
    /// Positive sample duration in media ticks.
    pub duration: u32,
    /// Signed composition offset; version-0 offsets remain unsigned values widened to i64.
    pub composition_offset: i64,
    /// Container sync-table assertion, not proof of a decodable picture.
    pub sync_sample: bool,
    /// A type-5 NAL was present in the validated length-prefixed sample.
    pub contains_idr: bool,
}
impl AvcSample {
    /// Exact media presentation ticks before edit-list mapping, possibly negative.
    pub fn presentation_time(&self) -> i128 {
        i128::from(self.decode_time) + i128::from(self.composition_offset)
    }
}

/// A unit-rate edit; preserved as metadata, never silently applied to extracted NAL bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mp4Edit {
    /// Duration in the movie time scale, not the selected media time scale.
    pub movie_duration: u64,
    /// Media start ticks; -1 denotes an empty edit.
    pub media_time: i64,
}

/// Tracks present in the source. Nonselected tracks are not decoded or exported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mp4Track {
    /// tkhd identifier.
    pub id: u32,
    /// hdlr media handler, for example `vide` or `soun`.
    pub handler: [u8; 4],
}

/// An immutable, fully checked selection borrowing its exact original source.
#[derive(Debug)]
pub struct AvcMp4<'a> {
    source: &'a [u8],
    track: u32,
    tracks: Vec<Mp4Track>,
    movie_timescale: u32,
    timescale: u32,
    dimensions: [u16; 2],
    matrix: [i32; 9],
    edits: Vec<Mp4Edit>,
    length_bytes: usize,
    parameter_sets: Vec<Range<usize>>,
    samples: Vec<AvcSample>,
    limits: DemuxLimits,
    boxes_visited: usize,
    table_entries: usize,
    nals_inspected: usize,
}

impl<'a> AvcMp4<'a> {
    /// Parse an exact source buffer. More than one video track requires an explicit track ID.
    pub fn parse(
        source: &'a [u8],
        track: Option<u32>,
        limits: DemuxLimits,
    ) -> Result<Self, DemuxError> {
        Self::parse_with_checkpoint(source, track, limits, &mut || Ok(()))
    }
    /// Same parser with cooperative checkpoints at box, table and NAL boundaries.
    pub fn parse_with_checkpoint(
        source: &'a [u8],
        track: Option<u32>,
        limits: DemuxLimits,
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<Self, DemuxError> {
        limits.validate()?;
        if source.len() > limits.maximum_input_bytes {
            return Err(DemuxError::Limit);
        }
        let mut r = Reader::new(source, limits, check);
        let top = r.children(0..source.len(), true)?;
        let ftyp = one(&top, b"ftyp")?;
        let brands = r.body(&ftyp);
        if brands.len() < 8 || (brands.len() - 8) % 4 != 0 {
            return Err(DemuxError::Layout);
        }
        // These ordinary ISO BMFF brands do not add an unsupported container interpretation.
        let supported = |b: &[u8]| matches!(b, b"isom" | b"iso2" | b"mp41" | b"mp42" | b"avc1");
        if !supported(&brands[..4]) && !brands[8..].chunks_exact(4).any(supported) {
            return Err(DemuxError::Unsupported);
        }
        if top
            .iter()
            .any(|b| matches!(&b.kind, b"moof" | b"sidx" | b"mfra"))
        {
            return Err(DemuxError::Unsupported);
        }
        let media: Vec<_> = top
            .iter()
            .filter(|b| b.kind == *b"mdat")
            .map(|b| b.body.clone())
            .collect();
        if media.is_empty() {
            return Err(DemuxError::MissingBox(*b"mdat"));
        }
        let media_bytes = media.iter().try_fold(0_usize, |n, b| {
            n.checked_add(b.len()).ok_or(DemuxError::Limit)
        })?;
        if source.len() - media_bytes > limits.maximum_metadata_bytes {
            return Err(DemuxError::Limit);
        }
        let moov = one(&top, b"moov")?;
        let movie = r.children(moov.body, false)?;
        if movie.iter().any(|b| matches!(&b.kind, b"mvex" | b"cmov")) {
            return Err(DemuxError::Unsupported);
        }
        let mvhd = one(&movie, b"mvhd")?;
        let movie_timescale = time_header(r.body(&mvhd))?.0;
        let mut tracks = Vec::new();
        let mut selected = None;
        let mut videos = 0;
        for trak in movie.iter().filter(|b| b.kind == *b"trak") {
            if tracks.len() == limits.maximum_tracks {
                return Err(DemuxError::Limit);
            }
            let children = r.children(trak.body.clone(), false)?;
            let tkhd = one(&children, b"tkhd")?;
            let (id, matrix) = track_header(r.body(&tkhd))?;
            if tracks.iter().any(|t: &Mp4Track| t.id == id) {
                return Err(DemuxError::Layout);
            }
            let mdia = one(&children, b"mdia")?;
            let contents = r.children(mdia.body, false)?;
            let handler = one(&contents, b"hdlr")?;
            let h = r.body(&handler);
            full(h, 0, 0)?;
            if h.len() < 24 {
                return Err(DemuxError::Truncated);
            }
            let handler: [u8; 4] = h[8..12].try_into().map_err(|_| DemuxError::Layout)?;
            tracks.push(Mp4Track { id, handler });
            if handler == *b"vide" {
                videos += 1;
                if track.is_none() || track == Some(id) {
                    selected = Some((id, matrix, children, contents));
                }
            }
        }
        if track.is_none() && videos != 1 {
            return Err(DemuxError::TrackSelection);
        }
        let (track, matrix, track_boxes, media_boxes) =
            selected.ok_or(DemuxError::TrackSelection)?;
        let edits = parse_edits(&mut r, &track_boxes)?;
        let mdhd = one(&media_boxes, b"mdhd")?;
        let mdhd_body = r.body(&mdhd);
        let mdhd_len = match mdhd_body.first() {
            Some(0) => 24,
            Some(1) => 36,
            _ => return Err(DemuxError::Unsupported),
        };
        if mdhd_body.len() != mdhd_len {
            return Err(DemuxError::Layout);
        }
        let (timescale, declared_duration) = time_header(mdhd_body)?;
        let minf = one(&media_boxes, b"minf")?;
        let info = r.children(minf.body, false)?;
        validate_data_reference(&mut r, &info)?;
        let stbl = one(&info, b"stbl")?;
        let tables = r.children(stbl.body, false)?;
        // Auxiliary encryption and alternate size/layout tables cannot be ignored.
        if tables.iter().any(|b| {
            matches!(
                &b.kind,
                b"stz2" | b"senc" | b"saiz" | b"saio" | b"sgpd" | b"sbgp"
            )
        }) {
            return Err(DemuxError::Unsupported);
        }
        let stsd = one(&tables, b"stsd")?;
        let (dimensions, length_bytes, parameter_sets) = configuration(&mut r, &stsd)?;
        let sizes = sizes(&mut r, &one(&tables, b"stsz")?)?;
        if sizes.is_empty() {
            return Err(DemuxError::Layout);
        }
        let offsets = offsets(&mut r, &tables)?;
        let locations = locations(&mut r, &one(&tables, b"stsc")?, &sizes, &offsets, &media)?;
        let timing = timing(&mut r, &one(&tables, b"stts")?, sizes.len())?;
        let total_duration = timing
            .last()
            .and_then(|(d, n)| d.checked_add(u64::from(*n)))
            .ok_or(DemuxError::Timeline)?;
        if declared_duration != u64::MAX && declared_duration != total_duration {
            return Err(DemuxError::Timeline);
        }
        let composition = composition(&mut r, optional(&tables, b"ctts")?, sizes.len())?;
        let sync = sync_samples(&mut r, optional(&tables, b"stss")?, sizes.len())?;
        let mut samples = Vec::with_capacity(sizes.len());
        for (index, range) in locations.into_iter().enumerate() {
            let mut idr = false;
            let mut vcl = false;
            nals(source, range.clone(), length_bytes, &mut |nal| {
                r.checkpoint()?;
                r.nals = r
                    .nals
                    .checked_add(1)
                    .filter(|n| *n <= limits.maximum_nals)
                    .ok_or(DemuxError::Limit)?;
                let kind = nal_kind(&source[nal.clone()])?;
                if matches!(kind, 7 | 8 | 13)
                    && !parameter_sets
                        .iter()
                        .any(|p| source[p.clone()] == source[nal.clone()])
                {
                    return Err(DemuxError::Nal);
                }
                idr |= kind == 5;
                vcl |= kind == 1 || kind == 5;
                Ok(())
            })?;
            if !vcl {
                return Err(DemuxError::Nal);
            }
            samples.push(AvcSample {
                index,
                source: range,
                decode_time: timing[index].0,
                duration: timing[index].1,
                composition_offset: composition[index],
                sync_sample: sync[index],
                contains_idr: idr,
            });
        }
        r.checkpoint()?;
        Ok(Self {
            source,
            track,
            tracks,
            movie_timescale,
            timescale,
            dimensions,
            matrix,
            edits,
            length_bytes,
            parameter_sets,
            samples,
            limits,
            boxes_visited: r.boxes,
            table_entries: r.entries,
            nals_inspected: r.nals,
        })
    }
    /// Exact borrowed original container bytes, not normalized media.
    pub fn source(&self) -> &'a [u8] {
        self.source
    }
    /// Selected video track identity.
    pub const fn track_id(&self) -> u32 {
        self.track
    }
    /// All source track identities and handler kinds, including unselected tracks.
    pub fn tracks(&self) -> &[Mp4Track] {
        &self.tracks
    }
    /// Movie ticks per second, used by the preserved edit durations.
    pub const fn movie_timescale(&self) -> u32 {
        self.movie_timescale
    }
    /// Media ticks per second; not a UTC or sensor clock.
    pub const fn timescale(&self) -> u32 {
        self.timescale
    }
    /// Sample-entry dimensions, not decoder-verified dimensions.
    pub const fn dimensions(&self) -> [u16; 2] {
        self.dimensions
    }
    /// Raw signed fixed-point tkhd matrix values, not applied by Annex-B extraction.
    pub const fn track_matrix(&self) -> &[i32; 9] {
        &self.matrix
    }
    /// Unit-rate edit-list metadata, not applied by Annex-B extraction.
    pub fn edits(&self) -> &[Mp4Edit] {
        &self.edits
    }
    /// Complete selected-track sample index in decode order.
    pub fn samples(&self) -> &[AvcSample] {
        &self.samples
    }
    /// Exact parser counters: box visits, declared table entries, inspected NALs.
    pub const fn work(&self) -> [usize; 3] {
        [self.boxes_visited, self.table_entries, self.nals_inspected]
    }
    /// Extract a sync/IDR-led sample range. NAL payloads are byte-exact copies, never transcoded.
    pub fn annex_b(&self, first: usize, count: usize) -> Result<AnnexBExtraction, DemuxError> {
        self.annex_b_with_checkpoint(first, count, &mut || Ok(()))
    }
    /// Extraction with cancellation checkpoints; no output escapes a refused operation.
    pub fn annex_b_with_checkpoint(
        &self,
        first: usize,
        count: usize,
        check: &mut dyn FnMut() -> Result<(), DemuxError>,
    ) -> Result<AnnexBExtraction, DemuxError> {
        check()?;
        let end = first
            .checked_add(count)
            .filter(|end| *end <= self.samples.len())
            .ok_or(DemuxError::Layout)?;
        if count == 0 {
            return Err(DemuxError::Layout);
        }
        let initial = &self.samples[first];
        if !initial.sync_sample || !initial.contains_idr {
            return Err(DemuxError::RandomAccessRequired);
        }
        let mut selected: Vec<(Option<usize>, Range<usize>)> = self
            .parameter_sets
            .iter()
            .cloned()
            .map(|p| (None, p))
            .collect();
        for sample in &self.samples[first..end] {
            nals(
                self.source,
                sample.source.clone(),
                self.length_bytes,
                &mut |nal| {
                    check()?;
                    if selected.len() == self.limits.maximum_nals {
                        return Err(DemuxError::Limit);
                    }
                    selected.push((Some(sample.index), nal));
                    Ok(())
                },
            )?;
        }
        let size = selected.iter().try_fold(0_usize, |total, (_, range)| {
            total
                .checked_add(4)
                .and_then(|n| n.checked_add(range.len()))
                .filter(|n| *n <= self.limits.maximum_output_bytes)
                .ok_or(DemuxError::Limit)
        })?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| DemuxError::Limit)?;
        let mut mappings = Vec::with_capacity(selected.len());
        for (sample, source) in selected {
            check()?;
            let prefix = bytes.len();
            bytes.extend_from_slice(&[0, 0, 0, 1]);
            bytes.extend_from_slice(&self.source[source.clone()]);
            mappings.push(NalCopy {
                sample,
                source,
                output_start: prefix + 4,
            });
        }
        check()?;
        Ok(AnnexBExtraction {
            bytes,
            mappings,
            first_sample: first,
            sample_count: count,
        })
    }
}

/// One copy proof. The four bytes preceding output_start are generated Annex-B start codes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NalCopy {
    /// None for out-of-band parameter sets copied from avcC; otherwise original sample index.
    pub sample: Option<usize>,
    /// Exact original MP4 NAL-payload range, excluding its length field.
    pub source: Range<usize>,
    /// Start of the identical payload in the extracted stream, after its four-byte start code.
    pub output_start: usize,
}
/// Complete extraction and byte-exact source map. No timestamps are embedded in Annex-B bytes.
#[derive(Debug)]
pub struct AnnexBExtraction {
    bytes: Vec<u8>,
    mappings: Vec<NalCopy>,
    first_sample: usize,
    sample_count: usize,
}
impl AnnexBExtraction {
    /// Complete elementary stream.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Complete configuration/sample NAL map in output order.
    pub fn mappings(&self) -> &[NalCopy] {
        &self.mappings
    }
    /// Original sample range as first/count, in decode order.
    pub const fn selection(&self) -> [usize; 2] {
        [self.first_sample, self.sample_count]
    }
}

#[cfg(test)]
mod tests;
