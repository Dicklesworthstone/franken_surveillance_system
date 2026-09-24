#![forbid(unsafe_code)]
//! Source-preserving, IDR-led HEVC fragmented MP4. No decoder or ambient I/O.

mod init;

use crate::{Mp4Error, Mp4Limits, boxes::Writer};
use fss_packet::hevc::{HevcBoundary, HevcConfiguration, HevcPictureGroup};
use fss_packet::{H265SourceSpan, StreamKey};
use std::ops::Range;

/// One observed picture and owner-supplied track timing, independent of RTP/arrival time.
#[derive(Clone, Copy, Debug)]
pub struct TimedHevcPicture<'a> {
    /// Borrowed group; neither success nor refusal consumes it.
    pub picture: &'a HevcPictureGroup,
    /// Decode time in the configured positive time scale.
    pub decode_time: u64,
    /// Positive sample duration in track ticks.
    pub duration: u32,
    /// Signed presentation-minus-decode offset; no POC or timing is guessed.
    pub composition_offset: i32,
}

/// Deterministic ftyp + moov, track 1, hev1 and four-byte NAL lengths.
/// Array completeness is deliberately zero: this is not a complete-config certificate.
#[derive(Eq, PartialEq)]
pub struct HevcInitialization {
    pub(super) bytes: Vec<u8>,
    pub(super) parameter_ranges: [Range<usize>; 3],
}
impl HevcInitialization {
    /// Complete immutable initialization bytes; publication is an outer-owner operation.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Exact VPS, SPS, PPS locations in hvcC, excluding their length prefixes.
    /// The owner supplied these originals; no fabricated RTP provenance is attached.
    pub fn parameter_ranges(&self) -> &[Range<usize>; 3] {
        &self.parameter_ranges
    }
}
impl std::fmt::Debug for HevcInitialization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HevcInitialization")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Exact per-NAL copy mapping. All in-band NALs remain in media, including VPS/SPS/PPS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HevcNalMapping {
    /// Input sample ordinal in this fragment.
    pub sample: usize,
    /// NAL ordinal in the input group.
    pub nal: usize,
    /// Exact output NAL bytes, after the synthesized four-byte size prefix.
    pub range: Range<usize>,
    /// Original RTP copy spans and FU header synthesis inputs, unchanged.
    pub sources: Vec<H265SourceSpan>,
}
/// Explicit timing and boundary evidence, not strengthened to decoder-verified truth.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HevcSampleMapping {
    /// Complete length-prefixed sample in this fragment's mdat.
    pub range: Range<usize>,
    /// Owner-supplied decode time.
    pub decode_time: u64,
    /// Checked presentation time after the signed composition offset.
    pub presentation_time: u64,
    /// Positive duration in track ticks.
    pub duration: u32,
    /// Unconverted original RTP timestamp.
    pub rtp_timestamp: u32,
    /// Observed IDR NAL type 19/20, not a decoded random-access certificate.
    pub idr: bool,
    /// Exact observed grouping boundary.
    pub boundary: HevcBoundary,
    /// NAL mappings for this sample.
    pub mappings: Range<usize>,
}

/// One immutable moof + mdat derivative with source and timeline accounting.
#[derive(Eq, PartialEq)]
pub struct HevcFragment {
    key: StreamKey,
    sequence: u32,
    bytes: Vec<u8>,
    samples: Vec<HevcSampleMapping>,
    mappings: Vec<HevcNalMapping>,
    timeline_gap: Option<Range<u64>>,
}
impl HevcFragment {
    /// Exact ingress/generation/SSRC binding, not an authorization capability.
    pub fn key(&self) -> StreamKey {
        self.key
    }
    /// Nonzero monotonically advancing movie-fragment sequence.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }
    /// Encoded bytes without transcoding or removing any in-band NAL.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Explicit timing and retained boundary classes.
    pub fn samples(&self) -> &[HevcSampleMapping] {
        &self.samples
    }
    /// Original-to-container NAL copy spans.
    pub fn mappings(&self) -> &[HevcNalMapping] {
        &self.mappings
    }
    /// Explicit decode-timeline interval skipped after the preceding fragment.
    /// This is not a wall-clock/camera-outage or coverage assertion.
    pub fn timeline_gap(&self) -> Option<Range<u64>> {
        self.timeline_gap.clone()
    }
}
impl std::fmt::Debug for HevcFragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HevcFragment")
            .field("key", &self.key)
            .field("sequence", &self.sequence)
            .field("bytes", &self.bytes.len())
            .field("samples", &self.samples.len())
            .field("timeline_gap", &self.timeline_gap)
            .finish_non_exhaustive()
    }
}

/// IDR-led single-track hev1 remux over the existing source-linked HEVC picture API.
///
/// The first sample of every fragment must be an observed IDR (19/20). This
/// narrow subset rejects CRA/BLA and leading RADL/RASL pictures rather than
/// mislabeling open-GOP fragments as independently accessible. Decode times are
/// contiguous within a fragment; gaps between fragments are explicit receipts.
///
/// A prefix-screened configuration is not full syntax or decoder validation.
/// The original suffixes remain opaque, and output may be undecodable if the
/// source bodies are invalid. No completeness, custody, or publication claim
/// is made. All failures leave sequence/timeline/source cursors unchanged.
pub struct HevcMuxer {
    key: StreamKey,
    configuration: HevcConfiguration,
    limits: Mp4Limits,
    initialization: HevcInitialization,
    next_sequence: Option<u32>,
    last_end: Option<u64>,
    last_source: Option<(u64, usize)>,
}
impl std::fmt::Debug for HevcMuxer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HevcMuxer")
            .field("key", &self.key)
            .field("next_sequence", &self.next_sequence)
            .field("last_end", &self.last_end)
            .finish_non_exhaustive()
    }
}
impl HevcMuxer {
    /// Pin one exact configuration, stream epoch, positive track scale and hard budgets.
    /// This subset requires the source's progressive/frame-only declaration.
    pub fn new(
        key: StreamKey,
        configuration: HevcConfiguration,
        time_scale: u32,
        limits: Mp4Limits,
    ) -> Result<Self, Mp4Error> {
        limits.validate()?;
        if key.ingress == 0 || key.generation == 0 || time_scale == 0 {
            return Err(Mp4Error::Configuration);
        }
        // Constraint bits: progressive_source=1, interlaced_source=0, frame_only=1.
        // These are retained source declarations, not a decoded-frame guarantee.
        if configuration.profile_tier_level()[5] & 0xd0 != 0x90 {
            return Err(Mp4Error::UnsupportedFormat);
        }
        let initialization =
            init::build(&configuration, time_scale, limits.max_initialization_bytes)?;
        Ok(Self {
            key,
            configuration,
            limits,
            initialization,
            next_sequence: Some(1),
            last_end: None,
            last_source: None,
        })
    }
    /// Exact configuration used for every emitted fragment.
    pub fn configuration(&self) -> &HevcConfiguration {
        &self.configuration
    }
    /// Reusable initialization segment for this exact stream/configuration generation.
    pub fn initialization(&self) -> &HevcInitialization {
        &self.initialization
    }
    /// Next sequence, absent only after u32::MAX has been emitted.
    pub fn next_sequence(&self) -> Option<u32> {
        self.next_sequence
    }

    /// Borrow source-linked pictures and produce one bounded, deterministic fragment.
    /// Validation/allocation precede cursor mutation; retry never consumes input twice.
    pub fn fragment(&mut self, samples: &[TimedHevcPicture<'_>]) -> Result<HevcFragment, Mp4Error> {
        let sequence = self.next_sequence.ok_or(Mp4Error::SequenceExhausted)?;
        let plan = self.preflight(samples)?;
        let mut w = Writer::new(self.limits.max_fragment_bytes, plan.bytes)?;
        let mut mappings = Vec::new();
        mappings
            .try_reserve_exact(plan.nals)
            .map_err(|_| Mp4Error::Allocation)?;
        let mut receipts = Vec::new();
        receipts
            .try_reserve_exact(samples.len())
            .map_err(|_| Mp4Error::Allocation)?;
        let moof = w.start(b"moof")?;
        let mfhd = w.full(b"mfhd", 0)?;
        w.u32(sequence)?;
        w.end(mfhd)?;
        let traf = w.start(b"traf")?;
        let tfhd = w.full(b"tfhd", 0x00020000)?;
        w.u32(1)?;
        w.end(tfhd)?;
        let tfdt = w.full(b"tfdt", 0x01000000)?;
        w.u64(samples[0].decode_time)?;
        w.end(tfdt)?;
        let trun = w.full(b"trun", 0x01000f01)?;
        w.u32(samples.len() as u32)?;
        w.u32(plan.media_offset as u32)?;
        for sample in samples {
            w.u32(sample.duration)?;
            w.u32(media_size(sample.picture)? as u32)?;
            w.u32(if idr(sample.picture) {
                0x02000000
            } else {
                0x01010000
            })?;
            w.put(&sample.composition_offset.to_be_bytes())?;
        }
        w.end(trun)?;
        w.end(traf)?;
        w.end(moof)?;
        let mdat = w.start(b"mdat")?;
        if w.data.len() != plan.media_offset {
            return Err(Mp4Error::Layout);
        }
        for (sample_index, sample) in samples.iter().enumerate() {
            let start = w.data.len();
            let map_start = mappings.len();
            for (nal_index, nal) in sample.picture.nals().iter().enumerate() {
                w.u32(nal.bytes().len() as u32)?;
                let begin = w.data.len();
                w.put(nal.bytes())?;
                let mut sources = Vec::new();
                sources
                    .try_reserve_exact(nal.sources().len())
                    .map_err(|_| Mp4Error::Allocation)?;
                sources.extend(nal.sources().iter().cloned());
                mappings.push(HevcNalMapping {
                    sample: sample_index,
                    nal: nal_index,
                    range: begin..w.data.len(),
                    sources,
                });
            }
            receipts.push(HevcSampleMapping {
                range: start..w.data.len(),
                decode_time: sample.decode_time,
                presentation_time: pts(sample)?,
                duration: sample.duration,
                rtp_timestamp: sample.picture.timestamp(),
                idr: idr(sample.picture),
                boundary: sample.picture.boundary(),
                mappings: map_start..mappings.len(),
            });
        }
        w.end(mdat)?;
        if w.data.len() != plan.bytes {
            return Err(Mp4Error::Layout);
        }
        let timeline_gap = self
            .last_end
            .filter(|end| *end < samples[0].decode_time)
            .map(|end| end..samples[0].decode_time);
        let result = HevcFragment {
            key: self.key,
            sequence,
            bytes: w.data,
            samples: receipts,
            mappings,
            timeline_gap,
        };
        self.next_sequence = sequence.checked_add(1);
        self.last_end = Some(plan.end);
        self.last_source = plan.last_source;
        Ok(result)
    }

    fn preflight(&self, samples: &[TimedHevcPicture<'_>]) -> Result<Plan, Mp4Error> {
        if samples.is_empty() || samples.len() > self.limits.max_samples {
            return Err(Mp4Error::Limit);
        }
        if !idr(samples[0].picture) {
            return Err(Mp4Error::RandomAccessRequired);
        }
        if self
            .last_end
            .is_some_and(|end| samples[0].decode_time < end)
        {
            return Err(Mp4Error::Timeline);
        }
        // Fixed moof headers plus one 16-byte trun entry per sample and the mdat header.
        let media_offset = 96 + 16 * samples.len();
        let mut plan = Plan {
            media_offset,
            bytes: media_offset,
            nals: 0,
            end: samples[0].decode_time,
            last_source: self.last_source,
        };
        let mut span_count = 0_usize;
        for sample in samples {
            let p = sample.picture;
            if p.key() != self.key {
                return Err(Mp4Error::StreamMismatch);
            }
            if p.boundary() == HevcBoundary::EndOfInputUnverified
                || !p.prefix().first_slice
                || p.slice_count() == 0
            {
                return Err(Mp4Error::UnverifiedPicture);
            }
            if p.discontinuity_before() {
                return Err(Mp4Error::Discontinuity);
            }
            if p.prefix().pps_id != self.configuration.pps_id() {
                return Err(Mp4Error::ParameterSet);
            }
            if !matches!(p.prefix().nal_type, 0..=5 | 19 | 20) {
                return Err(Mp4Error::UnsupportedFormat);
            }
            if sample.duration == 0 || sample.decode_time != plan.end {
                return Err(Mp4Error::Timeline);
            }
            plan.end = sample
                .decode_time
                .checked_add(u64::from(sample.duration))
                .ok_or(Mp4Error::Timeline)?;
            pts(sample)?;
            plan.nals = plan
                .nals
                .checked_add(p.nals().len())
                .ok_or(Mp4Error::Limit)?;
            if plan.nals > self.limits.max_nals {
                return Err(Mp4Error::Limit);
            }
            plan.bytes = plan
                .bytes
                .checked_add(media_size(p)?)
                .ok_or(Mp4Error::Limit)?;
            if plan.bytes > self.limits.max_fragment_bytes {
                return Err(Mp4Error::Limit);
            }
            for nal in p.nals() {
                if nal.key() != self.key {
                    return Err(Mp4Error::StreamMismatch);
                }
                if nal.layer_id() != 0
                    || nal.temporal_id_plus_one() > self.configuration.temporal_layers()
                {
                    return Err(Mp4Error::UnsupportedFormat);
                }
                let expected = match nal.nal_type() {
                    32 => Some(self.configuration.vps()),
                    33 => Some(self.configuration.sps()),
                    34 => Some(self.configuration.pps()),
                    _ => None,
                };
                if expected.is_some_and(|bytes| bytes != nal.bytes()) {
                    return Err(Mp4Error::ParameterSet);
                }
                span_count = span_count
                    .checked_add(nal.sources().len())
                    .ok_or(Mp4Error::Limit)?;
                if span_count > self.limits.max_source_spans {
                    return Err(Mp4Error::Limit);
                }
                if nal.sources().is_empty() {
                    return Err(Mp4Error::SourceOrder);
                }
                for source in nal.sources() {
                    let start = source
                        .fragment_header_range
                        .as_ref()
                        .map_or(source.wire_range.start, |h| h.start);
                    if source.wire_range.start >= source.wire_range.end
                        || plan
                            .last_source
                            .is_some_and(|last| (source.sequence, start) < last)
                    {
                        return Err(Mp4Error::SourceOrder);
                    }
                    plan.last_source = Some((source.sequence, source.wire_range.end));
                }
            }
        }
        Ok(plan)
    }
}
struct Plan {
    media_offset: usize,
    bytes: usize,
    nals: usize,
    end: u64,
    last_source: Option<(u64, usize)>,
}
fn idr(p: &HevcPictureGroup) -> bool {
    matches!(p.prefix().nal_type, 19 | 20)
}
fn pts(sample: &TimedHevcPicture<'_>) -> Result<u64, Mp4Error> {
    sample
        .decode_time
        .checked_add_signed(i64::from(sample.composition_offset))
        .ok_or(Mp4Error::Timeline)
}
fn media_size(picture: &HevcPictureGroup) -> Result<usize, Mp4Error> {
    picture.nals().iter().try_fold(0_usize, |size, nal| {
        size.checked_add(4)
            .and_then(|s| s.checked_add(nal.bytes().len()))
            .ok_or(Mp4Error::Limit)
    })
}
