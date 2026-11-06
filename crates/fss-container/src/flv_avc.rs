#![forbid(unsafe_code)]
//! AVC-in-FLV to fragmented MP4 with explicit, connection-relative source maps.
//!
//! This narrow reference accepts exactly one SPS/PPS pair and requires a later
//! distinct primary picture as a boundary witness for every emitted sample.
//! FLV successor selection remains heuristic even when not provisional. The
//! caller must supply all intervening source records, bind one connection and
//! stream generation, retain source custody, and establish publication and
//! decoding separately. Input records are borrowed and never consumed.

use std::{fmt, ops::Range};

use fss_packet::{
    avc::{
        AvcPps, AvcSliceIdentity, AvcSps, AvcSyntaxLimits, parse_pps, parse_slice_identity,
        parse_sps,
    },
    extended_flv::{
        self, Parse, Tag, avc,
        stream::{RecordKind, SourceRecord},
    },
};

use crate::{InitializationSegment, Mp4Error, Mp4Limits, boxes::Writer, init};

/// Caller-owned stream identity; neither field authenticates a camera.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceKey {
    /// Nonzero identity of one TCP connection.
    pub connection: u64,
    /// Nonzero immutable stream generation within the caller's deployment.
    pub generation: u64,
}

/// One original AVC sample with explicit extended FLV media-clock timing.
#[derive(Clone, Copy, Debug)]
pub struct TimedSample<'a> {
    /// Original record returned by the FLV source framer.
    pub record: &'a SourceRecord,
    /// Unwrapped camera timestamp in milliseconds; low 32 bits must match the tag.
    pub decode_time_ms: u64,
    /// Positive media duration, ending at the next supplied picture timestamp.
    pub duration_ms: u32,
}

/// Exact byte mapping for one copied source NAL, excluding synthesized lengths.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NalMapping {
    /// Emitted sample ordinal.
    pub sample: usize,
    /// Half-open byte range within the original connection.
    pub source: Range<u64>,
    /// Half-open byte range within the generated fragment.
    pub target: Range<usize>,
}

/// One sample's timing and ranges; no decoded-picture completeness is asserted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleMapping {
    /// Length-prefixed sample range in the generated fragment.
    pub target: Range<usize>,
    /// Decode timestamp in milliseconds.
    pub decode_time_ms: u64,
    /// Signed FLV presentation offset in milliseconds.
    pub composition_offset_ms: i32,
    /// Positive duration in milliseconds.
    pub duration_ms: u32,
    /// Syntactic IDR observation, not a decoder proof.
    pub idr: bool,
    /// Corresponding range in the fragment's NAL mappings.
    pub nals: Range<usize>,
}

/// In-memory derivative; original media and archive custody remain external.
#[derive(Eq, PartialEq)]
pub struct Fragment {
    key: SourceKey,
    configuration_sources: [Range<u64>; 2],
    sequence: u32,
    bytes: Vec<u8>,
    samples: Vec<SampleMapping>,
    nals: Vec<NalMapping>,
    timeline_gap: Option<Range<u64>>,
}
impl Fragment {
    /// Explicit caller-supplied connection and generation identity.
    pub fn key(&self) -> SourceKey {
        self.key
    }
    /// Source ranges of the SPS and PPS for this fragment's video epoch.
    pub fn configuration_sources(&self) -> [Range<u64>; 2] {
        self.configuration_sources.clone()
    }
    /// Local monotonically increasing fragment sequence.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }
    /// Encoded moof and mdat bytes.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Timing and range observations for each emitted sample.
    pub fn samples(&self) -> &[SampleMapping] {
        &self.samples
    }
    /// Exact source-to-derivative NAL copy mappings.
    pub fn nals(&self) -> &[NalMapping] {
        &self.nals
    }
    /// Explicit media-clock interval skipped between fragment outputs.
    pub fn timeline_gap(&self) -> Option<Range<u64>> {
        self.timeline_gap.clone()
    }
}
impl fmt::Debug for Fragment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Fragment")
            .field("key", &self.key)
            .field("sequence", &self.sequence)
            .field("bytes", &self.bytes.len())
            .field("samples", &self.samples.len())
            .field("timeline_gap", &self.timeline_gap)
            .finish_non_exhaustive()
    }
}

/// One immutable FLV configuration epoch and its local fragment cursor.
pub struct Muxer {
    key: SourceKey,
    config: Vec<u8>,
    config_end: u64,
    config_sources: [Range<u64>; 2],
    sps: AvcSps,
    pps: AvcPps,
    initialization: InitializationSegment,
    limits: Mp4Limits,
    sequence: Option<u32>,
    last_end: Option<u64>,
    last_source_end: u64,
}
impl fmt::Debug for Muxer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Muxer")
            .field("key", &self.key)
            .field("sequence", &self.sequence)
            .field("last_end", &self.last_end)
            .finish_non_exhaustive()
    }
}

impl Muxer {
    /// Configure the one-track muxer from an exact original FLV configuration.
    /// Multiple parameter sets, unknown extension data and provisional records
    /// are refused rather than silently normalized.
    pub fn new(key: SourceKey, source: &SourceRecord, limits: Mp4Limits) -> Result<Self, Mp4Error> {
        limits.validate()?;
        if key.connection == 0 || key.generation == 0 {
            return Err(Mp4Error::Configuration);
        }
        let (tag, start, end) = source_tag(source)?;
        let video = avc::VideoTag::parse(tag).map_err(|_| Mp4Error::ParameterSet)?;
        let config = video
            .configuration(avc::Limits::default())
            .map_err(|_| Mp4Error::ParameterSet)?;
        if config.sps().len() != 1 || config.pps().len() != 1 || !config.extension().is_empty() {
            return Err(Mp4Error::UnsupportedFormat);
        }
        let sps_nal = config.sps().next().ok_or(Mp4Error::ParameterSet)?;
        let pps_nal = config.pps().next().ok_or(Mp4Error::ParameterSet)?;
        let syntax = AvcSyntaxLimits::default();
        let sps = parse_sps(sps_nal.bytes(), syntax).map_err(|_| Mp4Error::ParameterSet)?;
        let pps = parse_pps(pps_nal.bytes(), &sps, syntax).map_err(|_| Mp4Error::ParameterSet)?;
        if !sps.frame_mbs_only()
            || sps.nal_bytes().len() > u16::MAX as usize
            || pps.nal_bytes().len() > u16::MAX as usize
        {
            return Err(Mp4Error::UnsupportedFormat);
        }
        let config_sources = [
            absolute(start, sps_nal.range())?,
            absolute(start, pps_nal.range())?,
        ];
        let initialization = init::build(&sps, &pps, 1000, limits.max_initialization_bytes)?;
        let mut copy = Vec::new();
        copy.try_reserve_exact(tag.wire_bytes().len())
            .map_err(|_| Mp4Error::Allocation)?;
        copy.extend_from_slice(tag.wire_bytes());
        Ok(Self {
            key,
            config: copy,
            config_end: end,
            config_sources,
            sps,
            pps,
            initialization,
            limits,
            sequence: Some(1),
            last_end: None,
            last_source_end: end,
        })
    }

    /// Initialization bytes for this exact configuration epoch.
    pub fn initialization(&self) -> &InitializationSegment {
        &self.initialization
    }
    /// Derive an AVC plus AAC initialization for the same video configuration.
    /// The caller must independently bind the audio configuration and its
    /// clock to this source connection before publishing any A/V derivative.
    pub fn av_initialization(
        &self,
        audio: &fss_packet::extended_flv::aac::Configuration<'_>,
    ) -> Result<crate::flv_av::Initialization, Mp4Error> {
        let (video, audio_range) = init::build_av(
            &self.sps,
            &self.pps,
            1000,
            self.limits.max_initialization_bytes,
            audio,
        )?;
        Ok(crate::flv_av::Initialization::new(
            video,
            audio_range,
            self.key,
            self.config_sources.clone(),
        ))
    }
    /// Original SPS and PPS ranges in the current connection, respectively.
    pub fn configuration_sources(&self) -> &[Range<u64>; 2] {
        &self.config_sources
    }
    /// Next fragment sequence; absent after exhaustion.
    pub fn next_sequence(&self) -> Option<u32> {
        self.sequence
    }

    /// Advance over explicitly returned pre-roll records before the first
    /// fragment. Source ownership remains with the caller; this operation is
    /// not a custody or deletion receipt. It refuses IDR pictures, configuration
    /// changes, provisional boundaries, and any attempt after the first
    /// fragment. Refusal leaves the cursor unchanged.
    pub fn advance_pre_roll(&mut self, records: &[&SourceRecord]) -> Result<Range<u64>, Mp4Error> {
        if self.last_end.is_some() || self.sequence != Some(1) {
            return Err(Mp4Error::Discontinuity);
        }
        if records.is_empty() || records.len() > self.limits.max_source_spans {
            return Err(Mp4Error::Limit);
        }
        let begin = self.last_source_end;
        let mut end = begin;
        for record in records {
            if record.offset() != end {
                return Err(Mp4Error::SourceOrder);
            }
            let (tag, _, next) = source_tag(record)?;
            if tag.kind() == 9 {
                let video = avc::VideoTag::parse(tag).map_err(|_| Mp4Error::UnsupportedFormat)?;
                let Parse::Complete(config_tag) =
                    Tag::parse(&self.config, extended_flv::Limits::default())
                        .map_err(|_| Mp4Error::ParameterSet)?
                else {
                    return Err(Mp4Error::ParameterSet);
                };
                let config = avc::VideoTag::parse(config_tag)
                    .map_err(|_| Mp4Error::ParameterSet)?
                    .configuration(avc::Limits::default())
                    .map_err(|_| Mp4Error::ParameterSet)?;
                let nals = video
                    .nal_units(&config, avc::Limits::default())
                    .map_err(|_| Mp4Error::UnverifiedPicture)?;
                if nals.contains_idr_nal_type() {
                    return Err(Mp4Error::RandomAccessRequired);
                }
            }
            end = next;
        }
        self.last_source_end = end;
        Ok(begin..end)
    }

    /// Emit IDR-led samples only after a later distinct sample witnesses the tail.
    ///
    /// `lookahead` is parsed but not emitted or consumed. `coverage` must
    /// contain every original record from the preceding committed tag through
    /// that lookahead, including audio or metadata, in exact source order.
    /// Every video record must be one of `samples` or the final `lookahead`.
    /// This proves no framed video record was silently skipped, while the
    /// source framer's candidate boundaries remain heuristic. The caller must
    /// not cross a configuration or connection epoch.
    /// Refusal leaves sequence, timeline and source cursors unchanged.
    pub fn fragment(
        &mut self,
        samples: &[TimedSample<'_>],
        lookahead: &SourceRecord,
        coverage: &[&SourceRecord],
    ) -> Result<Fragment, Mp4Error> {
        let sequence = self.sequence.ok_or(Mp4Error::SequenceExhausted)?;
        if samples.is_empty() || samples.len() > self.limits.max_samples {
            return Err(Mp4Error::Limit);
        }
        if self
            .last_end
            .is_some_and(|end| samples[0].decode_time_ms < end)
        {
            return Err(Mp4Error::Timeline);
        }
        self.validate_coverage(samples, lookahead, coverage)?;
        let mut parsed = Vec::new();
        parsed
            .try_reserve_exact(samples.len())
            .map_err(|_| Mp4Error::Allocation)?;
        let mut source_end = self.last_source_end.max(self.config_end);
        let mut end_time = samples[0].decode_time_ms;
        let mut total_nals = 0_usize;
        let media_offset = samples
            .len()
            .checked_mul(16)
            .and_then(|n| n.checked_add(96))
            .ok_or(Mp4Error::Limit)?;
        let mut size = media_offset;
        for sample in samples {
            if sample.duration_ms == 0 || sample.decode_time_ms != end_time {
                return Err(Mp4Error::Timeline);
            }
            let value = self.parse_sample(sample.record)?;
            if value.source_start < source_end {
                return Err(Mp4Error::SourceOrder);
            }
            if value.timestamp != sample.decode_time_ms as u32 {
                return Err(Mp4Error::Timeline);
            }
            sample
                .decode_time_ms
                .checked_add_signed(i64::from(value.composition))
                .ok_or(Mp4Error::Timeline)?;
            end_time = sample
                .decode_time_ms
                .checked_add(u64::from(sample.duration_ms))
                .ok_or(Mp4Error::Timeline)?;
            source_end = value.source_end;
            total_nals = total_nals
                .checked_add(value.nals.len())
                .ok_or(Mp4Error::Limit)?;
            if total_nals > self.limits.max_nals || total_nals > self.limits.max_source_spans {
                return Err(Mp4Error::Limit);
            }
            size = size.checked_add(value.bytes).ok_or(Mp4Error::Limit)?;
            if size > self.limits.max_fragment_bytes {
                return Err(Mp4Error::Limit);
            }
            if let Some(previous) = parsed.last().map(|p: &ParsedSample<'_>| p.identity)
                && !value.identity.starts_new_picture(previous)
            {
                return Err(Mp4Error::UnverifiedPicture);
            }
            parsed.push(value);
        }
        if parsed[0].identity.idr_pic_id().is_none() {
            return Err(Mp4Error::RandomAccessRequired);
        }
        let next = self.parse_sample(lookahead)?;
        if next.source_start < source_end {
            return Err(Mp4Error::SourceOrder);
        }
        if next.timestamp != end_time as u32 {
            return Err(Mp4Error::Timeline);
        }
        if !next
            .identity
            .starts_new_picture(parsed.last().ok_or(Mp4Error::Layout)?.identity)
        {
            return Err(Mp4Error::UnverifiedPicture);
        }
        let mut writer = Writer::new(self.limits.max_fragment_bytes, size)?;
        let mut nal_mappings = Vec::new();
        nal_mappings
            .try_reserve_exact(total_nals)
            .map_err(|_| Mp4Error::Allocation)?;
        let mut sample_mappings = Vec::new();
        sample_mappings
            .try_reserve_exact(samples.len())
            .map_err(|_| Mp4Error::Allocation)?;
        let moof = writer.start(b"moof")?;
        let mfhd = writer.full(b"mfhd", 0)?;
        writer.u32(sequence)?;
        writer.end(mfhd)?;
        let traf = writer.start(b"traf")?;
        let tfhd = writer.full(b"tfhd", 0x00020000)?;
        writer.u32(1)?;
        writer.end(tfhd)?;
        let tfdt = writer.full(b"tfdt", 0x01000000)?;
        writer.u64(samples[0].decode_time_ms)?;
        writer.end(tfdt)?;
        let trun = writer.full(b"trun", 0x01000f01)?;
        writer.u32(u32::try_from(samples.len()).map_err(|_| Mp4Error::Limit)?)?;
        writer.u32(u32::try_from(media_offset).map_err(|_| Mp4Error::Limit)?)?;
        for (sample, p) in samples.iter().zip(&parsed) {
            writer.u32(sample.duration_ms)?;
            writer.u32(u32::try_from(p.bytes).map_err(|_| Mp4Error::Limit)?)?;
            writer.u32(if p.identity.idr_pic_id().is_some() {
                0x02000000
            } else {
                0x01010000
            })?;
            writer.put(&p.composition.to_be_bytes())?;
        }
        writer.end(trun)?;
        writer.end(traf)?;
        writer.end(moof)?;
        let mdat = writer.start(b"mdat")?;
        if writer.data.len() != media_offset {
            return Err(Mp4Error::Layout);
        }
        for (index, (sample, p)) in samples.iter().zip(&parsed).enumerate() {
            let target_start = writer.data.len();
            let nals_start = nal_mappings.len();
            for nal in &p.nals {
                writer.u32(u32::try_from(nal.bytes.len()).map_err(|_| Mp4Error::Limit)?)?;
                let start = writer.data.len();
                writer.put(nal.bytes)?;
                nal_mappings.push(NalMapping {
                    sample: index,
                    source: nal.source.clone(),
                    target: start..writer.data.len(),
                });
            }
            sample_mappings.push(SampleMapping {
                target: target_start..writer.data.len(),
                decode_time_ms: sample.decode_time_ms,
                composition_offset_ms: p.composition,
                duration_ms: sample.duration_ms,
                idr: p.identity.idr_pic_id().is_some(),
                nals: nals_start..nal_mappings.len(),
            });
        }
        writer.end(mdat)?;
        if writer.data.len() != size {
            return Err(Mp4Error::Layout);
        }
        let timeline_gap = self
            .last_end
            .filter(|end| *end < samples[0].decode_time_ms)
            .map(|end| end..samples[0].decode_time_ms);
        let output = Fragment {
            key: self.key,
            configuration_sources: self.config_sources.clone(),
            sequence,
            bytes: writer.data,
            samples: sample_mappings,
            nals: nal_mappings,
            timeline_gap,
        };
        self.sequence = sequence.checked_add(1);
        self.last_end = Some(end_time);
        self.last_source_end = source_end;
        Ok(output)
    }

    fn validate_coverage(
        &self,
        samples: &[TimedSample<'_>],
        lookahead: &SourceRecord,
        coverage: &[&SourceRecord],
    ) -> Result<(), Mp4Error> {
        let mut expected = self.last_source_end;
        let mut video_index = 0_usize;
        if coverage.is_empty() || coverage.len() > self.limits.max_source_spans {
            return Err(Mp4Error::Limit);
        }
        for (index, record) in coverage.iter().enumerate() {
            if record.offset() != expected {
                return Err(Mp4Error::SourceOrder);
            }
            let (tag, _, end) = source_tag(record)?;
            expected = end;
            if tag.kind() == 9 {
                if video_index < samples.len() && std::ptr::eq(*record, samples[video_index].record)
                {
                    video_index += 1;
                } else if video_index == samples.len()
                    && index + 1 == coverage.len()
                    && std::ptr::eq(*record, lookahead)
                {
                    video_index += 1;
                } else {
                    return Err(Mp4Error::UnverifiedPicture);
                }
            }
        }
        if video_index != samples.len() + 1
            || !coverage
                .last()
                .is_some_and(|last| std::ptr::eq(*last, lookahead))
        {
            return Err(Mp4Error::UnverifiedPicture);
        }
        Ok(())
    }

    fn parse_sample<'a>(&self, source: &'a SourceRecord) -> Result<ParsedSample<'a>, Mp4Error> {
        let (tag, start, end) = source_tag(source)?;
        let video = avc::VideoTag::parse(tag).map_err(|_| Mp4Error::UnsupportedFormat)?;
        let Parse::Complete(config_tag) = Tag::parse(&self.config, extended_flv::Limits::default())
            .map_err(|_| Mp4Error::ParameterSet)?
        else {
            return Err(Mp4Error::ParameterSet);
        };
        let config = avc::VideoTag::parse(config_tag)
            .map_err(|_| Mp4Error::ParameterSet)?
            .configuration(avc::Limits::default())
            .map_err(|_| Mp4Error::ParameterSet)?;
        let units = video
            .nal_units(&config, avc::Limits::default())
            .map_err(|_| Mp4Error::UnverifiedPicture)?;
        if units.len() > self.limits.max_nals || units.len() > self.limits.max_source_spans {
            return Err(Mp4Error::Limit);
        }
        let mut nals = Vec::new();
        nals.try_reserve_exact(units.len())
            .map_err(|_| Mp4Error::Allocation)?;
        let mut identity: Option<AvcSliceIdentity> = None;
        let mut bytes = 0_usize;
        for nal in units.iter() {
            match nal.bytes()[0] & 31 {
                1 | 5 => {
                    let current = parse_slice_identity(
                        nal.bytes(),
                        &self.sps,
                        &self.pps,
                        AvcSyntaxLimits::default(),
                    )
                    .map_err(|_| Mp4Error::UnverifiedPicture)?;
                    if current.redundant_pic_cnt() != 0 {
                        return Err(Mp4Error::UnsupportedFormat);
                    }
                    if let Some(previous) = identity {
                        if current.starts_new_picture(previous) || current.first_mb_in_slice() == 0
                        {
                            return Err(Mp4Error::UnverifiedPicture);
                        }
                    } else if current.first_mb_in_slice() != 0 {
                        return Err(Mp4Error::UnverifiedPicture);
                    }
                    identity = Some(current);
                }
                6 | 9 if identity.is_none() => {}
                12 => {}
                _ => return Err(Mp4Error::UnsupportedFormat),
            }
            bytes = bytes
                .checked_add(4)
                .and_then(|n| n.checked_add(nal.bytes().len()))
                .ok_or(Mp4Error::Limit)?;
            if bytes > self.limits.max_fragment_bytes {
                return Err(Mp4Error::Limit);
            }
            nals.push(NalRef {
                bytes: nal.bytes(),
                source: absolute(start, nal.range())?,
            });
        }
        Ok(ParsedSample {
            source_start: start,
            source_end: end,
            timestamp: video.timestamp_ms(),
            composition: video.composition_offset_ms(),
            identity: identity.ok_or(Mp4Error::UnverifiedPicture)?,
            nals,
            bytes,
        })
    }
}

struct NalRef<'a> {
    bytes: &'a [u8],
    source: Range<u64>,
}
struct ParsedSample<'a> {
    source_start: u64,
    source_end: u64,
    timestamp: u32,
    composition: i32,
    identity: AvcSliceIdentity,
    nals: Vec<NalRef<'a>>,
    bytes: usize,
}

fn source_tag(record: &SourceRecord) -> Result<(Tag<'_>, u64, u64), Mp4Error> {
    if matches!(
        record.kind(),
        RecordKind::Header
            | RecordKind::Candidate {
                provisional: true,
                ..
            }
    ) {
        return Err(Mp4Error::UnverifiedPicture);
    }
    let range = record.tag_range().ok_or(Mp4Error::Layout)?;
    let bytes = record.bytes().get(range.clone()).ok_or(Mp4Error::Layout)?;
    let Parse::Complete(tag) =
        Tag::parse(bytes, extended_flv::Limits::default()).map_err(|_| Mp4Error::Layout)?
    else {
        return Err(Mp4Error::Layout);
    };
    if tag.wire_bytes().len() != bytes.len() {
        return Err(Mp4Error::Layout);
    }
    let start = record
        .offset()
        .checked_add(u64::try_from(range.start).map_err(|_| Mp4Error::Limit)?)
        .ok_or(Mp4Error::Limit)?;
    let end = start
        .checked_add(u64::try_from(bytes.len()).map_err(|_| Mp4Error::Limit)?)
        .ok_or(Mp4Error::Limit)?;
    Ok((tag, start, end))
}
fn absolute(base: u64, range: Range<usize>) -> Result<Range<u64>, Mp4Error> {
    let start = base
        .checked_add(u64::try_from(range.start).map_err(|_| Mp4Error::Limit)?)
        .ok_or(Mp4Error::Limit)?;
    let end = base
        .checked_add(u64::try_from(range.end).map_err(|_| Mp4Error::Limit)?)
        .ok_or(Mp4Error::Limit)?;
    Ok(start..end)
}
