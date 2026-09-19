use crate::{Mp4Error, Mp4Limits, boxes::Writer, init};
use fss_packet::avc::{AvcBoundary, AvcPictureGroup, AvcPps, AvcSps, AvcSyntaxLimits, parse_pps};
use fss_packet::{NalSourceSpan, StreamKey};
use std::ops::Range;

/// One picture with explicit media-clock timing. Arrival/RTP time is not DTS.
#[derive(Clone, Copy, Debug)]
pub struct TimedAvcPicture<'a> {
    /// Borrowed source-linked group; it is never consumed on success or refusal.
    pub picture: &'a AvcPictureGroup,
    /// Decode time in the muxer's time-scale ticks, independent of capture time.
    pub decode_time: u64,
    /// Positive sample duration in the same ticks.
    pub duration: u32,
    /// Signed presentation-minus-decode offset, preserving B-picture reordering.
    pub composition_offset: i32,
}

/// Initialization bytes and exact out-of-band parameter-set locations.
#[derive(Eq, PartialEq)]
pub struct InitializationSegment {
    pub(crate) bytes: Vec<u8>,
    pub(crate) sps_range: Range<usize>,
    pub(crate) pps_range: Range<usize>,
}
impl InitializationSegment {
    /// Deterministic ftyp + moov, track 1, avc1 and four-byte NAL lengths.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Exact original SPS NAL location, excluding its avcC length prefix.
    pub fn sps_range(&self) -> Range<usize> {
        self.sps_range.clone()
    }
    /// Exact original PPS NAL location, excluding its avcC length prefix.
    pub fn pps_range(&self) -> Range<usize> {
        self.pps_range.clone()
    }
}
impl std::fmt::Debug for InitializationSegment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitializationSegment")
            .field("bytes", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Where exact source NAL bytes went; parameter removal is never silent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NalTarget {
    /// Exact SPS/PPS bytes occur in the associated initialization segment.
    Initialization(Range<usize>),
    /// Exact NAL bytes occur in this fragment, after a synthesized four-byte length.
    Media(Range<usize>),
}

/// Byte-level provenance for one NAL, including copied and synthesized FU headers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NalMapping {
    /// Input sample ordinal in this fragment.
    pub sample: usize,
    /// NAL ordinal within that input picture.
    pub nal: usize,
    /// Exact output range in initialization or media bytes.
    pub target: NalTarget,
    /// Unchanged original RTP copy spans; owner binding is on the fragment.
    pub sources: Vec<NalSourceSpan>,
}

/// Sample timing, source timestamp and boundary evidence retained alongside bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SampleMapping {
    /// Complete length-prefixed sample range in the fragment's mdat.
    pub range: Range<usize>,
    /// Decode time in track ticks.
    pub decode_time: u64,
    /// Presentation time in track ticks, checked without wrapping.
    pub presentation_time: u64,
    /// Positive media duration in track ticks.
    pub duration: u32,
    /// Original unconverted RTP timestamp.
    pub rtp_timestamp: u32,
    /// Syntactically observed IDR, not decoder-verified random access.
    pub idr: bool,
    /// Exact assembly boundary, not strengthened to a completeness claim.
    pub boundary: AvcBoundary,
    /// Range of NAL mappings belonging to this sample.
    pub mappings: Range<usize>,
}

/// An immutable moof + mdat derivative. Publication and source custody are external.
#[derive(Eq, PartialEq)]
pub struct AvcFragment {
    key: StreamKey,
    sequence: u32,
    bytes: Vec<u8>,
    samples: Vec<SampleMapping>,
    mappings: Vec<NalMapping>,
    timeline_gap: Option<Range<u64>>,
}
impl AvcFragment {
    /// Exact owner ingress epoch, not an authentication token or durable identity.
    pub fn key(&self) -> StreamKey {
        self.key
    }
    /// Nonzero monotonically increasing movie-fragment sequence.
    pub fn sequence(&self) -> u32 {
        self.sequence
    }
    /// Encoded moof followed by mdat; no source NAL body was re-encoded.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Explicit sample timing and retained epistemic boundary classes.
    pub fn samples(&self) -> &[SampleMapping] {
        &self.samples
    }
    /// Exact per-NAL locations and source spans, including parameter-set relocation.
    pub fn mappings(&self) -> &[NalMapping] {
        &self.mappings
    }
    /// Declared decode-timeline interval skipped since the preceding fragment.
    /// This is not an inferred camera outage or a wall-clock interval.
    pub fn timeline_gap(&self) -> Option<Range<u64>> {
        self.timeline_gap.clone()
    }
}
impl std::fmt::Debug for AvcFragment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvcFragment")
            .field("key", &self.key)
            .field("sequence", &self.sequence)
            .field("bytes", &self.bytes.len())
            .field("samples", &self.samples.len())
            .field("timeline_gap", &self.timeline_gap)
            .finish_non_exhaustive()
    }
}

/// Deterministic, IDR-led AVC fragment writer for one immutable owner configuration.
///
/// Each fragment starts with an observed IDR and has contiguous positive-duration
/// decode times internally. Explicit gaps between independent fragments are
/// receipted, never padded with fabricated samples. All failures preserve the
/// sequence, previous timeline and source cursor; input pictures are only borrowed.
/// There is no retained media queue to flush, background task, or I/O authority.
pub struct AvcMuxer {
    key: StreamKey,
    sps: AvcSps,
    pps: AvcPps,
    limits: Mp4Limits,
    initialization: InitializationSegment,
    next_sequence: Option<u32>,
    last_end: Option<u64>,
    last_source: Option<(u64, usize)>,
}
impl std::fmt::Debug for AvcMuxer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvcMuxer")
            .field("key", &self.key)
            .field("next_sequence", &self.next_sequence)
            .field("last_end", &self.last_end)
            .finish_non_exhaustive()
    }
}

impl AvcMuxer {
    /// Create track 1 with exact configuration and a positive caller-owned media
    /// time scale. Field pictures and oversized avcC parameter sets fail closed.
    pub fn new(
        key: StreamKey,
        sps: AvcSps,
        pps: AvcPps,
        time_scale: u32,
        limits: Mp4Limits,
    ) -> Result<Self, Mp4Error> {
        limits.validate()?;
        if key.ingress == 0 || key.generation == 0 || time_scale == 0 {
            return Err(Mp4Error::Configuration);
        }
        if !sps.frame_mbs_only() {
            return Err(Mp4Error::UnsupportedFormat);
        }
        if sps.nal_bytes().len() > u16::MAX as usize || pps.nal_bytes().len() > u16::MAX as usize {
            return Err(Mp4Error::ParameterSet);
        }
        // Eq includes the PPS's exact SPS-byte binding, not just its numeric id.
        let bound = parse_pps(
            pps.nal_bytes(),
            &sps,
            AvcSyntaxLimits {
                max_width: 16_384,
                max_height: 16_384,
                max_luma_samples: 268_435_456,
                ..AvcSyntaxLimits::default()
            },
        )
        .map_err(|_| Mp4Error::ParameterSet)?;
        if bound != pps {
            return Err(Mp4Error::ParameterSet);
        }
        let initialization = init::build(&sps, &pps, time_scale, limits.max_initialization_bytes)?;
        Ok(Self {
            key,
            sps,
            pps,
            limits,
            initialization,
            next_sequence: Some(1),
            last_end: None,
            last_source: None,
        })
    }

    /// Reuse these initialization bytes for every fragment of this exact track.
    pub fn initialization(&self) -> &InitializationSegment {
        &self.initialization
    }
    /// Next fragment sequence, absent only after u32::MAX was emitted.
    pub fn next_sequence(&self) -> Option<u32> {
        self.next_sequence
    }

    /// Produce one bounded IDR-led fragment without transcoding. All validation
    /// and allocations complete before the state advances. Cancellation before
    /// calling this synchronous bounded operation has no pending-media obligation.
    pub fn fragment(&mut self, samples: &[TimedAvcPicture<'_>]) -> Result<AvcFragment, Mp4Error> {
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
            w.u32(if sample.picture.identity().idr_pic_id().is_some() {
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
        for (index, sample) in samples.iter().enumerate() {
            let begin = w.data.len();
            let map_begin = mappings.len();
            for (ordinal, nal) in sample.picture.nals().iter().enumerate() {
                let target = match nal.nal_type() {
                    7 => NalTarget::Initialization(self.initialization.sps_range.clone()),
                    8 => NalTarget::Initialization(self.initialization.pps_range.clone()),
                    _ => {
                        w.u32(nal.bytes().len() as u32)?;
                        let start = w.data.len();
                        w.put(nal.bytes())?;
                        NalTarget::Media(start..w.data.len())
                    }
                };
                let mut sources = Vec::new();
                sources
                    .try_reserve_exact(nal.sources().len())
                    .map_err(|_| Mp4Error::Allocation)?;
                sources.extend(nal.sources().iter().cloned());
                mappings.push(NalMapping {
                    sample: index,
                    nal: ordinal,
                    target,
                    sources,
                });
            }
            receipts.push(SampleMapping {
                range: begin..w.data.len(),
                decode_time: sample.decode_time,
                presentation_time: presentation_time(sample)?,
                duration: sample.duration,
                rtp_timestamp: sample.picture.timestamp(),
                idr: sample.picture.identity().idr_pic_id().is_some(),
                boundary: sample.picture.boundary(),
                mappings: map_begin..mappings.len(),
            });
        }
        w.end(mdat)?;
        if w.data.len() != plan.bytes {
            return Err(Mp4Error::Layout);
        }
        let gap = self
            .last_end
            .filter(|end| *end < samples[0].decode_time)
            .map(|end| end..samples[0].decode_time);
        let output = AvcFragment {
            key: self.key,
            sequence,
            bytes: w.data,
            samples: receipts,
            mappings,
            timeline_gap: gap,
        };
        // This is a local sequence cursor, not an archive publication/acknowledgement.
        self.next_sequence = sequence.checked_add(1);
        self.last_end = Some(plan.end);
        self.last_source = plan.last_source;
        Ok(output)
    }

    fn preflight(&self, samples: &[TimedAvcPicture<'_>]) -> Result<Plan, Mp4Error> {
        if samples.is_empty() || samples.len() > self.limits.max_samples {
            return Err(Mp4Error::Limit);
        }
        if samples[0].picture.identity().idr_pic_id().is_none() {
            return Err(Mp4Error::RandomAccessRequired);
        }
        if self
            .last_end
            .is_some_and(|end| samples[0].decode_time < end)
        {
            return Err(Mp4Error::Timeline);
        }
        let media_offset = 96 + 16 * samples.len();
        let mut plan = Plan {
            bytes: media_offset,
            media_offset,
            nals: 0,
            end: samples[0].decode_time,
            last_source: self.last_source,
        };
        let mut spans = 0_usize;
        for sample in samples {
            let picture = sample.picture;
            if picture.key() != self.key {
                return Err(Mp4Error::StreamMismatch);
            }
            if picture.sps().nal_bytes() != self.sps.nal_bytes()
                || picture.pps().nal_bytes() != self.pps.nal_bytes()
            {
                return Err(Mp4Error::ParameterSet);
            }
            if !picture.saw_first_macroblock()
                || picture.boundary() == AvcBoundary::EndOfInputUnverified
            {
                return Err(Mp4Error::UnverifiedPicture);
            }
            if picture.discontinuity_before() {
                return Err(Mp4Error::Discontinuity);
            }
            if sample.duration == 0 || sample.decode_time != plan.end {
                return Err(Mp4Error::Timeline);
            }
            plan.end = sample
                .decode_time
                .checked_add(u64::from(sample.duration))
                .ok_or(Mp4Error::Timeline)?;
            presentation_time(sample)?;
            plan.nals = plan
                .nals
                .checked_add(picture.nals().len())
                .ok_or(Mp4Error::Limit)?;
            if plan.nals > self.limits.max_nals {
                return Err(Mp4Error::Limit);
            }
            plan.bytes = plan
                .bytes
                .checked_add(media_size(picture)?)
                .ok_or(Mp4Error::Limit)?;
            if plan.bytes > self.limits.max_fragment_bytes {
                return Err(Mp4Error::Limit);
            }
            for nal in picture.nals() {
                spans = spans
                    .checked_add(nal.sources().len())
                    .ok_or(Mp4Error::Limit)?;
                if spans > self.limits.max_source_spans {
                    return Err(Mp4Error::Limit);
                }
                let first = nal.sources().first().ok_or(Mp4Error::SourceOrder)?;
                let last = nal.sources().last().ok_or(Mp4Error::SourceOrder)?;
                if plan.last_source.is_some_and(|(seq, end)| {
                    first.sequence < seq || (first.sequence == seq && first.wire_range.start < end)
                }) {
                    return Err(Mp4Error::SourceOrder);
                }
                plan.last_source = Some((last.sequence, last.wire_range.end));
            }
        }
        Ok(plan)
    }
}

struct Plan {
    bytes: usize,
    media_offset: usize,
    nals: usize,
    end: u64,
    last_source: Option<(u64, usize)>,
}
fn presentation_time(sample: &TimedAvcPicture<'_>) -> Result<u64, Mp4Error> {
    sample
        .decode_time
        .checked_add_signed(i64::from(sample.composition_offset))
        .ok_or(Mp4Error::Timeline)
}
fn media_size(picture: &AvcPictureGroup) -> Result<usize, Mp4Error> {
    let mut size = 0_usize;
    for nal in picture.nals() {
        if !matches!(nal.nal_type(), 7 | 8) {
            size = size
                .checked_add(4)
                .and_then(|s| s.checked_add(nal.bytes().len()))
                .ok_or(Mp4Error::Limit)?;
        }
    }
    if size == 0 {
        return Err(Mp4Error::Layout);
    }
    Ok(size)
}
