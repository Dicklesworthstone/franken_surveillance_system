#![forbid(unsafe_code)]
//! Bounded AVC plus AAC fragmented MP4 from an existing source-linked video
//! fragment and caller-bound FLV audio records. No transcoding or I/O occurs.
//!
//! The caller must establish source custody, configuration epoch, audio/video
//! clock alignment and coverage. These local mappings do not authenticate a
//! camera, prove that a compressed frame is decodable, or establish persistence.

use std::ops::Range;

use fss_packet::extended_flv::{aac::Configuration, aac_adts::SourceFrame, aac_clock::SampleTime};

use crate::{InitializationSegment, Mp4Error, Mp4Limits, boxes::Writer, flv_avc};

/// Two-track initialization retaining the video parameter-set byte locations.
pub struct Initialization {
    inner: InitializationSegment,
    audio_configuration: Range<usize>,
    key: flv_avc::SourceKey,
    video_configuration_sources: [Range<u64>; 2],
}
impl Initialization {
    pub(crate) fn new(
        inner: InitializationSegment,
        audio_configuration: Range<usize>,
        key: flv_avc::SourceKey,
        video_configuration_sources: [Range<u64>; 2],
    ) -> Self {
        Self {
            inner,
            audio_configuration,
            key,
            video_configuration_sources,
        }
    }
    /// Encoded ftyp and moov containing AVC track 1 and AAC track 2.
    pub fn bytes(&self) -> &[u8] {
        self.inner.bytes()
    }
    /// Caller-supplied connection and generation associated with this initialization.
    /// This is an identity claim, not authentication of the device.
    pub fn source_key(&self) -> flv_avc::SourceKey {
        self.key
    }
    /// Original connection-relative video parameter-set ranges.
    pub fn video_configuration_sources(&self) -> [Range<u64>; 2] {
        self.video_configuration_sources.clone()
    }
    /// Exact source SPS bytes in the initialization.
    pub fn sps_range(&self) -> Range<usize> {
        self.inner.sps_range()
    }
    /// Exact source PPS bytes in the initialization.
    pub fn pps_range(&self) -> Range<usize> {
        self.inner.pps_range()
    }
    /// Supplied AudioSpecificConfig byte location in the initialization.
    pub fn audio_configuration_range(&self) -> Range<usize> {
        self.audio_configuration.clone()
    }
}

/// One original audio body and its caller-bound sample-clock position.
pub struct TimedAudio<'a> {
    /// Borrowed source-linked frame, retaining its original record with the owner.
    pub frame: &'a SourceFrame<'a>,
    /// Caller-selected AAC sample-clock position and original FLV timestamp.
    pub time: SampleTime,
}

/// Exact original and emitted compressed AAC body locations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AudioMapping {
    /// Original body range in the connection.
    pub source: Range<u64>,
    /// Copied body range in the A/V fragment.
    pub target: Range<usize>,
    /// Decode time in the AAC sample-rate timescale.
    pub decode_ticks: u64,
    /// Duration in AAC sample-rate ticks.
    pub duration_ticks: u16,
}

/// One derived A/V fragment and the original borrowed video mappings.
pub struct Fragment<'a> {
    video: &'a flv_avc::Fragment,
    bytes: Vec<u8>,
    video_shift: usize,
    audio: Vec<AudioMapping>,
}
impl<'a> Fragment<'a> {
    /// Complete moof and mdat bytes; no media is re-encoded.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Original video fragment and its source-relative NAL mappings.
    pub fn video(&self) -> &'a flv_avc::Fragment {
        self.video
    }
    /// Added offset for each video mapping's original target range.
    pub fn video_target_shift(&self) -> usize {
        self.video_shift
    }
    /// Original-to-output AAC sample mappings.
    pub fn audio(&self) -> &[AudioMapping] {
        &self.audio
    }
}

/// Sequential A/V fragment owner for one caller-bound connection and epoch.
/// It rejects gaps, repeated fragments and audio clock resets across fragment
/// boundaries. It performs no persistence, I/O, identity verification or
/// independent A/V clock alignment.
/// A clone is an independent in-memory hypothesis, not duplicate source
/// custody or permission to publish.
#[derive(Clone)]
pub struct Session {
    key: flv_avc::SourceKey,
    video_configuration_sources: [Range<u64>; 2],
    audio_configuration: [u8; 2],
    next_sequence: Option<u32>,
    started: bool,
    video_end_ms: Option<u64>,
    audio_end_ticks: Option<u64>,
    audio_source_end: Option<u64>,
    audio_sender_ms: Option<u32>,
    audio_elapsed_ms: Option<u64>,
}
impl Session {
    /// Bind a session to the exact initialization selected by the caller.
    pub fn new(initialization: &Initialization) -> Result<Self, Mp4Error> {
        let bytes: [u8; 2] = initialization
            .bytes()
            .get(initialization.audio_configuration.clone())
            .ok_or(Mp4Error::Layout)?
            .try_into()
            .map_err(|_| Mp4Error::Layout)?;
        Ok(Self {
            key: initialization.key,
            video_configuration_sources: initialization.video_configuration_sources.clone(),
            audio_configuration: bytes,
            next_sequence: None,
            started: false,
            video_end_ms: None,
            audio_end_ticks: None,
            audio_source_end: None,
            audio_sender_ms: None,
            audio_elapsed_ms: None,
        })
    }

    /// Derive the next ordered fragment. A refusal leaves this session's
    /// sequence, timing and source cursors unchanged; input remains borrowed.
    pub fn fragment<'a>(
        &mut self,
        initialization: &Initialization,
        video: &'a flv_avc::Fragment,
        config: &Configuration<'_>,
        samples: &[TimedAudio<'_>],
        limits: Mp4Limits,
    ) -> Result<Fragment<'a>, Mp4Error> {
        if initialization.key != self.key
            || initialization.video_configuration_sources != self.video_configuration_sources
        {
            return Err(Mp4Error::StreamMismatch);
        }
        if config.bytes() != self.audio_configuration.as_slice() {
            return Err(Mp4Error::ParameterSet);
        }
        if self.started && self.next_sequence != Some(video.sequence()) {
            return Err(if self.next_sequence.is_none() {
                Mp4Error::SequenceExhausted
            } else {
                Mp4Error::SourceOrder
            });
        }
        let first_video = video.samples().first().ok_or(Mp4Error::Limit)?;
        let last_video = video.samples().last().ok_or(Mp4Error::Limit)?;
        if self
            .video_end_ms
            .is_some_and(|end| first_video.decode_time_ms != end)
            || (self.started && video.timeline_gap().is_some())
        {
            return Err(Mp4Error::Timeline);
        }
        let first_audio = samples.first().ok_or(Mp4Error::Limit)?;
        let last_audio = samples.last().ok_or(Mp4Error::Limit)?;
        if self
            .audio_end_ticks
            .is_some_and(|end| first_audio.time.decode_ticks != end)
        {
            return Err(Mp4Error::Timeline);
        }
        if self
            .audio_source_end
            .is_some_and(|end| first_audio.frame.body_range().start < end)
        {
            return Err(Mp4Error::SourceOrder);
        }
        if let (Some(sender), Some(elapsed)) = (self.audio_sender_ms, self.audio_elapsed_ms) {
            let delta = first_audio.frame.timestamp_ms().wrapping_sub(sender);
            if delta == 0
                || delta >= (1 << 31)
                || first_audio.time.elapsed_ms.checked_sub(elapsed) != Some(u64::from(delta))
            {
                return Err(Mp4Error::Timeline);
            }
        }
        let video_end = last_video
            .decode_time_ms
            .checked_add(u64::from(last_video.duration_ms))
            .ok_or(Mp4Error::Timeline)?;
        let audio_end = last_audio
            .time
            .decode_ticks
            .checked_add(u64::from(last_audio.time.duration_ticks))
            .ok_or(Mp4Error::Timeline)?;
        let output = fragment(initialization, video, config, samples, limits)?;
        self.started = true;
        self.next_sequence = video.sequence().checked_add(1);
        self.video_end_ms = Some(video_end);
        self.audio_end_ticks = Some(audio_end);
        self.audio_source_end = Some(last_audio.frame.body_range().end);
        self.audio_sender_ms = Some(last_audio.frame.timestamp_ms());
        self.audio_elapsed_ms = Some(last_audio.time.elapsed_ms);
        Ok(output)
    }
}

/// Build one two-track fragment from a validated AVC fragment and ordered AAC
/// samples. The caller must bind `config` to every audio frame and to the
/// initialization, use a common media-clock mapping for both tracks, and
/// account for any missing audio records. No frame or source record is consumed.
pub fn fragment<'a>(
    initialization: &Initialization,
    video: &'a flv_avc::Fragment,
    config: &Configuration<'_>,
    samples: &[TimedAudio<'_>],
    limits: Mp4Limits,
) -> Result<Fragment<'a>, Mp4Error> {
    limits.validate()?;
    if initialization.key != video.key()
        || initialization.video_configuration_sources != video.configuration_sources()
    {
        return Err(Mp4Error::StreamMismatch);
    }
    if initialization
        .bytes()
        .get(initialization.audio_configuration.clone())
        != Some(config.bytes())
    {
        return Err(Mp4Error::ParameterSet);
    }
    if config.frame_samples() != 1024 || config.sample_rate() > u16::MAX as u32 {
        return Err(Mp4Error::UnsupportedFormat);
    }
    if samples.is_empty() || samples.len() > limits.max_samples {
        return Err(Mp4Error::Limit);
    }
    let old = video.bytes();
    let n = video.samples().len();
    if n > limits.max_samples
        || video.nals().len() > limits.max_nals
        || video
            .nals()
            .len()
            .checked_add(samples.len())
            .is_none_or(|count| count > limits.max_source_spans)
    {
        return Err(Mp4Error::Limit);
    }
    let old_moof = n
        .checked_mul(16)
        .and_then(|x| x.checked_add(88))
        .ok_or(Mp4Error::Limit)?;
    let original_offset = old_moof.checked_add(8).ok_or(Mp4Error::Limit)?;
    if n == 0
        || old.get(4..8) != Some(b"moof")
        || read_u32(old, 0)? as usize != old_moof
        || old.get(72..76) != Some(b"trun")
        || read_u32(old, 84)? as usize != original_offset
        || old.get(old_moof + 4..old_moof + 8) != Some(b"mdat")
        || read_u32(old, old_moof)? as usize
            != old.len().checked_sub(old_moof).ok_or(Mp4Error::Layout)?
    {
        return Err(Mp4Error::Layout);
    }
    let extra = samples
        .len()
        .checked_mul(8)
        .and_then(|x| x.checked_add(64))
        .ok_or(Mp4Error::Limit)?;
    let new_video_offset = original_offset
        .checked_add(extra)
        .filter(|x| *x <= i32::MAX as usize)
        .ok_or(Mp4Error::Limit)?;
    let video_payload = old.get(original_offset..).ok_or(Mp4Error::Layout)?;
    let audio_offset = new_video_offset
        .checked_add(video_payload.len())
        .filter(|x| *x <= i32::MAX as usize)
        .ok_or(Mp4Error::Limit)?;
    let mut total = old.len().checked_add(extra).ok_or(Mp4Error::Limit)?;
    let mut previous_end = None;
    let mut previous_source_end = None;
    let mut previous_sender = None;
    let mut previous_elapsed = None;
    let cfg = config.bytes();
    let expected_rate = (cfg[0] & 7) << 1 | cfg[1] >> 7;
    let channel = config.channel_configuration();
    for sample in samples {
        let frame = sample.frame;
        let source = frame.body_range();
        if frame.provisional()
            || source.start >= source.end
            || previous_source_end.is_some_and(|end| source.start < end)
        {
            return Err(Mp4Error::SourceOrder);
        }
        if frame.timestamp_ms() != sample.time.sender_timestamp_ms
            || sample.time.duration_ticks != config.frame_samples()
            || previous_end.is_some_and(|end| sample.time.decode_ticks != end)
        {
            return Err(Mp4Error::Timeline);
        }
        if let (Some(previous), Some(elapsed)) = (previous_sender, previous_elapsed) {
            let delta = frame.timestamp_ms().wrapping_sub(previous);
            if delta == 0
                || delta >= (1 << 31)
                || sample.time.elapsed_ms.checked_sub(elapsed) != Some(u64::from(delta))
            {
                return Err(Mp4Error::Timeline);
            }
        }
        let h = frame.header();
        if h[2] != ((1 << 6) | (expected_rate << 2) | (channel >> 2))
            || h[3] & 0xc0 != (channel & 3) << 6
        {
            return Err(Mp4Error::ParameterSet);
        }
        previous_end = Some(
            sample
                .time
                .decode_ticks
                .checked_add(u64::from(sample.time.duration_ticks))
                .ok_or(Mp4Error::Timeline)?,
        );
        previous_source_end = Some(source.end);
        previous_sender = Some(frame.timestamp_ms());
        previous_elapsed = Some(sample.time.elapsed_ms);
        total = total
            .checked_add(frame.body().len())
            .filter(|n| *n <= limits.max_fragment_bytes)
            .ok_or(Mp4Error::Limit)?;
    }
    let mut w = Writer::new(limits.max_fragment_bytes, total)?;
    let mut mappings = Vec::new();
    mappings
        .try_reserve_exact(samples.len())
        .map_err(|_| Mp4Error::Allocation)?;
    let moof = w.start(b"moof")?;
    w.put(old.get(8..old_moof).ok_or(Mp4Error::Layout)?)?;
    w.data
        .get_mut(84..88)
        .ok_or(Mp4Error::Layout)?
        .copy_from_slice(&(new_video_offset as u32).to_be_bytes());
    let traf = w.start(b"traf")?;
    let tfhd = w.full(b"tfhd", 0x00020000)?;
    w.u32(2)?;
    w.end(tfhd)?;
    let tfdt = w.full(b"tfdt", 0x01000000)?;
    w.u64(samples[0].time.decode_ticks)?;
    w.end(tfdt)?;
    let trun = w.full(b"trun", 0x00000301)?;
    w.u32(u32::try_from(samples.len()).map_err(|_| Mp4Error::Limit)?)?;
    w.u32(u32::try_from(audio_offset).map_err(|_| Mp4Error::Limit)?)?;
    for sample in samples {
        w.u32(u32::from(sample.time.duration_ticks))?;
        w.u32(u32::try_from(sample.frame.body().len()).map_err(|_| Mp4Error::Limit)?)?;
    }
    w.end(trun)?;
    w.end(traf)?;
    w.end(moof)?;
    let mdat = w.start(b"mdat")?;
    if w.data.len() != new_video_offset {
        return Err(Mp4Error::Layout);
    }
    w.put(video_payload)?;
    if w.data.len() != audio_offset {
        return Err(Mp4Error::Layout);
    }
    for sample in samples {
        let start = w.data.len();
        w.put(sample.frame.body())?;
        mappings.push(AudioMapping {
            source: sample.frame.body_range(),
            target: start..w.data.len(),
            decode_ticks: sample.time.decode_ticks,
            duration_ticks: sample.time.duration_ticks,
        });
    }
    w.end(mdat)?;
    if w.data.len() != total {
        return Err(Mp4Error::Layout);
    }
    Ok(Fragment {
        video,
        bytes: w.data,
        video_shift: extra,
        audio: mappings,
    })
}

fn read_u32(bytes: &[u8], at: usize) -> Result<u32, Mp4Error> {
    let end = at.checked_add(4).ok_or(Mp4Error::Layout)?;
    Ok(u32::from_be_bytes(
        bytes
            .get(at..end)
            .ok_or(Mp4Error::Layout)?
            .try_into()
            .map_err(|_| Mp4Error::Layout)?,
    ))
}

/// Reconstruct this writer's A/V initialization from a verified video clip
/// and supplied AAC configuration, then compare every encoded byte. This is a
/// deterministic writer-profile check, not independent codec, clock, identity,
/// or source-provenance verification.
pub fn verify_archived_initialization(
    video_clip: &[u8],
    av_initialization: &[u8],
    audio: &Configuration<'_>,
    limits: Mp4Limits,
) -> Result<(), Mp4Error> {
    use crate::demux::{AvcMp4, DemuxLimits, VideoCodec};
    use fss_packet::avc::{AvcSyntaxLimits, parse_pps, parse_sps};

    limits.validate()?;
    if av_initialization.len() > limits.max_initialization_bytes {
        return Err(Mp4Error::Limit);
    }
    let movie =
        AvcMp4::parse(video_clip, None, DemuxLimits::default()).map_err(|_| Mp4Error::Layout)?;
    if movie.codec() != VideoCodec::Avc
        || movie.timescale() != 1000
        || movie.parameter_sets().len() != 2
    {
        return Err(Mp4Error::ParameterSet);
    }
    let sps_bytes = video_clip
        .get(movie.parameter_sets()[0].clone())
        .ok_or(Mp4Error::Layout)?;
    let pps_bytes = video_clip
        .get(movie.parameter_sets()[1].clone())
        .ok_or(Mp4Error::Layout)?;
    let sps =
        parse_sps(sps_bytes, AvcSyntaxLimits::default()).map_err(|_| Mp4Error::ParameterSet)?;
    let pps = parse_pps(pps_bytes, &sps, AvcSyntaxLimits::default())
        .map_err(|_| Mp4Error::ParameterSet)?;
    let (expected, _) =
        crate::init::build_av(&sps, &pps, 1000, limits.max_initialization_bytes, audio)?;
    if expected.bytes() != av_initialization {
        return Err(Mp4Error::Layout);
    }
    Ok(())
}

/// Verify this writer's fragment layout and AAC sample table against a video
/// fragment and caller-supplied source mappings. It does not establish source
/// custody, audio decoding, physical time, or independent A/V synchronization.
pub fn verify_archived_fragment(
    video: &[u8],
    av: &[u8],
    audio: &[AudioMapping],
    limits: Mp4Limits,
) -> Result<(), Mp4Error> {
    limits.validate()?;
    if audio.is_empty()
        || audio.len() > limits.max_samples
        || video.len() > limits.max_fragment_bytes
        || av.len() > limits.max_fragment_bytes
    {
        return Err(Mp4Error::Limit);
    }
    let old_moof = read_u32(video, 0)? as usize;
    let extra = audio
        .len()
        .checked_mul(8)
        .and_then(|v| v.checked_add(64))
        .ok_or(Mp4Error::Limit)?;
    let new_moof = old_moof.checked_add(extra).ok_or(Mp4Error::Limit)?;
    let old_video = old_moof.checked_add(8).ok_or(Mp4Error::Limit)?;
    let new_video = new_moof.checked_add(8).ok_or(Mp4Error::Limit)?;
    let payload = video.get(old_video..).ok_or(Mp4Error::Layout)?;
    let audio_start = new_video
        .checked_add(payload.len())
        .ok_or(Mp4Error::Limit)?;
    if old_moof < 88
        || video.get(4..8) != Some(b"moof")
        || video.get(72..76) != Some(b"trun")
        || read_u32(video, 84)? as usize != old_video
        || video.get(old_moof.checked_add(4).ok_or(Mp4Error::Limit)?..old_video) != Some(b"mdat")
        || read_u32(video, old_moof)? as usize
            != video.len().checked_sub(old_moof).ok_or(Mp4Error::Layout)?
        || read_u32(av, 0)? as usize != new_moof
        || av.get(4..8) != Some(b"moof")
        || av.get(8..84) != video.get(8..84)
        || av.get(88..old_moof) != video.get(88..old_moof)
        || read_u32(av, 84)? as usize != new_video
        || av.get(new_moof.checked_add(4).ok_or(Mp4Error::Limit)?..new_video) != Some(b"mdat")
        || read_u32(av, new_moof)? as usize
            != av.len().checked_sub(new_moof).ok_or(Mp4Error::Layout)?
        || av.get(new_video..audio_start) != Some(payload)
    {
        return Err(Mp4Error::Layout);
    }
    let tfhd = old_moof.checked_add(8).ok_or(Mp4Error::Limit)?;
    let tfdt = tfhd.checked_add(16).ok_or(Mp4Error::Limit)?;
    let trun = tfdt.checked_add(20).ok_or(Mp4Error::Limit)?;
    let entries = trun.checked_add(20).ok_or(Mp4Error::Limit)?;
    let trun_size = audio
        .len()
        .checked_mul(8)
        .and_then(|v| v.checked_add(20))
        .ok_or(Mp4Error::Limit)?;
    if read_u32(av, old_moof)? as usize != extra
        || av.get(old_moof + 4..tfhd) != Some(b"traf")
        || read_u32(av, tfhd)? != 16
        || av.get(tfhd + 4..tfhd + 8) != Some(b"tfhd")
        || read_u32(av, tfhd + 8)? != 0x0002_0000
        || read_u32(av, tfhd + 12)? != 2
        || read_u32(av, tfdt)? != 20
        || av.get(tfdt + 4..tfdt + 8) != Some(b"tfdt")
        || read_u32(av, tfdt + 8)? != 0x0100_0000
        || read_u64(av, tfdt + 12)? != audio[0].decode_ticks
        || read_u32(av, trun)? as usize != trun_size
        || av.get(trun + 4..trun + 8) != Some(b"trun")
        || read_u32(av, trun + 8)? != 0x0000_0301
        || read_u32(av, trun + 12)? as usize != audio.len()
        || read_u32(av, trun + 16)? as usize != audio_start
        || entries.checked_add(audio.len() * 8) != Some(new_moof)
    {
        return Err(Mp4Error::Layout);
    }
    let mut cursor = audio_start;
    let mut next_tick = audio[0].decode_ticks;
    let mut previous_source_end = None;
    for (index, mapping) in audio.iter().enumerate() {
        let at = entries
            .checked_add(index.checked_mul(8).ok_or(Mp4Error::Limit)?)
            .ok_or(Mp4Error::Limit)?;
        let size = mapping
            .target
            .end
            .checked_sub(mapping.target.start)
            .ok_or(Mp4Error::Layout)?;
        if size == 0
            || mapping.target.start != cursor
            || mapping.target.end > av.len()
            || mapping.source.start >= mapping.source.end
            || mapping.source.end - mapping.source.start != size as u64
            || previous_source_end.is_some_and(|end| mapping.source.start < end)
            || mapping.duration_ticks == 0
            || mapping.decode_ticks != next_tick
            || read_u32(av, at)? != u32::from(mapping.duration_ticks)
            || read_u32(av, at + 4)? as usize != size
        {
            return Err(Mp4Error::Layout);
        }
        cursor = mapping.target.end;
        next_tick = next_tick
            .checked_add(u64::from(mapping.duration_ticks))
            .ok_or(Mp4Error::Timeline)?;
        previous_source_end = Some(mapping.source.end);
    }
    if cursor != av.len() {
        return Err(Mp4Error::Layout);
    }
    Ok(())
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64, Mp4Error> {
    let end = at.checked_add(8).ok_or(Mp4Error::Layout)?;
    Ok(u64::from_be_bytes(
        bytes
            .get(at..end)
            .ok_or(Mp4Error::Layout)?
            .try_into()
            .map_err(|_| Mp4Error::Layout)?,
    ))
}
