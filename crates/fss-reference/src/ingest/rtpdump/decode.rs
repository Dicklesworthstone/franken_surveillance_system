#![forbid(unsafe_code)]
//! Source-linked native pixels from recorded RTP, including bounded packet reordering.
//!
//! This is a rebuildable codec derivative, not an import, a display authorization, a
//! capture-time assertion, or negative-evidence authority. The caller retains the whole
//! original recording and the exact selected parameter bytes independently. Presentation
//! consumers must apply their current privacy policy before serving these raw planes.

use super::avc::{AvcDumpAdmission, AvcDumpConfig, AvcDumpError, AvcDumpStep, RecordedAvcReplay};
use super::replay::FileNalSource;
use crate::ReplayCx;
use fss_codec_h264::{DecodeError, Decoder, DecoderLimits, Picture};
use fss_core::ContentDigest;
use fss_packet::StreamKey;
use fss_packet::avc::{
    AvcAssemblyStep, AvcBoundary, AvcPictureGroup, AvcReceivePoll, AvcRetirementReason,
    parse_pps, parse_sps,
};
use std::collections::VecDeque;

/// Lifetime bounds in addition to the receiver's independent transport/assembly bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RtpDecodeLimits {
    /// Native decoder allocation and syntax ceilings; pictures are additionally narrowed below.
    pub codec: DecoderLimits,
    /// Maximum observed picture groups, including skipped/refused groups (1..=4,096).
    pub max_groups: usize,
    /// Maximum source-copy spans mapped over the entire attempt (1..=65,536).
    pub max_source_spans: usize,
    /// Maximum NAL submissions, including out-of-band parameters (2..=65,536).
    pub max_decode_calls: usize,
    /// Maximum NAL bytes submitted over the entire attempt (1..=256 MiB).
    pub max_decode_bytes: usize,
    /// Maximum decoded I420 bytes queued or served in total (1..=256 MiB), not an RSS claim.
    pub max_output_bytes: usize,
}
impl Default for RtpDecodeLimits {
    fn default() -> Self {
        Self {
            codec: DecoderLimits::default(),
            max_groups: 1024,
            max_source_spans: 65_536,
            max_decode_calls: 65_536,
            max_decode_bytes: 64 * 1024 * 1024,
            max_output_bytes: 64 * 1024 * 1024,
        }
    }
}

/// Payload-free refusal; no path, credential, or partial image is disclosed.
#[derive(Debug)]
pub enum RtpDecodeError {
    /// An explicit lifetime budget could not admit more work.
    Limit,
    /// Bounded bookkeeping allocation failed.
    Allocation,
    /// Actual receiver/configuration refusal.
    Replay(AvcDumpError),
    /// Actual native codec refusal, never concealment or approximate pixels.
    Codec(DecodeError),
    /// Output could not be bound one-to-one to an accepted source picture group.
    PictureMapping,
    /// An upstream discontinuity invalidated pending reference-dependent decode work.
    Discontinuity,
    /// Owner cancellation; already returned frames and original custody remain the caller's.
    Cancelled,
}
impl std::fmt::Display for RtpDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "recorded RTP decode refusal: {self:?}")
    }
}
impl std::error::Error for RtpDecodeError {}
impl From<DecodeError> for RtpDecodeError {
    fn from(error: DecodeError) -> Self {
        Self::Codec(error)
    }
}

/// One complete NAL's byte identity and verified offsets into the ORIGINAL rtpdump file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpDecodedNalSource {
    /// Digest excludes synthesized Annex-B delimiters; no delimiters are inserted.
    pub digest: ContentDigest,
    /// Exact original copy spans and separately represented FU header synthesis.
    pub spans: Vec<FileNalSource>,
}

/// Binding for the access unit that actually coded a picture, not the later output trigger.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RtpDecodedPictureSource {
    /// Digest of the complete immutable recording, including refused records and any bad tail.
    pub recording: ContentDigest,
    /// Exact SPS/PPS supplied at construction; selection is the caller's responsibility.
    pub parameters: [ContentDigest; 2],
    /// Owner-bound source epoch. Decoder output order never changes this identity.
    pub key: StreamKey,
    /// Zero-based observed picture group in this replay, including any skipped groups.
    pub group: usize,
    /// Original sender RTP timestamp, not converted into capture or wall-clock time.
    pub timestamp: u32,
    /// Observed grouping boundary; even an RTP marker is not a completeness certificate.
    pub boundary: AvcBoundary,
    /// Decode-order complete NALs that contributed to this picture group.
    pub nals: Vec<RtpDecodedNalSource>,
}

/// Complete native output in display order, privately bound to its decode-order source group.
pub struct RtpDecodedPicture {
    source: RtpDecodedPictureSource,
    picture: Picture,
}
impl RtpDecodedPicture {
    /// Verified original-record provenance of the picture's own access unit.
    pub fn source(&self) -> &RtpDecodedPictureSource {
        &self.source
    }
    /// Raw native I420 planes. Authorization and privacy masking belong to the consumer.
    pub fn picture(&self) -> &Picture {
        &self.picture
    }
}
impl std::fmt::Debug for RtpDecodedPicture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RtpDecodedPicture")
            .field("group", &self.source.group)
            .field("decode_index", &self.picture.decode_index())
            .field("width", &self.picture.width())
            .field("height", &self.picture.height())
            .finish_non_exhaustive()
    }
}

/// Decode consequences accompany, never replace, the actual source/receiver event.
#[derive(Debug)]
pub enum RtpDecodeEffect {
    /// No picture-decode work was requested by this event.
    None,
    /// Source-mapped picture group admitted to the native decoder.
    Admitted { group: usize },
    /// Dependent picture was not decoded because no valid IDR-led state exists yet.
    WaitingForIdr { group: usize },
    /// Decode is fenced; receiver originals and its typed events remain inspectable.
    Fenced,
    /// Pending groups were retired, never silently counted as successfully decoded frames.
    Refused {
        /// Exact decoder/adapter reason.
        error: RtpDecodeError,
        /// Accepted groups not yet returned to the owner, including queued complete frames.
        retired_groups: usize,
    },
    /// Native EOF flushed successfully; queued display pictures can still follow.
    Finished,
}

/// One bounded original/receiver event or one complete display-order picture.
#[derive(Debug)]
pub enum RtpDecodeStep<'a> {
    /// The original adapter event is unchanged, including refusals and cancellation receipts.
    Replay {
        event: AvcDumpStep<'a>,
        effect: RtpDecodeEffect,
    },
    /// The corresponding ingress records and grouping event were returned first.
    Picture(RtpDecodedPicture),
    /// Both original enumeration and decoder output have ended.
    Exhausted,
}

/// Ordered recorded-RTP receiver composed with the canonical safe-Rust H.264 decoder.
///
/// Complete picture groups, not individual arrival-order packets, reach the decoder.
/// Output is joined by the codec's decode index, so B-picture display reordering cannot
/// attribute pixels to the packet that merely triggered their release. A refusal fences
/// this decode attempt without hiding subsequent original records. No durable import or
/// existing import-report bytes are rewritten by this operation.
pub struct RecordedRtpH264Decoder<'a> {
    replay: RecordedAvcReplay<'a>,
    decoder: Option<Decoder>,
    limits: RtpDecodeLimits,
    recording: ContentDigest,
    parameters: [ContentDigest; 2],
    sources: Vec<Option<RtpDecodedPictureSource>>,
    ready: VecDeque<RtpDecodedPicture>,
    groups: usize,
    calls: usize,
    encoded_bytes: usize,
    source_spans: usize,
    output_bytes: usize,
    waiting_idr: bool,
}
impl<'a> RecordedRtpH264Decoder<'a> {
    /// Bind exact owner-selected parameters to both syntax admission and native decoding.
    /// Construction neither publishes source custody nor confers authority to display pixels.
    pub fn new(
        input: &'a [u8],
        config: AvcDumpConfig,
        sps: &[u8],
        pps: &[u8],
        limits: RtpDecodeLimits,
    ) -> Result<Self, RtpDecodeError> {
        if !(1..=4096).contains(&limits.max_groups)
            || !(1..=65_536).contains(&limits.max_source_spans)
            || !(2..=65_536).contains(&limits.max_decode_calls)
            || !(1..=256 * 1024 * 1024).contains(&limits.max_decode_bytes)
            || !(1..=256 * 1024 * 1024).contains(&limits.max_output_bytes)
        {
            return Err(RtpDecodeError::Limit);
        }
        let parsed_sps = parse_sps(sps, config.receiver.syntax).map_err(DecodeError::from)?;
        let parsed_pps = parse_pps(pps, &parsed_sps, config.receiver.syntax)
            .map_err(DecodeError::from)?;
        let replay = RecordedAvcReplay::new(input, config, (parsed_sps, parsed_pps))
            .map_err(RtpDecodeError::Replay)?;
        let encoded_bytes = sps.len().checked_add(pps.len()).ok_or(RtpDecodeError::Limit)?;
        if encoded_bytes > limits.max_decode_bytes {
            return Err(RtpDecodeError::Limit);
        }
        let mut decoder = Decoder::new(DecoderLimits {
            max_pictures: limits.codec.max_pictures.min(limits.max_groups as u64),
            ..limits.codec
        })?;
        for parameter in [sps, pps] {
            if decoder.decode_nal(parameter)?.is_some() || decoder.next_output().is_some() {
                return Err(RtpDecodeError::PictureMapping);
            }
        }
        let mut sources = Vec::new();
        sources.try_reserve_exact(limits.max_groups).map_err(|_| RtpDecodeError::Allocation)?;
        let mut ready = VecDeque::new();
        ready.try_reserve_exact(limits.max_groups).map_err(|_| RtpDecodeError::Allocation)?;
        Ok(Self {
            replay,
            decoder: Some(decoder),
            limits,
            recording: ContentDigest::sha256(input),
            parameters: [ContentDigest::sha256(sps), ContentDigest::sha256(pps)],
            sources,
            ready,
            groups: 0,
            calls: 2,
            encoded_bytes,
            source_spans: 0,
            output_bytes: 0,
            waiting_idr: true,
        })
    }

    /// Original receiver events precede their output. Cancellation is checked even while
    /// decoded pictures are queued, so buffered pixels cannot bypass a cancelled context.
    pub fn step(&mut self, cx: &ReplayCx) -> RtpDecodeStep<'a> {
        if cx.checkpoint("rtpdump:decode").is_err() {
            let effect = self.fence(RtpDecodeError::Cancelled);
            return match self.replay.step(cx) {
                AvcDumpStep::Exhausted => RtpDecodeStep::Exhausted,
                event => RtpDecodeStep::Replay { event, effect },
            };
        }
        if let Some(picture) = self.ready.pop_front() {
            return RtpDecodeStep::Picture(picture);
        }
        let event = self.replay.step(cx);
        if matches!(event, AvcDumpStep::Exhausted) {
            return RtpDecodeStep::Exhausted;
        }
        let effect = if self.decoder.is_none() {
            RtpDecodeEffect::Fenced
        } else if interrupted(&event) {
            self.fence(RtpDecodeError::Discontinuity)
        } else {
            match self.advance(&event) {
                Ok(effect) => effect,
                Err(error) => self.fence(error),
            }
        };
        RtpDecodeStep::Replay { event, effect }
    }

    fn advance(&mut self, event: &AvcDumpStep<'_>) -> Result<RtpDecodeEffect, RtpDecodeError> {
        let mut effect = RtpDecodeEffect::None;
        if let Some(group) = picture_group(event) {
            if self.groups == self.limits.max_groups {
                return Err(RtpDecodeError::Limit);
            }
            let index = self.groups;
            self.groups += 1;
            let idr = group.nals().iter().any(|nal| nal.nal_type() == 5);
            if self.waiting_idr && !idr {
                return Ok(RtpDecodeEffect::WaitingForIdr { group: index });
            }
            self.admit(group, index)?;
            self.waiting_idr = false;
            effect = RtpDecodeEffect::Admitted { group: index };
        }
        if matches!(event, AvcDumpStep::Progress(AvcReceivePoll::Ended { .. })) {
            let decoder = self.decoder.as_mut().ok_or(RtpDecodeError::PictureMapping)?;
            let output = decoder.finish()?;
            for picture in output {
                self.bind(picture)?;
            }
            if self.sources.iter().any(Option::is_some) {
                return Err(RtpDecodeError::PictureMapping);
            }
            self.decoder = None;
            effect = RtpDecodeEffect::Finished;
        }
        Ok(effect)
    }

    fn admit(&mut self, group: &AvcPictureGroup, index: usize) -> Result<(), RtpDecodeError> {
        let spans = group.nals().iter().try_fold(0_usize, |sum, nal| {
            sum.checked_add(nal.sources().len()).ok_or(RtpDecodeError::Limit)
        })?;
        let calls = self.calls.checked_add(group.nals().len()).ok_or(RtpDecodeError::Limit)?;
        let bytes = self.encoded_bytes.checked_add(group.byte_len()).ok_or(RtpDecodeError::Limit)?;
        let mapped = self.source_spans.checked_add(spans).ok_or(RtpDecodeError::Limit)?;
        if calls > self.limits.max_decode_calls || bytes > self.limits.max_decode_bytes
            || mapped > self.limits.max_source_spans || self.sources.len() == self.limits.max_groups
        {
            return Err(RtpDecodeError::Limit);
        }
        let mut nals = Vec::new();
        nals.try_reserve_exact(group.nals().len()).map_err(|_| RtpDecodeError::Allocation)?;
        for nal in group.nals() {
            nals.push(RtpDecodedNalSource {
                digest: ContentDigest::sha256(nal.bytes()),
                spans: self.replay.map_nal(nal).map_err(RtpDecodeError::Replay)?,
            });
        }
        self.sources.push(Some(RtpDecodedPictureSource {
            recording: self.recording,
            parameters: self.parameters,
            key: group.key(),
            group: index,
            timestamp: group.timestamp(),
            boundary: group.boundary(),
            nals,
        }));
        self.calls = calls;
        self.encoded_bytes = bytes;
        self.source_spans = mapped;
        for nal in group.nals() {
            let output = self.decoder.as_mut().ok_or(RtpDecodeError::PictureMapping)?
                .decode_nal(nal.bytes())?;
            if let Some(picture) = output {
                self.bind(picture)?;
            }
            loop {
                let output = self.decoder.as_mut().ok_or(RtpDecodeError::PictureMapping)?
                    .next_output();
                match output {
                    Some(picture) => self.bind(picture)?,
                    None => break,
                }
            }
        }
        Ok(())
    }

    fn bind(&mut self, picture: Picture) -> Result<(), RtpDecodeError> {
        let index = usize::try_from(picture.decode_index()).map_err(|_| RtpDecodeError::PictureMapping)?;
        let bytes = picture.luma().len().checked_add(picture.cb().len())
            .and_then(|n| n.checked_add(picture.cr().len()))
            .and_then(|n| self.output_bytes.checked_add(n)).ok_or(RtpDecodeError::Limit)?;
        if bytes > self.limits.max_output_bytes || self.ready.len() == self.limits.max_groups {
            return Err(RtpDecodeError::Limit);
        }
        let source = self.sources.get_mut(index).and_then(Option::take)
            .ok_or(RtpDecodeError::PictureMapping)?;
        self.output_bytes = bytes;
        self.ready.push_back(RtpDecodedPicture { source, picture });
        Ok(())
    }

    fn fence(&mut self, error: RtpDecodeError) -> RtpDecodeEffect {
        let retired_groups = self.sources.iter().filter(|source| source.is_some()).count()
            + self.ready.len();
        self.sources.clear();
        self.ready.clear();
        self.decoder = None;
        RtpDecodeEffect::Refused { error, retired_groups }
    }
}

fn picture_group<'a>(event: &'a AvcDumpStep<'_>) -> Option<&'a AvcPictureGroup> {
    match event {
        AvcDumpStep::Progress(AvcReceivePoll::Picture(group)) => Some(group),
        AvcDumpStep::Progress(AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(output)))
        | AvcDumpStep::Progress(AvcReceivePoll::Ended { tail: Some(output), .. }) => output.picture.as_ref(),
        _ => None,
    }
}

fn interrupted(event: &AvcDumpStep<'_>) -> bool {
    match event {
        AvcDumpStep::Record { admission, .. } => match admission {
            AvcDumpAdmission::Rtp(receipt) => receipt.transport.transport.discarded.is_some(),
            AvcDumpAdmission::CapturedPrefix(_) | AvcDumpAdmission::Refused { .. }
            | AvcDumpAdmission::Fenced => true,
            AvcDumpAdmission::Rtcp(_) => false,
        },
        AvcDumpStep::Progress(event) => match event {
            AvcReceivePoll::Source { gap_before, fragment, picture, .. } =>
                *gap_before || fragment.is_some() || picture.is_some(),
            AvcReceivePoll::CodecRefused { .. } | AvcReceivePoll::Gap { .. }
            | AvcReceivePoll::FragmentRetired { .. }
            | AvcReceivePoll::Assembly(AvcAssemblyStep::Refused(_)) => true,
            AvcReceivePoll::PictureRetired(retired) => retired.reason != AvcRetirementReason::NoPrimaryPicture,
            AvcReceivePoll::Assembly(AvcAssemblyStep::Accepted(output)) => output.retired.as_ref()
                .is_some_and(|retired| retired.reason != AvcRetirementReason::NoPrimaryPicture),
            AvcReceivePoll::Ended { fragment, interrupted_picture, .. } =>
                fragment.is_some() || interrupted_picture.is_some(),
            AvcReceivePoll::Picture(_) | AvcReceivePoll::Pending { .. } => false,
        },
        AvcDumpStep::FramingRefused { .. } | AvcDumpStep::ReceiverRefused { .. }
        | AvcDumpStep::Cancelled(_) => true,
        AvcDumpStep::InputEnded | AvcDumpStep::Exhausted => false,
    }
}
