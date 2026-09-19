#![forbid(unsafe_code)]
//! Deterministic AVC/HEVC fragmented MP4 without transcoding or ambient I/O (FSS-115).
//!
//! Narrow single-video-track, avc1 or hev1, IDR-led fragment writers. Timing is
//! explicitly supplied in track ticks, never guessed from RTP, VUI, or arrival
//! clocks. Picture grouping is not decoding or a complete-picture certificate.
//! Source custody, privacy, storage publication, and authentication remain with
//! the owner. No codec, socket, filesystem, worker, or external runtime is used.

mod boxes;
mod hevc;
mod init;
mod mux;

pub use hevc::{
    HevcFragment, HevcInitialization, HevcMuxer, HevcNalMapping, HevcSampleMapping,
    TimedHevcPicture,
};
pub use mux::{
    AvcFragment, AvcMuxer, InitializationSegment, NalMapping, NalTarget, SampleMapping,
    TimedAvcPicture,
};

/// Independent work/output ceilings. All are checked before copying media.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Mp4Limits {
    /// Samples per fragment, in 1..=4096.
    pub max_samples: usize,
    /// NALs per fragment, including parameter sets moved to initialization; at most 65536.
    pub max_nals: usize,
    /// Retained RTP copy spans per fragment, at most 262144.
    pub max_source_spans: usize,
    /// Encoded moof + mdat bytes, at most 128 MiB.
    pub max_fragment_bytes: usize,
    /// Encoded ftyp + moov bytes, at most 1 MiB.
    pub max_initialization_bytes: usize,
}

impl Default for Mp4Limits {
    fn default() -> Self {
        Self {
            max_samples: 256,
            max_nals: 16_384,
            max_source_spans: 16_384,
            max_fragment_bytes: 32 * 1_024 * 1_024,
            max_initialization_bytes: 256 * 1_024,
        }
    }
}

impl Mp4Limits {
    /// Reject zero/oversized limits rather than silently widening a policy.
    pub fn validate(self) -> Result<(), Mp4Error> {
        if !(1..=4096).contains(&self.max_samples)
            || !(1..=65_536).contains(&self.max_nals)
            || !(1..=262_144).contains(&self.max_source_spans)
            || !(8..=128 * 1_024 * 1_024).contains(&self.max_fragment_bytes)
            || !(8..=1_048_576).contains(&self.max_initialization_bytes)
        {
            return Err(Mp4Error::Configuration);
        }
        Ok(())
    }
}

/// Payload-free, retry-safe container refusal categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mp4Error {
    /// Invalid owner identity, time scale, or bounds.
    Configuration,
    /// Only the writer's declared progressive codec/sample-format subset is admitted.
    UnsupportedFormat,
    /// Parameter sets do not bind exactly, exceed configuration-record bounds, or changed.
    ParameterSet,
    /// Input is from a different owner stream epoch/SSRC.
    StreamMismatch,
    /// First sample must be an observed IDR picture, not merely an intra slice.
    RandomAccessRequired,
    /// An unverified EOF tail or missing required first-slice evidence cannot be remuxed here.
    UnverifiedPicture,
    /// A picture resumes after a declared input discontinuity.
    Discontinuity,
    /// Zero duration, noncontiguous decode times within a fragment, reversal, or overflow.
    Timeline,
    /// Original packet copy spans overlap or move backwards.
    SourceOrder,
    /// Empty input, count, byte, or arithmetic resource ceiling.
    Limit,
    /// A bounded allocation failed; no sequence or input was consumed.
    Allocation,
    /// Fragment sequence is exhausted; it never silently wraps to zero.
    SequenceExhausted,
    /// Box layout or byte ranges are invalid for the supported container subset.
    Layout,
}

impl std::fmt::Display for Mp4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MP4 remux refusal: {self:?}")
    }
}
impl std::error::Error for Mp4Error {}
