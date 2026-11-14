#![forbid(unsafe_code)]
//! Bounded Annex-B configuration probing with borrowed source bindings.
//!
//! The first complete AVC SPS/PPS or HEVC VPS/SPS/PPS tuple is interpreted by
//! the packet owner's existing parsers. No picture is decoded, no source is
//! retained, and no live timing, continuity or decoder-support claim is made.
//! AVC collection begins at an SPS and accepts a subsequent bound PPS. An
//! ambiguous PPS-like header before an SPS does not establish a codec. HEVC
//! candidates are restricted to the admitted base-layer parameter headers.
//! HEVC interpretation has the explicitly limited prefix scope of
//! fss_packet::hevc::HevcConfiguration.

use std::{fmt, ops::Range};

use fss_packet::{
    avc::{AvcError, AvcSyntaxLimits, parse_pps, parse_sps},
    hevc::{HevcConfiguration, HevcConfigurationError, HevcConfigurationLimits},
};

use super::{ContainerKind, MAX_PROBE_BYTES, ProbeLimits, ProbeOutcome, probe};

/// Independent byte, work and geometry ceilings; invalid policies fail closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParameterLimits {
    /// At most this many head bytes may be inspected, in 12..=4096.
    pub max_bytes: usize,
    /// At most this many NAL units may be inspected, in 1..=64.
    pub max_units: usize,
    /// Coded luma width ceiling, in 1..=16384.
    pub max_width: u32,
    /// Coded luma height ceiling, in 1..=16384.
    pub max_height: u32,
    /// Coded luma sample ceiling, in 1..=268435456.
    pub max_luma_samples: u64,
}

impl Default for ParameterLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_PROBE_BYTES,
            max_units: 64,
            max_width: 8192,
            max_height: 8192,
            max_luma_samples: 8192 * 8192,
        }
    }
}

impl ParameterLimits {
    /// Reject out-of-range policy without clamping or widening authority.
    pub fn validate(self) -> Result<(), ParameterError> {
        if !(12..=MAX_PROBE_BYTES).contains(&self.max_bytes)
            || !(1..=64).contains(&self.max_units)
            || !(1..=16384).contains(&self.max_width)
            || !(1..=16384).contains(&self.max_height)
            || !(1..=268435456).contains(&self.max_luma_samples)
        {
            return Err(ParameterError::Configuration);
        }
        Ok(())
    }
}

/// Payload-free refusal. A family signature can remain known after refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterError {
    /// Invalid caller policy.
    Configuration,
    /// A byte, NAL-count, geometry or native syntax ceiling was reached.
    Limit,
    /// The supplied prefix does not yet contain a complete parameter tuple.
    Truncated,
    /// The container, codec or signalled parameter syntax is not admitted here.
    Unsupported,
    /// Invalid framing, reserved bits, IDs, escapes or parameter values.
    Malformed,
    /// Mixed codec declarations or distinct candidates prevent one coherent tuple.
    Contradictory,
    /// Caller cancellation was observed before returning a result.
    Cancelled,
    /// A native bounded metadata allocation was refused.
    Allocation,
}

impl fmt::Display for ParameterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "media parameter probe refusal: {self:?}")
    }
}
impl std::error::Error for ParameterError {}

/// Codec identified by a parsed, internally bound parameter tuple.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParameterCodec {
    /// AVC Baseline/Main/High 8-bit 4:2:0 parameter syntax.
    Avc,
    /// HEVC Main/Main10 single-layer 4:2:0 configuration-prefix syntax.
    Hevc,
}
impl ParameterCodec {
    /// Stable machine name; this is not a decoder-support claim.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Avc => "h264",
            Self::Hevc => "h265",
        }
    }
}

/// One exact original NAL. The borrow prevents reuse/mutation while the result lives.
#[derive(Clone, Eq, PartialEq)]
pub struct ParameterSource<'a> {
    /// Range in the supplied source head, excluding delimiters and trailing zero bytes.
    pub range: Range<usize>,
    bytes: &'a [u8],
}
impl ParameterSource<'_> {
    /// Exact bytes interpreted by the native parser; never reconstructed metadata.
    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }
}
impl fmt::Debug for ParameterSource<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParameterSource")
            .field("range", &self.range)
            .finish_non_exhaustive()
    }
}

/// Metadata for the first complete configuration tuple in the bounded source prefix.
/// Subsequent configuration changes, sample timelines and pictures are not inspected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VideoParameters<'a> {
    /// Codec whose native parameter parser accepted the tuple.
    pub codec: ParameterCodec,
    /// Coded luma dimensions before the signalled crop.
    pub coded_dimensions: (u32, u32),
    /// Dimensions after the native parser's signalled crop interpretation.
    pub display_dimensions: (u32, u32),
    /// Equal component depth admitted by the native parser.
    pub bit_depth: u8,
    /// Signalled profile indicator; not full profile conformance.
    pub profile: u8,
    /// Signalled level indicator; not full level conformance.
    pub level: u8,
    /// Original VPS for HEVC; AVC has no VPS.
    pub vps: Option<ParameterSource<'a>>,
    /// Original SPS.
    pub sps: ParameterSource<'a>,
    /// Original PPS, checked against the SPS.
    pub pps: ParameterSource<'a>,
    /// Highest inspected source offset, including any terminating delimiter.
    pub inspected_bytes: usize,
    /// Number of complete NAL units considered, including skipped non-parameter units.
    pub inspected_units: usize,
}

fn checkpoint(cancelled: &mut impl FnMut() -> bool) -> Result<(), ParameterError> {
    if cancelled() {
        Err(ParameterError::Cancelled)
    } else {
        Ok(())
    }
}

/// Return delimiter start and payload start without allocating or scanning beyond bytes.
fn delimiter(
    bytes: &[u8],
    from: usize,
    cancelled: &mut impl FnMut() -> bool,
) -> Result<Option<(usize, usize)>, ParameterError> {
    let mut at = from;
    while at.saturating_add(2) < bytes.len() {
        if (at - from).is_multiple_of(128) {
            checkpoint(cancelled)?;
        }
        if bytes[at..at + 3] == [0, 0, 1] {
            let start = if at > from && bytes[at - 1] == 0 {
                at - 1
            } else {
                at
            };
            return Ok(Some((start, at + 3)));
        }
        at += 1;
    }
    Ok(None)
}

fn save<'a>(
    slot: &mut Option<ParameterSource<'a>>,
    source: ParameterSource<'a>,
) -> Result<(), ParameterError> {
    if let Some(prior) = slot {
        if prior.bytes != source.bytes {
            return Err(ParameterError::Contradictory);
        }
    } else {
        *slot = Some(source);
    }
    Ok(())
}

/// Inspect a bounded Annex-B prefix with cancellation checkpoints between units,
/// every 128 delimiter-scan bytes, and before/after native parsing.
///
/// end_of_source may be true only when the supplied bytes end at an observed EOF.
/// Reaching a byte allowance is not EOF: the final undelimited NAL is then incomplete.
/// A delimiter following the tuple is sufficient; the first picture need not fit.
/// Allocation is limited to native parameter-set parsing, over at most 4096 source bytes.
pub fn probe_parameters<'a>(
    head: &'a [u8],
    end_of_source: bool,
    limits: ParameterLimits,
    mut cancelled: impl FnMut() -> bool,
) -> Result<VideoParameters<'a>, ParameterError> {
    limits.validate()?;
    checkpoint(&mut cancelled)?;
    let window = &head[..head.len().min(limits.max_bytes)];
    let complete = end_of_source && head.len() <= limits.max_bytes;
    let incomplete = if !complete && window.len() == limits.max_bytes {
        ParameterError::Limit
    } else {
        ParameterError::Truncated
    };
    match probe(
        window,
        &ProbeLimits {
            max_bytes: limits.max_bytes,
        },
    ) {
        ProbeOutcome::Identified {
            container: ContainerKind::AnnexB,
            ..
        } => {}
        ProbeOutcome::Identified { .. } | ProbeOutcome::Unsupported => {
            return Err(ParameterError::Unsupported);
        }
        ProbeOutcome::Insufficient { .. } => return Err(incomplete),
        ProbeOutcome::Contradictory => return Err(ParameterError::Contradictory),
    }
    let (_, mut start) =
        delimiter(window, 0, &mut cancelled)?.ok_or(ParameterError::Unsupported)?;
    let mut vps = None;
    let mut sps = None;
    let mut pps = None;
    let mut codec = None;
    let mut units = 0;
    loop {
        checkpoint(&mut cancelled)?;
        if units == limits.max_units {
            return Err(ParameterError::Limit);
        }
        let next = delimiter(window, start, &mut cancelled)?;
        let mut end = match next {
            Some((end, _)) => end,
            None if complete => window.len(),
            None => return Err(incomplete),
        };
        // Annex-B trailing_zero_8bits are outside the NAL, including at EOF.
        while end > start && window[end - 1] == 0 {
            end -= 1;
        }
        if end <= start {
            return Err(ParameterError::Malformed);
        }
        units += 1;
        let source = ParameterSource {
            range: start..end,
            bytes: &window[start..end],
        };
        let header = source.bytes[0];
        // NAL-header bit positions overlap across codecs: AVC slice 0x41
        // resembles a nonzero-layer HEVC VPS, while HEVC IRAP 0x28 resembles
        // AVC PPS. Only admitted base-layer HEVC headers are candidates, and
        // a PPS cannot establish AVC before an SPS has selected that codec.
        let candidate =
            if header & 31 == 7 || (header & 31 == 8 && codec == Some(ParameterCodec::Avc)) {
                Some(ParameterCodec::Avc)
            } else if matches!(header & 0x7f, 0x40 | 0x42 | 0x44) {
                Some(ParameterCodec::Hevc)
            } else {
                None
            };
        if let Some(candidate) = candidate {
            if codec.is_some_and(|prior| prior != candidate) {
                return Err(ParameterError::Contradictory);
            }
            codec = Some(candidate);
            match candidate {
                ParameterCodec::Avc if header & 31 == 7 => save(&mut sps, source)?,
                ParameterCodec::Avc => save(&mut pps, source)?,
                ParameterCodec::Hevc => match (header >> 1) & 63 {
                    32 => save(&mut vps, source)?,
                    33 => save(&mut sps, source)?,
                    _ => save(&mut pps, source)?,
                },
            }
        }
        let ready =
            sps.is_some() && pps.is_some() && (codec == Some(ParameterCodec::Avc) || vps.is_some());
        if ready {
            checkpoint(&mut cancelled)?;
            let sps = sps.ok_or(ParameterError::Truncated)?;
            let pps = pps.ok_or(ParameterError::Truncated)?;
            let codec = codec.ok_or(ParameterError::Unsupported)?;
            let (coded, display, depth, profile, level) = match codec {
                ParameterCodec::Avc => {
                    let syntax = AvcSyntaxLimits {
                        max_nal_bytes: limits.max_bytes,
                        max_parameter_set_bytes: limits.max_bytes,
                        max_width: limits.max_width,
                        max_height: limits.max_height,
                        max_luma_samples: limits.max_luma_samples,
                        ..AvcSyntaxLimits::default()
                    };
                    let parsed = parse_sps(sps.bytes, syntax).map_err(avc_error)?;
                    checkpoint(&mut cancelled)?;
                    parse_pps(pps.bytes, &parsed, syntax).map_err(avc_error)?;
                    (
                        parsed.coded_dimensions(),
                        parsed.display_dimensions(),
                        8,
                        parsed.profile_idc(),
                        parsed.level_idc(),
                    )
                }
                ParameterCodec::Hevc => {
                    let parsed = HevcConfiguration::parse(
                        vps.as_ref().ok_or(ParameterError::Truncated)?.bytes,
                        sps.bytes,
                        pps.bytes,
                        HevcConfigurationLimits {
                            max_parameter_bytes: limits.max_bytes,
                            max_width: limits.max_width,
                            max_height: limits.max_height,
                            max_luma_samples: limits.max_luma_samples,
                        },
                    )
                    .map_err(hevc_error)?;
                    (
                        parsed.coded_dimensions(),
                        parsed.display_dimensions(),
                        parsed.bit_depth(),
                        parsed.profile_tier_level()[0] & 31,
                        parsed.profile_tier_level()[11],
                    )
                }
            };
            checkpoint(&mut cancelled)?;
            return Ok(VideoParameters {
                codec,
                coded_dimensions: coded,
                display_dimensions: display,
                bit_depth: depth,
                profile,
                level,
                vps,
                sps,
                pps,
                inspected_bytes: next.map_or(window.len(), |(_, payload)| payload),
                inspected_units: units,
            });
        }
        start = match next {
            Some((_, start)) => start,
            None => return Err(ParameterError::Truncated),
        };
    }
}

fn avc_error(error: AvcError) -> ParameterError {
    match error {
        AvcError::Configuration => ParameterError::Configuration,
        AvcError::Limit => ParameterError::Limit,
        AvcError::Truncated => ParameterError::Truncated,
        AvcError::UnsupportedProfile
        | AvcError::UnsupportedSampleFormat
        | AvcError::UnsupportedSliceGroups
        | AvcError::UnsupportedPicture => ParameterError::Unsupported,
        AvcError::Allocation => ParameterError::Allocation,
        _ => ParameterError::Malformed,
    }
}

fn hevc_error(error: HevcConfigurationError) -> ParameterError {
    match error {
        HevcConfigurationError::Configuration => ParameterError::Configuration,
        HevcConfigurationError::Limit => ParameterError::Limit,
        HevcConfigurationError::Truncated => ParameterError::Truncated,
        HevcConfigurationError::Unsupported => ParameterError::Unsupported,
        HevcConfigurationError::Allocation => ParameterError::Allocation,
        _ => ParameterError::Malformed,
    }
}

#[cfg(test)]
mod tests;
