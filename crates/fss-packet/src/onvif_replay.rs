#![forbid(unsafe_code)]
//! Bounded interpretation of ONVIF recorded-RTP timestamp assertions.
//!
//! ONVIF Streaming Specification 26.06 sections 6.3 and 6.3.1 assign the 0xABAC
//! header extension to an access unit's original frame-grabber NTP timestamp,
//! replay flags and the low byte of PLAY CSeq. The first packet of each access
//! unit must carry the extension; subsequent packets may omit it. The owning
//! source-to-sample verifier checks that placement and any repeated assertions.
//!
//! This module accepts the fixed three-word AVC/HEVC extension only. The combined
//! JPEG extension from section 6.3.2 is a separate unsupported profile. Reserved
//! bits must be zero; the final two padding octets have no interpreted value.
//! Exact padding remains in the caller's retained original datagram.
//!
//! RFC 5905 section 6 requires an external NTP-era basis and treats a zero raw
//! timestamp as unknown or unsynchronized. Era selection is therefore explicit:
//! requested replay UTC, receive time, RTP timestamps and RTCP sender reports
//! never supply it here. In particular, ONVIF section 6.11 gives replay RTCP
//! sender reports no historical capture-time meaning.
//!
//! Returned UTC intervals bound integer rounding of a device assertion only.
//! They do not bound the device's clock error, authenticate the frame grabber,
//! prove frame completeness, or establish recording coverage.
//!
//! Primary contracts:
//! https://www.onvif.org/specs/stream/ONVIF-Streaming-Spec.pdf
//! https://www.rfc-editor.org/rfc/rfc5905#section-6

use std::fmt;

use crate::{HeaderExtension, NtpTimestamp};

/// ONVIF recorded-media RTP extension profile, independent of the payload codec.
pub const REPLAY_EXTENSION_PROFILE: u16 = 0xABAC;
/// Fixed AVC/HEVC extension content length, excluding the four-byte preamble.
pub const REPLAY_EXTENSION_BYTES: usize = 12;
/// Last representable integer nanosecond in the bounded Gregorian UTC profile.
pub const MAX_RECORDED_UTC_NS: i128 = 253_402_300_799_999_999_999;

const NTP_UNIX_EPOCH_SECONDS: i128 = 2_208_988_800;
const ERA_SECONDS: i128 = 1_i128 << 32;
const FRACTION_SCALE: i128 = 1_i128 << 32;
const NANOS_PER_SECOND: i128 = 1_000_000_000;

/// Payload-free protocol and conversion refusals; no wire bytes enter errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayExtensionError {
    /// The known profile is truncated or includes an unsupported extension tail.
    Length,
    /// At least one of the four must-be-zero flag bits is nonzero.
    ReservedBits,
    /// The raw NTP timestamp is the protocol's unknown/unsynchronized value.
    UnknownTimestamp,
    /// The explicitly supplied era produces UTC outside 1970 through 9999.
    UtcRange,
    /// A full PLAY correlation coordinate must be nonzero.
    InvalidPlayCseq,
    /// The extension differs from the supplied PLAY coordinate's low byte.
    PlayCseqMismatch,
}

impl ReplayExtensionError {
    /// Stable reason tag for bounded machine reports, without source payload.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Length => "ERR-RTP-REPLAY-EXTENSION-LENGTH-001",
            Self::ReservedBits => "ERR-RTP-REPLAY-RESERVED-001",
            Self::UnknownTimestamp => "ERR-RTP-REPLAY-TIME-UNKNOWN-001",
            Self::UtcRange => "ERR-RTP-REPLAY-UTC-RANGE-001",
            Self::InvalidPlayCseq => "ERR-RTP-REPLAY-CSEQ-INVALID-001",
            Self::PlayCseqMismatch => "ERR-RTP-REPLAY-CSEQ-MISMATCH-001",
        }
    }
}

impl fmt::Display for ReplayExtensionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for ReplayExtensionError {}

/// Numeric projection of one device-advertised historical time.
/// The interval accounts only for outward rounding of the exact NTP fraction;
/// physical capture-time accuracy and device-clock calibration remain unknown.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordedUtcInterval {
    /// Floor of the asserted UTC value in nanoseconds since 1970-01-01.
    pub earliest_ns: i128,
    /// Ceiling of that same value; differs from the floor by at most one.
    pub latest_ns: i128,
}

/// Exact semantic fields of an ONVIF recorded-RTP extension.
/// None of the flags substitutes for native codec parsing or source custody.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayHeaderExtension {
    /// Original NTP seconds and fraction, before external era interpretation.
    pub ntp: NtpTimestamp,
    /// C: the device labels this access unit a synchronization/clean point.
    pub clean_point: bool,
    /// E: the device labels this access unit the end of a contiguous section.
    pub end_of_contiguous_section: bool,
    /// D: the device reports a discontinuity before this access unit.
    pub discontinuity: bool,
    /// T: the device labels this the terminal access unit of the track.
    pub terminal: bool,
    /// Only the low-order byte of the PLAY command's sequence coordinate.
    pub cseq_low: u8,
}

/// Parse a length-validated RTP extension without allocation or I/O.
///
/// A foreign profile returns None, so unrelated extensions cannot become
/// historical time. A malformed known profile returns an error. Raw-zero NTP
/// remains a parsed assertion so its flags and CSeq are retained; conversion
/// reports UnknownTimestamp instead of inventing an epoch.
pub fn parse_replay_extension(
    extension: HeaderExtension<'_>,
) -> Result<Option<ReplayHeaderExtension>, ReplayExtensionError> {
    if extension.profile != REPLAY_EXTENSION_PROFILE {
        return Ok(None);
    }
    let bytes = extension.bytes;
    if bytes.len() != REPLAY_EXTENSION_BYTES {
        return Err(ReplayExtensionError::Length);
    }
    let flags = bytes[8];
    if flags & 0x0F != 0 {
        return Err(ReplayExtensionError::ReservedBits);
    }
    Ok(Some(ReplayHeaderExtension {
        ntp: NtpTimestamp {
            seconds: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            fraction: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        },
        clean_point: flags & 0x80 != 0,
        end_of_contiguous_section: flags & 0x40 != 0,
        discontinuity: flags & 0x20 != 0,
        terminal: flags & 0x10 != 0,
        cseq_low: bytes[9],
    }))
}

impl ReplayHeaderExtension {
    /// Check the low-byte relation to the actual successful PLAY CSeq.
    ///
    /// Success is compatible with every full sequence differing by 256. This
    /// check cannot establish a full PLAY identity, freshness or authenticity.
    /// The caller must retain its separately verified receipt/session binding.
    pub fn correlate_play(self, full_cseq: u32) -> Result<(), ReplayExtensionError> {
        if full_cseq == 0 {
            return Err(ReplayExtensionError::InvalidPlayCseq);
        }
        if self.cseq_low != (full_cseq & 0xFF) as u8 {
            return Err(ReplayExtensionError::PlayCseqMismatch);
        }
        Ok(())
    }

    /// Interpret the exact NTP value in one explicitly supplied external era.
    ///
    /// No era guessing or wrap inference occurs. An owner interpreting footage
    /// across an era boundary must provide the correct era for each assertion.
    /// The 32-bit fraction is scaled with integer floor/ceiling, never truncated
    /// into an unjustifiably exact nanosecond. The admitted range matches the
    /// project's bounded 1970-9999 UTC profile, including both rounded endpoints.
    pub fn utc_for_era(self, era: u32) -> Result<RecordedUtcInterval, ReplayExtensionError> {
        if self.ntp.seconds == 0 && self.ntp.fraction == 0 {
            return Err(ReplayExtensionError::UnknownTimestamp);
        }
        // A u32 era and u32 offset fit in u64 seconds; multiplication by 1e9
        // remains far below i128's ceiling. No ambient clock participates.
        let seconds =
            i128::from(era) * ERA_SECONDS + i128::from(self.ntp.seconds) - NTP_UNIX_EPOCH_SECONDS;
        let numerator = i128::from(self.ntp.fraction) * NANOS_PER_SECOND;
        let earliest_ns = seconds * NANOS_PER_SECOND + numerator / FRACTION_SCALE;
        let latest_ns =
            seconds * NANOS_PER_SECOND + (numerator + FRACTION_SCALE - 1) / FRACTION_SCALE;
        if earliest_ns < 0 || latest_ns > MAX_RECORDED_UTC_NS {
            return Err(ReplayExtensionError::UtcRange);
        }
        Ok(RecordedUtcInterval {
            earliest_ns,
            latest_ns,
        })
    }
}
