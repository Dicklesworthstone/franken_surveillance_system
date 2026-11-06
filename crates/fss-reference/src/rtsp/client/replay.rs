#![forbid(unsafe_code)]
//! Closed forward ONVIF replay requests and server acknowledgements.
//!
//! These values describe requested or recorder-asserted time. They never establish
//! camera exposure time, clock calibration, received media coverage, or network authority.

use std::fmt;

/// Maximum requested historical interval in this bounded replay profile: seven days.
/// This does not extend the caller's independent network lease or media/byte budgets.
pub const MAX_REPLAY_DURATION_SECONDS: u64 = 604_800;

const NANOS_PER_SECOND: u128 = 1_000_000_000;
const MAX_RANGE_BYTES: usize = 6 + 26 + 1 + 26;

/// Payload-free syntax, interval, and acknowledgement refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayError {
    /// Expected compact Gregorian UTC in 1970..=9999, with seconds 00..=59 and
    /// at most nine fractional digits. Leap-second interpretation is not inferred.
    Timestamp,
    /// Expected exactly one closed `clock=START-END` interval, without parameters.
    Range,
    /// The end must be strictly after the start.
    WindowOrder,
    /// The interval exceeds the public seven-day ceiling.
    DurationLimit,
    /// A successful replay PLAY did not acknowledge a range.
    MissingRange,
    /// More than one Range response header makes the acknowledgement ambiguous.
    DuplicateRange,
    /// The server would play outside the owner-requested interval.
    WidenedRange,
    /// An optional rate-control or scale echo contradicts the forward replay
    /// profile, is malformed, or appears more than once.
    ResponsePolicy,
    /// A replay acknowledgement must name a nonzero matching request CSeq.
    Correlation,
}
impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RTSP replay refusal: {self:?}")
    }
}
impl std::error::Error for ReplayError {}

/// Specific replay negotiation rejections, without server-controlled reason text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayRejection {
    /// RTSP 456: a requested header does not apply to this resource.
    HeaderNotValidForResource,
    /// RTSP 457: invalid/out-of-bounds range; not proof of upstream retention expiry.
    RangeRejected,
    /// RTSP 551: the required replay option is unsupported.
    OptionNotSupported,
}
impl ReplayRejection {
    /// Exact RTSP status represented by this refusal.
    pub const fn status_code(self) -> u16 {
        match self {
            Self::HeaderNotValidForResource => 456,
            Self::RangeRejected => 457,
            Self::OptionNotSupported => 551,
        }
    }

    pub(super) const fn from_status(status: u16) -> Option<Self> {
        match status {
            456 => Some(Self::HeaderNotValidForResource),
            457 => Some(Self::RangeRejected),
            551 => Some(Self::OptionNotSupported),
            _ => None,
        }
    }
}

/// A validated Gregorian clock coordinate, independent of any trust or clock basis.
/// Parsing accepts `YYYYMMDDThhmmss[.1-9 digits]Z`; rendering trims fractional zeros.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReplayTimestamp {
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    nanosecond: u32,
}
impl ReplayTimestamp {
    /// Parse a bounded compact UTC coordinate. No local timezone, current clock,
    /// calendar normalization, leap-second guess, or ambient input is consulted.
    pub fn parse(value: &str) -> Result<Self, ReplayError> {
        let bytes = value.as_bytes();
        if !(16..=26).contains(&bytes.len())
            || bytes[8] != b'T'
            || bytes.last() != Some(&b'Z')
        {
            return Err(ReplayError::Timestamp);
        }
        let year = decimal(&bytes[..4])? as u16;
        let month = decimal(&bytes[4..6])? as u8;
        let day = decimal(&bytes[6..8])? as u8;
        let hour = decimal(&bytes[9..11])? as u8;
        let minute = decimal(&bytes[11..13])? as u8;
        let second = decimal(&bytes[13..15])? as u8;
        let nanosecond = if bytes.len() == 16 {
            0
        } else {
            if bytes.len() < 18 || bytes[15] != b'.' {
                return Err(ReplayError::Timestamp);
            }
            let fraction = &bytes[16..bytes.len() - 1];
            decimal(fraction)? * 10_u32.pow((9 - fraction.len()) as u32)
        };
        if !(1970..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || day == 0
            || day > month_days(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(ReplayError::Timestamp);
        }
        Ok(Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
            nanosecond,
        })
    }

    /// Exact arithmetic coordinate under this profile's Gregorian, non-leap-second
    /// convention. This is not a conversion from a camera or receive clock.
    pub fn unix_nanoseconds(self) -> u128 {
        let prior_year = u64::from(self.year) - 1;
        let before_year = 365 * prior_year + prior_year / 4 - prior_year / 100 + prior_year / 400;
        // Days through 1969 in the same proleptic Gregorian convention.
        let mut days = before_year - 719_162 + u64::from(self.day - 1);
        for month in 1..self.month {
            days += u64::from(month_days(self.year, month));
        }
        let seconds = ((days * 24 + u64::from(self.hour)) * 60 + u64::from(self.minute))
            * 60
            + u64::from(self.second);
        u128::from(seconds) * NANOS_PER_SECOND + u128::from(self.nanosecond)
    }
}
impl fmt::Display for ReplayTimestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}{:02}{:02}T{:02}{:02}{:02}",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )?;
        if self.nanosecond != 0 {
            let mut fraction = self.nanosecond;
            let mut width = 9;
            while fraction.is_multiple_of(10) {
                fraction /= 10;
                width -= 1;
            }
            write!(f, ".{fraction:0width$}")?;
        }
        f.write_str("Z")
    }
}

/// One nonempty, closed, forward clock request with a maximum seven-day duration.
/// It bounds requested playback, independently of the amount of media actually received.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayWindow {
    start: ReplayTimestamp,
    end: ReplayTimestamp,
}
impl ReplayWindow {
    /// Validate ordering and the public duration ceiling.
    pub fn new(start: ReplayTimestamp, end: ReplayTimestamp) -> Result<Self, ReplayError> {
        if start >= end {
            return Err(ReplayError::WindowOrder);
        }
        let window = Self { start, end };
        if window.duration_ns() > u128::from(MAX_REPLAY_DURATION_SECONDS) * NANOS_PER_SECOND {
            return Err(ReplayError::DurationLimit);
        }
        Ok(window)
    }

    /// Parse two explicit endpoints, suitable for a pure command preview.
    pub fn from_timestamps(start: &str, end: &str) -> Result<Self, ReplayError> {
        Self::new(ReplayTimestamp::parse(start)?, ReplayTimestamp::parse(end)?)
    }

    /// Parse one complete clock Range value. NPT, open intervals, reverse playback,
    /// multiple ranges, scheduling parameters and surrounding whitespace are refused.
    pub fn parse(value: &str) -> Result<Self, ReplayError> {
        if value.len() > MAX_RANGE_BYTES {
            return Err(ReplayError::Range);
        }
        let (unit, endpoints) = value.split_once('=').ok_or(ReplayError::Range)?;
        if !unit.eq_ignore_ascii_case("clock") {
            return Err(ReplayError::Range);
        }
        let (start, end) = endpoints.split_once('-').ok_or(ReplayError::Range)?;
        Self::from_timestamps(start, end)
    }

    /// Requested or acknowledged start coordinate, not observed capture time.
    pub const fn start(self) -> ReplayTimestamp {
        self.start
    }
    /// Requested or acknowledged end coordinate, not evidence of completion.
    pub const fn end(self) -> ReplayTimestamp {
        self.end
    }
    /// Exact endpoint difference under this profile's explicit calendar convention.
    pub fn duration_ns(self) -> u128 {
        self.end.unix_nanoseconds() - self.start.unix_nanoseconds()
    }
    /// Whether every coordinate in the other interval stays within this interval.
    pub fn contains(self, other: Self) -> bool {
        self.start <= other.start && self.end >= other.end
    }
}
impl fmt::Display for ReplayWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "clock={}-{}", self.start, self.end)
    }
}

/// A matching successful PLAY acknowledgement. This records a server assertion,
/// not media continuity, retention inventory, timestamp calibration or completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReplayAcceptance {
    cseq: u32,
    requested: ReplayWindow,
    acknowledged: ReplayWindow,
}
impl ReplayAcceptance {
    /// Validate the correlation coordinate and prevent server-directed widening.
    /// The session separately verifies that CSeq belongs to its pending PLAY.
    pub fn new(
        cseq: u32,
        requested: ReplayWindow,
        acknowledged: ReplayWindow,
    ) -> Result<Self, ReplayError> {
        if cseq == 0 {
            return Err(ReplayError::Correlation);
        }
        if !requested.contains(acknowledged) {
            return Err(ReplayError::WidenedRange);
        }
        Ok(Self {
            cseq,
            requested,
            acknowledged,
        })
    }
    /// Actual successful PLAY correlation, including any authorized Digest retry.
    pub const fn cseq(self) -> u32 {
        self.cseq
    }
    /// Exact normalized owner request.
    pub const fn requested(self) -> ReplayWindow {
        self.requested
    }
    /// Exact normalized server acknowledgement, which may narrow the request.
    pub const fn acknowledged(self) -> ReplayWindow {
        self.acknowledged
    }
}

fn decimal(bytes: &[u8]) -> Result<u32, ReplayError> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(ReplayError::Timestamp);
    }
    Ok(bytes.iter().fold(0, |value, byte| value * 10 + u32::from(byte - b'0')))
}

fn month_days(year: u16, month: u8) -> u8 {
    match month {
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

pub(super) fn validate_response_policy(
    headers: &super::RtspHeaders,
) -> Result<(), ReplayError> {
    let rate_control = super::singleton(headers, "Rate-Control")
        .map_err(|_| ReplayError::ResponsePolicy)?;
    let scale = super::singleton(headers, "Scale").map_err(|_| ReplayError::ResponsePolicy)?;
    // ONVIF does not require these echoes. A present contradictory assertion
    // cannot be treated as acceptance of our unpaced, forward request.
    if rate_control.is_some_and(|value| !value.eq_ignore_ascii_case("no"))
        || scale.is_some_and(|value| !unit_scale(value))
    {
        return Err(ReplayError::ResponsePolicy);
    }
    Ok(())
}

fn unit_scale(value: &str) -> bool {
    // Bounded decimal comparison, never floating-point rounding of values near one.
    if value.len() > 32 {
        return false;
    }
    let value = value.strip_prefix('+').unwrap_or(value);
    let (whole, fraction) = value.split_once('.').map_or((value, None), |(whole, fraction)| {
        (whole, Some(fraction))
    });
    !whole.is_empty()
        && whole.bytes().all(|byte| byte.is_ascii_digit())
        && whole.trim_start_matches('0') == "1"
        && fraction.is_none_or(|digits| digits.bytes().all(|byte| byte == b'0'))
}
