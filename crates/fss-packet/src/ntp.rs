#![forbid(unsafe_code)]
//! Bounded basic-mode SNTPv4 evidence from one supplied request/reply exchange.
//!
//! RFC 5905 sections 7–8 define the fixed header and four-timestamp arithmetic.
//! This narrow profile accepts only an exact 48-byte basic-mode server response:
//! RFC 7822 extensions, MAC/NTS authentication and RFC 9769 interleaved modes are
//! unsupported. The I/O owner must select and approve its endpoint, use an
//! ephemeral client port (RFC 9109), bind one response to one request, record the
//! original bytes, and prove its local clock did not step during the exchange.
//!
//! For nonnegative one-way delay, the server-minus-local offset lies between
//! `T3 - T4` and `T2 - T1`, equivalently the RFC offset plus/minus half the
//! measured round-trip delay. Local sampling brackets and fixed-point rounding
//! widen those bounds. The result also includes the server's asserted root
//! delay/dispersion, precision and the RFC's nominal 15 ppm exchange growth.
//! None of these untrusted fields authenticates a server or certifies UTC.
//! Actual oscillator bounds, freshness/holdover, leap-second handling and
//! clock-generation validity remain with the owning host-clock contract.
//! The caller's era hint must already be within half an NTP era (about 68 years)
//! of the server; an unauthenticated 32-bit seconds field cannot prove its era.
//!
//! This module performs no I/O, clock adjustment, allocation or retry.

use std::fmt;

use crate::NtpTimestamp;

/// Exact header size admitted by this basic-mode profile.
pub const PACKET_BYTES: usize = 48;
/// Maximum admitted local exchange duration in this bounded local-daemon profile.
pub const MAX_EXCHANGE_NS: u64 = 1_000_000_000;
/// Maximum absolute midpoint correction supported by this profile.
pub const MAX_OFFSET_NS: u64 = 10_000_000_000;
/// Maximum conservative uncertainty radius supported by this profile.
pub const MAX_UNCERTAINTY_NS: u64 = 10_000_000_000;
/// Nominal disciplined-clock dispersion growth in RFC 5905, not a measured bound.
pub const NOMINAL_FREQUENCY_TOLERANCE_PPM: u64 = 15;

const NS_PER_SECOND: i128 = 1_000_000_000;
const FRACTION_SCALE: i128 = 1_i128 << 32;
const ERA_SECONDS: i128 = 1_i128 << 32;
const NTP_UNIX_EPOCH_SECONDS: i128 = 2_208_988_800;

/// Inclusive local Unix-time bracket supplied by the authorized clock owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixTimeInterval {
    /// Earliest possible local reading, in nanoseconds since the Unix epoch.
    pub earliest_ns: u64,
    /// Latest possible local reading, in nanoseconds since the Unix epoch.
    pub latest_ns: u64,
}

/// Brackets enclosing request transmission and response reception.
///
/// These use the same local Unix-clock generation. They are not camera clocks or
/// externally corrected UTC. The owner must reject local wall-clock steps using
/// its independent monotonic samples before supplying these brackets.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalExchange {
    /// Request transmission bracket, including the original request timestamp.
    pub sent: UnixTimeInterval,
    /// Response reception bracket, following the complete transmission bracket.
    pub received: UnixTimeInterval,
}

/// Inclusive signed interval for server time minus local time, in nanoseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OffsetInterval {
    /// Conservative lower endpoint.
    pub lower_ns: i64,
    /// Conservative upper endpoint.
    pub upper_ns: i64,
}

/// Inclusive nonnegative duration interval, in nanoseconds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DurationInterval {
    /// Conservative lower endpoint.
    pub lower_ns: u64,
    /// Conservative upper endpoint.
    pub upper_ns: u64,
}

/// Explicit caller-selected bounds; each may narrow, but not widen, this profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SntpLimits {
    /// Largest complete local exchange bracket, at most [`MAX_EXCHANGE_NS`].
    pub max_exchange_ns: u64,
    /// Largest absolute midpoint correction, at most [`MAX_OFFSET_NS`].
    pub max_offset_ns: u64,
    /// Largest containing radius, at most [`MAX_UNCERTAINTY_NS`].
    pub max_uncertainty_ns: u64,
}

/// Payload-free refusal; packet strings and endpoint identities are never logged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SntpError {
    /// A caller limit is zero or exceeds this bounded profile.
    Limits,
    /// A datagram is truncated or carries unsupported trailing bytes.
    Length,
    /// Only version 4 is admitted; no implicit downgrade is allowed.
    Version,
    /// Only a basic-mode server reply is admitted.
    Mode,
    /// The server advertises an unsynchronized clock or invalid stratum.
    Unsynchronized,
    /// Stratum zero, including Kiss-o'-Death responses, supplies no time sample.
    KissOfDeath,
    /// Origin does not exactly equal the request's complete transmit timestamp.
    Origin,
    /// An admitted timestamp is the reserved all-zero value.
    ZeroTimestamp,
    /// Era unfolding is ambiguous or cannot produce nonnegative Unix nanoseconds.
    Era,
    /// Local brackets are reversed, overlap, or do not contain the request stamp.
    LocalTime,
    /// The complete measured exchange exceeds its explicit bound.
    ExchangeLimit,
    /// Remote timestamp order or processing duration is impossible for this exchange.
    Timing,
    /// Root delay is negative; this profile cannot treat it as an error bound.
    RootDelay,
    /// The conservative uncertainty cannot fit the caller's bound.
    Uncertainty,
    /// The required midpoint correction exceeds the caller's bound.
    Offset,
}

impl fmt::Display for SntpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Limits => "SNTP limits outside bounded profile",
            Self::Length => "SNTP requires an exact basic-mode header",
            Self::Version => "SNTP response version unsupported",
            Self::Mode => "SNTP response mode unsupported",
            Self::Unsynchronized => "SNTP server reports no synchronized time",
            Self::KissOfDeath => "SNTP stratum-zero response supplies no time",
            Self::Origin => "SNTP response does not match request",
            Self::ZeroTimestamp => "SNTP timestamp is unspecified",
            Self::Era => "SNTP era cannot be resolved within supplied time basis",
            Self::LocalTime => "SNTP local time brackets are inconsistent",
            Self::ExchangeLimit => "SNTP exchange duration exceeds limit",
            Self::Timing => "SNTP timestamp order or delay is inconsistent",
            Self::RootDelay => "SNTP negative root delay unsupported",
            Self::Uncertainty => "SNTP uncertainty exceeds limit",
            Self::Offset => "SNTP correction exceeds limit",
        })
    }
}

impl std::error::Error for SntpError {}

/// One immutable request. Evaluation is pure; one-use/replay ownership is external.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SntpRequest {
    bytes: [u8; PACKET_BYTES],
    transmit_unix_ns: u64,
    transmit: NtpTimestamp,
}

/// Conservative server-asserted measurement, never an authenticated clock certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SntpObservation {
    /// Complete server-minus-local interval including the stated error allowances.
    pub offset_interval_ns: OffsetInterval,
    /// Integer midpoint of the interval, rounded toward its lower endpoint.
    pub offset_ns: i64,
    /// Radius enclosing both endpoints around `offset_ns`; always at least one ns.
    pub uncertainty_ns: u64,
    /// Measured local elapsed time minus server processing time, outward rounded.
    pub network_round_trip_ns: DurationInterval,
    /// Complete elapsed time allowed by the caller's transmission/reception brackets.
    pub local_elapsed_ns: DurationInterval,
    /// Server-asserted time between receiving the request and transmitting the reply.
    pub server_processing_ns: DurationInterval,
    /// Nonnegative server root round-trip delay, rounded up to nanoseconds.
    pub root_delay_ns: u64,
    /// Server root dispersion, rounded up to nanoseconds.
    pub root_dispersion_ns: u64,
    /// Server precision `2^precision_log2` seconds, rounded up to at least one ns.
    pub server_precision_ns: u64,
    /// Nominal 15 ppm allowance across the maximum local elapsed time.
    pub frequency_tolerance_ns: u64,
    /// Server leap indication, preserving announced positive or negative leap seconds.
    pub leap_indicator: u8,
    /// Server stratum in the admitted range 1 through 15.
    pub stratum: u8,
    /// Original server poll exponent; the owner must not infer a retry schedule.
    pub poll_log2: i8,
    /// Original server clock precision exponent.
    pub precision_log2: i8,
    /// Opaque reference identifier; never interpreted as executable text or authority.
    pub reference_id: [u8; 4],
    /// Exact wire reference timestamp.
    pub reference_timestamp: NtpTimestamp,
    /// Exact wire request-receive timestamp.
    pub receive_timestamp: NtpTimestamp,
    /// Exact wire response-transmit timestamp.
    pub transmit_timestamp: NtpTimestamp,
    /// Reference timestamp unfolded against the request's local era hint.
    pub reference_unix_ns: UnixTimeInterval,
    /// Request-receive timestamp unfolded against the same era hint.
    pub receive_unix_ns: UnixTimeInterval,
    /// Response-transmit timestamp unfolded against the same era hint.
    pub transmit_unix_ns: UnixTimeInterval,
}

impl SntpRequest {
    /// Construct one fixed-size version-4 client request from a local Unix reading.
    ///
    /// The unquantized reading remains the explicit era hint and must be inside
    /// the send bracket supplied to evaluation. The wire fraction is truncated
    /// at 2^-32 seconds. A reserved all-zero wire timestamp is refused rather than
    /// silently shifted. Other request fields are zero and grant no time quality.
    pub fn new(transmit_unix_ns: u64) -> Result<Self, SntpError> {
        let seconds = i128::from(transmit_unix_ns) / NS_PER_SECOND + NTP_UNIX_EPOCH_SECONDS;
        let fraction =
            (i128::from(transmit_unix_ns) % NS_PER_SECOND) * FRACTION_SCALE / NS_PER_SECOND;
        let transmit = NtpTimestamp {
            seconds: (seconds % ERA_SECONDS) as u32,
            fraction: fraction as u32,
        };
        nonzero(transmit)?;
        let mut bytes = [0_u8; PACKET_BYTES];
        bytes[0] = (4 << 3) | 3;
        bytes[40..44].copy_from_slice(&transmit.seconds.to_be_bytes());
        bytes[44..48].copy_from_slice(&transmit.fraction.to_be_bytes());
        Ok(Self {
            bytes,
            transmit_unix_ns,
            transmit,
        })
    }

    /// Exact bytes to send and retain; no caller-provided extension is appended.
    pub const fn wire_bytes(&self) -> &[u8; PACKET_BYTES] {
        &self.bytes
    }

    /// Exact wire origin expected in the single response.
    pub const fn transmit_timestamp(&self) -> NtpTimestamp {
        self.transmit
    }

    /// Validate a complete supplied reply and derive one conservative interval.
    ///
    /// No state is advanced, no error is clamped into success, and no prior reply
    /// can be consumed implicitly. Endpoints and byte provenance belong to the
    /// I/O owner. In addition to unsynchronized replies, this strict profile
    /// refuses negative root delay and server processing longer than the full
    /// local bracket, even though broader NTP implementations may filter such
    /// clock-rate artifacts over multiple observations.
    pub fn evaluate_reply(
        &self,
        reply: &[u8],
        times: LocalExchange,
        limits: SntpLimits,
    ) -> Result<SntpObservation, SntpError> {
        validate_limits(limits)?;
        let local_elapsed_ns = validate_local(self.transmit_unix_ns, times, limits)?;
        if reply.len() != PACKET_BYTES {
            return Err(SntpError::Length);
        }
        if (reply[0] >> 3) & 7 != 4 {
            return Err(SntpError::Version);
        }
        if reply[0] & 7 != 4 {
            return Err(SntpError::Mode);
        }
        if reply[1] == 0 {
            return Err(SntpError::KissOfDeath);
        }
        let leap_indicator = reply[0] >> 6;
        if leap_indicator == 3 || reply[1] >= 16 {
            return Err(SntpError::Unsynchronized);
        }
        if timestamp(reply, 24) != self.transmit {
            return Err(SntpError::Origin);
        }
        let root_delay = word(reply, 4);
        if root_delay & 0x8000_0000 != 0 {
            return Err(SntpError::RootDelay);
        }
        let root_delay_ns = short_up(root_delay);
        let root_dispersion_ns = short_up(word(reply, 8));
        let precision_log2 = reply[3] as i8;
        let server_precision_ns = precision_up(precision_log2)?;
        let reference_timestamp = timestamp(reply, 16);
        let receive_timestamp = timestamp(reply, 32);
        let transmit_timestamp = timestamp(reply, 40);
        let reference = unfold(reference_timestamp, self.transmit_unix_ns)?;
        let receive = unfold(receive_timestamp, self.transmit_unix_ns)?;
        let transmit = unfold(transmit_timestamp, self.transmit_unix_ns)?;
        if transmit.ticks < receive.ticks || reference.ticks > transmit.ticks {
            return Err(SntpError::Timing);
        }
        let processing_ticks = transmit.ticks - receive.ticks;
        if processing_ticks * NS_PER_SECOND > i128::from(local_elapsed_ns.upper_ns) * FRACTION_SCALE
        {
            return Err(SntpError::Timing);
        }
        let server_processing_ns = duration_from_ticks(processing_ticks);
        let network_round_trip_ns = DurationInterval {
            lower_ns: local_elapsed_ns
                .lower_ns
                .saturating_sub(server_processing_ns.upper_ns),
            upper_ns: local_elapsed_ns.upper_ns - server_processing_ns.lower_ns,
        };
        let frequency_tolerance_ns =
            (local_elapsed_ns.upper_ns * NOMINAL_FREQUENCY_TOLERANCE_PPM).div_ceil(1_000_000);
        let allowance = i128::from(root_delay_ns.div_ceil(2))
            + i128::from(root_dispersion_ns)
            + i128::from(server_precision_ns)
            + i128::from(frequency_tolerance_ns);
        // Feasible asymmetric path delay, without a symmetric-delay assumption.
        // Fixed-point timestamps are rounded outwards before signed subtraction.
        let lower =
            i128::from(transmit.ns.earliest_ns) - i128::from(times.received.latest_ns) - allowance;
        let upper =
            i128::from(receive.ns.latest_ns) - i128::from(times.sent.earliest_ns) + allowance;
        if lower > upper {
            return Err(SntpError::Timing);
        }
        let midpoint = (lower + upper).div_euclid(2);
        let uncertainty = (midpoint - lower).max(upper - midpoint).max(1);
        if uncertainty > i128::from(limits.max_uncertainty_ns) {
            return Err(SntpError::Uncertainty);
        }
        if midpoint.abs() > i128::from(limits.max_offset_ns) {
            return Err(SntpError::Offset);
        }
        Ok(SntpObservation {
            offset_interval_ns: OffsetInterval {
                // Limits cap midpoint and radius at 10 s, so both fit i64.
                lower_ns: lower as i64,
                upper_ns: upper as i64,
            },
            offset_ns: midpoint as i64,
            uncertainty_ns: uncertainty as u64,
            network_round_trip_ns,
            local_elapsed_ns,
            server_processing_ns,
            root_delay_ns,
            root_dispersion_ns,
            server_precision_ns,
            frequency_tolerance_ns,
            leap_indicator,
            stratum: reply[1],
            poll_log2: reply[2] as i8,
            precision_log2,
            reference_id: [reply[12], reply[13], reply[14], reply[15]],
            reference_timestamp,
            receive_timestamp,
            transmit_timestamp,
            reference_unix_ns: reference.ns,
            receive_unix_ns: receive.ns,
            transmit_unix_ns: transmit.ns,
        })
    }
}

fn validate_limits(limits: SntpLimits) -> Result<(), SntpError> {
    if limits.max_exchange_ns == 0
        || limits.max_exchange_ns > MAX_EXCHANGE_NS
        || limits.max_offset_ns == 0
        || limits.max_offset_ns > MAX_OFFSET_NS
        || limits.max_uncertainty_ns == 0
        || limits.max_uncertainty_ns > MAX_UNCERTAINTY_NS
    {
        return Err(SntpError::Limits);
    }
    Ok(())
}

fn validate_local(
    request_unix_ns: u64,
    times: LocalExchange,
    limits: SntpLimits,
) -> Result<DurationInterval, SntpError> {
    if times.sent.earliest_ns > request_unix_ns
        || times.sent.latest_ns < request_unix_ns
        || times.received.earliest_ns > times.received.latest_ns
        || times.sent.latest_ns > times.received.earliest_ns
    {
        return Err(SntpError::LocalTime);
    }
    let elapsed = DurationInterval {
        lower_ns: times.received.earliest_ns - times.sent.latest_ns,
        upper_ns: times.received.latest_ns - times.sent.earliest_ns,
    };
    if elapsed.upper_ns > limits.max_exchange_ns {
        return Err(SntpError::ExchangeLimit);
    }
    Ok(elapsed)
}

fn nonzero(value: NtpTimestamp) -> Result<(), SntpError> {
    if value.seconds == 0 && value.fraction == 0 {
        return Err(SntpError::ZeroTimestamp);
    }
    Ok(())
}

fn word(bytes: &[u8], position: usize) -> u32 {
    u32::from_be_bytes([
        bytes[position],
        bytes[position + 1],
        bytes[position + 2],
        bytes[position + 3],
    ])
}

fn timestamp(bytes: &[u8], position: usize) -> NtpTimestamp {
    NtpTimestamp {
        seconds: word(bytes, position),
        fraction: word(bytes, position + 4),
    }
}

fn short_up(value: u32) -> u64 {
    (u64::from(value) * 1_000_000_000).div_ceil(1_u64 << 16)
}

fn precision_up(exponent: i8) -> Result<u64, SntpError> {
    if exponent <= -30 {
        return Ok(1);
    }
    if exponent < 0 {
        return Ok(1_000_000_000_u64.div_ceil(1_u64 << (-i16::from(exponent) as u32)));
    }
    if exponent > 3 {
        // 2^4 seconds already exceeds the entire ten-second uncertainty profile.
        // Check the exponent before shifting; checked_shl alone does not detect
        // significant bits shifted out of an integer's most-significant end.
        return Err(SntpError::Uncertainty);
    }
    Ok(1_000_000_000_u64 << exponent as u32)
}

struct Unfolded {
    ticks: i128,
    ns: UnixTimeInterval,
}

fn unfold(value: NtpTimestamp, hint_unix_ns: u64) -> Result<Unfolded, SntpError> {
    nonzero(value)?;
    let hint_ntp_ns = i128::from(hint_unix_ns) + NTP_UNIX_EPOCH_SECONDS * NS_PER_SECOND;
    let hint_scaled = hint_ntp_ns * FRACTION_SCALE;
    let hint_era = hint_ntp_ns / (ERA_SECONDS * NS_PER_SECOND);
    let mut nearest = None;
    let mut distance = i128::MAX;
    let mut ambiguous = false;
    for era in (hint_era - 1)..=(hint_era + 1) {
        let ticks = (era * ERA_SECONDS + i128::from(value.seconds)) * FRACTION_SCALE
            + i128::from(value.fraction);
        let candidate_distance = (ticks * NS_PER_SECOND - hint_scaled).abs();
        if candidate_distance < distance {
            nearest = Some(ticks);
            distance = candidate_distance;
            ambiguous = false;
        } else if candidate_distance == distance {
            ambiguous = true;
        }
    }
    if ambiguous {
        return Err(SntpError::Era);
    }
    let ticks = nearest.ok_or(SntpError::Era)? - NTP_UNIX_EPOCH_SECONDS * FRACTION_SCALE;
    if ticks < 0 {
        return Err(SntpError::Era);
    }
    let lower = ticks * NS_PER_SECOND / FRACTION_SCALE;
    let upper = (ticks * NS_PER_SECOND + FRACTION_SCALE - 1) / FRACTION_SCALE;
    if upper > i128::from(u64::MAX) {
        return Err(SntpError::Era);
    }
    Ok(Unfolded {
        ticks,
        ns: UnixTimeInterval {
            earliest_ns: lower as u64,
            latest_ns: upper as u64,
        },
    })
}

fn duration_from_ticks(ticks: i128) -> DurationInterval {
    // The caller has proved this duration lies within the one-second exchange.
    let numerator = ticks * NS_PER_SECOND;
    DurationInterval {
        lower_ns: (numerator / FRACTION_SCALE) as u64,
        upper_ns: ((numerator + FRACTION_SCALE - 1) / FRACTION_SCALE) as u64,
    }
}
