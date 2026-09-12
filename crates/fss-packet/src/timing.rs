use crate::{ContinuityError, SenderReport, StreamKey};

/// Integer RFC 3550 A.8 jitter estimator in explicitly negotiated RTP clock units.
///
/// Arrival ticks are supplied by the owner, not read from a wall clock. Out-of-order
/// media timestamps are allowed. An ambiguous half-cycle gap is refused atomically.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct JitterEstimator {
    previous: Option<(u64, u32)>,
    scaled: u64,
}

impl JitterEstimator {
    /// Current jitter in RTP clock ticks, rounded down as specified by the integer oracle.
    pub fn ticks(self) -> u32 {
        (self.scaled >> 4) as u32
    }

    /// Observe arrivals in arrival order, including accepted duplicates/reordered packets.
    pub fn observe(&mut self, arrival_ticks: u64, timestamp: u32) -> Result<u32, ContinuityError> {
        if let Some((previous_arrival, previous_timestamp)) = self.previous {
            let arrival_delta = arrival_ticks.checked_sub(previous_arrival).ok_or(ContinuityError::ClockReversed)?;
            let raw_delta = timestamp.wrapping_sub(previous_timestamp);
            if arrival_delta >= 0x8000_0000 || raw_delta == 0x8000_0000 {
                return Err(ContinuityError::ClockAmbiguous);
            }
            let variation = (arrival_delta as i64 - i64::from(raw_delta as i32)).unsigned_abs();
            self.scaled = self.scaled + variation - ((self.scaled + 8) >> 4);
        }
        self.previous = Some((arrival_ticks, timestamp));
        Ok(self.ticks())
    }
}

/// Convert monotonic nanoseconds to negotiated RTP ticks without floating point or overflow.
pub fn arrival_ticks(monotonic_ns: u64, clock_rate: u32) -> Result<u64, ContinuityError> {
    if clock_rate == 0 || clock_rate > 1_000_000_000 {
        return Err(ContinuityError::Configuration);
    }
    let ticks = u128::from(monotonic_ns) * u128::from(clock_rate) / 1_000_000_000;
    u64::try_from(ticks).map_err(|_| ContinuityError::Exhausted)
}

/// An asserted sender-clock interval, explicitly not an authenticated capture-time interval.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderTimeEstimate {
    /// Earliest sender NTP time in nanoseconds relative to its unguessed era.
    pub earliest_ntp_ns: i128,
    /// Latest sender NTP time in nanoseconds relative to the same unguessed era.
    pub latest_ntp_ns: i128,
    /// Owner stream key that prevents reuse across source resets.
    pub key: StreamKey,
}

/// One source-bound sender-report observation with caller-supplied uncertainty/validity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SenderReportClock {
    key: StreamKey,
    rate: u32,
    report: SenderReport,
    received_ns: u64,
    uncertainty_ns: u64,
    max_distance_ticks: u32,
}

impl SenderReportClock {
    /// Bind a parsed report to an exact owner epoch, without guessing clock trust or NTP era.
    pub fn new(
        key: StreamKey,
        rate: u32,
        report: SenderReport,
        received_ns: u64,
        uncertainty_ns: u64,
        max_distance_ticks: u32,
    ) -> Result<Self, ContinuityError> {
        if key.ingress == 0 || key.generation == 0 || rate == 0 || rate > 1_000_000_000
            || max_distance_ticks == 0 || max_distance_ticks >= 0x8000_0000
        {
            return Err(ContinuityError::Configuration);
        }
        if report.ssrc != key.ssrc {
            return Err(ContinuityError::StreamMismatch);
        }
        if report.ntp.seconds == 0 && report.ntp.fraction == 0 {
            return Err(ContinuityError::NoSenderReport);
        }
        Ok(Self { key, rate, report, received_ns, uncertainty_ns, max_distance_ticks })
    }

    /// Map a nearby timestamp to a conservative sender assertion, not physical capture truth.
    ///
    /// The owner must include drift/measurement uncertainty in `uncertainty_ns` and choose
    /// a distance ceiling justified by its clock model. Unsupported extrapolation is refused.
    pub fn estimate(&self, key: StreamKey, timestamp: u32) -> Result<SenderTimeEstimate, ContinuityError> {
        if key != self.key {
            return Err(ContinuityError::StreamMismatch);
        }
        let raw = timestamp.wrapping_sub(self.report.rtp_timestamp);
        if raw == 0x8000_0000 {
            return Err(ContinuityError::ClockAmbiguous);
        }
        let delta = raw as i32;
        if delta.unsigned_abs() > self.max_distance_ticks {
            return Err(ContinuityError::ClockAmbiguous);
        }
        let fraction = i128::from(self.report.ntp.fraction) * 1_000_000_000;
        let ntp_floor = i128::from(self.report.ntp.seconds) * 1_000_000_000 + fraction / (1_i128 << 32);
        let numerator = i128::from(delta) * 1_000_000_000;
        let rate = i128::from(self.rate);
        let offset_floor = numerator.div_euclid(rate);
        let offset_ceil = offset_floor + i128::from(numerator.rem_euclid(rate) != 0);
        Ok(SenderTimeEstimate {
            earliest_ntp_ns: ntp_floor + offset_floor - i128::from(self.uncertainty_ns),
            latest_ntp_ns: ntp_floor + 1 + offset_ceil + i128::from(self.uncertainty_ns),
            key,
        })
    }

    /// LSR and DLSR fields for a later report, refusing unrepresentable elapsed time.
    pub fn report_delay(&self, now_ns: u64) -> Result<(u32, u32), ContinuityError> {
        let elapsed = now_ns.checked_sub(self.received_ns).ok_or(ContinuityError::ClockReversed)?;
        let delay = u128::from(elapsed) * 65_536 / 1_000_000_000;
        let delay = u32::try_from(delay).map_err(|_| ContinuityError::ClockAmbiguous)?;
        Ok((self.report.ntp.middle_32(), delay))
    }
}
