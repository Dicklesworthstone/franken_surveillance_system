#![forbid(unsafe_code)]
//! Bounded Device UTC observation for authentication freshness only.

use std::fmt;

use super::{
    DEVICE_NS, OnvifOperation, SCHEMA_NS, SoapRequest, WireError, request, required, response,
    scalar, xml,
};

const SECONDS_PER_DAY: u64 = 86_400;
const MAX_UTC_SECONDS: u64 = 253_402_300_799; // 9999-12-31T23:59:59Z

/// Valid Gregorian UTC in the bounded 1970–9999 interoperability range. This
/// value carries no clock trust or capture-time authority. Leap seconds are
/// refused rather than assigned an inferred monotonic mapping.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct UtcDateTime {
    seconds: u64,
}

impl UtcDateTime {
    /// Validate numeric Device UTC fields without consulting any ambient clock.
    pub fn new(
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
    ) -> Result<Self, WireError> {
        if !(1970..=9999).contains(&year)
            || !(1..=12).contains(&month)
            || day == 0
            || day > month_days(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(WireError::InvalidField);
        }
        let mut days = days_before_year(year) - days_before_year(1970);
        for preceding in 1..month {
            days += u64::from(month_days(year, preceding));
        }
        days += u64::from(day - 1);
        Ok(Self {
            seconds: days * SECONDS_PER_DAY
                + u64::from(hour) * 3600
                + u64::from(minute) * 60
                + u64::from(second),
        })
    }

    /// Advance only by an explicitly supplied elapsed duration, refusing
    /// overflow or dates outside the supported range without clamping.
    pub fn checked_add_seconds(self, seconds: u64) -> Result<Self, WireError> {
        let seconds = self
            .seconds
            .checked_add(seconds)
            .ok_or(WireError::InvalidField)?;
        if seconds > MAX_UTC_SECONDS {
            return Err(WireError::InvalidField);
        }
        Ok(Self { seconds })
    }

    /// Exact Created lexical form used in both the digest preimage and SOAP.
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        let days = self.seconds / SECONDS_PER_DAY;
        let day_seconds = self.seconds % SECONDS_PER_DAY;
        // At most thirteen iterations over 8030 years.
        let mut low = 1970_u16;
        let mut high = 10_000_u16;
        while low + 1 < high {
            let year = low + (high - low) / 2;
            if days_before_year(year) - days_before_year(1970) <= days {
                low = year;
            } else {
                high = year;
            }
        }
        let mut day = days - (days_before_year(low) - days_before_year(1970));
        let mut month = 1_u8;
        while day >= u64::from(month_days(low, month)) {
            day -= u64::from(month_days(low, month));
            month += 1;
        }
        format!(
            "{low:04}-{month:02}-{:02}T{:02}:{:02}:{:02}Z",
            day + 1,
            day_seconds / 3600,
            day_seconds / 60 % 60,
            day_seconds % 60,
        )
    }
}

impl fmt::Debug for UtcDateTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("UtcDateTime([authentication freshness only])")
    }
}

const fn days_before_year(year: u16) -> u64 {
    let preceding = year as u64 - 1;
    preceding * 365 + preceding / 4 - preceding / 100 + preceding / 400
}

const fn month_days(year: u16, month: u8) -> u8 {
    match month {
        4 | 6 | 9 | 11 => 30,
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 31,
    }
}

/// ONVIF Core's PRE_AUTH time read. No credentials or clock change is implied.
#[must_use]
pub fn get_system_date_and_time_request() -> SoapRequest {
    request(
        OnvifOperation::GetSystemDateAndTime,
        "<tds:GetSystemDateAndTime/>",
    )
}

/// Require one namespace-resolved UTC value. Local time, timezone, extensions,
/// and foreign-namespace names cannot substitute for missing Device UTC.
pub fn parse_system_date_and_time(bytes: &[u8]) -> Result<UtcDateTime, WireError> {
    let (doc, response) = response(bytes, DEVICE_NS, "GetSystemDateAndTimeResponse")?;
    let system = required(&doc, response, DEVICE_NS, "SystemDateAndTime")?;
    let utc = required(&doc, system, SCHEMA_NS, "UTCDateTime")?;
    let date = required(&doc, utc, SCHEMA_NS, "Date")?;
    let time = required(&doc, utc, SCHEMA_NS, "Time")?;
    UtcDateTime::new(
        component(&doc, date, "Year")?,
        small_component(&doc, date, "Month")?,
        small_component(&doc, date, "Day")?,
        small_component(&doc, time, "Hour")?,
        small_component(&doc, time, "Minute")?,
        small_component(&doc, time, "Second")?,
    )
}

fn component(doc: &xml::Document, parent: usize, name: &str) -> Result<u16, WireError> {
    let value = scalar(doc, required(doc, parent, SCHEMA_NS, name)?)?;
    let value = value.strip_prefix('+').unwrap_or(value);
    if value.is_empty() || value.len() > 4 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(WireError::InvalidField);
    }
    value.parse().map_err(|_| WireError::InvalidField)
}

fn small_component(doc: &xml::Document, parent: usize, name: &str) -> Result<u8, WireError> {
    component(doc, parent, name)?
        .try_into()
        .map_err(|_| WireError::InvalidField)
}
