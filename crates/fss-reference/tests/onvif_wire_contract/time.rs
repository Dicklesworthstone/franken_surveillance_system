//! Exact-source UTC parsing and arithmetic, without ambient wall-clock access.

use super::*;
use wire::{UtcDateTime, get_system_date_and_time_request, parse_system_date_and_time};

const UTC: &str = "<t:UTCDateTime><t:Time><t:Hour>23</t:Hour><t:Minute>59</t:Minute><t:Second>59</t:Second></t:Time><t:Date><t:Year>2024</t:Year><t:Month>2</t:Month><t:Day>29</t:Day></t:Date></t:UTCDateTime>";

fn time_response(fields: &str) -> String {
    envelope(&format!(
        "<d:GetSystemDateAndTimeResponse><d:SystemDateAndTime>{fields}</d:SystemDateAndTime></d:GetSystemDateAndTimeResponse>"
    ))
}

#[test]
fn pre_auth_time_request_and_namespace_resolved_utc_are_exact() -> Result<(), WireError> {
    let request = get_system_date_and_time_request();
    assert_eq!(
        request.action(),
        OnvifOperation::GetSystemDateAndTime.action()
    );
    assert!(!request.has_username_token());
    let body = std::str::from_utf8(request.body()).unwrap();
    assert!(body.contains("<tds:GetSystemDateAndTime/>"));
    assert!(!body.contains("Header"));
    let parsed = parse_system_date_and_time(time_response(UTC).as_bytes())?;
    assert_eq!(parsed.to_rfc3339(), "2024-02-29T23:59:59Z");
    let alternate = format!(
        "<GetSystemDateAndTimeResponse xmlns='{DEVICE}'><SystemDateAndTime><TimeZone xmlns='{SCHEMA}'><TZ>wrong-local-zone</TZ></TimeZone>{}</SystemDateAndTime></GetSystemDateAndTimeResponse>",
        UTC.replace("t:", "")
            .replace("<UTCDateTime>", &format!("<UTCDateTime xmlns='{SCHEMA}'>"))
    );
    assert_eq!(
        parse_system_date_and_time(envelope(&alternate).as_bytes())?,
        parsed
    );
    assert!(!format!("{parsed:?}").contains("2024"));
    Ok(())
}

#[test]
fn utc_requires_unambiguous_exact_namespace_fields() {
    for invalid in [
        String::new(),
        UTC.replace("UTCDateTime", "LocalDateTime"),
        UTC.replace("<t:UTCDateTime>", "<t:UTCDateTime xmlns:t='urn:foreign'>"),
        UTC.replace("<t:Second>59</t:Second>", ""),
        UTC.replace(
            "<t:Year>2024</t:Year>",
            "<x:Year xmlns:x='urn:foreign'>2024</x:Year>",
        ),
    ] {
        assert_eq!(
            parse_system_date_and_time(time_response(&invalid).as_bytes()),
            Err(WireError::MissingField)
        );
    }
    for duplicate in [
        format!("{UTC}{UTC}"),
        UTC.replace("</t:Date>", "<t:Year>2024</t:Year></t:Date>"),
        UTC.replace("</t:Time>", "<t:Second>59</t:Second></t:Time>"),
    ] {
        assert_eq!(
            parse_system_date_and_time(time_response(&duplicate).as_bytes()),
            Err(WireError::DuplicateField)
        );
    }
}

#[test]
fn gregorian_arithmetic_handles_leap_years_boundaries_and_overflow() -> Result<(), WireError> {
    for (before, elapsed, expected) in [
        ((1970, 1, 1, 0, 0, 0), 0, "1970-01-01T00:00:00Z"),
        ((2024, 2, 29, 23, 59, 59), 1, "2024-03-01T00:00:00Z"),
        ((2000, 2, 28, 23, 59, 59), 1, "2000-02-29T00:00:00Z"),
        ((2100, 2, 28, 23, 59, 59), 1, "2100-03-01T00:00:00Z"),
        ((2024, 12, 31, 23, 59, 59), 2, "2025-01-01T00:00:01Z"),
        (
            (1970, 1, 1, 0, 0, 0),
            253_402_300_799,
            "9999-12-31T23:59:59Z",
        ),
    ] {
        let (year, month, day, hour, minute, second) = before;
        assert_eq!(
            UtcDateTime::new(year, month, day, hour, minute, second)?
                .checked_add_seconds(elapsed)?
                .to_rfc3339(),
            expected
        );
    }
    let last = UtcDateTime::new(9999, 12, 31, 23, 59, 59)?;
    assert_eq!(last.checked_add_seconds(1), Err(WireError::InvalidField));
    assert_eq!(
        last.checked_add_seconds(u64::MAX),
        Err(WireError::InvalidField)
    );
    for (year, month, day, hour, minute, second) in [
        (1969, 12, 31, 23, 59, 59),
        (10000, 1, 1, 0, 0, 0),
        (2023, 2, 29, 0, 0, 0),
        (2100, 2, 29, 0, 0, 0),
        (2024, 0, 1, 0, 0, 0),
        (2024, 13, 1, 0, 0, 0),
        (2024, 4, 31, 0, 0, 0),
        (2024, 1, 0, 0, 0, 0),
        (2024, 1, 1, 24, 0, 0),
        (2024, 1, 1, 0, 60, 0),
        (2024, 1, 1, 0, 0, 60),
    ] {
        assert_eq!(
            UtcDateTime::new(year, month, day, hour, minute, second),
            Err(WireError::InvalidField)
        );
    }
    Ok(())
}

#[test]
fn utc_lexical_values_and_calendar_errors_are_refused_without_reinterpretation() {
    for value in ["", "-1", "1.0", "1e1", "++1", "00001", "60", "１２"] {
        let body = time_response(&UTC.replace(
            "<t:Second>59</t:Second>",
            &format!("<t:Second>{value}</t:Second>"),
        ));
        assert!(parse_system_date_and_time(body.as_bytes()).is_err());
    }
    for invalid in [
        UTC.replace("<t:Year>2024</t:Year>", "<t:Year>2023</t:Year>"),
        UTC.replace("<t:Year>2024</t:Year>", "<t:Year>10000</t:Year>"),
        UTC.replace(
            "<t:Second>59</t:Second>",
            "<t:Second><t:Value>59</t:Value></t:Second>",
        ),
    ] {
        assert!(parse_system_date_and_time(time_response(&invalid).as_bytes()).is_err());
    }
    let signed = UTC.replace("<t:Year>2024</t:Year>", "<t:Year>+2024</t:Year>");
    assert_eq!(
        parse_system_date_and_time(time_response(&signed).as_bytes())
            .unwrap()
            .to_rfc3339(),
        "2024-02-29T23:59:59Z"
    );
}
