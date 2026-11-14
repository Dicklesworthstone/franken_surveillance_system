#![forbid(unsafe_code)]
//! Shared nonrenewing payload-read ceilings for native retained inference inspection.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::time::Duration;

use fss_reference::agent_orient::OrientLimits;
use fss_reference::retained_source::ImmutableRetainedReadLimits;

/// Cooperative read deadline, also checked after bounded model/association work.
pub(super) const DEADLINE: Duration = Duration::from_secs(60);
const DEFAULT_READ_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_READ_BYTES: u64 = 4 * DEFAULT_READ_BYTES;
const DEFAULT_READ_OBJECTS: u64 = 1_000_000;
const MAX_READ_OBJECTS: u64 = 4_000_000;

fn limit(
    values: &BTreeMap<String, OsString>,
    key: &str,
    default: u64,
    maximum: u64,
) -> Result<usize, String> {
    let value = match values.get(key) {
        Some(raw) => {
            let text = raw.to_str().ok_or_else(|| format!("{key} must be UTF-8"))?;
            let number = text
                .parse::<u64>()
                .map_err(|_| format!("{key} requires a canonical positive integer"))?;
            if number.to_string() != text {
                return Err(format!("{key} requires a canonical positive integer"));
            }
            number
        }
        None => default,
    };
    if value == 0 || value > maximum {
        return Err(format!("{key} must be in 1..{maximum}"));
    }
    usize::try_from(value).map_err(|_| format!("{key} exceeds this platform's address range"))
}

/// Parses the aggregate allowance shared by metadata, source verification and final rereads.
/// Command-specific parsers must separately admit these two option names.
pub(super) fn parse_limits(
    values: &BTreeMap<String, OsString>,
) -> Result<ImmutableRetainedReadLimits, String> {
    Ok(ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: limit(
            values,
            "--max-read-bytes",
            DEFAULT_READ_BYTES,
            MAX_READ_BYTES,
        )?,
        max_read_objects: limit(
            values,
            "--max-read-objects",
            DEFAULT_READ_OBJECTS,
            MAX_READ_OBJECTS,
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_allowances_are_positive_bounded_and_canonical() -> Result<(), String> {
        let defaults = parse_limits(&BTreeMap::new())?;
        assert_eq!(defaults.max_read_bytes as u64, DEFAULT_READ_BYTES);
        assert_eq!(defaults.max_read_objects as u64, DEFAULT_READ_OBJECTS);
        for (key, maximum) in [
            ("--max-read-bytes", MAX_READ_BYTES),
            ("--max-read-objects", MAX_READ_OBJECTS),
        ] {
            for value in ["0", "-1", "+1", "01", "1.0", "1 ", "18446744073709551616"] {
                let values = BTreeMap::from([(key.to_owned(), OsString::from(value))]);
                assert!(parse_limits(&values).is_err(), "{key}: {value}");
            }
            let excessive =
                BTreeMap::from([(key.to_owned(), OsString::from((maximum + 1).to_string()))]);
            assert!(parse_limits(&excessive).is_err());
            let smallest = BTreeMap::from([(key.to_owned(), OsString::from("1"))]);
            assert!(parse_limits(&smallest).is_ok());
        }
        Ok(())
    }
}
