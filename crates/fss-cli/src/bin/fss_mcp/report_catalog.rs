#![forbid(unsafe_code)]
//! Closed transport adapter for metadata-only retained report discovery through AOP-005.

use std::collections::BTreeMap;
use std::ffi::OsString;

use super::json::Value;

pub(super) fn arguments(
    fields: &BTreeMap<String, Value>,
    mut argv: Vec<OsString>,
) -> Result<Vec<OsString>, (i32, &'static str)> {
    if fields.keys().any(|field| {
        ![
            "target",
            "family",
            "from_ns",
            "through_ns",
            "max_entries",
            "anchor",
            "continuation",
            "max_query_read_bytes",
            "max_query_read_objects",
            "max_query_results",
        ]
        .contains(&field.as_str())
    }) {
        return Err((
            -32602,
            "Unexpected report-catalog argument or scope override",
        ));
    }
    if fields.get("target").and_then(Value::text) != Some("reports") {
        return Err((-32602, "Expected exact reports query target"));
    }
    argv.push("--target=reports".into());
    if let Some(value) = fields.get("family") {
        let family = value
            .text()
            .filter(|value| matches!(*value, "package_detection_record" | "package_zone_report"))
            .ok_or((
                -32602,
                "Expected an existing package detection or package-zone report family",
            ))?;
        argv.push(format!("--family={family}").into());
    }
    for (field, flag) in [("from_ns", "from-ns"), ("through_ns", "through-ns")] {
        if let Some(value) = fields.get(field) {
            let time = value
                .text()
                .filter(|value| {
                    value
                        .parse::<i128>()
                        .is_ok_and(|number| number.to_string() == *value)
                })
                .ok_or((
                    -32602,
                    "Report intervals require exact canonical decimal strings",
                ))?;
            argv.push(format!("--{flag}={time}").into());
        }
    }
    if let Some(value) = fields.get("max_entries") {
        let Value::Number(text) = value else {
            return Err((
                -32602,
                "Report page size must be an integer from one to thirty-two",
            ));
        };
        if !text
            .parse::<u32>()
            .is_ok_and(|number| (1..=32).contains(&number) && number.to_string() == *text)
        {
            return Err((
                -32602,
                "Report page size must be an integer from one to thirty-two",
            ));
        }
        argv.push(format!("--max-entries={text}").into());
    }
    for (field, flag) in [("anchor", "anchor"), ("continuation", "continuation")] {
        if let Some(value) = fields.get(field) {
            let text = value
                .text()
                .filter(|value| !value.is_empty() && value.len() <= 256)
                .ok_or((
                    -32602,
                    "Expected a bounded exact report-catalog anchor or continuation",
                ))?;
            argv.push(format!("--{flag}={text}").into());
        }
    }
    for (field, flag, maximum) in [
        (
            "max_query_read_bytes",
            "max-query-read-bytes",
            268_435_456_u64,
        ),
        (
            "max_query_read_objects",
            "max-query-read-objects",
            65_536_u64,
        ),
        ("max_query_results", "max-query-results", 4096_u64),
    ] {
        if let Some(value) = fields.get(field) {
            let text = value.text().filter(|value| {
                value.parse::<u64>().is_ok_and(|number| (1..=maximum).contains(&number) && number.to_string() == *value)
            }).ok_or((-32602, "Report read and complete-index limits require bounded canonical decimal strings"))?;
            argv.push(format!("--{flag}={text}").into());
        }
    }
    Ok(argv)
}
