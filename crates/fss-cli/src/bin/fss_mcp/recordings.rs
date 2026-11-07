#![forbid(unsafe_code)]
//! Closed MCP argument adapter for explicitly pinned native recording metadata.
//! The native CLI parser owns identities, exact integers, scope and interval validation.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};

use super::json::Value;

pub(super) fn arguments(
    fields: &BTreeMap<String, Value>,
    archive_root: Option<&OsStr>,
    mut argv: Vec<OsString>,
) -> Result<Vec<OsString>, (i32, &'static str)> {
    if fields.keys().any(|field| {
        ![
            "target",
            "codec",
            "catalog_slot",
            "catalog_root",
            "sensor",
            "stream",
            "generation",
            "source_anchor",
            "receive_clock",
            "decode_clock",
            "time_scale",
            "start_tick",
            "end_tick",
            "clock_slot",
            "clock_root",
            "start_utc_ns",
            "end_utc_ns",
            "max_windows",
            "max_hydration_bytes",
            "anchor",
        ]
        .contains(&field.as_str())
    }) {
        return Err((-32602, "Unexpected recording argument or scope override"));
    }
    let archive_root = archive_root.ok_or((
        -32602,
        "Recording queries require an operator-bound archive root at launch",
    ))?;
    let utc = ["clock_slot", "clock_root", "start_utc_ns", "end_utc_ns"]
        .iter()
        .any(|field| fields.contains_key(*field));
    if utc
        && ["start_tick", "end_tick"]
            .iter()
            .any(|field| fields.contains_key(*field))
    {
        return Err((
            -32602,
            "UTC and decode-clock query intervals are mutually exclusive",
        ));
    }
    argv.extend([
        "--target=recordings".into(),
        "--archive-root".into(),
        archive_root.to_os_string(),
    ]);
    for (field, option, bound, required) in [
        ("codec", "codec", 4, true),
        ("catalog_slot", "catalog-slot", 128, true),
        ("catalog_root", "catalog-root", 71, true),
        ("sensor", "sensor", 128, true),
        ("stream", "stream", 128, true),
        ("generation", "generation", 20, true),
        ("source_anchor", "source-anchor", 71, true),
        ("receive_clock", "receive-clock", 71, true),
        ("decode_clock", "decode-clock", 71, true),
        ("start_tick", "start-tick", 20, !utc),
        ("end_tick", "end-tick", 20, !utc),
        ("clock_slot", "clock-slot", 128, utc),
        ("clock_root", "clock-root", 71, utc),
        ("start_utc_ns", "start-utc-ns", 20, utc),
        ("end_utc_ns", "end-utc-ns", 20, utc),
        ("max_hydration_bytes", "max-hydration-bytes", 20, false),
        ("anchor", "anchor", 256, false),
    ] {
        let Some(value) = fields.get(field) else {
            if required {
                return Err((-32602, "Missing required recording pin or interval"));
            }
            continue;
        };
        let text = value
            .text()
            .filter(|value| !value.is_empty() && value.len() <= bound)
            .ok_or((
                -32602,
                "Expected a bounded recording token or decimal string",
            ))?;
        // Inline values are data. A decimal string is never rounded, trimmed,
        // normalized or interpreted through floating point in this adapter.
        argv.push(format!("--{option}={text}").into());
    }
    for (field, option, maximum, required) in [
        ("time_scale", "time-scale", u64::from(u32::MAX), true),
        ("max_windows", "max-windows", 32, false),
    ] {
        let Some(value) = fields.get(field) else {
            if required {
                return Err((-32602, "Missing recording time scale"));
            }
            continue;
        };
        let Value::Number(text) = value else {
            return Err((-32602, "Expected a positive recording integer"));
        };
        if !text.bytes().all(|byte| byte.is_ascii_digit())
            || !text
                .parse::<u64>()
                .is_ok_and(|number| number > 0 && number <= maximum)
        {
            return Err((-32602, "Recording integer is outside the admitted range"));
        }
        argv.push(format!("--{option}={text}").into());
    }
    Ok(argv)
}
