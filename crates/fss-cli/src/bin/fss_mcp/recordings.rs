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
            "catalogs",
            "discover_catalogs",
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
    let catalog_set = fields.contains_key("catalogs");
    let discovery = match fields.get("discover_catalogs") {
        None => false,
        Some(Value::Boolean(true)) => true,
        Some(_) => return Err((-32602, "discover_catalogs must be true when supplied")),
    };
    if discovery
        && (catalog_set
            || utc
            || fields.contains_key("catalog_slot")
            || fields.contains_key("catalog_root"))
    {
        return Err((
            -32602,
            "Archive discovery requires decode-clock bounds and excludes manual catalog or UTC pins",
        ));
    }

    if catalog_set
        && (utc || fields.contains_key("catalog_slot") || fields.contains_key("catalog_root"))
    {
        return Err((
            -32602,
            "Catalog sets require decode-clock bounds and exclude singleton or UTC pins",
        ));
    }
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
    if discovery {
        argv.push("--discover-catalogs=yes".into());
    }
    if let Some(value) = fields.get("catalogs") {
        let Value::Array(pins) = value else {
            return Err((-32602, "Expected a bounded array of exact catalog pins"));
        };
        if !(1..=8).contains(&pins.len()) {
            return Err((-32602, "Expected one to eight catalog pins"));
        }
        let mut tokens = Vec::with_capacity(pins.len());
        for pin in pins {
            let object = pin
                .object()
                .filter(|object| object.len() == 2)
                .ok_or((-32602, "Catalog pins contain only slot and root"))?;
            let slot = object
                .get("slot")
                .and_then(Value::text)
                .filter(|text| {
                    !text.is_empty()
                        && text.len() <= 128
                        && text.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || byte == b'_'
                                || byte == b'-'
                        })
                })
                .ok_or((-32602, "Expected an exact catalog publication slot"))?;
            let root = object
                .get("root")
                .and_then(Value::text)
                .filter(|text| {
                    text.len() == 71
                        && text.starts_with("sha256:")
                        && text[7..]
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
                .ok_or((-32602, "Expected a canonical SHA-256 catalog root"))?;
            tokens.push(format!("{slot}={root}"));
        }
        argv.push(format!("--catalogs={}", tokens.join(",")).into());
    }
    for (field, option, bound, required) in [
        ("codec", "codec", 4, true),
        (
            "catalog_slot",
            "catalog-slot",
            128,
            !catalog_set && !discovery,
        ),
        (
            "catalog_root",
            "catalog-root",
            71,
            !catalog_set && !discovery,
        ),
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
