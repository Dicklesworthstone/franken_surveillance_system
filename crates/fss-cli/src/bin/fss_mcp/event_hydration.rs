#![forbid(unsafe_code)]
//! Closed AOP-005 transport for session-owned H0/H1 and capability-gated H2/H3 hydration.

use std::collections::BTreeMap;
use std::ffi::OsString;

use super::json::Value;

fn is_sha256_nonzero(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && value[7..].bytes().any(|byte| byte != b'0')
}

fn canonical_u64(value: &Value, min: u64, max: u64) -> Option<u64> {
    let Value::Number(raw) = value else {
        return None;
    };
    raw.parse::<u64>()
        .ok()
        .filter(|n| (min..=max).contains(n) && n.to_string() == *raw)
}

fn bounded_clean_text(value: &Value, max_len: usize) -> Option<&str> {
    value
        .text()
        .filter(|v| !v.is_empty() && v.len() <= max_len && !v.chars().any(char::is_control))
}

fn parse_segment_indices(value: &Value) -> Result<String, (i32, &'static str)> {
    match value {
        Value::Array(items) => {
            if items.is_empty() || items.len() > 16 {
                return Err((
                    -32602,
                    "segment_indices must be a non-empty bounded integer array",
                ));
            }
            let mut parts = Vec::with_capacity(items.len());
            for item in items {
                let idx = canonical_u64(item, 0, 1_000_000).ok_or((
                    -32602,
                    "segment_indices entries must be canonical nonnegative integers",
                ))?;
                parts.push(idx.to_string());
            }
            Ok(parts.join(","))
        }
        Value::Text(raw) if !raw.is_empty() && raw.len() <= 128 => {
            for part in raw.split(',') {
                let parsed = part
                    .parse::<u64>()
                    .map_err(|_| (-32602, "segment_indices must contain canonical decimals"))?;
                if parsed.to_string() != part {
                    return Err((
                        -32602,
                        "segment_indices must use canonical decimal spelling",
                    ));
                }
            }
            Ok(raw.clone())
        }
        _ => Err((
            -32602,
            "segment_indices must be an integer array or comma decimal string",
        )),
    }
}

fn parse_crop_box(value: &Value) -> Result<String, (i32, &'static str)> {
    match value {
        Value::Text(raw) if !raw.is_empty() && raw.len() <= 64 => {
            fss_cli::query_cmd::hydration::CropBox::parse(raw)
                .map_err(|_| (-32602, "crop_box must be canonical X,Y,W,H"))?;
            Ok(raw.clone())
        }
        Value::Object(obj) => {
            if obj.len() != 4 {
                return Err((
                    -32602,
                    "crop_box object must contain exact x, y, width, height",
                ));
            }
            let x = obj
                .get("x")
                .and_then(|v| canonical_u64(v, 0, u64::from(u32::MAX)))
                .ok_or((-32602, "crop_box.x must be a canonical u32 integer"))?;
            let y = obj
                .get("y")
                .and_then(|v| canonical_u64(v, 0, u64::from(u32::MAX)))
                .ok_or((-32602, "crop_box.y must be a canonical u32 integer"))?;
            let w = obj
                .get("width")
                .and_then(|v| canonical_u64(v, 1, u64::from(u32::MAX)))
                .ok_or((
                    -32602,
                    "crop_box.width must be a positive canonical u32 integer",
                ))?;
            let h = obj
                .get("height")
                .and_then(|v| canonical_u64(v, 1, u64::from(u32::MAX)))
                .ok_or((
                    -32602,
                    "crop_box.height must be a positive canonical u32 integer",
                ))?;
            Ok(format!("{x},{y},{w},{h}"))
        }
        _ => Err((
            -32602,
            "crop_box must be X,Y,W,H string or {x,y,width,height} object",
        )),
    }
}

pub(super) fn arguments(
    fields: &BTreeMap<String, Value>,
    allow_visual_hydration: bool,
    granted_capabilities: &[String],
    mut argv: Vec<OsString>,
) -> Result<Vec<OsString>, (i32, &'static str)> {
    let allowed = [
        "target",
        "session",
        "generation",
        "event_id",
        "revision_digest",
        "anchor",
        "level",
        "descriptor_digest",
        "budget_tokens",
        "continuation",
        "import_id",
        "segment_indices",
        "max_dimension",
        "crop_box",
        "max_h3_frames",
        "max_h3_bytes",
    ];
    if fields
        .keys()
        .any(|field| !allowed.contains(&field.as_str()))
    {
        return Err((
            -32602,
            "Unexpected evidence-hydration argument or authority override",
        ));
    }
    if fields.get("target").and_then(Value::text) != Some("evidence-hydration") {
        return Err((-32602, "Expected exact evidence-hydration query target"));
    }
    argv.push("--target=evidence-hydration".into());
    let level = fields
        .get("level")
        .and_then(Value::text)
        .filter(|value| matches!(*value, "H0" | "H1" | "H2" | "H3"))
        .ok_or((-32602, "Evidence hydration admits only H0, H1, H2, or H3"))?;
    argv.push(format!("--level={level}").into());

    if matches!(level, "H0" | "H1") {
        for extended_only in [
            "import_id",
            "segment_indices",
            "max_dimension",
            "crop_box",
            "max_h3_frames",
            "max_h3_bytes",
        ] {
            if fields.contains_key(extended_only) {
                return Err((
                    -32602,
                    "Visual/import hydration options are not admitted at H0/H1",
                ));
            }
        }
        for (field, flag, maximum) in [
            ("session", "session", 128),
            ("event_id", "event-id", 128),
            ("anchor", "anchor", 256),
        ] {
            let value = fields
                .get(field)
                .and_then(|v| bounded_clean_text(v, maximum))
                .ok_or((
                    -32602,
                    "Expected exact retained session, event and current anchor identities",
                ))?;
            argv.push(format!("--{flag}={value}").into());
        }
        let generation = fields
            .get("generation")
            .and_then(Value::text)
            .filter(|value| {
                value
                    .parse::<u64>()
                    .is_ok_and(|number| number.to_string() == *value)
            })
            .ok_or((
                -32602,
                "Session generation requires a canonical nonnegative u64 decimal string",
            ))?;
        argv.push(format!("--generation={generation}").into());
        for (field, flag, required) in [
            ("revision_digest", "revision-digest", true),
            ("descriptor_digest", "descriptor-digest", level == "H1"),
        ] {
            match fields.get(field) {
                Some(value) => {
                    let value = value.text().filter(|v| is_sha256_nonzero(v)).ok_or((
                        -32602,
                        "Expected a canonical nonzero SHA-256 revision or descriptor digest",
                    ))?;
                    argv.push(format!("--{flag}={value}").into());
                }
                None if required => {
                    return Err((
                        -32602,
                        "Exact revision and the H1 descriptor precondition are required",
                    ));
                }
                None => {}
            }
        }
        if let Some(value) = fields.get("budget_tokens") {
            let tokens = canonical_u64(value, 1, 16_000).ok_or((
                -32602,
                "Hydration budget_tokens must be a JSON integer in 1..16000",
            ))?;
            argv.push(format!("--budget-tokens={tokens}").into());
        }
        if let Some(value) = fields.get("continuation") {
            if level != "H1" || !fields.contains_key("descriptor_digest") {
                return Err((
                    -32602,
                    "A progressive continuation requires H1 and its exact descriptor",
                ));
            }
            let value = value
                .text()
                .filter(|value| !value.is_empty() && value.len() <= 16 * 1024)
                .ok_or((
                    -32602,
                    "Continuation requires the complete native cursor JSON as a bounded string",
                ))?;
            argv.push(format!("--continuation={value}").into());
        }
        return Ok(argv);
    }

    // H2 / H3 capability-gated path.
    if fields.contains_key("continuation") {
        return Err((
            -32602,
            "H2/H3 hydration does not accept progressive H1 continuations",
        ));
    }
    let has_import = fields.contains_key("import_id");
    let has_event = fields.contains_key("event_id")
        || fields.contains_key("revision_digest")
        || fields.contains_key("descriptor_digest");
    if has_import == has_event {
        return Err((
            -32602,
            "H2/H3 requires either import_id OR (event_id, revision_digest, descriptor_digest)",
        ));
    }
    if has_import {
        let import_id = fields
            .get("import_id")
            .and_then(Value::text)
            .filter(|v| is_sha256_nonzero(v))
            .ok_or((
                -32602,
                "import_id must be a canonical nonzero SHA-256 digest",
            ))?;
        argv.push(format!("--import-id={import_id}").into());
    } else {
        let event_id = fields
            .get("event_id")
            .and_then(|v| bounded_clean_text(v, 128))
            .ok_or((-32602, "H2/H3 event hydration requires event_id"))?;
        let rev = fields
            .get("revision_digest")
            .and_then(Value::text)
            .filter(|v| is_sha256_nonzero(v))
            .ok_or((-32602, "H2/H3 event hydration requires revision_digest"))?;
        let desc = fields
            .get("descriptor_digest")
            .and_then(Value::text)
            .filter(|v| is_sha256_nonzero(v))
            .ok_or((
                -32602,
                "H2/H3 event hydration requires exact H0 descriptor_digest pin",
            ))?;
        argv.push(format!("--event-id={event_id}").into());
        argv.push(format!("--revision-digest={rev}").into());
        argv.push(format!("--descriptor-digest={desc}").into());
    }
    if let Some(session) = fields.get("session") {
        let s = bounded_clean_text(session, 128)
            .ok_or((-32602, "session must be a bounded non-empty string"))?;
        argv.push(format!("--session={s}").into());
    }
    if let Some(generation) = fields.get("generation") {
        let g = generation
            .text()
            .filter(|v| v.parse::<u64>().is_ok_and(|n| n.to_string() == *v))
            .ok_or((
                -32602,
                "generation must be a canonical nonnegative u64 string",
            ))?;
        argv.push(format!("--generation={g}").into());
    }
    if let Some(anchor) = fields.get("anchor") {
        let a = bounded_clean_text(anchor, 256)
            .ok_or((-32602, "anchor must be a bounded non-empty string"))?;
        argv.push(format!("--anchor={a}").into());
    }
    if let Some(value) = fields.get("budget_tokens") {
        let tokens = canonical_u64(value, 1, 1_000_000).ok_or((
            -32602,
            "H2/H3 budget_tokens must be a JSON integer in 1..=1000000",
        ))?;
        argv.push(format!("--budget-tokens={tokens}").into());
    }

    if level == "H2" {
        for h3_only in [
            "segment_indices",
            "max_dimension",
            "crop_box",
            "max_h3_frames",
            "max_h3_bytes",
        ] {
            if fields.contains_key(h3_only) {
                return Err((
                    -32602,
                    "H3 visual options are not admitted for H2 analytic hydration",
                ));
            }
        }
    } else {
        if let Some(segs) = fields.get("segment_indices") {
            let formatted = parse_segment_indices(segs)?;
            argv.push(format!("--segment-indices={formatted}").into());
        }
        if let Some(dim) = fields.get("max_dimension") {
            let d = canonical_u64(dim, 0, u64::from(u32::MAX))
                .ok_or((-32602, "max_dimension must be a canonical integer"))?;
            argv.push(format!("--max-dimension={d}").into());
        }
        if let Some(crop) = fields.get("crop_box") {
            let formatted = parse_crop_box(crop)?;
            argv.push(format!("--crop-box={formatted}").into());
        }
        if let Some(frames) = fields.get("max_h3_frames") {
            let n = canonical_u64(frames, 0, 1024)
                .ok_or((-32602, "max_h3_frames must be a canonical integer"))?;
            argv.push(format!("--max-h3-frames={n}").into());
        }
        if let Some(bytes) = fields.get("max_h3_bytes") {
            let n = canonical_u64(bytes, 0, 16 * 1024 * 1024)
                .ok_or((-32602, "max_h3_bytes must be a canonical integer"))?;
            argv.push(format!("--max-h3-bytes={n}").into());
        }
        // Launcher-only visual gate: clients can NEVER supply this flag.
        if allow_visual_hydration {
            argv.push("--allow-visual-hydration".into());
        }
    }
    // Launcher-only capability grants: clients can NEVER supply these flags.
    for capability in granted_capabilities {
        argv.push(format!("--capability={capability}").into());
    }
    Ok(argv)
}
