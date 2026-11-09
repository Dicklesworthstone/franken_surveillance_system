#![forbid(unsafe_code)]
//! Closed MCP adapter for the existing query operation's retained ONVIF target.
//! All source pins and inline policies go through the native canonical CLI parser.

use std::collections::BTreeMap;
use std::ffi::OsString;

use super::json::Value;

fn literal(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Boolean(value) => value.to_string(),
        Value::Number(value) => value.clone(),
        Value::Text(value) => fss_cli::json_output::string(value),
        Value::Array(values) => {
            fss_cli::json_output::array(&values.iter().map(literal).collect::<Vec<_>>())
        }
        Value::Object(fields) => format!(
            "{{{}}}",
            fields
                .iter()
                .map(|(key, value)| format!(
                    "{}:{}",
                    fss_cli::json_output::string(key),
                    literal(value)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

pub(super) fn arguments(
    fields: &BTreeMap<String, Value>,
    mut argv: Vec<OsString>,
) -> Result<Vec<OsString>, (i32, &'static str)> {
    if fields.keys().any(|field| {
        ![
            "target",
            "analysis",
            "sources",
            "zone_policy",
            "max_entries",
            "anchor",
        ]
        .contains(&field.as_str())
    }) {
        return Err((-32602, "Unexpected ONVIF argument or scope override"));
    }
    if fields.get("target").and_then(Value::text) != Some("onvif") {
        return Err((-32602, "Expected exact ONVIF query target"));
    }
    let analysis = fields
        .get("analysis")
        .and_then(Value::text)
        .filter(|value| matches!(*value, "tracks" | "lifecycle" | "zones"))
        .ok_or((-32602, "Expected tracks, lifecycle or zones analysis"))?;
    let source_value = fields
        .get("sources")
        .ok_or((-32602, "Missing exact ONVIF source pins"))?;
    let Value::Array(sources) = source_value else {
        return Err((-32602, "ONVIF sources must be an ordered array"));
    };
    if !(1..=32).contains(&sources.len()) {
        return Err((-32602, "Expected one to 32 exact ONVIF source pins"));
    }
    for source in sources {
        let fields = source
            .object()
            .filter(|fields| {
                fields.len() == 3
                    && ["kind", "identity", "root"]
                        .iter()
                        .all(|key| fields.contains_key(*key))
            })
            .ok_or((
                -32602,
                "ONVIF source pins contain only kind, identity and root",
            ))?;
        if !matches!(
            fields.get("kind").and_then(Value::text),
            Some("xml" | "rtp")
        ) {
            return Err((-32602, "ONVIF source kind must be xml or rtp"));
        }
        for field in ["identity", "root"] {
            fields
                .get(field)
                .and_then(Value::text)
                .filter(|value| value.len() == 71)
                .ok_or((-32602, "Expected exact canonical ONVIF source digest"))?;
        }
    }
    let selector = literal(source_value);
    if selector.len() > 16 * 1024 {
        return Err((-32602, "ONVIF source selector exceeds its bound"));
    }
    argv.extend([
        "--target=onvif".into(),
        format!("--analysis={analysis}").into(),
        format!("--sources={selector}").into(),
    ]);
    match (analysis, fields.get("zone_policy")) {
        ("zones", Some(value @ Value::Object(_))) => {
            let policy = literal(value);
            if policy.len() > 64 * 1024 {
                return Err((-32602, "ONVIF zone policy exceeds its bound"));
            }
            argv.push(format!("--zone-policy={policy}").into());
        }
        ("zones", _) => {
            return Err((
                -32602,
                "Zone analysis requires an inline JSON policy object",
            ));
        }
        (_, Some(_)) => return Err((-32602, "Zone policy is exclusive to zones analysis")),
        (_, None) => {}
    }
    if let Some(value) = fields.get("max_entries") {
        let Value::Number(text) = value else {
            return Err((-32602, "max_entries must be an integer"));
        };
        if !text
            .parse::<usize>()
            .is_ok_and(|number| (1..=32).contains(&number) && number.to_string() == *text)
        {
            return Err((-32602, "max_entries must be a canonical integer 1..32"));
        }
        argv.push(format!("--max-entries={text}").into());
    }
    if let Some(value) = fields.get("anchor") {
        let text = value
            .text()
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .ok_or((-32602, "Expected a bounded exact deployment anchor"))?;
        argv.push(format!("--anchor={text}").into());
    }
    Ok(argv)
}
