#![forbid(unsafe_code)]
//! Closed transport adapter for immutable QSR reads through AOP-005.
//! Only the launcher grants internal source verification; canonical native parsing owns admission.

use std::collections::BTreeMap;
use std::ffi::OsString;

use super::json::Value;

pub(super) fn arguments(
    fields: &BTreeMap<String, Value>,
    allow_source_verification: bool,
    mut argv: Vec<OsString>,
) -> Result<Vec<OsString>, (i32, &'static str)> {
    if fields.keys().any(|field| {
        ![
            "target",
            "report_digest",
            "zone_roles",
            "lane_stages",
            "anchor",
            "max_query_read_bytes",
            "max_query_read_objects",
        ]
        .contains(&field.as_str())
    }) {
        return Err((-32602, "Unexpected QSR argument or scope override"));
    }
    if fields.get("target").and_then(Value::text) != Some("qsr") {
        return Err((-32602, "Expected exact QSR query target"));
    }
    if !allow_source_verification {
        return Err((
            -32602,
            "QSR source verification requires the launcher's separate grant",
        ));
    }
    let report = fields
        .get("report_digest")
        .and_then(Value::text)
        .filter(|value| value.len() == 71)
        .ok_or((
            -32602,
            "Expected an exact retained QSR source report digest",
        ))?;
    argv.extend([
        "--target=qsr".into(),
        format!("--report-digest={report}").into(),
        "--verify-qsr-source=yes".into(),
    ]);
    if let Some(value) = fields.get("zone_roles") {
        let Value::Array(roles) = value else {
            return Err((-32602, "QSR zone roles must be an inline array"));
        };
        if roles.len() > 16 {
            return Err((-32602, "QSR zone roles exceed the sixteen-zone bound"));
        }
        let mut encoded = Vec::with_capacity(roles.len());
        for role in roles {
            let role = role
                .object()
                .filter(|fields| {
                    fields.len() == 2 && fields.contains_key("zone") && fields.contains_key("role")
                })
                .ok_or((-32602, "QSR zone roles contain only zone and role"))?;
            let zone = zone_id(role.get("zone"))?;
            let kind = role
                .get("role")
                .and_then(Value::text)
                .filter(|value| matches!(*value, "area" | "queue" | "register"))
                .ok_or((-32602, "QSR role must be area, queue or register"))?;
            encoded.push(format!(
                "{{\"zone\":{},\"role\":{}}}",
                fss_cli::json_output::string(zone),
                fss_cli::json_output::string(kind),
            ));
        }
        argv.push(format!("--zone-roles={}", fss_cli::json_output::array(&encoded)).into());
    }
    if let Some(value) = fields.get("lane_stages") {
        let Value::Array(stages) = value else {
            return Err((-32602, "QSR lane stages must be an inline ordered array"));
        };
        if stages.len() == 1 || stages.len() > 16 {
            return Err((
                -32602,
                "QSR lane stages must be empty or contain two to sixteen zones",
            ));
        }
        let mut encoded = Vec::with_capacity(stages.len());
        for stage in stages {
            encoded.push(fss_cli::json_output::string(zone_id(Some(stage))?));
        }
        argv.push(format!("--lane-stages={}", fss_cli::json_output::array(&encoded)).into());
    }
    if let Some(value) = fields.get("anchor") {
        let text = value
            .text()
            .filter(|value| !value.is_empty() && value.len() <= 256)
            .ok_or((-32602, "Expected a bounded exact deployment anchor"))?;
        argv.push(format!("--anchor={text}").into());
    }
    for (field, flag, maximum) in [
        (
            "max_query_read_bytes",
            "max-query-read-bytes",
            4_294_967_296_u64,
        ),
        (
            "max_query_read_objects",
            "max-query-read-objects",
            4_000_000_u64,
        ),
    ] {
        if let Some(value) = fields.get(field) {
            let text = value
                .text()
                .filter(|value| {
                    value.parse::<u64>().is_ok_and(|number| {
                        (1..=maximum).contains(&number) && number.to_string() == *value
                    })
                })
                .ok_or((
                    -32602,
                    "QSR read limits require bounded canonical decimal strings",
                ))?;
            argv.push(format!("--{flag}={text}").into());
        }
    }
    Ok(argv)
}

fn zone_id(value: Option<&Value>) -> Result<&str, (i32, &'static str)> {
    value
        .and_then(Value::text)
        .filter(|value| {
            (1..=64).contains(&value.len())
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        })
        .ok_or((
            -32602,
            "QSR zone identifiers require one to sixty-four ASCII identifier bytes",
        ))
}
