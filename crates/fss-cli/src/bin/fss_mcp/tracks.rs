#![forbid(unsafe_code)]
//! Closed transport adapter for source-verified retained track observations through AOP-005.
//! Only the launcher grants internal source verification; native parsing owns admission.

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
            "label",
            "confirmation_hits",
            "maximum_missed_frames",
            "minimum_iou_ppm",
            "max_entries",
            "continuation",
            "anchor",
            "max_query_read_bytes",
            "max_query_read_objects",
        ]
        .contains(&field.as_str())
    }) {
        return Err((-32602, "Unexpected tracks argument or scope override"));
    }
    if fields.get("target").and_then(Value::text) != Some("tracks") {
        return Err((-32602, "Expected exact tracks query target"));
    }
    if !allow_source_verification {
        return Err((
            -32602,
            "Track source verification requires the launcher's separate grant",
        ));
    }
    let report = fields
        .get("report_digest")
        .and_then(Value::text)
        .filter(|text| text.len() == 71)
        .ok_or((
            -32602,
            "Expected an exact retained package-detection report digest",
        ))?;
    let label = fields
        .get("label")
        .and_then(Value::text)
        .filter(|text| (1..=512).contains(&text.len()) && !text.chars().any(char::is_control))
        .ok_or((-32602, "Expected a bounded exact model-vocabulary label"))?;
    argv.extend([
        "--target=tracks".into(),
        format!("--report-digest={report}").into(),
        format!("--label={label}").into(),
        "--verify-tracks-source=yes".into(),
    ]);
    for (field, flag, minimum, maximum) in [
        ("confirmation_hits", "confirmation-hits", 1, u32::MAX),
        (
            "maximum_missed_frames",
            "maximum-missed-frames",
            1,
            u32::MAX,
        ),
        ("minimum_iou_ppm", "minimum-iou-ppm", 0, 1_000_000),
        ("max_entries", "max-entries", 1, 32),
    ] {
        if let Some(value) = fields.get(field) {
            let Value::Number(text) = value else {
                return Err((-32602, "Track recipe and page bounds require JSON integers"));
            };
            if !text.parse::<u32>().is_ok_and(|number| {
                (minimum..=maximum).contains(&number) && number.to_string() == *text
            }) {
                return Err((
                    -32602,
                    "Track recipe or page integer is outside its canonical bound",
                ));
            }
            argv.push(format!("--{flag}={text}").into());
        }
    }
    for (field, flag) in [("anchor", "anchor"), ("continuation", "continuation")] {
        if let Some(value) = fields.get(field) {
            let text = value
                .text()
                .filter(|text| !text.is_empty() && text.len() <= 256)
                .ok_or((
                    -32602,
                    "Expected a bounded exact track anchor or continuation",
                ))?;
            argv.push(format!("--{flag}={text}").into());
        }
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
                .filter(|text| {
                    text.parse::<u64>().is_ok_and(|number| {
                        (1..=maximum).contains(&number) && number.to_string() == *text
                    })
                })
                .ok_or((
                    -32602,
                    "Track read limits require bounded canonical decimal strings",
                ))?;
            argv.push(format!("--{flag}={text}").into());
        }
    }
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    type Test = Result<(), Box<dyn std::error::Error>>;
    const REPORT: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn fields() -> BTreeMap<String, Value> {
        BTreeMap::from([
            ("target".into(), Value::Text("tracks".into())),
            ("report_digest".into(), Value::Text(REPORT.into())),
            ("label".into(), Value::Text("person".into())),
        ])
    }

    fn base() -> Vec<OsString> {
        [
            "query",
            "--json",
            "--root=/operator/fixed",
            "--principal=principal:track-reader",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn tracks_adapter_uses_the_canonical_parser_and_exact_native_recipe() -> Test {
        let mut fields = fields();
        for (field, value) in [
            ("confirmation_hits", 4),
            ("maximum_missed_frames", 2),
            ("minimum_iou_ppm", 0),
            ("max_entries", 1),
        ] {
            fields.insert(field.into(), Value::Number(value.to_string()));
        }
        let command = fss_cli::parse_fss_args(
            arguments(&fields, true, base()).map_err(|(_, reason)| reason)?,
        )?;
        let fss_cli::FssCommand::TracksQuery(args) = command else {
            return Err("tracks command".into());
        };
        assert_eq!(args.request.report_digest.to_text(), REPORT);
        assert_eq!(args.request.label, "person");
        assert_eq!(args.request.config.confirmation_hits, 4);
        assert_eq!(args.request.config.maximum_missed_frames, 2);
        assert_eq!(args.request.config.minimum_iou_ppm, 0);
        assert_eq!(args.request.max_entries, 1);
        assert!(args.verify_tracks_source);
        assert_eq!(args.root, std::path::PathBuf::from("/operator/fixed"));
        assert_eq!(args.request.principal.as_str(), "principal:track-reader");
        Ok(())
    }

    #[test]
    fn tracks_transport_rejects_missing_launcher_grant_and_all_client_scope_overrides() {
        assert!(arguments(&fields(), false, base()).is_err());
        for name in [
            "root",
            "principal",
            "verify_tracks_source",
            "allow_tracks_source_verification",
            "archive",
            "at",
            "media",
            "execute",
            "zone_roles",
        ] {
            let mut fields = fields();
            fields.insert(name.into(), Value::Text("private-scope-canary".into()));
            assert!(arguments(&fields, true, base()).is_err(), "{name}");
        }
        for (name, value) in [
            ("confirmation_hits", Value::Number("0".into())),
            ("maximum_missed_frames", Value::Number("0".into())),
            ("minimum_iou_ppm", Value::Number("1000001".into())),
            ("max_entries", Value::Number("33".into())),
            ("max_entries", Value::Number("1e0".into())),
            ("max_entries", Value::Text("1".into())),
            ("max_query_read_bytes", Value::Number("1024".into())),
            ("max_query_read_objects", Value::Text("01".into())),
        ] {
            let mut fields = fields();
            fields.insert(name.into(), value);
            assert!(arguments(&fields, true, base()).is_err(), "{name}");
        }
    }
}
