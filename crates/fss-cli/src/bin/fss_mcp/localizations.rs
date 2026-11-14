#![forbid(unsafe_code)]
//! Closed transport adapter for retained localization discovery through AOP-005.

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
            "sensor",
            "stream",
            "import_id",
            "twin_digest",
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
            "Unexpected localization discovery argument or scope override",
        ));
    }
    if fields.get("target").and_then(Value::text) != Some("localizations") {
        return Err((-32602, "Expected exact localizations query target"));
    }
    argv.push("--target=localizations".into());
    for (field, flag) in [("sensor", "sensor"), ("stream", "stream")] {
        if let Some(value) = fields.get(field) {
            let identity = value
                .text()
                .filter(|value| !value.is_empty() && value.len() <= 128)
                .ok_or((
                    -32602,
                    "Expected an exact bounded sensor or stream identity",
                ))?;
            argv.push(format!("--{flag}={identity}").into());
        }
    }
    for (field, flag) in [("import_id", "import-id"), ("twin_digest", "twin-digest")] {
        if let Some(value) = fields.get(field) {
            let text = value
                .text()
                .filter(|text| {
                    text.parse::<fss_core::ContentDigest>().is_ok_and(|digest| {
                        digest.algorithm() == fss_core::DigestAlgorithm::Sha256
                            && digest.bytes().iter().any(|byte| *byte != 0)
                            && digest.to_text() == *text
                    })
                })
                .ok_or((
                    -32602,
                    "Expected an exact nonzero canonical SHA-256 identity",
                ))?;
            argv.push(format!("--{flag}={text}").into());
        }
    }
    if let Some(value) = fields.get("max_entries") {
        let Value::Number(text) = value else {
            return Err((
                -32602,
                "Localization discovery page size must be an integer from one to thirty-two",
            ));
        };
        if !text
            .parse::<u32>()
            .is_ok_and(|number| (1..=32).contains(&number) && number.to_string() == *text)
        {
            return Err((
                -32602,
                "Localization discovery page size must be an integer from one to thirty-two",
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
                    "Expected a bounded exact localization discovery anchor or continuation",
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
        ("max_query_results", "max-query-results", 1024_u64),
    ] {
        if let Some(value) = fields.get(field) {
            let text = value.text().filter(|value| {
                value.parse::<u64>().is_ok_and(|number| (1..=maximum).contains(&number) && number.to_string() == *value)
            }).ok_or((-32602, "Localization discovery read and complete-index limits require bounded canonical decimal strings"))?;
            argv.push(format!("--{flag}={text}").into());
        }
    }
    Ok(argv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Vec<OsString> {
        [
            "query",
            "--json",
            "--root=/operator/fixed",
            "--principal=principal:localization-reader",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    }

    #[test]
    fn localization_selection_dispatches_through_native_parser()
    -> Result<(), Box<dyn std::error::Error>> {
        let fields = BTreeMap::from([
            ("target".into(), Value::Text("localizations".into())),
            ("sensor".into(), Value::Text("sensor:rear".into())),
            ("stream".into(), Value::Text("stream:rear:1".into())),
            (
                "import_id".into(),
                Value::Text(format!("sha256:{}", "a".repeat(64))),
            ),
            (
                "twin_digest".into(),
                Value::Text(format!("sha256:{}", "b".repeat(64))),
            ),
            ("max_entries".into(), Value::Number("2".into())),
            ("max_query_results".into(), Value::Text("64".into())),
        ]);
        let command =
            fss_cli::parse_fss_args(arguments(&fields, base()).map_err(|(_, reason)| reason)?)?;
        let fss_cli::FssCommand::LocalizationsQuery(args) = command else {
            return Err("localizations query command".into());
        };
        assert_eq!(
            args.request
                .filter
                .sensor_id
                .as_ref()
                .map(|value| value.as_str()),
            Some("sensor:rear")
        );
        assert_eq!(
            args.request
                .filter
                .stream_id
                .as_ref()
                .map(|value| value.as_str()),
            Some("stream:rear:1")
        );
        assert_eq!(
            args.request
                .filter
                .import_identity
                .map(|value| value.to_text()),
            Some(format!("sha256:{}", "a".repeat(64)))
        );
        assert_eq!(
            args.request.filter.twin_digest.map(|value| value.to_text()),
            Some(format!("sha256:{}", "b".repeat(64)))
        );
        assert_eq!(args.root, std::path::PathBuf::from("/operator/fixed"));
        assert_eq!(
            args.request.principal.as_str(),
            "principal:localization-reader"
        );
        assert_eq!(args.request.max_entries, 2);
        assert_eq!(args.limits.max_localizations, 64);
        Ok(())
    }

    #[test]
    fn discovery_rejects_scope_overrides_and_media_or_execution_arguments() {
        for key in [
            "root",
            "principal",
            "sources",
            "localizations",
            "family",
            "from_ns",
            "at",
            "report_digest",
            "session",
            "verify_source",
            "hydrate",
            "execute",
        ] {
            let fields = BTreeMap::from([
                ("target".into(), Value::Text("localizations".into())),
                (key.into(), Value::Text("ungranted".into())),
            ]);
            assert!(arguments(&fields, base()).is_err(), "{key}");
        }
    }

    #[test]
    fn limits_and_page_size_are_exact_and_bounded() {
        for (key, value) in [
            ("max_entries", Value::Number("0".into())),
            ("max_entries", Value::Number("33".into())),
            ("max_entries", Value::Text("2".into())),
            ("max_entries", Value::Number("1.0".into())),
            ("max_query_read_bytes", Value::Text("268435457".into())),
            ("max_query_read_bytes", Value::Text("01".into())),
            ("max_query_read_objects", Value::Text("65537".into())),
            ("max_query_results", Value::Text("1025".into())),
            ("max_query_results", Value::Number("16".into())),
            (
                "import_id",
                Value::Text(format!("sha256:{}", "0".repeat(64))),
            ),
            (
                "import_id",
                Value::Text(format!("sha256:{}", "A".repeat(64))),
            ),
            (
                "twin_digest",
                Value::Text(format!("blake3:{}", "a".repeat(64))),
            ),
            ("twin_digest", Value::Text("malformed".into())),
            ("sensor", Value::Text(String::new())),
            ("stream", Value::Text("s".repeat(129))),
        ] {
            let fields = BTreeMap::from([
                ("target".into(), Value::Text("localizations".into())),
                (key.into(), value),
            ]);
            assert!(arguments(&fields, base()).is_err(), "{key}");
        }
    }
}
