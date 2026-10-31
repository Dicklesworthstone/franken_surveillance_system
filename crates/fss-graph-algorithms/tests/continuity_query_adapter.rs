#![forbid(unsafe_code)]
//! Exercise the actual pure CLI adapter against the native graph library. No runtime or
//! algorithm stand-in is used; filesystem/process ownership has separate CLI contracts.

#[path = "../../fss-cli/src/continuity_query.rs"]
pub mod continuity_query;
#[path = "../../fss-cli/src/json_input.rs"]
pub mod json_input;
#[path = "../../fss-cli/src/json_output.rs"]
pub mod json_output;

use fss_core::ContentDigest;
use fss_graph_algorithms::certified::Budget;
use json_input::Value;
use json_output::{array, object, string};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
type Test = TestResult<()>;
const FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/continuity/three_camera_handoffs.json");

fn encode(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.clone(),
        Value::Text(v) => string(v),
        Value::Array(v) => array(&v.iter().map(encode).collect::<Vec<_>>()),
        Value::Object(v) => object(
            &v.iter()
                .map(|(k, v)| (k.as_str(), encode(v)))
                .collect::<Vec<_>>(),
        ),
    }
}

fn fixture() -> TestResult<Value> {
    Ok(json_input::parse(std::str::from_utf8(FIXTURE)?)?)
}
fn fields(value: &mut Value) -> TestResult<&mut std::collections::BTreeMap<String, Value>> {
    let Value::Object(value) = value else {
        return Err("fixture object".into());
    };
    Ok(value)
}
fn list(value: &mut Value) -> TestResult<&mut Vec<Value>> {
    let Value::Array(value) = value else {
        return Err("fixture array".into());
    };
    Ok(value)
}
fn required<T>(value: Option<T>) -> TestResult<T> {
    value.ok_or_else(|| "fixture/report required field".into())
}
fn at<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    required(value.object().and_then(|o| o.get(key)))
}
fn run(value: &Value) -> TestResult<Value> {
    let result = continuity_query::analyze(
        encode(value).as_bytes(),
        Budget::new(2_000_000, 32_768),
        continuity_query::MAX_REPORT_BYTES,
        &|| false,
    )?;
    Ok(json_input::parse(&result)?)
}
fn admit_count(value: &Value) -> TestResult<usize> {
    let mut count = 0;
    for row in required(at(value, "transitions")?.array())? {
        if at(row, "admitted")?.boolean() == Some(true) {
            count += 1;
        }
    }
    Ok(count)
}

#[test]
fn three_camera_query_keeps_global_paths_complete_family_and_real_certificates() -> Test {
    let output = run(&fixture()?)?;
    assert_eq!(
        at(&output, "schema")?.text(),
        Some(continuity_query::REPORT_SCHEMA)
    );
    assert_eq!(
        at(&output, "source_provenance")?.text(),
        Some("owner_declared_handles_not_authenticated_custody")
    );
    assert_eq!(
        at(&output, "physical_identity_established")?.boolean(),
        Some(false)
    );
    assert_eq!(
        at(&output, "displayed_prefix_complete")?.boolean(),
        Some(false)
    );
    let alternatives = at(&output, "alternatives")?.array().ok_or("alternatives")?;
    assert_eq!(alternatives.len(), 2);
    for alternative in alternatives {
        assert_eq!(at(alternative, "total_cost")?.integer(), Some(22));
        let paths = at(alternative, "paths")?
            .array()
            .ok_or("paths")?
            .iter()
            .map(|path| path.array().ok_or("report path"))
            .collect::<Result<Vec<_>, _>>()?;
        let mut ids = paths
            .iter()
            .flat_map(|path| path.iter())
            .map(|id| id.text().ok_or("report id"))
            .collect::<Result<Vec<_>, _>>()?;
        ids.sort_unstable();
        assert_eq!(ids, vec!["a", "b", "c", "x"]);
        assert!(paths.iter().any(|path| path.len() == 3));
    }
    let family = at(&output, "alternative_family")?;
    assert_eq!(
        at(family, "complete_for_declared_domain")?.boolean(),
        Some(true)
    );
    assert_eq!(at(family, "edges")?.array().ok_or("edges")?.len(), 5);
    assert_eq!(
        at(at(family, "all_singletons")?, "total_cost")?.integer(),
        Some(40)
    );
    assert_eq!(
        at(&output, "transitions")?
            .array()
            .ok_or("transitions")?
            .len(),
        12
    );
    assert_eq!(admit_count(&output)?, 5);
    for name in ["continuity_certificate", "matching_certificate"] {
        let proof = at(&output, name)?;
        assert_eq!(at(proof, "stop_reason")?.text(), Some("completed"));
        assert!(at(proof, "operations")?.integer().ok_or("operations")? > 0);
        ContentDigest::parse(at(proof, "input_digest")?.text().ok_or("digest")?)?;
        ContentDigest::parse(at(proof, "output_digest")?.text().ok_or("digest")?)?;
        assert!(
            !at(proof, "operation_counts")?
                .object()
                .ok_or("counters")?
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn declaration_order_changes_document_pin_but_not_canonical_query_or_answer() -> Test {
    let original = fixture()?;
    let mut reordered = original.clone();
    for key in ["tracklets", "transitions"] {
        list(fields(&mut reordered)?.get_mut(key).ok_or("field")?)?.reverse();
    }
    let mut before = run(&original)?;
    let mut after = run(&reordered)?;
    let before_pin = fields(&mut before)?.remove("input_document_digest");
    let after_pin = fields(&mut after)?.remove("input_document_digest");
    assert_ne!(before_pin, after_pin);
    assert_eq!(before, after);
    Ok(())
}

#[test]
fn unavailable_support_keeps_tracklets_and_explains_every_rejected_transition() -> Test {
    for support in ["missing", "invalidated", "redacted"] {
        let mut input = fixture()?;
        let row = fields(&mut list(fields(&mut input)?.get_mut("tracklets").ok_or("tracks")?)?[2])?;
        assert_eq!(row.get("id").and_then(Value::text), Some("b"));
        row.insert("support".into(), Value::Text(support.into()));
        row.insert("evidence".into(), Value::Array(Vec::new()));
        let output = run(&input)?;
        assert_eq!(at(&output, "tracklets")?.array().ok_or("tracks")?.len(), 4);
        assert_eq!(admit_count(&output)?, 2);
        for alternative in at(&output, "alternatives")?.array().ok_or("alternatives")? {
            assert!(
                at(alternative, "paths")?
                    .array()
                    .ok_or("paths")?
                    .iter()
                    .any(|path| path
                        .array()
                        .is_some_and(|p| p.len() == 1 && p[0].text() == Some("b")))
            );
        }
        for row in at(&output, "transitions")?.array().ok_or("transitions")? {
            if at(row, "from")?.text() == Some("b") || at(row, "to")?.text() == Some("b") {
                assert_eq!(at(row, "admitted")?.boolean(), Some(false));
                assert!(!at(row, "reasons")?.array().ok_or("reasons")?.is_empty());
            }
        }
    }
    Ok(())
}

#[test]
fn widening_intervals_and_mixing_model_spaces_cannot_add_stronger_handoffs() -> Test {
    let mut wider = fixture()?;
    let row = fields(&mut list(fields(&mut wider)?.get_mut("tracklets").ok_or("tracks")?)?[2])?;
    row.insert(
        "start".into(),
        Value::Array(vec![Value::Number("6".into()), Value::Number("13".into())]),
    );
    let wider = run(&wider)?;
    assert_eq!(admit_count(&wider)?, 3);
    let mut mixed = fixture()?;
    let row = fields(&mut list(fields(&mut mixed)?.get_mut("tracklets").ok_or("tracks")?)?[2])?;
    row.insert(
        "model".into(),
        Value::Text(ContentDigest::sha256(b"different model generation").to_text()),
    );
    assert_eq!(admit_count(&run(&mixed)?)?, 2);
    Ok(())
}

#[test]
fn strict_query_boundary_refuses_unknown_fields_numeric_coercion_and_bad_pins() -> Test {
    for (field, value) in [
        ("extra", Value::Bool(true)),
        ("schema", Value::Text("wrong".into())),
        ("birth_cost", Value::Text("5".into())),
        ("birth_cost", Value::Number("5.0".into())),
        ("birth_cost", Value::Number("5e0".into())),
        ("birth_cost", Value::Number("-1".into())),
        ("end_cost", Value::Number("18446744073709551616".into())),
        ("k", Value::Number("0".into())),
        ("k", Value::Number("33".into())),
    ] {
        let mut query = fixture()?;
        fields(&mut query)?.insert(field.into(), value);
        assert!(run(&query).is_err(), "accepted {field}");
    }
    let mut missing = fixture()?;
    fields(&mut missing)?.remove("scope");
    assert!(run(&missing).is_err());
    let mut zero = fixture()?;
    fields(fields(&mut zero)?.get_mut("scope").ok_or("scope")?)?.insert(
        "clock".into(),
        Value::Text(format!("sha256:{}", "0".repeat(64))),
    );
    assert!(run(&zero).is_err());
    let duplicate = format!("{{\"k\":2,{}", &encode(&fixture()?)[1..]);
    assert!(continuity_query::parse_query(duplicate.as_bytes()).is_err());
    assert!(continuity_query::parse_query(&[255]).is_err());
    Ok(())
}

#[test]
fn cancellation_budget_and_complete_report_bounds_fail_without_partial_result() -> Test {
    let budget = Budget::new(2_000_000, 32_768);
    let cancelled = continuity_query::analyze(FIXTURE, budget, 2 * 1024 * 1024, &|| true)
        .err()
        .ok_or("expected cancellation")?;
    assert!(matches!(cancelled, continuity_query::QueryError::Cancelled));
    assert_eq!(cancelled.code(), "ERR-GRAPH-CANCELLED-001");
    let exhausted =
        continuity_query::analyze(FIXTURE, Budget::new(1, 32_768), 2 * 1024 * 1024, &|| false)
            .err()
            .ok_or("expected work exhaustion")?;
    assert!(matches!(
        exhausted,
        continuity_query::QueryError::Graph(
            fss_graph_algorithms::GraphError::BudgetExhausted { .. }
        )
    ));
    let oversized = continuity_query::analyze(FIXTURE, budget, 1024, &|| false)
        .err()
        .ok_or("expected output ceiling refusal")?;
    assert!(matches!(
        oversized,
        continuity_query::QueryError::ReportLimit
    ));
    assert_eq!(oversized.code(), "ERR-SCENE-FUSION-LIMIT-001");
    let report = continuity_query::analyze(FIXTURE, budget, 2 * 1024 * 1024, &|| false)?;
    assert!(continuity_query::analyze(FIXTURE, budget, report.len(), &|| false).is_err());
    assert_eq!(
        continuity_query::analyze(FIXTURE, budget, report.len() + 1, &|| false)?,
        report
    );
    let parsed = json_input::parse(&report)?;
    assert_eq!(
        at(&parsed, "input_document_digest")?.text(),
        Some(ContentDigest::sha256(FIXTURE).to_text().as_str())
    );
    Ok(())
}

#[test]
fn shared_json_primitives_preserve_legacy_escaping_and_parse_exactly() -> Test {
    let source = "quote\" slash\\ newline\n\r\t\x08\x0c\0\u{001f}\u{007f}\u{0085}\u{2028}\u{2029}é";
    let encoded = string(source);
    assert!(encoded.contains("\\u2028\\u2029"));
    assert!(encoded.contains("\\u0000\\u001f\\u007f\\u0085"));
    assert_eq!(json_input::parse(&encoded)?.text(), Some(source));
    assert_eq!(
        object(&[
            ("b", "1".into()),
            ("a", array(&["true".into(), "null".into()]))
        ]),
        "{\"b\":1,\"a\":[true,null]}"
    );
    Ok(())
}
