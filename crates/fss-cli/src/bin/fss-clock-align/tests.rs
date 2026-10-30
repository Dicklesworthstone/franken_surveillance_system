#![forbid(unsafe_code)]
use super::*;
use fss_cli::json_input::Value;

const FIXTURE: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../fixtures/clock-alignment/moving_feature.json"));
type Test = std::result::Result<(), String>;
fn document() -> std::result::Result<Value, String> {
    parse(std::str::from_utf8(FIXTURE).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}
fn root_mut(value: &mut Value) -> std::result::Result<&mut BTreeMap<String, Value>, String> {
    match value { Value::Object(fields) => Ok(fields), _ => Err("fixture object".into()) }
}
fn row_mut<'a>(value: &'a mut Value, group: &str, index: usize)
    -> std::result::Result<&'a mut BTreeMap<String, Value>, String>
{
    let Some(Value::Array(rows)) = root_mut(value)?.get_mut(group) else { return Err("fixture rows".into()); };
    root_mut(rows.get_mut(index).ok_or("fixture row")?)
}

#[test]
fn complete_native_scan_reports_every_hypothesis_and_preserves_claim_limits() -> Test {
    let (report, supported) = analyze(FIXTURE, ContentDigest::sha256(FIXTURE), DEFAULT_WORK)
        .map_err(|e| e.detail)?;
    assert!(supported);
    let value = parse(&report).map_err(|e| e.to_string())?;
    let body = value.object().and_then(|v| v.get("report")).and_then(Value::object).ok_or("report")?;
    assert_eq!(body.get("hypothesis_count").and_then(Value::integer), Some(3));
    assert_eq!(body.get("all_times_supported_count").and_then(Value::integer), Some(1));
    assert_eq!(body.get("sources").and_then(Value::array).map(|v| v.len()), Some(14));
    for name in ["clock_activated", "continuous_offset_certified", "source_custody_verified",
        "physical_calibration_verified", "independent_clock_validation", "coverage_or_effect_authority"] {
        assert_eq!(body.get(name).and_then(Value::boolean), Some(false));
    }
    let start = report.rfind("\"report\":").ok_or("report body boundary")? + "\"report\":".len();
    let exact_body = report[start..report.len()-1].trim();
    let expected = ContentDigest::sha256(exact_body.as_bytes()).to_text();
    assert_eq!(value.object().and_then(|v| v.get("report_digest")).and_then(Value::text), Some(expected.as_str()));
    Ok(())
}

#[test]
fn digest_mismatch_and_exhausted_shared_budget_never_produce_a_report() {
    assert!(analyze(FIXTURE, ContentDigest::sha256(b"wrong"), DEFAULT_WORK).is_err());
    assert!(analyze(FIXTURE, ContentDigest::sha256(FIXTURE), 1).is_err());
}

#[test]
fn unknown_fields_and_changed_clock_generation_refuse() -> Test {
    let mut value = document()?;
    root_mut(&mut value)?.insert("activate".into(), Value::Bool(true));
    assert!(input::query(&value).is_err());
    let mut value = document()?;
    row_mut(&mut value, "training", 0)?.insert("clock".into(), Value::Number("20".into()));
    assert!(input::query(&value).is_err());
    Ok(())
}

#[test]
fn source_and_evidence_aliases_cannot_disguise_training_validation_reuse() -> Test {
    for key in ["exposure", "source_digest", "evidence_digest"] {
        let mut value = document()?;
        let original = row_mut(&mut value, "training", 0)?.get(key).cloned().ok_or("source field")?;
        row_mut(&mut value, "validation", 0)?.insert(key.into(), original);
        assert!(input::query(&value).is_err());
    }
    Ok(())
}

#[test]
fn argument_boundary_requires_an_independent_pin_and_finite_work() {
    let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
    assert!(options(args(&["--input", "sample.json"])).is_err());
    assert!(options(args(&["--help", "--activate"])).is_err());
    assert!(options(args(&["--input", "a", "--input", "b"])).is_err());
    let pin = ContentDigest::sha256(FIXTURE).to_text();
    assert!(options(args(&["--input", "a", "--input-digest", &pin, "--work-units", "0"])).is_err());
}
