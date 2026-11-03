#![forbid(unsafe_code)]
//! Native admission and rendering through the actual versioned command dispatcher.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::agent_json::{object, string};
use crate::json_input::{Value, parse};

use super::*;

const FIXTURE: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/clock-alignment/validated_sessions.json"
));
const WORK: u64 = 100_000_000;
type Test = std::result::Result<(), String>;

fn document() -> std::result::Result<Value, String> {
    parse(std::str::from_utf8(FIXTURE).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}
fn fields(value: &Value) -> std::result::Result<&BTreeMap<String, Value>, String> {
    value.object().ok_or_else(|| "object".into())
}
fn fields_mut(value: &mut Value) -> std::result::Result<&mut BTreeMap<String, Value>, String> {
    match value {
        Value::Object(f) => Ok(f),
        _ => Err("object".into()),
    }
}
fn rows_mut<'a>(
    value: &'a mut Value,
    key: &str,
) -> std::result::Result<&'a mut Vec<Value>, String> {
    match fields_mut(value)?.get_mut(key) {
        Some(Value::Array(rows)) => Ok(rows),
        _ => Err("array".into()),
    }
}
fn encode(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.clone(),
        Value::Text(v) => string(v),
        Value::Array(rows) => format!(
            "[{}]",
            rows.iter().map(encode).collect::<Vec<_>>().join(",")
        ),
        Value::Object(fields) => object(
            &fields
                .iter()
                .map(|(k, v)| (k.as_str(), encode(v)))
                .collect::<Vec<_>>(),
        ),
    }
}
fn run(value: &Value, work: u64) -> Result<(String, bool)> {
    let bytes = encode(value);
    super::super::analyze(
        bytes.as_bytes(),
        ContentDigest::sha256(bytes.as_bytes()),
        work,
    )
}
fn body(text: &str) -> std::result::Result<BTreeMap<String, Value>, String> {
    let document = parse(text).map_err(|e| e.to_string())?;
    fields(&document)?
        .get("report")
        .and_then(Value::object)
        .cloned()
        .ok_or_else(|| "report".into())
}
fn array<'a>(
    fields: &'a BTreeMap<String, Value>,
    key: &str,
) -> std::result::Result<&'a [Value], String> {
    fields
        .get(key)
        .and_then(Value::array)
        .ok_or_else(|| format!("array {key}"))
}
fn interval(value: &Value) -> std::result::Result<[i128; 2], String> {
    let values = value.array().filter(|v| v.len() == 2).ok_or("interval")?;
    Ok([
        values[0].integer().ok_or("lower")?,
        values[1].integer().ok_or("upper")?,
    ])
}

#[test]
fn disjoint_sessions_can_resolve_static_search_ambiguity_without_narrowing_time_envelopes() -> Test
{
    let (text, supported) = run(&document()?, WORK).map_err(|e| e.detail)?;
    assert!(supported);
    let report = body(&text)?;
    assert_eq!(
        report.get("hypothesis_count").and_then(Value::integer),
        Some(3)
    );
    assert_eq!(
        report
            .get("additional_session_count")
            .and_then(Value::integer),
        Some(2)
    );
    assert_eq!(
        report
            .get("supported_in_every_session_count")
            .and_then(Value::integer),
        Some(1)
    );
    let search = fields(report.get("search").ok_or("search")?)?;
    assert_eq!(
        search
            .get("all_times_supported_count")
            .and_then(Value::integer),
        Some(3)
    );
    assert_eq!(array(search, "sources")?.len(), 10);
    assert_eq!(array(search, "trials")?.len(), 3);
    let sessions = array(&report, "sessions")?;
    assert_eq!(
        fields(&sessions[0])?
            .get("session_id")
            .and_then(Value::integer),
        Some(10)
    );
    assert_eq!(
        fields(&sessions[1])?
            .get("session_id")
            .and_then(Value::integer),
        Some(20)
    );
    for session in sessions {
        let session = fields(session)?;
        assert_eq!(array(session, "trials")?.len(), 3);
        assert_eq!(array(session, "sources")?.len(), 10);
        assert_eq!(
            session
                .get("all_times_supported_count")
                .and_then(Value::integer),
            Some(1)
        );
    }
    for projection in array(&report, "projections")? {
        let projection = fields(projection)?;
        let hull = interval(projection.get("reference_envelope_ns").ok_or("envelope")?)?;
        let mappings = array(projection, "mappings")?;
        assert_eq!(mappings.len(), 3);
        let mut supported_bounds = None;
        for mapping in mappings {
            let mapping = fields(mapping)?;
            let candidate = fields(mapping.get("hypothesis").ok_or("hypothesis")?)?;
            let bounds = interval(mapping.get("reference_interval_ns").ok_or("mapping")?)?;
            assert!(hull[0] <= bounds[0] && bounds[1] <= hull[1]);
            if candidate.get("skew_ppb").and_then(Value::integer) == Some(500_000) {
                supported_bounds = Some(bounds);
            }
        }
        assert_ne!(
            Some(hull),
            supported_bounds,
            "support must not shrink the complete-inventory hull"
        );
    }
    let projections = array(&report, "projections")?;
    assert_eq!(
        array(fields(&projections[0])?, "containing_session_ids")?,
        &[Value::Text("10".into())]
    );
    assert_eq!(
        fields(&projections[1])?
            .get("observation_window")
            .and_then(Value::text),
        Some("outside_declared_sessions")
    );
    for flag in [
        "clock_activated",
        "source_custody_verified",
        "physical_calibration_verified",
        "independent_clock_validation",
        "continuous_rate_or_offset_certified",
        "coverage_or_effect_authority",
    ] {
        assert_eq!(report.get(flag).and_then(Value::boolean), Some(false));
    }
    let response = parse(&text).map_err(|e| e.to_string())?;
    let start = text.rfind("\"report\":").ok_or("report boundary")? + "\"report\":".len();
    let digest = ContentDigest::sha256(text[start..text.len() - 1].as_bytes()).to_text();
    assert_eq!(
        fields(&response)?
            .get("report_digest")
            .and_then(Value::text),
        Some(digest.as_str())
    );
    Ok(())
}

#[test]
fn fresh_labels_and_times_cannot_hide_reused_source_evidence_or_exposures() -> Test {
    for key in ["source_digest", "evidence_digest", "exposure"] {
        let mut value = document()?;
        let alias = fields(&rows_mut(&mut value, "training")?[0])?
            .get(key)
            .cloned()
            .ok_or("pin")?;
        let session = &mut rows_mut(&mut value, "sessions")?[0];
        fields_mut(&mut rows_mut(session, "training")?[0])?.insert(key.into(), alias);
        assert_eq!(
            query(&value).err().ok_or("expected alias refusal")?.code,
            "ERR-CLOCK-ALIGNMENT-INPUT-001"
        );
    }
    // A source cannot move to the other camera in a new session to escape membership checks.
    let mut value = document()?;
    let alias = fields(&rows_mut(&mut value, "training")?[0])?
        .get("source_digest")
        .cloned()
        .ok_or("source")?;
    let session = &mut rows_mut(&mut value, "sessions")?[0];
    fields_mut(&mut rows_mut(session, "training")?[3])?.insert("source_digest".into(), alias);
    assert!(query(&value).is_err());
    Ok(())
}

#[test]
fn session_scope_cannot_override_cameras_clocks_fit_policy_or_hypotheses() -> Test {
    for key in [
        "reference_camera",
        "target_camera",
        "fit_options",
        "hypotheses",
        "world_basis",
    ] {
        let mut value = document()?;
        let replacement = fields(&value)?.get(key).cloned().ok_or("scope")?;
        fields_mut(&mut rows_mut(&mut value, "sessions")?[0])?.insert(key.into(), replacement);
        assert!(query(&value).is_err());
    }
    let mut value = document()?;
    let session = &mut rows_mut(&mut value, "sessions")?[0];
    fields_mut(&mut rows_mut(session, "training")?[0])?
        .insert("clock".into(), Value::Number("21".into()));
    assert!(query(&value).is_err());
    Ok(())
}

#[test]
fn session_and_projection_inventories_refuse_aliases_empty_oversized_or_reversed_membership() -> Test
{
    for field in ["sessions", "projections"] {
        let mut value = document()?;
        let rows = rows_mut(&mut value, field)?;
        let duplicate = fields(&rows[0])?
            .get("id")
            .and_then(Value::integer)
            .ok_or("id")?;
        fields_mut(&mut rows[1])?.insert("id".into(), Value::Text(duplicate.to_string()));
        assert!(query(&value).is_err());
        let mut value = document()?;
        let rows = rows_mut(&mut value, field)?;
        let example = rows[0].clone();
        let limit = if field == "sessions" { 8 } else { 128 };
        *rows = vec![example; limit + 1];
        assert!(query(&value).is_err());
    }
    let mut value = document()?;
    rows_mut(&mut value, "sessions")?.clear();
    assert!(query(&value).is_err());
    let mut value = document()?;
    let projection = &mut rows_mut(&mut value, "projections")?[0];
    rows_mut(projection, "target_interval_ns")?.reverse();
    assert!(query(&value).is_err());
    Ok(())
}

#[test]
fn overlapping_or_clock_reordered_passages_refuse_without_a_successful_prefix() -> Test {
    for shift_only_target in [false, true] {
        let mut value = document()?;
        // Session 10 starts at -24 s; shifting by -16 s overlaps search on both cameras.
        // Shifting only the target by -40 s reverses session order across cameras instead.
        let session = &mut rows_mut(&mut value, "sessions")?[1];
        for group in ["training", "validation"] {
            for row in rows_mut(session, group)? {
                let row = fields_mut(row)?;
                let camera = row.get("camera").and_then(Value::integer).ok_or("camera")?;
                if shift_only_target && camera != 2 {
                    continue;
                }
                let seconds = if shift_only_target { 40 } else { 16 };
                let delta = seconds
                    * if camera == 2 {
                        1_000_500_000_i128
                    } else {
                        1_000_000_000
                    };
                let time = row
                    .get_mut(if group == "training" {
                        "capture_ns"
                    } else {
                        "capture_interval_ns"
                    })
                    .ok_or("time")?;
                if let Value::Array(times) = time {
                    for t in times {
                        *t = Value::Text((t.integer().ok_or("integer")? - delta).to_string());
                    }
                } else {
                    *time = Value::Text((time.integer().ok_or("integer")? - delta).to_string());
                }
            }
        }
        let error = run(&value, WORK)
            .err()
            .ok_or("expected session-window refusal")?;
        assert_eq!(error.code, "ERR-CLOCK-ALIGNMENT-SCAN-001");
        assert!(error.detail.contains(if shift_only_target {
            "order changed"
        } else {
            "overlap"
        }));
    }
    Ok(())
}

#[test]
fn exact_shared_work_budget_never_refills_for_later_sessions_or_output() -> Test {
    let value = document()?;
    let parsed = query(&value).map_err(|e| e.detail)?;
    let mut work = WorkBudget::new(WORK);
    let native = evaluate(&parsed, &mut work).map_err(|e| e.detail)?;
    assert_eq!(native.work_units, work.used());
    let exact = native.work_units;
    assert!(run(&value, exact).is_ok());
    assert_eq!(
        run(&value, exact - 1).err().ok_or("budget refusal")?.code,
        "ERR-CLOCK-ALIGNMENT-LIMIT-001"
    );
    Ok(())
}

#[test]
fn owner_cancellation_during_native_fits_and_late_output_never_becomes_an_unresolved_trial() -> Test
{
    let value = document()?;
    let parsed = query(&value).map_err(|e| e.detail)?;
    let flag = AtomicBool::new(true);
    let mut stopped = WorkBudget::cancellable(WORK, &flag);
    assert_eq!(
        evaluate(&parsed, &mut stopped)
            .err()
            .ok_or("early cancellation")?
            .code,
        "ERR-CLOCK-ALIGNMENT-CANCELLED-001"
    );
    assert_eq!(stopped.used(), 0);
    let encoded = encode(&value);
    let pin = ContentDigest::sha256(encoded.as_bytes());
    let calls = AtomicUsize::new(0);
    let count = || {
        calls.fetch_add(1, Ordering::Relaxed);
        false
    };
    super::super::analyze_with_probe(encoded.as_bytes(), pin, WORK, &count)
        .map_err(|e| e.detail)?;
    let all = calls.load(Ordering::Relaxed);
    for stop in [0, 1, all / 2, all - 1] {
        let calls = AtomicUsize::new(0);
        let cancel = || calls.fetch_add(1, Ordering::Relaxed) >= stop;
        let error = super::super::analyze_with_probe(encoded.as_bytes(), pin, WORK, &cancel)
            .err()
            .ok_or("late cancellation")?;
        assert_eq!(
            error.code, "ERR-CLOCK-ALIGNMENT-CANCELLED-001",
            "stop={stop}: {}",
            error.detail
        );
    }
    Ok(())
}

#[test]
fn output_limit_reserves_the_integrity_wrapper_and_newline_without_truncating_a_session() -> Test {
    let value = document()?;
    let parsed = query(&value).map_err(|e| e.detail)?;
    let mut work = WorkBudget::new(WORK);
    let native = evaluate(&parsed, &mut work).map_err(|e| e.detail)?;
    let pin = ContentDigest::sha256(FIXTURE);
    let complete = report::render(&parsed, &native, pin, WORK, FIXTURE.len(), &mut work)
        .map_err(|e| e.detail)?;
    let exact = complete.len() + 1;
    assert_eq!(
        report::render_with_limit(&parsed, &native, pin, WORK, FIXTURE.len(), &mut work, exact)
            .map_err(|e| e.detail)?,
        complete
    );
    assert_eq!(
        report::render_with_limit(
            &parsed,
            &native,
            pin,
            WORK,
            FIXTURE.len(),
            &mut work,
            exact - 1
        )
        .err()
        .ok_or("output refusal")?
        .code,
        "ERR-CLOCK-ALIGNMENT-LIMIT-001"
    );
    Ok(())
}

#[test]
fn unresolved_candidates_and_empty_projection_requests_remain_explicit() -> Test {
    let mut value = document()?;
    rows_mut(&mut value, "hypotheses")?
        .push(parse(r#"{"offset_ns":"60000000000","skew_ppb":"0"}"#).map_err(|e| e.to_string())?);
    rows_mut(&mut value, "projections")?.clear();
    let (text, supported) = run(&value, WORK).map_err(|e| e.detail)?;
    assert!(supported);
    let report = body(&text)?;
    assert_eq!(
        report.get("hypothesis_count").and_then(Value::integer),
        Some(4)
    );
    assert!(array(&report, "projections")?.is_empty());
    let sessions = array(&report, "sessions")?;
    let trials = array(fields(&sessions[0])?, "trials")?;
    assert_eq!(
        fields(&trials[3])?.get("outcome").and_then(Value::text),
        Some("unresolved")
    );
    Ok(())
}
