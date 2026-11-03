#![forbid(unsafe_code)]
//! Exact production pure projection and CLI adapter against real core/graph implementations.
//! Typed fixtures here test transforms and serialization, never fabricate a sealed authenticated
//! projection. Real custody, privacy and deletion checks have separate reference-owner tests.

#[path = "../../fss-cli/src/continuity_query.rs"]
pub mod continuity_query;
#[path = "../../fss-cli/src/json_input.rs"]
pub mod json_input;
#[path = "../../fss-cli/src/json_output.rs"]
pub mod json_output;
#[path = "../../fss-cli/src/retained_continuity_query.rs"]
pub mod retained_continuity_query;
#[path = "../../fss-reference/src/ingest/package_handoffs/contract.rs"]
pub mod retained_handoff_contract;

use fss_core::{ContentDigest, LedgerAnchor};
use fss_graph_algorithms::certified::Budget;
use json_input::Value;
use json_output::{array, object, string};
use retained_continuity_query::{RetainedReportInput, analyze, parse_query};
use retained_handoff_contract::{
    PackageHandoffBinding, PackageHandoffContractError, PackageHandoffObservation,
    PackageHandoffRequest, camera_generation, continuity_query as project, model_comparison_key,
    projection_bytes,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
type Test = TestResult<()>;
const FIXTURE: &[u8] =
    include_bytes!("../../../tests/fixtures/continuity/retained_package_selection.json");

fn h(text: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::sha256(text.as_ref())
}
fn required<T>(value: Option<T>) -> TestResult<T> {
    value.ok_or_else(|| "required fixture value".into())
}
fn at<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    required(value.object().and_then(|o| o.get(key)))
}
fn fields(value: &mut Value) -> TestResult<&mut std::collections::BTreeMap<String, Value>> {
    match value {
        Value::Object(v) => Ok(v),
        _ => Err("expected fixture object".into()),
    }
}
fn list(value: &mut Value) -> TestResult<&mut Vec<Value>> {
    match value {
        Value::Array(v) => Ok(v),
        _ => Err("expected fixture array".into()),
    }
}
fn selection(value: &mut Value) -> TestResult<&mut Value> {
    required(list(required(fields(value)?.get_mut("selections"))?)?.first_mut())
}
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

fn bindings(
    request: &PackageHandoffRequest,
    anchor: &LedgerAnchor,
) -> TestResult<Vec<PackageHandoffBinding>> {
    request
        .selections
        .iter()
        .enumerate()
        .map(|(n, s)| {
            let base = 100 + 30 * n as i128;
            let sensor = format!("sensor:{}", s.id);
            let observations = (0..2)
                .map(|index| {
                    let capture = [base + index as i128 * 10, base + index as i128 * 10 + 2];
                    Ok(PackageHandoffObservation {
                        segment: index as u64,
                        capsule_digest: h(format!("{}-capsule-{index}", s.id)),
                        source_digest: h(format!("{}-source-{index}", s.id)),
                        capture,
                        aligned_capture: s.alignment.align(capture)?,
                        detection_row: 7,
                        class_index: 0,
                        score_bits: 0.75_f32.to_bits(),
                        bounds: [256, 256, 1024, 2048],
                        inference_identity: h(format!("{}-inference-{index}", s.id)),
                        output_digest: h(format!("{}-output-{index}", s.id)),
                        detection_report_digest: h(format!("{}-head-{index}", s.id)),
                        confirmed: index + 1 >= s.tracking.confirmation_hits as usize,
                    })
                })
                .collect::<TestResult<Vec<_>>>()?;
            let mut value = PackageHandoffBinding {
                id: s.id.clone(),
                report_digest: s.report_digest,
                analysis_digest: h(format!("{}-analysis", s.id)),
                record_digest: h(format!("{}-record", s.id)),
                retained_root: h(format!("{}-retained", s.id)),
                import_identity: s.alignment.import_identity,
                import_root: h(format!("{}-import-root", s.id)),
                retained_anchor: anchor.clone(),
                track: s.track,
                sensor_id: sensor.clone(),
                stream_id: s.alignment.stream_id.clone(),
                clock_basis: s.alignment.clock_basis,
                capture_time_label: "operator_assumption".into(),
                dimensions: [64, 48],
                camera_generation: camera_generation(&sensor, &s.alignment.stream_id, [64, 48])?,
                calibration: s.calibration,
                model: h("placeholder"),
                package_digest: h("same-package"),
                manifest_digest: h("same-manifest"),
                model_digest: h("same-model"),
                graph_digest: h("same-graph"),
                contract_digest: h("same-head"),
                model_id: "MOD-SYNTHETIC-001".into(),
                model_generation: "model:synthetic:g1".into(),
                label: s.label.clone(),
                class_index: 0,
                tracking: s.tracking,
                privacy_binding: h("explicit-unmasked-fixture"),
                privacy_policy: None,
                alignment: s.alignment.clone(),
                confirmed: true,
                observations,
            };
            value.model = model_comparison_key(&value);
            Ok(value)
        })
        .collect()
}

fn report(
    request: &PackageHandoffRequest,
    anchor: &LedgerAnchor,
    bindings: &[PackageHandoffBinding],
    maximum: usize,
    cancelled: &dyn Fn() -> bool,
) -> TestResult<String> {
    let query = project(anchor, request, bindings)?;
    let bytes = projection_bytes(anchor, request, bindings)?;
    Ok(analyze(
        RetainedReportInput {
            input_document: h(FIXTURE),
            projection_digest: h(bytes),
            anchor,
            bindings,
            query: &query,
        },
        Budget::new(2_000_000, 32_768),
        maximum,
        cancelled,
    )?)
}

#[test]
fn source_projection_preserves_exact_observations_and_drives_real_native_handoffs() -> Test {
    let request = parse_query(FIXTURE)?;
    let anchor = LedgerAnchor::genesis("property:synthetic-fixture");
    let bindings = bindings(&request, &anchor)?;
    let query = project(&anchor, &request, &bindings)?;
    assert_eq!(query.tracklets[0].start, [98, 105]);
    assert_eq!(query.tracklets[0].end, [108, 115]);
    assert_eq!(query.time_unit, "nanoseconds");
    let output = report(
        &request,
        &anchor,
        &bindings,
        retained_continuity_query::MAX_REPORT_BYTES,
        &|| false,
    )?;
    let value = json_input::parse(&output)?;
    assert_eq!(
        at(&value, "schema")?.text(),
        Some(retained_continuity_query::REPORT_SCHEMA)
    );
    assert_eq!(
        at(&value, "physical_identity_established")?.boolean(),
        Some(false)
    );
    let rows = required(at(&value, "bindings")?.array())?;
    assert_eq!(rows.len(), 2);
    assert_eq!(at(&rows[0], "clock_basis")?.text(), Some("estimated"));
    let observations = required(at(&rows[0], "observations")?.array())?;
    assert_eq!(observations.len(), 2);
    assert_eq!(at(&observations[0], "confirmed")?.boolean(), Some(false));
    assert_eq!(at(&observations[1], "confirmed")?.boolean(), Some(true));
    let conditional = at(&value, "conditional_analysis")?;
    assert_eq!(
        at(conditional, "source_provenance")?.text(),
        Some("owner_declared_handles_not_authenticated_custody")
    );
    let alternatives = required(at(conditional, "alternatives")?.array())?;
    assert_eq!(alternatives.len(), 2);
    assert_eq!(at(&alternatives[0], "total_cost")?.integer(), Some(11));
    assert_eq!(at(&alternatives[1], "total_cost")?.integer(), Some(20));
    assert_eq!(
        at(at(conditional, "continuity_certificate")?, "stop_reason")?.text(),
        Some("completed")
    );
    // Retained by the explicit --nocapture native lane for independent schema checking.
    println!("retained-handoff-native-report:{output}");
    Ok(())
}

#[test]
fn strict_selection_cannot_inject_source_facts_or_coerce_integer_controls() -> Test {
    for key in [
        "capture",
        "camera",
        "model",
        "privacy_policy",
        "property",
        "source_authenticated",
    ] {
        let mut value = fixture()?;
        fields(selection(&mut value)?)?.insert(key.into(), Value::Text("invented".into()));
        assert!(
            parse_query(encode(&value).as_bytes()).is_err(),
            "accepted injected {key}"
        );
    }
    for bad in [
        Value::Text("2".into()),
        Value::Number("2.0".into()),
        Value::Number("2e0".into()),
        Value::Number("-1".into()),
        Value::Number("33".into()),
    ] {
        let mut value = fixture()?;
        fields(&mut value)?.insert("k".into(), bad);
        assert!(parse_query(encode(&value).as_bytes()).is_err());
    }
    let text = std::str::from_utf8(FIXTURE)?;
    assert!(
        parse_query(
            text.replacen("\"k\": 2", "\"k\": 2, \"k\": 2", 1)
                .as_bytes()
        )
        .is_err()
    );
    assert!(parse_query(&[0xff]).is_err());
    assert!(parse_query(&vec![b' '; retained_continuity_query::MAX_INPUT_BYTES + 1]).is_err());
    Ok(())
}

#[test]
fn duplicate_aliases_missing_members_and_excessive_recipes_refuse_before_source_work() -> Test {
    let original = parse_query(FIXTURE)?;
    let mut request = original.clone();
    request.selections[1].id = request.selections[0].id.clone();
    assert!(request.validate().is_err());
    let mut request = original.clone();
    request.selections[1].report_digest = request.selections[0].report_digest;
    request.selections[1].track = request.selections[0].track;
    assert!(request.validate().is_err());
    let mut request = original.clone();
    request.transitions[0].to = "absent".into();
    assert!(request.validate().is_err());
    let mut request = original.clone();
    request.selections[0].tracking.maximum_missed_frames = 0;
    assert!(request.validate().is_err());
    request.selections[0].tracking.maximum_missed_frames = 65;
    assert!(request.validate().is_err());
    let mut request = original.clone();
    request.transitions.clear();
    for index in 2..5 {
        let mut selected = original.selections[0].clone();
        selected.id = format!("extra{index}");
        selected.report_digest = h(format!("report-{index}"));
        selected.track = h(format!("track-{index}"));
        request.selections.push(selected);
    }
    assert_eq!(request.validate(), Err(PackageHandoffContractError::Limit));
    Ok(())
}

#[test]
fn canonical_projection_is_order_independent_and_binds_all_assumptions() -> Test {
    let mut request = parse_query(FIXTURE)?;
    let anchor = LedgerAnchor::genesis("property:synthetic-fixture");
    let mut values = bindings(&request, &anchor)?;
    let original = projection_bytes(&anchor, &request, &values)?;
    let request_digest = request.digest()?;
    values.reverse();
    request.selections.reverse();
    request.transitions.reverse();
    assert_eq!(projection_bytes(&anchor, &request, &values)?, original);
    assert_eq!(request.digest()?, request_digest);
    request.clock = h("different-common-clock");
    assert_ne!(projection_bytes(&anchor, &request, &values)?, original);
    let mut changed_anchor = anchor.clone();
    changed_anchor.commit_sequence = 1;
    assert_ne!(
        projection_bytes(&changed_anchor, &request, &values)?,
        projection_bytes(&anchor, &request, &values)?
    );
    Ok(())
}

#[test]
fn conservative_clock_mapping_never_truncates_or_overflows_original_intervals() -> Test {
    let request = parse_query(FIXTURE)?;
    let mut alignment = request.selections[0].alignment.clone();
    assert_eq!(alignment.align([100, 102])?, [98, 105]);
    alignment.offset_ns = [-5, 7];
    assert_eq!(alignment.align([100, 102])?, [95, 109]);
    alignment.offset_ns = [0, 0];
    assert_eq!(
        alignment.align([i64::MIN as i128, i64::MAX as i128])?,
        [i64::MIN, i64::MAX]
    );
    assert_eq!(
        alignment.align([i64::MAX as i128 + 1, i64::MAX as i128 + 1]),
        Err(PackageHandoffContractError::TimeOverflow)
    );
    alignment.offset_ns = [1, 1];
    assert_eq!(
        alignment.align([i128::MAX, i128::MAX]),
        Err(PackageHandoffContractError::TimeOverflow)
    );
    alignment.offset_ns = [-1, -1];
    assert_eq!(
        alignment.align([i128::MIN, i128::MIN]),
        Err(PackageHandoffContractError::TimeOverflow)
    );
    alignment.offset_ns = [2, 1];
    assert!(alignment.align([0, 1]).is_err());
    Ok(())
}

#[test]
fn mismatched_source_bindings_and_reused_detection_rows_refuse() -> Test {
    let request = parse_query(FIXTURE)?;
    let anchor = LedgerAnchor::genesis("property:synthetic-fixture");
    let original = bindings(&request, &anchor)?;
    let mut value = original.clone();
    value[0].observations[0].aligned_capture[0] += 1;
    assert!(project(&anchor, &request, &value).is_err());
    let mut value = original.clone();
    value[0].camera_generation = h("invented-generation");
    assert!(project(&anchor, &request, &value).is_err());
    let mut value = original.clone();
    value[0].model = h("invented-model-space");
    assert!(project(&anchor, &request, &value).is_err());
    let mut value = original.clone();
    value[0].retained_anchor.ledger_epoch += 1;
    assert!(project(&anchor, &request, &value).is_err());
    let mut value = original.clone();
    value[0].observations[0].confirmed = true;
    assert!(project(&anchor, &request, &value).is_err());
    let mut value = original.clone();
    value[1].observations[0].capsule_digest = value[0].observations[0].capsule_digest;
    assert!(project(&anchor, &request, &value).is_err());
    let mut value = original;
    value.pop();
    assert!(project(&anchor, &request, &value).is_err());
    Ok(())
}

#[test]
fn model_space_includes_package_head_generation_and_label_not_just_weights() -> Test {
    let request = parse_query(FIXTURE)?;
    let anchor = LedgerAnchor::genesis("property:synthetic-fixture");
    let mut values = bindings(&request, &anchor)?;
    let original = values[0].model;
    values[0].contract_digest = h("other-head");
    assert_ne!(model_comparison_key(&values[0]), original);
    values[0].model = model_comparison_key(&values[0]);
    let query = project(&anchor, &request, &values)?;
    let run = fss_graph_algorithms::continuity::plan(&query, Budget::new(2_000_000, 32_768))?;
    assert!(run.output.family.edges.is_empty());
    assert_eq!(run.output.family.all_singletons.total_cost, 20);
    Ok(())
}

#[test]
fn cancellation_and_complete_report_limits_never_release_partial_answers() -> Test {
    let request = parse_query(FIXTURE)?;
    let anchor = LedgerAnchor::genesis("property:synthetic-fixture");
    let values = bindings(&request, &anchor)?;
    assert!(
        report(
            &request,
            &anchor,
            &values,
            retained_continuity_query::MAX_REPORT_BYTES,
            &|| true
        )
        .is_err()
    );
    assert!(report(&request, &anchor, &values, 1024, &|| false).is_err());
    let output = report(
        &request,
        &anchor,
        &values,
        retained_continuity_query::MAX_REPORT_BYTES,
        &|| false,
    )?;
    assert_eq!(
        report(&request, &anchor, &values, output.len() + 1, &|| false)?,
        output
    );
    assert!(report(&request, &anchor, &values, output.len(), &|| false).is_err());
    Ok(())
}
