#![forbid(unsafe_code)]
//! Command adapter contracts. Retained storage is covered by the separate process fixture.

use super::*;
use fss_cli::json_input::{Value, parse as parse_json};
use fss_core::LedgerAnchor;
use fss_graph_algorithms::{CoverageObservation, GraphBudget, SensorCoverageProjection};

type Test = Result<(), Box<dyn std::error::Error>>;

fn args(extra: &[&str]) -> Vec<OsString> {
    [
        "capacity",
        "--root",
        "/unused/capacity",
        "--site",
        "site:test",
        "--during",
        "10:20",
        "--rate-unit",
        "megabits-per-second",
        "--cost-unit",
        "routing-points",
        "--node",
        "camera-switch",
        "--node",
        "archive",
        "--camera",
        "sensor:known=camera-switch=6",
        "--recorder",
        "disk=archive=8",
        "--link",
        "primary=camera-switch=archive=4=1",
        "--link",
        "backup=camera-switch=archive=4=3",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(OsString::from)
    .collect()
}
fn source() -> Result<CoverageGraphReport, Box<dyn std::error::Error>> {
    let projection = SensorCoverageProjection::build(
        "site:test",
        &[
            CoverageObservation {
                sensor_id: "sensor:known".into(),
                zone_scope: "zone:gate".into(),
                witnesses: 1,
            },
            CoverageObservation {
                sensor_id: "sensor:unseen".into(),
                zone_scope: "zone:gate".into(),
                witnesses: 0,
            },
        ],
    )?;
    let answer = projection.single_points(GraphBudget::registered(&projection.graph))?;
    let anchor = LedgerAnchor::genesis("site:test");
    let projection_id = "synthetic-capacity-window-fixture".to_owned();
    let witness = answer.analysis.witness(&projection_id, anchor.clone())?;
    Ok(CoverageGraphReport {
        site: "site:test".into(),
        anchor,
        projection_id,
        records: 0,
        projection,
        answer,
        witness,
    })
}
fn field<'a>(value: &'a Value, name: &str) -> Result<&'a Value, String> {
    value
        .object()
        .and_then(|object| object.get(name))
        .ok_or_else(|| format!("missing {name}"))
}
fn rendered(request: &Request, source: &CoverageGraphReport) -> Result<String, String> {
    let support = retained_support(request, source, &|| false)?;
    let analysis =
        stream_capacity::analyze(&request.query, request.budget).map_err(|e| e.to_string())?;
    render(request, source, support, &analysis)
}

#[test]
fn cheapest_feasible_routing_keeps_complete_topology_source_and_proofs() -> Test {
    let request = parse(&args(&[]))?;
    let source = source()?;
    let text = rendered(&request, &source)?;
    let value = parse_json(&text)?;
    assert_eq!(field(&value, "format")?.text(), Some(FORMAT));
    assert_eq!(field(&value, "status")?.text(), Some("fully_routed"));
    assert_eq!(field(&value, "requested")?.integer(), Some(6));
    assert_eq!(field(&value, "delivered")?.integer(), Some(6));
    assert_eq!(field(&value, "total_cost")?.integer(), Some(10));
    assert_eq!(
        field(&value, "source_coverage_witness_digest")?.text(),
        Some(source.witness.digest().to_text().as_str())
    );
    assert_eq!(field(&value, "links")?.array().ok_or("links")?.len(), 2);
    for name in ["maximum_flow_proof", "minimum_cost_proof"] {
        let proof = field(&value, name)?;
        assert!(field(proof, "output")?.object().is_some());
        assert_eq!(
            field(field(proof, "witness")?, "stopReason")?.text(),
            Some("completed")
        );
    }
    assert_eq!(
        field(&value, "authority")?.text(),
        Some("derived_cognition_no_effect_authority")
    );
    Ok(())
}

#[test]
fn declared_failure_preserves_camera_demand_and_exposes_shortfall() -> Test {
    let request = parse(&args(&["--failed-node", "camera-switch"]))?;
    let value = parse_json(&rendered(&request, &source()?)?)?;
    assert_eq!(field(&value, "status")?.text(), Some("capacity_shortfall"));
    assert_eq!(field(&value, "requested")?.integer(), Some(6));
    assert_eq!(field(&value, "delivered")?.integer(), Some(0));
    assert_eq!(field(&value, "shortfall")?.integer(), Some(6));
    assert_eq!(field(&value, "cameras")?.array().ok_or("cameras")?.len(), 1);
    assert!(!field(&value, "cut")?.array().ok_or("cut")?.is_empty());
    Ok(())
}

#[test]
fn zero_retained_support_does_not_invent_coverage_or_suppress_requested_rate() -> Test {
    let request = parse(&args(&["--camera", "sensor:unseen=camera-switch=2"]))?;
    let value = parse_json(&rendered(&request, &source()?)?)?;
    assert_eq!(field(&value, "delivered")?.integer(), Some(8));
    let rows = field(&value, "retained_sensor_support")?
        .array()
        .ok_or("support rows")?;
    assert_eq!(rows.len(), 2);
    assert_eq!(
        field(&rows[1], "qualifying_witness_count")?.integer(),
        Some(0)
    );
    assert!(
        field(&rows[1], "qualifying_zones")?
            .array()
            .ok_or("zones")?
            .is_empty()
    );
    let unknown = parse(&args(&["--camera", "sensor:unknown=camera-switch=1"]))?;
    assert!(rendered(&unknown, &source()?).is_err());
    Ok(())
}

#[test]
fn complete_report_is_canonical_under_declaration_order_and_binds_changes() -> Test {
    let original = args(&[]);
    let mut reversed = vec![OsString::from("capacity")];
    for pair in original[1..].as_chunks::<2>().0.iter().rev() {
        reversed.extend_from_slice(pair);
    }
    let source = source()?;
    let a = rendered(&parse(&original)?, &source)?;
    assert_eq!(a, rendered(&parse(&reversed)?, &source)?);
    let b = rendered(&parse(&args(&["--failed-link", "primary"]))?, &source)?;
    let (a, b) = (parse_json(&a)?, parse_json(&b)?);
    assert_ne!(field(&a, "witness_digest")?, field(&b, "witness_digest")?);
    assert_eq!(
        field(&a, "source_coverage_witness_digest")?,
        field(&b, "source_coverage_witness_digest")?
    );
    Ok(())
}

#[test]
fn malformed_duplicate_unknown_and_unbounded_declarations_fail_before_source_reads() -> Test {
    for extra in [
        vec!["--camera", "sensor:known=camera-switch=1"],
        vec!["--node", "archive"],
        vec!["--link", "primary=camera-switch=archive=4=1"],
        vec!["--failed-node", "unknown"],
        vec!["--failed-link", "unknown"],
        vec!["--camera", "camera=unknown=1"],
        vec!["--link", "self=archive=archive=1=0"],
        vec!["--link", "zero=camera-switch=archive=0=0"],
        vec!["--camera", "zero=camera-switch=0"],
        vec!["--recorder", "rec=archive=-1"],
        vec!["--camera", "extra=camera-switch=18446744073709551616"],
        vec!["--work-units", "50000001"],
        vec!["--work-units", "0"],
        vec!["--timeout-ms", "0"],
        vec!["--max-report-bytes", "2097153"],
        vec!["--expected-coverage", "sha256:broken"],
        vec!["--rate-unit", "another"],
        vec!["--unknown", "value"],
    ] {
        assert!(parse(&args(&extra)).is_err(), "{extra:?}");
    }
    for option in ["--during", "--root", "--site", "--rate-unit", "--cost-unit"] {
        let mut missing = args(&[]);
        let index = missing
            .iter()
            .position(|v| v == option)
            .ok_or("missing fixture option")?;
        missing.drain(index..index + 2);
        assert!(parse(&missing).is_err(), "missing {option}");
    }
    Ok(())
}

#[test]
fn complete_output_and_native_solver_work_bounds_refuse_without_truncation() -> Test {
    let source = source()?;
    assert!(retained_support(&parse(&args(&[]))?, &source, &|| true).is_err());
    assert!(rendered(&parse(&args(&["--max-report-bytes", "1024"]))?, &source).is_err());
    assert!(rendered(&parse(&args(&["--work-units", "1"]))?, &source).is_err());
    let mut request = parse(&args(&[]))?;
    let size = rendered(&request, &source)?.len();
    request.report_bytes = size;
    assert_eq!(rendered(&request, &source)?.len(), size);
    request.report_bytes -= 1;
    assert!(rendered(&request, &source).is_err());
    Ok(())
}
