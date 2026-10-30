#![forbid(unsafe_code)]
//! Adapter tests over synthetic coverage; the process test exercises actual retained custody.

use super::*;
use fss_cli::json_input::{Value, parse as parse_json};
use fss_core::LedgerAnchor;
use fss_graph_algorithms::{CoverageObservation, GraphBudget, SensorCoverageProjection};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn args(extra: &[&str]) -> Vec<OsString> {
    [
        "placement",
        "--root",
        "/unused/placement",
        "--site",
        "site:test",
        "--during",
        "10:20",
        "--zone",
        "zone:entry",
        "--zone",
        "zone:target",
        "--entry",
        "zone:entry",
        "--target",
        "zone:target",
        "--move",
        "zone:entry=zone:target",
        "--candidate",
        "sensor:new=5:1:zone:entry",
        "--installation-budget",
        "5",
        "--installation-cost-unit",
        "installation-points",
        "--sensor-loss-cost-unit",
        "sensor-count",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(OsString::from)
    .collect()
}

fn request(extra: &[&str]) -> Result<PlacementRequest, String> {
    parse(&args(extra))
        .map_err(|e| format!("{e:?}"))?
        .ok_or_else(|| "fixture asked for help".into())
}

fn source() -> Result<CoverageGraphReport, Box<dyn std::error::Error>> {
    let projection = SensorCoverageProjection::build(
        "site:test",
        &[
            CoverageObservation {
                sensor_id: "sensor:old".into(),
                zone_scope: "zone:target".into(),
                witnesses: 1,
            },
            CoverageObservation {
                sensor_id: "sensor:unseen".into(),
                zone_scope: "zone:entry".into(),
                witnesses: 0,
            },
        ],
    )?;
    let answer = projection.single_points(GraphBudget::registered(&projection.graph))?;
    let anchor = LedgerAnchor::genesis("site:test");
    let projection_id = "synthetic-placement-fixture".to_owned();
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

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, String> {
    value
        .object()
        .and_then(|o| o.get(key))
        .ok_or_else(|| format!("missing field {key}"))
}

#[test]
fn additive_camera_is_hypothetical_and_zero_witness_sensor_is_not_support() -> TestResult {
    let request = request(&[])?;
    let source = source()?;
    let query = problem(&request, &source).map_err(|e| format!("{e:?}"))?;
    assert!(query.baseline.observers["zone:entry"].is_empty());
    assert_eq!(
        query.baseline.costs.keys().cloned().collect::<Vec<_>>(),
        vec!["sensor:old"]
    );
    let text = select(&request, &source, &|| false).map_err(|e| format!("{e:?}"))?;
    let report = parse_json(&text)?;
    assert_eq!(
        field(field(&report, "baseline")?, "sensor_loss_cost_units")?.integer(),
        Some(1)
    );
    assert_eq!(
        field(field(&report, "defended")?, "sensor_loss_cost_units")?.integer(),
        Some(2)
    );
    assert_eq!(
        field(&report, "installation_cost_units")?.integer(),
        Some(5)
    );
    assert_eq!(
        field(field(&report, "declared_problem")?, "provenance")?.text(),
        Some("operator_asserted_hypothetical")
    );
    assert_eq!(
        field(&report, "authority")?.text(),
        Some("derived_cognition_no_effect_authority")
    );
    assert_eq!(
        field(&report, "source_coverage_witness_digest")?.text(),
        Some(source.witness.digest().to_text().as_str())
    );
    Ok(())
}

#[test]
fn input_order_does_not_change_the_complete_report_or_witness() -> TestResult {
    let a = args(&["--candidate", "sensor:other=5:1:zone:target"]);
    let mut b = vec![OsString::from("placement")];
    for pair in a[1..].as_chunks::<2>().0.iter().rev() {
        b.extend_from_slice(pair);
    }
    let a = parse(&a)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("missing request")?;
    let b = parse(&b)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("missing request")?;
    let source = source()?;
    assert_eq!(
        select(&a, &source, &|| false).map_err(|e| format!("{e:?}"))?,
        select(&b, &source, &|| false).map_err(|e| format!("{e:?}"))?
    );
    Ok(())
}

#[test]
fn malformed_and_ambiguous_declarations_refuse_before_source_io() {
    for extra in [
        vec!["--entry", "zone:entry"],
        vec!["--move", "zone:entry=zone:target"],
        vec!["--move", "zone:target=zone:target"],
        vec!["--move", "zone:entry=zone:unknown"],
        vec!["--candidate", "sensor:new=4:1:zone:target"],
        vec!["--candidate", "sensor:bad=4:1:zone:unknown"],
        vec!["--candidate", "sensor:bad=4:1:zone:target,zone:target"],
        vec!["--candidate", "sensor:bad=4:1:"],
        vec!["--candidate", "sensor:bad=4:zone:target"],
        vec![
            "--candidate",
            "sensor:bad=18446744073709551616:1:zone:target",
        ],
        vec!["--installation-budget", "1"],
        vec!["--max-additions", "17"],
        vec!["--method", "greedy"],
        vec!["--exclude-sensor", "sensor:old"],
        vec!["--unknown", "value"],
    ] {
        assert!(parse(&args(&extra)).is_err(), "{extra:?}");
    }
    assert!(parse(&vec![OsString::from("x"); MAX_ARGS + 1]).is_err());
    assert!(
        parse(&[
            "placement".into(),
            "--help".into(),
            "--root".into(),
            "unused".into()
        ])
        .is_err()
    );
    assert!(run(&["placement".into(), "--help".into()]).is_ok_and(|s| s.contains(FORMAT)));
}

#[test]
fn retained_sensor_collisions_and_unknown_costs_do_not_create_facts() -> TestResult {
    let source = source()?;
    for extra in [
        vec!["--candidate", "sensor:old=1:1:zone:entry"],
        vec!["--candidate", "sensor:unseen=1:1:zone:entry"],
        vec!["--sensor-disable-cost", "sensor:missing=2"],
        vec!["--sensor-disable-cost", "sensor:unseen=2"],
    ] {
        assert!(matches!(
            problem(&request(&extra)?, &source),
            Err(CommandError::Usage(_))
        ));
    }
    Ok(())
}

#[test]
fn exact_work_cancellation_and_complete_output_limits_do_not_emit_partial_optima() -> TestResult {
    let source = source()?;
    assert!(select(&request(&[])?, &source, &|| true).is_err());
    assert!(select(&request(&["--work-units", "1"])?, &source, &|| false).is_err());
    assert!(matches!(
        select(&request(&["--max-report-bytes", "1024"])?, &source, &|| {
            false
        }),
        Err(CommandError::OutputBound)
    ));
    Ok(())
}

#[test]
fn no_additions_and_unreachable_routes_preserve_limited_claims() -> TestResult {
    let source = source()?;
    let report = parse_json(
        &select(&request(&["--max-additions", "0"])?, &source, &|| false)
            .map_err(|e| format!("{e:?}"))?,
    )?;
    assert_eq!(
        field(&report, "selected_sensors")?.array(),
        Some([].as_slice())
    );
    assert_eq!(field(&report, "baseline")?, field(&report, "defended")?);
    let mut values = args(&[]);
    let at = values
        .iter()
        .position(|v| v == "--move")
        .ok_or("move missing")?;
    values.drain(at..at + 2);
    let request = parse(&values)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("request missing")?;
    let report = parse_json(&select(&request, &source, &|| false).map_err(|e| format!("{e:?}"))?)?;
    assert_eq!(
        field(field(&report, "defended")?, "status")?.text(),
        Some("unreachable_in_declared_graph")
    );
    assert_eq!(
        field(field(&report, "defended")?, "sensor_loss_cost_units")?,
        &Value::Null
    );
    assert_eq!(
        field(&report, "selected_sensors")?.array(),
        Some([].as_slice())
    );
    Ok(())
}
