#![forbid(unsafe_code)]
//! Read-only, owner-declared simultaneous-loss scenarios; never independence certificates.

use fss_cli::agent_json::{array, object, string, strings};
use fss_graph_algorithms::GraphBudget;
use fss_graph_algorithms::failure_domains::{
    FailureDomain, FailureDomainKind, MAX_DOMAIN_MEMBERS, MAX_FAILURE_OPERATIONS,
    MAX_FAILURE_OUTPUT_ENTRIES, analyse_failure_domains,
};
use fss_reference::coverage_graph::CoverageGraphReport;

pub(super) const MAX_REPORT_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn parse_domain(value: &str) -> Result<FailureDomain, String> {
    // Bound before allocating member strings. Sensor IDs include the graph's sensor/ prefix.
    if value.len() > 80 + MAX_DOMAIN_MEMBERS * 513 {
        return Err("--failure-domain declaration exceeds its byte limit".to_owned());
    }
    let (label, members) = value
        .split_once('=')
        .ok_or("--failure-domain requires KIND:ID=SENSOR[,SENSOR...]")?;
    let (kind, id) = label
        .split_once(':')
        .ok_or("--failure-domain requires KIND:ID=SENSOR[,SENSOR...]")?;
    let kind = match kind {
        "network" => FailureDomainKind::Network,
        "power" => FailureDomainKind::Power,
        "clock" => FailureDomainKind::Clock,
        "host" => FailureDomainKind::Host,
        _ => return Err("failure domain kind must be network, power, clock, or host".to_owned()),
    };
    let members: Vec<String> = members
        .split(',')
        .take(MAX_DOMAIN_MEMBERS + 1)
        .map(str::to_owned)
        .collect();
    FailureDomain::new(kind, id, &members).map_err(|error| error.to_string())
}

pub(super) fn render(
    value: &CoverageGraphReport,
    domains: &[FailureDomain],
) -> Result<String, String> {
    let result = analyse_failure_domains(
        &value.projection,
        domains,
        GraphBudget {
            max_operations: MAX_FAILURE_OPERATIONS,
            max_output_entries: MAX_FAILURE_OUTPUT_ENTRIES,
        },
    )
    .map_err(|error| format!("{}: {error}", error.stable_id()))?;
    let parent_digest = value.witness.digest().to_text();
    let mut rows = Vec::new();
    let mut bytes = 0_usize;
    for scenario in &result.scenarios {
        // The graph digest binds full membership; the parent binds the source projection,
        // selection rule, exact signed capture endpoints and committed authority anchor.
        let projection_id = format!(
            "DeviceFailureGraph@parent:{parent_digest}@{}",
            scenario.domain.node_id()
        );
        let witness = scenario
            .analysis
            .witness(&projection_id, value.anchor.clone())
            .map_err(|error| format!("common failure witness rejected: {error:?}"))?;
        fss_graph_algorithms::bridges::check_witness_bound(&witness)
            .map_err(|error| format!("{}: {error}", error.stable_id()))?;
        let row = object(&[
            ("kind", string(scenario.domain.kind().as_str())),
            ("id", string(scenario.domain.id())),
            ("members", strings(scenario.domain.members())),
            ("lost_zones", strings(&scenario.lost_zones)),
            ("cut_vertex", string(&scenario.domain.node_id())),
            ("projection_id", string(&projection_id)),
            ("witness", super::witness(&witness)),
            ("witness_digest", string(&witness.digest().to_text())),
        ]);
        bytes += row.len();
        if bytes > MAX_REPORT_BYTES {
            return Err(
                "ERR-GRAPH-BUDGET-EXHAUSTED-001: shared failure report exceeds 8 MiB".to_owned(),
            );
        }
        rows.push(row);
    }
    Ok(object(&[
        ("model", string("independent-simultaneous-member-loss-v1")),
        (
            "declaration_basis",
            string("owner_assertion_not_verified_topology"),
        ),
        ("parent_witness_digest", string(&parent_digest)),
        ("scenarios", array(&rows)),
        ("operations", result.operations.to_string()),
        ("output_entries", result.output_entries.to_string()),
        ("independence", string("unknown")),
        ("undeclared_dependencies", string("unknown_not_absent")),
        ("joint_domain_failures_evaluated", "false".to_owned()),
        ("authority", string("derived_cognition_no_effect_authority")),
        ("qualification", string("implemented_not_qualified")),
        (
            "claim",
            string(
                "conditional loss of retained qualifying witnesses, not current availability, calibrated clock independence, or evidence of absence",
            ),
        ),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_core::LedgerAnchor;
    use fss_graph_algorithms::{CoverageObservation, SensorCoverageProjection};

    fn sample(context: &str) -> Result<CoverageGraphReport, Box<dyn std::error::Error>> {
        let projection = SensorCoverageProjection::build(
            "site:test",
            &[
                CoverageObservation {
                    sensor_id: "sensor:a".to_owned(),
                    zone_scope: "zone:door".to_owned(),
                    witnesses: 1,
                },
                CoverageObservation {
                    sensor_id: "sensor:b".to_owned(),
                    zone_scope: "zone:door".to_owned(),
                    witnesses: 1,
                },
                CoverageObservation {
                    sensor_id: "sensor:c".to_owned(),
                    zone_scope: "zone:blind".to_owned(),
                    witnesses: 0,
                },
            ],
        )?;
        let answer = projection.single_points(GraphBudget::registered(&projection.graph))?;
        let anchor = LedgerAnchor::genesis("site:test");
        let witness = answer.analysis.witness(context, anchor.clone())?;
        Ok(CoverageGraphReport {
            site: "site:test".to_owned(),
            anchor,
            projection_id: context.to_owned(),
            records: 3,
            projection,
            answer,
            witness,
        })
    }

    #[test]
    fn declarations_are_bounded_strict_and_preserve_colon_sensor_ids() -> Result<(), String> {
        let value = parse_domain("network:lan=sensor:b,sensor:a")?;
        assert_eq!(value.kind(), FailureDomainKind::Network);
        assert_eq!(
            value
                .members()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            ["sensor:a", "sensor:b"]
        );
        for malformed in [
            "",
            "network:x",
            "network=x",
            "other:x=a",
            "power:=a",
            "host:x=",
            "clock:x=a,a",
            "network:x=a,",
        ] {
            assert!(parse_domain(malformed).is_err(), "accepted {malformed}");
        }
        assert!(
            parse_domain(&format!(
                "power:x={}",
                vec!["a"; MAX_DOMAIN_MEMBERS + 1].join(",")
            ))
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn shared_loss_is_explicit_and_never_promotes_independence()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = sample("SensorCoverageGraph@commit:0")?;
        let declared = parse_domain("network:lan=sensor:a,sensor:b")?;
        let rendered = render(&value, &[declared])?;
        assert!(rendered.contains("\"lost_zones\":[\"zone:door\"]"));
        assert!(!rendered.contains("\"lost_zones\":[\"zone:blind\""));
        assert!(rendered.contains("\"independence\":\"unknown\""));
        assert!(rendered.contains("owner_assertion_not_verified_topology"));
        assert!(rendered.contains(&value.witness.digest().to_text()));
        assert!(rendered.contains("fss.graph_algorithm_witness.v1"));
        Ok(())
    }

    #[test]
    fn identical_topology_at_different_capture_windows_has_different_scenario_witnesses()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = sample("SensorCoverageGraph@commit:0@capture:1:2:whole-witness-v1")?;
        let second = sample("SensorCoverageGraph@commit:0@capture:2:3:whole-witness-v1")?;
        assert_eq!(first.projection, second.projection);
        let declared = parse_domain("power:circuit=sensor:a,sensor:b")?;
        let a = render(&first, std::slice::from_ref(&declared))?;
        let b = render(&second, &[declared])?;
        assert_ne!(a, b);
        assert!(a.contains(&first.witness.digest().to_text()));
        assert!(!b.contains(&first.witness.digest().to_text()));
        Ok(())
    }

    #[test]
    fn missing_members_do_not_turn_into_a_claim_of_redundancy()
    -> Result<(), Box<dyn std::error::Error>> {
        let value = sample("SensorCoverageGraph@commit:0")?;
        let declared = parse_domain("host:recorder=sensor:missing")?;
        assert!(
            matches!(render(&value, &[declared]), Err(error) if error.contains("ERR-GRAPH-INPUT-INVALID-001"))
        );
        Ok(())
    }
}
