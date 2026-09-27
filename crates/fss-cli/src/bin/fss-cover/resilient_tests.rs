#![forbid(unsafe_code)]
//! Native adapter contracts. Source fixtures here are synthetic graphs, not storage read receipts.
use super::*;
use fss_core::LedgerAnchor;
use fss_graph_algorithms::{CoverageObservation, GraphBudget, SensorCoverageProjection};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn args(extra: &[&str]) -> Vec<OsString> {
    ["select-resilient", "--root", "/unused/resilient", "--site", "site:test", "--during", "10:20", "--zone", "zone:gate"]
        .into_iter().chain(extra.iter().copied()).map(OsString::from).collect()
}
fn request(extra: &[&str]) -> Result<ResilientRequest, String> {
    parse(&args(extra)).map_err(|error| format!("{error:?}"))?
        .ok_or_else(|| "fixture unexpectedly requested help".to_owned())
}
fn source() -> Result<CoverageGraphReport, Box<dyn std::error::Error>> {
    let facts: Vec<_> = ["sensor:a", "sensor:b", "sensor:c"].into_iter().map(|sensor| CoverageObservation {
        sensor_id: sensor.to_owned(), zone_scope: "zone:gate".to_owned(), witnesses: 1,
    }).collect();
    let projection = SensorCoverageProjection::build("site:test", &facts)?;
    let answer = projection.single_points(GraphBudget::registered(&projection.graph))?;
    let anchor = LedgerAnchor::genesis("site:test");
    let projection_id = "synthetic-window-fixture".to_owned();
    let witness = answer.analysis.witness(&projection_id, anchor.clone())?;
    Ok(CoverageGraphReport {
        site: "site:test".to_owned(), anchor, projection_id, records: 0, projection, answer, witness,
    })
}
fn build(request: &ResilientRequest, source: &CoverageGraphReport) -> Result<ResilientCoverProblem, CoverError> {
    let c = &request.common;
    ResilientCoverProblem::from_coverage(&source.projection, &c.zones, &request.domains, &c.mandatory, &c.excluded, c.maximum)
}

#[test]
fn declaration_order_and_member_order_are_canonical_without_merging_duplicates() -> TestResult {
    let a = request(&["--failure-domain", "power:ups=sensor:b,sensor:a", "--failure-domain", "network:switch=sensor:c,sensor:b"])?;
    let b = request(&["--failure-domain", "network:switch=sensor:b,sensor:c", "--failure-domain", "power:ups=sensor:a,sensor:b"])?;
    assert_eq!(a.domains, b.domains);
    assert_eq!(a.domains[0].kind(), FailureDomainKind::Network);
    assert_eq!(a.domains[1].members().iter().cloned().collect::<Vec<_>>(), vec!["sensor:a", "sensor:b"]);
    let source = source()?;
    assert_eq!(select(&a, &source, &|| false).map_err(|e| format!("{e:?}"))?,
        select(&b, &source, &|| false).map_err(|e| format!("{e:?}"))?);
    Ok(())
}

#[test]
fn missing_domains_bad_grammar_duplicates_and_cross_command_options_are_refused() {
    assert!(parse(&args(&[])).is_err());
    for domain in ["ups=sensor:a", "power:ups", "other:ups=sensor:a", "power:=sensor:a",
        "power:ups=", "power:ups=sensor:a,", "power:ups=sensor:a,sensor:a", "power:bad\nlabel=sensor:a"] {
        assert!(parse(&args(&["--failure-domain", domain])).is_err(), "{domain:?}");
    }
    assert!(parse(&args(&["--failure-domain", "power:ups=sensor:a", "--failure-domain", "power:ups=sensor:b"])).is_err());
    // Kind scopes the identity: same label on a network and a power domain is valid.
    assert!(parse(&args(&["--failure-domain", "power:shared=sensor:a", "--failure-domain", "network:shared=sensor:b"])).is_ok());
    let mut nominal = args(&["--failure-domain", "power:ups=sensor:a"]);
    nominal[0] = "select".into();
    assert!(super::super::parse(&nominal).is_err());
    assert!(parse(&nominal).is_err());
    assert!(parse(&args(&["--failure-domain", "power:ups=sensor:a", "--method", "greedy", "--method", "exact-small"])).is_err());
}

#[test]
fn obligation_and_argument_ceilings_are_checked_before_reading_storage() {
    let mut values = args(&["--failure-domain", "power:ups=sensor:a"]);
    for zone in 1..32 { values.extend(["--zone".into(), format!("zone:z{zone}").into()]); }
    assert!(parse(&values).is_ok()); // 32 zones * (one domain + baseline) = all 64 bits.
    values.extend(["--zone".into(), "zone:overflow".into()]);
    assert!(matches!(parse(&values), Err(CommandError::Usage(_))));
    let mut domains = args(&[]);
    for index in 0..16 { domains.extend(["--failure-domain".into(), format!("host:h{index}=sensor:a").into()]); }
    assert!(parse(&domains).is_ok());
    domains.extend(["--failure-domain".into(), "host:overflow=sensor:a".into()]);
    assert!(parse(&domains).is_err());
    let mut oversized = args(&[]);
    oversized.extend(["--failure-domain".into(), "x".repeat(MAX_ARG_BYTES + 1).into()]);
    assert!(parse(&oversized).is_err());
    assert!(parse(&vec![OsString::from("x"); MAX_ARGS + 1]).is_err());
}

#[test]
fn help_is_explicit_and_does_not_swallow_trailing_options() {
    assert!(matches!(parse(&["select-resilient".into(), "--help".into()]), Ok(None)));
    assert!(parse(&["select-resilient".into(), "--help".into(), "--failure-domain".into(), "power:ups=sensor:a".into()]).is_err());
    assert!(run(&["select-resilient".into(), "--help".into()]).is_ok_and(|help| help.contains(FORMAT) && help.contains("--during")));
}

#[test]
fn one_shared_selection_covers_each_separate_failure_with_decoded_certificates() -> TestResult {
    let request = request(&["--failure-domain", "power:ups=sensor:a,sensor:b",
        "--failure-domain", "network:switch=sensor:b,sensor:c", "--max-sensors", "2"])?;
    let source = source()?;
    let problem = build(&request, &source)?;
    let analysis = problem.solve(request.common.method, request.common.budget)?;
    assert_eq!(analysis.selected(), vec!["sensor:a", "sensor:c"]);
    let rows = obligation_rows(&problem, &analysis).map_err(|e| format!("{e:?}"))?;
    assert_eq!(rows.len(), 3);
    assert!(rows[0].contains("\"failed_domain\":null"));
    assert!(rows[1].contains("failure/network/switch") && rows[1].contains("\"sensor_id\":\"sensor:a\""));
    assert!(rows[2].contains("failure/power/ups") && rows[2].contains("\"sensor_id\":\"sensor:c\""));
    assert!(rows.iter().all(|row| row.contains("\"status\":\"supported\"")));
    let report = render(&request, &source, &problem, &analysis).map_err(|e| format!("{e:?}"))?;
    assert!(report.contains(&format!("\"format\":\"{FORMAT}\"")));
    assert!(report.contains(&format!("\"scenario_semantics\":\"{SEMANTICS}\"")));
    assert!(report.contains(&format!("SensorCoverageGraph:resilient-set-cover:parent:{}", source.witness.digest())));
    assert!(report.contains(&problem.expanded_problem().digest().to_text()));
    assert!(report.contains("\"objective_covered\":true"));
    Ok(())
}

#[test]
fn exact_limit_failure_and_greedy_incompletion_stay_distinct_in_reports() -> TestResult {
    let mut request = request(&["--failure-domain", "power:ups=sensor:a,sensor:b",
        "--failure-domain", "network:switch=sensor:b,sensor:c", "--max-sensors", "1"])?;
    let source = source()?;
    let exact = select(&request, &source, &|| false).map_err(|e| format!("{e:?}"))?;
    assert!(exact.contains("\"status\":\"infeasible_within_limit\""));
    assert!(exact.contains("\"objective_covered\":false"));
    request.common.method = CoverMethod::Greedy;
    let greedy = select(&request, &source, &|| false).map_err(|e| format!("{e:?}"))?;
    assert!(greedy.contains("\"status\":\"heuristic_incomplete\""));
    assert!(!greedy.contains("infeasible_within_limit"));
    assert!(greedy.contains("\"status\":\"uncovered\""));
    Ok(())
}

#[test]
fn failed_mandatory_sensor_is_selected_but_not_a_surviving_witness() -> TestResult {
    let request = request(&["--failure-domain", "power:ups=sensor:a,sensor:b",
        "--require-sensor", "sensor:a", "--exclude-sensor", "sensor:c"])?;
    let source = source()?;
    let problem = build(&request, &source)?;
    let analysis = problem.solve(request.common.method, request.common.budget)?;
    assert_eq!(analysis.status(), CoverStatus::Uncoverable);
    assert_eq!(analysis.selected(), vec!["sensor:a"]);
    let rows = obligation_rows(&problem, &analysis).map_err(|e| format!("{e:?}"))?;
    assert!(rows[0].contains("\"status\":\"supported\""));
    assert!(rows[1].contains("\"status\":\"uncoverable\""));
    assert!(rows[1].contains("\"sensor_id\":null"));
    Ok(())
}

#[test]
fn unseen_zones_remain_explicit_and_unknown_domain_members_are_refused() -> TestResult {
    let source = source()?;
    let req = request(&["--failure-domain", "host:host=sensor:a", "--zone", "zone:unseen"])?;
    let problem = build(&req, &source)?;
    let answer = problem.solve(req.common.method, req.common.budget)?;
    let rows = obligation_rows(&problem, &answer).map_err(|e| format!("{e:?}"))?;
    assert_eq!(rows.len(), 4);
    assert_eq!(rows.iter().filter(|row| row.contains("zone:unseen") && row.contains("\"status\":\"uncoverable\"")).count(), 2);
    let unknown = request(&["--failure-domain", "host:host=sensor:unknown"])?;
    assert!(matches!(select(&unknown, &source, &|| false), Err(CommandError::Selection(_))));
    Ok(())
}

#[test]
fn foreign_reduction_results_cannot_be_rendered_under_other_domain_declarations() -> TestResult {
    let source = source()?;
    let a = request(&["--failure-domain", "power:ups=sensor:a"])?;
    let b = request(&["--failure-domain", "power:renamed=sensor:a"])?;
    let p = build(&a, &source)?;
    let q = build(&b, &source)?;
    let answer = p.solve(a.common.method, a.common.budget)?;
    assert!(matches!(obligation_rows(&q, &answer), Err(CommandError::Witness)));
    Ok(())
}

#[test]
fn cancellation_work_and_complete_report_bound_return_no_report() -> TestResult {
    let source = source()?;
    let mut request = request(&["--failure-domain", "power:ups=sensor:a"])?;
    assert!(matches!(select(&request, &source, &|| true), Err(CommandError::Stopped)));
    request.common.budget.max_work_units = 1;
    assert!(matches!(select(&request, &source, &|| false), Err(CommandError::Selection(_))));
    request.common.budget = CoverBudget::default();
    let good = select(&request, &source, &|| false).map_err(|e| format!("{e:?}"))?;
    request.common.report_limit = good.len();
    assert_eq!(select(&request, &source, &|| false).map_err(|e| format!("{e:?}"))?, good);
    request.common.report_limit -= 1;
    assert!(matches!(select(&request, &source, &|| false), Err(CommandError::OutputBound)));
    Ok(())
}
