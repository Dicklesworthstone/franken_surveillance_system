#![forbid(unsafe_code)]
//! Public-consumer tests for the scenario reduction; native execution is not claimed.
use std::collections::BTreeSet;

use fss_core::LedgerAnchor;
use fss_graph_algorithms::failure_domains::{FailureDomain, FailureDomainKind};
use fss_graph_algorithms::resilient_cover::ResilientCoverProblem;
use fss_graph_algorithms::set_cover::{
    CoverBudget, CoverError, CoverMethod, CoverStatus, SetCoverProblem,
};
use fss_graph_algorithms::{CoverageObservation, GraphError, SensorCoverageProjection};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn ids(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}
fn fact(sensor: &str, zone: &str, witnesses: u64) -> CoverageObservation {
    CoverageObservation {
        sensor_id: sensor.to_owned(),
        zone_scope: zone.to_owned(),
        witnesses,
    }
}
fn fixture() -> Result<SensorCoverageProjection, GraphError> {
    SensorCoverageProjection::build(
        "site:resilient",
        &[
            fact("a", "gate", 1),
            fact("b", "gate", 1),
            fact("c", "gate", 1),
        ],
    )
}
fn domain(
    kind: FailureDomainKind,
    id: &str,
    members: &[&str],
) -> Result<FailureDomain, GraphError> {
    FailureDomain::new(kind, id, &ids(members))
}

#[test]
fn minimum_selection_survives_a_declared_shared_power_loss() -> TestResult {
    let source = fixture()?;
    let domains = [domain(FailureDomainKind::Power, "ups", &["a", "b"])?];
    let nominal = SetCoverProblem::from_coverage(&source, &ids(&["gate"]), &[], &[], 2)?;
    assert_eq!(
        nominal
            .solve(CoverMethod::ExactSmall, CoverBudget::default())?
            .selected(),
        ids(&["a"])
    );
    let robust =
        ResilientCoverProblem::from_coverage(&source, &ids(&["gate"]), &domains, &[], &[], 2)?;
    for method in [CoverMethod::ExactSmall, CoverMethod::Greedy] {
        let answer = robust.solve(method, CoverBudget::default())?;
        assert_eq!(answer.status(), CoverStatus::Covered);
        assert_eq!(answer.selected(), ids(&["c"]));
        assert_eq!(answer.certificate().len(), 2);
        for edge in answer.certificate() {
            let obligation = robust
                .obligation(&edge.element)
                .ok_or("unbound certificate")?;
            assert_eq!(obligation.zone_scope(), "gate");
            assert_eq!(edge.set_id, "c");
        }
    }
    Ok(())
}

#[test]
fn overlapping_domains_require_one_selection_valid_for_each_separate_loss() -> TestResult {
    let source = fixture()?;
    let domains = [
        domain(FailureDomainKind::Power, "ups", &["a", "b"])?,
        domain(FailureDomainKind::Network, "switch", &["b", "c"])?,
    ];
    let robust =
        ResilientCoverProblem::from_coverage(&source, &ids(&["gate"]), &domains, &[], &[], 2)?;
    let result = robust.solve(CoverMethod::ExactSmall, CoverBudget::default())?;
    assert_eq!(result.selected(), ids(&["a", "c"]));
    assert_eq!(result.status(), CoverStatus::Covered);
    // The union of both failed domains removes everyone. It was NOT a declared scenario.
    assert_eq!(robust.obligations().len(), 3);
    let mandatory = ResilientCoverProblem::from_coverage(
        &source,
        &ids(&["gate"]),
        &domains,
        &ids(&["b"]),
        &[],
        2,
    )?;
    assert_eq!(
        mandatory
            .solve(CoverMethod::ExactSmall, CoverBudget::default())?
            .status(),
        CoverStatus::InfeasibleWithinLimit
    );
    let enough = ResilientCoverProblem::from_coverage(
        &source,
        &ids(&["gate"]),
        &domains,
        &ids(&["b"]),
        &[],
        3,
    )?;
    assert_eq!(
        enough
            .solve(CoverMethod::ExactSmall, CoverBudget::default())?
            .selected(),
        ids(&["a", "b", "c"])
    );
    Ok(())
}

#[test]
fn exclusions_unknown_zones_and_failed_mandatory_sensors_cannot_supply_coverage() -> TestResult {
    let domains = [domain(FailureDomainKind::Power, "ups", &["a", "b"])?];
    let source = fixture()?;
    let robust = ResilientCoverProblem::from_coverage(
        &source,
        &ids(&["gate", "unseen"]),
        &domains,
        &ids(&["a"]),
        &ids(&["c"]),
        2,
    )?;
    let answer = robust.solve(CoverMethod::ExactSmall, CoverBudget::default())?;
    assert_eq!(answer.status(), CoverStatus::Uncoverable);
    assert_eq!(answer.selected(), ids(&["a"]));
    assert_eq!(answer.uncoverable().len(), 3);
    let lost_gate = answer
        .uncoverable()
        .iter()
        .filter_map(|id| robust.obligation(id))
        .any(|obligation| {
            obligation.zone_scope() == "gate" && obligation.failure_domain().is_some()
        });
    assert!(lost_gate);
    assert_eq!(robust.obligations().len(), 4);
    Ok(())
}

#[test]
fn canonical_reordering_preserves_results_and_context_rebinding_changes_tokens() -> TestResult {
    let source = fixture()?;
    let power = domain(FailureDomainKind::Power, "ups", &["b", "a"])?;
    let net = domain(FailureDomainKind::Network, "switch", &["c", "b"])?;
    let first = ResilientCoverProblem::from_coverage(
        &source,
        &ids(&["gate"]),
        &[power.clone(), net.clone()],
        &[],
        &[],
        3,
    )?;
    let reordered =
        ResilientCoverProblem::from_coverage(&source, &ids(&["gate"]), &[net, power], &[], &[], 3)?;
    assert_eq!(first, reordered);
    assert_eq!(
        first.solve(CoverMethod::Greedy, CoverBudget::default())?,
        reordered.solve(CoverMethod::Greedy, CoverBudget::default())?
    );
    let changed = ResilientCoverProblem::from_coverage(
        &source,
        &ids(&["gate"]),
        &[
            domain(FailureDomainKind::Power, "renamed", &["a", "b"])?,
            domain(FailureDomainKind::Network, "switch", &["b", "c"])?,
        ],
        &[],
        &[],
        3,
    )?;
    assert_ne!(first.digest(), changed.digest());
    assert_ne!(
        first.expanded_problem().digest(),
        changed.expanded_problem().digest()
    );
    assert!(changed.obligation(first.obligations()[0].id()).is_none());
    let a = first.solve(CoverMethod::ExactSmall, CoverBudget::default())?;
    let b = changed.solve(CoverMethod::ExactSmall, CoverBudget::default())?;
    assert_eq!(a.selected(), b.selected());
    assert_ne!(
        a.witness("source-parent", LedgerAnchor::genesis("site:resilient"))?
            .digest(),
        b.witness("source-parent", LedgerAnchor::genesis("site:resilient"))?
            .digest()
    );
    Ok(())
}

#[test]
fn witness_count_and_redundant_domain_members_are_input_not_incidental_metadata() -> TestResult {
    let source = fixture()?;
    let one = [domain(FailureDomainKind::Power, "ups", &["a"])?];
    let two = [domain(FailureDomainKind::Power, "ups", &["a", "b"])?];
    let a =
        ResilientCoverProblem::from_coverage(&source, &ids(&["gate"]), &one, &[], &ids(&["b"]), 2)?;
    let b =
        ResilientCoverProblem::from_coverage(&source, &ids(&["gate"]), &two, &[], &ids(&["b"]), 2)?;
    assert_ne!(a.digest(), b.digest());
    let changed = SensorCoverageProjection::build(
        "site:resilient",
        &[
            fact("a", "gate", 2),
            fact("b", "gate", 1),
            fact("c", "gate", 1),
        ],
    )?;
    let c = ResilientCoverProblem::from_coverage(
        &changed,
        &ids(&["gate"]),
        &one,
        &[],
        &ids(&["b"]),
        2,
    )?;
    assert_ne!(a.digest(), c.digest());
    assert_eq!(
        a.solve(CoverMethod::ExactSmall, CoverBudget::default())?
            .selected(),
        c.solve(CoverMethod::ExactSmall, CoverBudget::default())?
            .selected()
    );
    Ok(())
}

#[test]
fn all_sixty_four_obligations_are_supported_and_oversize_is_never_sampled() -> TestResult {
    let zones: Vec<String> = (0..33).map(|n| format!("z{n:02}")).collect();
    let facts: Vec<_> = zones
        .iter()
        .flat_map(|zone| [fact("a", zone, 1), fact("b", zone, 1)])
        .collect();
    let source = SensorCoverageProjection::build("site:resilient", &facts)?;
    let domains = [domain(FailureDomainKind::Host, "host", &["a"])?];
    let allowed =
        ResilientCoverProblem::from_coverage(&source, &zones[..32], &domains, &[], &[], 1)?;
    let answer = allowed.solve(CoverMethod::ExactSmall, CoverBudget::default())?;
    assert_eq!(allowed.obligations().len(), 64);
    assert_eq!(answer.status(), CoverStatus::Covered);
    assert_eq!(answer.certificate().len(), 64);
    assert!(matches!(
        ResilientCoverProblem::from_coverage(&source, &zones, &domains, &[], &[], 1),
        Err(CoverError::Graph(GraphError::TooLarge))
    ));
    Ok(())
}

#[test]
fn invalid_declarations_and_tampered_projection_fail_closed() -> TestResult {
    let mut source = fixture()?;
    let power = domain(FailureDomainKind::Power, "ups", &["a"])?;
    assert!(
        ResilientCoverProblem::from_coverage(&source, &ids(&["gate"]), &[], &[], &[], 3).is_err()
    );
    assert!(
        ResilientCoverProblem::from_coverage(&source, &[], &[power.clone()], &[], &[], 3).is_err()
    );
    assert!(
        ResilientCoverProblem::from_coverage(
            &source,
            &ids(&["gate"]),
            &[power.clone(), power.clone()],
            &[],
            &[],
            3
        )
        .is_err()
    );
    let unknown = domain(FailureDomainKind::Clock, "clock", &["unknown"])?;
    assert!(
        ResilientCoverProblem::from_coverage(&source, &ids(&["gate"]), &[unknown], &[], &[], 3)
            .is_err()
    );
    source.witnesses.insert(("a".into(), "gate".into()), 0);
    assert!(
        ResilientCoverProblem::from_coverage(&source, &ids(&["gate"]), &[power], &[], &[], 3)
            .is_err()
    );
    Ok(())
}

#[test]
fn cancellation_and_work_exhaustion_return_no_resilient_selection() -> TestResult {
    let source = fixture()?;
    let domains = [domain(FailureDomainKind::Power, "ups", &["a", "b"])?];
    let p = ResilientCoverProblem::from_coverage(&source, &ids(&["gate"]), &domains, &[], &[], 3)?;
    for method in [CoverMethod::ExactSmall, CoverMethod::Greedy] {
        assert!(matches!(
            p.solve_cancellable(method, CoverBudget::default(), &|| true),
            Err(CoverError::Cancelled)
        ));
        let answer = p.solve(method, CoverBudget::default())?;
        let exact_budget = CoverBudget {
            max_work_units: answer.counters().work_units(),
            ..CoverBudget::default()
        };
        assert_eq!(answer, p.solve(method, exact_budget)?);
        assert!(
            p.solve(
                method,
                CoverBudget {
                    max_work_units: exact_budget.max_work_units - 1,
                    ..exact_budget
                }
            )
            .is_err()
        );
    }
    Ok(())
}

// Direct string/observer oracle: no obligation tokens, expanded support masks, or reduction.
fn oracle(
    source: &SensorCoverageProjection,
    zones: &[String],
    domains: &[FailureDomain],
    mandatory: &[String],
    excluded: &[String],
    maximum: usize,
) -> Option<Vec<String>> {
    let sensors: Vec<String> = source
        .witnesses
        .keys()
        .map(|(sensor, _)| sensor.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut best: Option<Vec<String>> = None;
    for mask in 0..(1_usize << sensors.len()) {
        let selected: Vec<String> = sensors
            .iter()
            .enumerate()
            .filter(|(at, _)| mask & (1 << *at) != 0)
            .map(|(_, sensor)| sensor.clone())
            .collect();
        if selected.len() > maximum
            || mandatory.iter().any(|sensor| !selected.contains(sensor))
            || excluded.iter().any(|sensor| selected.contains(sensor))
        {
            continue;
        }
        let covers = std::iter::once(None)
            .chain(domains.iter().map(Some))
            .all(|domain| {
                zones.iter().all(|zone| {
                    selected.iter().any(|sensor| {
                        !domain.is_some_and(|domain| domain.members().contains(sensor))
                            && source
                                .witnesses
                                .get(&(sensor.clone(), zone.clone()))
                                .is_some_and(|count| *count > 0)
                    })
                })
            });
        if covers
            && best
                .as_ref()
                .is_none_or(|old| (selected.len(), &selected) < (old.len(), old))
        {
            best = Some(selected);
        }
    }
    best
}
fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

#[test]
fn exact_reduction_matches_direct_scenario_oracle_on_seeded_constraints() -> TestResult {
    let mut seed = 0xfeed_cafe_41_u64;
    for trial in 0..1000 {
        let n = 1 + (next(&mut seed) % 6) as usize;
        let m = 1 + (next(&mut seed) % 4) as usize;
        let count = 1 + (next(&mut seed) % 3) as usize;
        let sensors: Vec<String> = (0..n).map(|n| format!("s{n}")).collect();
        let zones: Vec<String> = (0..m).map(|n| format!("z{n}")).collect();
        let mut facts = Vec::new();
        for sensor in &sensors {
            for zone in &zones {
                facts.push(fact(sensor, zone, next(&mut seed) & 1));
            }
        }
        let source = SensorCoverageProjection::build("site:resilient", &facts)?;
        let mut domains = Vec::new();
        for index in 0..count {
            let mut members = sensors
                .iter()
                .filter(|_| next(&mut seed) & 1 != 0)
                .cloned()
                .collect::<Vec<_>>();
            if members.is_empty() {
                members.push(sensors[0].clone());
            }
            domains.push(FailureDomain::new(
                FailureDomainKind::Network,
                &format!("d{index}"),
                &members,
            )?);
        }
        let mut mandatory = Vec::new();
        let mut excluded = Vec::new();
        for sensor in &sensors {
            match next(&mut seed) % 7 {
                0 => mandatory.push(sensor.clone()),
                1 => excluded.push(sensor.clone()),
                _ => {}
            }
        }
        let maximum =
            mandatory.len() + (next(&mut seed) % (n + 1 - mandatory.len()) as u64) as usize;
        let p = ResilientCoverProblem::from_coverage(
            &source, &zones, &domains, &mandatory, &excluded, maximum,
        )?;
        let answer = p.solve(CoverMethod::ExactSmall, CoverBudget::default())?;
        match oracle(&source, &zones, &domains, &mandatory, &excluded, maximum) {
            Some(expected) => {
                assert_eq!(answer.status(), CoverStatus::Covered, "trial {trial}");
                assert_eq!(answer.selected(), expected, "trial {trial}");
            }
            None => assert!(
                matches!(
                    answer.status(),
                    CoverStatus::Uncoverable | CoverStatus::InfeasibleWithinLimit
                ),
                "trial {trial}"
            ),
        }
        for edge in answer.certificate() {
            let obligation = p.obligation(&edge.element).ok_or("unbound certificate")?;
            assert!(
                source
                    .witnesses
                    .get(&(edge.set_id.clone(), obligation.zone_scope().to_owned()))
                    .is_some_and(|count| *count > 0)
            );
            if let Some(failed) = obligation.failure_domain() {
                let domain = p
                    .domains()
                    .iter()
                    .find(|domain| domain.node_id() == failed)
                    .ok_or("unknown scenario")?;
                assert!(!domain.members().contains(&edge.set_id));
            }
        }
    }
    Ok(())
}
