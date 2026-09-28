#![forbid(unsafe_code)]
//! Operator adapter for one retained-evidence selection satisfying every declared scenario.
//! The existing resilient-cover owner defines the reduction and solver semantics. This edge
//! parses explicit declarations, binds the whole-window source, and renders all obligations.

use super::*;
use fss_graph_algorithms::failure_domains::{
    FailureDomain, FailureDomainKind, MAX_DOMAIN_MEMBERS, MAX_FAILURE_DOMAINS,
};
use fss_graph_algorithms::resilient_cover::ResilientCoverProblem;

const FORMAT: &str = "fss.coverage_resilient_selection.v1";
const SEMANTICS: &str = "baseline_and_each_declared_domain_separately";
const CLAIM: &str = "one retained-evidence selection for baseline and each declared domain loss separately; not joint-domain failure survival, domain completeness, independence, live observability, or permission to disable sensors";
const HELP: &str = "fss-cover select-resilient [the same required source, window and zone options as select]\n\
  --failure-domain KIND:ID=SENSOR[,SENSOR...] [--failure-domain ...]\n\
\n\
  KIND is network, power, clock or host. Declarations are explicit owner assertions.\n\
  ID cannot contain '='; comma separates sensor identities. Nothing is trimmed or\n\
  inferred. Members of one domain fail together. Each domain is tested separately,\n\
  NOT together with other domains, even when memberships overlap.\n\
  One shared selected sensor set must cover the baseline AND every declared scenario.\n\
  Mandatory failed sensors remain selected and count toward cost, but cannot witness\n\
  a zone in that scenario. The common capture window and all nominal hard bounds apply.\n\
\n\
  Require 1..16 domains, each with 1..1024 known members, and at most 64 total\n\
  (domains + baseline) * zones obligations. The command refuses larger inputs BEFORE\n\
  reading the deployment; it never samples failures or falls back to nominal selection.\n\
  Duplicate domain kind/ID pairs and duplicate members are errors. The nominal select\n\
  command does not accept --failure-domain. Domain and member order are canonical.\n\
\n\
  The fss.coverage_resilient_selection.v1 report includes every obligation, with its\n\
  zone, failed domain (null = baseline), supporting selected sensor or explicit failure.\n\
  'uncovered' means unsupported by the returned selection; 'uncoverable' means no\n\
  eligible sensor survives with support. Greedy failure is NOT an infeasibility proof.\n\
  Exit 0 means a complete QUERY, not necessarily a feasible selection. No effects.\n\
\n\
  --expected-coverage pins the same source witness as nominal selection; it does not\n\
  approve domain assertions. Reduction and solver digests bind the full declared problem.\n\
  Native validation and production qualification are not claimed for this candidate.\n";

#[derive(Clone, Debug)]
struct ResilientRequest {
    common: Request,
    domains: Vec<FailureDomain>,
}

fn declaration(value: &OsStr) -> Result<FailureDomain, CommandError> {
    let (name, members) = text(value)?.split_once('=').ok_or(CommandError::Usage(
        "failure domain requires KIND:ID=SENSOR[,SENSOR...]",
    ))?;
    let (kind, id) = name.split_once(':').ok_or(CommandError::Usage(
        "failure domain requires an explicit kind and ID",
    ))?;
    let kind = match kind {
        "network" => FailureDomainKind::Network,
        "power" => FailureDomainKind::Power,
        "clock" => FailureDomainKind::Clock,
        "host" => FailureDomainKind::Host,
        _ => return Err(CommandError::Usage("unknown failure-domain kind")),
    };
    // Bound the collection before cloning. The typed owner rejects empty/duplicate members,
    // invalid identities and labels; the parser does not silently repair a declaration.
    let members: Vec<String> = members
        .split(',')
        .take(MAX_DOMAIN_MEMBERS + 1)
        .map(str::to_owned)
        .collect();
    FailureDomain::new(kind, id, &members).map_err(|_| {
        CommandError::Usage("invalid, duplicate or oversized failure-domain membership or label")
    })
}

fn parse(args: &[OsString]) -> Result<Option<ResilientRequest>, CommandError> {
    if args.len() > MAX_ARGS
        || args
            .iter()
            .any(|value| value.as_encoded_bytes().len() > MAX_ARG_BYTES)
    {
        return Err(CommandError::Usage(
            "argument count or length exceeds its bound",
        ));
    }
    if args.first().and_then(|value| value.to_str()) != Some("select-resilient") {
        return Err(CommandError::Usage("expected select-resilient"));
    }
    if args.len() == 2 && matches!(args[1].to_str(), Some("--help" | "-h")) {
        return Ok(None);
    }
    if args.len() % 2 != 1 {
        return Err(CommandError::Usage("expected separate option/value pairs"));
    }
    // Reuse the existing parser for every nominal input, including native path bytes. Only
    // domain declarations are removed. Invalid common options retain their original refusal.
    let mut common = vec![OsString::from("select")];
    let mut domains = BTreeMap::new();
    for pair in args[1..].chunks_exact(2) {
        if pair[0] != "--failure-domain" {
            common.extend_from_slice(pair);
            continue;
        }
        if domains.len() >= MAX_FAILURE_DOMAINS {
            return Err(CommandError::Usage("too many declared failure domains"));
        }
        let domain = declaration(&pair[1])?;
        if domains
            .insert((domain.kind(), domain.id().to_owned()), domain)
            .is_some()
        {
            return Err(CommandError::Usage("duplicate failure-domain kind and ID"));
        }
    }
    let common = super::parse(&common)?.ok_or(CommandError::Usage(
        "help cannot be combined with selection options",
    ))?;
    if domains.is_empty() {
        return Err(CommandError::Usage(
            "select-resilient requires at least one failure domain",
        ));
    }
    if (domains.len() + 1) * common.zones.len() > MAX_ELEMENTS {
        return Err(CommandError::Usage(
            "more than 64 baseline/scenario-zone obligations",
        ));
    }
    Ok(Some(ResilientRequest {
        common,
        domains: domains.into_values().collect(),
    }))
}

// This is a projection of the owner's result, not a second selection algorithm. Each source
// token must be in exactly one result partition; a foreign reduction cannot borrow a witness.
fn obligation_rows(
    problem: &ResilientCoverProblem,
    analysis: &CoverAnalysis,
) -> Result<Vec<String>, CommandError> {
    if analysis.input_digest() != problem.expanded_problem().digest() {
        return Err(CommandError::Witness);
    }
    let support: BTreeMap<&str, &str> = analysis
        .certificate()
        .iter()
        .map(|row| (row.element.as_str(), row.set_id.as_str()))
        .collect();
    let uncovered: BTreeSet<&str> = analysis.uncovered().iter().map(String::as_str).collect();
    let uncoverable: BTreeSet<&str> = analysis.uncoverable().iter().map(String::as_str).collect();
    if support.len() != analysis.certificate().len()
        || uncovered.len() != analysis.uncovered().len()
        || uncoverable.len() != analysis.uncoverable().len()
        || !uncoverable.is_subset(&uncovered)
        || support.len() + uncovered.len() != problem.obligations().len()
        || support.keys().any(|id| uncovered.contains(id))
        || support
            .keys()
            .chain(uncovered.iter())
            .any(|id| problem.obligation(id).is_none())
    {
        return Err(CommandError::Witness);
    }
    problem
        .obligations()
        .iter()
        .map(|obligation| {
            let sensor = support.get(obligation.id()).copied();
            let status = if sensor.is_some() {
                "supported"
            } else if uncoverable.contains(obligation.id()) {
                "uncoverable"
            } else if uncovered.contains(obligation.id()) {
                "uncovered"
            } else {
                return Err(CommandError::Witness);
            };
            Ok(object(&[
                ("obligation_id", string(obligation.id())),
                ("zone_scope", string(obligation.zone_scope())),
                (
                    "failed_domain",
                    obligation
                        .failure_domain()
                        .map_or_else(|| "null".to_owned(), string),
                ),
                ("status", string(status)),
                (
                    "sensor_id",
                    sensor.map_or_else(|| "null".to_owned(), string),
                ),
            ]))
        })
        .collect()
}

fn render(
    request: &ResilientRequest,
    source: &CoverageGraphReport,
    problem: &ResilientCoverProblem,
    analysis: &CoverAnalysis,
) -> Result<String, CommandError> {
    let request = &request.common;
    let obligations = obligation_rows(problem, analysis)?;
    let domains: Vec<String> = problem
        .domains()
        .iter()
        .map(|domain| {
            object(&[
                ("kind", string(domain.kind().as_str())),
                ("id", string(domain.id())),
                ("node_id", string(&domain.node_id())),
                (
                    "members",
                    strings(&domain.members().iter().cloned().collect::<Vec<_>>()),
                ),
            ])
        })
        .collect();
    let parent = source.witness.digest();
    let selection_witness = analysis
        .witness(
            &format!("SensorCoverageGraph:resilient-set-cover:parent:{parent}"),
            source.anchor.clone(),
        )
        .map_err(|_| CommandError::Witness)?;
    let result = object(&[
        ("format", string(FORMAT)),
        ("site", string(&source.site)),
        ("anchor", evidence_anchor(&source.anchor)),
        (
            "capture_window",
            object(&[
                ("start_ns", string(&request.window.earliest.0.to_string())),
                ("end_ns", string(&request.window.latest.0.to_string())),
                ("endpoints", string("inclusive")),
                ("selection", string("whole-witness-v1")),
                ("clock_alignment", string("operator_hints_not_calibration")),
            ]),
        ),
        ("source_coverage_witness", witness(&source.witness)),
        ("source_coverage_witness_digest", string(&parent.to_text())),
        (
            "objective",
            object(&[
                ("required_zones", strings(&request.zones)),
                ("mandatory_sensors", strings(&request.mandatory)),
                ("excluded_sensors", strings(&request.excluded)),
                ("maximum_sensors", request.maximum.to_string()),
                ("cost_model", string("one_unit_per_selected_sensor")),
            ]),
        ),
        ("failure_domains", array(&domains)),
        ("scenario_semantics", string(SEMANTICS)),
        (
            "reduction_input_digest",
            string(&problem.digest().to_text()),
        ),
        (
            "expanded_input_digest",
            string(&problem.expanded_problem().digest().to_text()),
        ),
        ("method", string(analysis.method().as_str())),
        ("status", string(analysis.status().as_str())),
        (
            "objective_covered",
            (analysis.status() == CoverStatus::Covered).to_string(),
        ),
        ("selected_sensors", strings(analysis.selected())),
        (
            "selection_cost_units",
            analysis.selected().len().to_string(),
        ),
        ("obligations", array(&obligations)),
        ("witness", witness(&selection_witness)),
        (
            "witness_digest",
            string(&selection_witness.digest().to_text()),
        ),
        (
            "work_budget_scope",
            string(
                "expanded_set_cover_solver_only; source_reader_and_reduction_separately_bounded",
            ),
        ),
        (
            "working_bytes_interpretation",
            string(
                "conservative_charged_solver_workspace_bound_not_measured_allocator_peak_or_reduction_memory",
            ),
        ),
        ("authority", string("derived_cognition_no_effect_authority")),
        ("claim", string(CLAIM)),
        (
            "qualification",
            string("authored_unvalidated_reference_candidate"),
        ),
    ]);
    if result.len() + 1 > request.report_limit {
        return Err(CommandError::OutputBound);
    }
    Ok(result + "\n")
}

fn select(
    request: &ResilientRequest,
    source: &CoverageGraphReport,
    stopped: &impl Fn() -> bool,
) -> Result<String, CommandError> {
    if stopped() {
        return Err(CommandError::Stopped);
    }
    let common = &request.common;
    let problem = ResilientCoverProblem::from_coverage(
        &source.projection,
        &common.zones,
        &request.domains,
        &common.mandatory,
        &common.excluded,
        common.maximum,
    )
    .map_err(CommandError::Selection)?;
    let analysis = problem
        .solve_cancellable(common.method, common.budget, stopped)
        .map_err(CommandError::Selection)?;
    let report = render(request, source, &problem, &analysis)?;
    if stopped() {
        return Err(CommandError::Stopped);
    }
    Ok(report)
}

pub(super) fn run(args: &[OsString]) -> Result<String, CommandError> {
    let Some(request) = parse(args)? else {
        return Ok(format!("{HELP}\n{}", super::HELP));
    };
    let started = Instant::now();
    let stopped = || started.elapsed() >= request.common.timeout;
    let source = super::read_source(&request.common, &stopped)?;
    select(&request, &source, &stopped)
}

#[cfg(test)]
#[path = "resilient_tests.rs"]
mod tests;
