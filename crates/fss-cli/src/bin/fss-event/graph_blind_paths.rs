#![forbid(unsafe_code)]
//! Read-only adversarial blind-path analysis over retained coverage (`ALG-INTERDICT-001`).
//!
//! The retained coverage projection supplies each zone's observers; the owner declares how an
//! intruder can move between zones, where they enter and what they target, and what disabling,
//! dazzling or covering each sensor costs. The report names an existing blind walk, or the
//! cheapest sensor set whose loss opens one (with a witness walk), or that the target is
//! unreachable. Nothing is written, locked or authorized.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::agent_json::{evidence_anchor, object, string, strings};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::interdiction::{self, InterdictionOutcome, InterdictionQuery};
use fss_graph_algorithms::weighted::WeightedGraphBuilder;
use fss_reference::coverage_graph::read_coverage_single_points;

/// Report format tag (`SCHEMA-DOMAIN-COVERAGE-BLIND-PATHS-001`).
const FORMAT: &str = "fss.coverage_blind_paths.v1";
/// Operation ceiling of one run (fails closed beyond it).
const MAX_OPERATIONS: u64 = 500_000_000;
/// Most declared moves.
const MAX_MOVES: usize = 4_096;

const HELP: &str = "fss-event graph blind-paths --root DIR --site SITE --entry ZONE --target ZONE\n\
  --move ZONE~ZONE [--move ...] [--one-way ZONE>ZONE ...] [--cost SENSOR=N ...] [--default-cost N]\n\
  Finds how cheaply an intruder can walk from an entry zone to a target zone with no working\n\
  observer on any zone of the walk (ALG-INTERDICT-001): an existing blind walk, or the\n\
  minimum-cost set of sensors to disable, dazzle or cover (ties: fewer sensors, then\n\
  identity order) with a witness walk, or unreachable. Observers come from one committed\n\
  retained-coverage snapshot; --move declares a two-way passage, --one-way a one-way one\n\
  (zones are coverage scopes such as zone:door, or owner labels for unwatched areas).\n\
  Costs default to 1 per sensor. Exact up to 20 observing sensors; beyond that the report\n\
  is an explicitly approximate feasible upper bound. Movement is an owner assertion; retained\n\
  coverage is not current observability. Nothing is written.\n";

struct Request {
    root: PathBuf,
    site: String,
    entries: BTreeSet<String>,
    targets: BTreeSet<String>,
    moves: Vec<(String, String, bool)>,
    costs: BTreeMap<String, u64>,
    default_cost: u64,
}

fn parse(args: &[OsString]) -> Result<Request, String> {
    let mut root = None;
    let mut site = None;
    let mut entries = BTreeSet::new();
    let mut targets = BTreeSet::new();
    let mut moves = Vec::new();
    let mut costs = BTreeMap::new();
    let mut default_cost = None;
    let mut index = 1;
    while index < args.len() {
        let key = args[index].to_str().ok_or("option names require UTF-8")?;
        let value = args
            .get(index + 1)
            .ok_or_else(|| format!("required value for {key}"))?
            .to_str()
            .ok_or_else(|| format!("{key} requires UTF-8"))?;
        match key {
            "--root" if root.is_none() => root = Some(PathBuf::from(value)),
            "--site" if site.is_none() => site = Some(value.to_owned()),
            "--entry" => {
                entries.insert(value.to_owned());
            }
            "--target" => {
                targets.insert(value.to_owned());
            }
            "--move" | "--one-way" => {
                if moves.len() == MAX_MOVES {
                    return Err(format!("at most {MAX_MOVES} moves are allowed"));
                }
                let separator = if key == "--move" { '~' } else { '>' };
                let (a, b) = value
                    .split_once(separator)
                    .ok_or_else(|| format!("{key} requires ZONE{separator}ZONE"))?;
                moves.push((a.to_owned(), b.to_owned(), key == "--move"));
            }
            "--cost" => {
                let (sensor, cost) = value.rsplit_once('=').ok_or("--cost requires SENSOR=N")?;
                let cost = cost
                    .parse::<u64>()
                    .map_err(|_| "--cost requires an integer cost")?;
                if costs.insert(sensor.to_owned(), cost).is_some() {
                    return Err(format!("duplicate cost for {sensor}"));
                }
            }
            "--default-cost" if default_cost.is_none() => {
                default_cost = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "--default-cost requires an integer")?,
                );
            }
            "--root" | "--site" | "--default-cost" => {
                return Err(format!("duplicate option {key}"));
            }
            _ => return Err(format!("unknown option {key} for graph blind-paths")),
        }
        index += 2;
    }
    if entries.is_empty() || targets.is_empty() {
        return Err("graph blind-paths requires --entry and --target".to_owned());
    }
    Ok(Request {
        root: root.ok_or("required option --root")?,
        site: site.ok_or("required option --site")?,
        entries,
        targets,
        moves,
        costs,
        default_cost: default_cost.unwrap_or(1),
    })
}

fn run(request: &Request) -> Result<String, String> {
    let report = read_coverage_single_points(&request.root, &request.site).map_err(|error| {
        match error.stable_id() {
            Some(id) => format!("{error}; refusal_id={id}"),
            None => error.to_string(),
        }
    })?;
    let mut observers: BTreeMap<String, BTreeSet<String>> = report
        .answer
        .zones
        .iter()
        .map(|zone| (zone.scope.clone(), zone.observers.iter().cloned().collect()))
        .collect();
    let mut zones: BTreeSet<String> = observers.keys().cloned().collect();
    for (a, b, _) in &request.moves {
        zones.insert(a.clone());
        zones.insert(b.clone());
    }
    zones.extend(request.entries.iter().cloned());
    zones.extend(request.targets.iter().cloned());
    for zone in &zones {
        observers.entry(zone.clone()).or_default();
    }
    let mut builder = WeightedGraphBuilder::directed("passage");
    for zone in &zones {
        builder.add_node(zone.clone());
    }
    let mut arcs = BTreeSet::new();
    for (a, b, two_way) in &request.moves {
        arcs.insert((a.clone(), b.clone()));
        if *two_way {
            arcs.insert((b.clone(), a.clone()));
        }
    }
    for (a, b) in &arcs {
        builder.add_arc(a.clone(), b.clone(), 1);
    }
    let graph = builder
        .build()
        .map_err(|error| format!("{}: {error}", error.stable_id()))?;
    let sensors: BTreeSet<&String> = observers.values().flatten().collect();
    if let Some(unknown) = request
        .costs
        .keys()
        .find(|sensor| !sensors.contains(sensor))
    {
        return Err(format!(
            "ERR-GRAPH-INPUT-INVALID-001: cost for unknown sensor {unknown}"
        ));
    }
    let costs: BTreeMap<String, u64> = sensors
        .iter()
        .map(|sensor| {
            let cost = request
                .costs
                .get(*sensor)
                .copied()
                .unwrap_or(request.default_cost);
            ((*sensor).clone(), cost)
        })
        .collect();
    let query = InterdictionQuery {
        observers,
        costs,
        entries: request.entries.clone(),
        targets: request.targets.clone(),
    };
    let run = interdiction::interdiction(&graph, &query, Budget::new(MAX_OPERATIONS, 1 << 20))
        .map_err(|error| format!("{}: {error}", error.stable_id()))?;
    let parent = report.witness.digest().to_text();
    let witness = run
        .witness(
            &format!("SensorCoverageGraph+movement@parent:{parent}"),
            report.anchor.clone(),
        )
        .map_err(|error| format!("witness: {error}"))?;
    let outcome = match &run.output.outcome {
        InterdictionOutcome::BlindPath { path } => object(&[
            ("kind", string("blind_path")),
            ("walk", strings(path)),
            ("sensors_to_disable", strings::<[&str; 0], &str>([])),
            ("cost", "0".to_owned()),
            ("exact", "true".to_owned()),
        ]),
        InterdictionOutcome::Interdiction {
            sensors,
            cost,
            path,
            exact,
        } => object(&[
            ("kind", string("interdiction")),
            ("walk", strings(path)),
            ("sensors_to_disable", strings(sensors)),
            ("cost", cost.to_string()),
            ("exact", exact.to_string()),
        ]),
        InterdictionOutcome::Unreachable => object(&[("kind", string("unreachable"))]),
    };
    Ok(object(&[
        ("format", string(FORMAT)),
        ("site", string(&report.site)),
        ("anchor", evidence_anchor(&report.anchor)),
        ("coverage_witness_digest", string(&parent)),
        ("algorithm", string(interdiction::IDENTITY.algorithm_id)),
        (
            "implementation",
            string(interdiction::IDENTITY.implementation_id),
        ),
        ("entries", strings(&request.entries)),
        ("targets", strings(&request.targets)),
        ("observing_sensors", strings(&run.output.relevant_sensors)),
        ("outcome", outcome),
        ("witness_digest", string(&witness.digest().to_text())),
        ("output_digest", string(&run.output_digest.to_text())),
        (
            "assumptions",
            strings([
                "movement and disable costs are owner assertions",
                "observers are retained coverage witnesses, not current observability",
                "a zone with any working observer is observed for the whole walk",
            ]),
        ),
        ("authority", string("derived_cognition_no_effect_authority")),
    ]))
}

pub(super) fn main(args: &[OsString]) -> ExitCode {
    if matches!(args, [_, flag] if matches!(flag.to_str(), Some("--help" | "-h"))) {
        return match io::stdout().lock().write_all(HELP.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        };
    }
    let request = match parse(args) {
        Ok(request) => request,
        Err(reason) => {
            eprintln!(
                "{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-event graph blind-paths --help"
            );
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(&request) {
        Ok(rendered) => match writeln!(io::stdout().lock(), "{rendered}") {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}
