#![forbid(unsafe_code)]
//! Read-only blindness probability bounds over retained coverage (`ALG-RELIABILITY-001`).
//!
//! The retained coverage projection (one committed snapshot, optionally one whole-witness
//! capture window) supplies each zone's observers; the owner declares failure domains with
//! probability intervals. The report bounds, per zone, the probability that every observer is
//! down, and lists the minimal blinding domain sets. Declarations are assertions, not measured
//! availability; nothing is written, locked or authorized.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::agent_json::{array, evidence_anchor, object, string, strings};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{CaptureInterval, LedgerAnchor, TimestampNs};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::reliability::{self, DomainSpec, ReliabilityModel};
use fss_reference::coverage_graph::{
    read_coverage_single_points, read_coverage_single_points_during,
};

/// Report format tag (`SCHEMA-DOMAIN-COVERAGE-RELIABILITY-001`).
const FORMAT: &str = "fss.coverage_reliability.v1";
/// Most declared domains.
const MAX_DOMAINS: usize = 256;
/// Operation ceiling of one run (fails closed beyond it).
const MAX_OPERATIONS: u64 = 200_000_000;

const HELP: &str = "fss-event graph reliability --root DIR --site SITE [--during START_NS:END_NS]\n\
  [--camera-failure LO_PPM:HI_PPM] [--domain ID=LO_PPM:HI_PPM=SENSOR[,SENSOR...]]...\n\
  Bounds, per retained zone, the probability that every observing sensor is down over the\n\
  declared horizon (ALG-RELIABILITY-001), and lists its minimal blinding domain sets.\n\
  Observers come from one committed coverage snapshot (with --during: witnesses whose certain\n\
  bounds contain the whole window). --camera-failure declares one domain camera:<sensor> per\n\
  observing sensor; --domain declares a shared dependency (power circuit, switch, recorder)\n\
  with its failure probability interval in parts per million and its member sensors.\n\
  Domains fail independently; correlation is modelled only by sharing a domain. A zone with\n\
  no retained observer is blind with certainty. Probabilities are owner assertions, not\n\
  measured availability; bounds are outward-rounded (10^-18 fixed point). Nothing is written.\n";

struct Request {
    root: PathBuf,
    site: String,
    window: Option<CaptureInterval>,
    camera_failure: Option<(u32, u32)>,
    domains: Vec<DomainSpec>,
}

fn interval(text: &str, what: &str) -> Result<(u32, u32), String> {
    let (lo, hi) = text
        .split_once(':')
        .ok_or_else(|| format!("{what} requires LO_PPM:HI_PPM"))?;
    let parse = |value: &str| {
        value
            .parse::<u32>()
            .map_err(|_| format!("{what} probabilities are integer parts per million"))
    };
    let (lo, hi) = (parse(lo)?, parse(hi)?);
    if lo > hi || hi > 1_000_000 {
        return Err(format!("{what} requires 0 <= LO_PPM <= HI_PPM <= 1000000"));
    }
    Ok((lo, hi))
}

fn parse(args: &[OsString]) -> Result<Request, String> {
    let mut root = None;
    let mut site = None;
    let mut window = None;
    let mut camera_failure = None;
    let mut domains: Vec<DomainSpec> = Vec::new();
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
            "--during" if window.is_none() => {
                let (first, last) = value
                    .split_once(':')
                    .ok_or("--during requires START_NS:END_NS")?;
                let first = first
                    .parse::<i128>()
                    .map_err(|_| "--during start must be integer nanoseconds")?;
                let last = last
                    .parse::<i128>()
                    .map_err(|_| "--during end must be integer nanoseconds")?;
                window = Some(
                    CaptureInterval::new(TimestampNs(first), TimestampNs(last))
                        .map_err(|_| "--during requires START_NS <= END_NS")?,
                );
            }
            "--camera-failure" if camera_failure.is_none() => {
                camera_failure = Some(interval(value, "--camera-failure")?);
            }
            "--domain" => {
                if domains.len() == MAX_DOMAINS {
                    return Err(format!("at most {MAX_DOMAINS} domains are allowed"));
                }
                let mut parts = value.splitn(3, '=');
                let (Some(id), Some(probability), Some(members)) =
                    (parts.next(), parts.next(), parts.next())
                else {
                    return Err("--domain requires ID=LO_PPM:HI_PPM=SENSOR[,SENSOR...]".to_owned());
                };
                let (lo_ppm, hi_ppm) = interval(probability, "--domain")?;
                domains.push(DomainSpec {
                    id: id.to_owned(),
                    lo_ppm,
                    hi_ppm,
                    members: members
                        .split(',')
                        .map(str::to_owned)
                        .collect::<BTreeSet<_>>(),
                });
            }
            "--root" | "--site" | "--during" | "--camera-failure" => {
                return Err(format!("duplicate option {key}"));
            }
            _ => return Err(format!("unknown option {key} for graph reliability")),
        }
        index += 2;
    }
    Ok(Request {
        root: root.ok_or("required option --root")?,
        site: site.ok_or("required option --site")?,
        window,
        camera_failure,
        domains,
    })
}

fn decimal(value: u128) -> String {
    string(&value.to_string())
}

fn run(request: &Request) -> Result<String, String> {
    let report = match request.window {
        None => read_coverage_single_points(&request.root, &request.site),
        Some(window) => read_coverage_single_points_during(&request.root, &request.site, window),
    }
    .map_err(|error| match error.stable_id() {
        Some(id) => format!("{error}; refusal_id={id}"),
        None => error.to_string(),
    })?;
    let zones: Vec<(String, Vec<String>)> = report
        .answer
        .zones
        .iter()
        .map(|zone| (zone.scope.clone(), zone.observers.clone()))
        .collect();
    let mut domains = request.domains.clone();
    if let Some((lo_ppm, hi_ppm)) = request.camera_failure {
        let observers: BTreeSet<&String> =
            zones.iter().flat_map(|(_, observers)| observers).collect();
        for sensor in observers {
            domains.push(DomainSpec {
                id: format!("camera:{sensor}"),
                lo_ppm,
                hi_ppm,
                members: BTreeSet::from([sensor.clone()]),
            });
        }
    }
    let model = ReliabilityModel::new(&zones, &domains)
        .map_err(|error| format!("{}: {error}", error.stable_id()))?;
    let run = reliability::reliability_bounds(&model, Budget::new(MAX_OPERATIONS, 1 << 24))
        .map_err(|error| format!("{}: {error}", error.stable_id()))?;
    let parent = report.witness.digest().to_text();
    let projection_id = format!("DeviceFailureGraph@parent:{parent}");
    let anchor: LedgerAnchor = report.anchor.clone();
    let witness = run
        .witness(&projection_id, anchor)
        .map_err(|error| format!("witness: {error}"))?;
    let ppm = |value: u128, ceil: bool| -> String {
        let scaled = if ceil {
            value.div_ceil(1_000_000_000_000)
        } else {
            value / 1_000_000_000_000
        };
        scaled.to_string()
    };
    let rows: Vec<String> = run
        .output
        .zones
        .iter()
        .map(|zone| {
            let (lo, hi) = zone.blind_probability_e18;
            let cuts: Vec<String> = zone
                .minimal_cuts
                .iter()
                .map(|cut| {
                    object(&[
                        ("domains", strings(&cut.domains)),
                        (
                            "joint_failure_probability_e18",
                            array(&[
                                decimal(cut.probability_e18.0),
                                decimal(cut.probability_e18.1),
                            ]),
                        ),
                    ])
                })
                .collect();
            object(&[
                ("scope", string(&zone.zone)),
                ("observers", strings(&zone.observers)),
                ("relevant_domains", strings(&zone.relevant_domains)),
                ("undeclared_observers", strings(&zone.undeclared_observers)),
                ("blind_probability_e18", array(&[decimal(lo), decimal(hi)])),
                (
                    "blind_probability_ppm",
                    array(&[ppm(lo, false), ppm(hi, true)]),
                ),
                ("minimal_cut_count", zone.minimal_cut_count.to_string()),
                ("minimal_cuts", array(&cuts)),
            ])
        })
        .collect();
    Ok(object(&[
        ("format", string(FORMAT)),
        ("site", string(&report.site)),
        ("anchor", evidence_anchor(&report.anchor)),
        ("coverage_witness_digest", string(&parent)),
        ("coverage_projection_id", string(&report.projection_id)),
        ("algorithm", string(reliability::IDENTITY.algorithm_id)),
        (
            "implementation",
            string(reliability::IDENTITY.implementation_id),
        ),
        ("model_digest", string(&model.digest().to_text())),
        ("zones", array(&rows)),
        ("witness_digest", string(&witness.digest().to_text())),
        ("output_digest", string(&run.output_digest.to_text())),
        (
            "assumptions",
            strings([
                "declared domains fail independently; correlation only through shared domains",
                "probabilities are owner assertions over the declared horizon, not measured availability",
                "observers are retained coverage witnesses, not current observability",
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
                "{ERR_CLI_MALFORMED_VALUE}: {reason}; use fss-event graph reliability --help"
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
