#![forbid(unsafe_code)]
//! Read-only QSR projection of one exact retained, screened package-zone report.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, OperationId, PrincipalId};
use fss_reference::ingest::qsr_observations::{
    QsrConfig, QsrObservationReport, QsrZoneBinding, QsrZoneRole,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Run<T> = Result<T, Box<dyn Error>>;
const HELP: &str = "fss-event qsr --root EXISTING_DIR --site SITE --report-digest sha256:ZONE_REPORT\n\
  [--zone-role ZONE:area|queue|register] [--zone-role ...]\n\
  [--lane-stage ORDER_ZONE --lane-stage PAY_ZONE --lane-stage PRESENT_ZONE]\n\
  [--principal ID]\n\
Reads one retained fss.package_zone_report.v2 produced by package-zones analyze\n\
with --require-health-screening yes and its exact retention approval. The native owner\n\
rechecks source custody, current privacy, historical screening and deletion before delivery.\n\
Returns per-source-frame observed track counts/presence, source-sampled dwell and adjacent\n\
ordered lane-stage observations. Roles annotate existing image zones; they change no geometry.\n\
Unknown or masked samples have null counts. Zero observed tracks is never proof of absence.\n\
Stage times bound observed endpoint separation; they are not service time or queue wait.\n\
Missing, tentative, clipped, screening-excluded, clock-unreliable or discontinuous samples\n\
interrupt lane sequences. Skipped, reversed and ambiguous stages never produce a completed trip.\n\
No inference, source acquisition, QSR persistence, event publication or effect is performed.\n\
At most 16 source zones and 64 sampled frames; output is complete JSON, at most 8 MiB.\n";

struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    report: ContentDigest,
    config: QsrConfig,
}
fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .ok_or_else(|| format!("required option {key}"))?
        .to_str()
        .ok_or_else(|| format!("{key} requires UTF-8"))
}
fn zone_id(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err("zone requires a bounded existing ASCII identifier".into());
    }
    Ok(value.to_owned())
}
fn parse(args: &[OsString]) -> Result<Options, String> {
    if args.len() > 74
        || args
            .iter()
            .any(|value| value.as_encoded_bytes().len() > 4096)
    {
        return Err("argument bounds exceeded".into());
    }
    let mut values = BTreeMap::new();
    let mut config = QsrConfig::default();
    for pair in args.chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        if ![
            "--root",
            "--site",
            "--principal",
            "--report-digest",
            "--zone-role",
            "--lane-stage",
        ]
        .contains(&key)
        {
            return Err(format!("unknown option {key}"));
        }
        let value = pair
            .get(1)
            .filter(|value| {
                !value.is_empty() && !value.to_str().is_some_and(|s| s.starts_with("--"))
            })
            .ok_or_else(|| format!("missing value for {key}"))?;
        match key {
            "--zone-role" => {
                if config.zone_roles.len() == 16 {
                    return Err("zone-role count exceeds 16".into());
                }
                let (zone, role) = value
                    .to_str()
                    .ok_or("zone role requires UTF-8")?
                    .split_once(':')
                    .ok_or("zone role requires ZONE:area|queue|register")?;
                let zone = zone_id(zone)?;
                if config.zone_roles.iter().any(|binding| binding.zone == zone) {
                    return Err("duplicate zone role".into());
                }
                let role = match role {
                    "area" => QsrZoneRole::Area,
                    "queue" => QsrZoneRole::Queue,
                    "register" => QsrZoneRole::Register,
                    _ => return Err(
                        "zone role requires area, queue or register; lane stages use --lane-stage"
                            .into(),
                    ),
                };
                config.zone_roles.push(QsrZoneBinding { zone, role });
            }
            "--lane-stage" => {
                if config.lane_stages.len() == 16 {
                    return Err("lane-stage count exceeds 16".into());
                }
                let zone = zone_id(value.to_str().ok_or("lane stage requires UTF-8")?)?;
                if config.lane_stages.contains(&zone) {
                    return Err("duplicate lane stage".into());
                }
                config.lane_stages.push(zone);
            }
            _ => {
                if values.insert(key.to_owned(), value.clone()).is_some() {
                    return Err(format!("duplicate {key}"));
                }
            }
        }
    }
    if config.lane_stages.len() == 1 {
        return Err("a lane requires at least two stages".into());
    }
    if config
        .zone_roles
        .iter()
        .any(|binding| config.lane_stages.contains(&binding.zone))
    {
        return Err("lane stages cannot also carry another zone role".into());
    }
    let root = PathBuf::from(values.get("--root").ok_or("required option --root")?);
    if !root.is_absolute() {
        return Err("--root must be absolute".into());
    }
    let site = text(&values, "--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site lineage")?;
    let principal = values
        .get("--principal")
        .map_or(Ok("principal:local-operator"), |value| {
            value.to_str().ok_or("principal requires UTF-8")
        })?
        .to_owned();
    if site.len() > 256 || principal.len() > 128 {
        return Err("site or principal exceeds bound".into());
    }
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let report = ContentDigest::parse(text(&values, "--report-digest")?)
        .map_err(|_| "invalid report digest")?;
    if report.algorithm() != DigestAlgorithm::Sha256 || report.bytes() == [0; 32] {
        return Err("nonzero SHA-256 report required".into());
    }
    Ok(Options {
        root,
        site,
        principal,
        report,
        config,
    })
}
fn run(options: Options) -> Run<String> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:qsr-read-cli".into(),
        operation_id: OperationId::parse("operation:qsr-read-cli")?,
        principal: options.principal,
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(512 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:current-deployment-policy".into(),
        retention_scope: "retention:read-existing".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    let root = super::replay::preflight(&options.root, &options.site, &authority)?;
    let cx = ReplayCx::from_context_authority_read_only(&authority, &root)?;
    let result = (|| -> Run<String> {
        let deployment = ReferenceDeployment::open(&root, &options.site, &cx)?;
        Ok(
            QsrObservationReport::open(&deployment, options.report, options.config, &cx)?
                .to_json()?,
        )
    })();
    cx.drain_and_finalize();
    result
}
pub(super) fn main(args: &[OsString]) -> ExitCode {
    if args.is_empty()
        || args
            .iter()
            .any(|value| value == "--help" || value == "help")
    {
        return match super::replay::emit(&mut io::stdout().lock(), HELP.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        };
    }
    let options = match parse(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {error}; use fss-event qsr --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(options).and_then(|output| {
        super::replay::emit(&mut io::stdout().lock(), output.as_bytes())?;
        Ok(())
    }) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{ERR_CLI_RUNTIME_FAILURE}: {error}");
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(extra: &[&str]) -> Vec<OsString> {
        let mut args: Vec<_> = [
            "--root",
            "/tmp/qsr-existing",
            "--site",
            "site:qsr",
            "--report-digest",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        args.push(
            ContentDigest::sha256(b"retained screened source")
                .to_text()
                .into(),
        );
        args.extend(extra.iter().map(OsString::from));
        args
    }
    #[test]
    fn roles_and_lane_order_are_explicit_and_bounded() -> Result<(), String> {
        let parsed = parse(&args(&[
            "--zone-role",
            "queue:queue",
            "--zone-role",
            "till:register",
            "--lane-stage",
            "order",
            "--lane-stage",
            "pay",
            "--lane-stage",
            "present",
        ]))?;
        assert_eq!(parsed.config.zone_roles.len(), 2);
        assert_eq!(parsed.config.lane_stages, ["order", "pay", "present"]);
        assert_eq!(parsed.principal, "principal:local-operator");
        Ok(())
    }
    #[test]
    fn authority_mutations_and_ambiguous_annotations_have_no_cli_path() {
        for extra in [
            vec!["--retain", "yes"],
            vec!["--approve", "yes"],
            vec!["--zone-role", "queue:customer_identity"],
            vec!["--lane-stage", "pay"],
            vec!["--lane-stage", "pay", "--lane-stage", "pay"],
            vec![
                "--zone-role",
                "pay:register",
                "--lane-stage",
                "pay",
                "--lane-stage",
                "present",
            ],
            vec!["--zone-role", "queue:queue", "--zone-role", "queue:area"],
            vec!["--root", "/tmp/another"],
        ] {
            assert!(parse(&args(&extra)).is_err(), "accepted {extra:?}");
        }
    }
    #[test]
    fn malformed_digest_relative_root_missing_value_and_non_utf8_are_refused() {
        let mut input = args(&[]);
        input[1] = "relative".into();
        assert!(parse(&input).is_err());
        let mut input = args(&[]);
        input[5] = "sha256:0000000000000000000000000000000000000000000000000000000000000000".into();
        assert!(parse(&input).is_err());
        let mut input = args(&[]);
        input.push("--lane-stage".into());
        assert!(parse(&input).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let mut input = args(&[]);
            input[5] = OsString::from_vec(vec![255]);
            assert!(parse(&input).is_err());
        }
    }
}
