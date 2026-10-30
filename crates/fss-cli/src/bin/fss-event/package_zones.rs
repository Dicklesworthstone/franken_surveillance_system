#![forbid(unsafe_code)]
//! Approved retained class-selected zone derivation and exact cold source verification.

use std::collections::BTreeMap;
use std::error::Error;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, OperationId, PrincipalId};
use fss_reference::ingest::package_event::PackageTrackingConfig;
use fss_reference::ingest::package_zones::{
    PackageZone, PackageZoneConfig, PackageZoneDwell, PackageZoneOperation, PackageZoneReport,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Run<T> = Result<T, Box<dyn Error>>;
const HELP: &str = "fss-event package-zones analyze --root EXISTING_DIR --site SITE\n\
  --package-report sha256:RETAINED_DETECTION_REPORT --label EXACT_PACKAGE_LABEL\n\
  --zone NAME:X:Y:WIDTH:HEIGHT[:MARGIN] [--zone ...] --maximum-sample-gap-ns N\n\
  [--dwell-ns N --minimum-observations N]\n\
  [--confirmation-hits N --maximum-missed-frames N --minimum-iou-ppm N]\n\
  [--retain sha256:EXACT_APPROVAL] [--principal ID]\n\
fss-event package-zones read --root EXISTING_DIR --site SITE\n\
  --report-digest sha256:RETAINED_ZONE_REPORT [--principal ID]\n\
Analyze reopens fss-infer package-detect --retain yes custody and selects exactly one\n\
package vocabulary label. It does not run inference, decode media or use foreground tracks.\n\
The full output includes source frames, every track/zone/frame cell, actual assigned boxes\n\
in 1/256 pixels, per-sample confirmation, interruptions, observed transitions and sampled dwell.\n\
Clipped, masked, tentative and missing samples interrupt observation. Boundary samples\n\
preserve observed crossing endpoints but never count as inside dwell or a definite side.\n\
Dwell requires the retained import's explicit capture-time hints. Missing source bytes and\n\
unreliable frame-index timing cannot be replaced with receive time or assumed continuity.\n\
Preview first, inspect the complete report, then rerun with its exact approval_digest.\n\
Retention is root-last cognition and exact retries preserve the original commit. Read rebuilds\n\
the exact retained recipe with current source/privacy/deletion checks, without loose source,\n\
model or report files. It never repairs missing custody. A report is not a canonical event,\n\
calibrated class/presence assertion, continuous occupancy, absence proof or effect grant.\n\
At most 16 zones, 64 source frames and 8192 total track/zone/frame cells; complete overflow\n\
refuses. Output is complete JSON on stdout (maximum 16 MiB); no safety fields are truncated.\n\
The original source health has not been screened by this operation.\n";

enum Action {
    Analyze {
        package: ContentDigest,
        label: String,
        tracking: PackageTrackingConfig,
        config: PackageZoneConfig,
        approval: Option<ContentDigest>,
    },
    Read(ContentDigest),
}
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    action: Action,
}
fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .ok_or_else(|| format!("required option {key}"))?
        .to_str()
        .ok_or_else(|| format!("{key} requires UTF-8"))
}
fn digest(value: &str) -> Result<ContentDigest, String> {
    let value = ContentDigest::parse(value).map_err(|_| "invalid content digest")?;
    if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
        return Err("nonzero SHA-256 required".into());
    }
    Ok(value)
}
fn integer(value: &str) -> Result<u64, String> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err("unsigned decimal required".into());
    }
    value.parse().map_err(|_| "integer overflow".into())
}
fn number(values: &BTreeMap<String, OsString>, key: &str, default: u64) -> Result<u64, String> {
    values
        .get(key)
        .map_or(Ok(default), |_| integer(text(values, key)?))
}
fn zone(value: &str) -> Result<PackageZone, String> {
    let fields: Vec<_> = value.split(':').collect();
    if !(5..=6).contains(&fields.len()) {
        return Err("zone requires NAME:X:Y:WIDTH:HEIGHT[:MARGIN]".into());
    }
    let mut numbers = [0_u32; 5];
    for (index, value) in fields[1..].iter().enumerate() {
        numbers[index] = u32::try_from(integer(value)?).map_err(|_| "zone coordinate overflow")?;
    }
    Ok(PackageZone {
        id: fields[0].to_owned(),
        x: numbers[0],
        y: numbers[1],
        width: numbers[2],
        height: numbers[3],
        margin: numbers[4],
    })
}
fn parse(args: &[OsString]) -> Result<Options, String> {
    if args.len() > 65 || args.iter().any(|arg| arg.as_encoded_bytes().len() > 4096) {
        return Err("argument bounds exceeded".into());
    }
    let analyze = match args.first().and_then(|arg| arg.to_str()) {
        Some("analyze") => true,
        Some("read") => false,
        _ => return Err("expected package-zones analyze or read".into()),
    };
    let mut values = BTreeMap::new();
    let mut zones = Vec::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or("option names require UTF-8")?;
        let common = ["--root", "--site", "--principal"];
        let analysis = [
            "--package-report",
            "--label",
            "--zone",
            "--maximum-sample-gap-ns",
            "--dwell-ns",
            "--minimum-observations",
            "--confirmation-hits",
            "--maximum-missed-frames",
            "--minimum-iou-ppm",
            "--retain",
        ];
        if !common.contains(&key)
            && !(analyze && analysis.contains(&key))
            && !(key == "--report-digest" && !analyze)
        {
            return Err(format!("unknown or inapplicable option {key}"));
        }
        let value = pair
            .get(1)
            .filter(|v| !v.is_empty() && !v.to_str().is_some_and(|s| s.starts_with("--")))
            .ok_or_else(|| format!("missing value for {key}"))?;
        if key == "--zone" {
            if zones.len() == 16 {
                return Err("zone count exceeds 16".into());
            }
            zones.push(zone(value.to_str().ok_or("zone requires UTF-8")?)?);
        } else if values.insert(key.to_owned(), value.clone()).is_some() {
            return Err(format!("duplicate {key}"));
        }
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
        .map_or(Ok("principal:local-operator"), |v| {
            v.to_str().ok_or("principal requires UTF-8")
        })?
        .to_owned();
    if site.len() > 256 || principal.len() > 128 {
        return Err("site or principal exceeds bound".into());
    }
    PrincipalId::parse(&principal).map_err(|_| "invalid principal ID")?;
    let action = if analyze {
        let label = text(&values, "--label")?.to_owned();
        if label.is_empty() || label.len() > 512 || zones.is_empty() {
            return Err("bounded exact label and at least one zone required".into());
        }
        let dwell = if values.contains_key("--dwell-ns") {
            Some(PackageZoneDwell {
                minimum_duration_ns: integer(text(&values, "--dwell-ns")?)?,
                minimum_observations: usize::try_from(number(
                    &values,
                    "--minimum-observations",
                    2,
                )?)
                .map_err(|_| "observation count overflow")?,
            })
        } else {
            if values.contains_key("--minimum-observations") {
                return Err("--minimum-observations requires --dwell-ns".into());
            }
            None
        };
        let u32_number = |key, default| -> Result<u32, String> {
            u32::try_from(number(&values, key, default)?).map_err(|_| format!("{key} overflow"))
        };
        Action::Analyze {
            package: digest(text(&values, "--package-report")?)?,
            label,
            tracking: PackageTrackingConfig {
                confirmation_hits: u32_number("--confirmation-hits", 2)?,
                maximum_missed_frames: u32_number("--maximum-missed-frames", 1)?,
                minimum_iou_ppm: u32_number("--minimum-iou-ppm", 100_000)?,
            },
            config: PackageZoneConfig {
                maximum_sample_gap_ns: integer(text(&values, "--maximum-sample-gap-ns")?)?,
                dwell,
                zones,
            },
            approval: values
                .get("--retain")
                .map(|_| digest(text(&values, "--retain")?))
                .transpose()?,
        }
    } else {
        Action::Read(digest(text(&values, "--report-digest")?)?)
    };
    Ok(Options {
        root,
        site,
        principal,
        action,
    })
}
fn run(options: Options) -> Run<String> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:package-zones-cli".into(),
        operation_id: OperationId::parse("operation:package-zones-cli")?,
        principal: options.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(512 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:current-deployment-policy".into(),
        retention_scope: "retention:approved-derived-report".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })?;
    let root = super::replay::preflight(&options.root, &options.site, &authority)?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let result = (|| -> Run<String> {
        let mut deployment = ReferenceDeployment::open(&root, &options.site, &cx)?;
        let (report, operation) = match options.action {
            Action::Read(digest) => (
                PackageZoneReport::open(&deployment, digest, &cx)?,
                PackageZoneOperation::ReadVerified,
            ),
            Action::Analyze {
                package,
                label,
                tracking,
                config,
                approval,
            } => {
                let mut report = PackageZoneReport::analyze(
                    &deployment,
                    package,
                    &label,
                    tracking,
                    config,
                    &cx,
                )?;
                report.admit_retention_json()?;
                let operation = match approval {
                    None => PackageZoneOperation::Analyzed,
                    Some(approval) => {
                        if report.retain(&mut deployment, approval, &cx)? {
                            PackageZoneOperation::AlreadyRetained
                        } else {
                            PackageZoneOperation::Retained
                        }
                    }
                };
                (report, operation)
            }
        };
        Ok(report.to_json(operation)?)
    })();
    cx.drain_and_finalize();
    result
}
pub(super) fn main(args: &[OsString]) -> ExitCode {
    if args.is_empty() || args.iter().any(|v| v == "--help" || v == "help") {
        return match super::replay::emit(&mut io::stdout().lock(), HELP.as_bytes()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(_) => ExitCode::from(1),
        };
    }
    let options = match parse(args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {error}; use fss-event package-zones --help");
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
            eprintln!(
                "A previously committed exact retention remains durable; no event or effect is authorized."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}
