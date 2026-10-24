#![forbid(unsafe_code)]
//! Read-only retained supervisor admission; the shared library owns every source decision.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fss_cli::supervisor::retained::{
    MAX_RETAINED_SUPERVISOR_PLAN_BYTES, RetainedDiscoveryRequest, RetainedSupervisorPlan,
    run_discovered_retained_supervisor, run_retained_supervisor,
};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, DigestAlgorithm, OperationId, PrincipalId,
    RootAuthoritySpec,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

#[derive(Clone, Copy)]
enum Mode {
    Explicit,
    Discover,
}

enum InputPlan {
    Explicit(RetainedSupervisorPlan),
    Discover(RetainedDiscoveryRequest),
}

impl InputPlan {
    fn template(&self) -> &RetainedSupervisorPlan {
        match self {
            Self::Explicit(plan) => plan,
            Self::Discover(request) => request.template(),
        }
    }
}

struct Options {
    mode: Mode,
    root: PathBuf,
    site: String,
    principal: String,
    plan: PathBuf,
    digest: ContentDigest,
    report_out: Option<PathBuf>,
}

struct Failure {
    exit: u8,
    identity: &'static str,
    reason: String,
}
impl Failure {
    fn malformed(reason: impl fmt::Display) -> Self {
        Self {
            exit: ExitIdentity::MALFORMED_VALUE.code,
            identity: ERR_CLI_MALFORMED_VALUE,
            reason: reason.to_string(),
        }
    }
    fn runtime(reason: impl fmt::Display) -> Self {
        Self {
            exit: ExitIdentity::RUNTIME_FAILURE.code,
            identity: ERR_CLI_RUNTIME_FAILURE,
            reason: reason.to_string(),
        }
    }
}
type Result<T> = std::result::Result<T, Failure>;

fn text<'a>(values: &'a BTreeMap<String, OsString>, key: &str) -> Result<&'a str> {
    values
        .get(key)
        .and_then(|value| value.to_str())
        .ok_or_else(|| Failure::malformed(format!("required UTF-8 option {key}")))
}

fn parse(values: &BTreeMap<String, OsString>) -> Result<Options> {
    let explicit =
        values.contains_key("--retained-plan") || values.contains_key("--retained-digest");
    let discover =
        values.contains_key("--discover-plan") || values.contains_key("--discover-digest");
    if values.contains_key("--plan") || (explicit && discover) {
        return Err(Failure::malformed(
            "--plan, --retained-plan and --discover-plan are mutually exclusive modes",
        ));
    }
    let (mode, plan_flag, digest_flag) = if discover {
        (Mode::Discover, "--discover-plan", "--discover-digest")
    } else {
        (Mode::Explicit, "--retained-plan", "--retained-digest")
    };
    let root = values
        .get("--root")
        .ok_or_else(|| Failure::malformed("required --root"))?;
    let plan = values
        .get(plan_flag)
        .ok_or_else(|| Failure::malformed(format!("required {plan_flag}")))?;
    let digest = ContentDigest::parse(text(values, digest_flag)?).map_err(Failure::malformed)?;
    if digest.algorithm() != DigestAlgorithm::Sha256 || digest.bytes() == [0; 32] {
        return Err(Failure::malformed(format!(
            "{digest_flag} must be a nonzero SHA-256 digest",
        )));
    }
    let site = text(values, "--site")?;
    if site.is_empty() || site.len() > 256 || site.chars().any(char::is_control) {
        return Err(Failure::malformed("invalid --site"));
    }
    let principal = match values.get("--principal") {
        Some(value) => value
            .to_str()
            .ok_or_else(|| Failure::malformed("--principal requires UTF-8"))?,
        None => "principal:local-operator",
    };
    PrincipalId::parse(principal).map_err(Failure::malformed)?;
    Ok(Options {
        mode,
        root: PathBuf::from(root),
        site: site.to_owned(),
        principal: principal.to_owned(),
        plan: PathBuf::from(plan),
        digest,
        report_out: values.get("--report-out").map(PathBuf::from),
    })
}

fn load_plan(path: &Path, expected: ContentDigest, mode: Mode, cx: &ReplayCx) -> Result<InputPlan> {
    cx.checkpoint("retained_supervisor_cli:plan")
        .map_err(Failure::runtime)?;
    let metadata = fs::symlink_metadata(path).map_err(Failure::malformed)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_RETAINED_SUPERVISOR_PLAN_BYTES as u64
    {
        return Err(Failure::malformed(
            "retained plan must be a regular file of at most 256 KiB",
        ));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .and_then(|file| {
            file.take(MAX_RETAINED_SUPERVISOR_PLAN_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(Failure::malformed)?;
    cx.checkpoint("retained_supervisor_cli:plan_read")
        .map_err(Failure::runtime)?;
    match mode {
        Mode::Explicit => {
            RetainedSupervisorPlan::from_json(&bytes, expected).map(InputPlan::Explicit)
        }
        Mode::Discover => {
            RetainedDiscoveryRequest::from_json(&bytes, expected).map(InputPlan::Discover)
        }
    }
    .map_err(Failure::malformed)
}

fn run(options: Options) -> Result<()> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:event-supervise-retained".into(),
        operation_id: OperationId::parse("operation:event-supervise-retained")
            .map_err(Failure::runtime)?,
        principal: options.principal,
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(64 * 1024 * 1024)
            .build()
            .map_err(Failure::runtime)?,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(Failure::runtime)?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())
        .map_err(Failure::runtime)?;
    let result = (|| {
        let plan = load_plan(&options.plan, options.digest, options.mode, &cx)?;
        if plan.template().spec().site_lineage != options.site {
            return Err(Failure::malformed(
                "retained plan site_lineage does not match --site",
            ));
        }
        cx.checkpoint("retained_supervisor_cli:existing_deployment")
            .map_err(Failure::runtime)?;
        let root_exists = fs::symlink_metadata(&options.root).is_ok_and(|m| m.file_type().is_dir());
        let layout_exists = fs::symlink_metadata(options.root.join("LAYOUT"))
            .is_ok_and(|m| m.file_type().is_file());
        if !root_exists || !layout_exists {
            return Err(Failure::runtime("existing non-symlink deployment required"));
        }
        let mut deployment = ReferenceDeployment::open(&options.root, &options.site, &cx)
            .map_err(Failure::runtime)?;
        let rendered = match &plan {
            InputPlan::Explicit(plan) => run_retained_supervisor(&mut deployment, plan, &cx)
                .and_then(|report| report.to_json()),
            InputPlan::Discover(request) => {
                run_discovered_retained_supervisor(&mut deployment, request, &cx)
                    .and_then(|report| report.to_json())
            }
        }
        .map_err(|error| Failure {
            exit: ExitIdentity::RUNTIME_FAILURE.code,
            identity: error.stable_id(),
            reason: error.to_string(),
        })?;
        let rendered = format!("{rendered}\n");
        cx.checkpoint("retained_supervisor_cli:output")
            .map_err(Failure::runtime)?;
        if let Some(path) = &options.report_out {
            super::super::export(path, rendered.as_bytes(), &options.root, &cx)
                .map_err(Failure::runtime)?;
        }
        io::stdout()
            .lock()
            .write_all(rendered.as_bytes())
            .map_err(Failure::runtime)?;
        Ok(())
    })();
    cx.drain_and_finalize();
    result
}

pub(super) fn main(values: &BTreeMap<String, OsString>) -> ExitCode {
    match parse(values).and_then(run) {
        Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
        Err(error) => {
            eprintln!("{}: {}", error.identity, error.reason);
            ExitCode::from(error.exit)
        }
    }
}
