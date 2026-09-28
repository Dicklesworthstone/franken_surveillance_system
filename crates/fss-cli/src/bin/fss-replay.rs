#![forbid(unsafe_code)]
//! Local operator discovery and exact-tip native reconstruction of retained HTTP/RGB histories.
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, evidence_anchor, object, string};
use fss_cli::{ERR_CLI_MALFORMED_VALUE, ERR_CLI_RUNTIME_FAILURE, ExitIdentity};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, DigestAlgorithm, OperationId, PrincipalId};
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{
    LocalPublicationLimits, LocalRootPublisher, PublishCancellation, PublishCutPoint,
};
use fss_reference::ingest::http_rgb_history::{
    HistoryAuthority, HistoryLimits, HistoryOperation, HttpRgbHistory, HttpRgbHistoryTip,
};
use fss_reference::ingest::http_rgb_history_replay::*;
use fss_reference::ingest::rgb_archive::{RgbArchiveAuthority, RgbArchiveOperation};
use fss_reference::{ExecBudget, ReferenceDeployment, ReplayCx, ScalarExecCx};

#[path = "fss-replay/selection.rs"]
mod selection;

type Run<T> = Result<T, Box<dyn Error>>;
const HELP: &str = "fss-replay inspect-http-rgb --root EXISTING_DEPLOYMENT --site SITE --session sha256:HEX\n\
fss-replay http-rgb --root EXISTING_DEPLOYMENT --site SITE --session sha256:HEX\n\
  --expected-root sha256:HEX --expected-revision N --original-root EXISTING_ARCHIVE\n\
  --read-originals yes --execute-model yes [bounds]\n\
Inspect returns the exact committed tip and any pending unledgered prefix; it runs no model.\n\
Replay executes every selected frame and compares source, detector, tracking and zone identities.\n\
A changed committed tip refuses. A prefix is not source completion. No network, repair,\n\
model download, raw-media export, event/alert write or production qualification is implied.\n\
The retained configuration names the sensor; current privacy policy cannot be overridden.\n\
Common: --principal ID --timeout-ms N --max-work N --max-report-bytes N\n\
Replay bounds: --max-frames N --max-steps N --read-bytes N --max-copy-work N\n\
  --max-import-work N --max-decode-work N --max-framing-work N --max-head-work N\n\
  --max-temporal-work N --max-attempts N --stage-macs N --stage-bytes N\n\
  --max-execution-macs N\n\
Optional original tip: --wire-head sha256:HEX --wire-reads N --wire-bytes N (all three).\n\
Optional current privacy authority: --privacy-root EXISTING_DIR --privacy-site SITE.\n\
Stage ceilings apply independently to preprocessing and execution. Their sum is reserved\n\
per attempt against the whole-session execution allowance, not reported as measured work.\n\
Existing exclusive locks/recovery sync apply. Deadlines are checked between native stages;\n\
a kernel, filesystem operation or stdout write is not hard-real-time preemptible.\n";

#[derive(Debug)]
struct Options {
    root: PathBuf,
    site: String,
    principal: String,
    session: ContentDigest,
    expected: Option<HttpRgbHistoryTip>,
    original: Option<PathBuf>,
    selection: selection::Selection,
    timeout: Duration,
    report_bytes: usize,
    maximum_frames: usize,
    maximum_steps: u64,
    read_bytes: usize,
    work: u64,
    copy: u64,
    import: u64,
    decode: u64,
    framing: u64,
    head: u64,
    temporal: u64,
    attempts: u64,
    stage_macs: u64,
    stage_bytes: usize,
    execution_macs: u64,
}
fn parse(args: &[OsString]) -> Result<Options, String> {
    if args.len() > 65 || args.iter().any(|s| s.as_encoded_bytes().len() > 4096) {
        return Err("argument bounds exceeded".into());
    }
    let action = args
        .first()
        .and_then(|s| s.to_str())
        .ok_or("expected inspect-http-rgb or http-rgb")?;
    let verify = match action {
        "inspect-http-rgb" => false,
        "http-rgb" => true,
        _ => return Err("unknown replay command".into()),
    };
    let common = [
        "--root",
        "--site",
        "--session",
        "--principal",
        "--timeout-ms",
        "--max-work",
        "--max-report-bytes",
    ];
    let replay = [
        "--expected-root",
        "--expected-revision",
        "--original-root",
        "--read-originals",
        "--execute-model",
        "--max-frames",
        "--max-steps",
        "--read-bytes",
        "--max-copy-work",
        "--max-import-work",
        "--max-decode-work",
        "--max-framing-work",
        "--max-head-work",
        "--max-temporal-work",
        "--max-attempts",
        "--stage-macs",
        "--stage-bytes",
        "--max-execution-macs",
        "--privacy-root",
        "--privacy-site",
        "--wire-head",
        "--wire-reads",
        "--wire-bytes",
    ];
    let mut values: BTreeMap<&str, &OsStr> = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or("option requires UTF-8")?;
        if !common.contains(&key) && !(verify && replay.contains(&key)) {
            return Err("unknown or inapplicable option".into());
        }
        let value = pair
            .get(1)
            .filter(|s| !s.is_empty() && !s.to_str().is_some_and(|s| s.starts_with("--")))
            .ok_or("missing option value")?;
        if values.insert(key, value.as_os_str()).is_some() {
            return Err("duplicate option".into());
        }
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| format!("required option {key}"))
    };
    let text = |key: &str| {
        required(key)?
            .to_str()
            .ok_or_else(|| format!("{key} requires UTF-8"))
    };
    let digest = |key: &str| -> Result<ContentDigest, String> {
        let d = ContentDigest::parse(text(key)?).map_err(|_| "invalid content digest")?;
        if d.algorithm() != DigestAlgorithm::Sha256 || d.bytes() == [0; 32] {
            return Err("nonzero SHA-256 required".into());
        }
        Ok(d)
    };
    let number = |key: &str, default: u64, min: u64, max: u64| -> Result<u64, String> {
        let n = if values.contains_key(key) {
            let s = text(key)?;
            if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("{key} requires unsigned decimal"));
            }
            s.parse().map_err(|_| format!("{key} integer overflow"))?
        } else {
            default
        };
        if n < min || n > max {
            return Err(format!("{key} outside bounds"));
        }
        Ok(n)
    };
    let root = PathBuf::from(required("--root")?);
    if !root.is_absolute() {
        return Err("--root must be absolute".into());
    }
    let site = text("--site")?.to_owned();
    fss_reference::reference_deployment::validate_site_lineage(&site)
        .map_err(|_| "invalid site")?;
    let principal = if values.contains_key("--principal") {
        text("--principal")?
    } else {
        "principal:local-operator"
    }
    .to_owned();
    PrincipalId::parse(&principal).map_err(|_| "invalid principal")?;
    if site.len() > 256 || principal.len() > 256 {
        return Err("site and principal exceed 256 bytes".into());
    }
    let session = digest("--session")?;
    let (expected, original) = if verify {
        if text("--read-originals")? != "yes" {
            return Err("explicit original-header/JPEG/model read acknowledgement required".into());
        }
        if text("--execute-model")? != "yes" {
            return Err("explicit exact-model execution acknowledgement required".into());
        }
        required("--expected-revision")?;
        let path = PathBuf::from(required("--original-root")?);
        if !path.is_absolute() {
            return Err("--original-root must be absolute".into());
        }
        (
            Some(HttpRgbHistoryTip {
                session,
                root: digest("--expected-root")?,
                revision: number("--expected-revision", 0, 0, 65)?,
            }),
            Some(path),
        )
    } else {
        (None, None)
    };
    Ok(Options {
        root,
        site,
        principal,
        session,
        expected,
        original,
        selection: selection::Selection::parse(&values)?,
        timeout: Duration::from_millis(number("--timeout-ms", 60_000, 1, 3_600_000)?),
        report_bytes: number("--max-report-bytes", 1024 * 1024, 1024, 16 * 1024 * 1024)? as usize,
        maximum_frames: number("--max-frames", 64, 1, 64)? as usize,
        maximum_steps: number("--max-steps", 1_000_000, 1, 1_000_000)?,
        read_bytes: number("--read-bytes", 16384, 1, 65536)? as usize,
        work: number("--max-work", 10_000_000_000_000, 0, 1_000_000_000_000_000)?,
        copy: number("--max-copy-work", 100_000_000_000, 0, 1_000_000_000_000_000)?,
        import: number(
            "--max-import-work",
            10_000_000_000,
            0,
            1_000_000_000_000_000,
        )?,
        decode: number(
            "--max-decode-work",
            10_000_000_000,
            0,
            1_000_000_000_000_000,
        )?,
        framing: number(
            "--max-framing-work",
            1_000_000_000,
            0,
            1_000_000_000_000_000,
        )?,
        head: number("--max-head-work", 10_000_000_000, 0, 1_000_000_000_000_000)?,
        temporal: number(
            "--max-temporal-work",
            1_000_000_000,
            0,
            1_000_000_000_000_000,
        )?,
        attempts: number("--max-attempts", 64, 0, 64)?,
        stage_macs: number("--stage-macs", 20_000_000_000, 0, 1_000_000_000_000)?,
        stage_bytes: number("--stage-bytes", 256 * 1024 * 1024, 1, 512 * 1024 * 1024)? as usize,
        execution_macs: number(
            "--max-execution-macs",
            3_000_000_000_000,
            0,
            1_000_000_000_000_000,
        )?,
    })
}
struct Clock {
    start: Instant,
    duration: Duration,
}
impl Clock {
    fn alive(&self) -> bool {
        self.start.elapsed() < self.duration
    }
}
impl PublishCancellation for Clock {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        !self.alive()
    }
}
struct HistoryRead<'a> {
    session: ContentDigest,
    clock: &'a Clock,
}
impl HistoryAuthority for HistoryRead<'_> {
    fn permits(&self, operation: HistoryOperation, session: ContentDigest) -> bool {
        operation == HistoryOperation::Read && session == self.session && self.clock.alive()
    }
}
struct EvidenceRead<'a> {
    retention: ContentDigest,
    evidence: BTreeSet<ContentDigest>,
    clock: &'a Clock,
}
impl RgbArchiveAuthority for EvidenceRead<'_> {
    fn permits(
        &self,
        operation: RgbArchiveOperation,
        retention: ContentDigest,
        evidence: ContentDigest,
    ) -> bool {
        operation == RgbArchiveOperation::ReadOriginals
            && retention == self.retention
            && self.evidence.contains(&evidence)
            && self.clock.alive()
    }
}
struct Execute<'a> {
    session: ContentDigest,
    model: ContentDigest,
    clock: &'a Clock,
}
impl ReplayAuthority for Execute<'_> {
    fn permits_replay(&self, session: ContentDigest, model: ContentDigest) -> bool {
        session == self.session && model == self.model && self.clock.alive()
    }
}
fn failure(message: &'static str) -> Box<dyn Error> {
    io::Error::other(message).into()
}
fn directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}
fn file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}
fn existing_deployment(path: &Path) -> Run<PathBuf> {
    if !directory(path) || !file(&path.join("LAYOUT")) {
        return Err(failure("existing non-symlink deployment required"));
    }
    Ok(std::fs::canonicalize(path)?)
}
fn existing_original(path: &Path) -> Run<PathBuf> {
    if !directory(path) {
        return Err(failure("existing non-symlink original archive required"));
    }
    let root = std::fs::canonicalize(path)?;
    for name in [
        "roots",
        "tombstones",
        "spool",
        "spool/objects",
        "spool/staging",
        "spool/verified",
    ] {
        if !directory(&root.join(name)) {
            return Err(failure("existing original archive layout required"));
        }
    }
    if !file(&root.join("LOCK")) || !file(&root.join("spool/LOCK")) {
        return Err(failure("existing original archive lock layout required"));
    }
    Ok(root)
}
fn tip(value: HttpRgbHistoryTip) -> String {
    object(&[
        ("session", string(&value.session.to_text())),
        ("root", string(&value.root.to_text())),
        ("revision", value.revision.to_string()),
    ])
}
fn summary(value: &HttpRgbHistory) -> Run<String> {
    let config = value.config().spec();
    Ok(object(&[
        ("tip", tip(value.tip()?)),
        ("frames", value.frames().len().to_string()),
        (
            "source_completion_recorded",
            value.is_complete().to_string(),
        ),
        ("sensor", string(config.sensor.as_str())),
        ("model", string(&config.model.to_text())),
        ("head", string(&config.head.to_text())),
        ("numerical_execution", string("not_run")),
    ]))
}
fn optional_tip(value: Option<HttpRgbHistoryTip>) -> String {
    value.map_or_else(|| "null".into(), tip)
}
fn run(o: &Options) -> Run<String> {
    let clock = Clock {
        start: Instant::now(),
        duration: o.timeout,
    };
    let root = existing_deployment(&o.root)?;
    let original = o
        .original
        .as_ref()
        .map(|p| existing_original(p))
        .transpose()?;
    if original
        .as_ref()
        .is_some_and(|p| p.starts_with(&root) || root.starts_with(p))
    {
        return Err(failure(
            "original archive and evidence deployment must not overlap",
        ));
    }
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:http-rgb-history-replay-cli".into(),
        operation_id: OperationId::parse("operation:http-rgb-history-replay-cli")?,
        principal: o.principal.clone(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(1_000_000)
            .build()?,
        privacy_scope: "privacy:owner-authorized-history-replay".into(),
        retention_scope: "retention:read-existing-no-mutation".into(),
        anchor_universe: ContentDigest::sha256(o.site.as_bytes()),
        generation: 1,
    })?;
    authority.validate()?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
    let result = run_with(o, &root, original.as_deref(), &cx, &clock);
    cx.drain_and_finalize();
    result
}
fn usage(u: ReplayUsage) -> String {
    object(&[
        ("steps", u.steps.to_string()),
        ("inferences", u.inferences.to_string()),
        ("source", u.source.to_string()),
        ("copy", u.copy.to_string()),
        ("import", u.import.to_string()),
        ("framing", u.framing.to_string()),
        ("decode", u.decode.to_string()),
        ("detections", u.detections.to_string()),
        ("temporal", u.temporal.to_string()),
        ("numerical_reserved", u.numerical_reserved.to_string()),
    ])
}
fn run_with(
    o: &Options,
    root: &Path,
    original: Option<&Path>,
    cx: &ReplayCx,
    clock: &Clock,
) -> Run<String> {
    if !clock.alive() {
        return Err(ReplayError::Denied.into());
    }
    let privacy = o
        .selection
        .open_privacy(root, original, &o.principal, clock)?;
    let auth = HistoryRead {
        session: o.session,
        clock,
    };
    let mut deployment = ReferenceDeployment::reopen(root, &o.site, cx)?;
    let mut budget = ReplayBudget::new(
        ReplayAllowance {
            steps: o.maximum_steps,
            inferences: o.attempts,
            source: o.work,
            copy: o.copy,
            import: o.import,
            framing: o.framing,
            decode: o.decode,
            detections: o.head,
            temporal: o.temporal,
            numerical: o.execution_macs,
        },
        64 * 1024 * 1024,
    )?;
    let found = inspect_history(
        &mut deployment,
        o.session,
        HistoryLimits::default(),
        &auth,
        &mut budget,
        cx,
    )?;
    let result = if let Some(expected) = o.expected {
        let selected = found
            .committed
            .as_ref()
            .ok_or(ReplayError::StaleSelection)?;
        if selected.tip()? != expected {
            return Err(ReplayError::StaleSelection.into());
        }
        if selected.frames().len() > o.maximum_frames {
            return Err(ReplayError::Limit.into());
        }
        let evidence = EvidenceRead {
            retention: selected.config().spec().retention,
            evidence: selected
                .frames()
                .iter()
                .map(|p| p.archive.evidence)
                .collect(),
            clock,
        };
        let execution = Execute {
            session: o.session,
            model: selected.config().spec().model,
            clock,
        };
        let wire_tip = o
            .selection
            .wire_tip(selected.config().spec().source.digest()?);
        let privacy = privacy
            .as_ref()
            .map_or(ReplayPrivacy::HistoryDeployment, |p| {
                ReplayPrivacy::External(&p.deployment)
            });
        let storage = LocalPublicationLimits::new(
            8192,
            MAX_MANIFEST_CHILDREN,
            8192,
            65536,
            SpoolLimits::new(65536, 1024 * 1024 * 1024, 16 * 1024 * 1024, 65536),
        );
        if !clock.alive() {
            return Err(ReplayError::Denied.into());
        }
        let publisher = LocalRootPublisher::open(
            original.ok_or_else(|| failure("original archive required"))?,
            storage,
        )?;
        let mut limits = ReplayLimits::default();
        limits.parser.read_bytes = o.read_bytes;
        limits.parser.frames = o.maximum_frames as u64 + 1;
        limits.parser.multipart.frame_bytes = 16 * 1024 * 1024;
        let stage = ExecBudget::new(o.stage_macs, o.stage_bytes);
        limits.execution.run.preprocess = stage;
        limits.execution.run.execution = stage;
        let scalar = ScalarExecCx::new();
        let replayed = replay_history(
            &mut deployment,
            ReplaySource {
                publisher: &publisher,
                tip: wire_tip,
            },
            expected,
            privacy,
            limits,
            ReplayAccess {
                history: &auth,
                evidence: &evidence,
                originals: clock,
                execution: &execution,
            },
            &mut budget,
            cx,
            &scalar,
        );
        scalar.drain_and_finalize();
        let report = replayed?;
        let rows: Vec<_> = report
            .frames()
            .iter()
            .map(|frame| {
                let p = frame.pin;
                let stages: Vec<_> = p
                    .stages
                    .iter()
                    .map(|s| string(&ContentDigest::new(DigestAlgorithm::Sha256, *s).to_text()))
                    .collect();
                object(&[
                    ("ordinal", p.ordinal.to_string()),
                    (
                        "exposure",
                        string(&ContentDigest::new(DigestAlgorithm::Sha256, p.exposure).to_text()),
                    ),
                    (
                        "capture_ns",
                        array(&p.archive.capture.map(|n| string(&n.to_string()))),
                    ),
                    ("stages", array(&stages)),
                    (
                        "mask_policy",
                        p.mask_policy
                            .map_or_else(|| "null".into(), |d| string(&d.to_text())),
                    ),
                    (
                        "mask_generation",
                        p.mask_generation
                            .map_or_else(|| "null".into(), |g| g.to_string()),
                    ),
                    ("detections", frame.detections.to_string()),
                    (
                        "selected_class_detections",
                        frame.selected_class_detections.to_string(),
                    ),
                    ("executed_macs", frame.executed_macs.to_string()),
                    ("preprocess_work", frame.preprocess_work.to_string()),
                ])
            })
            .collect();
        object(&[
            ("status", string(report.status().as_str())),
            ("tip", tip(report.tip())),
            ("anchor", evidence_anchor(report.anchor())),
            ("pending_not_executed", optional_tip(report.pending())),
            ("result_digest", string(&report.digest().to_text())),
            ("privacy_site", string(report.privacy_site())),
            ("privacy_anchor", evidence_anchor(report.privacy_anchor())),
            (
                "source",
                report.source().map_or_else(
                    || "null".into(),
                    |p| {
                        object(&[
                            ("scope", string(&p.scope.to_text())),
                            ("head", string(&p.head.to_text())),
                            ("reads", p.reads.to_string()),
                            ("bytes", p.bytes.to_string()),
                        ])
                    },
                ),
            ),
            (
                "completion_root",
                report
                    .completion()
                    .map_or_else(|| "null".into(), |p| string(&p.root.to_text())),
            ),
            (
                "source_complete",
                (report.status() == ReplayStatus::CompleteVerified).to_string(),
            ),
            ("verified_frames", rows.len().to_string()),
            ("frames", array(&rows)),
            ("execution_attempts", budget.used().inferences.to_string()),
            ("usage", usage(budget.used())),
            ("execution_reservations_are_measured_usage", "false".into()),
        ])
    } else {
        object(&[
            (
                "status",
                string(if found.committed.is_some() {
                    "history_found"
                } else {
                    "no_committed_history"
                }),
            ),
            ("anchor", evidence_anchor(&found.anchor)),
            (
                "committed",
                found
                    .committed
                    .as_ref()
                    .map(summary)
                    .transpose()?
                    .unwrap_or_else(|| "null".into()),
            ),
            (
                "pending_not_executed",
                found
                    .pending
                    .as_ref()
                    .map(summary)
                    .transpose()?
                    .unwrap_or_else(|| "null".into()),
            ),
            ("numerical_execution", string("not_run")),
            ("usage", usage(budget.used())),
        ])
    };
    if !clock.alive() {
        return Err(ReplayError::Denied.into());
    }
    let json = object(&[
        ("schema", string("fss.local_http_rgb_replay.v1")),
        ("site", string(&o.site)),
        ("principal", string(&o.principal)),
        ("result", result),
        ("new_evidence_published", "false".into()),
        ("raw_media_emitted", "false".into()),
        ("physical_coverage_claimed", "false".into()),
        ("qualification", string("implemented_not_qualified")),
    ]);
    if json.len().checked_add(1).is_none_or(|n| n > o.report_bytes) {
        return Err(failure("complete replay report exceeds output bound"));
    }
    Ok(json)
}
fn emit(writer: &mut impl Write, mut bytes: &[u8]) -> io::Result<()> {
    let mut interruptions = 0;
    while !bytes.is_empty() {
        let chunk = &bytes[..bytes.len().min(65536)];
        match writer.write(chunk) {
            Ok(n) if n > 0 && n <= chunk.len() => {
                bytes = &bytes[n..];
                interruptions = 0;
            }
            Ok(_) => return Err(io::ErrorKind::WriteZero.into()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted && interruptions < 7 => {
                interruptions += 1
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).take(66).collect();
    if args.len() == 1 && matches!(args[0].to_str(), Some("--help" | "help" | "-h")) {
        print!("{HELP}");
        return ExitCode::from(ExitIdentity::SUCCESS.code);
    }
    let options = match parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{ERR_CLI_MALFORMED_VALUE}: {e}; use fss-replay --help");
            return ExitCode::from(ExitIdentity::MALFORMED_VALUE.code);
        }
    };
    match run(&options) {
        Ok(mut report) => {
            report.push('\n');
            ExitCode::from(
                if emit(&mut io::stdout().lock(), report.as_bytes()).is_ok() {
                    ExitIdentity::SUCCESS.code
                } else {
                    ExitIdentity::RUNTIME_FAILURE.code
                },
            )
        }
        Err(error) => {
            let code = error
                .downcast_ref::<ReplayError>()
                .map_or(ERR_CLI_RUNTIME_FAILURE, ReplayError::stable_id);
            eprintln!(
                "{code}: no complete replay result; source and event history were not changed. Use fss-replay --help."
            );
            ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn args(verify: bool) -> Vec<OsString> {
        let d = ContentDigest::sha256(b"selected history").to_text();
        let mut v: Vec<_> = [
            if verify {
                "http-rgb"
            } else {
                "inspect-http-rgb"
            },
            "--root",
            "/evidence",
            "--site",
            "site:test",
            "--session",
            &d,
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        if verify {
            v.extend(
                [
                    "--expected-root",
                    &d,
                    "--expected-revision",
                    "2",
                    "--original-root",
                    "/originals",
                    "--read-originals",
                    "yes",
                    "--execute-model",
                    "yes",
                ]
                .into_iter()
                .map(OsString::from),
            );
        }
        v
    }
    #[test]
    fn inspection_is_not_inference_and_needs_no_original_path() -> Result<(), String> {
        let o = parse(&args(false))?;
        assert!(o.expected.is_none());
        assert!(o.original.is_none());
        Ok(())
    }
    #[test]
    fn verification_requires_exact_tip_and_explicit_original_read() -> Result<(), String> {
        for key in [
            "--expected-root",
            "--expected-revision",
            "--original-root",
            "--read-originals",
            "--execute-model",
        ] {
            let mut a = args(true);
            let i = a
                .iter()
                .position(|v| v.as_os_str() == OsStr::new(key))
                .ok_or("fixture option missing")?;
            a.drain(i..i + 2);
            assert!(parse(&a).is_err(), "accepted missing {key}");
        }
        Ok(())
    }
    #[test]
    fn duplicate_and_inapplicable_options_never_open_storage() {
        for (verify, key, value) in [
            (true, "--site", "site:other"),
            (false, "--read-originals", "yes"),
            (true, "--force", "yes"),
        ] {
            let mut a = args(verify);
            a.extend([key, value].into_iter().map(OsString::from));
            assert!(parse(&a).is_err());
        }
    }
    #[test]
    fn whole_session_and_stage_budgets_remain_independent() -> Result<(), String> {
        let mut a = args(true);
        a.extend(
            [
                "--max-attempts",
                "1",
                "--stage-macs",
                "100",
                "--max-execution-macs",
                "150",
            ]
            .into_iter()
            .map(OsString::from),
        );
        let o = parse(&a)?;
        assert_eq!(o.attempts, 1);
        assert_eq!(o.stage_macs, 100);
        assert_eq!(o.execution_macs, 150);
        Ok(())
    }
    #[test]
    fn excessive_negative_or_overflowed_bounds_are_refused() {
        for (key, value) in [
            ("--max-frames", "65"),
            ("--max-steps", "0"),
            ("--stage-macs", "-1"),
            ("--read-bytes", "18446744073709551616"),
        ] {
            let mut a = args(true);
            a.extend([key, value].into_iter().map(OsString::from));
            assert!(parse(&a).is_err());
        }
    }
    #[test]
    fn read_adapters_cannot_retain_or_change_another_session() {
        let clock = Clock {
            start: Instant::now(),
            duration: Duration::from_secs(60),
        };
        let d = ContentDigest::sha256(b"one");
        let auth = HistoryRead {
            session: d,
            clock: &clock,
        };
        assert!(auth.permits(HistoryOperation::Read, d));
        assert!(!auth.permits(HistoryOperation::Retain, d));
        assert!(!auth.permits(HistoryOperation::Read, ContentDigest::sha256(b"other")));
        let evidence = EvidenceRead {
            retention: d,
            evidence: BTreeSet::from([d]),
            clock: &clock,
        };
        assert!(!evidence.permits(RgbArchiveOperation::RetainOriginals, d, d));
    }
    #[test]
    fn compute_authority_is_separate_exact_and_deadline_bound() -> Result<(), String> {
        let d = ContentDigest::sha256(b"model");
        let other = ContentDigest::sha256(b"other");
        let clock = Clock {
            start: Instant::now(),
            duration: Duration::from_secs(60),
        };
        let compute = Execute {
            session: d,
            model: d,
            clock: &clock,
        };
        assert!(compute.permits_replay(d, d));
        assert!(!compute.permits_replay(other, d));
        assert!(!compute.permits_replay(d, other));
        let expired = Clock {
            start: Instant::now(),
            duration: Duration::ZERO,
        };
        assert!(
            !Execute {
                session: d,
                model: d,
                clock: &expired
            }
            .permits_replay(d, d)
        );
        for key in ["--read-originals", "--execute-model"] {
            let mut a = args(true);
            let i = a
                .iter()
                .position(|v| v.as_os_str() == OsStr::new(key))
                .ok_or("fixture option missing")?;
            a[i + 1] = OsString::from("no");
            assert!(parse(&a).is_err());
        }
        Ok(())
    }
    #[test]
    fn output_interruptions_are_bounded() {
        struct Interrupt(usize);
        impl Write for Interrupt {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.0 += 1;
                Err(io::ErrorKind::Interrupted.into())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut sink = Interrupt(0);
        assert!(emit(&mut sink, b"not emitted").is_err());
        assert_eq!(sink.0, 8);
    }
}
