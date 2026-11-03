#![forbid(unsafe_code)]
//! Exact current ownership across HTTP archive, local model, imports and native sentinel.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{array, object, string};
use fss_codec_mjpeg::DecodeBudget;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{LocalPublicationLimits, PublishCancellation, PublishCutPoint};
use fss_reference::http_reconnect_history::VerifiedReconnectHistory;
use fss_reference::ingest::http_history_sentinel::{
    HttpHistorySentinelAuthority, HttpHistorySentinelPlan, process_http_history_sentinel,
};
use fss_reference::ingest::long_sentinel::retained::MAX_LONG_SENTINEL_METADATA_BYTES;
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

use super::archive_open::{ArchiveReadBudget, open_archive};
use super::plan::{FORMAT, Options, PACKAGE_COMPILE_MACS, STORAGE_OPERATIONS};

const AUTHORITY: &str = "ERR-HTTP-HISTORY-SENTINEL-AUTHORITY-001";
const REQUEST: &str = "ERR-HTTP-HISTORY-SENTINEL-REQUEST-001";
const LIMIT: &str = "ERR-HTTP-HISTORY-SENTINEL-LIMIT-001";
const PACKAGE: &str = "ERR-HTTP-HISTORY-SENTINEL-PACKAGE-001";
const SOURCE: &str = "ERR-HTTP-IMPORT-SOURCE-001";
const CAPS: [&str; 5] = [
    "ADP-REPLAY-001",
    "CAP-READ-MEDIA-001",
    "CAP-OBJECT-STAGE-001",
    "CAP-OBJECT-PUBLISH-001",
    "CAP-RETENTION-COMMIT-001",
];

fn current(authority: &ContextAuthority, start: Instant, timeout: u64) -> bool {
    authority.validate().is_ok()
        && authority.cancellation_reason.is_none()
        && CAPS
            .iter()
            .all(|capability| authority.has_capability(capability))
        && start.elapsed() < Duration::from_millis(timeout)
}

struct Owner<'a> {
    options: &'a Options,
    plan_digest: ContentDigest,
    authority: &'a ContextAuthority,
    cx: &'a ReplayCx,
    scalar: &'a ScalarExecCx,
    start: Instant,
}
impl Owner<'_> {
    fn check(&self) -> Result<(), &'static str> {
        if current(self.authority, self.start, self.options.timeout_ms)
            && self.cx.checkpoint("http_history_sentinel:operator").is_ok()
            && self
                .scalar
                .checkpoint("http_history_sentinel:operator")
                .is_ok()
        {
            Ok(())
        } else {
            Err(AUTHORITY)
        }
    }
}
impl HttpHistorySentinelAuthority for Owner<'_> {
    fn permit_sentinel(
        &self,
        plan: &HttpHistorySentinelPlan,
        destination: &ReferenceDeployment,
    ) -> bool {
        plan.digest(&self.options.limits)
            .is_ok_and(|digest| digest == self.plan_digest)
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && self.check().is_ok()
    }
}
impl PublishCancellation for Owner<'_> {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.check().is_err()
    }
}

fn archive_error(error: &'static str) -> &'static str {
    match error {
        "ERR-RTSP-CAMPAIGN-WATCH-AUTHORITY-001" => AUTHORITY,
        "ERR-RTSP-CAMPAIGN-WATCH-LIMIT-001" | "ERR-RTSP-CAMPAIGN-SENTINEL-LIMIT-001" => LIMIT,
        "ERR-RTSP-IMPORT-SOURCE-001" => SOURCE,
        "ERR-RTSP-CAMPAIGN-SENTINEL-PACKAGE-001" => PACKAGE,
        error => error,
    }
}

fn paths(
    options: &Options,
    owner: &Owner<'_>,
    work: &mut WorkBudget<'_>,
) -> Result<(), &'static str> {
    for name in ["", "spool", "roots", "tombstones"] {
        owner.check()?;
        work.charge(128).map_err(|_| LIMIT)?;
        if !std::fs::symlink_metadata(options.archive.join(name))
            .is_ok_and(|m| m.file_type().is_dir())
        {
            return Err(SOURCE);
        }
    }
    owner.check()?;
    work.charge(512).map_err(|_| LIMIT)?;
    let source = options.archive.canonicalize().map_err(|_| SOURCE)?;
    owner.check()?;
    let target = match std::fs::symlink_metadata(&options.root) {
        Ok(m) if m.file_type().is_dir() => options.root.canonicalize().map_err(|_| REQUEST)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => options
            .root
            .parent()
            .ok_or(REQUEST)?
            .canonicalize()
            .map_err(|_| REQUEST)?
            .join(options.root.file_name().ok_or(REQUEST)?),
        _ => return Err(REQUEST),
    };
    owner.check()?;
    // The local model reader independently rejects leaf symlinks and binds its opened inode.
    let package = options.package.canonicalize().map_err(|_| PACKAGE)?;
    if source.starts_with(&target)
        || target.starts_with(&source)
        || package.starts_with(&source)
        || package.starts_with(&target)
    {
        return Err(REQUEST);
    }
    owner.check()
}

fn quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:,./=@+".contains(&b))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn rerun(options: &Options, report: ContentDigest) -> Result<String, &'static str> {
    let l = &options.limits.sentinel;
    let mut args = vec!["fss-infer".to_owned(), "sentinel-replay".into()];
    for (key, value) in [
        ("--root", options.root.to_str().ok_or(REQUEST)?.to_owned()),
        ("--site", options.site.clone()),
        ("--principal", options.principal.clone()),
        ("--report-digest", report.to_text()),
        (
            "--stream-read-bytes",
            l.maximum_source_chunk_bytes.to_string(),
        ),
        ("--stream-pixel-budget", l.maximum_pixel_samples.to_string()),
        ("--max-report-bytes", l.maximum_report_bytes.to_string()),
        ("--max-macs", l.package.run.execution.max_macs.to_string()),
        (
            "--max-tensor-bytes",
            l.package.run.execution.max_bytes.to_string(),
        ),
        (
            "--max-metadata-bytes",
            MAX_LONG_SENTINEL_METADATA_BYTES.to_string(),
        ),
    ] {
        args.push(key.into());
        args.push(quote(&value));
    }
    if let Some(pixels) = options.frame_pixels {
        args.push("--max-frame-pixels".into());
        args.push(pixels.to_string());
    }
    let text = args.join(" ");
    if text.len() > 8192 {
        return Err(LIMIT);
    }
    Ok(text)
}

pub(super) fn execute(options: &Options) -> Result<String, &'static str> {
    // Exact approval and all numerical admission precede every filesystem or clock observation.
    if options.approve != Some(options.approval()?) {
        return Err(AUTHORITY);
    }
    options.preview()?;
    let plan_digest = options
        .plan
        .digest(&options.limits)
        .map_err(|e| e.stable_id())?;
    let authority = Arc::new(
        ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:http-history-sentinel".into(),
            operation_id: OperationId::parse("operation:http-history-sentinel")
                .map_err(|_| AUTHORITY)?,
            principal: options.principal.clone(),
            capabilities: CAPS.iter().map(|c| (*c).to_owned()).collect(),
            deadline: None,
            priority: 10,
            budgets: BudgetVector::builder()
                .bytes(options.authority_byte_budget()?)
                .storage_operations(STORAGE_OPERATIONS)
                .build()
                .map_err(|_| AUTHORITY)?,
            privacy_scope: "privacy:owner-original-http-history-model".into(),
            retention_scope: "retention:source-closed-http-history-sentinel".into(),
            anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
            generation: 1,
        })
        .map_err(|_| AUTHORITY)?,
    );
    authority.validate().map_err(|_| AUTHORITY)?;
    let start = Instant::now();
    let cx = Arc::new(
        ReplayCx::from_context_authority(&authority, options.root.clone())
            .map_err(|_| AUTHORITY)?,
    );
    let scalar = Arc::new(ScalarExecCx::new());
    let result =
        (|| {
            let owner = Owner {
                options,
                plan_digest,
                authority: &authority,
                cx: &cx,
                scalar: &scalar,
                start,
            };
            let mut work = WorkBudget::new(options.work);
            let mut framing = DecodeBudget::new(options.framing);
            paths(options, &owner, &mut work)?;
            let archive_authority = Arc::clone(&authority);
            let archive_cx = Arc::clone(&cx);
            let archive_scalar = Arc::clone(&scalar);
            let allowed = options.archive.clone();
            let timeout = options.timeout_ms;
            let budget = ArchiveReadBudget::new(
                options.archive_read_bytes,
                STORAGE_OPERATIONS,
                Arc::new(move |root: &Path| {
                    root == allowed
                        && current(&archive_authority, start, timeout)
                        && archive_cx
                            .checkpoint("http_history_sentinel:archive_io")
                            .is_ok()
                        && !archive_scalar.is_cancelled()
                }),
            );
            owner.check()?;
            let archive = open_archive(
                &options.archive,
                LocalPublicationLimits::new(
                    65536,
                    MAX_MANIFEST_CHILDREN,
                    65536,
                    65536,
                    SpoolLimits::new(65536, 1024 * 1024 * 1024, 16 * 1024 * 1024, 131072),
                ),
                &budget,
            )
            .map_err(archive_error)?;
            let startup_bytes = budget.bytes_read();
            let startup_operations = budget.operations();
            owner.check()?;
            // Do not read the model or create a deployment for a wrong history or generation binding.
            let history = VerifiedReconnectHistory::load(
                &archive,
                options.plan.history,
                options.limits.history,
                &owner,
                &mut work,
            )
            .map_err(|e| {
                budget
                    .check()
                    .err()
                    .map(archive_error)
                    .unwrap_or(e.stable_id())
            })?;
            if history.boundaries().len() != options.plan.bindings.len()
                || history.boundaries().iter().zip(&options.plan.bindings).any(
                    |(source, binding)| {
                        source.scope().stream.generation != binding.generation
                            || source.prefix().bytes > options.limits.maximum_bytes_per_generation
                            || source.totals().frames
                                > options.limits.maximum_frames_per_generation as u64
                    },
                )
            {
                return Err(REQUEST);
            }
            owner.check()?;
            let package_bytes = super::model::read(
                &options.package,
                options.plan.package_digest,
                &|| owner.check(),
                &mut work,
            )
            .map_err(archive_error)?;
            let package = RgbDetectorPackage::load_with_backend(
                &package_bytes,
                options.plan.package_digest,
                PACKAGE_COMPILE_MACS,
                options.plan.backend,
                &cx,
                &scalar,
            )
            .map_err(|e| e.stable_id())?
            .with_execution_threads(options.threads);
            owner.check()?;
            let mut destination = ReferenceDeployment::open(&options.root, &options.site, &cx)
                .map_err(|_| "ERR-HTTP-IMPORT-CUSTODY-001")?;
            let report = process_http_history_sentinel(
                &archive,
                &mut destination,
                &package,
                &package_bytes,
                &options.plan,
                &options.limits,
                &owner,
                &cx,
                &scalar,
                &mut work,
                &mut framing,
            )
            .map_err(|e| {
                budget
                    .check()
                    .err()
                    .map(archive_error)
                    .unwrap_or(e.stable_id())
            })?;
            owner.check()?;
            budget.check().map_err(archive_error)?;
            if report.plan_digest() != plan_digest {
                return Err(AUTHORITY);
            }
            let commands = report
                .generations()
                .iter()
                .map(|generation| {
                    let command = generation
                        .retained()
                        .map(|retained| rerun(options, retained.report_digest()))
                        .transpose()?;
                    Ok(object(&[
                        ("connection", generation.connection().to_string()),
                        ("generation", generation.generation().to_string()),
                        (
                            "command",
                            command.as_deref().map_or_else(|| "null".into(), string),
                        ),
                        (
                            "analysis_retained",
                            generation.retained().is_some().to_string(),
                        ),
                        ("event_publication_authorized", "false".into()),
                    ]))
                })
                .collect::<Result<Vec<_>, &'static str>>()?;
            let native = report
                .to_json(destination.current_anchor().commit_sequence)
                .map_err(|e| e.stable_id())?;
            let output = object(&[
                ("format", string(FORMAT)),
                ("kind", string("completed")),
                ("approval_digest", string(&options.approval()?.to_text())),
                ("report", native),
                ("native_sentinel_reruns", array(&commands)),
                (
                    "history_import_model_work",
                    object(&[
                        ("used", work.used().to_string()),
                        ("remaining", work.remaining().to_string()),
                    ]),
                ),
                (
                    "framing_work",
                    object(&[
                        ("used", framing.used().to_string()),
                        ("remaining", framing.remaining().to_string()),
                    ]),
                ),
                ("model_read_bytes", package_bytes.len().to_string()),
                (
                    "archive_io",
                    object(&[
                        ("startup_read_bytes", startup_bytes.to_string()),
                        ("startup_operations", startup_operations.to_string()),
                        ("total_read_bytes", budget.bytes_read().to_string()),
                        ("total_operations", budget.operations().to_string()),
                        ("maximum_read_bytes", options.archive_read_bytes.to_string()),
                        ("maximum_operations", STORAGE_OPERATIONS.to_string()),
                    ]),
                ),
                ("event_publication_authorized", "false".into()),
                ("capture_resume_authorized", "false".into()),
            ]);
            if output.len() >= options.limits.maximum_report_bytes {
                return Err(LIMIT);
            }
            owner.check()?;
            Ok(output)
        })();
    scalar.drain_and_finalize();
    cx.drain_and_finalize();
    result
}
