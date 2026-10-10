#![forbid(unsafe_code)]
//! Explicit custody authority and bounded offline import execution.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_geometry::WorkBudget;
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{LocalPublicationLimits, LocalRootPublisher};
use fss_reference::ingest::rtsp_import::{
    MAX_ORIGINAL_BYTES, RtspImportAuthority, RtspImportRequest, import_rtsp,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::plan::{CAPS, FORMAT, Options};

struct Owner<'a> {
    options: &'a Options,
    authority: &'a ContextAuthority,
    cx: &'a ReplayCx,
    start: Instant,
}
impl RtspImportAuthority for Owner<'_> {
    fn permit(&self, request: &RtspImportRequest, destination: &ReferenceDeployment) -> bool {
        request
            .digest()
            .is_ok_and(|digest| self.options.request.digest().ok() == Some(digest))
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && self.authority.cancellation_reason.is_none()
            && CAPS.iter().all(|capability| self.authority.has_capability(capability))
            && boundary(self.options, self.cx, self.start).is_ok()
    }
}

fn boundary(options: &Options, cx: &ReplayCx, start: Instant) -> Result<(), &'static str> {
    cx.checkpoint("import_rtsp:operator")
        .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    if start.elapsed() >= Duration::from_millis(options.timeout_ms) {
        return Err("ERR-RTSP-IMPORT-AUTHORITY-001");
    }
    Ok(())
}

fn existing_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

fn execute_authorized(
    options: &Options,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    start: Instant,
) -> Result<String, &'static str> {
    for name in ["", "spool", "roots", "tombstones"] {
        boundary(options, cx, start)?;
        if !existing_directory(&options.archive.join(name)) {
            return Err("ERR-RTSP-IMPORT-SOURCE-001");
        }
    }
    boundary(options, cx, start)?;
    let source_path = options
        .archive
        .canonicalize()
        .map_err(|_| "ERR-RTSP-IMPORT-SOURCE-001")?;
    boundary(options, cx, start)?;
    let target_path = match std::fs::symlink_metadata(&options.root) {
        Ok(metadata) if metadata.file_type().is_dir() => options
            .root
            .canonicalize()
            .map_err(|_| "ERR-RTSP-IMPORT-REQUEST-001")?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => options
            .root
            .parent()
            .ok_or("ERR-RTSP-IMPORT-REQUEST-001")?
            .canonicalize()
            .map_err(|_| "ERR-RTSP-IMPORT-REQUEST-001")?
            .join(options.root.file_name().ok_or("ERR-RTSP-IMPORT-REQUEST-001")?),
        _ => return Err("ERR-RTSP-IMPORT-REQUEST-001"),
    };
    if source_path.starts_with(&target_path) || target_path.starts_with(&source_path) {
        return Err("ERR-RTSP-IMPORT-REQUEST-001");
    }
    boundary(options, cx, start)?;
    let source = LocalRootPublisher::open(
        &options.archive,
        LocalPublicationLimits::new(
            65536,
            MAX_MANIFEST_CHILDREN,
            65536,
            65536,
            SpoolLimits::new(65536, 1024 * 1024 * 1024, MAX_ORIGINAL_BYTES as usize, 131072),
        ),
    )
    .map_err(|_| "ERR-RTSP-IMPORT-SOURCE-001")?;
    boundary(options, cx, start)?;
    let mut destination = ReferenceDeployment::open(&options.root, &options.site, cx)
        .map_err(|_| "ERR-RTSP-IMPORT-CUSTODY-001")?;
    let owner = Owner {
        options,
        authority,
        cx,
        start,
    };
    let mut work = WorkBudget::new(options.work);
    let receipt = import_rtsp(
        &source,
        &mut destination,
        &options.request,
        &owner,
        cx,
        &mut work,
    )
    .map_err(|error| error.stable_id())?;
    // Durable completion remains reportable even if the cooperative deadline expires now.
    Ok(object(&[
        ("format", string(FORMAT)),
        ("kind", string("imported")),
        ("approval_digest", string(&options.approval()?.to_text())),
        ("import_identity", string(&receipt.import_identity.to_text())),
        ("import_root", string(&receipt.import_root.to_text())),
        ("manifest_digest", string(&receipt.manifest_digest.to_text())),
        ("origin_proof", string(&receipt.proof.to_text())),
        ("window_slot", string(options.request.slot.as_str())),
        ("window_root", string(&options.request.root.to_text())),
        ("codec", string(receipt.codec.as_str())),
        ("frames", receipt.frames.to_string()),
        ("capture_time_label", string(receipt.capture_time_label)),
        ("sample_timing", string("retained_mp4_presentation_timestamps")),
        ("reused", receipt.reused.to_string()),
        ("source_archive_retained_separately", "true".into()),
        ("destination_contains_original_recording", "true".into()),
        ("network", string("none")),
        ("work_used", work.used().to_string()),
    ]))
}

pub(super) fn execute(options: &Options) -> Result<String, &'static str> {
    // The exact approval check precedes every filesystem and clock operation.
    if options.approve != Some(options.approval()?) {
        return Err("ERR-RTSP-IMPORT-APPROVAL-001");
    }
    let mut capabilities: Vec<_> = CAPS.iter().map(|value| (*value).to_owned()).collect();
    capabilities.push("ADP-REPLAY-001".into());
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-import".into(),
        operation_id: OperationId::parse("operation:rtsp-import")
            .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(1024 * 1024 * 1024)
            .storage_operations(1_000_000)
            .build()
            .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?,
        privacy_scope: "privacy:owner-original-rtsp-custody".into(),
        retention_scope: "retention:source-closed-rtsp-import".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    authority.validate().map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())
        .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    let result = execute_authorized(options, &authority, &cx, Instant::now());
    cx.drain_and_finalize();
    result
}
