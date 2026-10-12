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
use fss_reference::ingest::rtsp_import::catalog::{
    RtspCatalogImportAuthority, RtspCatalogImportRequest, import_rtsp_catalog,
};
use fss_reference::ingest::rtsp_import::pages::{
    RtspCatalogPagesImportAuthority, RtspCatalogPagesImportRequest, import_rtsp_catalog_pages,
};
use fss_reference::ingest::rtsp_import::{
    MAX_ORIGINAL_BYTES, RtspImportAuthority, RtspImportRequest, import_rtsp,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::plan::{CAPS, CATALOG_FORMAT, FORMAT, Options, PAGES_FORMAT, page_selection_json};

struct Owner<'a> {
    options: &'a Options,
    authority: &'a ContextAuthority,
    cx: &'a ReplayCx,
    start: Instant,
}
impl RtspImportAuthority for Owner<'_> {
    fn permit(&self, request: &RtspImportRequest, destination: &ReferenceDeployment) -> bool {
        self.options.catalog.is_none()
            && self.options.pages.is_none()
            && request
                .digest()
                .is_ok_and(|digest| self.options.request.digest().ok() == Some(digest))
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && self.authority.cancellation_reason.is_none()
            && CAPS
                .iter()
                .all(|capability| self.authority.has_capability(capability))
            && boundary(self.options, self.cx, self.start).is_ok()
    }
}

impl RtspCatalogImportAuthority for Owner<'_> {
    fn permit(
        &self,
        request: &RtspCatalogImportRequest,
        destination: &ReferenceDeployment,
    ) -> bool {
        self.options
            .catalog
            .as_ref()
            .is_some_and(|expected| request.digest().ok() == expected.digest().ok())
            && request.digest().is_ok()
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && self.authority.cancellation_reason.is_none()
            && CAPS
                .iter()
                .all(|capability| self.authority.has_capability(capability))
            && boundary(self.options, self.cx, self.start).is_ok()
    }
}

impl RtspCatalogPagesImportAuthority for Owner<'_> {
    fn permit(
        &self,
        request: &RtspCatalogPagesImportRequest,
        destination: &ReferenceDeployment,
    ) -> bool {
        self.options
            .pages
            .as_ref()
            .is_some_and(|expected| request.digest().ok() == expected.digest().ok())
            && request.digest().is_ok()
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && self.authority.cancellation_reason.is_none()
            && CAPS
                .iter()
                .all(|capability| self.authority.has_capability(capability))
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

fn authority_boundary(
    options: &Options,
    authority: &ContextAuthority,
    start: Instant,
) -> Result<(), &'static str> {
    if authority.cancellation_reason.is_some()
        || !CAPS
            .iter()
            .all(|capability| authority.has_capability(capability))
        || start.elapsed() >= Duration::from_millis(options.timeout_ms)
    {
        return Err("ERR-RTSP-IMPORT-AUTHORITY-001");
    }
    Ok(())
}

fn preflight_source_paths(
    options: &Options,
    authority: &ContextAuthority,
    start: Instant,
) -> Result<(), &'static str> {
    // ReplayCx construction creates its root. These read-only checks therefore use the
    // validated, exact-plan authority before constructing destination I/O authority.
    for name in ["", "spool", "roots", "tombstones"] {
        authority_boundary(options, authority, start)?;
        if !existing_directory(&options.archive.join(name)) {
            return Err("ERR-RTSP-IMPORT-SOURCE-001");
        }
    }
    authority_boundary(options, authority, start)?;
    let source_path = options
        .archive
        .canonicalize()
        .map_err(|_| "ERR-RTSP-IMPORT-SOURCE-001")?;
    authority_boundary(options, authority, start)?;
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
            .join(
                options
                    .root
                    .file_name()
                    .ok_or("ERR-RTSP-IMPORT-REQUEST-001")?,
            ),
        _ => return Err("ERR-RTSP-IMPORT-REQUEST-001"),
    };
    if source_path.starts_with(&target_path) || target_path.starts_with(&source_path) {
        return Err("ERR-RTSP-IMPORT-REQUEST-001");
    }
    Ok(())
}

fn execute_authorized(
    options: &Options,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    start: Instant,
) -> Result<String, &'static str> {
    boundary(options, cx, start)?;
    let source = LocalRootPublisher::open(
        &options.archive,
        LocalPublicationLimits::new(
            65536,
            MAX_MANIFEST_CHILDREN,
            65536,
            65536,
            SpoolLimits::new(
                65536,
                1024 * 1024 * 1024,
                MAX_ORIGINAL_BYTES as usize,
                131072,
            ),
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
    let (receipt, catalog_result) = if let Some(request) = &options.pages {
        let result =
            import_rtsp_catalog_pages(&source, &mut destination, request, &owner, cx, &mut work)
                .map_err(|error| error.stable_id())?;
        (
            result.catalog.import,
            Some((result.catalog.windows, result.catalog.decode_interval)),
        )
    } else if let Some(request) = &options.catalog {
        let result = import_rtsp_catalog(&source, &mut destination, request, &owner, cx, &mut work)
            .map_err(|error| error.stable_id())?;
        (
            result.import,
            Some((result.windows, result.decode_interval)),
        )
    } else {
        let result = import_rtsp(
            &source,
            &mut destination,
            &options.request,
            &owner,
            cx,
            &mut work,
        )
        .map_err(|error| error.stable_id())?;
        (result, None)
    };
    // Durable completion remains reportable even if the cooperative deadline expires now.
    let mut fields = vec![
        (
            "format",
            string(if options.pages.is_some() {
                PAGES_FORMAT
            } else if options.catalog.is_some() {
                CATALOG_FORMAT
            } else {
                FORMAT
            }),
        ),
        ("kind", string("imported")),
        ("approval_digest", string(&options.approval()?.to_text())),
        (
            "import_identity",
            string(&receipt.import_identity.to_text()),
        ),
        ("import_root", string(&receipt.import_root.to_text())),
        (
            "manifest_digest",
            string(&receipt.manifest_digest.to_text()),
        ),
        ("origin_proof", string(&receipt.proof.to_text())),
        (
            if options.pages.is_some() {
                "first_catalog_slot"
            } else if options.catalog.is_some() {
                "catalog_slot"
            } else {
                "window_slot"
            },
            string(options.request.slot.as_str()),
        ),
        (
            if options.pages.is_some() {
                "first_catalog_root"
            } else if options.catalog.is_some() {
                "catalog_root"
            } else {
                "window_root"
            },
            string(&options.request.root.to_text()),
        ),
        ("codec", string(receipt.codec.as_str())),
        ("frames", receipt.frames.to_string()),
        ("capture_time_label", string(receipt.capture_time_label)),
        (
            "sample_timing",
            string("retained_mp4_presentation_timestamps"),
        ),
        ("reused", receipt.reused.to_string()),
        ("source_archive_retained_separately", "true".into()),
        ("destination_contains_original_recording", "true".into()),
        ("network", string("none")),
        ("work_used", work.used().to_string()),
    ];
    let scope = options
        .catalog
        .as_ref()
        .map(|r| &r.scope)
        .or_else(|| options.pages.as_ref().map(|r| &r.scope));
    if let (Some(scope), Some((windows, interval))) = (scope, catalog_result) {
        fields.extend([
            ("windows", windows.to_string()),
            ("decode_clock", string(&scope.decode_clock.to_text())),
            ("time_scale", scope.time_scale.to_string()),
            ("decode_start", string(&interval.start.to_string())),
            ("decode_end", string(&interval.end.to_string())),
            ("destination_contains_complete_catalog", "true".into()),
        ]);
    }
    if let Some(request) = &options.pages {
        fields.extend([
            ("pages", request.pages.len().to_string()),
            ("catalog_pages", page_selection_json(request)),
            ("destination_contains_complete_catalog_pages", "true".into()),
        ]);
    }
    Ok(object(&fields))
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
    authority
        .validate()
        .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    let start = Instant::now();
    preflight_source_paths(options, &authority, start)?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())
        .map_err(|_| "ERR-RTSP-IMPORT-AUTHORITY-001")?;
    let result = execute_authorized(options, &authority, &cx, start);
    cx.drain_and_finalize();
    result
}
