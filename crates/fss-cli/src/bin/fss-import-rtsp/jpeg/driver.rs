#![forbid(unsafe_code)]
//! Explicit original-read authority and bounded source-closed import execution.

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use fss_cli::agent_json::{object, string};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId};
use fss_geometry::WorkBudget;
use fss_publication::LocalRootPublisher;
use fss_reference::ingest::rtsp_jpeg_import::{
    JpegImportAuthority, JpegImportRequest, JpegImportTerminal, import_rtsp_jpeg,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

use super::plan::{
    AUTHORITY_BYTES, AUTHORITY_STORAGE_OPERATIONS, CAPS, FORMAT, Options, bounded, mapping_json,
    pin_json, replay_json, source_json, source_storage_limits,
};

const AUTHORITY: &str = "ERR-RTSP-JPEG-IMPORT-AUTHORITY-001";
const SOURCE: &str = "ERR-RTSP-JPEG-IMPORT-SOURCE-001";
const REQUEST: &str = "ERR-RTSP-JPEG-IMPORT-REQUEST-001";
const CUSTODY: &str = "ERR-RTSP-JPEG-IMPORT-CUSTODY-001";

struct Owner<'a> {
    options: &'a Options,
    request_digest: ContentDigest,
    authority: &'a ContextAuthority,
    cx: &'a ReplayCx,
    started: Instant,
}

impl JpegImportAuthority for Owner<'_> {
    fn permit(&self, request: &JpegImportRequest, destination: &ReferenceDeployment) -> bool {
        request.digest().ok() == Some(self.request_digest)
            && destination.root() == self.options.root
            && destination.site_lineage() == self.options.site
            && authority_boundary(self.options, self.authority, self.started).is_ok()
            && self.cx.checkpoint("import_rtsp_jpeg:operator").is_ok()
    }
}

fn authority_boundary(
    options: &Options,
    authority: &ContextAuthority,
    started: Instant,
) -> Result<(), &'static str> {
    if authority.cancellation_reason.is_some()
        || !CAPS
            .iter()
            .all(|capability| authority.has_capability(capability))
        || started.elapsed() >= Duration::from_millis(options.timeout_ms)
    {
        Err(AUTHORITY)
    } else {
        Ok(())
    }
}

fn boundary(options: &Options, cx: &ReplayCx, started: Instant) -> Result<(), &'static str> {
    cx.checkpoint("import_rtsp_jpeg:operator")
        .map_err(|_| AUTHORITY)?;
    if started.elapsed() >= Duration::from_millis(options.timeout_ms) {
        return Err(AUTHORITY);
    }
    Ok(())
}

fn existing_directory(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_dir())
}

fn preflight_paths(
    options: &Options,
    authority: &ContextAuthority,
    started: Instant,
) -> Result<(), &'static str> {
    // Exact approval and root authority precede these reads. A missing archive must not be
    // initialized by LocalRootPublisher::open, nor create destination authority through ReplayCx.
    for name in ["", "spool", "roots", "tombstones"] {
        authority_boundary(options, authority, started)?;
        if !existing_directory(&options.archive.join(name)) {
            return Err(SOURCE);
        }
    }
    authority_boundary(options, authority, started)?;
    let source = options.archive.canonicalize().map_err(|_| SOURCE)?;
    authority_boundary(options, authority, started)?;
    let destination = match std::fs::symlink_metadata(&options.root) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            options.root.canonicalize().map_err(|_| REQUEST)?
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => options
            .root
            .parent()
            .ok_or(REQUEST)?
            .canonicalize()
            .map_err(|_| REQUEST)?
            .join(options.root.file_name().ok_or(REQUEST)?),
        _ => return Err(REQUEST),
    };
    if source.starts_with(&destination) || destination.starts_with(&source) {
        return Err(REQUEST);
    }
    Ok(())
}

fn execute_authorized(
    options: &Options,
    authority: &ContextAuthority,
    cx: &ReplayCx,
    started: Instant,
) -> Result<String, &'static str> {
    boundary(options, cx, started)?;
    let source =
        LocalRootPublisher::open(&options.archive, source_storage_limits()).map_err(|_| SOURCE)?;
    boundary(options, cx, started)?;
    let mut destination =
        ReferenceDeployment::open(&options.root, &options.site, cx).map_err(|_| CUSTODY)?;
    let request_digest = options.request.digest().map_err(|_| REQUEST)?;
    let owner = Owner {
        options,
        request_digest,
        authority,
        cx,
        started,
    };
    let cancelled =
        || cx.is_cancelled() || started.elapsed() >= Duration::from_millis(options.timeout_ms);
    let mut work = WorkBudget::with_cancellation_probe(options.work, &cancelled);
    let receipt = import_rtsp_jpeg(
        &source,
        &mut destination,
        &options.request,
        &owner,
        cx,
        &mut work,
    )
    .map_err(|error| error.stable_id())?;
    // Once completion is durable, report that receipt even if the cooperative deadline expires.
    // A failed stdout write must not encourage an unsafe alternate request; exact retry verifies
    // source and destination custody and recovers the same completion identity.
    bounded(object(&[
        ("format", string(FORMAT)),
        ("kind", string("imported")),
        ("approval_digest", string(&options.approval()?.to_text())),
        ("request_digest", string(&request_digest.to_text())),
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
        ("interpretation", string(&receipt.interpretation.to_text())),
        ("source_scope", source_json(&options.request.source)?),
        ("prefix", pin_json(receipt.source)),
        ("replay", replay_json(options.request.replay)),
        ("physical_mapping", mapping_json(&options.request)),
        (
            "receive_time_ns",
            string(&options.request.receive_time.0.to_string()),
        ),
        ("frames", receipt.frames.to_string()),
        ("original_bytes", receipt.original_bytes.to_string()),
        ("media_bytes", receipt.media_bytes.to_string()),
        (
            "read_bytes_reserved",
            receipt.read_bytes_reserved.to_string(),
        ),
        ("replay_steps", receipt.replay_steps.to_string()),
        ("ending", string(receipt.ending)),
        (
            "accounting",
            object(&[
                (
                    "rtp_datagrams",
                    receipt.accounting.rtp_datagrams.to_string(),
                ),
                (
                    "rtcp_datagrams",
                    receipt.accounting.rtcp_datagrams.to_string(),
                ),
                (
                    "invalid_rtcp_datagrams",
                    receipt.accounting.invalid_rtcp_datagrams.to_string(),
                ),
                (
                    "ordered_packets",
                    receipt.accounting.ordered_packets.to_string(),
                ),
                (
                    "codec_refusals",
                    receipt.accounting.codec_refusals.to_string(),
                ),
                ("gap_events", receipt.accounting.gap_events.to_string()),
                (
                    "fragment_discards",
                    receipt.accounting.fragment_discards.to_string(),
                ),
            ]),
        ),
        ("terminal", terminal_json(&receipt.terminal)),
        ("capture_time_label", string(receipt.capture_time_label)),
        ("pixels_decoded", "false".into()),
        ("entropy_validated", "false".into()),
        ("absence_certifiable", "false".into()),
        ("source_prefix_exhaustion_is_eof", "false".into()),
        ("destination_contains_original_datagrams", "true".into()),
        ("source_archive_retained_separately", "true".into()),
        ("reused", receipt.reused.to_string()),
        ("bounds", options.bounds_json()),
        ("work_used", work.used().to_string()),
        ("network", string("none")),
    ]))
}

fn terminal_json(terminal: &JpegImportTerminal) -> String {
    let sequence = |number: Option<u64>| number.map_or_else(|| "null".into(), |n| n.to_string());
    object(&[
        ("replay_ns", terminal.replay_ns.to_string()),
        ("queue_packets", terminal.queue_packets.to_string()),
        ("queue_bytes", terminal.queue_bytes.to_string()),
        (
            "queue_first_sequence",
            sequence(terminal.queue_first_sequence),
        ),
        (
            "queue_last_sequence",
            sequence(terminal.queue_last_sequence),
        ),
        ("gap_pending", terminal.gap_pending.to_string()),
        (
            "fragment",
            terminal.fragment.as_ref().map_or_else(
                || "null".into(),
                |fragment| {
                    object(&[
                        ("reason", string(fragment.reason)),
                        ("first_sequence", fragment.first_sequence.to_string()),
                        ("last_sequence", fragment.last_sequence.to_string()),
                        ("bytes", fragment.bytes.to_string()),
                        ("fragments", fragment.fragments.to_string()),
                    ])
                },
            ),
        ),
    ])
}

pub(super) fn execute(options: &Options) -> Result<String, &'static str> {
    // No filesystem or monotonic clock access precedes exact approval admission.
    if options.approve != Some(options.approval()?) {
        return Err("ERR-RTSP-JPEG-IMPORT-APPROVAL-001");
    }
    let mut capabilities: Vec<_> = CAPS
        .iter()
        .map(|capability| (*capability).to_owned())
        .collect();
    capabilities.push("ADP-REPLAY-001".into());
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:rtsp-jpeg-import".into(),
        operation_id: OperationId::parse("operation:rtsp-jpeg-import").map_err(|_| AUTHORITY)?,
        principal: options.principal.clone(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(AUTHORITY_BYTES)
            .storage_operations(AUTHORITY_STORAGE_OPERATIONS)
            .build()
            .map_err(|_| AUTHORITY)?,
        privacy_scope: "privacy:owner-original-rtsp-jpeg-custody".into(),
        retention_scope: "retention:source-closed-rtsp-jpeg-import".into(),
        anchor_universe: ContentDigest::sha256(options.site.as_bytes()),
        generation: 1,
    })
    .map_err(|_| AUTHORITY)?;
    authority.validate().map_err(|_| AUTHORITY)?;
    let started = Instant::now();
    preflight_paths(options, &authority, started)?;
    let cx = ReplayCx::from_context_authority(&authority, options.root.clone())
        .map_err(|_| AUTHORITY)?;
    let result = execute_authorized(options, &authority, &cx, started);
    cx.drain_and_finalize();
    result
}
