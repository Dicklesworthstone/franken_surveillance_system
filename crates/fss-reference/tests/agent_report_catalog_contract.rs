#![forbid(unsafe_code)]
//! Native retained report discovery, exact continuation and metadata-only custody boundaries.

#[path = "package_evaluation_support/mod.rs"]
mod package_support;
mod qsr_observations_support;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::{
    ContentDigest, ContextAuthority, KnowledgeState, ObjectId, OperationId, PrincipalId,
    RootAuthoritySpec, RuntimeGrant,
};
use fss_object::SPOOL_OBJECTS_DIR;
use fss_publication::LOCAL_SPOOL_DIR;
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_report_catalog::{
    ReportCatalogError, ReportCatalogFamily, ReportCatalogFilter, ReportCatalogLimits,
    ReportCatalogRequest, query_report_catalog,
};
use fss_reference::deletion::{approval_digest, commit_deletion, plan_deletion};
use fss_reference::ingest::package_event::PACKAGE_DETECTION_RECORD_DOMAIN;
use fss_reference::ingest::package_zones::{
    PACKAGE_ZONE_REPORT_DOMAIN, PACKAGE_ZONE_SCREENED_REPORT_DOMAIN, PackageZone,
    PackageZoneConfig, PackageZoneReport,
};
use fss_reference::retained_source::{ImmutableRetainedSource, RetainedSource};
use fss_reference::{ReferenceDeployment, ReplayCx};
use qsr_observations_support::{Directory, Fixture, PRINCIPAL, SITE, Test};

fn request() -> Test<ReportCatalogRequest> {
    Ok(ReportCatalogRequest {
        filter: ReportCatalogFilter::default(),
        principal: PrincipalId::parse(PRINCIPAL)?,
        max_entries: 16,
        expected_anchor: None,
        continuation: None,
    })
}

fn context(
    root: &Path,
    request: &ReportCatalogRequest,
    limits: ReportCatalogLimits,
) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:report-catalog-contract".into(),
        operation_id: OperationId::parse("operation:report-catalog-contract")?,
        principal: request.principal.as_str().to_owned(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            RuntimeGrant::AgentQuery.as_str().into(),
        ],
        deadline: None,
        priority: 10,
        budgets: limits.allowance()?,
        privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    assert!(!authority.has_capability(RuntimeGrant::ReadMedia.as_str()));
    Ok(ReplayCx::from_context_authority_read_only(
        &authority, root,
    )?)
}

fn object_path(root: &Path, digest: ContentDigest) -> PathBuf {
    root.join("objects")
        .join(LOCAL_SPOOL_DIR)
        .join(SPOOL_OBJECTS_DIR)
        .join(
            digest
                .bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
}

fn files(root: &Path) -> Test<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>) -> Test {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                visit(root, &path, result)?;
            } else {
                result.insert(path.strip_prefix(root)?.to_path_buf(), fs::read(path)?);
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result)?;
    Ok(result)
}

#[test]
fn discovers_exact_native_report_handles_without_read_media_or_source_payloads() -> Test {
    let fixture = Fixture::new("agent-report-catalog-handles")?;
    let root = &fixture.source.root;
    let temporary = root.join("LAYOUT.tmp.catalog-preserve");
    fs::write(&temporary, b"metadata discovery must not recover this file")?;
    let before = files(root)?;
    let request = request()?;
    let limits = ReportCatalogLimits::default();
    let cx = context(root, &request, limits)?;
    let query = query_report_catalog(root, &request, limits, &cx, &|| false)?;
    assert_eq!(query.scanned_reports, 2);
    assert_eq!(query.matched_reports, 2);
    assert_eq!(query.rows.len(), 2);
    let detection = &query.rows[0];
    assert_eq!(
        detection.family,
        ReportCatalogFamily::PackageDetectionRecord
    );
    assert_eq!(detection.report_digest, fixture.source.report);
    assert_ne!(detection.report_digest, detection.record_digest);
    assert_eq!(detection.schema, PACKAGE_DETECTION_RECORD_DOMAIN);
    assert!(detection.publication_slot.starts_with("pd-"));
    let zones = &query.rows[1];
    assert_eq!(zones.family, ReportCatalogFamily::PackageZoneReport);
    assert_eq!(zones.report_digest, fixture.report);
    assert_eq!(zones.record_digest, fixture.report);
    assert_eq!(zones.schema, PACKAGE_ZONE_SCREENED_REPORT_DOMAIN);
    assert!(zones.publication_slot.starts_with("pz-"));
    assert!(detection.committed_sequence < zones.committed_sequence);
    assert_eq!(query.remaining_reports(), 0);
    assert_eq!(query.coverage().omitted_count, 0);
    assert!(!query.snapshot.doctor_inspected);
    assert!(query.read_usage.read_bytes > 0);
    assert!(query.read_usage.read_bytes <= limits.read.max_read_bytes as u64);
    assert!(query.read_usage.read_objects <= limits.read.max_read_objects as u64);
    let epistemic = query.epistemic();
    assert!(epistemic.propositions.iter().any(|claim| {
        claim.state == KnowledgeState::Unknown && claim.statement.contains("grants no ReadMedia")
    }));
    for claim in &epistemic.propositions {
        assert!(!claim.statement.contains(root.to_str().ok_or("root")?));
    }
    assert_eq!(files(root)?, before);

    // The same handles remain discoverable when original media is unavailable. A later
    // tracks/QSR source read must make its own independent custody and authority decision.
    fs::remove_file(&fixture.source.chunk)?;
    let without_media = files(root)?;
    let again = query_report_catalog(root, &request, limits, &cx, &|| false)?;
    assert_eq!(again.rows, query.rows);
    assert_eq!(again.selection_witness, query.selection_witness);
    assert_eq!(again.decision_digest, query.decision_digest);
    assert_eq!(files(root)?, without_media);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn native_pagination_filters_and_exact_query_scope_cannot_be_reinterpreted() -> Test {
    let fixture = Fixture::new("agent-report-catalog-continuation")?;
    let root = &fixture.source.root;
    let mut request = request()?;
    request.max_entries = 1;
    let limits = ReportCatalogLimits::default();
    let cx = context(root, &request, limits)?;
    let first = query_report_catalog(root, &request, limits, &cx, &|| false)?;
    assert_eq!(first.rows.len(), 1);
    assert_eq!(first.remaining_reports(), 1);
    let next = first
        .page
        .next_cursor
        .as_ref()
        .ok_or("continuation")?
        .token()
        .to_owned();
    request.continuation = Some(next);
    request.expected_anchor = Some(AnchorToken::parse(&first.anchor_token).ok_or("anchor token")?);
    let second = query_report_catalog(root, &request, limits, &cx, &|| false)?;
    assert_eq!(second.rows.len(), 1);
    assert_eq!(
        second.rows[0].family,
        ReportCatalogFamily::PackageZoneReport
    );
    assert_eq!(second.remaining_reports(), 0);
    assert!(second.page.next_cursor.is_none());
    assert_eq!(first.selection_witness, second.selection_witness);
    assert_ne!(first.request_digest, second.request_digest);

    let mut changed_limits = limits;
    changed_limits.read.max_read_bytes -= 1;
    assert!(matches!(
        query_report_catalog(root, &request, changed_limits, &cx, &|| false),
        Err(ReportCatalogError::Continuation(_))
    ));
    for change in 0..3 {
        let mut altered = request.clone();
        match change {
            0 => altered.max_entries = 2,
            1 => altered.filter.family = Some(ReportCatalogFamily::PackageZoneReport),
            _ => altered.filter.from_ns = Some(second.rows[0].validity.earliest.0),
        }
        assert!(matches!(
            query_report_catalog(root, &altered, limits, &cx, &|| false),
            Err(ReportCatalogError::Continuation(_))
        ));
    }
    let mut altered = request.clone();
    altered.principal = PrincipalId::parse("principal:other-report-reader")?;
    let other_cx = context(root, &altered, limits)?;
    assert!(matches!(
        query_report_catalog(root, &altered, limits, &other_cx, &|| false),
        Err(ReportCatalogError::Continuation(_))
    ));
    other_cx.drain_and_finalize();

    request.continuation = None;
    request.max_entries = 16;
    request.filter.family = Some(ReportCatalogFamily::PackageZoneReport);
    request.filter.from_ns = Some(second.rows[0].validity.latest.0);
    request.filter.through_ns = request.filter.from_ns;
    let boundary = query_report_catalog(root, &request, limits, &cx, &|| false)?;
    assert_eq!(boundary.scanned_reports, 2);
    assert_eq!(boundary.rows, second.rows);
    request.filter.from_ns = Some(second.rows[0].validity.latest.0 + 1);
    request.filter.through_ns = None;
    let empty = query_report_catalog(root, &request, limits, &cx, &|| false)?;
    assert_eq!(empty.scanned_reports, 2);
    assert!(empty.rows.is_empty());
    assert!(
        empty
            .epistemic()
            .propositions
            .iter()
            .any(|claim| claim.state == KnowledgeState::Unknown)
    );
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn filters_never_bypass_complete_index_integrity_or_aggregate_read_limits() -> Test {
    let fixture = Fixture::new("agent-report-catalog-bounds")?;
    let root = &fixture.source.root;
    let mut request = request()?;
    request.filter.family = Some(ReportCatalogFamily::PackageDetectionRecord);
    let limits = ReportCatalogLimits::default();
    let cx = context(root, &request, limits)?;
    let before = files(root)?;
    let query = query_report_catalog(root, &request, limits, &cx, &|| false)?;
    assert_eq!(query.rows.len(), 1);
    assert_eq!(query.scanned_reports, 2);
    let mut bounded = limits;
    bounded.max_reports = 1;
    assert!(matches!(
        query_report_catalog(root, &request, bounded, &cx, &|| false),
        Err(ReportCatalogError::OverBudget)
    ));
    bounded = limits;
    bounded.read.max_read_objects = usize::try_from(query.read_usage.read_objects)? - 1;
    assert!(query_report_catalog(root, &request, bounded, &cx, &|| false).is_err());
    bounded = limits;
    bounded.read.max_read_bytes = usize::try_from(query.read_usage.read_bytes)? - 1;
    assert!(query_report_catalog(root, &request, bounded, &cx, &|| false).is_err());
    assert_eq!(files(root)?, before);

    // A damaged excluded family is an incomplete index, not a successful detector-only page.
    let path = object_path(root, fixture.report);
    let bytes = fs::read(&path)?;
    fs::write(&path, b"corrupt excluded package-zone metadata")?;
    let damaged = files(root)?;
    assert!(query_report_catalog(root, &request, limits, &cx, &|| false).is_err());
    assert_eq!(files(root)?, damaged);
    fs::write(path, bytes)?;
    assert_eq!(files(root)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn completed_native_source_deletion_revokes_derivatives_without_poisoning_discovery() -> Test {
    let fixture = Fixture::new("agent-report-catalog-completed-deletion")?;
    let root = &fixture.source.root;
    let request = request()?;
    let limits = ReportCatalogLimits::default();
    let cx = context(root, &request, limits)?;
    let before = query_report_catalog(root, &request, limits, &cx, &|| false)?;
    assert_eq!(before.rows.len(), 2);
    cx.drain_and_finalize();

    // Committed native deletion revokes the derivative closure. This is deliberately distinct
    // from missing source media with no revocation, which leaves metadata discoverable above.
    let writer = qsr_observations_support::context(root)?;
    let mut deployment = ReferenceDeployment::open(root, SITE, &writer)?;
    let plan = plan_deletion(&deployment, fixture.source.import, &writer)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    let report_objects = before
        .rows
        .iter()
        .map(|row| {
            let native = match row.family {
                ReportCatalogFamily::PackageDetectionRecord => "package-detection",
                ReportCatalogFamily::PackageZoneReport => "package-zones",
            };
            let identity: String = row
                .report_digest
                .bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect();
            ObjectId::parse(format!("object:{native}:{identity}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    for object in &report_objects {
        assert!(
            plan.tombstones
                .iter()
                .any(|entry| entry.object_id == object.as_str())
        );
    }
    let digest = plan.digest()?;
    commit_deletion(
        &mut deployment,
        digest,
        approval_digest(digest, SITE, PRINCIPAL)?,
        PRINCIPAL,
        &writer,
    )?;
    for object in &report_objects {
        let current = deployment
            .ledger()
            .current()
            .objects
            .get(object)
            .ok_or("current report tombstone")?;
        assert_eq!(current.family, "deletion_tombstone");
        assert_eq!(current.generation, 2);
        assert_eq!(current.payload_digest, digest);
    }
    drop(deployment);
    writer.drain_and_finalize();

    let deleted = files(root)?;
    let cx = context(root, &request, limits)?;
    let after = query_report_catalog(root, &request, limits, &cx, &|| false)?;
    assert_eq!(after.scanned_reports, 0);
    assert_eq!(after.matched_reports, 0);
    assert!(after.rows.is_empty());
    assert_ne!(after.anchor_token, before.anchor_token);
    assert_eq!(files(root)?, deleted);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn legacy_zone_schema_remains_explicit_and_never_claims_qsr_eligibility() -> Test {
    let fixture = package_support::Fixture::new(
        "agent-report-catalog-legacy",
        [128, 160, 192],
        Some(1_000_000),
    )?;
    let writer = package_support::context(&fixture.root)?;
    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &writer)?;
    let mut zones = PackageZoneReport::analyze(
        &deployment,
        fixture.report,
        "numeric-a",
        package_support::tracking(),
        PackageZoneConfig {
            maximum_sample_gap_ns: 110_000_000,
            dwell: None,
            zones: vec![PackageZone {
                id: "image".into(),
                x: 0,
                y: 0,
                width: 32,
                height: 16,
                margin: 0,
            }],
        },
        &writer,
    )?;
    zones.retain(&mut deployment, zones.approval_digest(), &writer)?;
    drop(deployment);
    writer.drain_and_finalize();
    let mut request = request()?;
    request.filter.family = Some(ReportCatalogFamily::PackageZoneReport);
    let limits = ReportCatalogLimits::default();
    let cx = context(&fixture.root, &request, limits)?;
    let query = query_report_catalog(&fixture.root, &request, limits, &cx, &|| false)?;
    assert_eq!(query.rows.len(), 1);
    assert_eq!(query.rows[0].report_digest, zones.digest());
    assert_eq!(query.rows[0].schema, PACKAGE_ZONE_REPORT_DOMAIN);
    let epistemic = query.epistemic();
    let encoded = epistemic
        .propositions
        .iter()
        .find_map(|claim| claim.statement.strip_prefix("Retained report metadata: "))
        .ok_or("native report metadata projection")?;
    let projected = fss_core::json_input::parse(encoded)?;
    let fields = projected.object().ok_or("report metadata object")?;
    assert_eq!(
        fields
            .get("schema")
            .and_then(fss_core::json_input::Value::text),
        Some(PACKAGE_ZONE_REPORT_DOMAIN)
    );
    assert_eq!(
        fields
            .get("report_digest")
            .and_then(fss_core::json_input::Value::text),
        Some(zones.digest().to_text().as_str())
    );
    assert_eq!(
        fields
            .get("metadata_availability")
            .and_then(fss_core::json_input::Value::text),
        Some("verified")
    );
    assert_eq!(
        fields
            .get("source_payload_availability")
            .and_then(fss_core::json_input::Value::text),
        Some("unknown")
    );
    assert_eq!(
        fields
            .get("qsr_eligibility")
            .and_then(fss_core::json_input::Value::text),
        Some("unknown")
    );
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn invalid_inputs_root_authority_and_cancellation_never_create_or_repair_a_store() -> Test {
    let directory = Directory::new("agent-report-catalog-no-create")?;
    let root = directory.0.join("absent");
    let limits = ReportCatalogLimits::default();
    let request = request()?;
    let cx = context(&root, &request, limits)?;
    assert!(ReportCatalogFamily::parse("detections").is_err());
    assert_eq!(
        ReportCatalogFamily::parse("package_zone_report")?,
        ReportCatalogFamily::PackageZoneReport
    );
    for change in 0..3 {
        let mut invalid = request.clone();
        match change {
            0 => invalid.max_entries = 0,
            1 => {
                invalid.filter.from_ns = Some(2);
                invalid.filter.through_ns = Some(1);
            }
            _ => invalid.continuation = Some("continuation:INVALID".into()),
        }
        assert!(matches!(
            query_report_catalog(&root, &invalid, limits, &cx, &|| false),
            Err(ReportCatalogError::InvalidRequest(_))
        ));
    }
    let mut other = request.clone();
    other.principal = PrincipalId::parse("principal:another-catalog-reader")?;
    assert!(matches!(
        query_report_catalog(&root, &other, limits, &cx, &|| false),
        Err(ReportCatalogError::Unauthorized)
    ));
    assert!(matches!(
        query_report_catalog(&directory.0.join("other"), &request, limits, &cx, &|| false),
        Err(ReportCatalogError::Unauthorized)
    ));
    assert!(matches!(
        query_report_catalog(&root, &request, limits, &cx, &|| true),
        Err(ReportCatalogError::Cancelled)
    ));
    assert!(!root.exists());
    assert_eq!(fs::read_dir(&directory.0)?.count(), 0);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn final_live_admission_refusal_never_returns_a_catalog_page() -> Test {
    let fixture = Fixture::new("agent-report-catalog-final-admission")?;
    let root = &fixture.source.root;
    let request = request()?;
    let limits = ReportCatalogLimits::default();
    let cx = context(root, &request, limits)?;
    let calls = AtomicUsize::new(0);
    query_report_catalog(root, &request, limits, &cx, &|| {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    })?;
    let last = calls.load(Ordering::SeqCst);
    assert!(last > 0);
    calls.store(0, Ordering::SeqCst);
    let refused = AtomicBool::new(false);
    let before = files(root)?;
    let result = query_report_catalog(root, &request, limits, &cx, &|| {
        if calls.fetch_add(1, Ordering::SeqCst) + 1 == last {
            refused.store(true, Ordering::SeqCst);
            true
        } else {
            false
        }
    });
    assert!(refused.load(Ordering::SeqCst));
    assert!(
        result.is_err(),
        "final live admission cannot be skipped to release a page"
    );
    assert_eq!(files(root)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn cooperative_metadata_revalidation_refuses_observed_report_changes() -> Test {
    let fixture = Fixture::new("agent-report-catalog-revalidation")?;
    let root = &fixture.source.root;
    let request = request()?;
    let limits = ReportCatalogLimits::default();
    let cx = context(root, &request, limits)?;
    let query = query_report_catalog(root, &request, limits, &cx, &|| false)?;
    let digest = query.rows[0].record_digest;
    let path = object_path(root, digest);
    let original = fs::read(&path)?;
    let armed = AtomicBool::new(false);
    let mutated = AtomicBool::new(false);
    let admission = || {
        if armed.swap(false, Ordering::SeqCst) {
            assert!(fs::write(&path, b"changed before cooperative final metadata reread").is_ok());
            mutated.store(true, Ordering::SeqCst);
        }
        false
    };
    let owner = ImmutableRetainedSource::open_cancellable(root, limits.read, &cx, &admission)?;
    assert_eq!(owner.read_object_bounded(digest, original.len())?, original);
    armed.store(true, Ordering::SeqCst);
    assert!(owner.revalidate().is_err());
    assert!(mutated.load(Ordering::SeqCst));
    fs::write(path, original)?;
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn cancellation_at_final_catalog_stage_preserves_the_entire_store() -> Test {
    let fixture = Fixture::new("agent-report-catalog-cancel-final")?;
    let root = &fixture.source.root;
    let request = request()?;
    let limits = ReportCatalogLimits::default();
    let cx = context(root, &request, limits)?;
    let before = files(root)?;
    cx.set_cancel_at_checkpoint("report_catalog:complete");
    assert!(matches!(
        query_report_catalog(root, &request, limits, &cx, &|| false),
        Err(ReportCatalogError::Cancelled)
    ));
    assert_eq!(files(root)?, before);
    Ok(())
}
