#![forbid(unsafe_code)]
//! Historical sources query invariants: native inventory parity, bounded exact continuation,
//! incomplete/deleted accounting, immutable metadata-only reads and shared final read budgets.

#[path = "cascade_support/mod.rs"]
mod support;
mod qsr_observations_support;
#[path = "agent_sources_contract/health.rs"]
mod health;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_core::{
    BatchId, CanonicalEncode, CapsuleId, CaptureInterval, ClockBasis, ContentDigest,
    ContextAuthority, EvidenceDelta, KnowledgeState, ObjectId, OperationId, Plane, PrincipalId,
    RootAuthoritySpec, RuntimeGrant, SensorCapsule, SensorId, StreamId, TimestampNs,
};
use fss_object::SPOOL_OBJECTS_DIR;
use fss_publication::LOCAL_SPOOL_DIR;
use fss_reference::agent_follow::AnchorToken;
use fss_reference::agent_sources::{
    SourcesQueryError, SourcesQueryFilter, SourcesQueryLimits, SourcesQueryRequest,
    SourcesQuerySummary, query_sources, row_json,
};
use fss_reference::deletion::{approval_digest, commit_deletion, plan_deletion};
use fss_reference::deployment_status::{
    ContinuityReason, StatusLimits, StreamContinuity, inspect_deployment_status,
};
use fss_reference::ingest::FileFormatHint;
use fss_reference::reference_deployment::{FAMILY_FILE_IMPORT, FAMILY_SENSOR_CAPSULE};
use fss_reference::retained_source::ImmutableRetainedSource;
use fss_reference::ReplayCx;
use support::{Fixture, TestResult, SITE};

const PRINCIPAL: &str = "principal:cascade";

fn request() -> TestResult<SourcesQueryRequest> {
    Ok(SourcesQueryRequest {
        filter: SourcesQueryFilter::default(),
        principal: PrincipalId::parse(PRINCIPAL)?,
        max_entries: 16,
        expected_anchor: None,
        continuation: None,
    })
}

fn context(
    root: &Path,
    request: &SourcesQueryRequest,
    limits: SourcesQueryLimits,
) -> TestResult<ReplayCx> {
    context_for_site(root, request, limits, SITE)
}

fn context_for_site(
    root: &Path,
    request: &SourcesQueryRequest,
    limits: SourcesQueryLimits,
    site: &str,
) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:sources-contract".into(),
        operation_id: OperationId::parse("operation:sources-contract")?,
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
        anchor_universe: ContentDigest::sha256(site.as_bytes()),
        generation: 1,
    })?;
    assert!(!authority.has_capability(RuntimeGrant::ReadMedia.as_str()));
    Ok(ReplayCx::from_context_authority_read_only(&authority, root)?)
}

fn object_path(root: &Path, digest: ContentDigest) -> PathBuf {
    root.join("objects").join(LOCAL_SPOOL_DIR).join(SPOOL_OBJECTS_DIR).join(
        digest.bytes().iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
    )
}

fn files(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    fn visit(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, Vec<u8>>)
        -> TestResult
    {
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

fn capsule(label: &str, sensor: &str, stream: &str, clock: ClockBasis)
    -> TestResult<SensorCapsule>
{
    Ok(SensorCapsule {
        capsule_id: CapsuleId::parse(format!("capsule:sources:{label}"))?,
        sensor_id: SensorId::parse(sensor)?,
        stream_id: StreamId::parse(stream)?,
        sequence: 1,
        capture: CaptureInterval::new(TimestampNs(10), TimestampNs(20))?,
        receive_time: TimestampNs(30),
        clock_basis: clock,
        source_digest: ContentDigest::sha256(format!("media-never-retained:{label}").as_bytes()),
        source_bytes: 37,
        frame_count: 1,
        gap_before: false,
    })
}

fn retain_capsule(fixture: &mut Fixture, label: &str, capsule: &SensorCapsule)
    -> TestResult<ContentDigest>
{
    let digest = fixture.deployment.stage_payload(&capsule.canonical_bytes())?;
    fixture.deployment.append_batch(
        BatchId::parse(format!("batch:sources:{label}"))?,
        vec![EvidenceDelta {
            delta_id: format!("delta:sources:{label}"),
            family: FAMILY_SENSOR_CAPSULE.into(),
            object_id: ObjectId::parse(format!("object:capsule:{}", capsule.capsule_id.as_str()))?,
            prior_generation: None,
            new_generation: 1,
            validity: capsule.capture,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        }],
        vec![digest],
        &fixture.cx,
    )?;
    Ok(digest)
}

fn populated(label: &str) -> TestResult<Fixture> {
    let mut fixture = Fixture::new(label)?;
    for (name, sensor, stream, basis) in [
        ("a1", "sensor:a", "stream:shared", ClockBasis::Estimated),
        ("a2", "sensor:a", "stream:shared", ClockBasis::DeviceMonotonic),
        ("a3", "sensor:a", "stream:second", ClockBasis::DeviceMonotonic),
        ("b1", "sensor:b", "stream:shared", ClockBasis::Estimated),
    ] {
        let mut value = capsule(name, sensor, stream, basis)?;
        value.gap_before = name == "a2";
        retain_capsule(&mut fixture, name, &value)?;
    }
    Ok(fixture)
}

#[test]
fn source_rows_match_native_status_and_never_require_media_or_a_writer_reopen() -> TestResult {
    let fixture = populated("sources-native-parity")?;
    let root = fixture.deployment.root();
    fs::write(root.join("LAYOUT.tmp.sources-preserve"), b"read must not recover me")?;
    let before = files(root)?;
    let request = request()?;
    let limits = SourcesQueryLimits::default();
    let cx = context(root, &request, limits)?;
    // The existing writer remains open, so a second mutable deployment owner would fail.
    let query = query_sources(root, &request, limits, &cx, &|| false)?;
    let native = inspect_deployment_status(root, &StatusLimits::default())?;
    assert_eq!(
        query.rows.iter().map(|row| row.stream.clone()).collect::<Vec<_>>(),
        native.sources.streams,
    );
    assert_eq!(query.summary, SourcesQuerySummary::from(&native.sources));
    assert_eq!(query.scanned_streams, 3);
    assert_eq!(query.summary.sensors, 2);
    assert_eq!(query.summary.retained_capsules, 4);
    assert_eq!(query.rows[0].stream.stream_id, "stream:second");
    let mixed = &query.rows[1];
    assert_eq!(mixed.stream.continuity, StreamContinuity::Degraded);
    assert_eq!(mixed.stream.continuity_reason, ContinuityReason::MixedEstimatedClock);
    assert_eq!(mixed.stream.recorded_gaps, 1);
    assert_eq!(query.rows[2].stream.continuity, StreamContinuity::NotObservableFileSource);
    assert!(query.rows.iter().all(|row| {
        !row.capsule_metadata.is_empty() && row.capsule_metadata.len() <= 2
    }));
    assert!(query.epistemic().propositions.iter().any(|claim| {
        claim.state == KnowledgeState::Unknown && claim.statement.contains("Current source health")
    }));
    for row in &query.rows {
        let value = fss_core::json_input::parse(&row_json(row))?;
        let fields = value.object().ok_or("source row object")?;
        assert_eq!(
            fields.get("current_health").and_then(fss_core::json_input::Value::text),
            Some("unknown"),
        );
    }
    assert!(!query.snapshot.doctor_inspected);
    assert_eq!(query.remaining_streams(), 0);
    let repeated = query_sources(root, &request, limits, &cx, &|| false)?;
    assert_eq!(query, repeated);
    assert_eq!(files(root)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn exact_sensor_and_stream_filters_preserve_full_inventory_and_native_pagination() -> TestResult {
    let fixture = populated("sources-pagination")?;
    let root = fixture.deployment.root();
    let mut request = request()?;
    request.max_entries = 1;
    let limits = SourcesQueryLimits::default();
    let cx = context(root, &request, limits)?;
    let first = query_sources(root, &request, limits, &cx, &|| false)?;
    assert_eq!(first.rows.len(), 1);
    assert_eq!(first.remaining_streams(), 2);
    let token = first.page.next_cursor.as_ref().ok_or("next cursor")?.token().to_owned();
    request.continuation = Some(token);
    request.expected_anchor = Some(AnchorToken::parse(&first.anchor_token).ok_or("anchor")?);
    let second = query_sources(root, &request, limits, &cx, &|| false)?;
    assert_eq!(second.cursor.position, 1);
    assert_eq!(second.selection_witness, first.selection_witness);
    assert_ne!(second.request_digest, first.request_digest);
    assert_ne!(second.rows, first.rows);
    assert_eq!(second.summary, first.summary);

    for change in 0..4 {
        let mut changed = request.clone();
        let mut changed_limits = limits;
        match change {
            0 => changed.filter.sensor_id = Some(SensorId::parse("sensor:a")?),
            1 => changed.filter.stream_id = Some(StreamId::parse("stream:shared")?),
            2 => changed.max_entries = 2,
            _ => changed_limits.max_streams -= 1,
        }
        assert!(matches!(
            query_sources(root, &changed, changed_limits, &cx, &|| false),
            Err(SourcesQueryError::Continuation(_)),
        ));
    }
    let mut changed = request.clone();
    changed.principal = PrincipalId::parse("principal:other-source-reader")?;
    let other_cx = context(root, &changed, limits)?;
    assert!(matches!(
        query_sources(root, &changed, limits, &other_cx, &|| false),
        Err(SourcesQueryError::Continuation(_)),
    ));
    other_cx.drain_and_finalize();

    request.continuation = None;
    request.max_entries = 32;
    request.filter.stream_id = Some(StreamId::parse("stream:shared")?);
    let shared = query_sources(root, &request, limits, &cx, &|| false)?;
    assert_eq!(shared.rows.len(), 2);
    assert_eq!(shared.summary, first.summary);
    assert_eq!(shared.scanned_streams, 3);
    request.filter.sensor_id = Some(SensorId::parse("sensor:a")?);
    let exact = query_sources(root, &request, limits, &cx, &|| false)?;
    assert_eq!(exact.rows.len(), 1);
    assert_eq!(exact.rows[0].stream.sensor_id, "sensor:a");
    request.filter.sensor_id = Some(SensorId::parse("sensor:absent")?);
    let empty = query_sources(root, &request, limits, &cx, &|| false)?;
    assert!(empty.rows.is_empty());
    assert_eq!(empty.summary, first.summary);
    assert_eq!(empty.snapshot.historical_health, first.snapshot.historical_health);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn unmatched_corrupt_metadata_and_duplicate_capsule_identity_refuse_the_whole_page() -> TestResult {
    let mut fixture = populated("sources-corrupt-outside-filter")?;
    let root = fixture.deployment.root().to_path_buf();
    let mut request = request()?;
    let limits = SourcesQueryLimits::default();
    let cx = context(&root, &request, limits)?;
    let full = query_sources(&root, &request, limits, &cx, &|| false)?;
    let other = full.rows.iter().find(|row| row.stream.sensor_id == "sensor:b")
        .ok_or("other sensor")?;
    let path = object_path(&root, other.capsule_metadata[0]);
    let bytes = fs::read(&path)?;
    fs::write(&path, b"corrupt capsule outside selected sensor")?;
    request.filter.sensor_id = Some(SensorId::parse("sensor:a")?);
    assert!(query_sources(&root, &request, limits, &cx, &|| false).is_err());
    fs::write(&path, bytes)?;

    let mut duplicate = capsule("a1", "sensor:a", "stream:shared", ClockBasis::Estimated)?;
    duplicate.sequence = 2;
    let digest = fixture.deployment.stage_payload(&duplicate.canonical_bytes())?;
    fixture.deployment.append_batch(
        BatchId::parse("batch:sources:duplicate-identity")?,
        vec![EvidenceDelta {
            delta_id: "delta:sources:duplicate-identity".into(),
            family: FAMILY_SENSOR_CAPSULE.into(),
            object_id: ObjectId::parse("object:capsule:duplicate-container")?,
            prior_generation: None,
            new_generation: 1,
            validity: duplicate.capture,
            plane: Plane::Authority,
            payload_digest: digest,
            witness_digest: None,
            operation_id: None,
        }],
        vec![digest],
        &fixture.cx,
    )?;
    assert!(matches!(
        query_sources(&root, &request, limits, &cx, &|| false),
        Err(SourcesQueryError::InvalidRecord),
    ));
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn incomplete_imports_are_reported_without_hydrating_or_promoting_their_capsules()
    -> TestResult
{
    let mut fixture = populated("sources-incomplete")?;
    let pending = capsule("pending", "sensor:pending", "stream:pending", ClockBasis::Estimated)?;
    let digest = fixture.deployment.stage_payload(&pending.canonical_bytes())?;
    let marker = fixture.deployment.stage_payload(b"incomplete-import-marker")?;
    fixture.deployment.append_batch(
        BatchId::parse("batch:file-import:incomplete:c0")?,
        vec![
            EvidenceDelta {
                delta_id: "delta:sources:pending-capsule".into(),
                family: FAMILY_SENSOR_CAPSULE.into(),
                object_id: ObjectId::parse("object:capsule:pending")?,
                prior_generation: None,
                new_generation: 1,
                validity: pending.capture,
                plane: Plane::Authority,
                payload_digest: digest,
                witness_digest: None,
                operation_id: None,
            },
            EvidenceDelta {
                delta_id: "delta:sources:pending-import".into(),
                family: FAMILY_FILE_IMPORT.into(),
                object_id: ObjectId::parse("object:file-import:pending")?,
                prior_generation: None,
                new_generation: 1,
                validity: pending.capture,
                plane: Plane::Authority,
                payload_digest: marker,
                witness_digest: None,
                operation_id: None,
            },
        ],
        vec![digest, marker],
        &fixture.cx,
    )?;
    let root = fixture.deployment.root();
    fs::remove_file(object_path(root, digest))?;
    let before = files(root)?;
    let mut request = request()?;
    request.filter.sensor_id = Some(SensorId::parse("sensor:pending")?);
    let limits = SourcesQueryLimits::default();
    let cx = context(root, &request, limits)?;
    let query = query_sources(root, &request, limits, &cx, &|| false)?;
    assert!(query.rows.is_empty());
    assert_eq!(query.summary.retained_capsules, 4);
    assert_eq!(query.summary.capsule_objects, 5);
    assert_eq!(query.summary.incomplete_import_capsules, 1);
    assert_eq!(query.summary.incomplete_imports, ["object:file-import:pending"]);
    assert_eq!(files(root)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn native_completed_deletion_remains_visible_in_summary_without_source_hydration()
    -> TestResult
{
    let mut fixture = Fixture::new("sources-deleted-import")?;
    let media = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/media/h264/clean.264");
    let identity = fixture.ingest(
        "sensor:deleted-source", &fs::read(media)?, FileFormatHint::AnnexB, Some(1_000_000),
    )?;
    let root = fixture.deployment.root().to_path_buf();
    let request = request()?;
    let limits = SourcesQueryLimits::default();
    let cx = context(&root, &request, limits)?;
    let before = query_sources(&root, &request, limits, &cx, &|| false)?;
    assert_eq!(before.summary.completed_imports, 1);
    assert!(before.summary.retained_capsules > 0);
    let plan = plan_deletion(&fixture.deployment, identity, &fixture.cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    let digest = plan.digest()?;
    commit_deletion(
        &mut fixture.deployment,
        digest,
        approval_digest(digest, SITE, PRINCIPAL)?,
        PRINCIPAL,
        &fixture.cx,
    )?;
    let deleted = files(&root)?;
    let after = query_sources(&root, &request, limits, &cx, &|| false)?;
    assert!(after.rows.is_empty());
    assert_eq!(after.summary.retained_capsules, 0);
    assert_eq!(after.summary.deleted_capsules, before.summary.retained_capsules);
    assert_eq!(after.summary.deleted_imports, 1);
    assert_eq!(after.summary.capsule_objects, before.summary.capsule_objects);
    assert!(after.snapshot.deletions_committed > 0);
    assert_ne!(after.selection_witness, before.selection_witness);
    assert_eq!(files(&root)?, deleted);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn all_inventory_and_final_reread_work_shares_one_nonrenewing_budget() -> TestResult {
    let fixture = populated("sources-budget")?;
    let root = fixture.deployment.root();
    let request = request()?;
    let limits = SourcesQueryLimits::default();
    let cx = context(root, &request, limits)?;
    let full = query_sources(root, &request, limits, &cx, &|| false)?;
    assert!(full.read_usage.read_bytes > 1);
    assert!(full.read_usage.read_objects > 1);
    let mut exact = limits;
    exact.read.max_read_bytes = usize::try_from(full.read_usage.read_bytes)?;
    exact.read.max_read_objects = usize::try_from(full.read_usage.read_objects)?;
    let accepted = query_sources(root, &request, exact, &cx, &|| false)?;
    assert_eq!(accepted.read_usage, full.read_usage);
    for bytes in [true, false] {
        let mut short = exact;
        if bytes {
            short.read.max_read_bytes -= 1;
        } else {
            short.read.max_read_objects -= 1;
        }
        assert!(query_sources(root, &request, short, &cx, &|| false).is_err());
    }
    let mut filtered = request.clone();
    filtered.filter.sensor_id = Some(SensorId::parse("sensor:none")?);
    for dimension in 0..4 {
        let mut bounded = limits;
        match dimension {
            0 => bounded.max_capsules = 3,
            1 => bounded.max_streams = 2,
            2 => bounded.max_metadata_bytes = 1,
            _ => bounded.max_objects = 1,
        }
        assert!(query_sources(root, &filtered, bounded, &cx, &|| false).is_err());
    }
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn invalid_inputs_root_binding_and_cancellation_leave_no_partial_result_or_repair()
    -> TestResult
{
    let fixture = Fixture::new("sources-validation")?;
    let root = fixture.deployment.root();
    let request = request()?;
    let limits = SourcesQueryLimits::default();
    let cx = context(root, &request, limits)?;
    let before = files(root)?;
    for change in 0..3 {
        let mut invalid = request.clone();
        match change {
            0 => invalid.max_entries = 0,
            1 => invalid.max_entries = 33,
            _ => invalid.continuation = Some("continuation:INVALID".into()),
        }
        assert!(matches!(
            query_sources(root, &invalid, limits, &cx, &|| false),
            Err(SourcesQueryError::InvalidRequest(_)),
        ));
    }
    let mut invalid_limits = limits;
    invalid_limits.max_streams = 0;
    assert!(matches!(
        query_sources(root, &request, invalid_limits, &cx, &|| false),
        Err(SourcesQueryError::InvalidRequest(_)),
    ));
    let mut other = request.clone();
    other.principal = PrincipalId::parse("principal:other")?;
    assert!(matches!(
        query_sources(root, &other, limits, &cx, &|| false),
        Err(SourcesQueryError::Unauthorized),
    ));
    let absent = fixture.directory.0.join("absent");
    assert!(matches!(
        query_sources(&absent, &request, limits, &cx, &|| false),
        Err(SourcesQueryError::Unauthorized),
    ));
    assert!(!absent.exists());
    assert!(matches!(
        query_sources(root, &request, limits, &cx, &|| true),
        Err(SourcesQueryError::Cancelled),
    ));
    assert_eq!(files(root)?, before);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn final_native_checkpoint_and_last_live_admission_can_each_refuse_the_page() -> TestResult {
    let fixture = populated("sources-final-admission")?;
    let root = fixture.deployment.root();
    let request = request()?;
    let limits = SourcesQueryLimits::default();
    let cx = context(root, &request, limits)?;
    let calls = AtomicUsize::new(0);
    query_sources(root, &request, limits, &cx, &|| {
        calls.fetch_add(1, Ordering::SeqCst);
        false
    })?;
    let last = calls.load(Ordering::SeqCst);
    assert!(last > 0);
    calls.store(0, Ordering::SeqCst);
    let fired = AtomicBool::new(false);
    let before = files(root)?;
    assert!(query_sources(root, &request, limits, &cx, &|| {
        if calls.fetch_add(1, Ordering::SeqCst) + 1 == last {
            fired.store(true, Ordering::SeqCst);
            true
        } else {
            false
        }
    }).is_err());
    assert!(fired.load(Ordering::SeqCst));
    assert_eq!(files(root)?, before);
    cx.drain_and_finalize();

    let cx = context(root, &request, limits)?;
    cx.set_cancel_at_checkpoint("sources:complete");
    assert!(matches!(
        query_sources(root, &request, limits, &cx, &|| false),
        Err(SourcesQueryError::Cancelled),
    ));
    assert_eq!(files(root)?, before);
    Ok(())
}

#[test]
fn authority_append_changes_the_exact_anchor_and_invalidates_old_continuations() -> TestResult {
    let mut fixture = populated("sources-anchor-change")?;
    let root = fixture.deployment.root().to_path_buf();
    let mut request = request()?;
    request.max_entries = 1;
    let limits = SourcesQueryLimits::default();
    let cx = context(&root, &request, limits)?;
    let first = query_sources(&root, &request, limits, &cx, &|| false)?;
    request.expected_anchor = Some(AnchorToken::parse(&first.anchor_token).ok_or("anchor")?);
    request.continuation = Some(first.page.next_cursor.as_ref().ok_or("next")?.token().to_owned());
    retain_capsule(
        &mut fixture,
        "new",
        &capsule("new", "sensor:z", "stream:new", ClockBasis::DeviceMonotonic)?,
    )?;
    assert!(matches!(
        query_sources(&root, &request, limits, &cx, &|| false),
        Err(SourcesQueryError::AnchorChanged),
    ));
    request.expected_anchor = None;
    assert!(matches!(
        query_sources(&root, &request, limits, &cx, &|| false),
        Err(SourcesQueryError::Continuation(_)),
    ));
    cx.drain_and_finalize();
    Ok(())
}
