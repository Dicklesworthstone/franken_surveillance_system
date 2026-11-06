#![forbid(unsafe_code)]

use super::*;
use crate::deletion::{approval_digest, commit_deletion, plan_deletion};
use crate::ingest::{FileFormatHint, FileIngestAdapter, FileIngestReceipt, FileIngestRequest};
use crate::{DeploymentLimits, ReferenceDeployment, ReplayCx, ReplayIoAuthority};
use fss_core::{
    BudgetVector, ClockBasis, ContextAuthority, OperationId, RootAuthoritySpec, TimestampNs,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:footage-query";
static NEXT: AtomicU64 = AtomicU64::new(0);
fn directory(label: &str) -> TestResult<PathBuf> {
    let root = std::env::var_os("CARGO_TARGET_TMPDIR")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join(format!(
            "fss-footage-{label}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    fs::create_dir_all(&root)?;
    Ok(root)
}
fn cx(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:footage-query".to_owned(),
        operation_id: OperationId::parse("operation:footage-query")?,
        principal: "operator:footage-query".to_owned(),
        capabilities: vec![
            crate::ADP_FILE_ROW_ID.to_owned(),
            crate::ADP_REPLAY_ROW_ID.to_owned(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_owned(),
        retention_scope: "retention:ephemeral".to_owned(),
        anchor_universe: ContentDigest::sha256(b"footage-query-test"),
        generation: 1,
    })?;
    Ok(ReplayCx::new(ReplayIoAuthority::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?))
}
fn input() -> TestResult<FileIngestRequest> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("repo unavailable")?;
    Ok(FileIngestRequest::new(
        repo.join("tests/fixtures/media/h264/clean.264"),
        SensorId::parse("sensor:footage-camera")?,
        StreamId::parse("stream:footage-main")?,
    )
    .with_format_hint(FileFormatHint::AnnexB)
    .with_receive_time(TimestampNs(2_000_000_000)))
}
fn fixture(label: &str) -> TestResult<(PathBuf, FileIngestReceipt)> {
    let root = directory(label)?;
    let context = cx(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &context)?;
    let receipt = FileIngestAdapter::ingest(input()?, &context, &mut deployment)?;
    drop(deployment);
    Ok((root, receipt))
}
fn request() -> TestResult<FootageQueryRequest> {
    Ok(FootageQueryRequest {
        filter: FootageQueryFilter::default(),
        principal: PrincipalId::parse("principal:footage-operator")?,
        max_entries: 2,
        expected_anchor: None,
        continuation: None,
    })
}
fn query(
    root: &Path,
    request: &FootageQueryRequest,
) -> Result<DeploymentFootageQuery, FootageQueryError> {
    query_footage(root, request, &FootageQueryLimits::default(), &mut |_| true)
}
fn bytes(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    fn walk(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let p = entry.path();
            if entry.file_type()?.is_dir() {
                walk(root, &p, out)?;
            } else if entry.file_type()?.is_file() {
                out.insert(p.strip_prefix(root)?.to_path_buf(), fs::read(p)?);
            }
        }
        Ok(())
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out)?;
    Ok(out)
}
fn spool_path(root: &Path, digest: ContentDigest) -> PathBuf {
    root.join("objects/spool/objects").join(
        digest
            .to_text()
            .split_once(':')
            .map_or(String::new(), |(_, h)| h.to_owned()),
    )
}

#[test]
fn paged_read_is_deterministic_exact_and_never_writes_or_claims_payload_availability() -> TestResult
{
    let (root, receipt) = fixture("pages")?;
    let before = bytes(&root)?;
    let mut req = request()?;
    let first = query(&root, &req)?;
    let same = query(&root, &req)?;
    assert_eq!(first, same);
    assert!(!first.snapshot.doctor_inspected);
    assert_eq!(first.scanned_capsules, receipt.capsule_count);
    assert_eq!(first.rows.len(), 2);
    assert_eq!(first.rows[0].capsule, receipt.capsules[0]);
    assert_eq!(first.rows[0].import_identity, receipt.import_identity);
    assert_eq!(first.rows[0].capsule.clock_basis, ClockBasis::Estimated);
    assert_eq!(first.rows[0].capture_time_label, "unknown");
    assert!(first.metadata_bytes_read > first.snapshot.bytes_read);
    assert!(
        first
            .epistemic()
            .propositions
            .iter()
            .any(|p| p.statement.contains("source_payload_availability=unknown"))
    );
    req.expected_anchor =
        Some(AnchorToken::parse(&first.anchor_token).ok_or("invalid issued anchor")?);
    let mut seen = first
        .rows
        .iter()
        .map(FootageQueryRow::row_digest)
        .collect::<Vec<_>>();
    let mut next = first.page.next_cursor;
    while let Some(cursor) = next {
        req.continuation = Some(cursor.token().to_owned());
        let page = query(&root, &req)?;
        assert_eq!(page.selection_witness, same.selection_witness);
        seen.extend(page.rows.iter().map(FootageQueryRow::row_digest));
        next = page.page.next_cursor;
    }
    assert_eq!(seen.len(), receipt.capsule_count);
    let unique: std::collections::BTreeSet<_> = seen.iter().copied().collect();
    assert_eq!(unique.len(), seen.len());
    assert_eq!(bytes(&root)?, before);
    Ok(())
}

#[test]
fn conjunctive_source_native_overlap_keeps_unknown_windows_and_empty_is_not_absence() -> TestResult
{
    let (root, receipt) = fixture("filters")?;
    let mut req = request()?;
    req.filter.sensor = Some(SensorId::parse("sensor:footage-camera")?);
    req.filter.stream = Some(StreamId::parse("stream:footage-main")?);
    req.filter.from_ns = Some(2_000_000_000);
    req.filter.through_ns = Some(2_000_000_000);
    let result = query(&root, &req)?;
    assert_eq!(result.matched_capsules, receipt.capsule_count);
    req.filter.from_ns = Some(2_000_000_001);
    req.filter.through_ns = None;
    let empty = query(&root, &req)?;
    assert!(empty.rows.is_empty());
    assert!(
        empty
            .epistemic()
            .propositions
            .iter()
            .any(|p| p.state == fss_core::KnowledgeState::Unknown)
    );
    assert_eq!(empty.coverage().stop_reason, "committed_index_exhausted");
    req.filter.from_ns = None;
    req.filter.stream = Some(StreamId::parse("stream:other")?);
    assert_eq!(query(&root, &req)?.matched_capsules, 0);
    req.filter.from_ns = Some(9);
    req.filter.through_ns = Some(8);
    assert!(matches!(
        query(&root, &req),
        Err(FootageQueryError::InvalidRequest(_))
    ));
    Ok(())
}

#[test]
fn native_cursor_binds_principal_filter_page_size_and_exact_anchor() -> TestResult {
    let (root, _) = fixture("cursor")?;
    let first = query(&root, &request()?)?;
    let mut req = request()?;
    req.continuation = Some(
        first
            .page
            .next_cursor
            .ok_or("next page missing")?
            .token()
            .to_owned(),
    );
    req.principal = PrincipalId::parse("principal:different")?;
    assert!(matches!(
        query(&root, &req),
        Err(FootageQueryError::Continuation(_))
    ));
    req = request()?;
    req.expected_anchor =
        Some(AnchorToken::parse(&first.anchor_token).ok_or("invalid issued anchor")?);
    let context = cx(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &context)?;
    let mut another = input()?;
    another.sensor_id = SensorId::parse("sensor:second")?;
    FileIngestAdapter::ingest(another, &context, &mut deployment)?;
    drop(deployment);
    assert!(matches!(
        query(&root, &req),
        Err(FootageQueryError::AnchorChanged)
    ));
    Ok(())
}

#[test]
fn source_payload_removal_is_not_hydrated_or_misreported_as_payload_availability() -> TestResult {
    let (root, receipt) = fixture("source-unavailable")?;
    let baseline = query(&root, &request()?)?;
    for digest in &receipt.manifest.ordered_chunks {
        fs::write(spool_path(&root, *digest), b"corrupt source payload")?;
    }
    let before = bytes(&root)?;
    let result = query(&root, &request()?)?;
    assert_eq!(result.rows, baseline.rows);
    assert_eq!(result.selection_witness, baseline.selection_witness);
    assert!(
        result
            .epistemic()
            .propositions
            .iter()
            .any(|p| p.statement.contains("source_payload_availability=unknown"))
    );
    assert_eq!(before, bytes(&root)?);
    for digest in &receipt.manifest.ordered_chunks {
        fs::remove_file(spool_path(&root, *digest))?;
    }
    assert_eq!(query(&root, &request()?)?.rows, baseline.rows);
    Ok(())
}

#[test]
fn corrupted_capsule_refuses_even_when_filter_would_exclude_it() -> TestResult {
    let (root, _) = fixture("corrupt-capsule")?;
    let selected = query(&root, &request()?)?;
    fs::write(
        spool_path(&root, selected.rows[0].capsule_digest),
        b"corrupt metadata",
    )?;
    let mut req = request()?;
    req.filter.sensor = Some(SensorId::parse("sensor:absent")?);
    assert!(query(&root, &req).is_err());
    Ok(())
}

#[test]
fn incomplete_imports_and_committed_deletions_are_excluded_without_recovery() -> TestResult {
    let root = directory("incomplete")?;
    let context = cx(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &context)?;
    context
        .set_cancel_at_checkpoint_occurrence(crate::ingest::file_adapter::STAGE_COMMIT_MANIFEST, 1);
    assert!(FileIngestAdapter::ingest(input()?, &context, &mut deployment).is_err());
    drop(deployment);
    let before = bytes(&root)?;
    assert!(query(&root, &request()?)?.rows.is_empty());
    assert_eq!(before, bytes(&root)?);
    let (root, receipt) = fixture("deleted")?;
    let context = cx(&root)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &context)?;
    let plan = plan_deletion(&deployment, receipt.import_identity, &context)?;
    assert!(plan.blockers.is_empty());
    let digest = plan.digest()?;
    let approval = approval_digest(digest, SITE, "operator:footage-query")?;
    commit_deletion(
        &mut deployment,
        digest,
        approval,
        "operator:footage-query",
        &context,
    )?;
    drop(deployment);
    let before = bytes(&root)?;
    assert!(query(&root, &request()?)?.rows.is_empty());
    assert_eq!(before, bytes(&root)?);
    Ok(())
}

#[test]
fn shared_budgets_cancellation_and_local_tombstone_races_fail_closed() -> TestResult {
    let (root, _) = fixture("limits-race")?;
    let req = request()?;
    let limits = FootageQueryLimits {
        max_metadata_bytes: 16,
        ..FootageQueryLimits::default()
    };
    assert!(matches!(
        query_footage(&root, &req, &limits, &mut |_| true),
        Err(FootageQueryError::OverBudget)
    ));
    assert!(matches!(
        query_footage(&root, &req, &FootageQueryLimits::default(), &mut |s| s
            != "footage:capsule"),
        Err(FootageQueryError::Cancelled)
    ));
    let row = query(&root, &req)?.rows.remove(0);
    let marker = root.join("objects/tombstones").join(format!(
        "{}.tomb",
        row.capsule_digest.to_text().replacen(':', "-", 1)
    ));
    let mut inserted = false;
    let result = query_footage(&root, &req, &FootageQueryLimits::default(), &mut |stage| {
        if stage == "footage:revalidate" && !inserted {
            fs::write(&marker, b"pending deletion").expect("fixture marker write");
            inserted = true;
        }
        true
    });
    assert!(inserted);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn authority_advance_during_read_refuses_the_pending_page() -> TestResult {
    let (root, _) = fixture("head-race")?;
    let mut changed = false;
    let mut failure = None;
    let result = query_footage(
        &root,
        &request()?,
        &FootageQueryLimits::default(),
        &mut |stage| {
            if stage == "footage:final_head" && !changed {
                let edit = (|| -> TestResult {
                    let context = cx(&root)?;
                    let mut deployment = ReferenceDeployment::open(&root, SITE, &context)?;
                    let mut another = input()?;
                    another.sensor_id = SensorId::parse("sensor:race")?;
                    FileIngestAdapter::ingest(another, &context, &mut deployment)?;
                    Ok(())
                })();
                failure = edit.err();
                changed = true;
            }
            true
        },
    );
    if let Some(error) = failure {
        return Err(error);
    }
    assert!(changed);
    assert!(matches!(result, Err(FootageQueryError::AnchorChanged)));
    Ok(())
}

#[test]
fn multipart_custody_is_resolved_without_reading_source_chunks() -> TestResult {
    let root = directory("parts")?;
    let context = cx(&root)?;
    let mut deployment = ReferenceDeployment::open_with_limits(
        &root,
        SITE,
        DeploymentLimits {
            manifest_children_max: 8,
            ..DeploymentLimits::standard()
        },
        &context,
    )?;
    let mut input = input()?;
    input.limits.chunk_bytes = 512;
    let receipt = FileIngestAdapter::ingest(input, &context, &mut deployment)?;
    assert!(!receipt.manifest.part_roots.is_empty());
    drop(deployment);
    let result = query(&root, &request()?)?;
    assert_eq!(result.scanned_capsules, receipt.capsule_count);
    fs::write(
        spool_path(&root, receipt.manifest.part_roots[0]),
        b"corrupt part",
    )?;
    assert!(query(&root, &request()?).is_err());
    Ok(())
}

#[test]
fn final_verification_spends_the_original_allowance_without_refilling() -> TestResult {
    let (root, _) = fixture("shared-allowance")?;
    let request = request()?;
    let measured = query(&root, &request)?;
    let limits = FootageQueryLimits {
        max_metadata_bytes: measured.metadata_bytes_read as usize - 1,
        ..FootageQueryLimits::default()
    };
    assert!(matches!(
        query_footage(&root, &request, &limits, &mut |_| true),
        Err(FootageQueryError::OverBudget)
    ));
    let limits = FootageQueryLimits {
        max_metadata_objects: measured.metadata_objects_read as usize - 1,
        ..FootageQueryLimits::default()
    };
    assert!(matches!(
        query_footage(&root, &request, &limits, &mut |_| true),
        Err(FootageQueryError::OverBudget)
    ));
    Ok(())
}

#[test]
fn committed_deletion_during_final_replay_cannot_release_the_old_page() -> TestResult {
    let (root, receipt) = fixture("deletion-race")?;
    let mut changed = false;
    let mut failure = None;
    let result = query_footage(
        &root,
        &request()?,
        &FootageQueryLimits::default(),
        &mut |stage| {
            if stage == "footage:final_head" && !changed {
                let edit = (|| -> TestResult {
                    let context = cx(&root)?;
                    let mut deployment = ReferenceDeployment::open(&root, SITE, &context)?;
                    let plan = plan_deletion(&deployment, receipt.import_identity, &context)?;
                    let digest = plan.digest()?;
                    let approval = approval_digest(digest, SITE, "operator:footage-query")?;
                    commit_deletion(
                        &mut deployment,
                        digest,
                        approval,
                        "operator:footage-query",
                        &context,
                    )?;
                    Ok(())
                })();
                failure = edit.err();
                changed = true;
            }
            true
        },
    );
    if let Some(error) = failure {
        return Err(error);
    }
    assert!(changed);
    assert!(matches!(result, Err(FootageQueryError::AnchorChanged)));
    assert!(query(&root, &request()?)?.rows.is_empty());
    Ok(())
}
