#![forbid(unsafe_code)]
//! Retained screened review clips: real source custody, exact local grants and interrupted writes.

#[allow(dead_code)]
#[path = "support/import_integrity.rs"]
mod support;

#[path = "review_media_contract/expiry.rs"]
mod expiry;

use std::{fs, path::PathBuf};

use fss_container::demux::{AvcMp4, DemuxLimits, VideoCodec};
use fss_core::{
    BatchId, BudgetVector, CanonicalDecoder, CanonicalEncode, CaptureInterval, ContentDigest,
    ContextAuthority, EvidenceDelta, ObjectId, OperationId, Plane, PrincipalId, RootAuthoritySpec,
    SensorId, StreamId, TimestampNs,
};
use fss_object::ObjectManifest;
use fss_publication::{LOCAL_ROOTS_DIR, ROOT_RECORD_SUFFIX, SlotName};
use fss_reference::deletion::{
    DeletionError, STAGE_DELETION_RECORD_APPENDED, commit_deletion, plan_deletion,
};
use fss_reference::evidence_export::{CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE};
use fss_reference::ingest::privacy_mask::{
    PrivacyMaskPolicy, current_mask, declare_mask, preview_mask,
};
use fss_reference::ingest::{FileIngestAdapter, FileIngestReceipt, FileIngestRequest};
use fss_reference::review_media::grant::{GrantError, ReviewAccessRequest};
use fss_reference::review_media::render::{ReviewMovieLimits, ReviewMovieRequest};
use fss_reference::review_media::{
    CAP_REVIEW_MEDIA_READ, FAMILY_REVIEW_MEDIA, FAMILY_REVIEW_REVOCATION, REVIEW_OBJECT_PREFIX,
    REVIEW_PROFILE, ReviewMediaError, ReviewMediaRecord, ReviewMediaRequest, commit_review_media,
    inspect_review_media, prepare_review_media, read_review_media, revalidate_review_media,
    revocation_approval, revoke_review_media,
};
use fss_reference::{ReferenceDeployment, ReferenceError, ReplayCx};
use support::{TestResult, snapshot};

const SITE: &str = "site:retained-review-test";
const OWNER: &str = "principal:retained-review-owner";
const READER: &str = "principal:retained-review-reader";
const SENSOR: &str = "sensor:retained-review";
const MEDIA_BOUND: u64 = 1024 * 1024;

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn authority(principal: &str, caps: &[&str], bytes: u64) -> TestResult<ContextAuthority> {
    let mut capabilities = vec!["ADP-REPLAY-001".to_owned()];
    capabilities.extend(caps.iter().map(|cap| (*cap).to_owned()));
    capabilities.sort();
    capabilities.dedup();
    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:retained-review".into(),
        operation_id: OperationId::parse("operation:retained-review")?,
        principal: principal.into(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(bytes)
            .storage_operations(131_072)
            .build()?,
        privacy_scope: "privacy:retained-review".into(),
        retention_scope: "retention:retained-review".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?)
}

fn now(earliest: i128, latest: i128) -> TestResult<CaptureInterval> {
    Ok(CaptureInterval::new(
        TimestampNs(earliest),
        TimestampNs(latest),
    )?)
}

struct Fixture {
    deployment: ReferenceDeployment,
    owner: ContextAuthority,
    cx: ReplayCx,
    source: FileIngestReceipt,
    codec: VideoCodec,
    dimensions: [u32; 2],
    root: PathBuf,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, name: &str) -> TestResult<Self> {
        let directory = Directory(support::directory(label)?);
        let root = directory.0.join("deployment");
        let owner = authority(
            OWNER,
            &[
                "ADP-FILE-001",
                "adp:file:001",
                CAP_EXPORT_PREPARE,
                CAP_EXPORT_COMMIT,
                CAP_REVIEW_MEDIA_READ,
            ],
            1024 * 1024 * 1024,
        )?;
        let cx = ReplayCx::from_context_authority(&owner, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let source_bytes = fs::read(
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../fss-container/tests/fixtures")
                .join(name),
        )?;
        let movie = AvcMp4::parse(&source_bytes, None, DemuxLimits::default())?;
        let codec = movie.codec();
        let [width, height] = movie.dimensions();
        let dimensions = [u32::from(width), u32::from(height)];
        let input = directory.0.join("original.mp4");
        fs::write(&input, source_bytes)?;
        let mut import = FileIngestRequest::new(
            &input,
            SensorId::parse(SENSOR)?,
            StreamId::parse("stream:retained-review")?,
        )
        .with_receive_time(TimestampNs(1_000_000_000));
        import.limits.chunk_bytes = 1024;
        import.limits.max_batch_deltas = 3;
        let source = FileIngestAdapter::ingest(import, &cx, &mut deployment)?;
        // Rendering and all later release checks must use completed retained custody.
        fs::remove_file(input)?;
        let policy = PrivacyMaskPolicy::new(
            SensorId::parse(SENSOR)?,
            dimensions,
            &[[0, 0, dimensions[0] / 2, dimensions[1]]],
        )?;
        let approval = preview_mask(&deployment, &policy)?.approval;
        declare_mask(&mut deployment, &policy, approval, &cx)?;
        Ok(Self {
            deployment,
            owner,
            cx,
            source,
            codec,
            dimensions,
            root,
            _directory: directory,
        })
    }

    fn request(&self) -> TestResult<ReviewMediaRequest> {
        // The HEVC fixture's later CRA skips its leading RASL pictures. Keep this positive
        // lifecycle case within its initial IDR range; separate renderer tests require refusal.
        let (movie_start_tick, movie_end_tick) = match self.codec {
            VideoCodec::Avc => (400, 800),
            VideoCodec::Hevc => (0, 400),
        };
        let movie = ReviewMovieRequest {
            import_identity: self.source.import_identity,
            movie_start_tick,
            movie_end_tick,
            limits: ReviewMovieLimits {
                max_output_bytes: MEDIA_BOUND,
                ..ReviewMovieLimits::default()
            },
        };
        Ok(ReviewMediaRequest {
            access: ReviewAccessRequest {
                import_identity: movie.import_identity,
                import_root: self.source.import_root,
                sensor: SensorId::parse(SENSOR)?,
                movie_start_tick: movie.movie_start_tick,
                movie_end_tick: movie.movie_end_tick,
                expected_privacy: current_mask(&self.deployment, &SensorId::parse(SENSOR)?)?
                    .digest(),
                recipient: PrincipalId::parse(READER)?,
                purpose: "Owner-authorized review of the selected interval".into(),
                issued_at: TimestampNs(10),
                expires_at: TimestampNs(100),
                maximum_media_bytes: MEDIA_BOUND,
            },
            movie,
        })
    }

    fn reader(&self, principal: &str, bytes: u64) -> TestResult<(ContextAuthority, ReplayCx)> {
        let a = authority(principal, &[CAP_REVIEW_MEDIA_READ], bytes)?;
        let cx = ReplayCx::from_context_authority_read_only(&a, self.root.clone())?;
        Ok((a, cx))
    }

    fn publish(&mut self) -> TestResult<(ReviewMediaRequest, ReviewMediaRecord)> {
        let request = self.request()?;
        let preview = prepare_review_media(&self.deployment, &request, &self.owner, &self.cx)?;
        let record = preview.record().clone();
        let committed = commit_review_media(
            &mut self.deployment,
            &request,
            preview.approval(),
            &self.owner,
            &self.cx,
        )?;
        assert!(committed.published);
        assert_eq!(committed.root, record.root());
        Ok((request, record))
    }

    fn cold_reopen(self) -> TestResult<Self> {
        let Self {
            deployment,
            owner,
            cx,
            source,
            codec,
            dimensions,
            root,
            _directory,
        } = self;
        drop(deployment);
        let deployment = ReferenceDeployment::reopen(&root, SITE, &cx)?;
        Ok(Self {
            deployment,
            owner,
            cx,
            source,
            codec,
            dimensions,
            root,
            _directory,
        })
    }
}

fn plant_candidate(
    f: &mut Fixture,
    wire: &[u8],
    media: &[u8],
    receipt: &[u8],
) -> TestResult<ReviewMediaRecord> {
    let record = ReviewMediaRecord::from_bytes(wire, ContentDigest::sha256(wire))?;
    assert_eq!(ContentDigest::sha256(media), record.media_digest());
    assert_eq!(
        ContentDigest::sha256(receipt),
        record.render_receipt_digest()
    );
    let mut decoder = CanonicalDecoder::new(record.to_bytes());
    assert_eq!(decoder.text()?, "fss.retained_review_media.v1");
    assert_eq!(decoder.u32()?, 1);
    assert_eq!(decoder.text()?, REVIEW_PROFILE);
    let identity = decoder.digest()?;
    let identity_hex: String = identity
        .bytes()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let slot = SlotName::parse(&format!("review-{identity_hex}"))?;
    let manifest = ObjectManifest::new(
        REVIEW_PROFILE,
        [record.media_digest(), record.render_receipt_digest()],
        Some(record.digest()),
    )?;
    assert_eq!(manifest.root(), record.root());
    f.deployment.stage_payload(media)?;
    f.deployment.stage_payload(receipt)?;
    f.deployment.stage_payload(record.to_bytes())?;
    f.deployment
        .publisher_mut()
        .stage_manifest(&slot, &manifest)?;
    f.deployment
        .publish_and_commit(&slot, &manifest, now(10, 100)?, &f.cx)?;
    Ok(record)
}

fn replace_one(wire: &mut [u8], old: &[u8], new: &[u8]) {
    assert_eq!(old.len(), new.len());
    let matches: Vec<_> = wire
        .windows(old.len())
        .enumerate()
        .filter_map(|(offset, bytes)| (bytes == old).then_some(offset))
        .collect();
    assert_eq!(matches.len(), 1);
    let offset = matches[0];
    wire[offset..offset + old.len()].copy_from_slice(new);
}

#[test]
fn actual_avc_and_hevc_previews_write_nothing_and_cold_reads_are_exact() -> TestResult {
    for (label, name) in [
        ("review-avc", "indexed_avc.mp4"),
        ("review-hevc", "hevc_av.mp4"),
    ] {
        let mut f = Fixture::new(label, name)?;
        let request = f.request()?;
        let before = snapshot(&f.root)?;
        let preview = prepare_review_media(&f.deployment, &request, &f.owner, &f.cx)?;
        assert!(!preview.already_committed());
        assert_eq!(snapshot(&f.root)?, before);
        assert!(preview.record().frames() > 0);
        assert_eq!(preview.record().grant().request(), &request.access);
        assert_eq!(preview.record().duration_ns(), 400_000_000);
        let bytes = preview.record().to_bytes();
        assert_eq!(
            ReviewMediaRecord::from_bytes(bytes, preview.record().digest())?,
            *preview.record()
        );
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(
            ReviewMediaRecord::from_bytes(&trailing, ContentDigest::sha256(&trailing)).is_err()
        );
        let record = preview.record().clone();
        let receipt = commit_review_media(
            &mut f.deployment,
            &request,
            preview.approval(),
            &f.owner,
            &f.cx,
        )?;
        assert!(receipt.published);
        assert_eq!(receipt.root, record.root());
        let committed = snapshot(&f.root)?;
        let retry = commit_review_media(
            &mut f.deployment,
            &request,
            preview.approval(),
            &f.owner,
            &f.cx,
        )?;
        assert!(!retry.published);
        assert_eq!(snapshot(&f.root)?, committed);
        f = f.cold_reopen()?;
        let before = snapshot(&f.root)?;
        let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
        let media = read_review_media(&f.deployment, receipt.root, now(20, 21)?, &reader, &cx)?;
        assert_eq!(media.record(), &record);
        assert_eq!(media.bytes().len() as u64, record.media_bytes());
        assert_eq!(ContentDigest::sha256(media.bytes()), record.media_digest());
        assert!(media.bytes().starts_with(&[0x1a, 0x45, 0xdf, 0xa3]));
        assert_eq!(
            inspect_review_media(&f.deployment, receipt.root, &f.owner, &f.cx)?,
            record
        );
        assert_eq!(snapshot(&f.root)?, before);
    }
    Ok(())
}

#[test]
fn roots_never_replace_exact_recipient_capability_time_or_current_byte_budget() -> TestResult {
    let mut f = Fixture::new("review-reader-admission", "indexed_avc.mp4")?;
    let (_, record) = f.publish()?;
    let before = snapshot(&f.root)?;
    let (wrong, wrong_cx) = f.reader("principal:other-reader", MEDIA_BOUND)?;
    assert!(matches!(
        read_review_media(
            &f.deployment,
            record.root(),
            now(20, 21)?,
            &wrong,
            &wrong_cx
        ),
        Err(ReviewMediaError::Grant(GrantError::ScopeMismatch))
    ));
    let unprivileged = authority(READER, &[], MEDIA_BOUND)?;
    let unprivileged_cx =
        ReplayCx::from_context_authority_read_only(&unprivileged, f.root.clone())?;
    assert!(matches!(
        read_review_media(
            &f.deployment,
            record.root(),
            now(20, 21)?,
            &unprivileged,
            &unprivileged_cx
        ),
        Err(ReviewMediaError::Unauthorized)
    ));
    let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
    for (earliest, latest, expected) in [
        (9, 10, GrantError::NotYetValid),
        (99, 100, GrantError::ExpiryUncertain),
        (100, 101, GrantError::Expired),
    ] {
        assert!(matches!(
            read_review_media(&f.deployment, record.root(), now(earliest, latest)?, &reader, &cx),
            Err(ReviewMediaError::Grant(error)) if error == expected
        ));
    }
    let loaded = read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx)?;
    let (narrow, narrow_cx) = f.reader(READER, record.media_bytes() - 1)?;
    assert!(matches!(
        read_review_media(
            &f.deployment,
            record.root(),
            now(20, 21)?,
            &narrow,
            &narrow_cx
        ),
        Err(ReviewMediaError::Limit)
    ));
    assert!(matches!(
        revalidate_review_media(&f.deployment, &loaded, now(20, 21)?, &narrow, &narrow_cx),
        Err(ReviewMediaError::Limit)
    ));
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn changing_masks_invalidates_old_approval_reads_and_pending_release() -> TestResult {
    let mut f = Fixture::new("review-mask-generation", "indexed_avc.mp4")?;
    let (request, record) = f.publish()?;
    let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
    let loaded = read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx)?;
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse(SENSOR)?,
        f.dimensions,
        &[[0, 0, f.dimensions[0], f.dimensions[1]]],
    )?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let before = snapshot(&f.root)?;
    assert!(matches!(
        read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx),
        Err(ReviewMediaError::PrivacyChanged)
    ));
    assert!(matches!(
        revalidate_review_media(&f.deployment, &loaded, now(20, 21)?, &reader, &cx),
        Err(ReviewMediaError::AuthorityChanged)
    ));
    assert!(matches!(
        commit_review_media(
            &mut f.deployment,
            &request,
            record.approval(),
            &f.owner,
            &f.cx
        ),
        Err(ReviewMediaError::PrivacyChanged)
    ));
    assert_eq!(snapshot(&f.root)?, before);
    let replacement = f.request()?;
    assert_ne!(
        replacement.access.expected_privacy,
        request.access.expected_privacy
    );
    let fresh = prepare_review_media(&f.deployment, &replacement, &f.owner, &f.cx)?;
    assert_ne!(fresh.root(), record.root());
    assert_ne!(fresh.approval(), record.approval());
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn revocation_survives_cold_reopen_and_cannot_be_undone_by_exact_commit_retry() -> TestResult {
    let mut f = Fixture::new("review-revoke", "indexed_avc.mp4")?;
    let (request, record) = f.publish()?;
    let before = snapshot(&f.root)?;
    let approval = revocation_approval(&f.deployment, record.root(), &f.owner, &f.cx)?;
    assert_eq!(snapshot(&f.root)?, before);
    assert!(matches!(
        revoke_review_media(
            &mut f.deployment,
            record.root(),
            record.approval(),
            &f.owner,
            &f.cx
        ),
        Err(ReviewMediaError::StaleApproval)
    ));
    assert_eq!(snapshot(&f.root)?, before);
    assert!(
        revoke_review_media(&mut f.deployment, record.root(), approval, &f.owner, &f.cx)?.published
    );
    f = f.cold_reopen()?;
    let before = snapshot(&f.root)?;
    assert!(
        !revoke_review_media(&mut f.deployment, record.root(), approval, &f.owner, &f.cx)?
            .published
    );
    assert_eq!(
        inspect_review_media(&f.deployment, record.root(), &f.owner, &f.cx)?,
        record
    );
    let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
    assert!(matches!(
        read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx),
        Err(ReviewMediaError::Revoked)
    ));
    assert!(matches!(
        commit_review_media(
            &mut f.deployment,
            &request,
            record.approval(),
            &f.owner,
            &f.cx
        ),
        Err(ReviewMediaError::Revoked)
    ));
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn cancellation_before_write_and_between_root_and_grant_has_exact_cold_retry() -> TestResult {
    let mut f = Fixture::new("review-interrupted-publication", "indexed_avc.mp4")?;
    let request = f.request()?;
    let preview = prepare_review_media(&f.deployment, &request, &f.owner, &f.cx)?;
    let before = snapshot(&f.root)?;
    let stop = ReplayCx::from_context_authority(&f.owner, f.root.clone())?;
    stop.set_cancel_at_checkpoint("review_media:revalidated");
    assert!(matches!(
        commit_review_media(
            &mut f.deployment,
            &request,
            preview.approval(),
            &f.owner,
            &stop
        ),
        Err(ReviewMediaError::Cancelled)
    ));
    assert_eq!(snapshot(&f.root)?, before);
    let stop = ReplayCx::from_context_authority(&f.owner, f.root.clone())?;
    stop.set_cancel_at_checkpoint("review_media:root_published");
    assert!(matches!(
        commit_review_media(
            &mut f.deployment,
            &request,
            preview.approval(),
            &f.owner,
            &stop
        ),
        Err(ReviewMediaError::Cancelled)
    ));
    f = f.cold_reopen()?;
    let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
    assert!(matches!(
        read_review_media(&f.deployment, preview.root(), now(20, 21)?, &reader, &cx),
        Err(ReviewMediaError::CustodyMismatch)
    ));
    let before = snapshot(&f.root)?;
    let resumed = prepare_review_media(&f.deployment, &request, &f.owner, &f.cx)?;
    assert!(!resumed.already_committed());
    assert_eq!(resumed.root(), preview.root());
    assert_eq!(resumed.approval(), preview.approval());
    assert_eq!(snapshot(&f.root)?, before);
    let committed = commit_review_media(
        &mut f.deployment,
        &request,
        preview.approval(),
        &f.owner,
        &f.cx,
    )?;
    assert!(committed.published);
    assert_eq!(committed.root, preview.root());
    let loaded = read_review_media(&f.deployment, committed.root, now(20, 21)?, &reader, &cx)?;
    assert_eq!(loaded.media_digest(), preview.record().media_digest());
    Ok(())
}

#[test]
fn committed_source_deletion_denies_review_before_any_payload_is_unlinked() -> TestResult {
    let mut f = Fixture::new("review-delete-source", "indexed_avc.mp4")?;
    let (request, record) = f.publish()?;
    let plan = plan_deletion(&f.deployment, f.source.import_identity, &f.cx)?;
    assert!(plan.blockers.is_empty(), "{:?}", plan.blockers);
    for digest in [
        record.root(),
        record.digest(),
        record.media_digest(),
        record.render_receipt_digest(),
    ] {
        assert!(
            plan.deletable.iter().any(|object| object.digest == digest),
            "review child absent from source deletion closure: {digest}"
        );
    }
    let digest = plan.digest()?;
    let approval = plan.approval_digest(OWNER)?;
    let stop = ReplayCx::from_context_authority(&f.owner, f.root.clone())?;
    stop.set_cancel_at_checkpoint(STAGE_DELETION_RECORD_APPENDED);
    assert!(matches!(
        commit_deletion(&mut f.deployment, digest, approval, OWNER, &stop),
        Err(DeletionError::Cancelled {
            stage: STAGE_DELETION_RECORD_APPENDED
        })
    ));
    assert!(
        f.deployment
            .publisher()
            .spool()
            .object_path(record.media_digest())
            .exists()
    );
    let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
    let before = snapshot(&f.root)?;
    assert!(matches!(
        read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx),
        Err(ReviewMediaError::Deleted)
    ));
    assert_eq!(snapshot(&f.root)?, before);
    f = f.cold_reopen()?;
    assert!(matches!(
        read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx),
        Err(ReviewMediaError::Deleted)
    ));
    commit_deletion(&mut f.deployment, digest, approval, OWNER, &f.cx)?;
    assert!(
        f.deployment
            .publisher()
            .visible_roots()
            .all(|root| root.root != record.root())
    );
    assert!(matches!(
        read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx),
        Err(ReviewMediaError::Deleted)
    ));
    assert!(matches!(
        prepare_review_media(&f.deployment, &request, &f.owner, &f.cx),
        Err(ReviewMediaError::Deleted)
    ));
    Ok(())
}

#[test]
fn missing_or_corrupt_root_custody_never_claims_deletion_or_authorizes_cached_reads() -> TestResult
{
    for damage in ["missing", "corrupt"] {
        let mut f = Fixture::new(&format!("review-root-{damage}"), "indexed_avc.mp4")?;
        let (request, record) = f.publish()?;
        let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
        let loaded = read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx)?;
        let visible = f
            .deployment
            .publisher()
            .visible_roots()
            .find(|root| root.root == record.root())
            .ok_or("published review root is absent")?;
        let path = f
            .deployment
            .publisher()
            .root_dir()
            .join(LOCAL_ROOTS_DIR)
            .join(format!("{}{ROOT_RECORD_SUFFIX}", visible.slot));
        if damage == "missing" {
            fs::remove_file(path)?;
        } else {
            let mut bytes = fs::read(&path)?;
            *bytes.last_mut().ok_or("empty root record")? ^= 1;
            fs::write(path, bytes)?;
        }
        // First exercise the still-cached publisher view, then the cold missing/broken slot.
        for cold in [false, true] {
            if cold {
                f = f.cold_reopen()?;
            }
            let before = snapshot(&f.root)?;
            assert!(matches!(
                prepare_review_media(&f.deployment, &request, &f.owner, &f.cx),
                Err(ReviewMediaError::CustodyMismatch)
            ));
            assert!(matches!(
                inspect_review_media(&f.deployment, record.root(), &f.owner, &f.cx),
                Err(ReviewMediaError::CustodyMismatch)
            ));
            assert!(matches!(
                read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx),
                Err(ReviewMediaError::CustodyMismatch)
            ));
            assert!(matches!(
                revalidate_review_media(&f.deployment, &loaded, now(20, 21)?, &reader, &cx),
                Err(ReviewMediaError::CustodyMismatch)
            ));
            assert!(matches!(
                commit_review_media(
                    &mut f.deployment,
                    &request,
                    record.approval(),
                    &f.owner,
                    &f.cx
                ),
                Err(ReviewMediaError::CustodyMismatch)
            ));
            assert_eq!(snapshot(&f.root)?, before);
        }
    }
    Ok(())
}

#[test]
fn missing_or_corrupt_source_root_refuses_hot_and_cold_review_release_without_writes() -> TestResult
{
    for damage in ["missing", "corrupt"] {
        let mut f = Fixture::new(&format!("review-source-root-{damage}"), "indexed_avc.mp4")?;
        let (request, record) = f.publish()?;
        let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
        let loaded = read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx)?;
        let source_manifest = f
            .deployment
            .publisher()
            .spool()
            .read(f.source.import_root)?;
        let review_manifest = f.deployment.publisher().spool().read(record.root())?;
        assert!(f.source.root_slot.as_str().starts_with("fi-"));
        let source_record = f
            .deployment
            .publisher()
            .root_dir()
            .join(LOCAL_ROOTS_DIR)
            .join(format!("{}{ROOT_RECORD_SUFFIX}", f.source.root_slot));
        if damage == "missing" {
            fs::remove_file(source_record)?;
        } else {
            let mut bytes = fs::read(&source_record)?;
            *bytes.last_mut().ok_or("empty source root record")? ^= 1;
            fs::write(source_record, bytes)?;
        }
        // Only the original import's durable root record is damaged. Its object graph and
        // the complete reviewed derivative remain present, including the previously read bytes.
        for cold in [false, true] {
            if cold {
                f = f.cold_reopen()?;
            }
            let before = snapshot(&f.root)?;
            assert_eq!(
                f.deployment
                    .publisher()
                    .spool()
                    .read(f.source.import_root)?,
                source_manifest
            );
            assert_eq!(
                f.deployment.publisher().spool().read(record.root())?,
                review_manifest
            );
            assert_eq!(
                f.deployment
                    .publisher()
                    .spool()
                    .read(record.media_digest())?,
                loaded.bytes()
            );
            // Metadata inspection confers no authority to disclose this retained media.
            assert_eq!(
                inspect_review_media(&f.deployment, record.root(), &f.owner, &f.cx)?,
                record
            );
            assert!(matches!(
                prepare_review_media(&f.deployment, &request, &f.owner, &f.cx),
                Err(ReviewMediaError::CustodyMismatch)
            ));
            assert!(matches!(
                commit_review_media(
                    &mut f.deployment,
                    &request,
                    record.approval(),
                    &f.owner,
                    &f.cx
                ),
                Err(ReviewMediaError::CustodyMismatch)
            ));
            assert!(matches!(
                read_review_media(&f.deployment, record.root(), now(20, 21)?, &reader, &cx),
                Err(ReviewMediaError::CustodyMismatch)
            ));
            assert!(matches!(
                revalidate_review_media(&f.deployment, &loaded, now(20, 21)?, &reader, &cx),
                Err(ReviewMediaError::CustodyMismatch)
            ));
            if !cold {
                // A different purpose has no existing review to recover. Its complete native
                // render still cannot turn a cached source-root observation into current custody.
                let mut fresh = request.clone();
                fresh
                    .access
                    .purpose
                    .push_str(" with a new local review purpose");
                assert!(matches!(
                    prepare_review_media(&f.deployment, &fresh, &f.owner, &f.cx),
                    Err(ReviewMediaError::CustodyMismatch)
                ));
            }
            assert_eq!(snapshot(&f.root)?, before);
        }
    }
    Ok(())
}

#[test]
fn generic_authority_append_cannot_forge_review_issuance_or_revocation() -> TestResult {
    let mut f = Fixture::new("review-reserved-authority", "indexed_avc.mp4")?;
    let before = snapshot(&f.root)?;
    for (family, object) in [
        (FAMILY_REVIEW_MEDIA, "object:any".to_owned()),
        (FAMILY_REVIEW_REVOCATION, "object:any".to_owned()),
        ("other_family", format!("{REVIEW_OBJECT_PREFIX}forged")),
    ] {
        let digest = ContentDigest::sha256(b"unstaged forged review authority");
        assert!(matches!(
            f.deployment.append_batch(
                BatchId::parse("batch:forged-review")?,
                vec![EvidenceDelta {
                    delta_id: "delta:forged-review".into(),
                    family: family.into(),
                    object_id: ObjectId::parse(object)?,
                    prior_generation: None,
                    new_generation: 1,
                    validity: now(10, 100)?,
                    plane: Plane::Authority,
                    payload_digest: digest,
                    witness_digest: None,
                    operation_id: None,
                }],
                vec![digest],
                &f.cx,
            ),
            Err(ReferenceError::ReservedDeltaFamily { .. })
        ));
    }
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn generic_root_publication_cannot_launder_arbitrary_bytes_into_a_review_grant() -> TestResult {
    let mut f = Fixture::new("review-forged-recovery", "indexed_avc.mp4")?;
    let request = f.request()?;
    let preview = prepare_review_media(&f.deployment, &request, &f.owner, &f.cx)?;
    let honest = preview.record();
    // Simulate an untrusted caller of the generic root publisher. The forged graph is complete,
    // has valid object digests, exact request/owner/sensor pins, and a canonical custody record.
    // Its bytes have never passed the native source renderer or current-mask application.
    let false_media = vec![0x42; honest.media_bytes().try_into()?];
    let false_receipt = vec![0x21; honest.render_receipt_bytes().try_into()?];
    let false_media_digest = ContentDigest::sha256(&false_media);
    let false_receipt_digest = ContentDigest::sha256(&false_receipt);
    let mut wire = honest.to_bytes().to_vec();
    for (old, new, expected_occurrences) in [
        (honest.media_digest(), false_media_digest, 1),
        (honest.render_receipt_digest(), false_receipt_digest, 2),
    ] {
        let matches: Vec<_> = wire
            .windows(32)
            .enumerate()
            .filter_map(|(offset, bytes)| (bytes == old.bytes()).then_some(offset))
            .collect();
        assert_eq!(matches.len(), expected_occurrences);
        for offset in matches {
            wire[offset..offset + 32].copy_from_slice(&new.bytes());
        }
    }
    let forged = plant_candidate(&mut f, &wire, &false_media, &false_receipt)?;
    assert_ne!(forged.media_digest(), honest.media_digest());
    assert_eq!(forged.grant().request(), honest.grant().request());
    let before = snapshot(&f.root)?;
    let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
    assert!(matches!(
        read_review_media(&f.deployment, forged.root(), now(20, 21)?, &reader, &cx),
        Err(ReviewMediaError::CustodyMismatch)
    ));
    assert!(matches!(
        commit_review_media(
            &mut f.deployment,
            &request,
            forged.approval(),
            &f.owner,
            &f.cx
        ),
        Err(ReviewMediaError::CustodyMismatch)
    ));
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn authentic_render_bytes_do_not_validate_fabricated_source_claims_or_historical_basis()
-> TestResult {
    let mut f = Fixture::new("review-forged-metadata", "indexed_avc.mp4")?;
    let (_, original) = f.publish()?;
    let (reader, cx) = f.reader(READER, MEDIA_BOUND)?;
    let media = read_review_media(&f.deployment, original.root(), now(20, 21)?, &reader, &cx)?;
    let receipt = f.deployment.publisher().spool().read_bounded(
        original.render_receipt_digest(),
        original.render_receipt_bytes().try_into()?,
    )?;
    for mutation in ["source-input", "read-limits", "historical-basis"] {
        let mut request = f.request()?;
        request.access.purpose.push_str(mutation);
        let preview = prepare_review_media(&f.deployment, &request, &f.owner, &f.cx)?;
        // Rendering provenance is stable across unrelated authority appends; its enclosing
        // record separately names the preparation head and immutable reviewer purpose.
        assert_eq!(preview.record().media_digest(), original.media_digest());
        assert_eq!(
            preview.record().render_receipt_digest(),
            original.render_receipt_digest()
        );
        let mut wire = preview.record().to_bytes().to_vec();
        match mutation {
            "source-input" => replace_one(
                &mut wire,
                &f.source.manifest.input_sha256.bytes(),
                &ContentDigest::sha256(b"fabricated original source digest").bytes(),
            ),
            "read-limits" => {
                let limits = request.movie.limits.read;
                let mut old = Vec::new();
                for value in [
                    limits.max_source_bytes,
                    limits.max_chunk_bytes,
                    limits.max_segment_bytes,
                ] {
                    old.extend_from_slice(&value.to_be_bytes());
                }
                let mut new = old.clone();
                new[..8].copy_from_slice(&(limits.max_source_bytes - 1).to_be_bytes());
                replace_one(&mut wire, &old, &new);
            }
            "historical-basis" => {
                assert_ne!(preview.record().basis(), original.basis());
                replace_one(
                    &mut wire,
                    &preview.record().basis().canonical_bytes(),
                    &original.basis().canonical_bytes(),
                );
            }
            _ => unreachable!("fixed mutation cases"),
        }
        let forged = plant_candidate(&mut f, &wire, media.bytes(), &receipt)?;
        let before = snapshot(&f.root)?;
        assert!(
            matches!(
                commit_review_media(
                    &mut f.deployment,
                    &request,
                    forged.approval(),
                    &f.owner,
                    &f.cx
                ),
                Err(ReviewMediaError::CustodyMismatch)
            ),
            "accepted forged {mutation}"
        );
        assert_eq!(snapshot(&f.root)?, before);
    }
    Ok(())
}
