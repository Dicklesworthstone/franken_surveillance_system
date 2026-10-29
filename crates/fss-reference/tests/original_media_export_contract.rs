#![forbid(unsafe_code)]
//! Real retained source → native observation/event → approved original-media package.

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, CaptureInterval, ContentDigest, EventId, LedgerAnchor, OperationId, SensorId,
    StreamId, TimestampNs,
};
use fss_reference::deletion::{commit_deletion, plan_deletion};
use fss_reference::event_review::{
    CAP_REVIEW_COMMIT, CAP_REVIEW_PREPARE, ReviewDisposition, ReviewRequest, commit_review,
    preview_review,
};
use fss_reference::evidence_export::{CAP_EXPORT_COMMIT, CAP_EXPORT_PREPARE, EventExportRequest};
use fss_reference::ingest::long_dwell::LongDwellLimits;
use fss_reference::ingest::long_watch::LongWatchReport;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_corroboration::streaming::LongCorroborationReport;
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationDependencies, CorroborationGates, CorroborationOptions,
    CorroborationPlan, GroundHomography, GroundZone,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest, RetainedFileImport,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::original_media_export::{
    CAP_EXPORT_ORIGINAL_MEDIA, MAX_ORIGINAL_MEDIA_BYTES, OriginalMediaExportError,
    OriginalMediaExportRequest, approve_original_media_export, preview_original_media_export,
    revalidate_original_media_export, verify_original_media_export,
};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
#[path = "original_media_export_contract/package.rs"]
mod package;
#[path = "original_media_export_contract/reviewed.rs"]
mod reviewed;
const SITE: &str = "site:original-media-export";
const ACTOR: &str = "principal:original-media-owner";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for n in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-original-media-{label}-{}-{n}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary-directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn authority(original_media: bool) -> Test<ContextAuthority> {
    let mut capabilities = vec![
        "ADP-REPLAY-001".to_owned(),
        CAP_EXPORT_PREPARE.into(),
        CAP_EXPORT_COMMIT.into(),
        CAP_REVIEW_PREPARE.into(),
        CAP_REVIEW_COMMIT.into(),
    ];
    if original_media {
        capabilities.push(CAP_EXPORT_ORIGINAL_MEDIA.into());
    }
    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:original-media-export".into(),
        operation_id: OperationId::parse("operation:original-media-export")?,
        principal: ACTOR.into(),
        capabilities,
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(256 * 1024 * 1024)
            .storage_operations(131_072)
            .build()?,
        privacy_scope: "privacy:owner-original-media".into(),
        retention_scope: "retention:local-test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?)
}

fn scene() -> Test<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut bytes = Vec::new();
    for frame in 0..24 {
        let mut pixels = vec![40_u8; 48 * 32];
        if frame >= 3 {
            for y in 8..24 {
                for x in 8..24 {
                    pixels[y * 48 + x] = 220;
                }
            }
        }
        bytes.extend(encode_jpeg(48, 32, &pixels, &config)?);
    }
    Ok(bytes)
}

struct Fixture {
    directory: Directory,
    deployment: ReferenceDeployment,
    authority: ContextAuthority,
    cx: ReplayCx,
    request: OriginalMediaExportRequest,
    source: Vec<u8>,
}
impl Fixture {
    fn new(label: &str) -> Test<Self> {
        Self::from_source(label, scene()?, "mjpeg", [48, 32])
    }
    fn from_source(label: &str, source: Vec<u8>, extension: &str, size: [u32; 2]) -> Test<Self> {
        Self::from_source_with_mask(label, source, extension, size, false)
    }
    fn from_source_with_mask(
        label: &str,
        source: Vec<u8>,
        extension: &str,
        size: [u32; 2],
        masked: bool,
    ) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let authority = authority(true)?;
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let input = directory.0.join(format!("input.{extension}"));
        fs::write(&input, &source)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = 1024;
        limits.chunk_bytes = 4096;
        let imported = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &input,
                SensorId::parse("sensor:original-media")?,
                StreamId::parse("stream:original-media")?,
            )
            .with_limits(limits)
            .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
            .with_receive_time(TimestampNs(1_000_000_000_000)),
            &cx,
            &mut deployment,
        )?;
        // The workflow must survive loss of the original input file.
        fs::remove_file(input)?;
        if masked {
            let policy = PrivacyMaskPolicy::new(
                SensorId::parse("sensor:original-media")?,
                size,
                &[[size[0] - 8, 0, 8, size[1]]],
            )?;
            let approval = preview_mask(&deployment, &policy)?.approval;
            declare_mask(&mut deployment, &policy, approval, &cx)?;
        }
        let plan = WatchPlan {
            import_identity: imported.import_identity,
            interpretation: if extension == "mjpeg" {
                ComponentInterpretation::Grayscale
            } else {
                ComponentInterpretation::YCbCr
            },
            first_segment: 0,
            segment_count: imported.capsule_count,
            zones: vec![WatchZone {
                zone_id: "porch".into(),
                x: 0,
                y: 0,
                // The event is valid under the current mask: its observed zone excludes
                // the masked right edge. Whole-source disclosure still includes that edge.
                width: if masked { size[0] - 8 } else { size[0] },
                height: size[1],
            }],
            detector: WatchDetectorConfig {
                learning_rate_num: 0,
                ..WatchDetectorConfig::default()
            },
            tracker: WatchTrackerConfig::default(),
        };
        let mut report = LongWatchReport::analyze(
            &deployment,
            &plan,
            WatchOptions::default(),
            &LongDwellLimits::default(),
            &cx,
        )?;
        let candidate = report
            .candidates()
            .first()
            .ok_or("native watch entry missing")?;
        let event_id: EventId = candidate.event().event_id.clone();
        let approval = candidate.proposal_digest();
        assert_eq!(
            report.publish(&mut deployment, &BTreeSet::from([approval]), &cx)?,
            1
        );
        let (event, _) = deployment.current_event_authority(&event_id)?;
        let retained = RetainedFileImport::open(
            &deployment,
            imported.import_identity,
            Default::default(),
            &cx,
        )?;
        let request = OriginalMediaExportRequest {
            event: EventExportRequest {
                event_id,
                expected_revision: event.revision_digest(),
                recipient: "recipient:owner-case".into(),
                purpose: "Review original incident video and its temporal context".into(),
                expires_at: TimestampNs(2_000_000_000_000),
            },
            import_identity: imported.import_identity,
            expected_import_root: retained.import_root(),
            whole_source_authorized: true,
            destination_binding: ContentDigest::sha256(b"approved-create-only-destination"),
            max_source_bytes: 4 * 1024 * 1024,
            attested_now: CaptureInterval {
                earliest: TimestampNs(1_000_000_000_000),
                latest: TimestampNs(1_000_000_001_000),
            },
        };
        Ok(Self {
            directory,
            deployment,
            authority,
            cx,
            request,
            source,
        })
    }
    fn snapshot(&self) -> (LedgerAnchor, ContentDigest, usize) {
        (
            self.deployment.current_anchor().clone(),
            self.deployment.effects().last_root(),
            self.deployment.publisher().spool().object_count(),
        )
    }
}

#[test]
fn cold_event_export_keeps_all_playable_original_bytes_and_explicit_context_without_writes() -> Test
{
    let f = Fixture::new("cold")?;
    let before = f.snapshot();
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    let preview = preview_original_media_export(&reopened, &f.request, &f.authority, &f.cx)?;
    assert_eq!(preview.media_bytes(), f.source);
    assert_eq!(preview.media_digest(), ContentDigest::sha256(&f.source));
    assert_eq!(preview.media_filename(), "source.mjpeg");
    let json = preview.record_json();
    assert_eq!(preview.profile(), "event-original-media-whole-source-v1");
    assert!(json.contains("\"schema\":\"fss.original_media_export.v1\""));
    assert!(!json.contains("review_chain"));
    for field in [
        "\"whole_source_authorized\":true",
        "\"frame_precise_trim\":false",
        "\"context_outside_event_may_be_included\":true",
        "\"audio_included\":false",
        "\"source_segments\":24",
        "\"source_capture_earliest_ns\":0",
        "\"capture_time_basis\":\"operator_assumption\"",
        "\"external_copies_auto_erased\":false",
        "\"delivery_status\":\"not_observed_by_preparation\"",
    ] {
        assert!(json.contains(field), "missing disclosure {field}: {json}");
    }
    let prepared = approve_original_media_export(
        &reopened,
        &f.request,
        preview.approval(),
        &f.authority,
        &f.cx,
    )?;
    revalidate_original_media_export(&reopened, &prepared, &f.authority, &f.cx)?;
    let record = verify_original_media_export(
        preview.manifest_bytes(),
        preview.record_bytes(),
        preview.media_bytes(),
        preview.root(),
    )?;
    assert_eq!(record.to_json(), preview.record_json());
    assert_eq!(record.request(), &f.request);
    assert_eq!(*reopened.current_anchor(), before.0);
    assert_eq!(reopened.effects().last_root(), before.1);
    assert_eq!(reopened.publisher().spool().object_count(), before.2);
    assert!(!f.directory.0.join("export").exists());
    Ok(())
}

#[test]
fn recipient_purpose_destination_time_and_budget_are_exact_approval_inputs() -> Test {
    let f = Fixture::new("approval")?;
    let preview = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
    let mut requests = Vec::new();
    let mut changed = f.request.clone();
    changed.event.recipient = "recipient:other".into();
    requests.push(changed);
    let mut changed = f.request.clone();
    changed.event.purpose = "Another purpose".into();
    requests.push(changed);
    let mut changed = f.request.clone();
    changed.destination_binding = ContentDigest::sha256(b"different-output-directory");
    requests.push(changed);
    let mut changed = f.request.clone();
    changed.max_source_bytes += 1;
    requests.push(changed);
    let mut changed = f.request.clone();
    changed.attested_now.latest.0 += 1;
    requests.push(changed);
    let mut changed = f.request.clone();
    changed.event.expires_at.0 += 1;
    requests.push(changed);
    let before = f.snapshot();
    for request in requests {
        assert!(matches!(
            approve_original_media_export(
                &f.deployment,
                &request,
                preview.approval(),
                &f.authority,
                &f.cx
            ),
            Err(OriginalMediaExportError::StaleApproval)
        ));
    }
    let no_original = authority(false)?;
    assert!(matches!(
        preview_original_media_export(&f.deployment, &f.request, &no_original, &f.cx),
        Err(OriginalMediaExportError::Unauthorized)
    ));
    let mut changed_scope = f.authority.clone();
    changed_scope.privacy_scope = "privacy:other".into();
    assert!(matches!(
        approve_original_media_export(
            &f.deployment,
            &f.request,
            preview.approval(),
            &changed_scope,
            &f.cx
        ),
        Err(OriginalMediaExportError::StaleApproval)
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn authority_deadline_is_exclusive_at_preview_approval_and_final_revalidation() -> Test {
    let f = Fixture::new("authority-deadline")?;
    let before = f.snapshot();
    // The authority can expire before the package itself. Even a one-nanosecond margin
    // beyond the complete attested interval is valid; no ambient clock is substituted.
    let mut valid = f.authority.clone();
    valid.deadline = Some(TimestampNs(f.request.attested_now.latest.0 + 1));
    let preview = preview_original_media_export(&f.deployment, &f.request, &valid, &f.cx)?;
    let prepared = approve_original_media_export(
        &f.deployment,
        &f.request,
        preview.approval(),
        &valid,
        &f.cx,
    )?;
    revalidate_original_media_export(&f.deployment, &prepared, &valid, &f.cx)?;
    for deadline in [
        TimestampNs(f.request.attested_now.earliest.0 - 1),
        TimestampNs(f.request.attested_now.latest.0 - 1),
        f.request.attested_now.latest,
    ] {
        // Includes already-expired authority, uncertainty crossing the deadline, and
        // exact equality. A newly narrowed grant must also stop an approved package.
        let mut expired = valid.clone();
        expired.deadline = Some(deadline);
        assert!(matches!(
            preview_original_media_export(&f.deployment, &f.request, &expired, &f.cx),
            Err(OriginalMediaExportError::Unauthorized)
        ));
        assert!(matches!(
            approve_original_media_export(
                &f.deployment,
                &f.request,
                preview.approval(),
                &expired,
                &f.cx
            ),
            Err(OriginalMediaExportError::Unauthorized)
        ));
        assert!(matches!(
            revalidate_original_media_export(&f.deployment, &prepared, &expired, &f.cx),
            Err(OriginalMediaExportError::Unauthorized)
        ));
    }
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn missing_whole_source_acknowledgement_expired_time_and_excess_bounds_fail_before_io() -> Test {
    let f = Fixture::new("bounds")?;
    let mut invalid = f.request.clone();
    invalid.whole_source_authorized = false;
    assert!(matches!(
        invalid.validate(),
        Err(OriginalMediaExportError::InvalidRequest)
    ));
    invalid = f.request.clone();
    invalid.max_source_bytes = MAX_ORIGINAL_MEDIA_BYTES + 1;
    assert!(matches!(
        invalid.validate(),
        Err(OriginalMediaExportError::InvalidRequest)
    ));
    invalid = f.request.clone();
    invalid.attested_now.latest = invalid.event.expires_at;
    assert!(matches!(
        invalid.validate(),
        Err(OriginalMediaExportError::Expired)
    ));
    invalid.attested_now.earliest = invalid.event.expires_at;
    assert!(matches!(
        invalid.validate(),
        Err(OriginalMediaExportError::Expired)
    ));
    invalid = f.request.clone();
    invalid.attested_now.earliest.0 = invalid.attested_now.latest.0 + 1;
    assert!(matches!(
        invalid.validate(),
        Err(OriginalMediaExportError::InvalidRequest)
    ));
    invalid = f.request.clone();
    invalid.max_source_bytes = f.source.len() as u64 - 1;
    assert!(preview_original_media_export(&f.deployment, &invalid, &f.authority, &f.cx).is_err());
    invalid = f.request.clone();
    invalid.import_identity = ContentDigest::sha256(b"unrelated-source");
    assert!(matches!(
        preview_original_media_export(&f.deployment, &invalid, &f.authority, &f.cx),
        Err(OriginalMediaExportError::SourceNotInEvent)
    ));
    invalid = f.request.clone();
    invalid.expected_import_root = ContentDigest::sha256(b"wrong-import-root");
    assert!(matches!(
        preview_original_media_export(&f.deployment, &invalid, &f.authority, &f.cx),
        Err(OriginalMediaExportError::CustodyMismatch)
    ));
    Ok(())
}

#[test]
fn offline_verifier_requires_the_independent_root_and_every_original_byte() -> Test {
    let f = Fixture::new("offline")?;
    let preview = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
    let mut changed = preview.media_bytes().to_vec();
    let last = changed.last_mut().ok_or("empty source")?;
    *last ^= 1;
    assert!(
        verify_original_media_export(
            preview.manifest_bytes(),
            preview.record_bytes(),
            &changed,
            preview.root()
        )
        .is_err()
    );
    assert!(
        verify_original_media_export(
            preview.manifest_bytes(),
            preview.record_bytes(),
            preview.media_bytes(),
            ContentDigest::sha256(b"other-root")
        )
        .is_err()
    );
    let mut record = preview.record_bytes().to_vec();
    record.push(0);
    assert!(
        verify_original_media_export(
            preview.manifest_bytes(),
            &record,
            preview.media_bytes(),
            preview.root()
        )
        .is_err()
    );
    assert!(
        verify_original_media_export(
            preview.manifest_bytes(),
            preview.record_bytes(),
            &preview.media_bytes()[..preview.media_bytes().len() - 1],
            preview.root()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn mask_change_between_approval_and_output_refuses_the_whole_unmasked_source() -> Test {
    let mut f = Fixture::new("privacy")?;
    let preview = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
    let prepared = approve_original_media_export(
        &f.deployment,
        &f.request,
        preview.approval(),
        &f.authority,
        &f.cx,
    )?;
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:original-media")?,
        [48, 32],
        &[[40, 0, 8, 32]],
    )?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
    assert!(matches!(
        revalidate_original_media_export(&reopened, &prepared, &f.authority, &f.cx),
        Err(OriginalMediaExportError::AuthorityChanged)
    ));
    // An old approval cannot be refreshed into an unmasked export through the same command.
    assert!(preview_original_media_export(&reopened, &f.request, &f.authority, &f.cx).is_err());
    Ok(())
}

#[test]
fn an_event_computed_under_the_current_mask_still_cannot_export_unmasked_originals() -> Test {
    let f = Fixture::from_source_with_mask("masked-event", scene()?, "mjpeg", [48, 32], true)?;
    let before = f.snapshot();
    let refusal =
        match preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx) {
            Err(refusal) => refusal,
            Ok(_) => return Err("current masked event authorized original pixels".into()),
        };
    assert_eq!(
        refusal.stable_id(),
        "ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001"
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn current_event_revision_and_committed_source_deletion_invalidate_prepared_media() -> Test {
    for deletion in [false, true] {
        let mut f = Fixture::new(if deletion { "deleted" } else { "reviewed" })?;
        let preview =
            preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
        let prepared = approve_original_media_export(
            &f.deployment,
            &f.request,
            preview.approval(),
            &f.authority,
            &f.cx,
        )?;
        if deletion {
            let plan = plan_deletion(&f.deployment, f.request.import_identity, &f.cx)?;
            assert!(
                plan.blockers.is_empty(),
                "unexpected deletion blockers: {:?}",
                plan.blockers
            );
            let approval = plan.approval_digest(ACTOR)?;
            commit_deletion(&mut f.deployment, plan.digest()?, approval, ACTOR, &f.cx)?;
        } else {
            let request = ReviewRequest {
                event_id: f.request.event.event_id.clone(),
                expected_revision: f.request.event.expected_revision,
                disposition: ReviewDisposition::Resolve,
                reason: "Operator resolved this exact candidate".into(),
            };
            let review = preview_review(&f.deployment, &request, &f.authority, &f.cx)?;
            commit_review(
                &mut f.deployment,
                &request,
                review.approval(),
                &f.authority,
                &f.cx,
            )?;
        }
        let root = f.deployment.root().to_path_buf();
        drop(f.deployment);
        let reopened = ReferenceDeployment::reopen(&root, SITE, &f.cx)?;
        assert!(matches!(
            revalidate_original_media_export(&reopened, &prepared, &f.authority, &f.cx),
            Err(OriginalMediaExportError::AuthorityChanged)
        ));
        assert!(preview_original_media_export(&reopened, &f.request, &f.authority, &f.cx).is_err());
    }
    Ok(())
}

#[test]
fn source_corruption_and_cancellation_never_return_a_successful_package() -> Test {
    for corrupt in [false, true] {
        let f = Fixture::new(if corrupt { "corrupt" } else { "cancel" })?;
        let before = f.snapshot();
        if corrupt {
            let retained = RetainedFileImport::open(
                &f.deployment,
                f.request.import_identity,
                Default::default(),
                &f.cx,
            )?;
            // Corruption after the event was published cannot be hidden by its valid metadata.
            let last = retained
                .manifest()
                .ordered_chunks
                .last()
                .ok_or("no source chunks")?;
            fs::remove_file(f.deployment.publisher().spool().object_path(*last))?;
        } else {
            f.cx.set_cancel_at_checkpoint("original_media_export:source_chunk");
        }
        assert!(
            preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx).is_err()
        );
        assert_eq!(*f.deployment.current_anchor(), before.0);
        assert_eq!(f.deployment.effects().last_root(), before.1);
        if !corrupt {
            assert_eq!(f.deployment.publisher().spool().object_count(), before.2);
        }
    }
    Ok(())
}

#[test]
fn generic_mp4_is_not_disclosed_as_video_only_without_native_source_attestation() -> Test {
    let source = include_bytes!("fixtures/hevc_ingest/watch_96x48_moving.mp4").to_vec();
    let f = Fixture::from_source("generic-mp4", source, "mp4", [96, 48])?;
    assert!(matches!(
        preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx),
        Err(OriginalMediaExportError::UnsupportedProfile)
    ));
    Ok(())
}

#[test]
fn corroborated_event_discloses_exactly_one_selected_camera_and_binds_switching_to_new_approval()
-> Test {
    let mut f = Fixture::new("two-cameras")?;
    let mut other_source = f.source.clone();
    other_source.extend(encode_jpeg(
        48,
        32,
        &[40; 48 * 32],
        &JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        },
    )?);
    assert_ne!(f.source, other_source);
    let input = f.directory.0.join("second-camera.mjpeg");
    fs::write(&input, &other_source)?;
    let imported = FileIngestAdapter::ingest(
        FileIngestRequest::new(
            &input,
            SensorId::parse("sensor:original-media-second")?,
            StreamId::parse("stream:original-media-second")?,
        )
        .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
        .with_receive_time(TimestampNs(1_000_000_000_000)),
        &f.cx,
        &mut f.deployment,
    )?;
    fs::remove_file(input)?;
    let second = RetainedFileImport::open(
        &f.deployment,
        imported.import_identity,
        Default::default(),
        &f.cx,
    )?;
    let plan = CorroborationPlan {
        cameras: [
            CorroborationCamera {
                name: "east".into(),
                import_identity: f.request.import_identity,
                homography: GroundHomography {
                    matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
                },
            },
            CorroborationCamera {
                name: "west".into(),
                import_identity: imported.import_identity,
                homography: GroundHomography {
                    matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
                },
            },
        ],
        interpretation: ComponentInterpretation::Grayscale,
        zones: vec![GroundZone {
            zone_id: "porch".into(),
            x: 0.0,
            y: 0.0,
            width: 48.0,
            height: 32.0,
        }],
        gates: CorroborationGates {
            time_gate_ns: 200_000_000,
            distance_gate: 4.0,
        },
        detector: WatchDetectorConfig {
            learning_rate_num: 0,
            ..WatchDetectorConfig::default()
        },
        tracker: WatchTrackerConfig::default(),
    };
    let mut report = LongCorroborationReport::analyze(
        &f.deployment,
        &plan,
        CorroborationOptions::default(),
        &LongDwellLimits::default(),
        &CorroborationDependencies::default(),
        &f.cx,
    )?;
    let candidate = report
        .candidates()
        .first()
        .ok_or("native two-camera event missing")?;
    f.request.event.event_id = candidate.event().event_id.clone();
    f.request.event.expected_revision = candidate.event().revision_digest();
    let approval = candidate.proposal_digest();
    assert_eq!(
        report.publish(&mut f.deployment, &BTreeSet::from([approval]), &f.cx)?,
        1
    );
    let before = f.snapshot();
    let left = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
    assert_eq!(left.media_bytes(), f.source);
    for field in [
        "\"event_profile\":\"long_corroboration\"",
        "\"event_source_count\":2",
        "\"included_source_count\":1",
        "\"excluded_event_source_count\":1",
        "\"other_camera_media_included\":false",
    ] {
        assert!(left.record_json().contains(field), "missing {field}");
    }
    f.request.import_identity = imported.import_identity;
    f.request.expected_import_root = second.import_root();
    let right = preview_original_media_export(&f.deployment, &f.request, &f.authority, &f.cx)?;
    assert_eq!(right.media_bytes(), other_source);
    assert_ne!(left.approval(), right.approval());
    assert!(matches!(
        approve_original_media_export(
            &f.deployment,
            &f.request,
            left.approval(),
            &f.authority,
            &f.cx
        ),
        Err(OriginalMediaExportError::StaleApproval)
    ));
    let prepared = approve_original_media_export(
        &f.deployment,
        &f.request,
        right.approval(),
        &f.authority,
        &f.cx,
    )?;
    revalidate_original_media_export(&f.deployment, &prepared, &f.authority, &f.cx)?;
    let verified = verify_original_media_export(
        right.manifest_bytes(),
        right.record_bytes(),
        right.media_bytes(),
        right.root(),
    )?;
    assert_eq!(verified.request(), &f.request);
    assert_eq!(f.snapshot(), before);
    Ok(())
}
