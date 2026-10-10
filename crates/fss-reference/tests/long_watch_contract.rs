#![forbid(unsafe_code)]
//! Native streaming perception, discontinuities, cumulative reads and publication preconditions.
//! Synthetic recordings exercise executable behavior; they do not qualify detection accuracy.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ContentDigest, EventKind, EventState, LedgerAnchor, OperationId, SensorId,
    StreamId, TimestampNs,
};
use fss_reference::ingest::long_dwell::LongDwellReport;
use fss_reference::ingest::long_watch::{LongWatchLimits, LongWatchReport};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchError, WatchOptions, WatchPlan, WatchStatus, WatchTrackerConfig,
    WatchZone,
};
use fss_reference::ingest::zone_dwell::DwellPolicy;
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest, RetainedFileImport,
    RetainedReadLimits,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:long-watch-contract";
const PRINCIPAL: &str = "principal:long-watch-contract";
const SENSOR: &str = "sensor:long-watch-contract";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-long-watch-{label}-{}-{attempt}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("temporary directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:long-watch-contract".into(),
        operation_id: OperationId::parse("operation:long-watch-contract")?,
        principal: PRINCIPAL.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(128 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

fn scene(
    frames: usize,
    appearance: usize,
    miss: Option<usize>,
    corrupt: bool,
    gap: bool,
) -> Test<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let background = vec![40_u8; 48 * 32];
    let mut square = background.clone();
    for y in 8..24 {
        for x in 8..24 {
            square[y * 48 + x] = 220;
        }
    }
    let quiet = encode_jpeg(48, 32, &background, &config)?;
    let target = encode_jpeg(48, 32, &square, &config)?;
    let mut unsupported = quiet.clone();
    let sof = unsupported
        .windows(2)
        .position(|w| w == [0xff, 0xc0])
        .ok_or("SOF0 missing")?;
    unsupported[sof + 1] = 0xc2;
    let mut bytes = Vec::new();
    for index in 0..frames {
        if gap && index == 20 {
            bytes.extend_from_slice(b"omitted-source-bytes");
        }
        if corrupt && index == 20 {
            bytes.extend_from_slice(&unsupported);
        } else if index >= appearance
            && miss != Some(index)
            && !(corrupt && (21..24).contains(&index))
        {
            bytes.extend_from_slice(&target);
        } else {
            bytes.extend_from_slice(&quiet);
        }
    }
    Ok(bytes)
}

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    plan: WatchPlan,
    input_bytes: u64,
    _directory: Directory,
}
impl Fixture {
    fn new(label: &str, bytes: &[u8], extension: &str) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let input = directory.0.join(format!("source.{extension}"));
        fs::write(&input, bytes)?;
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = 1024;
        limits.chunk_bytes = 4096;
        let request = FileIngestRequest::new(
            &input,
            SensorId::parse(SENSOR)?,
            StreamId::parse("stream:long-watch")?,
        )
        .with_limits(limits)
        .with_receive_time(TimestampNs(1_000_000_000_000))
        .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?);
        let receipt = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
        fs::remove_file(input)?;
        let plan = WatchPlan {
            import_identity: receipt.import_identity,
            interpretation: if extension == "mjpeg" {
                ComponentInterpretation::Grayscale
            } else {
                ComponentInterpretation::YCbCr
            },
            first_segment: 0,
            segment_count: receipt.capsule_count,
            zones: vec![WatchZone {
                zone_id: "porch".into(),
                x: 0,
                y: 0,
                width: 32,
                height: 32,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        };
        Ok(Self {
            deployment,
            cx,
            plan,
            input_bytes: bytes.len() as u64,
            _directory: directory,
        })
    }
    fn analyze(&self, tolerant: bool) -> Test<LongWatchReport> {
        Ok(LongWatchReport::analyze(
            &self.deployment,
            &self.plan,
            WatchOptions {
                tolerate_decode_refusals: tolerant,
            },
            &LongWatchLimits::default(),
            &self.cx,
        )?)
    }
    fn snapshot(&self) -> (LedgerAnchor, ContentDigest, usize) {
        (
            self.deployment.current_anchor().clone(),
            self.deployment.effects().last_root(),
            self.deployment.publisher().spool().digests().count(),
        )
    }
    fn mask(&mut self, x: u32) -> Test {
        // Outside the image zone: the entry remains visible, but privacy authority has changed.
        let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [48, 32], &[[x, 0, 4, 4]])?;
        let approval = preview_mask(&self.deployment, &policy)?.approval;
        declare_mask(&mut self.deployment, &policy, approval, &self.cx)?;
        Ok(())
    }
}

#[test]
fn a_late_entry_remains_one_candidate_across_a_miss_and_the_old_window_boundary() -> Test {
    let f = Fixture::new("late", &scene(300, 180, Some(250), false, false)?, "mjpeg")?;
    let before = f.snapshot();
    let report = f.analyze(false)?;
    assert_eq!(f.snapshot(), before);
    assert_eq!(report.frames_decoded(), 300);
    assert_eq!(report.source_chunk_bytes_read(), f.input_bytes);
    assert_eq!(report.candidates().len(), 1);
    let candidate = &report.candidates()[0];
    assert_eq!(candidate.entry().position(), 182);
    assert_eq!(candidate.entry().tracker_epoch(), 0);
    assert_eq!(candidate.event().kind, EventKind::Unclassified);
    assert_eq!(candidate.event().state, EventState::Indeterminate);
    assert!(candidate.event().decision_path.abstained);
    assert!(candidate.event().evidence.iter().all(|item| !item.supports));
    assert_eq!(
        report.analysis_digest(),
        f.analyze(false)?.analysis_digest()
    );
    Ok(())
}

#[test]
fn a_tolerated_decoder_refusal_resets_tracking_and_allows_a_new_epoch_entry() -> Test {
    let f = Fixture::new("decoder-gap", &scene(40, 3, None, true, false)?, "mjpeg")?;
    let before = f.snapshot();
    assert!(f.analyze(false).is_err());
    let report = f.analyze(true)?;
    assert_eq!(report.frames_decoded(), 39);
    assert_eq!(report.candidates().len(), 2);
    let entries: Vec<_> = report
        .candidates()
        .iter()
        .map(|candidate| {
            (
                candidate.entry().position(),
                candidate.entry().tracker_epoch(),
            )
        })
        .collect();
    assert_eq!(entries, [(5, 0), (26, 1)]);
    let json = report.to_json(0, None)?;
    assert!(json.contains("\"first_segment\":20,\"last_segment\":20"));
    assert!(json.contains("\"tracking_restarts\":1"));
    assert!(json.contains("\"absence_certifiable\":false"));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn a_later_source_gap_preserves_earlier_entries_and_excludes_unreliable_later_times() -> Test {
    let f = Fixture::new("source-gap", &scene(40, 3, None, false, true)?, "mjpeg")?;
    let before = f.snapshot();
    assert!(f.analyze(false).is_err());
    let report = f.analyze(true)?;
    assert_eq!(report.frames_decoded(), 40);
    assert_eq!(report.candidates().len(), 1);
    assert_eq!(report.candidates()[0].entry().position(), 5);
    assert!(
        report
            .to_json(0, None)?
            .contains("\"unreliable_time_frames\":20")
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn native_inter_coded_read_ceilings_are_cumulative_and_never_renewed_by_tolerance() -> Test {
    let avc = include_bytes!("fixtures/long_dwell_h264/square_300.mp4").as_slice();
    let hevc = include_bytes!("fixtures/hevc_ingest/watch_96x48_moving.mp4").as_slice();
    for (name, bytes) in [("avc", avc), ("hevc", hevc)] {
        let f = Fixture::new(name, bytes, "mp4")?;
        let before = f.snapshot();
        for tolerant in [false, true] {
            let limits = LongWatchLimits {
                maximum_source_chunk_bytes: 1,
                ..LongWatchLimits::default()
            };
            assert!(matches!(
                LongWatchReport::analyze(
                    &f.deployment,
                    &f.plan,
                    WatchOptions {
                        tolerate_decode_refusals: tolerant
                    },
                    &limits,
                    &f.cx
                ),
                Err(WatchError::Limit)
            ));
            assert_eq!(f.snapshot(), before);
        }
        if name == "hevc" {
            let report = f.analyze(false)?;
            let used = report.source_chunk_bytes_read();
            assert!(
                used > f.input_bytes,
                "out-of-band parameter reads must be counted"
            );
            let limits = LongWatchLimits {
                maximum_source_chunk_bytes: used - 1,
                ..LongWatchLimits::default()
            };
            assert!(matches!(
                LongWatchReport::analyze(
                    &f.deployment,
                    &f.plan,
                    WatchOptions::default(),
                    &limits,
                    &f.cx
                ),
                Err(WatchError::Limit)
            ));
            assert_eq!(f.snapshot(), before);
        }
    }
    Ok(())
}

#[test]
fn privacy_a_to_b_to_a_invalidates_old_reports_and_new_entry_approvals() -> Test {
    let mut f = Fixture::new(
        "mask-generation",
        &scene(40, 3, None, false, false)?,
        "mjpeg",
    )?;
    f.mask(40)?;
    let mut report = f.analyze(false)?;
    let approvals = BTreeSet::from([report.candidates()[0].proposal_digest()]);
    let mut dwell = LongDwellReport::analyze(
        &f.deployment,
        &f.plan,
        dwell_rule(),
        WatchOptions::default(),
        &LongWatchLimits::default(),
        &f.cx,
    )?;
    let dwell_approvals = BTreeSet::from([dwell.candidates()[0].proposal_digest()]);
    f.mask(44)?;
    f.mask(40)?;
    let before = f.snapshot();
    assert!(matches!(
        report.publish(&mut f.deployment, &approvals, &f.cx),
        Err(WatchError::InvalidPlan(_))
    ));
    assert!(matches!(
        dwell.publish(&mut f.deployment, &dwell_approvals, &f.cx),
        Err(WatchError::InvalidPlan(_))
    ));
    let mut fresh = f.analyze(false)?;
    assert_ne!(fresh.analysis_digest(), report.analysis_digest());
    assert!(matches!(
        fresh.publish(&mut f.deployment, &approvals, &f.cx),
        Err(WatchError::StaleApproval(_))
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

fn dwell_rule() -> DwellPolicy {
    DwellPolicy {
        minimum_duration_ns: 1_000_000_000,
        maximum_sample_gap_ns: 100_000_000,
        minimum_observations: 3,
    }
}

#[test]
fn chunk_and_background_capsule_damage_refuse_publication_even_after_success() -> Test {
    for capsule in [false, true] {
        for already_published in [false, true] {
            let mut f = Fixture::new("custody", &scene(40, 3, None, false, false)?, "mjpeg")?;
            let mut report = f.analyze(false)?;
            let approvals = BTreeSet::from([report.candidates()[0].proposal_digest()]);
            if already_published {
                assert_eq!(report.publish(&mut f.deployment, &approvals, &f.cx)?, 1);
            }
            let source = RetainedFileImport::open(
                &f.deployment,
                f.plan.import_identity,
                RetainedReadLimits::default(),
                &f.cx,
            )?;
            let digest = if capsule {
                let object = format!(
                    "object:capsule:{}",
                    source.manifest().segment_spans[1].capsule_id
                );
                f.deployment
                    .ledger()
                    .batches()
                    .iter()
                    .flat_map(|batch| &batch.deltas)
                    .find(|delta| delta.object_id.as_str() == object)
                    .ok_or("source capsule authority")?
                    .payload_digest
            } else {
                source.manifest().ordered_chunks[0]
            };
            let path = f.deployment.publisher().spool().object_path(digest);
            let mut bytes = fs::read(&path)?;
            *bytes.last_mut().ok_or("empty custody object")? ^= 0x80;
            fs::write(path, bytes)?;
            let before = f.snapshot();
            assert!(
                report
                    .publish(&mut f.deployment, &approvals, &f.cx)
                    .is_err()
            );
            assert_eq!(f.snapshot(), before);
        }
    }
    Ok(())
}

#[test]
fn cancellation_after_entry_provenance_recovers_the_same_single_event() -> Test {
    let mut f = Fixture::new("cancel", &scene(40, 3, None, false, false)?, "mjpeg")?;
    let mut report = f.analyze(false)?;
    let approvals = BTreeSet::from([report.candidates()[0].proposal_digest()]);
    let event_id = report.candidates()[0].event().event_id.clone();
    f.cx.set_cancel_at_checkpoint("long_watch:commit");
    assert!(
        report
            .publish(&mut f.deployment, &approvals, &f.cx)
            .is_err()
    );
    assert!(f.cx.is_drain_completed());
    assert!(f.deployment.current_event_authority(&event_id).is_err());
    let root = f.deployment.root().to_path_buf();
    drop(f.deployment);
    let cx = context(&root)?;
    let mut reopened = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let mut retry = LongWatchReport::analyze(
        &reopened,
        &f.plan,
        WatchOptions::default(),
        &LongWatchLimits::default(),
        &cx,
    )?;
    assert_eq!(retry.analysis_digest(), report.analysis_digest());
    assert_eq!(retry.publish(&mut reopened, &approvals, &cx)?, 1);
    assert_eq!(retry.candidates()[0].status(), WatchStatus::Published);
    let committed = reopened.current_anchor().clone();
    assert_eq!(retry.publish(&mut reopened, &approvals, &cx)?, 0);
    assert_eq!(*reopened.current_anchor(), committed);
    assert_eq!(reopened.effects().operations().count(), 0);
    Ok(())
}

const DETECTOR_PACKAGE: &[u8] = include_bytes!("../../../models/yolox-nano/yolox_nano.fmpk");
const DETECTOR_PACKAGE_DIGEST: &str =
    "sha256:5b6568750faa375de3742e5eb310fbd4e22ff26e1ba727f193b79ab984a68c74";

fn trained_package(
    f: &Fixture,
    scalar: &fss_reference::ScalarExecCx,
) -> Test<fss_reference::ingest::rgb_package::RgbDetectorPackage> {
    Ok(
        fss_reference::ingest::rgb_package::RgbDetectorPackage::load(
            DETECTOR_PACKAGE,
            ContentDigest::parse(DETECTOR_PACKAGE_DIGEST)?,
            1 << 36,
            &f.cx,
            scalar,
        )?,
    )
}

#[test]
fn long_detector_runs_after_old_window_boundary_and_retains_complete_model_custody() -> Test {
    use fss_reference::ingest::detector_cascade::{CascadeConfig, EvidenceOutcome};
    use fss_reference::ingest::long_watch::LongWatchDetector;
    use fss_reference::ingest::package_detect::PackageDetectLimits;
    let mut f = Fixture::new(
        "trained-late",
        &scene(170, 150, None, false, false)?,
        "mjpeg",
    )?;
    let scalar = fss_reference::ScalarExecCx::new();
    let package = trained_package(&f, &scalar)?;
    let detector = LongWatchDetector::new(
        &package,
        DETECTOR_PACKAGE,
        CascadeConfig {
            frames_per_track: 3,
            max_inferences: 1,
            ..CascadeConfig::default()
        },
        PackageDetectLimits::default(),
        &scalar,
    )?;
    let before = f.snapshot();
    let mut report = LongWatchReport::analyze_with_detector(
        &f.deployment,
        &f.plan,
        WatchOptions::default(),
        &LongWatchLimits::default(),
        &detector,
        false,
        &f.cx,
    )?;
    assert_eq!(f.snapshot(), before, "analysis must remain read-only");
    assert_eq!(report.frames_decoded(), 170);
    let outcome = report.detector_cascade().ok_or("trained outcome")?;
    assert_eq!(outcome.inferred_segments(), [152]);
    assert_eq!(outcome.budget_skipped_segments(), [153, 154]);
    assert_eq!(outcome.cascade_skipped.len(), 167);
    let candidate = &report.candidates()[0];
    assert_eq!(candidate.class_evidence().len(), 3);
    assert!(matches!(
        candidate.class_evidence()[1].outcome,
        EvidenceOutcome::BudgetExhausted
    ));
    assert!(matches!(
        candidate.class_evidence()[2].outcome,
        EvidenceOutcome::BudgetExhausted
    ));
    assert_eq!(candidate.event().kind, EventKind::Unclassified);
    assert_eq!(candidate.event().state, EventState::Indeterminate);
    assert!(candidate.event().decision_path.abstained);
    assert!(candidate.event().model_receipts.is_empty());
    assert_eq!(
        candidate
            .event()
            .evidence
            .iter()
            .map(|e| &e.failure_domain)
            .collect::<BTreeSet<_>>()
            .len(),
        1
    );
    assert!(report.source_chunk_bytes_read() > f.input_bytes);
    let approvals = BTreeSet::from([candidate.proposal_digest()]);
    let class_digests = candidate
        .class_evidence()
        .iter()
        .map(|e| e.digest)
        .collect::<Vec<_>>();
    assert_eq!(report.publish(&mut f.deployment, &approvals, &f.cx)?, 1);
    assert_eq!(report.publish(&mut f.deployment, &approvals, &f.cx)?, 0);
    assert_eq!(
        f.deployment
            .publisher()
            .spool()
            .read(ContentDigest::parse(DETECTOR_PACKAGE_DIGEST)?)?,
        DETECTOR_PACKAGE
    );
    for digest in class_digests {
        assert_eq!(
            ContentDigest::sha256(&f.deployment.publisher().spool().read(digest)?),
            digest
        );
    }
    assert!(report.to_json(0, None)?.contains("\"model_invoked\":true"));
    Ok(())
}

#[test]
fn long_detector_source_allowance_does_not_restart_after_the_cheap_scan() -> Test {
    use fss_reference::ingest::detector_cascade::CascadeConfig;
    use fss_reference::ingest::long_watch::LongWatchDetector;
    use fss_reference::ingest::package_detect::PackageDetectLimits;
    let f = Fixture::new(
        "trained-budget",
        &scene(40, 3, None, false, false)?,
        "mjpeg",
    )?;
    let scalar = fss_reference::ScalarExecCx::new();
    let package = trained_package(&f, &scalar)?;
    let detector = LongWatchDetector::new(
        &package,
        DETECTOR_PACKAGE,
        CascadeConfig::default(),
        PackageDetectLimits::default(),
        &scalar,
    )?;
    let before = f.snapshot();
    let limits = LongWatchLimits {
        maximum_source_chunk_bytes: f.input_bytes,
        ..LongWatchLimits::default()
    };
    assert!(
        LongWatchReport::analyze(
            &f.deployment,
            &f.plan,
            WatchOptions::default(),
            &limits,
            &f.cx
        )
        .is_ok()
    );
    assert!(matches!(
        LongWatchReport::analyze_with_detector(
            &f.deployment,
            &f.plan,
            WatchOptions::default(),
            &limits,
            &detector,
            false,
            &f.cx
        ),
        Err(WatchError::Limit)
    ));
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn long_detector_recovery_preserves_epochs_and_one_inference_allowance() -> Test {
    use fss_reference::ingest::detector_cascade::{CascadeConfig, EvidenceOutcome};
    use fss_reference::ingest::long_watch::LongWatchDetector;
    use fss_reference::ingest::package_detect::PackageDetectLimits;
    let f = Fixture::new(
        "trained-recovery",
        &scene(40, 3, None, true, false)?,
        "mjpeg",
    )?;
    let scalar = fss_reference::ScalarExecCx::new();
    let package = trained_package(&f, &scalar)?;
    let detector = LongWatchDetector::new(
        &package,
        DETECTOR_PACKAGE,
        CascadeConfig {
            frames_per_track: 3,
            max_inferences: 1,
            ..CascadeConfig::default()
        },
        PackageDetectLimits::default(),
        &scalar,
    )?;
    let report = LongWatchReport::analyze_with_detector(
        &f.deployment,
        &f.plan,
        WatchOptions {
            tolerate_decode_refusals: true,
        },
        &LongWatchLimits::default(),
        &detector,
        false,
        &f.cx,
    )?;
    assert_eq!(report.candidates().len(), 2);
    assert_eq!(
        report
            .detector_cascade()
            .ok_or("cascade")?
            .inferred_segments(),
        [5]
    );
    assert!(
        report.candidates()[0]
            .class_evidence()
            .iter()
            .all(|e| e.segment < 20)
    );
    assert!(
        report.candidates()[1]
            .class_evidence()
            .iter()
            .all(|e| e.segment >= 26 && matches!(e.outcome, EvidenceOutcome::BudgetExhausted))
    );
    assert_ne!(
        report.candidates()[0].entry().tracker_epoch(),
        report.candidates()[1].entry().tracker_epoch()
    );
    Ok(())
}

#[test]
fn long_detector_cancellation_during_selected_pass_leaves_no_publication() -> Test {
    use fss_reference::ingest::detector_cascade::CascadeConfig;
    use fss_reference::ingest::long_watch::LongWatchDetector;
    use fss_reference::ingest::package_detect::PackageDetectLimits;
    let f = Fixture::new(
        "trained-cancel",
        &scene(40, 3, None, false, false)?,
        "mjpeg",
    )?;
    let scalar = fss_reference::ScalarExecCx::new();
    let package = trained_package(&f, &scalar)?;
    let detector = LongWatchDetector::new(
        &package,
        DETECTOR_PACKAGE,
        CascadeConfig::default(),
        PackageDetectLimits::default(),
        &scalar,
    )?;
    let before = f.snapshot();
    f.cx.set_cancel_at_checkpoint("long_watch_detector:frame");
    assert!(
        LongWatchReport::analyze_with_detector(
            &f.deployment,
            &f.plan,
            WatchOptions::default(),
            &LongWatchLimits::default(),
            &detector,
            false,
            &f.cx
        )
        .is_err()
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn long_detector_refusals_are_explicit_and_changed_privacy_invalidates_publication() -> Test {
    use fss_reference::ingest::detector_cascade::{CascadeConfig, EvidenceOutcome};
    use fss_reference::ingest::long_watch::LongWatchDetector;
    use fss_reference::ingest::package_detect::PackageDetectLimits;
    let mut f = Fixture::new(
        "trained-refusal",
        &scene(40, 3, None, false, false)?,
        "mjpeg",
    )?;
    let scalar = fss_reference::ScalarExecCx::new();
    let package = trained_package(&f, &scalar)?;
    let mut limits = PackageDetectLimits::default();
    // The native model may complete, but a head budget of zero must still record the pipeline
    // attempt and its explicit refusal instead of falsely claiming no inference was invoked.
    limits.detection_work_units = 0;
    let detector = LongWatchDetector::new(
        &package,
        DETECTOR_PACKAGE,
        CascadeConfig {
            frames_per_track: 1,
            max_inferences: 1,
            ..CascadeConfig::default()
        },
        limits,
        &scalar,
    )?;
    let mut report = LongWatchReport::analyze_with_detector(
        &f.deployment,
        &f.plan,
        WatchOptions::default(),
        &LongWatchLimits::default(),
        &detector,
        false,
        &f.cx,
    )?;
    assert!(matches!(
        report.candidates()[0].class_evidence()[0].outcome,
        EvidenceOutcome::Refused(_)
    ));
    assert!(
        report
            .detector_cascade()
            .ok_or("cascade")?
            .inferred_segments()
            .is_empty()
    );
    assert_eq!(report.inference_pipeline_attempts(), 1);
    assert_eq!(report.inferences_completed(), 0);
    let json = report.to_json(0, None)?;
    assert!(json.contains("\"model_invoked\":true"));
    assert!(json.contains("\"inference_pipeline_attempts\":1"));
    assert!(json.contains("\"inferences_completed\":0"));
    let approvals = BTreeSet::from([report.candidates()[0].proposal_digest()]);
    f.mask(40)?;
    let before = f.snapshot();
    assert!(
        report
            .publish(&mut f.deployment, &approvals, &f.cx)
            .is_err()
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn long_detector_scalar_cancellation_is_not_publishable_refused_evidence() -> Test {
    use fss_reference::ingest::detector_cascade::{CascadeConfig, CascadeError};
    use fss_reference::ingest::long_watch::LongWatchDetector;
    use fss_reference::ingest::package_detect::PackageDetectLimits;
    let f = Fixture::new(
        "trained-scalar-cancel",
        &scene(40, 3, None, false, false)?,
        "mjpeg",
    )?;
    let scalar = fss_reference::ScalarExecCx::new();
    let package = trained_package(&f, &scalar)?;
    let detector = LongWatchDetector::new(
        &package,
        DETECTOR_PACKAGE,
        CascadeConfig::default(),
        PackageDetectLimits::default(),
        &scalar,
    )?;
    let before = f.snapshot();
    scalar.request_cancellation();
    assert!(matches!(
        LongWatchReport::analyze_with_detector(
            &f.deployment,
            &f.plan,
            WatchOptions::default(),
            &LongWatchLimits::default(),
            &detector,
            false,
            &f.cx
        ),
        Err(WatchError::Cascade(CascadeError::Cancelled))
    ));
    assert!(scalar.is_drain_completed());
    assert_eq!(f.snapshot(), before);
    Ok(())
}

#[test]
fn long_detector_rejects_package_substitution_before_source_analysis() -> Test {
    use fss_reference::ingest::detector_cascade::CascadeConfig;
    use fss_reference::ingest::long_watch::LongWatchDetector;
    use fss_reference::ingest::package_detect::PackageDetectLimits;
    let f = Fixture::new(
        "trained-package",
        &scene(3, 3, None, false, false)?,
        "mjpeg",
    )?;
    let scalar = fss_reference::ScalarExecCx::new();
    let package = trained_package(&f, &scalar)?;
    let before = f.snapshot();
    assert!(
        LongWatchDetector::new(
            &package,
            b"substituted",
            CascadeConfig::default(),
            PackageDetectLimits::default(),
            &scalar
        )
        .is_err()
    );
    assert_eq!(f.snapshot(), before);
    Ok(())
}

fn assert_same_jpeg_limits(
    left: fss_codec_mjpeg::DecodeLimits,
    right: fss_codec_mjpeg::DecodeLimits,
) {
    assert_eq!(
        (
            left.maximum_bytes,
            left.maximum_dimension,
            left.maximum_pixels,
            left.maximum_markers
        ),
        (
            right.maximum_bytes,
            right.maximum_dimension,
            right.maximum_pixels,
            right.maximum_markers
        )
    );
}

fn assert_same_decode_limits(
    left: &fss_reference::ingest::recorded_watch::WatchLimits,
    right: &fss_reference::ingest::recorded_watch::WatchLimits,
) {
    assert_eq!(left.read_limits, right.read_limits);
    assert_same_jpeg_limits(left.jpeg_limits, right.jpeg_limits);
    assert_eq!(left.jpeg_work_units, right.jpeg_work_units);
    assert_eq!(left.h264_limits, right.h264_limits);
    assert_eq!(left.h265_limits, right.h265_limits);
}

#[test]
fn long_detector_recipe_round_trip_preserves_every_admitted_ceiling() -> Test {
    use fss_codec_mjpeg::color::RgbDecodeLimits;
    use fss_reference::ExecBudget;
    use fss_reference::ingest::detector_cascade::CascadeConfig;
    use fss_reference::ingest::long_watch::detector::LongWatchDetectorRecipe;
    use fss_reference::ingest::package_detect::PackageDetectLimits;
    use fss_reference::ingest::recorded_watch::WatchLimits;
    use fss_reference::ingest::rgb_inference::RgbRunLimits;
    let f = Fixture::new("trained-recipe", &scene(3, 3, None, false, false)?, "mjpeg")?;
    let scalar = fss_reference::ScalarExecCx::new();
    let package = trained_package(&f, &scalar)?;
    let watch = LongWatchLimits {
        decode: WatchLimits {
            read_limits: RetainedReadLimits {
                max_source_bytes: 100_000,
                max_chunk_bytes: 50_000,
                max_segment_bytes: 49_000,
            },
            jpeg_limits: fss_codec_mjpeg::DecodeLimits {
                maximum_bytes: 48_000,
                maximum_dimension: 1024,
                maximum_pixels: 262_144,
                maximum_markers: 100,
            },
            jpeg_work_units: 1_000_003,
            h264_limits: fss_codec_h264::DecoderLimits {
                max_width: 1024,
                max_height: 576,
                max_macroblocks: 2048,
                max_pictures: 65,
                max_nal_bytes: 32_768,
                max_slices_per_picture: 64,
                max_reference_frames: 4,
            },
            h265_limits: fss_codec_h265::DecoderLimits {
                max_width: 960,
                max_height: 544,
                max_luma_samples: 522_240,
                max_pictures: 66,
                max_nal_bytes: 65_536,
                max_slices_per_picture: 32,
                max_dpb_pictures: 6,
            },
        },
        maximum_source_chunk_bytes: 2_000_003,
        maximum_pixel_samples: 1_000_007,
        maximum_assignment_work: 2_000_011,
        maximum_trace_bytes: 1_000_009,
    };
    let original = PackageDetectLimits {
        read: RetainedReadLimits {
            max_source_bytes: 300_000,
            max_chunk_bytes: 45_000,
            max_segment_bytes: 40_000,
        },
        jpeg: RgbDecodeLimits {
            frame: fss_codec_mjpeg::DecodeLimits {
                maximum_bytes: 40_000,
                maximum_dimension: 768,
                maximum_pixels: 524_288,
                maximum_markers: 128,
            },
            maximum_output_bytes: 1_572_864,
        },
        jpeg_work_units: 2_000_033,
        h264: fss_codec_h264::DecoderLimits {
            max_width: 720,
            max_height: 480,
            max_macroblocks: 1350,
            max_pictures: 70,
            max_nal_bytes: 16_384,
            max_slices_per_picture: 24,
            max_reference_frames: 2,
        },
        h265: fss_codec_h265::DecoderLimits {
            max_width: 800,
            max_height: 450,
            max_luma_samples: 360_000,
            max_pictures: 90,
            max_nal_bytes: 20_000,
            max_slices_per_picture: 20,
            max_dpb_pictures: 8,
        },
        run: RgbRunLimits {
            decode: RgbDecodeLimits {
                frame: fss_codec_mjpeg::DecodeLimits {
                    maximum_bytes: 30_000,
                    maximum_dimension: 640,
                    maximum_pixels: 200_000,
                    maximum_markers: 32,
                },
                maximum_output_bytes: 600_000,
            },
            preprocess: ExecBudget::new(100_003, 900_001),
            execution: ExecBudget::new(3_000_007, 4_000_009),
            maximum_output_bytes: 550_001,
        },
        detection_work_units: 5_000_009,
        detection_scratch_bytes: 6_000_011,
    };
    let config = CascadeConfig {
        frames_per_track: 4,
        max_inferences: 3,
        minimum_association_iou_ppm: 221_337,
        minimum_score_ppm: Some(654_321),
    };
    let recipe = LongWatchDetectorRecipe::new(&package, config, original, &watch)?;
    let restored =
        LongWatchDetectorRecipe::from_retained_bytes(&recipe.to_bytes(), recipe.digest())?;
    restored.verify_package(&package)?;
    assert_eq!(restored.config(), config);
    assert_eq!(restored.package_digest(), package.archive_digest());
    assert_eq!(restored.manifest_digest(), package.manifest_digest());
    assert_eq!(restored.model_digest(), package.model().digest());
    assert_eq!(restored.backend(), package.model().backend());
    assert_eq!(
        restored.contract_digest(),
        package.contract_with_threshold(654_321)?.digest()
    );
    let limits = restored.watch_limits();
    assert_same_decode_limits(&limits.decode, &watch.decode);
    assert_eq!(
        (
            limits.maximum_source_chunk_bytes,
            limits.maximum_pixel_samples,
            limits.maximum_assignment_work,
            limits.maximum_trace_bytes
        ),
        (
            watch.maximum_source_chunk_bytes,
            watch.maximum_pixel_samples,
            watch.maximum_assignment_work,
            watch.maximum_trace_bytes
        )
    );
    let limits = restored.package_limits();
    assert_eq!(limits.read, original.read);
    assert_same_jpeg_limits(limits.jpeg.frame, original.jpeg.frame);
    assert_eq!(
        limits.jpeg.maximum_output_bytes,
        original.jpeg.maximum_output_bytes
    );
    assert_eq!(limits.jpeg_work_units, original.jpeg_work_units);
    assert_eq!(limits.h264, original.h264);
    assert_eq!(limits.h265, original.h265);
    assert_same_jpeg_limits(limits.run.decode.frame, original.run.decode.frame);
    assert_eq!(
        limits.run.decode.maximum_output_bytes,
        original.run.decode.maximum_output_bytes
    );
    assert_eq!(limits.run.preprocess, original.run.preprocess);
    assert_eq!(limits.run.execution, original.run.execution);
    assert_eq!(
        limits.run.maximum_output_bytes,
        original.run.maximum_output_bytes
    );
    assert_eq!(limits.detection_work_units, original.detection_work_units);
    assert_eq!(
        limits.detection_scratch_bytes,
        original.detection_scratch_bytes
    );
    restored.validate_within(&LongWatchLimits::default(), &PackageDetectLimits::default())?;
    assert_eq!(restored.to_bytes(), recipe.to_bytes());
    Ok(())
}

#[test]
fn long_detector_recipe_refuses_narrowed_read_authority_and_changed_native_identity() -> Test {
    use fss_reference::ingest::detector_cascade::CascadeConfig;
    use fss_reference::ingest::long_watch::detector::LongWatchDetectorRecipe;
    use fss_reference::ingest::package_detect::PackageDetectLimits;
    let f = Fixture::new(
        "trained-recipe-refusal",
        &scene(3, 3, None, false, false)?,
        "mjpeg",
    )?;
    let scalar = fss_reference::ScalarExecCx::new();
    let package = trained_package(&f, &scalar)?;
    let recipe = LongWatchDetectorRecipe::new(
        &package,
        CascadeConfig::default(),
        PackageDetectLimits::default(),
        &LongWatchLimits::default(),
    )?;
    let mut watch = LongWatchLimits::default();
    watch.decode.read_limits.max_chunk_bytes -= 1;
    assert!(matches!(
        recipe.validate_within(&watch, &PackageDetectLimits::default()),
        Err(WatchError::Limit)
    ));
    let mut detector = PackageDetectLimits::default();
    detector.read.max_segment_bytes -= 1;
    assert!(matches!(
        recipe.validate_within(&LongWatchLimits::default(), &detector),
        Err(WatchError::Limit)
    ));
    let bytes = recipe.to_bytes();
    assert!(LongWatchDetectorRecipe::from_bytes(b"malformed recipe").is_err());
    assert!(LongWatchDetectorRecipe::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(LongWatchDetectorRecipe::from_bytes(&trailing).is_err());
    assert!(
        LongWatchDetectorRecipe::from_retained_bytes(
            &bytes,
            ContentDigest::sha256(b"other package")
        )
        .is_err()
    );
    let generation = recipe.backend().generation().bytes();
    let offset = bytes
        .windows(generation.len())
        .position(|candidate| candidate == generation)
        .ok_or("backend generation")?;
    let mut changed = bytes;
    changed[offset] ^= 1;
    assert!(LongWatchDetectorRecipe::from_bytes(&changed).is_err());
    Ok(())
}
