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
