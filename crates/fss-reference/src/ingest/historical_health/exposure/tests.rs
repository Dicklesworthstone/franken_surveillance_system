#![forbid(unsafe_code)]
//! Real retained JPEG screening and cold metadata custody, with no fabricated health receipts.

use super::*;
use crate::ingest::historical_health::HistoricalHealthRetention;
use crate::ingest::long_dwell::LongDwellLimits;
use crate::ingest::long_watch::LongWatchReport;
use crate::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use crate::ingest::recorded_decode::ComponentInterpretation;
use crate::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use crate::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BatchId, BudgetVector, OperationId, StreamId, TimestampNs};
use std::fs;
use std::path::Path;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:health-exposure";
const SENSOR: &str = "sensor:health-exposure";
const PRINCIPAL: &str = "principal:health-exposure";
const FRAMES: usize = 12;

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-health-exposure-{label}-{}-{attempt}",
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

fn context(root: &Path, principal: &str) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:health-exposure".into(),
        operation_id: OperationId::parse("operation:health-exposure")?,
        principal: principal.into(),
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

struct Fixture {
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    plan: WatchPlan,
    source: HealthExposureSource,
    _directory: Directory,
}

impl Fixture {
    fn new(label: &str, frozen: bool, refused_frame: bool) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let input = directory.0.join("camera.mjpeg");
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut bytes = Vec::new();
        for index in 0..FRAMES {
            let value = if frozen || index % 2 == 0 { 80 } else { 88 };
            let mut frame = encode_jpeg(16, 16, &vec![value; 256], &config)?;
            if refused_frame && index == 5 {
                let at = frame
                    .windows(2)
                    .position(|pair| pair == [0xff, 0xc0])
                    .ok_or("JPEG SOF0")?;
                frame[at + 1] = 0xc2;
            }
            bytes.extend(frame);
        }
        fs::write(&input, bytes)?;
        let cx = context(&root, PRINCIPAL)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.chunk_bytes = 4096;
        let imported = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &input,
                SensorId::parse(SENSOR)?,
                StreamId::parse("stream:exposure")?,
            )
            .with_limits(limits)
            .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
            .with_receive_time(TimestampNs(1_000_000_000_000)),
            &cx,
            &mut deployment,
        )?;
        fs::remove_file(input)?;
        let retained = crate::ingest::RetainedFileImport::open(
            &deployment,
            imported.import_identity,
            crate::ingest::RetainedReadLimits::default(),
            &cx,
        )?;
        let source = HealthExposureSource {
            import_identity: imported.import_identity,
            import_root: retained.import_root(),
            sensor_id: SensorId::parse(SENSOR)?,
            segment: 0,
            privacy_policy_digest: None,
            privacy_generation: None,
        };
        let plan = WatchPlan {
            import_identity: imported.import_identity,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: FRAMES,
            zones: vec![WatchZone {
                zone_id: "porch".into(),
                x: 0,
                y: 0,
                width: 16,
                height: 16,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        };
        Ok(Self {
            deployment,
            cx,
            plan,
            source,
            _directory: directory,
        })
    }

    fn retain(&mut self, tolerant: bool) -> Test<HistoricalHealthRetention> {
        let report = LongWatchReport::analyze_screened(
            &self.deployment,
            &self.plan,
            WatchOptions {
                tolerate_decode_refusals: tolerant,
            },
            &LongDwellLimits::default(),
            &self.cx,
        )?;
        let diagnostic = report
            .health_diagnostic()
            .ok_or("missing native diagnostic")?;
        Ok(diagnostic.retain(&mut self.deployment, diagnostic.approval_digest(), &self.cx)?)
    }

    fn read(&self) -> Test<HealthExposureCatalog> {
        Ok(HealthExposureCatalog::read(
            &self.deployment,
            HealthExposureLimits::default(),
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
}

#[test]
fn no_diagnostic_is_unknown_and_native_findings_withhold_threshold_latency_after_restart() -> Test {
    let mut fixture = Fixture::new("cold", true, false)?;
    let mut empty = fixture.read()?;
    assert!(empty.is_empty());
    assert_eq!(empty.usage().metadata_bytes_read, 0);
    let exposure = empty.assess(&fixture.source, &fixture.cx)?;
    assert_eq!(exposure.state(), HealthExposureState::NoMatchingDiagnostic);
    assert!(!exposure.support_withheld());
    let retained = fixture.retain(false)?;
    let before = fixture.snapshot();
    let mut catalog = fixture.read()?;
    assert_eq!(catalog.anchor(), &before.0);
    assert_eq!(catalog.pins().len(), 1);
    assert_eq!(catalog.pins()[0].record_digest, retained.record_digest);
    assert_eq!(catalog.pins()[0].provenance_root, retained.provenance_root);
    let exposure = catalog.assess(&fixture.source, &fixture.cx)?;
    assert_eq!(exposure.state(), HealthExposureState::Findings);
    assert!(exposure.support_withheld());
    assert!(!exposure.screening_incomplete());
    assert_eq!(exposure.reasons(), ["exact_frame_repetition"]);
    assert!(
        exposure.findings().iter().any(|finding| {
            finding.finding_first_segment > fixture.source.segment
                && finding.withheld_first_segment == 0
                && finding.withheld_last_segment == FRAMES as u64 - 1
        }),
        "threshold latency remains inside the finite conservative withheld scan"
    );
    let root = fixture.deployment.root().to_path_buf();
    drop(fixture.deployment);
    fixture.deployment = ReferenceDeployment::open(&root, SITE, &fixture.cx)?;
    let mut reopened = fixture.read()?;
    assert_eq!(reopened.pins(), catalog.pins());
    assert_eq!(reopened.assess(&fixture.source, &fixture.cx)?, exposure);
    assert_eq!(fixture.snapshot(), before, "no evidence or effect mutation");
    Ok(())
}

#[test]
fn exact_import_root_sensor_privacy_and_source_position_are_all_required() -> Test {
    let mut fixture = Fixture::new("binding", true, false)?;
    fixture.plan.first_segment = 2;
    fixture.plan.segment_count = FRAMES - 2;
    fixture.retain(false)?;
    let mut catalog = fixture.read()?;
    let mut matched = fixture.source.clone();
    matched.segment = 2;
    assert!(catalog.assess(&matched, &fixture.cx)?.support_withheld());
    let mut sources = Vec::new();
    let mut source = matched.clone();
    source.import_identity = ContentDigest::sha256(b"other import");
    sources.push(source);
    let mut source = matched.clone();
    source.import_root = ContentDigest::sha256(b"other source root");
    sources.push(source);
    let mut source = matched.clone();
    source.sensor_id = SensorId::parse("sensor:other")?;
    sources.push(source);
    let mut source = matched.clone();
    source.privacy_policy_digest = Some(ContentDigest::sha256(b"other privacy"));
    source.privacy_generation = Some(1);
    sources.push(source);
    let mut source = matched.clone();
    source.segment = 1;
    sources.push(source);
    let mut source = matched;
    source.segment = FRAMES as u64;
    sources.push(source);
    for source in sources {
        let exposure = catalog.assess(&source, &fixture.cx)?;
        assert_eq!(exposure.state(), HealthExposureState::NoMatchingDiagnostic);
        assert!(exposure.pins().is_empty());
        assert!(!exposure.support_withheld());
    }
    let mut malformed = fixture.source.clone();
    malformed.privacy_generation = Some(1);
    assert!(catalog.assess(&malformed, &fixture.cx).is_err());
    Ok(())
}

#[test]
fn complete_screen_without_findings_and_incomplete_screen_remain_distinct() -> Test {
    let mut complete = Fixture::new("complete", false, false)?;
    complete.retain(false)?;
    let mut catalog = complete.read()?;
    let exposure = catalog.assess(&complete.source, &complete.cx)?;
    assert_eq!(
        exposure.state(),
        HealthExposureState::ScreenedWithoutFindings
    );
    assert!(!exposure.support_withheld());
    assert!(exposure.findings().is_empty());
    assert_eq!(exposure.pins().len(), 1);

    let mut incomplete = Fixture::new("incomplete", false, true)?;
    incomplete.retain(true)?;
    let mut catalog = incomplete.read()?;
    let exposure = catalog.assess(&incomplete.source, &incomplete.cx)?;
    assert_eq!(exposure.state(), HealthExposureState::ScreeningIncomplete);
    assert!(exposure.support_withheld());
    assert!(
        exposure.findings().is_empty(),
        "no fake visual degradation from decode refusal"
    );
    assert_eq!(exposure.reasons(), ["historical_screening_incomplete"]);
    Ok(())
}

#[test]
fn every_matching_diagnostic_is_retained_and_work_does_not_refill_per_assessment() -> Test {
    let mut fixture = Fixture::new("cumulative", true, false)?;
    fixture.plan.segment_count = 7;
    let short = fixture.retain(false)?;
    fixture.plan.segment_count = FRAMES;
    let full = fixture.retain(false)?;
    assert_ne!(short.record_digest, full.record_digest);
    let before = fixture.snapshot();
    let mut catalog = fixture.read()?;
    let exposure = catalog.assess(&fixture.source, &fixture.cx)?;
    assert_eq!(exposure.pins().len(), 2);
    assert!(
        exposure.support_withheld(),
        "short clear screening cannot erase a longer finding"
    );
    assert!(
        catalog
            .pins()
            .windows(2)
            .all(|pair| pair[0].record_digest < pair[1].record_digest)
    );
    let spent = catalog.usage().assessment_work;
    let limits = HealthExposureLimits {
        maximum_assessment_work: spent,
        ..HealthExposureLimits::default()
    };
    let mut bounded = HealthExposureCatalog::read(&fixture.deployment, limits, &fixture.cx)?;
    assert_eq!(bounded.assess(&fixture.source, &fixture.cx)?, exposure);
    assert!(matches!(
        bounded.assess(&fixture.source, &fixture.cx),
        Err(HistoricalHealthError::Limit)
    ));
    let limits = HealthExposureLimits {
        maximum_records: 1,
        ..HealthExposureLimits::default()
    };
    assert!(matches!(
        HealthExposureCatalog::read(&fixture.deployment, limits, &fixture.cx),
        Err(HistoricalHealthError::Limit)
    ));
    assert_eq!(fixture.snapshot(), before);
    Ok(())
}

#[test]
fn metadata_bounds_cancellation_and_scope_refusal_change_no_authority() -> Test {
    let mut fixture = Fixture::new("admission", true, false)?;
    fixture.retain(false)?;
    let before = fixture.snapshot();
    for limits in [
        HealthExposureLimits {
            maximum_metadata_bytes: 1,
            ..HealthExposureLimits::default()
        },
        HealthExposureLimits {
            maximum_metadata_reads: 1,
            ..HealthExposureLimits::default()
        },
        HealthExposureLimits {
            maximum_history_work: 1,
            ..HealthExposureLimits::default()
        },
        HealthExposureLimits {
            maximum_records: 0,
            ..HealthExposureLimits::default()
        },
    ] {
        assert!(HealthExposureCatalog::read(&fixture.deployment, limits, &fixture.cx).is_err());
    }
    let foreign = context(&fixture._directory.0.join("foreign"), PRINCIPAL)?;
    assert!(matches!(
        HealthExposureCatalog::read(
            &fixture.deployment,
            HealthExposureLimits::default(),
            &foreign
        ),
        Err(HistoricalHealthError::AuthorityChanged)
    ));
    let mut catalog = fixture.read()?;
    let actor = context(fixture.deployment.root(), "principal:other")?;
    assert!(matches!(
        catalog.assess(&fixture.source, &actor),
        Err(HistoricalHealthError::AuthorityChanged)
    ));
    for stage in [
        "historical_health_exposure:inventory",
        "historical_health_exposure:metadata",
        "historical_health_exposure:complete",
    ] {
        let cancelled = context(fixture.deployment.root(), PRINCIPAL)?;
        cancelled.set_cancel_at_checkpoint(stage);
        assert!(matches!(
            HealthExposureCatalog::read(
                &fixture.deployment,
                HealthExposureLimits::default(),
                &cancelled
            ),
            Err(HistoricalHealthError::Cancelled)
        ));
    }
    let cancelled = context(fixture.deployment.root(), PRINCIPAL)?;
    cancelled.set_cancel_at_checkpoint("historical_health_exposure:match");
    assert!(matches!(
        catalog.assess(&fixture.source, &cancelled),
        Err(HistoricalHealthError::Cancelled)
    ));
    assert_eq!(fixture.snapshot(), before);
    Ok(())
}

#[test]
fn missing_or_corrupt_diagnostic_metadata_is_never_silently_dropped() -> Test {
    let mut fixture = Fixture::new("custody", true, false)?;
    let retained = fixture.retain(false)?;
    let before = fixture.snapshot();
    for digest in [
        retained.record_digest,
        retained.provenance_root,
        super::super::policy_digest(),
    ] {
        let path = fixture.deployment.publisher().spool().object_path(digest);
        let bytes = fs::read(&path)?;
        fs::write(&path, b"damaged retained health metadata")?;
        assert!(fixture.read().is_err());
        fs::remove_file(&path)?;
        assert!(fixture.read().is_err());
        fs::write(&path, bytes)?;
        assert_eq!(fixture.read()?.pins().len(), 1);
    }
    assert_eq!(fixture.snapshot(), before);
    Ok(())
}

#[test]
fn a_new_privacy_generation_cannot_borrow_old_findings_and_deletion_is_explicit() -> Test {
    let mut fixture = Fixture::new("privacy-deletion", true, false)?;
    let retained = fixture.retain(false)?;
    let policy = PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [16, 16], &[[0, 0, 4, 4]])?;
    let approval = preview_mask(&fixture.deployment, &policy)?.approval;
    declare_mask(&mut fixture.deployment, &policy, approval, &fixture.cx)?;
    let binding =
        crate::ingest::privacy_mask::current_mask(&fixture.deployment, &fixture.source.sensor_id)?;
    let mut source = fixture.source.clone();
    source.privacy_policy_digest = binding.policy_digest();
    source.privacy_generation = binding.generation();
    let mut catalog = fixture.read()?;
    assert_eq!(catalog.pins()[0].record_digest, retained.record_digest);
    assert!(
        catalog
            .assess(&fixture.source, &fixture.cx)?
            .support_withheld()
    );
    assert_eq!(
        catalog.assess(&source, &fixture.cx)?.state(),
        HealthExposureState::NoMatchingDiagnostic
    );

    let plan = crate::deletion::plan_deletion(
        &fixture.deployment,
        fixture.source.import_identity,
        &fixture.cx,
    )?;
    assert!(plan.blockers.is_empty());
    crate::deletion::commit_deletion(
        &mut fixture.deployment,
        plan.digest()?,
        plan.approval_digest(PRINCIPAL)?,
        PRINCIPAL,
        &fixture.cx,
    )?;
    let before = fixture.snapshot();
    let catalog = fixture.read()?;
    assert!(catalog.is_empty());
    assert_eq!(catalog.usage().records_seen, 1);
    assert_eq!(catalog.usage().deleted_records, 1);
    assert_eq!(catalog.usage().records_loaded, 0);
    assert_eq!(fixture.snapshot(), before);
    Ok(())
}

#[test]
fn an_orphan_deletion_tombstone_cannot_hide_a_retained_diagnostic() -> Test {
    let mut fixture = Fixture::new("orphan-tombstone", true, false)?;
    let retained = fixture.retain(false)?;
    let mut tombstone = fixture
        .deployment
        .ledger()
        .batches()
        .iter()
        .flat_map(|batch| &batch.deltas)
        .find(|delta| {
            delta.family == FAMILY_HISTORICAL_HEALTH
                && delta.payload_digest == retained.record_digest
        })
        .ok_or("missing retained health delta")?
        .clone();
    let unverified_plan = fixture
        .deployment
        .stage_payload(b"unverified health deletion plan")?;
    tombstone.delta_id = format!("delta:deletion-tombstone:{}", tombstone.object_id);
    tombstone.family = FAMILY_DELETION_TOMBSTONE.to_owned();
    tombstone.prior_generation = Some(tombstone.new_generation);
    tombstone.new_generation += 1;
    tombstone.payload_digest = unverified_plan;
    tombstone.witness_digest = None;
    tombstone.operation_id = None;
    // Exercise the reader with a canonical successor lacking the deletion owner's sealed
    // record and exact closure. Ordinary callers cannot append this reserved family.
    fixture.deployment.append_deletion_batch(
        BatchId::parse("batch:deletion:orphan-health-tombstone")?,
        vec![tombstone],
        vec![unverified_plan],
        &fixture.cx,
    )?;
    let before = fixture.snapshot();
    assert!(matches!(
        HealthExposureCatalog::read(
            &fixture.deployment,
            HealthExposureLimits::default(),
            &fixture.cx,
        ),
        Err(HistoricalHealthError::Unavailable)
    ));
    assert!(
        fixture
            .deployment
            .publisher()
            .spool()
            .object_path(retained.record_digest)
            .is_file()
    );
    assert_eq!(fixture.snapshot(), before);
    Ok(())
}
