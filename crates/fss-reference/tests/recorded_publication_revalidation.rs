#![forbid(unsafe_code)]
//! In-memory analysis is not permission to publish after source or privacy authority changes.
//! All recordings, policies, deletion plans and corruption faults here are synthetic and local.

#[path = "cascade_support/mod.rs"]
mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, OperationId, SensorId};
use fss_reference::deletion::{commit_deletion, plan_deletion};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::recorded_corroboration::{
    CorroborationCamera, CorroborationGates, CorroborationPlan, CorroborationReport,
    GroundHomography, GroundZone,
};
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchLimits, WatchPlan, WatchReport, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::{FileFormatHint, RetainedFileImport, RetainedReadLimits};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::{ReferenceDeployment, ReplayCx};
use support::{Fixture, TestResult};

const SENSOR_A: &str = "sensor:publication-east";
const SENSOR_B: &str = "sensor:publication-west";
const PRINCIPAL: &str = "principal:cascade";

fn scene() -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    for index in 0..14 {
        let mut pixels = vec![40_u8; 96 * 48];
        if index >= 3 {
            let left = (index - 3) * 8;
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * 96 + x] = 220;
                }
            }
        }
        bytes.extend(encode_jpeg(96, 48, &pixels, &config)?);
    }
    Ok(bytes)
}

fn setup(name: &str) -> TestResult<(Fixture, [ContentDigest; 2])> {
    let mut f = Fixture::new(name)?;
    let bytes = scene()?;
    let a = f.ingest(
        SENSOR_A,
        &bytes,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    let b = f.ingest(
        SENSOR_B,
        &bytes,
        FileFormatHint::JpegStream,
        Some(1_000_000_000),
    )?;
    Ok((f, [a, b]))
}

enum Analysis {
    Watch(WatchReport),
    Corroboration(CorroborationReport),
}

impl Analysis {
    fn prepare(f: &Fixture, imports: [ContentDigest; 2], two: bool) -> TestResult<Self> {
        let limits = WatchLimits::default();
        if two {
            let camera = |name: &str, import_identity| CorroborationCamera {
                name: name.to_owned(),
                import_identity,
                homography: GroundHomography {
                    matrix: [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0],
                },
            };
            let plan = CorroborationPlan {
                cameras: [camera("east", imports[0]), camera("west", imports[1])],
                interpretation: ComponentInterpretation::Grayscale,
                zones: vec![GroundZone {
                    zone_id: "door".to_owned(),
                    x: 56.0,
                    y: 0.0,
                    width: 40.0,
                    height: 48.0,
                }],
                gates: CorroborationGates {
                    time_gate_ns: 250_000_000,
                    distance_gate: 16.0,
                },
                detector: WatchDetectorConfig::default(),
                tracker: WatchTrackerConfig::default(),
            };
            let report = CorroborationReport::analyze(&f.deployment, &plan, &limits, &f.cx)?;
            assert_eq!(report.candidates().len(), 1);
            Ok(Self::Corroboration(report))
        } else {
            let plan = WatchPlan {
                import_identity: imports[0],
                interpretation: ComponentInterpretation::Grayscale,
                first_segment: 0,
                segment_count: 14,
                zones: vec![WatchZone {
                    zone_id: "door".to_owned(),
                    x: 64,
                    y: 0,
                    width: 32,
                    height: 32,
                }],
                detector: WatchDetectorConfig::default(),
                tracker: WatchTrackerConfig::default(),
            };
            let report = WatchReport::analyze(&f.deployment, &plan, &limits, &f.cx)?;
            assert_eq!(report.candidates().len(), 1);
            Ok(Self::Watch(report))
        }
    }

    fn publish(
        &mut self,
        deployment: &mut ReferenceDeployment,
        cx: &ReplayCx,
    ) -> TestResult<usize> {
        Ok(match self {
            Self::Watch(report) => {
                let approvals = BTreeSet::from([report.candidates()[0].proposal_digest()]);
                report.publish(deployment, &approvals, cx)?
            }
            Self::Corroboration(report) => {
                let approvals = BTreeSet::from([report.candidates()[0].proposal_digest()]);
                report.publish(deployment, &approvals, cx)?
            }
        })
    }

    fn retain(&mut self, deployment: &mut ReferenceDeployment, cx: &ReplayCx) -> TestResult {
        match self {
            Self::Watch(report) => {
                report.retain_coverage(deployment, report.coverage_approval(), cx)?;
            }
            Self::Corroboration(report) => {
                report.retain_coverage(deployment, report.coverage_approval(), cx)?;
            }
        }
        Ok(())
    }

    fn refused_without_writes(&mut self, f: &mut Fixture, why: &str) -> TestResult {
        let before = snapshot(f.deployment.root())?;
        assert!(
            self.publish(&mut f.deployment, &f.cx).is_err(),
            "event admitted {why}"
        );
        assert_eq!(
            snapshot(f.deployment.root())?,
            before,
            "event refusal wrote {why}"
        );
        assert!(
            self.retain(&mut f.deployment, &f.cx).is_err(),
            "coverage admitted {why}"
        );
        assert_eq!(
            snapshot(f.deployment.root())?,
            before,
            "coverage refusal wrote {why}"
        );
        Ok(())
    }
}

fn snapshot(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    let mut files = BTreeMap::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else {
                files.insert(
                    entry.path().strip_prefix(root)?.to_path_buf(),
                    fs::read(entry.path())?,
                );
            }
        }
    }
    Ok(files)
}

fn mask(f: &mut Fixture, sensor: &str, x: u32) -> TestResult {
    // The bottom corner is outside the moving object. Changing authority still invalidates
    // previously computed results even when this particular scene's candidate would survive.
    let policy = PrivacyMaskPolicy::new(SensorId::parse(sensor)?, [96, 48], &[[x, 40, 4, 4]])?;
    let approval = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approval, &f.cx)?;
    Ok(())
}

#[test]
fn new_privacy_policy_refuses_pending_and_already_published_analyses() -> TestResult {
    for two in [false, true] {
        for already_published in [false, true] {
            let (mut f, imports) = setup("new-policy")?;
            let mut report = Analysis::prepare(&f, imports, two)?;
            if already_published {
                assert_eq!(report.publish(&mut f.deployment, &f.cx)?, 1);
                report.retain(&mut f.deployment, &f.cx)?;
            }
            mask(&mut f, if two { SENSOR_B } else { SENSOR_A }, 0)?;
            report.refused_without_writes(&mut f, "a newer privacy policy")?;
        }
    }
    Ok(())
}

#[test]
fn returning_to_equal_mask_bytes_does_not_restore_an_old_generation() -> TestResult {
    for two in [false, true] {
        let (mut f, imports) = setup("mask-rotation")?;
        let sensor = if two { SENSOR_B } else { SENSOR_A };
        mask(&mut f, sensor, 0)?;
        let mut report = Analysis::prepare(&f, imports, two)?;
        mask(&mut f, sensor, 8)?;
        mask(&mut f, sensor, 0)?;
        report.refused_without_writes(&mut f, "A-to-B-to-A mask rotation")?;
    }
    Ok(())
}

#[test]
fn deleted_source_cannot_be_resurrected_by_a_cached_analysis() -> TestResult {
    for two in [false, true] {
        let (mut f, imports) = setup("source-deletion")?;
        let mut report = Analysis::prepare(&f, imports, two)?;
        let deletion = plan_deletion(&f.deployment, imports[usize::from(two)], &f.cx)?;
        assert!(deletion.blockers.is_empty());
        commit_deletion(
            &mut f.deployment,
            deletion.digest()?,
            deletion.approval_digest(PRINCIPAL)?,
            PRINCIPAL,
            &f.cx,
        )?;
        report.refused_without_writes(&mut f, "deleted source")?;
    }
    Ok(())
}

#[test]
fn corrupt_source_is_rejected_before_staging_any_provenance() -> TestResult {
    for two in [false, true] {
        let (mut f, imports) = setup("source-corruption")?;
        let mut report = Analysis::prepare(&f, imports, two)?;
        let source = RetainedFileImport::open(
            &f.deployment,
            imports[0],
            RetainedReadLimits::default(),
            &f.cx,
        )?;
        let path = f
            .deployment
            .publisher()
            .spool()
            .object_path(source.manifest().ordered_chunks[0]);
        let mut bytes = fs::read(&path)?;
        *bytes.last_mut().ok_or("empty source envelope")? ^= 0x80;
        fs::write(path, bytes)?;
        report.refused_without_writes(&mut f, "corrupted retained bytes")?;
    }
    Ok(())
}

#[test]
fn missing_or_corrupt_selected_capsule_refuses_event_and_coverage_before_writes() -> TestResult {
    for two in [false, true] {
        for remove in [false, true] {
            let (mut f, imports) = setup("capsule-damage")?;
            let mut report = Analysis::prepare(&f, imports, two)?;
            let source = RetainedFileImport::open(
                &f.deployment,
                imports[usize::from(two)],
                RetainedReadLimits::default(),
                &f.cx,
            )?;
            // This quiet frame contributes background state and coverage, not the entry's
            // positive observations. Its evidence must still be present before publication.
            let capsule_id = &source.manifest().segment_spans[1].capsule_id;
            let object = format!("object:capsule:{capsule_id}");
            let digest = f
                .deployment
                .ledger()
                .batches()
                .iter()
                .flat_map(|batch| &batch.deltas)
                .find(|delta| delta.object_id.as_str() == object)
                .ok_or("missing fixture capsule delta")?
                .payload_digest;
            let path = f.deployment.publisher().spool().object_path(digest);
            if remove {
                fs::remove_file(path)?;
            } else {
                let mut bytes = fs::read(&path)?;
                *bytes.last_mut().ok_or("empty capsule envelope")? ^= 0x80;
                fs::write(path, bytes)?;
            }
            report.refused_without_writes(&mut f, "damaged non-entry source capsule")?;
        }
    }
    Ok(())
}

fn other_principal(root: &Path) -> TestResult<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:publication-other".into(),
        operation_id: OperationId::parse("operation:publication-other")?,
        principal: "principal:other".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(256 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(support::SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

#[test]
fn another_principal_or_identical_imports_in_another_root_cannot_use_the_report() -> TestResult {
    for two in [false, true] {
        let (mut f, imports) = setup("context-owner")?;
        let mut report = Analysis::prepare(&f, imports, two)?;
        let cx = other_principal(f.deployment.root())?;
        let before = snapshot(f.deployment.root())?;
        assert!(report.publish(&mut f.deployment, &cx).is_err());
        assert!(report.retain(&mut f.deployment, &cx).is_err());
        assert_eq!(snapshot(f.deployment.root())?, before);
        let (mut other, same_imports) = setup("context-other")?;
        assert_eq!(same_imports, imports);
        report.refused_without_writes(&mut other, "an identical but different deployment")?;
    }
    Ok(())
}

#[test]
fn valid_unchanged_source_survives_unrelated_commits_and_exact_retries() -> TestResult {
    for two in [false, true] {
        let (mut f, imports) = setup("valid-retry")?;
        let mut report = Analysis::prepare(&f, imports, two)?;
        mask(&mut f, "sensor:unrelated", 0)?;
        assert_eq!(report.publish(&mut f.deployment, &f.cx)?, 1);
        report.retain(&mut f.deployment, &f.cx)?;
        let before = snapshot(f.deployment.root())?;
        assert_eq!(report.publish(&mut f.deployment, &f.cx)?, 0);
        report.retain(&mut f.deployment, &f.cx)?;
        assert_eq!(snapshot(f.deployment.root())?, before);
    }
    Ok(())
}
