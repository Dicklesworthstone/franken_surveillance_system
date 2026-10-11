#![forbid(unsafe_code)]
//! Actual retained MJPEG diagnostics, cold metadata projection, follow and deletion boundaries.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use fss_core::{
    AgentView, BudgetVector, ContentDigest, ContextAuthority, KnowledgeState, MeaningfulDeltaClass,
    OperationId, PrincipalId, ProvenanceClass, RootAuthoritySpec, SensorId, StreamId, TimestampNs,
};

use super::*;
use crate::agent_follow::{
    AnchorToken, DEFAULT_FOLLOW_MAX_ENTRIES, FollowRequest, follow_deployment,
    snapshot_anchor_token,
};
use crate::agent_orient::{
    CLAIM_COVERAGE, DeploymentHistory, OrientError, OrientLimits, OrientRequest, orient_deployment,
    read_deployment,
};
use crate::deletion::{commit_deletion, plan_deletion};
use crate::ingest::historical_health::HistoricalHealthRetention;
use crate::ingest::long_dwell::{LongDwellLimits, LongDwellReport};
use crate::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use crate::ingest::recorded_decode::ComponentInterpretation;
use crate::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use crate::ingest::zone_dwell::DwellPolicy;
use crate::ingest::{CaptureHint, FileIngestAdapter, FileIngestLimits, FileIngestRequest};
use crate::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use crate::{ReferenceDeployment, ReplayCx};

type Test<T = ()> = Result<T, Box<dyn Error>>;
const SITE: &str = "site:orient-historical-health";
const SENSOR: &str = "sensor:orient-historical-health";
const FRAMES: usize = 24;
const WIDTH: u32 = 32;
const HEIGHT: u32 = 24;

struct Fixture {
    directory: PathBuf,
    root: PathBuf,
    cx: ReplayCx,
    imports: usize,
}

impl Fixture {
    fn new(label: &str) -> Test<Self> {
        let mut directory = None;
        for attempt in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-orient-historical-health-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    directory = Some(path);
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        let directory = directory.ok_or("temporary directory capacity exhausted")?;
        let root = directory.join("deployment");
        let authority = ContextAuthority::new_root(RootAuthoritySpec {
            trace_id: "trace:orient-historical-health".into(),
            operation_id: OperationId::parse("operation:orient-historical-health")?,
            principal: "principal:orient-historical-health".into(),
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
        let cx = ReplayCx::from_context_authority(&authority, root.clone())?;
        drop(ReferenceDeployment::open(&root, SITE, &cx)?);
        Ok(Self {
            directory,
            root,
            cx,
            imports: 0,
        })
    }

    fn retain(
        &mut self,
        frozen: bool,
        corrupt_frame: bool,
    ) -> Test<(HistoricalHealthRecord, HistoricalHealthRetention)> {
        self.imports += 1;
        let input = self
            .directory
            .join(format!("camera-{}.mjpeg", self.imports));
        let config = JpegConfig {
            quality: 90,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        };
        let mut source = Vec::new();
        for frame in 0..FRAMES {
            let luma = if frozen {
                80
            } else {
                80 + (frame % 2) as u8 * 8
            };
            let pixels = vec![luma; (WIDTH * HEIGHT) as usize];
            let mut encoded = encode_jpeg(WIDTH, HEIGHT, &pixels, &config)?;
            if corrupt_frame && frame == FRAMES / 2 {
                let sof = encoded
                    .windows(2)
                    .position(|bytes| bytes == [0xff, 0xc0])
                    .ok_or("baseline JPEG marker missing")?;
                encoded[sof + 1] = 0xc2;
            }
            source.extend(encoded);
        }
        fs::write(&input, source)?;
        let mut deployment = ReferenceDeployment::open(&self.root, SITE, &self.cx)?;
        let mut limits = FileIngestLimits::standard();
        limits.max_segments = FRAMES + 1;
        limits.chunk_bytes = 4096;
        let imported = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &input,
                SensorId::parse(SENSOR)?,
                StreamId::parse("stream:orient-historical-health")?,
            )
            .with_limits(limits)
            .with_capture_hint(CaptureHint::new(TimestampNs(0), 0, 10.0)?)
            .with_receive_time(TimestampNs(1_000_000_000_000)),
            &self.cx,
            &mut deployment,
        )?;
        fs::remove_file(input)?;
        let plan = WatchPlan {
            import_identity: imported.import_identity,
            interpretation: ComponentInterpretation::Grayscale,
            first_segment: 0,
            segment_count: FRAMES,
            zones: vec![WatchZone {
                zone_id: "historical-image-zone".into(),
                x: 0,
                y: 0,
                width: WIDTH,
                height: HEIGHT,
            }],
            detector: WatchDetectorConfig::default(),
            tracker: WatchTrackerConfig::default(),
        };
        let report = LongDwellReport::analyze_screened(
            &deployment,
            &plan,
            DwellPolicy {
                minimum_duration_ns: 20_000_000_000,
                maximum_sample_gap_ns: 100_000_000,
                minimum_observations: 3,
            },
            WatchOptions {
                tolerate_decode_refusals: corrupt_frame,
            },
            &LongDwellLimits::default(),
            &self.cx,
        )?;
        assert!(report.candidates().is_empty(), "fixture has no dwell event");
        let diagnostic = report
            .health_diagnostic()
            .ok_or("screening receipt missing")?;
        let record = diagnostic.record().clone();
        let retention =
            diagnostic.retain(&mut deployment, diagnostic.approval_digest(), &self.cx)?;
        Ok((record, retention))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn request(view: AgentView) -> Test<OrientRequest> {
    Ok(OrientRequest {
        view,
        principal: PrincipalId::parse("principal:orient-historical-health")?,
        budget_tokens: None,
    })
}

#[test]
fn cold_health_projection_and_follow_keep_old_suspicion_after_no_findings() -> Test {
    let mut fixture = Fixture::new("cold-follow")?;
    let (suspect, _) = fixture.retain(true, false)?;
    assert_eq!(suspect.status(), "suspected_degradation");
    let limits = OrientLimits::default();
    let before = read_deployment(&fixture.root, &limits)?;
    assert!(before.events.is_empty());
    assert_eq!(before.historical_health.len(), 1);
    let before_brief = orient_deployment(&before, &request(AgentView::Brief)?, &limits)?;
    let before_claim = before_brief
        .capsule()
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| is_historical_health_claim(cell.claim_id()))
        .ok_or("health claim missing")?;
    let since =
        AnchorToken::parse(&snapshot_anchor_token(&before)).ok_or("anchor token invalid")?;

    let (clean, _) = fixture.retain(false, false)?;
    assert_eq!(clean.status(), "no_findings");
    let history = DeploymentHistory::read(&fixture.root, &limits)?;
    let historical = history.snapshot_at(before.position)?;
    assert_eq!(
        historical.historical_health.len(),
        1,
        "future receipt leaked into prefix"
    );
    let current = history.snapshot_at(history.head())?;
    assert_eq!(current.historical_health.len(), 2);
    let brief = orient_deployment(&current, &request(AgentView::Brief)?, &limits)?;
    brief.publication.verify()?;
    let frame = &brief.capsule().frame;
    let health: Vec<_> = frame
        .knowledge_cells
        .iter()
        .filter(|cell| is_historical_health_claim(cell.claim_id()))
        .collect();
    assert_eq!(health.len(), 2);
    let old = health
        .iter()
        .find(|cell| cell.claim_id() == before_claim.claim_id())
        .ok_or("earlier historical suspicion was lost")?;
    assert_eq!(old.cell_digest(), before_claim.cell_digest());
    assert!(old.statement().contains("reports suspected_degradation"));
    assert!(old.statement().contains("exact_frame_repetition"));
    for cell in health {
        assert_eq!(cell.knowledge_state(), KnowledgeState::Known);
        assert_eq!(cell.provenance(), ProvenanceClass::Derived);
        assert!(cell.statement().contains("literal retained result"));
        assert!(cell.statement().contains("operator_assumption"));
        assert!(cell.statement().contains("not continuous coverage"));
        assert!(cell.statement().contains("Source and trace were not read"));
        assert!(
            !frame
                .world_envelope
                .certified_core_claim_ids
                .contains(cell.claim_id())
        );
    }
    for record in [&suspect, &clean] {
        assert!(
            frame
                .evidence_handles
                .contains(&format!("fss://proof/{}", record.digest()))
        );
    }
    assert!(
        frame
            .at_risk
            .iter()
            .any(|risk| risk.contains("1 suspected_degradation"))
    );
    assert_eq!(
        frame.world_envelope.coverage_boundary_handles,
        before_brief
            .capsule()
            .frame
            .world_envelope
            .coverage_boundary_handles,
    );
    assert_eq!(
        brief.capsule().completeness,
        before_brief.capsule().completeness
    );
    assert_eq!(
        frame
            .knowledge_cells
            .iter()
            .find(|cell| cell.claim_id() == CLAIM_COVERAGE)
            .map(KnowledgeCell::knowledge_state),
        Some(KnowledgeState::NotObservable)
    );
    assert!(
        brief
            .attention
            .iter()
            .any(|item| item.kind == "historical_sensor_health")
    );
    for record in [&suspect, &clean] {
        let handle = brief
            .publication
            .compression_receipt
            .expansion_handles
            .iter()
            .find(|handle| handle.handle == format!("fss://proof/{}", record.digest()))
            .ok_or("priced diagnostic hydration missing")?;
        assert!(handle.purpose.contains("fss-event health read"));
        assert!(handle.purpose.contains("--max-metadata-bytes"));
        assert!(handle.estimated_cost.tokens >= record.to_json().len() as u64);
        assert_eq!(handle.estimated_cost.storage_operations, 65_536);
    }

    let pulse = orient_deployment(&current, &request(AgentView::Pulse)?, &limits)?;
    pulse.publication.verify()?;
    assert!(
        pulse.publication.context_pack.token_count <= u64::from(AgentView::Pulse.maximum_tokens())
    );
    assert!(pulse.publication.context_pack.items.iter().any(|item| {
        item.content
            .contains("Historical heuristic diagnostics: 1 suspected_degradation")
    }));
    assert!(pulse.publication.context_pack.items.iter().any(|item| {
        item.content
            .contains("no_findings clears no earlier finding")
    }));
    assert!(pulse.publication.context_pack.items.iter().any(|item| {
        item.content
            .contains("Current sensor health, outage, tamper")
            && item
                .content
                .contains("continuous coverage and certified absence are unproved")
            && item.content.contains("0 incomplete screens")
            && item.content.contains("0 deleted metadata/source")
    }));
    assert!(matches!(
        orient_deployment(
            &current,
            &OrientRequest {
                budget_tokens: Some(1),
                ..request(AgentView::Pulse)?
            },
            &limits
        ),
        Err(OrientError::ContextBudgetExceeded { .. })
    ));

    let follow = follow_deployment(
        &history,
        &since,
        &FollowRequest {
            view: AgentView::Brief,
            principal: request(AgentView::Brief)?.principal,
            max_entries: DEFAULT_FOLLOW_MAX_ENTRIES,
            continuation: None,
        },
    )?;
    assert!(
        follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::SensorHealth)
    );
    assert!(
        !follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::CoverageRecovery)
    );
    assert!(follow.delta.silence_certificate.is_none());
    assert!(
        !follow
            .delta
            .changed_cells
            .iter()
            .any(|cell| cell.claim_id() == before_claim.claim_id())
    );
    assert!(follow.delta.removed_claim_ids.is_empty());
    Ok(())
}

#[test]
fn metadata_reader_never_reads_native_trace_and_refuses_missing_or_overbounded_inventory() -> Test {
    let mut fixture = Fixture::new("bounded-reader")?;
    let (record, _) = fixture.retain(false, true)?;
    assert_eq!(record.status(), "incomplete");
    let deployment = ReferenceDeployment::open(&fixture.root, SITE, &fixture.cx)?;
    let mut reads = Vec::new();
    let inventory = read_inventory(
        deployment.ledger().batches(),
        &DeletionIndex::default(),
        OrientLimits::default().max_object_bytes,
        |digest, bound| {
            reads.push(digest);
            deployment
                .publisher()
                .spool()
                .read_bounded(digest, bound)
                .map_err(|error| corrupt(format!("test metadata read: {error}")))
        },
    )?;
    assert_eq!(inventory.len(), 1);
    assert!((3..=4).contains(&reads.len()));
    assert!(!reads.contains(&record.trace_digest()));
    assert!(!reads.contains(&record.import_root()));
    assert!(!reads.contains(&record.manifest_digest()));
    assert_eq!(inventory[0].metadata_reads, reads.len() as u64);
    let projection = project(&inventory)?;
    assert!(
        projection.cells[0]
            .statement()
            .contains("reports incomplete")
    );
    assert!(projection.at_risk[0].contains("1 incomplete screens"));

    let missing = read_inventory(
        deployment.ledger().batches(),
        &DeletionIndex::default(),
        1_024,
        |_, _| Err(corrupt("committed diagnostic metadata missing")),
    );
    assert!(matches!(missing, Err(DeploymentReadError::Corrupt { .. })));
    let mut admitted = Vec::new();
    let exceeded = read_inventory(
        deployment.ledger().batches(),
        &DeletionIndex::default(),
        7,
        |_, bound| {
            admitted.push(bound);
            Ok(vec![0; bound + 1])
        },
    );
    assert!(matches!(exceeded, Err(DeploymentReadError::Corrupt { .. })));
    assert_eq!(admitted, vec![7]);

    let template = deployment
        .ledger()
        .batches()
        .iter()
        .find(|batch| {
            batch
                .deltas
                .iter()
                .any(|delta| delta.family == FAMILY_HISTORICAL_HEALTH)
        })
        .ok_or("diagnostic authority batch missing")?;
    let batches: Vec<_> = (0..=MAX_HISTORICAL_HEALTH_RECORDS)
        .map(|index| {
            let mut batch = template.clone();
            batch.deltas[0].payload_digest =
                ContentDigest::sha256(format!("receipt-{index}").as_bytes());
            batch
        })
        .collect();
    let mut attempted_read = false;
    let exceeded = read_inventory(&batches, &DeletionIndex::default(), 65_536, |_, _| {
        attempted_read = true;
        Err(corrupt("must refuse inventory before reading any receipt"))
    });
    assert!(matches!(exceeded, Err(DeploymentReadError::Corrupt { .. })));
    assert!(
        !attempted_read,
        "an overbounded inventory was partially read"
    );
    Ok(())
}

#[test]
fn later_privacy_policy_preserves_old_historical_receipt_and_deletion_stays_explicit() -> Test {
    let mut fixture = Fixture::new("privacy-deletion")?;
    let (record, _) = fixture.retain(true, false)?;
    let limits = OrientLimits::default();
    let before = read_deployment(&fixture.root, &limits)?;
    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &fixture.cx)?;
    let policy =
        PrivacyMaskPolicy::new(SensorId::parse(SENSOR)?, [WIDTH, HEIGHT], &[[0, 0, 8, 8]])?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &fixture.cx)?;
    drop(deployment);
    let changed_policy = read_deployment(&fixture.root, &limits)?;
    assert_eq!(before.historical_health, changed_policy.historical_health);
    let since = AnchorToken::parse(&snapshot_anchor_token(&changed_policy))
        .ok_or("anchor token invalid")?;

    let mut deployment = ReferenceDeployment::open(&fixture.root, SITE, &fixture.cx)?;
    let plan = plan_deletion(&deployment, record.import_identity(), &fixture.cx)?;
    assert!(
        plan.deletable
            .iter()
            .any(|object| object.digest == record.digest())
    );
    let plan_digest = plan.digest()?;
    let principal = fixture.cx.io_authority().principal().to_owned();
    commit_deletion(
        &mut deployment,
        plan_digest,
        plan.approval_digest(&principal)?,
        &principal,
        &fixture.cx,
    )?;
    drop(deployment);
    let history = DeploymentHistory::read(&fixture.root, &limits)?;
    for position in [history.head(), before.position] {
        let deleted = history.snapshot_at(position)?;
        assert_eq!(deleted.historical_health.len(), 1);
        let HistoricalHealthMetadata::Deleted(custody) = &deleted.historical_health[0].metadata
        else {
            return Err("deleted metadata was presented as available".into());
        };
        assert_eq!(custody.authority_in_prefix, position == history.head());
        assert_eq!(deleted.historical_health[0].metadata_reads, 0);
        let orient = orient_deployment(&deleted, &request(AgentView::Brief)?, &limits)?;
        let claim = orient
            .capsule()
            .frame
            .knowledge_cells
            .iter()
            .find(|cell| is_historical_health_claim(cell.claim_id()))
            .ok_or("deleted claim disappeared")?;
        assert!(
            claim
                .statement()
                .contains("unavailable under committed deletion")
        );
        assert!(claim.statement().contains("unavailable is not no_findings"));
        assert!(
            !claim
                .evidence()
                .iter()
                .any(|evidence| evidence.digest == record.digest())
        );
        assert!(
            !orient
                .publication
                .situation
                .proof_roots
                .contains(&record.digest())
        );
        assert!(
            orient
                .capsule()
                .frame
                .evidence_handles
                .contains(&format!("fss://proof/{}", record.digest()))
        );
        assert!(
            orient
                .capsule()
                .frame
                .evidence_handles
                .contains(&format!("fss://proof/{plan_digest}"))
        );
        assert!(
            !orient
                .publication
                .compression_receipt
                .expansion_handles
                .iter()
                .any(
                    |handle| handle.handle == format!("fss://proof/{}", record.digest())
                        && handle.purpose.contains("fss-event health read")
                )
        );
    }
    let follow = follow_deployment(
        &history,
        &since,
        &FollowRequest {
            view: AgentView::Brief,
            principal: request(AgentView::Brief)?.principal,
            max_entries: DEFAULT_FOLLOW_MAX_ENTRIES,
            continuation: None,
        },
    )?;
    assert!(
        follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::SensorHealth)
    );
    assert!(
        !follow
            .delta
            .classes
            .contains(&MeaningfulDeltaClass::CoverageRecovery)
    );
    assert!(follow.delta.silence_certificate.is_none());
    let claim = follow
        .delta
        .changed_cells
        .iter()
        .find(|cell| is_historical_health_claim(cell.claim_id()))
        .ok_or("follow omitted the diagnostic deletion transition")?;
    assert!(
        claim
            .statement()
            .contains("unavailable under committed deletion")
    );
    assert!(
        claim
            .statement()
            .contains("within this snapshot's committed prefix")
    );
    let prior = follow
        .basis
        .capsule()
        .frame
        .knowledge_cells
        .iter()
        .find(|cell| is_historical_health_claim(cell.claim_id()))
        .ok_or("prior custody claim missing")?;
    assert!(
        prior
            .statement()
            .contains("unavailable under committed deletion")
    );
    assert!(
        prior
            .statement()
            .contains("later than this snapshot's committed prefix")
    );
    Ok(())
}
