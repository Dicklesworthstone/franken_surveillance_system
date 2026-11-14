#![forbid(unsafe_code)]
//! Small native watch/dwell publications using the shared retained-media fixture.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{BudgetVector, ContentDigest, EventHypothesis, OperationId, RuntimeGrant};
use fss_publication::{LOCAL_ROOTS_DIR, ROOT_RECORD_SUFFIX, SlotName};
use fss_reference::ReplayCx;
use fss_reference::agent_orient::OrientLimits;
use fss_reference::ingest::long_dwell::{LongDwellLimits, LongDwellReport};
use fss_reference::ingest::long_event_replay::LongEventReplayPins;
use fss_reference::ingest::long_watch::LongWatchReport;
use fss_reference::ingest::recorded_decode::ComponentInterpretation;
use fss_reference::ingest::recorded_watch::{
    WatchDetectorConfig, WatchOptions, WatchPlan, WatchTrackerConfig, WatchZone,
};
use fss_reference::ingest::zone_dwell::DwellPolicy;
use fss_reference::ingest::{FileFormatHint, RetainedFileImport, RetainedReadLimits};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_reference::reference_deployment::FAMILY_SENSOR_CAPSULE;
use fss_reference::retained_source::ImmutableRetainedReadLimits;

use super::support::{Fixture, SITE, TestResult as Test};

pub const SENSOR: &str = "sensor:long-event-immutable";

#[derive(Clone, Copy, Debug)]
pub enum Profile {
    Watch,
    Dwell,
}

pub struct Published {
    pub storage: Fixture,
    pub event: EventHypothesis,
    pub plan: WatchPlan,
    pub analysis_digest: ContentDigest,
    pub analysis_root: ContentDigest,
    pub event_root: ContentDigest,
    pub quiet_capsule: ContentDigest,
    pub source_chunks: Vec<ContentDigest>,
}

impl Published {
    pub fn new(label: &str, profile: Profile) -> Test<Self> {
        let mut storage = Fixture::new(label)?;
        let import = storage.ingest(SENSOR, &scene()?, FileFormatHint::JpegStream, Some(0))?;
        let plan = WatchPlan {
            import_identity: import,
            first_segment: 0,
            segment_count: 40,
            zones: vec![WatchZone {
                zone_id: "porch".into(),
                x: 0,
                y: 0,
                width: 48,
                height: 32,
            }],
            interpretation: ComponentInterpretation::Grayscale,
            detector: WatchDetectorConfig {
                learning_rate_num: 0,
                ..WatchDetectorConfig::default()
            },
            tracker: WatchTrackerConfig::default(),
        };
        let (event, analysis_digest, prefix) = match profile {
            Profile::Watch => {
                let mut report = LongWatchReport::analyze(
                    &storage.deployment,
                    &plan,
                    WatchOptions::default(),
                    &LongDwellLimits::default(),
                    &storage.cx,
                )?;
                let candidate = report
                    .candidates()
                    .first()
                    .ok_or("native watch candidate")?;
                let event = candidate.event().clone();
                let approval = candidate.proposal_digest();
                assert_eq!(
                    report.publish(
                        &mut storage.deployment,
                        &BTreeSet::from([approval]),
                        &storage.cx,
                    )?,
                    1,
                );
                (event, report.analysis_digest(), "lw-a")
            }
            Profile::Dwell => {
                let mut report = LongDwellReport::analyze(
                    &storage.deployment,
                    &plan,
                    DwellPolicy {
                        minimum_duration_ns: 1,
                        maximum_sample_gap_ns: 1_000_000_000,
                        minimum_observations: 3,
                    },
                    WatchOptions::default(),
                    &LongDwellLimits::default(),
                    &storage.cx,
                )?;
                let candidate = report
                    .candidates()
                    .first()
                    .ok_or("native dwell candidate")?;
                let event = candidate.event().clone();
                let approval = candidate.proposal_digest();
                assert_eq!(
                    report.publish(
                        &mut storage.deployment,
                        &BTreeSet::from([approval]),
                        &storage.cx,
                    )?,
                    1,
                );
                (event, report.analysis_digest(), "ld-a")
            }
        };
        let slot = SlotName::parse(&format!("{prefix}-{}", hex(analysis_digest)))?;
        let analysis_root = storage
            .deployment
            .publisher()
            .root(&slot)
            .ok_or("published analysis")?
            .root;
        let (_, receipt) = storage
            .deployment
            .current_event_authority(&event.event_id)?;
        let event_root = receipt.event_root;
        let quiet_capsule = storage
            .deployment
            .ledger()
            .current()
            .objects
            .values()
            .find(|object| object.family == FAMILY_SENSOR_CAPSULE)
            .ok_or("retained capsule")?
            .payload_digest;
        let retained = RetainedFileImport::open(
            &storage.deployment,
            import,
            RetainedReadLimits::default(),
            &storage.cx,
        )?;
        let source_chunks = retained.manifest().ordered_chunks.clone();
        Ok(Self {
            storage,
            event,
            plan,
            analysis_digest,
            analysis_root,
            event_root,
            quiet_capsule,
            source_chunks,
        })
    }

    pub fn root(&self) -> &Path {
        self.storage.deployment.root()
    }

    pub fn pins(&self) -> LongEventReplayPins {
        LongEventReplayPins {
            event_revision: self.event.revision_digest(),
            provenance_root: self.event.decision_path.fingerprint,
        }
    }

    pub fn object_path(&self, digest: ContentDigest) -> PathBuf {
        self.storage
            .deployment
            .publisher()
            .spool()
            .object_path(digest)
    }

    pub fn publication(&self, root: ContentDigest) -> Test<(PathBuf, SlotName, usize)> {
        let publisher = self.storage.deployment.publisher();
        let visible = publisher
            .visible_roots()
            .find(|value| value.root == root)
            .ok_or("named native publication")?;
        let path = publisher
            .root_dir()
            .join(LOCAL_ROOTS_DIR)
            .join(format!("{}{ROOT_RECORD_SUFFIX}", visible.slot));
        Ok((path, visible.slot.clone(), visible.child_count))
    }
}

pub fn limits() -> ImmutableRetainedReadLimits {
    ImmutableRetainedReadLimits {
        snapshot: OrientLimits::default(),
        max_read_bytes: 1024 * 1024 * 1024,
        max_read_objects: 1_000_000,
    }
}

pub fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:long-event-immutable".into(),
        operation_id: OperationId::parse("operation:long-event-immutable")?,
        principal: "principal:immutable-reader".into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            RuntimeGrant::AgentQuery.as_str().into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(limits().max_read_bytes as u64)
            .storage_operations(limits().max_read_objects as u64)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    assert!(!authority.has_capability(RuntimeGrant::ReadMedia.as_str()));
    Ok(ReplayCx::from_context_authority_read_only(
        &authority, root,
    )?)
}

pub fn tree(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    fn visit(
        root: &Path,
        directory: &Path,
        entries: &mut BTreeMap<PathBuf, Option<Vec<u8>>>,
    ) -> Test {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path.strip_prefix(root)?.to_path_buf();
            if entry.file_type()?.is_dir() {
                entries.insert(relative, None);
                visit(root, &path, entries)?;
            } else {
                entries.insert(relative, Some(fs::read(path)?));
            }
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    visit(root, root, &mut entries)?;
    Ok(entries)
}

fn scene() -> Test<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut bytes = Vec::new();
    for frame in 0..40 {
        let mut pixels = vec![40_u8 + (frame % 2) as u8 * 8; 48 * 32];
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

fn hex(digest: ContentDigest) -> String {
    digest
        .bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
