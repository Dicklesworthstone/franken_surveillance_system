#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Actual file import and first-party model execution for retained-evaluation contract tests.

use std::fs;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::region::{ContextAuthority, RootAuthoritySpec};
use fss_core::{
    BudgetVector, ClockBasis, ContentDigest, OperationId, SensorId, StreamId, TimestampNs,
};
use fss_reference::evaluation::{
    ClosedIntervalNs, EvaluationPolicy, FalseAlertBudget, LabelSet, LabeledClip, TruthEvent,
};
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::package_evaluation::PackageEvaluationRequest;
use fss_reference::ingest::package_event::{
    PackageAnalysisReport, PackageTrackingConfig, retain_package_detection,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};

#[path = "../package_zone_support/mod.rs"]
mod numeric;

pub type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub const SITE: &str = "site:package-evaluation-native";
pub const SENSOR: &str = "sensor:package-evaluation-native";
pub const STREAM: &str = "stream:package-evaluation-native";
pub const PRINCIPAL: &str = "principal:package-evaluation-native";
pub const ORIGIN: i128 = 1_000_000_000;
pub const DURATION: u64 = 200_000_000;

pub struct Directory(pub PathBuf);
impl Directory {
    pub fn new(label: &str) -> Test<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-package-evaluation-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub fn context(root: &Path) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:package-evaluation-native".into(),
        operation_id: OperationId::parse("operation:package-evaluation-native")?,
        principal: PRINCIPAL.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(512 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    Ok(ReplayCx::from_context_authority_read_only(
        &authority,
        root.to_path_buf(),
    )?)
}

pub fn tracking() -> PackageTrackingConfig {
    PackageTrackingConfig {
        confirmation_hits: 2,
        maximum_missed_frames: 1,
        minimum_iou_ppm: 0,
    }
}

pub fn policy() -> EvaluationPolicy {
    EvaluationPolicy {
        early_tolerance_ns: 0,
        late_tolerance_ns: 0,
        false_alert_budget: FalseAlertBudget {
            max_false_alerts: 0,
            per_observed_ns: 1_000_000_000,
        },
    }
}

pub fn labels(positive: bool) -> LabelSet {
    LabelSet {
        clips: vec![LabeledClip {
            clip_id: "clip".into(),
            duration_ns: DURATION,
            not_observable: Vec::new(),
        }],
        events: if positive {
            vec![TruthEvent {
                event_id: "truth".into(),
                clip_id: "clip".into(),
                class: "numeric-a".into(),
                zone: None,
                interval: ClosedIntervalNs::new(100_000_000, 100_000_000),
            }]
        } else {
            Vec::new()
        },
    }
}

pub struct Fixture {
    pub directory: Directory,
    pub root: PathBuf,
    pub report: ContentDigest,
    pub import: ContentDigest,
    pub chunk: PathBuf,
    pub source_bytes: u64,
    pub first_confirmation_score_bits: Option<u32>,
}

impl Fixture {
    /// Three real JPEG frames are imported, decoded, inferred, and retained. The original
    /// loose source is removed before any evaluation. None of these pixels claims real quality.
    pub fn new(label: &str, values: [u8; 3], uncertainty: Option<u64>) -> Test<Self> {
        let directory = Directory::new(label)?;
        let root = directory.0.join("deployment");
        let source = directory.0.join("source.mjpeg");
        let media: Vec<u8> = values.into_iter().flat_map(numeric::jpeg).collect();
        fs::write(&source, &media)?;
        let cx = context(&root)?;
        let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut request =
            FileIngestRequest::new(&source, SensorId::parse(SENSOR)?, StreamId::parse(STREAM)?)
                .with_receive_time(TimestampNs(10_000_000_000));
        if let Some(uncertainty) = uncertainty {
            request = request.with_capture_hint(CaptureHint::new(
                TimestampNs(ORIGIN),
                uncertainty,
                10.0,
            )?);
        }
        let imported = FileIngestAdapter::ingest(request, &cx, &mut deployment)?;
        fs::remove_file(source)?;
        let bytes = numeric::package()?;
        let scalar = ScalarExecCx::new();
        let package =
            RgbDetectorPackage::load(&bytes, ContentDigest::sha256(&bytes), 1 << 40, &cx, &scalar)?;
        let detection = run_package_detection(
            &deployment,
            &package,
            &PackageDetectRequest {
                import_identity: imported.import_identity,
                first_segment: 0,
                segment_count: 3,
                interpretation: ComponentInterpretation::YCbCr,
                minimum_score_ppm: None,
            },
            &PackageDetectLimits::default(),
            &cx,
            &scalar,
        )?;
        retain_package_detection(&mut deployment, &package, &detection, &cx)?;
        let analysis = PackageAnalysisReport::read(
            &deployment,
            detection.digest,
            "numeric-a",
            tracking(),
            &cx,
        )?;
        let first_confirmation_score_bits = analysis.tracks().iter().find_map(|track| {
            track
                .observations
                .iter()
                .enumerate()
                .find_map(|(index, observation)| {
                    (analysis.sample_is_confirmed(track.identity, index) == Some(true))
                        .then_some(observation.detection.map(|row| row.1))
                        .flatten()
                })
        });
        let retained = RetainedFileImport::open(
            &deployment,
            imported.import_identity,
            RetainedReadLimits::default(),
            &cx,
        )?;
        let chunk = deployment.publisher().spool().object_path(
            *retained
                .manifest()
                .ordered_chunks
                .first()
                .ok_or("source chunk")?,
        );
        let result = Self {
            directory,
            root,
            report: detection.digest,
            import: imported.import_identity,
            chunk,
            source_bytes: media.len() as u64,
            first_confirmation_score_bits,
        };
        drop(deployment);
        cx.drain_and_finalize();
        Ok(result)
    }

    pub fn request(&self) -> PackageEvaluationRequest {
        PackageEvaluationRequest {
            report_digest: self.report,
            label: "numeric-a".into(),
            tracking: tracking(),
            clip_id: "clip".into(),
            clip_origin_ns: ORIGIN,
            stream_id: STREAM.into(),
            clock_basis: ClockBasis::Estimated,
        }
    }

    pub fn journals(&self) -> Test<(Vec<u8>, Vec<u8>)> {
        Ok((
            fs::read(self.root.join("ledger/journal.fssj"))?,
            fs::read(self.root.join("effects/journal.fssj"))?,
        ))
    }
}
