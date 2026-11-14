#![forbid(unsafe_code)]
#![allow(dead_code)]
//! Shared native producer fixture for library and real-process localization discovery tests.
//! The candidate, insufficient-match and degenerate-geometry receipts all pass through the
//! native JPEG decoder, privacy projection, feature matcher and root-last retained publisher.

#[path = "../recorded_twin_localization/archive_fixture.rs"]
mod archive_fixture;

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fss_core::{
    BudgetQuantitiesSpec, BudgetVector, ContentDigest, ContextAuthority, OperationId,
    RootAuthoritySpec, RuntimeGrant, SensorId, StreamId, TimestampNs,
};
use fss_geometry::{GeometryBasis, PinholeIntrinsics, PoseSolverOptions, WorkBudget};
use fss_object::SPOOL_OBJECTS_DIR;
use fss_publication::LOCAL_SPOOL_DIR;
use fss_reference::ingest::recorded_decode::video_budget::RecordedVideoDecodeBudget;
use fss_reference::ingest::recorded_decode::{
    ComponentInterpretation, DecodeBudget, DecodeLimits, RecordedDecodeRequest,
};
use fss_reference::ingest::twin_localization::retained::{
    RetainedLocalizationPlan, localize_and_retain,
};
use fss_reference::ingest::twin_localization::{RecordedImageMode, RecordedLocalizationSource};
use fss_reference::ingest::{
    FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_twin::atlas_archive::{ArchiveExpectation, ReferenceProvenance, encode_atlas};
use fss_twin::localization::native::{
    ExtractionOptions, GrayImage, ImageIdentity, ImageLocalizationOptions, descriptor_domain,
    extract_gray,
};
use fss_twin::localization::{
    AtlasBinding, AtlasLandmark, AtlasReference, LocalizationAtlas, LocalizationOutcome,
    MatchOptions,
};
use fss_twin::rectification::{LensDistortion, LumaRange, RectificationSpec};
use fss_twin::{ImportExpectation, ImportLimits, PropertyTwin, import_twin};

pub type Test<T = ()> = Result<T, Box<dyn Error>>;
pub const SITE: &str = "site:localizations-query";
pub const PRINCIPAL: &str = "principal:localizations-query";
const JPEG: &[u8] = include_bytes!("../../../../tests/fixtures/media/jpeg/brown_luma_q100.jpg");

struct Directory(PathBuf);
impl Directory {
    fn new(tag: &str) -> Test<Self> {
        for n in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-localizations-query-{tag}-{}-{n}",
                std::process::id(),
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("localization query fixture directory capacity".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn authority() -> Test<ContextAuthority> {
    Ok(ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:localizations-query-fixture".into(),
        operation_id: OperationId::parse("operation:localizations-query-fixture")?,
        principal: PRINCIPAL.into(),
        capabilities: vec![
            "ADP-REPLAY-001".into(),
            RuntimeGrant::AgentQuery.as_str().into(),
        ],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::from_quantities(BudgetQuantitiesSpec {
            latency_ms: 60_000,
            bytes: 512 * 1024 * 1024,
            storage_operations: 65_536,
            ..BudgetQuantitiesSpec::ZERO
        }),
        privacy_scope: "privacy:internal".into(),
        retention_scope: "retention:ephemeral".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?)
}

/// A read context deliberately lacking source-media, model-execution and mutation grants.
pub fn context(root: &Path) -> Test<ReplayCx> {
    let authority = authority()?;
    assert!(!authority.has_capability(RuntimeGrant::ReadMedia.as_str()));
    Ok(ReplayCx::from_context_authority_read_only(
        &authority, root,
    )?)
}

#[derive(Clone, Debug)]
pub struct Record {
    pub identity: ContentDigest,
    pub root: ContentDigest,
    pub receipt: ContentDigest,
    pub import_identity: ContentDigest,
    pub import_root: ContentDigest,
    pub source_manifest: ContentDigest,
    pub capsule: ContentDigest,
    pub source_blob: ContentDigest,
    pub luma_blob: ContentDigest,
    pub decode_root: Option<ContentDigest>,
    pub twin_blob: ContentDigest,
    pub atlas_blob: ContentDigest,
    pub sensor_id: SensorId,
    pub stream_id: StreamId,
    /// The producer's actual outcome; discovery itself does not parse or promote that result.
    pub outcome: &'static str,
}

pub struct Fixture {
    pub cx: ReplayCx,
    pub deployment: ReferenceDeployment,
    pub records: Vec<Record>,
    directory: Directory,
}

impl Fixture {
    /// Keep the writer alive while separately authorized metadata readers inspect its state.
    pub fn new(tag: &str) -> Test<Self> {
        let directory = Directory::new(tag)?;
        let root = directory.0.join("deployment");
        let cx = ReplayCx::from_context_authority(&authority()?, root.clone())?;
        let deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
        let mut fixture = Self {
            cx,
            deployment,
            records: Vec::new(),
            directory,
        };
        let twin_bytes = archive_fixture::twin_archive(&[0.0], None)?;
        let twin = import_twin(
            &twin_bytes,
            twin_expectation(&twin_bytes)?,
            ImportLimits::default(),
            &mut WorkBudget::new(2_000_000_000),
        )?;
        let atlas = atlas(&twin)?;
        let atlas_bytes = archive(&atlas)?;
        let first = fixture.import("sensor:localization:a", "stream:localization:shared")?;
        fixture.retain(first, &twin_bytes, &atlas_bytes, options(), "candidates")?;
        let mut insufficient = options();
        insufficient.extraction.maximum_features = 1;
        fixture.retain(
            first,
            &twin_bytes,
            &atlas_bytes,
            insufficient,
            "insufficient_matches",
        )?;

        // Collinear map landmarks are valid retained atlas inputs but cannot support an
        // accepted 3D camera pose. The real geometric solver emits this failure receipt.
        let mut landmarks = atlas.landmarks().to_vec();
        for (index, point) in landmarks.iter_mut().enumerate() {
            point.world = [index as f64 * 0.1, 0.0, 6.0];
        }
        let degenerate = LocalizationAtlas::new(
            &twin,
            landmarks,
            atlas.references().to_vec(),
            atlas.bindings().to_vec(),
            &mut WorkBudget::new(2_000_000_000),
        )?;
        let second = fixture.import("sensor:localization:b", "stream:localization:other")?;
        fixture.retain(
            second,
            &twin_bytes,
            &archive(&degenerate)?,
            options(),
            "geometric_failure",
        )?;
        fixture.records.sort_by_key(|record| record.identity);
        Ok(fixture)
    }

    pub fn root(&self) -> &Path {
        self.deployment.root()
    }

    pub fn object_path(&self, digest: ContentDigest) -> PathBuf {
        object_path(self.root(), digest)
    }

    fn import(&mut self, sensor: &str, stream: &str) -> Test<ContentDigest> {
        let path = self.directory.0.join("recording.jpg");
        // A legal synthetic JPEG comment preserves the actual pixels while making the two
        // original recordings distinct custody leaves. Native import and decode consume it.
        assert_eq!(&JPEG[..2], &[0xff, 0xd8]);
        let mut bytes = JPEG[..2].to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe]);
        bytes.extend_from_slice(&u16::try_from(sensor.len() + 2)?.to_be_bytes());
        bytes.extend_from_slice(sensor.as_bytes());
        bytes.extend_from_slice(&JPEG[2..]);
        fs::write(&path, bytes)?;
        let request = FileIngestRequest::new(
            path.clone(),
            SensorId::parse(sensor)?,
            StreamId::parse(stream)?,
        )
        .with_receive_time(TimestampNs(1_000_000_000));
        let imported = FileIngestAdapter::ingest(request, &self.cx, &mut self.deployment)?;
        fs::remove_file(path)?;
        assert!(!imported.absence_certifiable);
        Ok(imported.import_identity)
    }

    fn retain(
        &mut self,
        import_identity: ContentDigest,
        twin_bytes: &[u8],
        atlas_bytes: &[u8],
        options: ImageLocalizationOptions,
        expected_outcome: &'static str,
    ) -> Test {
        let source = RecordedLocalizationSource::Jpeg(RecordedDecodeRequest {
            import_identity,
            segment_index: 0,
            interpretation: ComponentInterpretation::Grayscale,
            read_limits: RetainedReadLimits::default(),
            decode_limits: DecodeLimits::default(),
        });
        let (result, retained) = localize_and_retain(
            &mut self.deployment,
            &source,
            RetainedLocalizationPlan {
                twin_bytes,
                twin: twin_expectation(twin_bytes)?,
                atlas_bytes,
                atlas: ArchiveExpectation {
                    package: ContentDigest::sha256(atlas_bytes).bytes(),
                    provenance: [7; 32],
                    descriptor: descriptor_domain(),
                },
                image: RecordedImageMode::Raw(rectification()?),
                options,
            },
            &mut DecodeBudget::new(1_000_000_000),
            &mut RecordedVideoDecodeBudget::new(1_000_000_000),
            &mut WorkBudget::new(2_000_000_000),
            &self.cx,
        )?;
        let outcome = match &result.result().localization.outcome {
            LocalizationOutcome::Candidates(search) => {
                assert_eq!(search.candidates().len(), 1);
                assert!(search.candidates()[0].rms_px() <= 0.5);
                "candidates"
            }
            LocalizationOutcome::InsufficientMatches => "insufficient_matches",
            LocalizationOutcome::GeometricFailure(_) => "geometric_failure",
        };
        assert_eq!(outcome, expected_outcome);
        let binding = result.source();
        let imported = RetainedFileImport::open(
            &self.deployment,
            import_identity,
            RetainedReadLimits::default(),
            &self.cx,
        )?;
        let capsule = fss_reference::ingest::recorded_decode::retained_source_capsule(
            &self.deployment,
            &imported,
            0,
        )?;
        self.records.push(Record {
            identity: retained.identity(),
            root: retained.publication_root(),
            receipt: retained.receipt_digest(),
            import_identity,
            import_root: binding.import_root,
            source_manifest: binding.manifest,
            capsule: binding.capsule,
            source_blob: binding.encoded_source,
            luma_blob: binding.luma,
            decode_root: binding.decode_root,
            twin_blob: retained.twin_digest(),
            atlas_blob: retained.atlas_package(),
            sensor_id: capsule.sensor_id,
            stream_id: capsule.stream_id,
            outcome,
        });
        Ok(())
    }
}

pub fn object_path(root: &Path, digest: ContentDigest) -> PathBuf {
    root.join("objects")
        .join(LOCAL_SPOOL_DIR)
        .join(SPOOL_OBJECTS_DIR)
        .join(
            digest
                .bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )
}

fn twin_expectation(bytes: &[u8]) -> Test<ImportExpectation> {
    Ok(ImportExpectation {
        package_sha256: ContentDigest::sha256(bytes).bytes(),
        source_scene_sha256: [1; 32],
        basis: GeometryBasis::new(9, 4)?,
    })
}

fn archive(atlas: &LocalizationAtlas) -> Test<Vec<u8>> {
    Ok(encode_atlas(
        atlas,
        [7; 32],
        &[ReferenceProvenance {
            reference: 1,
            source_record: [6; 32],
            allowed_mask: [5; 32],
        }],
        &mut WorkBudget::new(2_000_000_000),
    )?)
}

fn options() -> ImageLocalizationOptions {
    ImageLocalizationOptions {
        extraction: ExtractionOptions {
            maximum_features: 200,
            ..ExtractionOptions::default()
        },
        matching: MatchOptions::default(),
        solving: PoseSolverOptions {
            ransac_trials: 0,
            ..PoseSolverOptions::default()
        },
    }
}

fn rectification() -> Test<RectificationSpec> {
    let camera = PinholeIntrinsics::new(96, 96, 80.0, 80.0, 48.0, 48.0)?;
    Ok(RectificationSpec {
        source: camera,
        target: camera,
        distortion: LensDistortion::BrownConrady {
            radial: [-0.1, 0.001, 0.0001],
            tangential: [0.001, -0.001],
        },
        maximum_radius: 1.0,
        source_domain: [3; 32],
        calibration: [4; 32],
        range: LumaRange::Full,
    })
}

fn atlas(twin: &PropertyTwin) -> Test<LocalizationAtlas> {
    // The same first-party LCG texture and Brown-Conrady observation used by the retained
    // localization owner tests. These are synthetic image features, not supplied poses.
    let mut budget = WorkBudget::new(2_000_000_000);
    let mut state = 1973_u32;
    let pixels: Vec<u8> = (0..96 * 96)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            20 + ((state >> 16) % 180) as u8
        })
        .collect();
    let allowed = vec![1; pixels.len()];
    let gray = GrayImage::new(
        ImageIdentity {
            exposure: [1; 32],
            pixels: ContentDigest::sha256(&pixels).bytes(),
            image_domain: [9; 32],
            dimensions: [96, 96],
        },
        &pixels,
        &allowed,
        &mut budget,
    )?;
    let frame = extract_gray(&gray, options().extraction, &mut budget)?.frame;
    let mut landmarks = Vec::new();
    let mut bindings = Vec::new();
    for (index, point) in frame.features().iter().enumerate() {
        let depth = 6.0 + (index % 7) as f64 * 0.5;
        landmarks.push(AtlasLandmark {
            id: index as u64 + 1,
            physical_group: index as u64 + 1,
            feature: 0,
            world: [
                (point.pixel[0] - 48.0) * depth / 80.0,
                (point.pixel[1] - 48.0) * depth / 80.0,
                depth,
            ],
            evidence: [8; 32],
            error: None,
        });
        bindings.push(AtlasBinding {
            landmark: index as u64 + 1,
            reference: 1,
            image_feature: point.id,
        });
    }
    Ok(LocalizationAtlas::new(
        twin,
        landmarks,
        vec![AtlasReference { id: 1, frame }],
        bindings,
        &mut budget,
    )?)
}
