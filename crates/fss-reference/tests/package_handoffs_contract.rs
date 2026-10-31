#![forbid(unsafe_code)]
//! Real retained source → native package inference → anonymous track → handoff projection.
//! The tiny first-party coefficients exercise custody and composition, not detector accuracy.

mod package_zone_support;

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};

use fss_codec_mjpeg::ComponentInterpretation;
use fss_core::{
    BudgetVector, ClockBasis, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec,
    SensorId, StreamId, TimestampNs,
};
use fss_graph_algorithms::certified::Budget;
use fss_graph_algorithms::continuity::{self, Transition};
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::package_event::{
    PackageAnalysisReport, PackageTrackingConfig, retain_package_detection,
};
use fss_reference::ingest::package_handoffs::{
    PackageClockAlignment, PackageHandoffError, PackageHandoffProjection, PackageHandoffRequest,
    PackageHandoffSelection, PackageHandoffTracking,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{
    CaptureHint, FileIngestAdapter, FileIngestRequest, RetainedFileImport, RetainedReadLimits,
};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use package_zone_support::{Test, jpeg, package};

const SITE: &str = "site:package-handoffs";
const PRINCIPAL: &str = "principal:package-handoffs";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> Test<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-package-handoffs-{label}-{}-{attempt}",
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

fn context(root: &Path, principal: &str) -> Test<ReplayCx> {
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:package-handoffs".into(),
        operation_id: OperationId::parse("operation:package-handoffs")?,
        principal: principal.into(),
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
    Ok(ReplayCx::from_context_authority(
        &authority,
        root.to_path_buf(),
    )?)
}

struct Fixture {
    _directory: Directory,
    root: PathBuf,
    deployment: ReferenceDeployment,
    cx: ReplayCx,
    reports: Vec<PackageAnalysisReport>,
    request: PackageHandoffRequest,
}

fn fixture(label: &str) -> Test<Fixture> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let cx = context(&root, PRINCIPAL)?;
    let mut deployment = ReferenceDeployment::open(&root, SITE, &cx)?;
    let bytes = package()?;
    let scalar = ScalarExecCx::new();
    let model =
        RgbDetectorPackage::load(&bytes, ContentDigest::sha256(&bytes), 1 << 40, &cx, &scalar)?;
    let tracking = PackageHandoffTracking {
        confirmation_hits: 2,
        maximum_missed_frames: 1,
        minimum_iou_ppm: 0,
    };
    let mut selections = Vec::new();
    let mut reports = Vec::new();
    for (id, start) in [("a", 1_000_000_000), ("b", 3_000_000_000)] {
        let source = directory.0.join(format!("source-{id}.mjpeg"));
        let media: Vec<_> = [192, 224, 240].into_iter().flat_map(jpeg).collect();
        fs::write(&source, media)?;
        let stream = format!("stream:handoff-{id}");
        let imported = FileIngestAdapter::ingest(
            FileIngestRequest::new(
                &source,
                SensorId::parse(format!("sensor:handoff-{id}"))?,
                StreamId::parse(&stream)?,
            )
            .with_receive_time(TimestampNs(10_000_000_000))
            .with_capture_hint(CaptureHint::new(TimestampNs(start), 1_000_000, 10.0)?),
            &cx,
            &mut deployment,
        )?;
        fs::remove_file(source)?;
        let detected = run_package_detection(
            &deployment,
            &model,
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
        retain_package_detection(&mut deployment, &model, &detected, &cx)?;
        let report = PackageAnalysisReport::read(
            &deployment,
            detected.digest,
            "numeric-a",
            PackageTrackingConfig {
                confirmation_hits: 2,
                maximum_missed_frames: 1,
                minimum_iou_ppm: 0,
            },
            &cx,
        )?;
        assert_eq!(report.tracks().len(), 1);
        selections.push(PackageHandoffSelection {
            id: id.into(),
            report_digest: detected.digest,
            label: "numeric-a".into(),
            tracking,
            track: report.tracks()[0].identity,
            calibration: ContentDigest::sha256(format!("declared calibration {id}").as_bytes()),
            alignment: PackageClockAlignment {
                import_identity: imported.import_identity,
                stream_id: stream,
                clock_basis: ClockBasis::Estimated,
                offset_ns: [-10, 20],
                basis: ContentDigest::sha256(b"explicit fixture clock mapping assumption"),
            },
        });
        reports.push(report);
    }
    Ok(Fixture {
        _directory: directory,
        root,
        deployment,
        cx,
        reports,
        request: PackageHandoffRequest {
            session: "session:bounded-handoff".into(),
            generation: ContentDigest::sha256(b"analysis generation"),
            clock: ContentDigest::sha256(b"declared common nanosecond clock"),
            cost_unit: "cost".into(),
            birth_cost: 10,
            end_cost: 10,
            k: 3,
            selections,
            transitions: vec![Transition {
                from: "a".into(),
                to: "b".into(),
                transit: [1_000_000_000, 3_000_000_000],
                cost: 1,
                basis: ContentDigest::sha256(b"declared fixture transit assumption"),
            }],
        },
    })
}

#[test]
fn real_sources_project_exact_observations_and_reopen_without_model_or_source_files() -> Test {
    let f = fixture("cold")?;
    let head = f.deployment.current_anchor().clone();
    let projected = PackageHandoffProjection::read(&f.deployment, &f.request, &f.cx)?;
    assert_eq!(projected.anchor(), &head);
    assert_eq!(f.deployment.current_anchor(), &head);
    assert_eq!(projected.bindings().len(), 2);
    for (binding, report) in projected.bindings().iter().zip(&f.reports) {
        assert_eq!(binding.analysis_digest, report.digest());
        assert_eq!(binding.track, report.tracks()[0].identity);
        assert_eq!(binding.dimensions, [32, 16]);
        assert_eq!(binding.clock_basis, ClockBasis::Estimated);
        assert_eq!(binding.capture_time_label, "operator_assumption");
        assert!(binding.confirmed);
        assert!(!binding.observations[0].confirmed);
        assert!(binding.observations[1].confirmed);
        assert_eq!(binding.observations.len(), 3);
        for (observation, native) in binding
            .observations
            .iter()
            .zip(&report.tracks()[0].observations)
        {
            let frame = report
                .retained()
                .record()
                .frames
                .iter()
                .find(|row| row.segment == native.segment)
                .ok_or("native frame")?;
            let (row, score, bounds, _) = native.detection.ok_or("native assignment")?;
            assert_eq!(observation.capsule_digest, native.capsule_digest);
            assert_eq!(
                observation.capture,
                [frame.capture.earliest.0, frame.capture.latest.0]
            );
            assert_eq!(
                (
                    observation.detection_row,
                    observation.score_bits,
                    observation.bounds
                ),
                (row, score, bounds)
            );
            assert_eq!(
                observation.aligned_capture,
                binding.alignment.align(observation.capture)?
            );
        }
        let member = projected
            .query()
            .tracklets
            .iter()
            .find(|row| row.id == binding.id)
            .ok_or("tracklet")?;
        assert_eq!(member.start, binding.observations[0].aligned_capture);
        assert_eq!(member.end, binding.observations[2].aligned_capture);
    }
    let planned = continuity::plan(projected.query(), Budget::new(2_000_000, 32_768))?;
    assert_eq!(planned.output.family.edges.len(), 1);
    assert_eq!(
        planned.output.alternatives[0].paths,
        vec![vec!["a".to_owned(), "b".to_owned()]]
    );
    assert_eq!(planned.output.family.all_singletons.paths.len(), 2);
    projected.revalidate(&f.deployment, &f.cx)?;
    let bytes = projected.encoded().to_vec();
    let digest = projected.digest();
    let Fixture {
        _directory,
        root,
        deployment,
        cx,
        request,
        ..
    } = f;
    drop(deployment);
    cx.drain_and_finalize();
    let cx = context(&root, PRINCIPAL)?;
    let deployment = ReferenceDeployment::reopen(&root, SITE, &cx)?;
    let cold = PackageHandoffProjection::read(&deployment, &request, &cx)?;
    assert_eq!(cold.encoded(), bytes);
    assert_eq!(cold.digest(), digest);
    assert_eq!(deployment.current_anchor(), &head);
    assert!(!_directory.0.join("source-a.mjpeg").exists());
    Ok(())
}

#[test]
fn source_pins_missing_tracks_aliases_and_reused_assignments_refuse_the_whole_query() -> Test {
    let f = fixture("pins")?;
    let mut request = f.request.clone();
    request.selections[0].alignment.stream_id = "stream:foreign".into();
    assert!(PackageHandoffProjection::read(&f.deployment, &request, &f.cx).is_err());
    request = f.request.clone();
    request.selections[0].alignment.clock_basis = ClockBasis::UtcDisciplined;
    assert!(PackageHandoffProjection::read(&f.deployment, &request, &f.cx).is_err());
    request = f.request.clone();
    request.selections[0].track = ContentDigest::sha256(b"absent native track");
    assert!(matches!(
        PackageHandoffProjection::read(&f.deployment, &request, &f.cx),
        Err(PackageHandoffError::TrackUnavailable)
    ));
    request = f.request.clone();
    let mut alias = request.selections[0].clone();
    alias.id = "alias".into();
    request.selections.push(alias);
    assert!(request.validate().is_err());
    // A different tracker policy produces a different native track identity, but it cannot
    // make the same actually assigned source detections independent twice in one hypothesis.
    let alternate = PackageAnalysisReport::read(
        &f.deployment,
        f.request.selections[0].report_digest,
        "numeric-a",
        PackageTrackingConfig {
            confirmation_hits: 1,
            maximum_missed_frames: 1,
            minimum_iou_ppm: 0,
        },
        &f.cx,
    )?;
    request = f.request.clone();
    let mut alias = request.selections[0].clone();
    alias.id = "different-recipe".into();
    alias.tracking.confirmation_hits = 1;
    alias.track = alternate.tracks()[0].identity;
    request.selections.push(alias);
    request.validate()?;
    assert!(PackageHandoffProjection::read(&f.deployment, &request, &f.cx).is_err());
    Ok(())
}

#[test]
fn custody_damage_is_rechecked_before_release_and_never_repaired() -> Test {
    let f = fixture("damage")?;
    let projected = PackageHandoffProjection::read(&f.deployment, &f.request, &f.cx)?;
    let source = RetainedFileImport::open(
        &f.deployment,
        f.request.selections[0].alignment.import_identity,
        RetainedReadLimits::default(),
        &f.cx,
    )?;
    let digests = [
        projected.bindings()[0].record_digest,
        projected.bindings()[0].report_digest,
        projected.bindings()[0].observations[1].capsule_digest,
        source.manifest().ordered_chunks[0],
    ];
    let head = f.deployment.current_anchor().clone();
    for digest in digests {
        let path = f.deployment.publisher().spool().object_path(digest);
        let bytes = fs::read(&path)?;
        let mut damaged = bytes.clone();
        *damaged.last_mut().ok_or("empty custody object")? ^= 1;
        fs::write(&path, &damaged)?;
        assert!(
            projected.revalidate(&f.deployment, &f.cx).is_err(),
            "{digest}"
        );
        assert!(
            PackageHandoffProjection::read(&f.deployment, &f.request, &f.cx).is_err(),
            "{digest}"
        );
        assert_eq!(fs::read(&path)?, damaged);
        assert_eq!(f.deployment.current_anchor(), &head);
        fs::write(&path, bytes)?;
    }
    projected.revalidate(&f.deployment, &f.cx)?;
    Ok(())
}

#[test]
fn changed_principal_anchor_and_current_privacy_withdraw_the_projection() -> Test {
    let mut f = fixture("privacy")?;
    let projected = PackageHandoffProjection::read(&f.deployment, &f.request, &f.cx)?;
    let foreign = context(&f.root, "principal:another")?;
    assert!(matches!(
        projected.revalidate(&f.deployment, &foreign),
        Err(PackageHandoffError::Stale(_))
    ));
    let policy = PrivacyMaskPolicy::new(
        SensorId::parse("sensor:handoff-a")?,
        [32, 16],
        &[[0, 0, 32, 16]],
    )?;
    let approved = preview_mask(&f.deployment, &policy)?.approval;
    declare_mask(&mut f.deployment, &policy, approved, &f.cx)?;
    assert!(matches!(
        projected.revalidate(&f.deployment, &f.cx),
        Err(PackageHandoffError::Stale(_))
    ));
    assert!(PackageHandoffProjection::read(&f.deployment, &f.request, &f.cx).is_err());
    Ok(())
}

#[test]
fn cancellation_during_source_composition_returns_no_projection_or_authority_change() -> Test {
    let f = fixture("cancel")?;
    let head = f.deployment.current_anchor().clone();
    let polls = Cell::new(0);
    let cancel = || {
        let next = polls.get() + 1;
        polls.set(next);
        next >= 3
    };
    assert!(matches!(
        PackageHandoffProjection::read_with_cancel(&f.deployment, &f.request, &f.cx, &cancel),
        Err(PackageHandoffError::Cancelled)
    ));
    assert_eq!(f.deployment.current_anchor(), &head);
    assert!(f.cx.is_cancelled());
    Ok(())
}

#[test]
fn one_source_allowance_covers_all_recipes_and_cannot_restart_on_revalidation_or_clone() -> Test {
    let f = fixture("source-budget")?;
    let measured = PackageHandoffProjection::read(&f.deployment, &f.request, &f.cx)?;
    let one_pass = measured.source_bytes_read();
    assert!(one_pass > 1);
    // Both different camera imports must reserve their chunks, even when the exact JPEG
    // bytes match. A recipe-level or per-import reset would wrongly admit this query.
    assert!(
        PackageHandoffProjection::read_with_source_limit(
            &f.deployment,
            &f.request,
            &f.cx,
            &|| false,
            one_pass - 1,
        )
        .is_err()
    );
    let projected = PackageHandoffProjection::read_with_source_limit(
        &f.deployment,
        &f.request,
        &f.cx,
        &|| false,
        one_pass.checked_mul(2).ok_or("budget overflow")?,
    )?;
    assert_eq!(projected.source_bytes_read(), one_pass);
    let clone = projected.clone();
    projected.revalidate(&f.deployment, &f.cx)?;
    assert_eq!(projected.source_bytes_read(), one_pass * 2);
    assert_eq!(clone.source_bytes_read(), one_pass * 2);
    assert!(clone.revalidate(&f.deployment, &f.cx).is_err());
    assert!(projected.revalidate(&f.deployment, &f.cx).is_err());
    assert_eq!(projected.source_bytes_read(), one_pass * 2);
    assert_eq!(f.deployment.current_anchor(), projected.anchor());
    Ok(())
}
