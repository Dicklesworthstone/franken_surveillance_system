#![forbid(unsafe_code)]
//! Actual native package custody plus the original clock solver and handoff planner.

use super::*;
use fss_core::{BudgetVector, ContextAuthority, OperationId, RootAuthoritySpec, TimestampNs};
use fss_reference::ingest::package_detect::{
    PackageDetectLimits, PackageDetectRequest, run_package_detection,
};
use fss_reference::ingest::package_event::{
    PackageAnalysisReport, PackageTrackingConfig, retain_package_detection,
};
use fss_reference::ingest::rgb_package::RgbDetectorPackage;
use fss_reference::ingest::{CaptureHint, FileIngestAdapter, FileIngestRequest};
use fss_reference::{ReferenceDeployment, ReplayCx, ScalarExecCx};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[path = "../../../fss-reference/tests/package_zone_support/mod.rs"]
mod native_support;
type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const CLOCK: &[u8] =
    include_bytes!("../../../../fixtures/clock-alignment/retained_handoffs_clock.json");
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    directory: PathBuf,
    cx: ReplayCx,
    deployment: ReferenceDeployment,
    request: ClockHandoffRequest,
    projection: PackageHandoffProjection,
    selection_bytes: Vec<u8>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.cx.drain_and_finalize();
        let _ = fs::remove_dir_all(&self.directory);
    }
}
impl Fixture {
    fn source_input(&self) -> RetainedReportInput<'_> {
        RetainedReportInput {
            input_document: self.request.input_document,
            projection_digest: self.projection.digest(),
            anchor: self.projection.anchor(),
            bindings: self.projection.bindings(),
            query: self.projection.query(),
        }
    }
    fn report(&self, work: &mut WorkBudget<'_>, maximum: usize) -> Result<String, QueryError> {
        analyze(
            ClockReportInput {
                request: &self.request,
                projection: &self.projection,
                clock_query: CLOCK,
            },
            work,
            maximum,
            &|| false,
        )
    }
}

fn fixture() -> Test<Fixture> {
    let directory = std::env::temp_dir().join(format!(
        "fss-clock-handoffs-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed),
    ));
    fs::create_dir(&directory)?;
    let root = directory.join("deployment");
    let auth = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:clock-handoffs-test".into(),
        operation_id: OperationId::parse("operation:clock-handoffs-test")?,
        principal: "principal:clock-handoffs-test".into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder()
            .bytes(512 * 1024 * 1024)
            .storage_operations(65_536)
            .build()?,
        privacy_scope: "privacy:test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(b"property:clock-handoffs"),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&auth, root.clone())?;
    let mut deployment = ReferenceDeployment::open(&root, "property:clock-handoffs", &cx)?;
    let bytes = native_support::package()?;
    let scalar = ScalarExecCx::new();
    let model =
        RgbDetectorPackage::load(&bytes, ContentDigest::sha256(&bytes), 1 << 40, &cx, &scalar)?;
    let clock = ClockValidationQuery::parse_pinned(
        CLOCK,
        ContentDigest::sha256(CLOCK),
        &mut WorkBudget::new(continuity_query::MAX_WORK),
    )?;
    let mut selections = Vec::new();
    let mut sources = Vec::new();
    let mut projections = Vec::new();
    for (side, (name, start)) in [("a", 1_000_000_000_i128), ("b", 3_000_000_000_i128)]
        .into_iter()
        .enumerate()
    {
        let path = directory.join(format!("{name}.mjpeg"));
        fs::write(
            &path,
            [192, 224, 240]
                .into_iter()
                .flat_map(native_support::jpeg)
                .collect::<Vec<_>>(),
        )?;
        let sensor = format!("sensor:clock-handoff-{name}");
        let stream = format!("stream:clock-handoff-{name}");
        let imported = FileIngestAdapter::ingest(
            FileIngestRequest::new(&path, SensorId::parse(&sensor)?, StreamId::parse(&stream)?)
                .with_receive_time(TimestampNs(10_000_000_000))
                .with_capture_hint(CaptureHint::new(TimestampNs(start), 1_000_000, 10.0)?),
            &cx,
            &mut deployment,
        )?;
        fs::remove_file(path)?;
        let detected = run_package_detection(
            &deployment,
            &model,
            &PackageDetectRequest {
                import_identity: imported.import_identity,
                first_segment: 0,
                segment_count: 3,
                interpretation: fss_codec_mjpeg::ComponentInterpretation::YCbCr,
                minimum_score_ppm: None,
            },
            &PackageDetectLimits::default(),
            &cx,
            &scalar,
        )?;
        retain_package_detection(&mut deployment, &model, &detected, &cx)?;
        let tracking = PackageTrackingConfig {
            confirmation_hits: 2,
            maximum_missed_frames: 1,
            minimum_iou_ppm: 0,
        };
        let report =
            PackageAnalysisReport::read(&deployment, detected.digest, "numeric-a", tracking, &cx)?;
        assert_eq!(report.tracks().len(), 1);
        let camera = &clock.cameras()[side];
        sources.push(object(&[
            ("camera", camera.id.to_string()),
            ("clock_generation", camera.clock.to_string()),
            ("import_identity", d(imported.import_identity)),
            ("sensor_id", string(&sensor)),
            ("stream_id", string(&stream)),
            ("clock_basis", string("estimated")),
            ("calibration_digest", d(camera.calibration)),
            ("image_domain", d(camera.image_domain)),
        ]));
        selections.push(object(&[
            ("id", string(name)),
            ("report_digest", d(detected.digest)),
            ("label", string("numeric-a")),
            (
                "tracking",
                "{\"confirmation_hits\":2,\"maximum_missed_frames\":1,\"minimum_iou_ppm\":0}"
                    .into(),
            ),
            ("track", d(report.tracks()[0].identity)),
            (
                "source",
                string(if side == 0 { "reference" } else { "target" }),
            ),
        ]));
        if side == 1 {
            for (index, observation) in report.tracks()[0].observations.iter().enumerate() {
                projections.push(object(&[
                    ("capsule_digest", d(observation.capsule_digest)),
                    ("projection_id", (index + 1).to_string()),
                ]));
            }
        }
    }
    let selection_bytes = object(&[
        ("schema", string(QUERY_SCHEMA)),
        ("session", string("session:clock-handoffs")),
        (
            "generation",
            d(ContentDigest::sha256(b"clock handoff analysis generation")),
        ),
        ("cost_unit", string("declared_cost")),
        ("birth_cost", "10".into()),
        ("end_cost", "10".into()),
        ("k", "2".into()),
        ("selections", array(&selections)),
        (
            "transitions",
            array(&[object(&[
                ("from", string("a")),
                ("to", string("b")),
                ("transit", "[1000000000,3000000000]".into()),
                ("cost", "1".into()),
                (
                    "basis",
                    d(ContentDigest::sha256(b"declared transit bounds")),
                ),
            ])]),
        ),
        (
            "clock_validation",
            object(&[
                ("query_path", string("clock.json")),
                ("query_digest", d(ContentDigest::sha256(CLOCK))),
                ("world_basis", d(clock.world_basis())),
                ("reference", sources[0].clone()),
                ("target", sources[1].clone()),
                ("projections", array(&projections)),
            ]),
        ),
    ])
    .into_bytes();
    let request = parse_query(&selection_bytes)?;
    let projection = PackageHandoffProjection::read(&deployment, request.source_request(), &cx)?;
    Ok(Fixture {
        directory,
        cx,
        deployment,
        request,
        projection,
        selection_bytes,
    })
}

#[test]
fn native_custody_clock_replay_and_solver_use_separate_complete_time_projections() -> Test {
    let f = fixture()?;
    let source_bytes = f.projection.encoded().to_vec();
    let source_query = f.projection.query().clone();
    let mut work = WorkBudget::new(continuity_query::MAX_WORK);
    let report = f.report(&mut work, retained::MAX_REPORT_BYTES)?;
    if let Some(directory) = std::env::var_os("FSS_HANDOFF_CLOCK_FIXTURE_DIR") {
        let directory = PathBuf::from(directory);
        fs::create_dir_all(&directory)?;
        fs::write(
            directory.join("native_handoff_clock_report.json"),
            format!("{report}\n"),
        )?;
        fs::write(
            directory.join("native_handoff_clock_selection.json"),
            &f.selection_bytes,
        )?;
        fs::write(directory.join("clock.json"), CLOCK)?;
    }
    let value = json_input::parse(&report)?;
    let value = value.object().ok_or("report")?;
    assert_eq!(value["schema"].text(), Some(REPORT_SCHEMA));
    assert_eq!(value["clock_activated"].boolean(), Some(false));
    assert_eq!(
        value["clock_observation_custody_verified"].boolean(),
        Some(false)
    );
    assert!(report.contains("identity_mapping_preserves_original_local_capture_only"));
    let clock = value["clock_validation"].object().ok_or("clock report")?;
    let original = clock["original_query_json"]
        .text()
        .ok_or("exact original query")?;
    assert_eq!(original.as_bytes(), CLOCK);
    assert_eq!(
        clock["query_digest"].text(),
        Some(
            ContentDigest::sha256(original.as_bytes())
                .to_text()
                .as_str()
        )
    );
    let rows = value["derived_clock_bindings"]
        .array()
        .ok_or("mapped bindings")?;
    assert_eq!(rows.len(), 2);
    for row in rows {
        let row = row.object().ok_or("mapped row")?;
        let observations = row["observations"].array().ok_or("observations")?;
        assert_eq!(observations.len(), 3);
        for observation in observations {
            let observation = observation.object().ok_or("observation")?;
            if row["id"].text() == Some("a") {
                assert_eq!(
                    observation["original_capture_ns"],
                    observation["common_capture_ns"]
                );
            } else {
                assert_ne!(
                    observation["original_capture_ns"],
                    observation["common_capture_ns"]
                );
                assert!(observation["projection_id"].integer().is_some());
            }
        }
    }
    assert_eq!(source_bytes, f.projection.encoded());
    assert_eq!(&source_query, f.projection.query());
    assert_eq!(value["work_used"].integer(), Some(i128::from(work.used())));
    let reads = f.projection.source_bytes_read();
    f.projection.revalidate(&f.deployment, &f.cx)?;
    assert!(f.projection.source_bytes_read() > reads);
    Ok(())
}

#[test]
fn unsupported_candidates_stay_in_hulls_and_can_remove_an_optimistic_transit_edge() -> Test {
    let f = fixture()?;
    let mut work = WorkBudget::new(continuity_query::MAX_WORK);
    let replay = prepare_clock(&f.request, CLOCK, &mut work)?;
    assert_eq!(replay.report().support.len(), 3);
    assert_eq!(
        replay
            .report()
            .support
            .iter()
            .filter(|s| s.supported_in_every_session())
            .count(),
        1
    );
    let (mut query, mapped) = derive(&f.request, f.source_input(), &replay, &mut work)?;
    let target = mapped.iter().find(|t| t.id == "b").ok_or("target")?;
    for observed in &target.observations {
        let p = replay
            .report()
            .projections
            .iter()
            .find(|p| Some(p.request.id) == observed.projection)
            .ok_or("projection")?;
        assert_eq!(p.mappings.len(), 3);
        assert_eq!(observed.common.map(i128::from), p.reference_envelope_ns);
    }
    let supported = replay
        .report()
        .support
        .iter()
        .find(|s| s.supported_in_every_session())
        .ok_or("supported trial")?
        .hypothesis;
    let first = &replay.report().projections[0];
    let favorable = first
        .mappings
        .iter()
        .find(|m| m.0 == supported)
        .ok_or("mapping")?
        .1;
    let left = query
        .tracklets
        .iter()
        .find(|t| t.id == "a")
        .ok_or("reference track")?
        .end;
    query.transitions[0].transit = [
        u64::try_from(favorable[0] - i128::from(left[1]))?,
        u64::try_from(favorable[1] - i128::from(left[0]))?,
    ];
    let result = continuity::plan(
        &query,
        Budget::new(work.remaining(), continuity_query::MAX_OUTPUT_ENTRIES),
    )?;
    assert!(
        result.output.family.edges.is_empty(),
        "the full hull must refuse a favored-candidate-only transit"
    );
    let mut favorable_query = query.clone();
    favorable_query
        .tracklets
        .iter_mut()
        .find(|t| t.id == "b")
        .ok_or("target track")?
        .start = [i64::try_from(favorable[0])?, i64::try_from(favorable[1])?];
    let favorable_result = continuity::plan(
        &favorable_query,
        Budget::new(work.remaining(), continuity_query::MAX_OUTPUT_ENTRIES),
    )?;
    assert_eq!(favorable_result.output.family.edges.len(), 1);
    Ok(())
}

#[test]
fn every_interior_target_capture_and_complete_projection_inventory_are_required() -> Test {
    let f = fixture()?;
    let mut work = WorkBudget::new(continuity_query::MAX_WORK);
    let replay = prepare_clock(&f.request, CLOCK, &mut work)?;
    let mut request = f.request.clone();
    let middle = f
        .projection
        .bindings()
        .iter()
        .find(|b| b.id == "b")
        .ok_or("target")?
        .observations[1]
        .capsule_digest;
    request.projections.retain(|p| p.capsule != middle);
    assert!(derive(&request, f.source_input(), &replay, &mut work).is_err());
    request = f.request.clone();
    request.projections[0].capsule = ContentDigest::sha256(b"another capsule");
    assert!(derive(&request, f.source_input(), &replay, &mut work).is_err());
    let mut bindings = f.projection.bindings().to_vec();
    let target = bindings.iter_mut().find(|b| b.id == "b").ok_or("target")?;
    target.observations[1].capture[1] += 1;
    target.observations[1].aligned_capture[1] += 1;
    let query =
        contract::continuity_query(f.projection.anchor(), f.request.source_request(), &bindings)?;
    let source = RetainedReportInput {
        bindings: &bindings,
        query: &query,
        ..f.source_input()
    };
    assert!(
        matches!(derive(&f.request, source, &replay, &mut work), Err(QueryError::Input(why)) if why.contains("entire actual"))
    );
    Ok(())
}

#[test]
fn reordered_interior_capture_cannot_hide_outside_the_track_endpoints() -> Test {
    let f = fixture()?;
    let mut work = WorkBudget::new(continuity_query::MAX_WORK);
    let replay = prepare_clock(&f.request, CLOCK, &mut work)?;
    let mut bindings = f.projection.bindings().to_vec();
    let reference = bindings
        .iter_mut()
        .find(|b| b.id == "a")
        .ok_or("reference")?;
    reference.observations[1].capture = [4_000_000_000, 4_001_000_000];
    reference.observations[1].aligned_capture = [4_000_000_000, 4_001_000_000];
    let query =
        contract::continuity_query(f.projection.anchor(), f.request.source_request(), &bindings)?;
    let source = RetainedReportInput {
        bindings: &bindings,
        query: &query,
        ..f.source_input()
    };
    assert!(
        matches!(derive(&f.request, source, &replay, &mut work), Err(QueryError::Input(why)) if why.contains("reordered"))
    );
    Ok(())
}

#[test]
fn original_query_scope_image_mode_and_exact_source_identity_cannot_be_substituted() -> Test {
    let f = fixture()?;
    for mutate in 0..6 {
        let mut request = f.request.clone();
        match mutate {
            0 => request.world = ContentDigest::sha256(b"foreign world"),
            1 => request.streams[1].camera += 10,
            2 => request.streams[1].clock += 10,
            3 => request.streams[1].calibration = ContentDigest::sha256(b"foreign calibration"),
            4 => request.streams[1].image_domain = ContentDigest::sha256(b"foreign image"),
            _ => request.query_digest = ContentDigest::sha256(b"wrong original bytes"),
        }
        assert!(
            prepare_clock(
                &request,
                CLOCK,
                &mut WorkBudget::new(continuity_query::MAX_WORK)
            )
            .is_err()
        );
    }
    let mut work = WorkBudget::new(continuity_query::MAX_WORK);
    let replay = prepare_clock(&f.request, CLOCK, &mut work)?;
    for mutate in 0..4 {
        let mut request = f.request.clone();
        match mutate {
            0 => request.streams[1].sensor = "sensor:foreign".into(),
            1 => request.streams[1].stream = "stream:foreign".into(),
            2 => request.streams[1].basis = ClockBasis::DeviceMonotonic,
            _ => request.streams[1].import = ContentDigest::sha256(b"foreign import"),
        }
        assert!(derive(&request, f.source_input(), &replay, &mut work).is_err());
    }
    Ok(())
}

#[test]
fn shared_work_cancellation_and_complete_output_bounds_fail_without_a_success_prefix() -> Test {
    let f = fixture()?;
    assert!(
        f.report(&mut WorkBudget::new(1), retained::MAX_REPORT_BYTES)
            .is_err()
    );
    assert!(matches!(
        f.report(&mut WorkBudget::new(continuity_query::MAX_WORK), 1024),
        Err(QueryError::ReportLimit)
    ));
    let mut measured = WorkBudget::new(continuity_query::MAX_WORK);
    f.report(&mut measured, retained::MAX_REPORT_BYTES)?;
    assert!(
        f.report(
            &mut WorkBudget::new(measured.used() / 2),
            retained::MAX_REPORT_BYTES
        )
        .is_err()
    );
    let cancelled = AtomicBool::new(false);
    let probe = || cancelled.load(Ordering::SeqCst);
    let mut work = WorkBudget::with_cancellation_probe(continuity_query::MAX_WORK, &probe);
    let replay = prepare_clock(&f.request, CLOCK, &mut work)?;
    cancelled.store(true, Ordering::SeqCst);
    assert!(matches!(
        derive(&f.request, f.source_input(), &replay, &mut work),
        Err(QueryError::Cancelled)
    ));
    assert!(replay.render(&mut work).is_err());
    assert!(matches!(
        analyze(
            ClockReportInput {
                request: &f.request,
                projection: &f.projection,
                clock_query: CLOCK
            },
            &mut work,
            retained::MAX_REPORT_BYTES,
            &probe
        ),
        Err(QueryError::Cancelled)
    ));
    Ok(())
}

#[test]
fn v2_is_explicit_strict_and_cannot_inject_offset_or_capture_values() -> Test {
    let f = fixture()?;
    assert!(retained::parse_query(&f.selection_bytes).is_err());
    let selection = std::str::from_utf8(&f.selection_bytes)?;
    for added in [
        "\"offset_ns\":[0,0],",
        "\"capture\":[1,2],",
        "\"clock\":\"caller\",",
    ] {
        let changed = selection.replacen('{', &format!("{{{added}"), 1);
        assert!(parse_query(changed.as_bytes()).is_err());
    }
    let v1 =
        include_bytes!("../../../../tests/fixtures/continuity/retained_package_selection.json");
    assert!(retained::parse_query(v1).is_ok());
    assert!(parse_query(v1).is_err());
    let duplicate = selection.replace("\"source\":\"target\"", "\"source\":\"reference\"");
    assert!(parse_query(duplicate.as_bytes()).is_err());
    Ok(())
}
