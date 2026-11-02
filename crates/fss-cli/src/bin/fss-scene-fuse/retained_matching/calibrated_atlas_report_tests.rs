#![forbid(unsafe_code)]
//! Native association/archive checks for the pure adopted-atlas envelope.
//!
//! Source/calibration JSON below is an explicitly synthetic opaque serializer input. These
//! tests establish exact-byte preservation and resource semantics, not retained authority or
//! source custody; the real command-owner tests exercise those independent boundaries.

use std::cell::Cell;
use std::error::Error;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use fss_cli::json_input::{Value, parse, parse_reconstruction_atlas_report};
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use fss_geometry::temporal_triangulation::TemporalTriangulationOptions;
use fss_geometry::triangulation::TriangulationOptions;
use fss_geometry::{PinholeIntrinsics, RigidPose};
use fss_twin::atlas_archive::{ArchiveExpectation, decode_atlas, encode_atlas};
use fss_twin::feature_association::{
    AssociationOptions, FeatureAssociation, FeatureHypothesisOutcome, FeatureView,
    associate_features,
};
use fss_twin::localization::native::ExtractionOptions;
use fss_twin::localization::{BinaryDescriptor, FeatureFrame, ImageFeature, ImageIdentity};
use fss_twin::multiview_feature_association::{
    ComponentOutcome, MultiFeatureAssociation, associate_multiview_features,
};
use fss_twin::reconstruction_atlas::{
    AtlasBuildRequest, LandmarkSelection, ReconstructedAtlas, Reconstruction, ReferenceSource,
    build_reconstruction_atlas,
};
use fss_twin::rectification::{
    LensDistortion, LumaRange, RawFrameIdentity, RawGrayFrame, RectificationPlan,
    RectificationSpec, extract_raw_features,
};
use fss_twin::temporal_feature_association::{
    TemporalAssociationOptions, TemporalComponentOutcome, associate_temporal_features,
};
use fss_twin::{ImportExpectation, ImportLimits, TrackingCamera, import_twin};

use super::*;

type Test<T = ()> = std::result::Result<T, Box<dyn Error>>;
const WORK: u64 = 1_000_000_000;
const JSON_BYTES: usize = 32 * 1024 * 1024;

fn checked<T>(result: Result<T>) -> Test<T> {
    result.map_err(|error| format!("adopted atlas report: {error:?}").into())
}

fn h(bytes: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::sha256(bytes.as_ref())
}

fn field<'a>(value: &'a Value, path: &[&str]) -> Test<&'a Value> {
    let Some((key, remaining)) = path.split_first() else {
        return Ok(value);
    };
    let child = match value {
        Value::Object(values) => values.get(*key),
        Value::Array(values) => values.get(key.parse::<usize>()?),
        _ => None,
    }
    .ok_or("missing fixture JSON field")?;
    field(child, remaining)
}

fn package() -> Vec<u8> {
    fn text(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    let mut body = h("synthetic authored CLI scene").bytes().to_vec();
    text(&mut body, "synthetic_cli_scene");
    text(&mut body, "fixture_epoch");
    body.push(0);
    for number in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&number.to_le_bytes());
    }
    for number in [1_u32, 1, 3, 1] {
        body.extend_from_slice(&number.to_le_bytes());
    }
    text(&mut body, "wall");
    body.push(5);
    text(&mut body, "wall");
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[0, 0]);
    for point in [
        [-10.0_f64, -10.0, 4.0],
        [10.0, -10.0, 4.0],
        [0.0, 10.0, 4.0],
    ] {
        for value in point {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    for number in [0_u32, 1, 2, 0] {
        body.extend_from_slice(&number.to_le_bytes());
    }
    let mut bytes = b"FSSTWIN1".to_vec();
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend(body);
    bytes.extend_from_slice(&h(&bytes).bytes());
    bytes
}

enum Native {
    Pair(Box<FeatureAssociation>),
    Multi(Box<MultiFeatureAssociation>),
}
impl Native {
    fn reconstruction(&self) -> Reconstruction<'_> {
        match self {
            Self::Pair(value) => Reconstruction::Pair(value),
            Self::Multi(value) => Reconstruction::Multiview(value),
        }
    }
    fn evidence(&self) -> [u8; 32] {
        match self {
            Self::Pair(value) => value.evidence(),
            Self::Multi(value) => value.evidence(),
        }
    }
}

struct Fixture {
    twin: PropertyTwin,
    built: ReconstructedAtlas,
    geometry: String,
    records: Vec<String>,
    entry: LedgerAnchor,
    anchor: LedgerAnchor,
}

fn fixture(cameras: usize) -> Test<Fixture> {
    let bytes = package();
    let twin = import_twin(
        &bytes,
        ImportExpectation {
            package_sha256: h(&bytes).bytes(),
            source_scene_sha256: h(b"synthetic authored CLI scene").bytes(),
            basis: GeometryBasis::new(7, 2)?,
        },
        ImportLimits::default(),
        &mut WorkBudget::new(WORK),
    )?;
    let mut views = Vec::new();
    let mut sources = Vec::new();
    let mut records = Vec::new();
    for ordinal in 0..cameras {
        let camera = ordinal as u64 + 1;
        let center = if ordinal == 2 {
            [0.0, 1.0, 0.0]
        } else {
            [ordinal as f64 * 2.0 - 1.0, 0.0, 0.0]
        };
        // These camera observations come from an independent scalar projection.
        let features = [[0.2, 0.3, 10.0], [2.0, 1.5, 12.0]]
            .into_iter()
            .enumerate()
            .map(|(index, world)| ImageFeature {
                id: index as u64 + 1,
                pixel: [
                    120.0 * (world[0] - center[0]) / world[2] + 96.0,
                    120.0 * (world[1] - center[1]) / world[2] + 64.0,
                ],
                descriptor: BinaryDescriptor([if index == 0 { 0 } else { u64::MAX }; 4]),
            })
            .collect();
        let domain = h(format!("exact-image-{camera}")).bytes();
        views.push(FeatureView {
            frame: FeatureFrame::new(
                ImageIdentity {
                    exposure: h(format!("original-exposure-{camera}")).bytes(),
                    pixels: h(format!("actual-feature-pixels-{camera}")).bytes(),
                    image_domain: domain,
                    dimensions: [192, 128],
                },
                h("native descriptor fixture").bytes(),
                features,
                &mut WorkBudget::new(WORK),
            )?,
            camera: TrackingCamera {
                geometry: twin.basis(),
                camera,
                calibration: camera + 100,
                image_domain: camera + 200,
                clock: 11,
                validity: [0, u64::MAX],
                pose: RigidPose::from_center(
                    [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
                    center,
                )?,
                intrinsics: PinholeIntrinsics::new(192, 128, 120.0, 120.0, 96.0, 64.0)?,
                error: None,
            },
            source_digest: h(format!("source-{camera}")).bytes(),
            allowed_mask_digest: h(format!("mask-{camera}")).bytes(),
            image_domain_digest: domain,
            mapping_basis: h(format!("mapping-{camera}")).bytes(),
            privacy_domain: 9,
            clock_evidence: h("common declared clock").bytes(),
            capture: [90, 110],
            sigma_pixels: 0.25,
        });
        // Opaque test-only records are never asserted to be a resolved retained owner.
        let record = object(&[
            ("test_only_source", count(camera)),
            (
                "literal",
                string("unchanged \"quoted\" bytes\nwith a control escape"),
            ),
        ]);
        let digest = h(record.as_bytes());
        sources.push(ReferenceSource {
            camera,
            source_record: digest.bytes(),
        });
        records.push(object(&[
            ("camera", count(camera)),
            ("record_digest", string(&digest.to_text())),
            ("record", record),
        ]));
    }
    let options = AssociationOptions {
        association_basis: h("declared static correspondence").bytes(),
        camera_rig_digest: h("exact rig document").bytes(),
        privacy_domain: 9,
        clock: 11,
        clock_evidence: h("common declared clock").bytes(),
        reference_time_ns: 100,
        max_capture_span_ns: 30,
        maximum_hamming_distance: 0,
        ratio_percent: 80,
        maximum_epipolar_distance_pixels: 0.01,
        triangulation: TriangulationOptions::default(),
    };
    let native = if cameras == 2 {
        Native::Pair(Box::new(associate_features(
            &twin,
            [&views[0], &views[1]],
            options,
            &mut WorkBudget::new(WORK),
        )?))
    } else {
        Native::Multi(Box::new(associate_multiview_features(
            &twin,
            &views,
            options,
            &mut WorkBudget::new(WORK),
        )?))
    };
    let pins = match &native {
        Native::Pair(value) => value
            .hypotheses()
            .iter()
            .map(|value| value.evidence)
            .collect::<Vec<_>>(),
        Native::Multi(value) => value
            .components()
            .iter()
            .map(|value| value.evidence())
            .collect::<Vec<_>>(),
    };
    let selections = pins
        .into_iter()
        .enumerate()
        .map(|(index, hypothesis)| LandmarkSelection {
            hypothesis,
            landmark: index as u64 + 1,
            physical_group: index as u64 + 101,
            feature: 0,
            enduring_static_basis: h(format!("explicit enduring-static declaration {index}"))
                .bytes(),
        })
        .collect::<Vec<_>>();
    let built = build_reconstruction_atlas(
        &twin,
        &AtlasBuildRequest {
            association_evidence: native.evidence(),
            selections: &selections,
            references: &sources,
        },
        native.reconstruction(),
        &mut WorkBudget::new(WORK),
    )?;
    let geometry = checked(atlas_report::geometry(
        native.reconstruction(),
        JSON_BYTES,
        &mut WorkBudget::new(WORK),
    ))?;
    let entry = LedgerAnchor::genesis("site:pure-adopted-atlas-report");
    let mut anchor = entry.clone();
    anchor.commit_sequence = 7;
    anchor.state_root = h("current authority snapshot fixture");
    Ok(Fixture {
        twin,
        built,
        geometry,
        records,
        entry,
        anchor,
    })
}

impl Fixture {
    fn input(&self) -> ManifestInput<'_> {
        ManifestInput {
            rectification: false,
            twin: &self.twin,
            geometry_basis: (7, 2),
            rig_digest: h("exact rig document"),
            rig_semantic_digest: h("sealed semantic rig fixture"),
            rig_declarations: "{\"test_only_rig\":true}",
            query_digest: h("exact query document"),
            query_declarations: "{\"test_only_query\":true}",
            selection_digest: h("exact selection document"),
            selection_declarations: "{\"test_only_selection\":true}",
            entry_anchor: &self.entry,
            anchor: &self.anchor,
            calibration: "{\"test_only_calibration_fragment\":true,\"escaped\":\"line\\nquoted\\\"\"}",
            source_records: &self.records,
            geometry: &self.geometry,
            build: self.built.receipt(),
        }
    }
    fn manifest(&self, work: &mut WorkBudget<'_>) -> Result<Manifest> {
        manifest(&self.input(), JSON_BYTES, work)
    }
    fn archive(&self, manifest: &Manifest) -> Test<(Vec<u8>, ArchiveSummary)> {
        let bytes = encode_atlas(
            self.built.atlas(),
            manifest.digest.bytes(),
            self.built.references(),
            &mut WorkBudget::new(WORK),
        )?;
        let summary = ArchiveSummary {
            package_digest: h(&bytes),
            atlas_digest: self.built.atlas().digest(),
            descriptor_digest: self.built.atlas().references()[0].frame.descriptor_domain(),
            bytes: bytes.len(),
            landmarks: self.built.atlas().landmarks().len(),
            references: self.built.atlas().references().len(),
            bindings: self.built.atlas().bindings().len(),
        };
        Ok((bytes, summary))
    }
}

fn cost(used: u64) -> String {
    object(&[("test_only_geometry_used", count(used))])
}

#[test]
fn native_pair_and_joint_admissions_keep_all_manifest_geometry_and_unknown_error() -> Test {
    for cameras in [2, 3] {
        let fixture = fixture(cameras)?;
        let input = fixture.input();
        let result = checked(fixture.manifest(&mut WorkBudget::new(WORK)))?;
        assert_eq!(result.digest, h(result.json.as_bytes()));
        let parsed = parse(&result.json)?;
        assert_eq!(field(&parsed, &["schema"])?.text(), Some(MANIFEST_SCHEMA));
        assert_eq!(
            field(&parsed, &["calibration"])?,
            &parse(input.calibration)?
        );
        assert_eq!(
            field(&parsed, &["rig_declarations"])?,
            &parse(input.rig_declarations)?
        );
        assert_eq!(field(&parsed, &["geometry"])?, &parse(&fixture.geometry)?);
        assert_eq!(
            field(&parsed, &["source_records"])?
                .array()
                .ok_or("records")?
                .len(),
            cameras
        );
        assert_eq!(
            field(&parsed, &["atlas_build", "sources"])?
                .array()
                .ok_or("sources")?
                .len(),
            cameras
        );
        assert_eq!(
            field(&parsed, &["atlas_build", "landmarks"])?
                .array()
                .ok_or("landmarks")?
                .len(),
            2
        );
        for landmark in fixture.built.atlas().landmarks() {
            assert!(landmark.error.is_none());
        }
        assert_eq!(result.references, cameras);
        assert_eq!(result.bindings, 2 * cameras);
    }
    Ok(())
}

#[test]
fn exact_manifest_survives_fs_atlas_roundtrip_and_report_hash_uses_original_body_bytes() -> Test {
    let fixture = fixture(3)?;
    let mut work = WorkBudget::new(WORK);
    let manifest = checked(fixture.manifest(&mut work))?;
    let original = manifest.json.clone();
    let provenance = manifest.digest;
    let (archive, summary) = fixture.archive(&manifest)?;
    let loaded = decode_atlas(
        &archive,
        &fixture.twin,
        ArchiveExpectation {
            package: summary.package_digest.bytes(),
            provenance: provenance.bytes(),
            descriptor: summary.descriptor_digest,
        },
        &mut WorkBudget::new(WORK),
    )?;
    assert_eq!(loaded.atlas().digest(), summary.atlas_digest);
    let result = checked(finish(manifest, summary, cost, JSON_BYTES, &mut work))?;
    let parsed = parse_reconstruction_atlas_report(&result)?;
    assert_eq!(
        field(&parsed, &["report", "provenance_manifest_utf8"])?.text(),
        Some(original.as_str())
    );
    assert_eq!(
        field(&parsed, &["report", "archive", "provenance_digest"])?.text(),
        Some(provenance.to_text().as_str())
    );
    // The outer serializer places its complete body last. Reparse/recanonicalization is not
    // used for this oracle; field reordering would otherwise accidentally validate bad hashes.
    let body = result
        .split_once(",\"report\":")
        .ok_or("exact report body")?
        .1
        .strip_suffix('}')
        .ok_or("outer object end")?;
    assert_eq!(
        field(&parsed, &["report_digest"])?.text(),
        Some(h(body.as_bytes()).to_text().as_str())
    );
    assert_eq!(
        field(&parsed, &["report", "cost", "test_only_geometry_used"])?.text(),
        Some(work.used().to_string().as_str())
    );
    Ok(())
}

#[test]
fn deterministic_manifests_bind_calibration_declarations_source_bytes_and_final_anchor() -> Test {
    let fixture = fixture(2)?;
    let baseline = checked(fixture.manifest(&mut WorkBudget::new(WORK)))?;
    assert_eq!(
        checked(fixture.manifest(&mut WorkBudget::new(WORK)))?.json,
        baseline.json
    );
    let changed_calibration = "{\"test_only_calibration_fragment\":false}";
    let changed_rig = "{\"test_only_rig\":false}";
    let mut changed_records = fixture.records.clone();
    changed_records[0] = changed_records[0].replace("unchanged", "changed");
    let mut changed_anchor = fixture.anchor.clone();
    changed_anchor.commit_sequence += 1;
    changed_anchor.state_root = h("different current authority");
    for index in 0..4 {
        let mut input = fixture.input();
        match index {
            0 => input.calibration = changed_calibration,
            1 => input.rig_declarations = changed_rig,
            2 => input.source_records = &changed_records,
            _ => input.anchor = &changed_anchor,
        }
        let changed = checked(manifest(&input, JSON_BYTES, &mut WorkBudget::new(WORK)))?;
        assert_ne!(changed.digest, baseline.digest);
    }
    Ok(())
}

#[test]
fn manifest_refuses_cross_twin_basis_incomplete_views_and_incompatible_anchor_history() -> Test {
    let fixture = fixture(3)?;
    let mut other_anchor = fixture.anchor.clone();
    other_anchor.ledger_epoch += 1;
    let mut wrong_receipt = fixture.built.receipt().clone();
    wrong_receipt.twin_digest = h("foreign twin").bytes();
    for index in 0..5 {
        let mut input = fixture.input();
        match index {
            0 => input.geometry_basis.1 += 1,
            1 => input.source_records = &fixture.records[..2],
            2 => input.anchor = &other_anchor,
            3 => input.build = &wrong_receipt,
            _ => input.entry_anchor = &fixture.anchor,
        }
        if index == 4 {
            input.anchor = &fixture.entry;
        }
        assert!(manifest(&input, JSON_BYTES, &mut WorkBudget::new(WORK)).is_err());
    }
    Ok(())
}

#[test]
fn archive_summary_cannot_replace_semantic_descriptor_or_membership_pins() -> Test {
    let fixture = fixture(2)?;
    for index in 0..6 {
        let manifest = checked(fixture.manifest(&mut WorkBudget::new(WORK)))?;
        let (_, mut summary) = fixture.archive(&manifest)?;
        match index {
            0 => summary.atlas_digest = h("foreign atlas").bytes(),
            1 => summary.descriptor_digest = h("foreign descriptors").bytes(),
            2 => summary.landmarks += 1,
            3 => summary.references += 1,
            4 => summary.bindings += 1,
            _ => summary.bytes = MAX_ATLAS_BYTES + 1,
        }
        let called = Cell::new(false);
        assert!(
            finish(
                manifest,
                summary,
                |_| {
                    called.set(true);
                    cost(0)
                },
                JSON_BYTES,
                &mut WorkBudget::new(WORK)
            )
            .is_err()
        );
        assert!(!called.get());
    }
    Ok(())
}

#[test]
fn manifest_output_cap_never_discounts_complete_native_inventory_work() -> Test {
    let fixture = fixture(3)?;
    let mut baseline = WorkBudget::new(WORK);
    let result = checked(fixture.manifest(&mut baseline))?;
    let mut tiny = WorkBudget::new(WORK);
    assert!(manifest(&fixture.input(), 1, &mut tiny).is_err());
    assert_eq!(tiny.used(), baseline.used());
    assert!(
        manifest(
            &fixture.input(),
            result.json.len(),
            &mut WorkBudget::new(WORK)
        )
        .is_err()
    );
    assert!(
        manifest(
            &fixture.input(),
            result.json.len() + 1,
            &mut WorkBudget::new(WORK)
        )
        .is_ok()
    );
    assert!(
        fixture
            .manifest(&mut WorkBudget::new(baseline.used()))
            .is_ok()
    );
    assert!(
        fixture
            .manifest(&mut WorkBudget::new(baseline.used() - 1))
            .is_err()
    );
    Ok(())
}

#[test]
fn final_cost_observes_all_charged_serialization_and_output_cap_is_inclusive() -> Test {
    let fixture = fixture(2)?;
    let create = || -> Test<_> {
        let manifest = checked(fixture.manifest(&mut WorkBudget::new(WORK)))?;
        let (_, summary) = fixture.archive(&manifest)?;
        Ok((manifest, summary))
    };
    let (manifest, summary) = create()?;
    let seen = Cell::new(0);
    let mut work = WorkBudget::new(WORK);
    let result = checked(finish(
        manifest,
        summary,
        |used| {
            seen.set(used);
            cost(used)
        },
        JSON_BYTES,
        &mut work,
    ))?;
    assert_eq!(seen.get(), work.used());
    assert!(work.used() > 262_144);
    for limit in [1, result.len()] {
        let (manifest, summary) = create()?;
        let mut limited = WorkBudget::new(WORK);
        assert!(finish(manifest, summary, cost, limit, &mut limited).is_err());
        assert_eq!(limited.used(), work.used());
    }
    let (manifest, summary) = create()?;
    assert!(
        finish(
            manifest,
            summary,
            cost,
            result.len() + 1,
            &mut WorkBudget::new(work.used())
        )
        .is_ok()
    );
    let (manifest, summary) = create()?;
    let called = Cell::new(false);
    assert!(
        finish(
            manifest,
            summary,
            |_| {
                called.set(true);
                cost(0)
            },
            JSON_BYTES,
            &mut WorkBudget::new(work.used() - 1)
        )
        .is_err()
    );
    assert!(!called.get());
    Ok(())
}

#[test]
fn final_cost_is_bounded_and_cancellation_during_cost_construction_discards_report() -> Test {
    let fixture = fixture(2)?;
    for size in [0, MAX_COST_BYTES + 1] {
        let manifest = checked(fixture.manifest(&mut WorkBudget::new(WORK)))?;
        let (_, summary) = fixture.archive(&manifest)?;
        assert!(
            finish(
                manifest,
                summary,
                |_| " ".repeat(size),
                JSON_BYTES,
                &mut WorkBudget::new(WORK)
            )
            .is_err()
        );
    }
    let manifest = checked(fixture.manifest(&mut WorkBudget::new(WORK)))?;
    let (_, summary) = fixture.archive(&manifest)?;
    let cancelled = AtomicBool::new(false);
    let probe = || cancelled.load(Ordering::SeqCst);
    let result = finish(
        manifest,
        summary,
        |used| {
            cancelled.store(true, Ordering::SeqCst);
            cost(used)
        },
        JSON_BYTES,
        &mut WorkBudget::with_cancellation_probe(WORK, &probe),
    );
    assert!(matches!(result, Err(error) if error.code == "ERR-SCENE-FUSION-CANCELLED-001"));
    Ok(())
}

#[test]
fn early_middle_and_terminal_cancellation_leave_no_complete_manifest() -> Test {
    let fixture = fixture(3)?;
    let probes = AtomicUsize::new(0);
    let count = || {
        probes.fetch_add(1, Ordering::SeqCst);
        false
    };
    checked(fixture.manifest(&mut WorkBudget::with_cancellation_probe(WORK, &count)))?;
    let total = probes.load(Ordering::SeqCst);
    assert!(total >= 4);
    for stop in [1, total / 2, total] {
        let probes = AtomicUsize::new(0);
        let cancelled = || probes.fetch_add(1, Ordering::SeqCst) + 1 >= stop;
        assert!(
            matches!(fixture.manifest(&mut WorkBudget::with_cancellation_probe(WORK, &cancelled)), Err(error) if error.code == "ERR-SCENE-FUSION-CANCELLED-001")
        );
    }
    Ok(())
}

#[test]
fn assumptions_preserve_unknown_error_physical_identity_and_future_privacy_boundaries() -> Test {
    let value = parse(&assumptions())?;
    let rows = value.array().ok_or("assumptions array")?;
    assert_eq!(rows.len(), 17);
    for required in [
        "absolute_landmark_error_remains_unknown_and_is_not_derived_from_pixel_covariance",
        "local_calibration_covariance_is_conditional_and_has_no_cross_camera_covariance_blocks",
        "physical_groups_are_declared_alias_groups_not_authenticated_object_identity",
        "archive_checksums_do_not_grant_source_access_or_establish_future_source_privacy",
        "capture_window_stationarity_does_not_establish_enduring_landmark_stability",
    ] {
        assert!(rows.iter().any(|value| value.text() == Some(required)));
    }
    let strings = rows
        .iter()
        .map(|value| value.text().map(string).ok_or("assumption string"))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    assert_eq!(array(&strings), assumptions());
    Ok(())
}

fn radial_jpegs() -> Test<Vec<Vec<u8>>> {
    [
        include_str!("../../../../tests/fixtures/adopted_radial/camera_0.jpeg.hex"),
        include_str!("../../../../tests/fixtures/adopted_radial/camera_1.jpeg.hex"),
        include_str!("../../../../tests/fixtures/adopted_radial/camera_2.jpeg.hex"),
    ]
    .into_iter()
    .map(|text| {
        let hex = text.split_whitespace().collect::<String>();
        if !hex.len().is_multiple_of(2) {
            return Err("incomplete fixture hex".into());
        }
        hex.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
            .collect()
    })
    .collect()
}

struct RadialImages {
    views: Vec<FeatureView>,
    records: Vec<String>,
    calibration: String,
}

fn radial_images(twin: &PropertyTwin, cameras: usize, masked: bool) -> Test<RadialImages> {
    let mut views = Vec::new();
    let mut records = Vec::new();
    let intrinsics = PinholeIntrinsics::new(192, 128, 160.0, 160.0, 96.0, 64.0)?;
    let mut work = WorkBudget::new(WORK);
    for (index, jpeg) in radial_jpegs()?.into_iter().take(cameras).enumerate() {
        let camera = index as u64 + 1;
        let source_digest = h(&jpeg);
        let spec = RectificationSpec {
            source: intrinsics,
            target: intrinsics,
            distortion: LensDistortion::BrownConrady {
                radial: [-0.08, 0.01, 0.0],
                tangential: [0.0, 0.0],
            },
            maximum_radius: 1.0,
            source_domain: h(format!("authored radial source mode {camera}")).bytes(),
            calibration: h("authored radial FSSCAL identity fixture, not retained authority")
                .bytes(),
            range: LumaRange::Full,
        };
        // Admission precedes decode, as in the sealed owner. The fixture itself remains pure.
        let plan = RectificationPlan::compile(spec, &mut work)?;
        let mapped = plan.source_pixel([12.5, 12.5])?.ok_or("source sample")?;
        assert!((mapped[0] - 12.5).abs() > 1.0, "nontrivial lens fixture");
        let decoded = decode_luma(
            &jpeg,
            source_digest.bytes(),
            ComponentInterpretation::Grayscale,
            DecodeLimits::default(),
            &mut DecodeBudget::new(100_000_000),
        )?;
        assert_eq!(decoded.dimensions(), [192, 128]);
        let mut mask = vec![1; 192 * 128];
        if masked {
            for row in mask.as_chunks_mut::<192>().0 {
                row[82..86].fill(0);
            }
        }
        let identity = RawFrameIdentity {
            exposure: h(format!("native radial original exposure {camera}")).bytes(),
            storage: h(decoded.pixels()).bytes(),
            allowed_mask: h(&mask).bytes(),
            image_domain: spec.source_domain,
            calibration: spec.calibration,
            dimensions: spec.source.dimensions(),
            row_stride: 192,
            range: spec.range,
        };
        let raw = RawGrayFrame::new(identity, decoded.pixels(), &mask, &mut work)?;
        let extracted = extract_raw_features(
            &plan,
            &raw,
            ExtractionOptions {
                threshold: 20,
                maximum_features: 64,
                separation: 6,
            },
            &mut work,
        )?;
        let receipt = extracted.rectification;
        assert_eq!(receipt.output, extracted.result.frame.identity());
        assert_eq!(receipt.source.exposure, receipt.output.exposure);
        assert_eq!(receipt.source.dimensions, receipt.output.dimensions);
        assert_ne!(receipt.source.storage, receipt.output.pixels);
        assert_ne!(receipt.source.image_domain, receipt.output.image_domain);
        if masked {
            assert!(receipt.privacy_rejected > 0);
        }
        let processing = super::super::image_report::processing(
            receipt.output,
            receipt.allowed_mask,
            Some((spec, receipt)),
        );
        println!("FSS_ADOPTED_RADIAL_IMAGE {camera} {processing}");
        let record = object(&[
            ("test_only_source", count(camera)),
            ("encoded_source_digest", string(&source_digest.to_text())),
            ("image_processing", processing),
        ]);
        let record_digest = h(record.as_bytes());
        records.push(object(&[
            ("camera", count(camera)),
            ("record_digest", string(&record_digest.to_text())),
            ("record", record),
        ]));
        views.push(FeatureView {
            frame: extracted.result.frame,
            camera: TrackingCamera {
                geometry: twin.basis(),
                camera,
                calibration: camera + 100,
                image_domain: camera + 200,
                clock: 11,
                validity: [0, u64::MAX],
                pose: RigidPose::from_center(
                    [[1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, 1.0]],
                    [index as f64, 0.0, 0.0],
                )?,
                intrinsics,
                error: None,
            },
            source_digest: source_digest.bytes(),
            allowed_mask_digest: receipt.allowed_mask,
            image_domain_digest: receipt.output.image_domain,
            mapping_basis: h(format!("mapping-{camera}")).bytes(),
            privacy_domain: 9,
            clock_evidence: h("common declared clock").bytes(),
            capture: [90, 110],
            sigma_pixels: 0.5,
        });
    }
    let calibration = object(&[
        ("test_only_calibration_fragment", "true".into()),
        (
            "selected_cameras",
            array(
                &views
                    .iter()
                    .map(|view| {
                        object(&[
                            ("camera", count(view.camera.camera)),
                            ("radial_distortion", "[-0.08,0.01]".into()),
                            ("intrinsics", "[160,160,96,64]".into()),
                            ("dimensions", "[192,128]".into()),
                            (
                                "absolute_calibration_error",
                                object(&[("state", string("unknown"))]),
                            ),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
    ]);
    Ok(RadialImages {
        views,
        records,
        calibration,
    })
}

fn radial_options() -> AssociationOptions {
    AssociationOptions {
        association_basis: h("declared static correspondence").bytes(),
        camera_rig_digest: h("exact rig document").bytes(),
        privacy_domain: 9,
        clock: 11,
        clock_evidence: h("common declared clock").bytes(),
        reference_time_ns: 100,
        max_capture_span_ns: 30,
        maximum_hamming_distance: 64,
        ratio_percent: 75,
        maximum_epipolar_distance_pixels: 1.01,
        triangulation: TriangulationOptions {
            max_reprojection_pixels: 1.01,
            ..TriangulationOptions::default()
        },
    }
}

fn radial_fixture(cameras: usize) -> Test<(Fixture, String)> {
    let bytes = package();
    let twin = import_twin(
        &bytes,
        ImportExpectation {
            package_sha256: h(&bytes).bytes(),
            source_scene_sha256: h(b"synthetic authored CLI scene").bytes(),
            basis: GeometryBasis::new(7, 2)?,
        },
        ImportLimits::default(),
        &mut WorkBudget::new(WORK),
    )?;
    let images = radial_images(&twin, cameras, false)?;
    let native = if cameras == 2 {
        Native::Pair(Box::new(associate_features(
            &twin,
            [&images.views[0], &images.views[1]],
            radial_options(),
            &mut WorkBudget::new(WORK),
        )?))
    } else {
        Native::Multi(Box::new(associate_multiview_features(
            &twin,
            &images.views,
            radial_options(),
            &mut WorkBudget::new(WORK),
        )?))
    };
    let pins = match &native {
        Native::Pair(value) => value
            .hypotheses()
            .iter()
            .filter_map(|row| match &row.outcome {
                FeatureHypothesisOutcome::Fused(point) => {
                    assert!((point.estimate().position[2] - 10.0).abs() < 1.0);
                    Some(row.evidence)
                }
                _ => None,
            })
            .collect::<Vec<_>>(),
        Native::Multi(value) => value
            .components()
            .iter()
            .filter_map(|row| match row.outcome() {
                ComponentOutcome::Fused(point) if row.members().len() == cameras => {
                    assert!((point.estimate().position[2] - 10.0).abs() < 1.0);
                    Some(row.evidence())
                }
                _ => None,
            })
            .collect::<Vec<_>>(),
    };
    println!(
        "FSS_ADOPTED_RADIAL_STATIC cameras={cameras} complete_points={}",
        pins.len()
    );
    assert!(
        pins.len() >= 8,
        "independent distorted-plane correspondences"
    );
    let selections = pins
        .into_iter()
        .enumerate()
        .map(|(index, hypothesis)| LandmarkSelection {
            hypothesis,
            landmark: index as u64 + 1,
            physical_group: index as u64 + 101,
            feature: 0,
            enduring_static_basis: h("declared enduring-static test plane").bytes(),
        })
        .collect::<Vec<_>>();
    let sources = images
        .records
        .iter()
        .enumerate()
        .map(|(index, record)| {
            let value = parse(record)?;
            let pin = field(&value, &["record_digest"])?
                .text()
                .ok_or("source pin")?;
            Ok(ReferenceSource {
                camera: index as u64 + 1,
                source_record: ContentDigest::parse(pin)?.bytes(),
            })
        })
        .collect::<Test<Vec<_>>>()?;
    let built = build_reconstruction_atlas(
        &twin,
        &AtlasBuildRequest {
            association_evidence: native.evidence(),
            selections: &selections,
            references: &sources,
        },
        native.reconstruction(),
        &mut WorkBudget::new(WORK),
    )?;
    let geometry = checked(atlas_report::geometry(
        native.reconstruction(),
        JSON_BYTES,
        &mut WorkBudget::new(WORK),
    ))?;
    let entry = LedgerAnchor::genesis("site:pure-adopted-atlas-report");
    let mut anchor = entry.clone();
    anchor.commit_sequence = 7;
    anchor.state_root = h("current authority snapshot fixture");
    Ok((
        Fixture {
            twin,
            built,
            geometry,
            records: images.records,
            entry,
            anchor,
        },
        images.calibration,
    ))
}

#[test]
fn rectified_v2_keeps_native_radial_jpeg_lineage_and_unknown_error_through_archive() -> Test {
    for cameras in [2, 3] {
        let (fixture, calibration) = radial_fixture(cameras)?;
        let mut input = fixture.input();
        input.rectification = true;
        input.calibration = &calibration;
        let mut work = WorkBudget::new(WORK);
        let manifest = checked(manifest(&input, JSON_BYTES, &mut work))?;
        assert!(manifest.rectification);
        let original = manifest.json.clone();
        let parsed = parse_reconstruction_atlas_report(&original)?;
        assert_eq!(
            field(&parsed, &["schema"])?.text(),
            Some(RECTIFIED_MANIFEST_SCHEMA)
        );
        assert_eq!(field(&parsed, &["calibration"])?, &parse(&calibration)?);
        assert_eq!(
            field(&parsed, &["geometry"])?,
            &parse_reconstruction_atlas_report(&fixture.geometry)?
        );
        assert_eq!(
            field(&parsed, &["assumptions"])?,
            &parse(&rectified_assumptions())?
        );
        for index in 0..cameras {
            let record = field(&parsed, &["source_records", &index.to_string(), "record"])?;
            let processing = field(record, &["image_processing"])?;
            assert_eq!(
                field(processing, &["kind"])?.text(),
                Some("native_rectified")
            );
            assert_eq!(
                field(processing, &["model", "distortion", "radial"])?,
                &parse("[-0.08,0.01,0]")?
            );
            assert_eq!(
                field(processing, &["model", "source_intrinsics"])?,
                field(processing, &["model", "target_intrinsics"])?
            );
            assert_eq!(
                field(processing, &["source", "exposure_digest"])?,
                field(processing, &["output", "exposure_digest"])?
            );
            assert_ne!(
                field(processing, &["source", "image_domain_digest"])?,
                field(processing, &["output", "image_domain_digest"])?
            );
            assert!(field(processing, &["map_digest"])?.text().is_some());
        }
        let provenance = manifest.digest;
        let (archive, summary) = fixture.archive(&manifest)?;
        let loaded = decode_atlas(
            &archive,
            &fixture.twin,
            ArchiveExpectation {
                package: summary.package_digest.bytes(),
                provenance: provenance.bytes(),
                descriptor: summary.descriptor_digest,
            },
            &mut work,
        )?;
        assert!(
            loaded
                .atlas()
                .landmarks()
                .iter()
                .all(|point| point.error.is_none())
        );
        assert_eq!(loaded.references().len(), cameras);
        let output = checked(finish(manifest, summary, cost, JSON_BYTES, &mut work))?;
        let value = parse_reconstruction_atlas_report(&output)?;
        assert_eq!(
            field(&value, &["schema"])?.text(),
            Some(RECTIFIED_REPORT_SCHEMA)
        );
        assert_eq!(
            field(&value, &["report", "schema"])?.text(),
            Some(RECTIFIED_BODY_SCHEMA)
        );
        assert_eq!(
            field(&value, &["report", "provenance_manifest_utf8"])?.text(),
            Some(original.as_str())
        );
        assert_eq!(
            field(&value, &["report", "archive", "provenance_digest"])?.text(),
            Some(h(&original).to_text().as_str())
        );
        let body = output
            .split_once(",\"report\":")
            .ok_or("body")?
            .1
            .strip_suffix('}')
            .ok_or("body end")?;
        assert_eq!(
            field(&value, &["report_digest"])?.text(),
            Some(h(body).to_text().as_str())
        );
    }
    Ok(())
}

#[test]
fn rectified_schema_profile_is_retained_and_cannot_fall_back_to_v1_on_finish() -> Test {
    let fixture = fixture(2)?;
    let direct = checked(fixture.manifest(&mut WorkBudget::new(WORK)))?;
    let mut input = fixture.input();
    input.rectification = true;
    let rectified = checked(manifest(&input, JSON_BYTES, &mut WorkBudget::new(WORK)))?;
    assert_ne!(direct.digest, rectified.digest);
    assert!(!direct.rectification);
    assert!(rectified.rectification);
    let direct_archive = fixture.archive(&direct)?.0;
    let (rectified_archive, summary) = fixture.archive(&rectified)?;
    assert_ne!(h(direct_archive), h(rectified_archive));
    let output = checked(finish(
        rectified,
        summary,
        cost,
        JSON_BYTES,
        &mut WorkBudget::new(WORK),
    ))?;
    assert_eq!(
        field(&parse(&output)?, &["schema"])?.text(),
        Some(RECTIFIED_REPORT_SCHEMA)
    );
    let second = checked(fixture.manifest(&mut WorkBudget::new(WORK)))?;
    assert_eq!(direct.json, second.json);
    assert_eq!(direct.digest, second.digest);
    Ok(())
}

#[test]
fn native_radial_mask_and_repeated_exposure_motion_remain_explicit() -> Test {
    let fixture = fixture(2)?;
    let images = radial_images(&fixture.twin, 2, true)?;
    for record in &images.records {
        let value = parse(record)?;
        assert!(
            field(
                &value,
                &["record", "image_processing", "coverage", "privacy_rejected"]
            )?
            .integer()
            .is_some_and(|v| v > 0)
        );
    }
    let images = radial_images(&fixture.twin, 2, false)?;
    let mut views = Vec::new();
    for original in images.views {
        for ordinal in 0..2 {
            let mut view = original.clone();
            let mut identity = view.frame.identity();
            identity.exposure = h(format!(
                "radial temporal camera {} exposure {ordinal}",
                view.camera.camera
            ))
            .bytes();
            view.frame = FeatureFrame::new(
                identity,
                view.frame.descriptor_domain(),
                view.frame.features().to_vec(),
                &mut WorkBudget::new(WORK),
            )?;
            let time = if ordinal == 0 { 1000 } else { 1_000_001_000 };
            view.capture = [time - 10, time + 10];
            views.push(view);
        }
    }
    let scene = associate_temporal_features(
        &fixture.twin,
        &views,
        TemporalAssociationOptions {
            association_basis: h("declared repeated stationary radial image exposures").bytes(),
            camera_rig_digest: h("exact rig document").bytes(),
            privacy_domain: 9,
            clock: 11,
            clock_evidence: h("common declared clock").bytes(),
            reference_time_ns: 500_001_000,
            max_capture_span_ns: 1_000_000_020,
            max_capture_uncertainty_ns: 20,
            maximum_hamming_distance: 64,
            ratio_percent: 75,
            triangulation: TemporalTriangulationOptions {
                max_reprojection_pixels: 1.01,
                max_speed: 10.0,
                ..TemporalTriangulationOptions::default()
            },
        },
        &mut WorkBudget::new(WORK),
    )?;
    let mut solved = 0;
    for component in scene.components() {
        if let TemporalComponentOutcome::Fused(motion) = component.outcome() {
            assert!((motion.estimate().position[2] - 10.0).abs() < 1.0);
            assert!(
                motion
                    .estimate()
                    .velocity_per_second
                    .iter()
                    .all(|value| value.abs() < 1e-8)
            );
            solved += 1;
        }
    }
    println!(
        "FSS_ADOPTED_RADIAL_TEMPORAL solved={solved} components={}",
        scene.components().len()
    );
    assert!(solved >= 8);
    Ok(())
}

#[test]
fn rectified_assumptions_describe_mixed_modes_and_do_not_invent_precision() -> Test {
    let atlas = parse(&rectified_assumptions())?;
    let atlas = atlas.array().ok_or("atlas assumptions")?;
    assert_eq!(atlas.len(), 23);
    for required in [
        "nonzero_radial_sources_require_native_rectification_and_zero_radial_direct_sources_preserve_the_original_domain",
        "reconstruction_pixel_covariance_excludes_interpolation_correlations_and_lens_parameter_error",
        "current_adoption_is_owner_authority_not_an_independent_physical_calibration_measurement",
    ] {
        assert!(atlas.iter().any(|value| value.text() == Some(required)));
    }
    for kind in ["static_pair", "static_multiview", "temporal"] {
        let value = parse(&super::super::calibrated_report::rectified_assumptions(
            kind,
        ))?;
        let rows = value.array().ok_or("scene assumptions")?;
        assert!(rows.iter().any(|v| v.text() == Some("sigma_pixels_is_declared_on_the_actual_output_grid_and_excludes_interpolation_correlations_and_lens_parameter_error")));
        assert_eq!(
            rows.iter()
                .any(|v| v.text()
                    == Some("motion_is_constant_velocity_over_the_complete_capture_hull")),
            kind == "temporal"
        );
        assert_eq!(
            rows.iter().any(|v| v.text()
                == Some("selected_features_are_stationary_over_the_complete_capture_hull")),
            kind != "temporal"
        );
    }
    assert_eq!(parse(&assumptions())?.array().ok_or("v1")?.len(), 17);
    Ok(())
}
