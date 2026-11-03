#![forbid(unsafe_code)]
//! Real adoption authority and retained JPEGs -> selected FSATLAS1 -> native localization.
//!
//! The fixture cameras and plane are authored numeric controls. A fresh image is
//! independently translated from the actually decoded left JPEG; it is a synthetic
//! camera at x=0.5 on that z=10 plane, not a claim of physically independent footage.

use super::super::calibrated::tests::{AdoptedFixture, preview_json};
use super::super::tests::{checked, context, field, h, json, put};
use super::*;
use crate::matching::fixtures::{HEIGHT, LEFT, WIDTH};
use fss_cli::json_input::{Value, parse, parse_reconstruction_atlas_report as parse_report};
use fss_cli::json_output::{array, object, string};
use fss_cli::retained_continuity_query::anchor_digest;
use fss_codec_mjpeg::{ComponentInterpretation, DecodeBudget, DecodeLimits, decode_luma};
use fss_core::{CanonicalEncode, ContentDigest};
use fss_geometry::{PinholeIntrinsics, PoseSolverOptions, WorkBudget};
use fss_reference::ingest::calibration_adoption::{
    CalibrationSubject, adopt, preview_adoption, retained_adoptions,
};
use fss_reference::ingest::calibration_invalidation::{
    InvalidationReason, InvalidationRequest, invalidate, preview_invalidation,
};
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_reference::{ReferenceDeployment, ReplayCx};
use fss_twin::atlas_archive::{ArchiveExpectation, ArchivedAtlas, decode_atlas, encode_atlas};
use fss_twin::localization::native::{
    ExtractionOptions, GrayImage, ImageLocalizationOptions, descriptor_domain, localize_gray_frame,
};
use fss_twin::localization::{
    ImageIdentity, LocalizationCamera, LocalizationOutcome, MatchOptions as NativeMatchOptions,
};
use fss_twin::{ImportExpectation, ImportLimits, PropertyTwin, import_twin};
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;
const WORK: u64 = 8_000_000_000;
const OUTPUT: usize = 32 * 1024 * 1024;

fn text(value: &Value) -> Test<&str> {
    value.text().ok_or("expected text".into())
}
fn pin(value: &Value) -> Test<ContentDigest> {
    Ok(ContentDigest::parse(text(value)?)?)
}
fn rows<'a>(value: &'a Value, path: &[&str]) -> Test<&'a [Value]> {
    field(value, path)?.array().ok_or("expected rows".into())
}
fn declarations(association: &str, hypotheses: &[String]) -> String {
    object(&[
        ("schema", string("fss.reconstruction_atlas_selection.v1")),
        ("association_evidence", string(association)),
        (
            "landmarks",
            array(
                &hypotheses
                    .iter()
                    .enumerate()
                    .map(|(index, hypothesis)| {
                        object(&[
                            ("hypothesis", string(hypothesis)),
                            ("landmark", (index + 1).to_string()),
                            ("physical_group", (index + 1001).to_string()),
                            ("feature", "0".into()),
                            (
                                "enduring_static_basis",
                                string(&h("explicit authored enduring reference plane").to_text()),
                            ),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
    ])
}

fn export_options(f: &AdoptedFixture, selection: &str) -> Test<Options> {
    let base = &f.base;
    let path = base.directory().join("adopted-atlas-selection.json");
    fs::write(&path, selection)?;
    Ok(Options {
        matching: super::super::Options {
            root: base.options.root.clone(),
            site: base.options.site.clone(),
            principal: base.options.principal.clone(),
            twin: base.options.twin.clone(),
            rig: base.options.rig.clone(),
            query: base.options.query.clone(),
            report_out: Some(base.directory().join("adopted-atlas-report.json")),
            expected_input: base.options.expected_input,
            expected_anchor: Some(anchor_digest(&base.head()?)),
            work: WORK,
            timeout: Duration::from_secs(30),
            report_bytes: OUTPUT,
        },
        selection: path,
        atlas_out: base.directory().join("adopted-reference.fsatlas"),
        expected_selection: Some(h(selection)),
    })
}

/// Select only actual solved points, with complete support from every fixture camera.
/// Using the whole valid set provides real spatial support for the fresh pose consumer.
fn preview(f: &AdoptedFixture) -> Test<Options> {
    let bytes = preview_json(f)?;
    let value = parse_report(&bytes)?;
    let geometry = field(&value, &["report", "analysis", "geometry"])?;
    let diagnostics = field(geometry, &["native_diagnostics"])?;
    let association = text(field(diagnostics, &["scene_evidence"])?)?;
    let multi = text(field(geometry, &["kind"])?)? == "static_multiview";
    let mut hypotheses = Vec::new();
    for row in rows(
        diagnostics,
        &[if multi { "components" } else { "hypotheses" }],
    )? {
        let estimated = field(row, &[if multi { "outcome" } else { "estimate" }, "state"])?.text()
            == Some("estimated");
        if estimated && (!multi || rows(row, &["members"])?.len() == f.base.capsules.len()) {
            hypotheses.push(text(field(row, &["evidence_digest"])?)?.to_owned());
        }
    }
    assert!(hypotheses.len() >= 12, "fixture needs planar pose support");
    assert!(hypotheses.len() <= 128);
    assert!(
        !f.base
            .options
            .report_out
            .as_ref()
            .ok_or("preview output")?
            .exists()
    );
    export_options(f, &declarations(association, &hypotheses))
}

fn dummy_options(f: &AdoptedFixture) -> Test<Options> {
    export_options(
        f,
        &declarations(
            &h("uncomputed adopted association").to_text(),
            &[h("uncomputed adopted point").to_text()],
        ),
    )
}
fn no_outputs(options: &Options) {
    assert!(!options.atlas_out.exists());
    if let Some(path) = &options.matching.report_out {
        assert!(!path.exists());
    }
}
fn refused(options: &Options) {
    let mut stdout = Vec::new();
    assert!(execute(options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    no_outputs(options);
}
fn update_selection(options: &mut Options, document: &Value) -> Test {
    let bytes = json(document);
    fs::write(&options.selection, &bytes)?;
    options.expected_selection = Some(h(bytes));
    Ok(())
}

fn load_export(
    f: &AdoptedFixture,
    options: &Options,
    stdout: &[u8],
) -> Test<(PropertyTwin, ArchivedAtlas, Value)> {
    let exact = std::str::from_utf8(stdout)?;
    let report = parse_report(exact)?;
    assert_eq!(
        field(&report, &["schema"])?.text(),
        Some("fss.reconstruction_atlas_adopted.v1")
    );
    let body = field(&report, &["report"])?;
    assert_eq!(
        field(body, &["schema"])?.text(),
        Some("fss.reconstruction_atlas_adopted_report.v1")
    );
    assert_eq!(field(body, &["outcome"])?.text(), Some("candidate_export"));
    let exact_body = exact
        .trim_end()
        .strip_suffix('}')
        .ok_or("outer wrapper")?
        .split_once(",\"report\":")
        .ok_or("exact report body")?
        .1;
    assert_eq!(pin(field(&report, &["report_digest"])?)?, h(exact_body));
    let manifest_text = text(field(body, &["provenance_manifest_utf8"])?)?;
    let manifest = parse_report(manifest_text)?;
    assert_eq!(
        field(&manifest, &["schema"])?.text(),
        Some("fss.reconstruction_atlas_adopted_provenance.v1")
    );
    let archive = fs::read(&options.atlas_out)?;
    let package = h(&archive);
    let provenance = h(manifest_text);
    assert_eq!(pin(field(body, &["archive", "package_digest"])?)?, package);
    assert_eq!(
        pin(field(body, &["archive", "provenance_digest"])?)?,
        provenance
    );
    assert_eq!(
        field(body, &["archive", "bytes"])?.integer(),
        Some(archive.len() as i128)
    );
    let selection = parse(std::str::from_utf8(&fs::read(&options.selection)?)?)?;
    let landmarks = rows(&selection, &["landmarks"])?.len();
    let references = f.base.capsules.len();
    for (key, count) in [
        ("landmarks", landmarks),
        ("references", references),
        ("bindings", landmarks * references),
    ] {
        assert_eq!(
            field(body, &["archive", key])?.integer(),
            Some(count as i128)
        );
    }
    assert_eq!(
        pin(field(&manifest, &["selection_digest"])?)?,
        h(fs::read(&options.selection)?)
    );
    assert_eq!(
        pin(field(&manifest, &["calibration", "calibration_digest"])?)?,
        f.calibration.digest()?
    );
    assert_eq!(
        pin(field(
            &manifest,
            &["calibration", "calibration_file_digest"]
        )?)?,
        h(fs::read(&f.calibration_path)?)
    );
    let cameras = rows(&manifest, &["calibration", "selected_cameras"])?;
    assert_eq!(cameras.len(), references);
    for camera in cameras {
        assert_eq!(field(camera, &["status"])?.text(), Some("adopted_current"));
        assert_eq!(
            field(camera, &["absolute_calibration_error", "state"])?.text(),
            Some("unknown")
        );
        assert_eq!(rows(camera, &["local_covariance", "matrix"])?.len(), 6);
    }
    assert_eq!(
        field(&manifest, &["geometry", "outcome"])?.text(),
        Some("reconstructed")
    );
    assert_eq!(rows(&manifest, &["source_records"])?.len(), references);
    assert_eq!(
        rows(&manifest, &["atlas_build", "landmarks"])?.len(),
        landmarks
    );
    assert_eq!(
        field(
            body,
            &["cost", "source_bytes", "includes_final_revalidation"]
        )?
        .boolean(),
        Some(true)
    );
    assert!(
        field(body, &["cost", "source_bytes", "used"])?
            .integer()
            .is_some_and(|n| n > 0)
    );

    let rig = parse(std::str::from_utf8(&fs::read(&f.base.options.rig)?)?)?;
    let (package_sha256, source_scene_sha256, basis) =
        checked(super::super::fusion_input::twin_expectation(&rig))?;
    let mut work = WorkBudget::new(WORK);
    let twin = import_twin(
        &fs::read(&f.base.options.twin)?,
        ImportExpectation {
            package_sha256,
            source_scene_sha256,
            basis,
        },
        ImportLimits::default(),
        &mut work,
    )?;
    let loaded = decode_atlas(
        &archive,
        &twin,
        ArchiveExpectation {
            package: package.bytes(),
            provenance: provenance.bytes(),
            descriptor: descriptor_domain(),
        },
        &mut work,
    )?;
    assert_eq!(loaded.atlas().landmarks().len(), landmarks);
    assert_eq!(loaded.atlas().references().len(), references);
    assert_eq!(loaded.atlas().bindings().len(), landmarks * references);
    for point in loaded.atlas().landmarks() {
        assert_eq!(point.error, None);
        assert!((point.world[2] - 10.).abs() < 1e-7);
    }
    for (index, reference) in loaded.references().iter().enumerate() {
        let source = field(&manifest, &["source_records", &index.to_string()])?;
        assert_eq!(
            pin(field(source, &["record_digest"])?)?.bytes(),
            reference.source_record
        );
        let view = field(source, &["record"])?;
        assert_eq!(field(view, &["status"])?.text(), Some("adopted_current"));
        assert_eq!(
            field(view, &["calibration_error", "state"])?.text(),
            Some("unknown")
        );
        let source_pin = pin(field(view, &["source", "encoded_source_digest"])?)?;
        assert!(
            f.base
                .capsules
                .iter()
                .any(|capsule| capsule.source_digest == source_pin)
        );
        assert!(!text(field(view, &["source", "native_receipt_hex"])?)?.is_empty());
    }
    assert_eq!(
        encode_atlas(
            loaded.atlas(),
            loaded.provenance(),
            loaded.references(),
            &mut work
        )?,
        archive
    );
    let output = options
        .matching
        .report_out
        .as_ref()
        .ok_or("report output")?;
    assert_eq!(fs::read(output)?, stdout);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&options.atlas_out, output] {
            assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        }
    }
    Ok((twin, loaded, manifest))
}

fn localize_fresh_image(twin: &PropertyTwin, loaded: &ArchivedAtlas) -> Test {
    let decoded = decode_luma(
        LEFT,
        h(LEFT).bytes(),
        ComponentInterpretation::Grayscale,
        DecodeLimits::default(),
        &mut DecodeBudget::new(100_000_000),
    )?;
    assert_eq!(decoded.dimensions(), [WIDTH, HEIGHT]);
    let width = WIDTH as usize;
    let height = HEIGHT as usize;
    let mut pixels = vec![0; width * height];
    let mut allowed = vec![0; pixels.len()];
    // u' = u - fx*(0.5)/z = u - 8. The vacant right border is disallowed;
    // no image features, correspondences, or solver pose are supplied by the test.
    for row in 0..height {
        let start = row * width;
        pixels[start..start + width - 8]
            .copy_from_slice(&decoded.pixels()[start + 8..start + width]);
        allowed[start..start + width - 8].fill(1);
    }
    let identity = ImageIdentity {
        exposure: h("fresh synthetic camera at x=0.5; distinct exposure").bytes(),
        pixels: h(&pixels).bytes(),
        image_domain: h("fresh fixed pinhole image grid").bytes(),
        dimensions: [WIDTH, HEIGHT],
    };
    assert!(
        loaded
            .atlas()
            .references()
            .iter()
            .all(|reference| reference.frame.identity().exposure != identity.exposure)
    );
    let mut work = WorkBudget::new(WORK);
    let image = GrayImage::new(identity, &pixels, &allowed, &mut work)?;
    let result = localize_gray_frame(
        loaded.atlas(),
        twin,
        &image,
        LocalizationCamera {
            intrinsics: PinholeIntrinsics::new(WIDTH, HEIGHT, 160., 160., 96., 64.)?,
            image_domain: identity.image_domain,
        },
        ImageLocalizationOptions {
            extraction: ExtractionOptions {
                threshold: 20,
                maximum_features: 64,
                separation: 6,
            },
            matching: NativeMatchOptions {
                maximum_distance: 0,
                ratio_percent: 80,
            },
            solving: PoseSolverOptions {
                ransac_trials: 0,
                minimum_inliers: 8,
                minimum_inlier_fraction: 0.99,
                inlier_threshold_px: 0.01,
                ..PoseSolverOptions::default()
            },
        },
        &mut work,
    )?;
    assert!(result.localization.matches.correspondences.len() >= 8);
    let LocalizationOutcome::Candidates(search) = result.localization.outcome else {
        return Err("fresh native pixels did not reach pose candidates".into());
    };
    assert!(search.planar_support().is_some());
    let known = search
        .candidates()
        .iter()
        .find(|candidate| {
            candidate
                .pose()
                .center()
                .into_iter()
                .zip([0.5, 0., 0.])
                .all(|(actual, expected)| (actual - expected).abs() < 1e-5)
        })
        .ok_or("known fresh planar pose missing from explicit alternatives")?;
    assert!(known.rms_px() < 1e-6);
    for (row, expected) in
        known
            .pose()
            .rotation()
            .into_iter()
            .zip([[1., 0., 0.], [0., 1., 0.], [0., 0., 1.]])
    {
        for (actual, expected) in row.into_iter().zip(expected) {
            assert!((actual - expected).abs() < 1e-5);
        }
    }
    Ok(())
}

#[test]
fn current_adopted_stereo_exports_exact_archive_and_localizes_fresh_native_pixels() -> Test {
    let f = AdoptedFixture::pair("adopted-atlas-stereo")?;
    let options = preview(&f)?;
    let mut stdout = Vec::new();
    assert!(checked(execute(&options, &mut stdout))?);
    let (twin, loaded, _) = load_export(&f, &options, &stdout)?;
    localize_fresh_image(&twin, &loaded)?;
    let cx = context(&f.base.options.root)?;
    let deployment = ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
    let history = retained_adoptions(&deployment)?;
    assert_eq!(history.len(), 2);
    assert!(history.values().all(|entries| entries.len() == 1));
    drop(deployment);
    cx.drain_and_finalize();
    Ok(())
}

#[test]
fn adopted_multiview_archive_keeps_complete_triples_and_remains_a_native_localization_input() -> Test
{
    let (base, _) = super::super::multiview::tests::atlas_fixture_preview("adopted-atlas-multi")?;
    let f = AdoptedFixture::from_source(base, true)?;
    let options = preview(&f)?;
    let mut stdout = Vec::new();
    assert!(checked(execute(&options, &mut stdout))?);
    let (twin, loaded, manifest) = load_export(&f, &options, &stdout)?;
    assert_eq!(
        field(&manifest, &["atlas_build", "kind"])?.text(),
        Some("multiview")
    );
    for landmark in rows(&manifest, &["atlas_build", "landmarks"])? {
        assert_eq!(rows(landmark, &["members"])?.len(), 3);
        assert_eq!(rows(landmark, &["residuals"])?.len(), 3);
    }
    localize_fresh_image(&twin, &loaded)?;
    Ok(())
}

#[test]
fn current_adopted_radial_sources_export_corrected_native_reference_frames_and_exact_provenance()
-> Test {
    use super::super::calibrated::tests::rectification::{
        Mode, export_fixture, fixture, preview_report,
    };

    let f = fixture("adopted-radial-atlas", Mode::Pair)?;
    let preview_bytes = preview_report(&f)?;
    let preview = parse_report(&preview_bytes)?;
    let diagnostics = field(
        &preview,
        &["report", "analysis", "geometry", "native_diagnostics"],
    )?;
    let association = text(field(diagnostics, &["scene_evidence"])?)?;
    let mut hypotheses = Vec::new();
    for row in rows(diagnostics, &["hypotheses"])? {
        if field(row, &["estimate", "state"])?.text() == Some("estimated") {
            hypotheses.push(text(field(row, &["evidence_digest"])?)?.to_owned());
        }
    }
    assert!(
        hypotheses.len() >= 3,
        "independent radial pixels must reconstruct native atlas points"
    );
    let options = export_options(&f, &declarations(association, &hypotheses))?;
    let mut stdout = Vec::new();
    assert!(checked(execute(&options, &mut stdout))?);
    let exact = std::str::from_utf8(&stdout)?;
    let value = parse_report(exact)?;
    assert_eq!(
        field(&value, &["schema"])?.text(),
        Some("fss.reconstruction_atlas_adopted.v2")
    );
    let body = field(&value, &["report"])?;
    assert_eq!(
        field(body, &["schema"])?.text(),
        Some("fss.reconstruction_atlas_adopted_report.v2")
    );
    assert_eq!(field(body, &["outcome"])?.text(), Some("candidate_export"));
    let exact_body = exact
        .trim_end()
        .strip_suffix('}')
        .ok_or("outer wrapper")?
        .split_once(",\"report\":")
        .ok_or("report bytes")?
        .1;
    assert_eq!(pin(field(&value, &["report_digest"])?)?, h(exact_body));
    let manifest_bytes = text(field(body, &["provenance_manifest_utf8"])?)?;
    let manifest = parse_report(manifest_bytes)?;
    export_fixture("atlas-report.json", &stdout)?;
    export_fixture("atlas-manifest.json", manifest_bytes.as_bytes())?;
    assert_eq!(
        field(&manifest, &["schema"])?.text(),
        Some("fss.reconstruction_atlas_adopted_provenance.v2")
    );
    assert_eq!(
        pin(field(&manifest, &["calibration", "calibration_digest"])?)?,
        f.calibration.digest()?
    );
    assert_eq!(
        pin(field(
            &manifest,
            &["calibration", "calibration_file_digest"]
        )?)?,
        h(fs::read(&f.calibration_path)?)
    );
    assert_eq!(
        pin(field(&manifest, &["selection_digest"])?)?,
        h(fs::read(&options.selection)?)
    );

    let archive = fs::read(&options.atlas_out)?;
    let package = h(&archive);
    let provenance = h(manifest_bytes);
    assert_eq!(pin(field(body, &["archive", "package_digest"])?)?, package);
    assert_eq!(
        pin(field(body, &["archive", "provenance_digest"])?)?,
        provenance
    );
    for (key, expected) in [
        ("bytes", archive.len()),
        ("landmarks", hypotheses.len()),
        ("references", 2),
        ("bindings", hypotheses.len() * 2),
    ] {
        assert_eq!(
            field(body, &["archive", key])?.integer(),
            Some(expected as i128)
        );
    }
    let rig = parse(std::str::from_utf8(&fs::read(&f.base.options.rig)?)?)?;
    let (package_sha256, source_scene_sha256, basis) =
        checked(super::super::fusion_input::twin_expectation(&rig))?;
    let mut work = WorkBudget::new(WORK);
    let twin = import_twin(
        &fs::read(&f.base.options.twin)?,
        ImportExpectation {
            package_sha256,
            source_scene_sha256,
            basis,
        },
        ImportLimits::default(),
        &mut work,
    )?;
    let loaded = decode_atlas(
        &archive,
        &twin,
        ArchiveExpectation {
            package: package.bytes(),
            provenance: provenance.bytes(),
            descriptor: descriptor_domain(),
        },
        &mut work,
    )?;
    assert_eq!(loaded.atlas().landmarks().len(), hypotheses.len());
    assert_eq!(loaded.atlas().references().len(), 2);
    assert_eq!(loaded.atlas().bindings().len(), hypotheses.len() * 2);
    for point in loaded.atlas().landmarks() {
        assert_eq!(
            point.error, None,
            "lens correction does not establish absolute landmark accuracy"
        );
        assert!((point.world[2] - 10.).abs() < 1.0);
    }
    let source_records = rows(&manifest, &["source_records"])?;
    assert_eq!(source_records.len(), 2);
    for ((source, provenance), reference) in source_records
        .iter()
        .zip(loaded.references())
        .zip(loaded.atlas().references())
    {
        assert_eq!(
            pin(field(source, &["record_digest"])?)?.bytes(),
            provenance.source_record
        );
        let view = field(source, &["record"])?;
        let processing = field(view, &["image_processing"])?;
        assert_eq!(field(view, &["status"])?.text(), Some("adopted_current"));
        assert_eq!(
            field(processing, &["kind"])?.text(),
            Some("native_rectified")
        );
        assert_eq!(
            pin(field(processing, &["model", "lens_basis"])?)?,
            f.calibration.digest()?
        );
        let identity = reference.frame.identity();
        assert_eq!(
            pin(field(processing, &["output", "pixel_digest"])?)?.bytes(),
            identity.pixels
        );
        assert_eq!(
            pin(field(processing, &["output", "image_domain_digest"])?)?.bytes(),
            identity.image_domain
        );
        assert_eq!(
            pin(field(processing, &["output", "exposure_digest"])?)?.bytes(),
            identity.exposure
        );
        assert_eq!(
            pin(field(view, &["allowed_mask_digest"])?)?.bytes(),
            provenance.allowed_mask
        );
        assert_eq!(
            field(processing, &["source", "storage_digest"])?,
            field(view, &["source", "pixel_digest"])?
        );
        assert_eq!(
            pin(field(view, &["source", "exposure_digest"])?)?.bytes(),
            identity.exposure
        );
        assert_ne!(
            pin(field(processing, &["source", "storage_digest"])?)?.bytes(),
            identity.pixels
        );
        assert_ne!(
            pin(field(processing, &["source", "image_domain_digest"])?)?.bytes(),
            identity.image_domain
        );
        let original = pin(field(view, &["source", "encoded_source_digest"])?)?;
        assert!(
            f.base
                .capsules
                .iter()
                .any(|capsule| capsule.source_digest == original)
        );
        assert!(!text(field(view, &["source", "native_receipt_hex"])?)?.is_empty());
    }
    assert_eq!(
        encode_atlas(
            loaded.atlas(),
            loaded.provenance(),
            loaded.references(),
            &mut work
        )?,
        archive
    );
    let report_out = options
        .matching
        .report_out
        .as_ref()
        .ok_or("private report")?;
    assert_eq!(fs::read(report_out)?, stdout);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&options.atlas_out, report_out] {
            assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        }
    }
    let mut refused_output = Vec::new();
    assert!(execute(&options, &mut refused_output).is_err());
    assert!(refused_output.is_empty());
    assert_eq!(fs::read(&options.atlas_out)?, archive);
    assert_eq!(fs::read(report_out)?, stdout);
    Ok(())
}

#[test]
fn supersession_or_withdrawal_after_preview_cannot_export_previously_adopted_geometry() -> Test {
    for supersede in [false, true] {
        let mut f = AdoptedFixture::pair(if supersede {
            "adopted-atlas-superseded"
        } else {
            "adopted-atlas-withdrawn"
        })?;
        let mut options = preview(&f)?;
        let cx = context(&f.base.options.root)?;
        let mut deployment =
            ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
        if supersede {
            let mut newer = f.calibration.clone();
            for camera in &mut newer.cameras {
                camera.identity.extrinsics = 2;
                camera.observations = h(format!(
                    "independently accepted newer input {}",
                    camera.name
                ));
            }
            let subject = CalibrationSubject::from_calibration(&newer, newer.digest()?);
            let bindings = newer
                .cameras
                .iter()
                .enumerate()
                .map(|(index, camera)| {
                    (
                        camera.name.clone(),
                        f.base.capsules[index].sensor_id.clone(),
                    )
                })
                .collect::<Vec<_>>();
            let approval = preview_adoption(&deployment, &subject, &bindings)?.approval;
            adopt(&mut deployment, &subject, &bindings, approval, &cx)?;
        } else {
            let request = InvalidationRequest {
                camera_handle: 1,
                adoption_digest: f.adoptions[0],
                reason: InvalidationReason::OwnerRevoked,
                evidence: None,
            };
            let approval = preview_invalidation(&deployment, &request)?.approval;
            invalidate(&mut deployment, &request, approval, &cx)?;
        }
        drop(deployment);
        cx.drain_and_finalize();
        f.refresh_anchor()?;
        options.matching.expected_anchor = Some(anchor_digest(&f.base.head));
        refused(&options);
        assert_eq!(f.base.head()?, f.base.head);
    }
    Ok(())
}

#[test]
fn current_privacy_after_preview_refuses_the_old_native_landmark_selection() -> Test {
    let f = AdoptedFixture::pair("adopted-atlas-current-mask")?;
    let mut options = preview(&f)?;
    let cx = context(&f.base.options.root)?;
    let mut deployment =
        ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
    let policy = PrivacyMaskPolicy::new(
        f.base.capsules[0].sensor_id.clone(),
        [WIDTH, HEIGHT],
        &[[0, 0, WIDTH, HEIGHT]],
    )?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &cx)?;
    options.matching.expected_anchor = Some(anchor_digest(deployment.current_anchor()));
    drop(deployment);
    cx.drain_and_finalize();
    refused(&options);
    Ok(())
}

#[test]
fn adopted_archive_requires_current_original_frame_capsule_receipt_and_input_bytes() -> Test {
    let f = AdoptedFixture::pair("adopted-atlas-custody")?;
    let mut options = preview(&f)?;
    options.matching.expected_anchor = None;
    let cx = context(&f.base.options.root)?;
    let deployment = ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
    let retained = RetainedFileImport::open(
        &deployment,
        f.base.imports[0],
        RetainedReadLimits::default(),
        &cx,
    )?;
    let spool = deployment.publisher().spool();
    let paths = [
        spool.object_path(retained.manifest().ordered_chunks[0]),
        spool.object_path(h(f.base.capsules[0].try_canonical_bytes()?)),
        spool.object_path(f.adoptions[0]),
        f.input_paths[0].clone(),
        f.calibration_path.clone(),
    ];
    drop(deployment);
    cx.drain_and_finalize();
    for path in paths {
        let original = fs::read(&path)?;
        let mut corrupted = original.clone();
        *corrupted.last_mut().ok_or("nonempty custody object")? ^= 1;
        fs::write(&path, &corrupted)?;
        refused(&options);
        assert_eq!(fs::read(&path)?, corrupted);
        fs::remove_file(&path)?;
        refused(&options);
        assert!(!path.exists());
        fs::write(&path, original)?;
    }
    Ok(())
}

#[test]
fn exact_selection_association_and_twin_feature_pins_are_all_required() -> Test {
    let f = AdoptedFixture::pair("adopted-atlas-selectors")?;
    let mut options = preview(&f)?;
    let original = parse(std::str::from_utf8(&fs::read(&options.selection)?)?)?;
    for path in [
        vec!["association_evidence"],
        vec!["landmarks", "0", "hypothesis"],
    ] {
        let mut invalid = original.clone();
        put(
            &mut invalid,
            &path,
            Value::Text(h("unrelated adopted point").to_text()),
        )?;
        update_selection(&mut options, &invalid)?;
        refused(&options);
    }
    update_selection(&mut options, &original)?;
    options.expected_selection = Some(h("different exact selection bytes"));
    refused(&options);

    let f = AdoptedFixture::pair("adopted-atlas-selector-preflight")?;
    let mut options = dummy_options(&f)?;
    let mut invalid = parse(std::str::from_utf8(&fs::read(&options.selection)?)?)?;
    put(
        &mut invalid,
        &["landmarks", "0", "feature"],
        Value::Number(u32::MAX.to_string()),
    )?;
    update_selection(&mut options, &invalid)?;
    refused(&options);
    assert_eq!(
        f.base.head()?,
        f.base.head,
        "no JPEG derivative before selector admission"
    );
    Ok(())
}

#[test]
fn temporal_reconstruction_is_not_silently_promoted_to_an_enduring_static_atlas() -> Test {
    let base = super::super::temporal::tests::fixture("adopted-atlas-temporal", false)?;
    let f = AdoptedFixture::from_source(base, true)?;
    let options = dummy_options(&f)?;
    refused(&options);
    assert_eq!(
        f.base.head()?,
        f.base.head,
        "temporal refusal precedes source decode"
    );
    let (f, _, _) =
        super::super::calibrated::tests::clock::fixture("adopted-atlas-clock-temporal", false)?;
    let options = dummy_options(&f)?;
    refused(&options);
    assert_eq!(
        f.base.head()?,
        f.base.head,
        "clock replay does not authorize temporal fits as static atlas landmarks"
    );
    Ok(())
}

#[test]
fn cancellation_work_deadline_anchor_and_output_bounds_leave_no_export_prefix() -> Test {
    let f = AdoptedFixture::pair("adopted-atlas-cancel")?;
    let options = dummy_options(&f)?;
    let cx = context(&f.base.options.root)?;
    cx.request_cancellation();
    assert!(analyze(&options, &f.base.options.root, &cx).is_err());
    cx.drain_and_finalize();
    no_outputs(&options);
    assert_eq!(f.base.head()?, f.base.head);
    for case in 0..4 {
        let f = AdoptedFixture::pair(&format!("adopted-atlas-limit-{case}"))?;
        let mut options = if case == 3 {
            preview(&f)?
        } else {
            dummy_options(&f)?
        };
        match case {
            0 => options.matching.work = 1,
            1 => options.matching.timeout = Duration::ZERO,
            2 => options.matching.expected_anchor = Some(h("unrelated entry anchor")),
            _ => options.matching.report_bytes = 1024,
        }
        refused(&options);
        if case < 3 {
            assert_eq!(f.base.head()?, f.base.head);
        }
    }
    Ok(())
}

#[test]
fn explicit_options_and_create_only_outputs_preserve_existing_private_files() -> Test {
    let f = AdoptedFixture::pair("adopted-atlas-exclusive")?;
    let mut export = dummy_options(&f)?;
    let arguments = vec![
        OsString::from("--root"),
        f.base.options.root.as_os_str().to_owned(),
        OsString::from("--site"),
        f.base.options.site.clone().into(),
        OsString::from("--twin"),
        f.base.options.twin.as_os_str().to_owned(),
        OsString::from("--rig"),
        f.base.options.rig.as_os_str().to_owned(),
        OsString::from("--query"),
        f.base.options.query.as_os_str().to_owned(),
        OsString::from("--selection"),
        export.selection.as_os_str().to_owned(),
        OsString::from("--atlas-out"),
        export.atlas_out.as_os_str().to_owned(),
    ];
    let parsed = checked(super::options(&arguments))?.ok_or("explicit atlas options")?;
    assert_eq!(parsed.atlas_out, export.atlas_out);
    assert_eq!(parsed.selection, export.selection);
    for extra in [
        vec!["--camera", "1"],
        vec!["--selection", "other.json"],
        vec!["--atlas-out", "other.fsatlas"],
        vec!["--work-units", "1", "--work-units", "2"],
    ] {
        let mut invalid = arguments.clone();
        invalid.extend(extra.into_iter().map(OsString::from));
        assert!(super::options(&invalid).is_err());
    }
    let sentinel = b"output belongs to its original owner";
    for path in [
        export.atlas_out.clone(),
        export.matching.report_out.clone().ok_or("report path")?,
    ] {
        fs::write(&path, sentinel)?;
        let mut stdout = Vec::new();
        assert!(execute(&export, &mut stdout).is_err());
        assert!(stdout.is_empty());
        assert_eq!(fs::read(&path)?, sentinel);
        assert_eq!(f.base.head()?, f.base.head);
        fs::remove_file(path)?;
    }
    export.matching.report_out = Some(export.atlas_out.clone());
    refused(&export);
    assert_eq!(f.base.head()?, f.base.head);
    #[cfg(unix)]
    {
        export.matching.report_out = None;
        let target = f.base.directory().join("existing-atlas-target");
        fs::write(&target, sentinel)?;
        std::os::unix::fs::symlink(&target, &export.atlas_out)?;
        let mut stdout = Vec::new();
        assert!(execute(&export, &mut stdout).is_err());
        assert!(stdout.is_empty());
        assert_eq!(fs::read(target)?, sentinel);
        assert!(
            fs::symlink_metadata(&export.atlas_out)?
                .file_type()
                .is_symlink()
        );
        assert_eq!(f.base.head()?, f.base.head);
    }
    Ok(())
}

#[test]
fn adopted_authority_remains_locked_through_release_and_failed_stdout_leaves_complete_files() -> Test
{
    struct GuardedStdout<'a> {
        root: &'a Path,
        site: &'a str,
        cx: &'a ReplayCx,
        bytes: Vec<u8>,
        writes: usize,
        refuse: bool,
    }
    impl Write for GuardedStdout<'_> {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            match ReferenceDeployment::reopen(self.root, self.site, self.cx) {
                Err(fss_reference::ReferenceError::DeploymentLocked { .. }) => self.writes += 1,
                Ok(_) => {
                    return Err(io::Error::other(
                        "adoption authority released before stdout",
                    ));
                }
                Err(error) => {
                    return Err(io::Error::other(format!(
                        "unexpected competing open: {error}"
                    )));
                }
            }
            if self.refuse {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "synthetic closed stdout",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for refuse in [false, true] {
        let f = AdoptedFixture::pair(if refuse {
            "adopted-atlas-output-failure"
        } else {
            "adopted-atlas-release"
        })?;
        let options = preview(&f)?;
        let cx = context(&f.base.options.root)?;
        let mut stdout = GuardedStdout {
            root: &f.base.options.root,
            site: &f.base.options.site,
            cx: &cx,
            bytes: Vec::new(),
            writes: 0,
            refuse,
        };
        let result = execute(&options, &mut stdout);
        if refuse {
            assert!(result.is_err());
        } else {
            assert!(checked(result)?);
        }
        assert!(stdout.writes > 0);
        let complete = fs::read(
            options
                .matching
                .report_out
                .as_ref()
                .ok_or("report output")?,
        )?;
        assert!(complete.ends_with(b"\n"));
        if refuse {
            assert!(stdout.bytes.is_empty());
        } else {
            assert_eq!(complete, stdout.bytes);
        }
        load_export(&f, &options, &complete)?;
        let reopened =
            ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
        drop(reopened);
        cx.drain_and_finalize();
    }
    Ok(())
}
