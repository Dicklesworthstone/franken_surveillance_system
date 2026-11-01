#![forbid(unsafe_code)]
//! Real retained source owners, reconstruction previews, atlas archives and CLI publication.
//! The original paired JPEG fixture has an authored z=10 plane, not calibrated real footage.

use super::super::tests::{Fixture, checked, context, field, h, json, put};
use super::*;
use crate::matching::fixtures::{HEIGHT, WIDTH};
use fss_cli::json_input::{Value, parse, parse_reconstruction_atlas_report};
use fss_core::CanonicalEncode;
use fss_reference::ingest::privacy_mask::{PrivacyMaskPolicy, declare_mask, preview_mask};
use fss_reference::ingest::{RetainedFileImport, RetainedReadLimits};
use fss_twin::atlas_archive::{ArchiveExpectation, decode_atlas};
use fss_twin::localization::native::descriptor_domain;
use std::time::Duration;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn declarations(association: &str, hypotheses: &[String]) -> String {
    object(&[
        ("schema", string(input::SCHEMA)),
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
                                string(&h("explicit synthetic stable reference plane").to_text()),
                            ),
                        ])
                    })
                    .collect::<Vec<_>>(),
            ),
        ),
    ])
}

fn export_options(f: &Fixture, selection: &str) -> Test<Options> {
    let path = f.directory().join("atlas-selection.json");
    fs::write(&path, selection)?;
    Ok(Options {
        matching: MatchOptions {
            root: f.options.root.clone(),
            site: f.options.site.clone(),
            principal: f.options.principal.clone(),
            twin: f.options.twin.clone(),
            rig: f.options.rig.clone(),
            query: f.options.query.clone(),
            report_out: Some(f.directory().join("atlas-report.json")),
            expected_input: f.options.expected_input,
            expected_anchor: Some(anchor_digest(&f.head()?)),
            work: DEFAULT_WORK,
            timeout: Duration::from_secs(30),
            report_bytes: MAX_REPORT_BYTES,
        },
        selection: path,
        atlas_out: f.directory().join("selected.fsatlas"),
        expected_selection: Some(h(selection)),
    })
}

/// The selector comes from the real retained matching report, not fabricated feature IDs.
fn preview(f: &Fixture) -> Test<Options> {
    let cx = context(&f.options.root)?;
    let preview = super::super::analyze(&f.options, &f.options.root, &cx);
    cx.drain_and_finalize();
    let preview = checked(preview)?;
    assert!(preview.reconstructed);
    assert!(
        !f.options
            .report_out
            .as_ref()
            .ok_or("preview output")?
            .exists()
    );
    let value = parse_reconstruction_atlas_report(&preview.json)?;
    let analysis = field(&value, &["report", "analysis"])?;
    let association = field(analysis, &["association_evidence"])?
        .text()
        .ok_or("association")?;
    let rows = field(analysis, &["hypotheses"])?
        .array()
        .ok_or("hypotheses")?;
    let mut hypotheses = Vec::new();
    for row in rows {
        if field(row, &["estimate", "state"])?.text() == Some("estimated") {
            hypotheses.push(
                field(row, &["evidence_digest"])?
                    .text()
                    .ok_or("hypothesis")?
                    .to_owned(),
            );
        }
    }
    assert!(
        hypotheses.len() >= 6,
        "original plane must provide usable localization support"
    );
    hypotheses.truncate(6);
    export_options(f, &declarations(association, &hypotheses))
}

fn dummy_options(f: &Fixture) -> Test<Options> {
    export_options(
        f,
        &declarations(
            &h("uncomputed association").to_text(),
            &[h("uncomputed point").to_text()],
        ),
    )
}

fn update_selection(options: &mut Options, document: &Value) -> Test {
    let bytes = json(document);
    fs::write(&options.selection, &bytes)?;
    options.expected_selection = Some(h(bytes));
    Ok(())
}

fn no_outputs(options: &Options) -> Test {
    assert!(!options.atlas_out.exists());
    if let Some(path) = &options.matching.report_out {
        assert!(!path.exists());
    }
    Ok(())
}

fn refused(options: &Options) -> Test {
    let mut stdout = Vec::new();
    assert!(execute(options, &mut stdout).is_err());
    assert!(stdout.is_empty());
    no_outputs(options)
}

fn inspect(f: &Fixture, options: &Options, stdout: &[u8]) -> Test<(Value, Value)> {
    let text = std::str::from_utf8(stdout)?;
    let report = parse_reconstruction_atlas_report(text)?;
    assert_eq!(
        field(&report, &["schema"])?.text(),
        Some("fss.reconstruction_atlas_retained.v1")
    );
    let body = field(&report, &["report"])?;
    assert_eq!(field(body, &["outcome"])?.text(), Some("candidate_export"));
    let exact_body = text
        .trim_end()
        .strip_suffix('}')
        .ok_or("wrapper")?
        .split_once(",\"report\":")
        .ok_or("body")?
        .1;
    assert_eq!(
        field(&report, &["report_digest"])?.text(),
        Some(h(exact_body).to_text().as_str())
    );
    let manifest_text = field(body, &["provenance_manifest_utf8"])?
        .text()
        .ok_or("manifest UTF-8")?;
    let manifest = parse_reconstruction_atlas_report(manifest_text)?;
    let archive = fs::read(&options.atlas_out)?;
    let package = h(&archive);
    let provenance = h(manifest_text);
    assert_eq!(
        field(body, &["archive", "package_digest"])?.text(),
        Some(package.to_text().as_str())
    );
    assert_eq!(
        field(body, &["archive", "provenance_digest"])?.text(),
        Some(provenance.to_text().as_str())
    );
    assert_eq!(
        field(body, &["archive", "bytes"])?.integer(),
        Some(archive.len() as i128)
    );
    assert_eq!(field(body, &["archive", "landmarks"])?.integer(), Some(6));
    assert_eq!(
        field(body, &["archive", "references"])?.integer(),
        Some(f.capsules.len() as i128)
    );
    assert_eq!(
        field(body, &["archive", "bindings"])?.integer(),
        Some((6 * f.capsules.len()) as i128)
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
    assert_eq!(
        field(&manifest, &["selection_digest"])?.text(),
        Some(h(fs::read(&options.selection)?).to_text().as_str())
    );
    assert_eq!(
        field(&manifest, &["source_records"])?
            .array()
            .ok_or("source records")?
            .len(),
        f.capsules.len()
    );
    assert!(
        field(&manifest, &["atlas_build", "candidates"])?
            .array()
            .ok_or("all candidates")?
            .len()
            > 6
    );
    assert_eq!(
        field(&manifest, &["atlas_build", "landmarks"])?
            .array()
            .ok_or("admitted landmarks")?
            .len(),
        6
    );

    let rig = parse(std::str::from_utf8(&fs::read(&f.options.rig)?)?)?;
    let (package_sha256, source_scene_sha256, basis) =
        checked(fusion_input::twin_expectation(&rig))?;
    let mut work = WorkBudget::new(1_000_000_000);
    let twin = import_twin(
        &fs::read(&f.options.twin)?,
        ImportExpectation {
            package_sha256,
            source_scene_sha256,
            basis,
        },
        ImportLimits::default(),
        &mut work,
    )?;
    let decoded = decode_atlas(
        &archive,
        &twin,
        ArchiveExpectation {
            package: package.bytes(),
            provenance: provenance.bytes(),
            descriptor: descriptor_domain(),
        },
        &mut work,
    )?;
    assert_eq!(decoded.package(), package.bytes());
    assert_eq!(decoded.provenance(), provenance.bytes());
    assert_eq!(
        field(body, &["archive", "atlas_digest"])?.text(),
        Some(
            fss_core::ContentDigest::new(
                fss_core::DigestAlgorithm::Sha256,
                decoded.atlas().digest()
            )
            .to_text()
            .as_str()
        )
    );
    assert_eq!(decoded.atlas().landmarks().len(), 6);
    assert_eq!(decoded.atlas().bindings().len(), 6 * f.capsules.len());
    for landmark in decoded.atlas().landmarks() {
        assert_eq!(landmark.error, None);
        assert!((landmark.world[2] - 10.0).abs() < 1e-8);
    }
    for (index, reference) in decoded.atlas().references().iter().enumerate() {
        assert!(reference.frame.features().len() >= 6);
        assert_eq!(reference.frame.descriptor_domain(), descriptor_domain());
        let source = field(&manifest, &["source_records", &index.to_string()])?;
        let pin = field(source, &["record_digest"])?
            .text()
            .ok_or("source pin")?;
        assert_eq!(
            ContentDigest::parse(pin)?.bytes(),
            decoded.references()[index].source_record
        );
        assert_eq!(
            field(source, &["record", "source", "encoded_source_digest"])?.text(),
            Some(f.capsules[index].source_digest.to_text().as_str())
        );
        assert!(
            !field(source, &["record", "source", "native_receipt_hex"])?
                .text()
                .ok_or("native receipt")?
                .is_empty()
        );
    }
    assert_eq!(
        encode_atlas(
            decoded.atlas(),
            decoded.provenance(),
            decoded.references(),
            &mut work
        )?,
        archive
    );
    let report_path = options.matching.report_out.as_ref().ok_or("report path")?;
    assert_eq!(fs::read(report_path)?, stdout);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for path in [&options.atlas_out, report_path] {
            assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
        }
    }
    Ok((report, manifest))
}

#[test]
fn retained_reconstruction_exports_a_complete_private_archive_with_exact_provenance() -> Test {
    let f = Fixture::new("atlas-complete")?;
    let options = preview(&f)?;
    let mut stdout = Vec::new();
    assert!(checked(execute(&options, &mut stdout))?); // main maps true to exit 0.
    inspect(&f, &options, &stdout)?;
    let archive = fs::read(&options.atlas_out)?;
    let report = fs::read(options.matching.report_out.as_ref().ok_or("report")?)?;
    let mut second_stdout = Vec::new();
    assert!(execute(&options, &mut second_stdout).is_err());
    assert!(second_stdout.is_empty());
    assert_eq!(fs::read(&options.atlas_out)?, archive);
    assert_eq!(
        fs::read(options.matching.report_out.as_ref().ok_or("report")?)?,
        report
    );
    Ok(())
}

#[test]
fn complete_three_camera_components_export_every_actual_member_binding() -> Test {
    let (f, preview) = super::super::multiview::tests::atlas_fixture_preview("atlas-multiview")?;
    let value = parse_reconstruction_atlas_report(&preview)?;
    let geometry = field(&value, &["report", "analysis", "geometry"])?;
    let association = field(geometry, &["scene_evidence"])?
        .text()
        .ok_or("scene evidence")?;
    let mut hypotheses = Vec::new();
    for component in field(geometry, &["components"])?
        .array()
        .ok_or("components")?
    {
        if field(component, &["outcome", "state"])?.text() == Some("estimated")
            && field(component, &["members"])?
                .array()
                .ok_or("members")?
                .len()
                == 3
        {
            hypotheses.push(
                field(component, &["evidence_digest"])?
                    .text()
                    .ok_or("component pin")?
                    .to_owned(),
            );
        }
    }
    assert!(hypotheses.len() >= 6);
    hypotheses.truncate(6);
    let options = export_options(&f, &declarations(association, &hypotheses))?;
    let mut stdout = Vec::new();
    assert!(checked(execute(&options, &mut stdout))?);
    let (_, manifest) = inspect(&f, &options, &stdout)?;
    assert_eq!(
        field(&manifest, &["atlas_build", "kind"])?.text(),
        Some("multiview")
    );
    assert_eq!(
        field(&manifest, &["geometry", "counts", "cameras"])?.integer(),
        Some(3)
    );
    for landmark in field(&manifest, &["atlas_build", "landmarks"])?
        .array()
        .ok_or("landmarks")?
    {
        assert_eq!(
            field(landmark, &["members"])?
                .array()
                .ok_or("members")?
                .len(),
            3
        );
        assert_eq!(
            field(landmark, &["residuals"])?
                .array()
                .ok_or("residuals")?
                .len(),
            3
        );
    }
    Ok(())
}

#[test]
fn corrected_retained_references_keep_original_sources_and_native_output_modes_in_the_atlas() -> Test
{
    let mut f = Fixture::new("atlas-crop")?;
    let mut query = f.document.clone();
    let mut rig = parse(std::str::from_utf8(&fs::read(&f.options.rig)?)?)?;
    put(
        &mut query,
        &["schema"],
        Value::Text(super::super::input::SCHEMA_V2.into()),
    )?;
    for (index, side) in ["left", "right"].into_iter().enumerate() {
        for (key, value) in [("width", 128), ("height", 96), ("cx", 64), ("cy", 48)] {
            put(
                &mut rig,
                &["cameras", &index.to_string(), "intrinsics", key],
                Value::Number(value.to_string()),
            )?;
        }
        let source_domain = field(&query, &[side, "image_domain_digest"])?.clone();
        let image = parse(&object(&[
            ("kind", string("rectified")),
            ("source_domain_digest", json(&source_domain)),
            (
                "lens_basis",
                string(&h(format!("explicit atlas integer crop {side}")).to_text()),
            ),
            (
                "source_intrinsics",
                r#"{"width":192,"height":128,"fx":160,"fy":160,"cx":96,"cy":64}"#.into(),
            ),
            ("distortion", r#"{"kind":"pinhole"}"#.into()),
            ("maximum_radius", "1".into()),
            ("luma_range", string("full")),
        ]))?;
        let Value::Object(fields) = &mut query else {
            return Err("query object".into());
        };
        let Value::Object(view) = fields.get_mut(side).ok_or("view")? else {
            return Err("view object".into());
        };
        view.remove("image_domain_digest");
        view.insert("image".into(), image);
    }
    let rig_text = json(&rig);
    fs::write(&f.options.rig, &rig_text)?;
    put(
        &mut query,
        &["camera_rig_digest"],
        Value::Text(h(&rig_text).to_text()),
    )?;
    f.set_query(&query)?;
    let options = preview(&f)?;
    let mut stdout = Vec::new();
    assert!(checked(execute(&options, &mut stdout))?);
    let (_, manifest) = inspect(&f, &options, &stdout)?;
    for index in 0..2 {
        let row = field(&manifest, &["source_records", &index.to_string(), "record"])?;
        assert_eq!(
            field(row, &["source", "dimensions", "0"])?.integer(),
            Some(192)
        );
        assert_eq!(
            field(row, &["source", "dimensions", "1"])?.integer(),
            Some(128)
        );
        assert_eq!(
            field(row, &["image_processing", "kind"])?.text(),
            Some("native_rectified")
        );
        assert_eq!(
            field(row, &["image_processing", "output", "dimensions", "0"])?.integer(),
            Some(128)
        );
        assert_eq!(
            field(row, &["image_processing", "output", "dimensions", "1"])?.integer(),
            Some(96)
        );
        assert_eq!(
            field(row, &["image_processing", "source", "exposure_digest"])?.text(),
            field(row, &["image_processing", "output", "exposure_digest"])?.text()
        );
        assert_ne!(
            field(row, &["image_processing", "source", "image_domain_digest"])?.text(),
            field(row, &["image_processing", "output", "image_domain_digest"])?.text()
        );
    }
    Ok(())
}

#[test]
fn privacy_change_after_preview_refuses_the_old_selection_even_at_the_new_authority_anchor() -> Test
{
    let f = Fixture::new("atlas-privacy")?;
    let mut options = preview(&f)?;
    let cx = context(&f.options.root)?;
    let mut deployment = ReferenceDeployment::reopen(&f.options.root, &f.options.site, &cx)?;
    let policy = PrivacyMaskPolicy::new(
        f.capsules[0].sensor_id.clone(),
        [WIDTH, HEIGHT],
        &[[0, 0, WIDTH, HEIGHT]],
    )?;
    let approval = preview_mask(&deployment, &policy)?.approval;
    declare_mask(&mut deployment, &policy, approval, &cx)?;
    options.matching.expected_anchor = Some(anchor_digest(deployment.current_anchor()));
    drop(deployment);
    cx.drain_and_finalize();
    refused(&options)?;
    Ok(())
}

#[test]
fn cached_native_derivatives_do_not_hide_missing_or_modified_original_source_custody() -> Test {
    let f = Fixture::new("atlas-custody")?;
    let mut options = preview(&f)?;
    options.matching.expected_anchor = None;
    let cx = context(&f.options.root)?;
    let deployment = ReferenceDeployment::reopen(&f.options.root, &f.options.site, &cx)?;
    let retained = RetainedFileImport::open(
        &deployment,
        f.imports[0],
        RetainedReadLimits::default(),
        &cx,
    )?;
    let paths = [
        deployment
            .publisher()
            .spool()
            .object_path(retained.manifest().ordered_chunks[0]),
        deployment
            .publisher()
            .spool()
            .object_path(h(f.capsules[0].try_canonical_bytes()?)),
    ];
    drop(deployment);
    cx.drain_and_finalize();
    for path in paths {
        let original = fs::read(&path)?;
        let mut corrupt = original.clone();
        *corrupt.last_mut().ok_or("source object")? ^= 1;
        fs::write(&path, &corrupt)?;
        refused(&options)?;
        assert_eq!(fs::read(&path)?, corrupt);
        fs::remove_file(&path)?;
        refused(&options)?;
        assert!(!path.exists());
        fs::write(&path, original)?;
    }
    Ok(())
}

#[test]
fn invalid_selector_and_twin_feature_fail_before_any_native_decode_publication() -> Test {
    let f = Fixture::new("atlas-preflight")?;
    let mut options = dummy_options(&f)?;
    let document = parse(std::str::from_utf8(&fs::read(&options.selection)?)?)?;
    for value in [
        Value::Number("1".into()),
        Value::Number(u32::MAX.to_string()),
    ] {
        let mut invalid = document.clone();
        put(&mut invalid, &["landmarks", "0", "feature"], value)?;
        update_selection(&mut options, &invalid)?;
        refused(&options)?;
        assert_eq!(f.head()?, f.head);
    }
    update_selection(&mut options, &document)?;
    options.expected_selection = Some(h("different exact selector bytes"));
    refused(&options)?;
    assert_eq!(f.head()?, f.head);
    let mut invalid = document;
    put(
        &mut invalid,
        &["landmarks", "0", "enduring_static_basis"],
        Value::Text(format!("sha256:{}", "0".repeat(64))),
    )?;
    update_selection(&mut options, &invalid)?;
    refused(&options)?;
    assert_eq!(f.head()?, f.head);
    Ok(())
}

#[test]
fn valid_but_unrelated_association_and_hypothesis_pins_cannot_be_exported() -> Test {
    let f = Fixture::new("atlas-selector")?;
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
            Value::Text(h("unrelated native reconstruction").to_text()),
        )?;
        update_selection(&mut options, &invalid)?;
        refused(&options)?;
    }
    Ok(())
}

#[test]
fn cancellation_deadline_work_and_complete_report_limits_publish_no_atlas_or_report() -> Test {
    let f = Fixture::new("atlas-cancel")?;
    let options = dummy_options(&f)?;
    let cx = context(&f.options.root)?;
    cx.request_cancellation();
    assert!(analyze(&options, &f.options.root, &cx).is_err());
    cx.drain_and_finalize();
    no_outputs(&options)?;
    assert_eq!(f.head()?, f.head);
    for case in 0..3 {
        let f = Fixture::new(&format!("atlas-limits-{case}"))?;
        let mut options = if case == 2 {
            preview(&f)?
        } else {
            dummy_options(&f)?
        };
        match case {
            0 => options.matching.timeout = Duration::ZERO,
            1 => options.matching.work = 1,
            _ => options.matching.report_bytes = 1024,
        }
        refused(&options)?;
        if case < 2 {
            assert_eq!(f.head()?, f.head);
        }
    }
    Ok(())
}

#[test]
fn existing_outputs_and_aliases_are_refused_before_source_publication() -> Test {
    let f = Fixture::new("atlas-exclusive")?;
    let mut options = dummy_options(&f)?;
    let sentinel = b"private output belongs to its original writer";
    for atlas in [true, false] {
        let path = if atlas {
            options.atlas_out.clone()
        } else {
            options.matching.report_out.clone().ok_or("report")?
        };
        fs::write(&path, sentinel)?;
        let mut stdout = Vec::new();
        assert!(execute(&options, &mut stdout).is_err());
        assert!(stdout.is_empty());
        assert_eq!(fs::read(&path)?, sentinel);
        fs::remove_file(&path)?;
        no_outputs(&options)?;
        assert_eq!(f.head()?, f.head);
    }
    options.matching.report_out = Some(options.atlas_out.clone());
    refused(&options)?;
    assert_eq!(f.head()?, f.head);
    #[cfg(unix)]
    {
        options.matching.report_out = None;
        let target = f.directory().join("existing-private-target");
        fs::write(&target, sentinel)?;
        std::os::unix::fs::symlink(&target, &options.atlas_out)?;
        let mut stdout = Vec::new();
        assert!(execute(&options, &mut stdout).is_err());
        assert!(stdout.is_empty());
        assert_eq!(fs::read(&target)?, sentinel);
        assert!(
            fs::symlink_metadata(&options.atlas_out)?
                .file_type()
                .is_symlink()
        );
        assert_eq!(f.head()?, f.head);
    }
    Ok(())
}

#[test]
fn stdout_failure_leaves_only_complete_checksums_and_private_output_files() -> Test {
    struct RefuseStdout;
    impl Write for RefuseStdout {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "test stdout closed",
            ))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let f = Fixture::new("atlas-stdout")?;
    let options = preview(&f)?;
    assert!(execute(&options, &mut RefuseStdout).is_err());
    let report = fs::read(options.matching.report_out.as_ref().ok_or("report")?)?;
    inspect(&f, &options, &report)?;
    Ok(())
}
