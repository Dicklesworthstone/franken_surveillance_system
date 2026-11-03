#![forbid(unsafe_code)]
//! Original clock replay through actual retained source, current adoption and temporal owners.
//! The calibration and clock observations are authored numeric controls, not physical evidence.

use super::*;
use crate::retained_matching::temporal_clock::fixtures as clock_fixtures;
use fss_core::CanonicalEncode;

pub(in crate::retained_matching) fn fixture(
    label: &str,
    radial: bool,
) -> Test<(AdoptedFixture, PathBuf, Vec<u8>)> {
    let mut f = if radial {
        rectification::fixture(label, rectification::Mode::Temporal)?
    } else {
        let base = crate::retained_matching::temporal::tests::fixture(label, false)?;
        AdoptedFixture::from_source(base, true)?
    };
    let rig_bytes = fs::read(&f.base.options.rig)?;
    let declaration = checked(input::parse_rig(&rig_bytes))?;
    let query = checked(MatchingQuery::for_rig(
        json(&f.base.document).as_bytes(),
        h(&rig_bytes),
        &declaration,
    ))?;
    let mut work = WorkBudget::new(WORK);
    let twin = import_twin(
        &fs::read(&f.base.options.twin)?,
        ImportExpectation {
            package_sha256: declaration.twin_digest.bytes(),
            source_scene_sha256: declaration.source_scene_digest.bytes(),
            basis: GeometryBasis::new(declaration.geometry_basis.0, declaration.geometry_basis.1)?,
        },
        ImportLimits::default(),
        &mut work,
    )?;
    let cx = context(&f.base.options.root)?;
    let deployment = ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
    let calibration = checked(load_calibration(
        &f.base.options,
        &declaration,
        &deployment,
        &twin,
        &mut work,
        &cx,
    ))?;
    let rig = checked(project_rig(&twin, &calibration, &declaration, &mut work))?;
    let images = checked(prepare_images(query.views(), &rig, &mut work))?;
    let mut original = clock_fixtures::query(
        &rig,
        [images[0].domain, images[1].domain],
        &[f.base.capsules[1].capture, f.base.capsules[3].capture],
        0,
    )?;
    for camera in ["reference_camera", "target_camera"] {
        put(
            &mut original,
            &[camera, "calibration_digest"],
            Value::Text(calibration.calibration_identity().to_text()),
        )?;
    }
    let path = f.base.directory().join("adopted-original-clock-query.json");
    let bytes = clock_fixtures::attach(
        &mut f.base.document,
        &rig,
        &f.base.capsules,
        &original,
        path.to_str().ok_or("clock path")?,
    )?;
    for index in 0..2 {
        put(
            &mut f.base.document,
            &[
                "clock_validation",
                "bindings",
                &index.to_string(),
                "calibration_digest",
            ],
            Value::Text(calibration.calibration_identity().to_text()),
        )?;
    }
    drop(deployment);
    cx.drain_and_finalize();
    fs::write(&path, &bytes)?;
    save_query(&mut f)?;
    Ok((f, path, bytes))
}

fn save_query(f: &mut AdoptedFixture) -> Test {
    let document = f.base.document.clone();
    f.base.set_query(&document)?;
    Ok(())
}

fn replace_original(f: &mut AdoptedFixture, path: &Path, original: &Value) -> Test {
    let bytes = json(original);
    fs::write(path, &bytes)?;
    let digest = h(&bytes).to_text();
    put(
        &mut f.base.document,
        &["clock_evidence"],
        Value::Text(digest.clone()),
    )?;
    put(
        &mut f.base.document,
        &["clock_validation", "query_digest"],
        Value::Text(digest.clone()),
    )?;
    for index in 0..4 {
        put(
            &mut f.base.document,
            &["views", &index.to_string(), "alignment", "basis"],
            Value::Text(digest.clone()),
        )?;
    }
    save_query(f)
}

#[test]
fn adopted_clock_replay_preserves_all_hypotheses_original_sources_and_current_adoption() -> Test {
    for radial in [false, true] {
        let (f, _, original) = fixture(
            if radial {
                "adopted-clock-radial"
            } else {
                "adopted-clock-pinhole"
            },
            radial,
        )?;
        let (stdout, value) = execute_report(&f)?;
        assert_eq!(
            field(&value, &["schema"])?.text(),
            Some("fss.scene_feature_match_adopted.v3")
        );
        assert_eq!(
            field(&value, &["report", "schema"])?.text(),
            Some("fss.scene_feature_match_adopted_report.v3")
        );
        check_sources(&f, &value)?;
        assert!(scalar(field(&value, &["report", "analysis", "counts", "solved"])?)? >= 3);
        let clock = field(&value, &["report", "analysis", "clock_validation"])?;
        assert_eq!(
            field(clock, &["original_query_json"])?.text(),
            Some(std::str::from_utf8(&original)?)
        );
        assert_eq!(
            field(clock, &["query_digest"])?.text(),
            Some(h(&original).to_text().as_str())
        );
        assert_eq!(
            field(clock, &["native_replay", "report", "hypothesis_count"])?.integer(),
            Some(3)
        );
        assert_eq!(
            field(
                clock,
                &[
                    "native_replay",
                    "report",
                    "supported_in_every_session_count"
                ]
            )?
            .integer(),
            Some(1)
        );
        for flag in [
            "clock_synchronization_established",
            "clock_query_source_custody_verified",
            "source_clock_basis_upgraded",
        ] {
            assert_eq!(field(clock, &[flag])?.boolean(), Some(false));
        }
        let mapped = rows(clock, &["mapped_exposures"])?;
        assert_eq!(mapped.len(), 4);
        for (index, row) in mapped.iter().enumerate() {
            let capsule = &f.base.capsules[index];
            assert_eq!(
                field(row, &["capsule_digest"])?.text(),
                Some(h(capsule.try_canonical_bytes()?).to_text().as_str())
            );
            assert_eq!(
                field(row, &["original_capture_ns", "0"])?.text(),
                Some(capsule.capture.earliest.0.to_string().as_str())
            );
            assert_eq!(
                field(row, &["original_capture_ns", "1"])?.text(),
                Some(capsule.capture.latest.0.to_string().as_str())
            );
        }
        let cost = field(&value, &["report", "cost"])?;
        assert_eq!(
            field(cost, &["source_bytes", "allowance"])?.text(),
            Some((SOURCE_BYTES - 1_048_576).to_string().as_str())
        );
        assert_eq!(
            field(cost, &["clock_query_bytes", "used"])?.text(),
            Some(original.len().to_string().as_str())
        );
        assert_eq!(
            field(cost, &["clock_query_bytes", "reserved_from_source_bytes"])?.boolean(),
            Some(true)
        );
        assert_eq!(
            fs::read(f.base.options.report_out.as_ref().ok_or("report output")?)?,
            stdout
        );
        let body = std::str::from_utf8(&stdout)?
            .trim_end()
            .strip_suffix('}')
            .ok_or("wrapper")?
            .split_once(",\"report\":")
            .ok_or("body")?
            .1;
        assert_eq!(
            field(&value, &["report_digest"])?.text(),
            Some(h(body).to_text().as_str())
        );
        if let Some(directory) = std::env::var_os("FSS_ADOPTED_CLOCK_FIXTURE_DIR") {
            let directory = PathBuf::from(directory);
            fs::create_dir_all(&directory)?;
            fs::write(
                directory.join(if radial {
                    "radial.json"
                } else {
                    "pinhole.json"
                }),
                stdout,
            )?;
        }
    }
    Ok(())
}

#[test]
fn repinning_clock_calibration_geometry_or_image_cannot_override_current_adoption() -> Test {
    for case in 0..4 {
        let (mut f, path, bytes) = fixture(&format!("adopted-clock-binding-{case}"), false)?;
        let mut original = parse(std::str::from_utf8(&bytes)?)?;
        match case {
            0 => {
                let fake = h("unadopted but internally consistent clock calibration").to_text();
                put(
                    &mut original,
                    &["reference_camera", "calibration_digest"],
                    Value::Text(fake.clone()),
                )?;
                put(
                    &mut f.base.document,
                    &["clock_validation", "bindings", "0", "calibration_digest"],
                    Value::Text(fake),
                )?;
            }
            1 => put(
                &mut original,
                &["reference_camera", "center", "0"],
                Value::Number("0.25".into()),
            )?,
            2 => put(
                &mut original,
                &["target_camera", "intrinsics", "fx"],
                Value::Number("161".into()),
            )?,
            _ => put(
                &mut original,
                &["target_camera", "image_domain"],
                Value::Text(h("unrelated clock image grid").to_text()),
            )?,
        }
        replace_original(&mut f, &path, &original)?;
        f.refused()?;
        assert_eq!(
            f.base.head()?,
            f.base.head,
            "clock/calibration mismatch precedes source decode"
        );
    }
    Ok(())
}

#[test]
fn altered_sidecar_full_interval_or_unsupported_hypothesis_hull_refuses_before_decode() -> Test {
    for case in 0..3 {
        let (mut f, path, bytes) = fixture(&format!("adopted-clock-capture-{case}"), false)?;
        match case {
            0 => fs::write(&path, b"{}")?,
            1 => {
                let mut original = parse(std::str::from_utf8(&bytes)?)?;
                put(
                    &mut original,
                    &["projections", "0", "target_interval_ns"],
                    parse("[1050,1050]")?,
                )?;
                replace_original(&mut f, &path, &original)?;
            }
            _ => {
                // The supported zero-skew hypothesis fits this limit, while the complete
                // declared envelope does not. Unsupported candidates may not disappear.
                put(
                    &mut f.base.document,
                    &["max_capture_uncertainty_ns"],
                    Value::Number("100".into()),
                )?;
                save_query(&mut f)?;
            }
        }
        f.refused()?;
        assert_eq!(
            f.base.head()?,
            f.base.head,
            "complete clock admission precedes source decode"
        );
    }
    Ok(())
}

#[test]
fn clock_replay_requires_current_adoption_and_original_source_after_preview() -> Test {
    for withdraw in [false, true] {
        let (mut f, _, _) = fixture(
            if withdraw {
                "adopted-clock-withdrawal"
            } else {
                "adopted-clock-custody"
            },
            false,
        )?;
        let cx = context(&f.base.options.root)?;
        let preview = checked(analyze(&f.base.options, &f.base.options.root, &cx))?;
        drop(preview);
        cx.drain_and_finalize();
        let cx = context(&f.base.options.root)?;
        let mut deployment =
            ReferenceDeployment::reopen(&f.base.options.root, &f.base.options.site, &cx)?;
        if withdraw {
            let request = InvalidationRequest {
                camera_handle: 1,
                adoption_digest: f.adoptions[0],
                reason: InvalidationReason::OwnerRevoked,
                evidence: None,
            };
            let approval = preview_invalidation(&deployment, &request)?.approval;
            invalidate(&mut deployment, &request, approval, &cx)?;
        } else {
            let source = RetainedFileImport::open(
                &deployment,
                f.base.imports[0],
                RetainedReadLimits::default(),
                &cx,
            )?;
            let path = deployment
                .publisher()
                .spool()
                .object_path(source.manifest().ordered_chunks[0]);
            let mut bytes = fs::read(&path)?;
            *bytes.last_mut().ok_or("source bytes")? ^= 1;
            fs::write(path, bytes)?;
        }
        drop(deployment);
        cx.drain_and_finalize();
        f.refresh_anchor()?;
        f.refused()?;
    }
    Ok(())
}

#[test]
fn clock_profile_obeys_original_work_cancellation_and_complete_output_limits() -> Test {
    let (f, _, _) = fixture("adopted-clock-cancel", false)?;
    let cx = context(&f.base.options.root)?;
    cx.request_cancellation();
    assert!(analyze(&f.base.options, &f.base.options.root, &cx).is_err());
    cx.drain_and_finalize();
    assert_eq!(f.base.head()?, f.base.head);
    for output_limit in [false, true] {
        let (mut f, _, _) = fixture(
            if output_limit {
                "adopted-clock-output-cap"
            } else {
                "adopted-clock-work-cap"
            },
            false,
        )?;
        if output_limit {
            f.base.options.report_bytes = 1024;
        } else {
            f.base.options.work = 1;
        }
        f.refused()?;
        if !output_limit {
            assert_eq!(f.base.head()?, f.base.head);
        }
    }
    assert_eq!(calibrated_clock::source_allowance(false), SOURCE_BYTES);
    assert_eq!(
        calibrated_clock::source_allowance(true) + fss_cli::clock_alignment::MAX_INPUT_BYTES as u64,
        SOURCE_BYTES
    );
    Ok(())
}
