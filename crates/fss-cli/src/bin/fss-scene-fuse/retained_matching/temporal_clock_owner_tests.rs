#![forbid(unsafe_code)]
//! Real retained imports, exact clock sidecar, and the production temporal command.
use super::*;
use crate::retained_matching::temporal_clock::fixtures as clock_fixtures;

fn clock_fixture(label: &str) -> Test<(Fixture, PathBuf, Vec<u8>)> {
    let mut f = fixture(label, false)?;
    let twin_bytes = fs::read(&f.options.twin)?;
    let rig_bytes = fs::read(&f.options.rig)?;
    let rig_document = parse(std::str::from_utf8(&rig_bytes)?)?;
    let (package_sha256, source_scene_sha256, basis) =
        checked(fusion_input::twin_expectation(&rig_document))?;
    let mut work = WorkBudget::new(100_000_000);
    let twin = import_twin(
        &twin_bytes,
        ImportExpectation {
            package_sha256,
            source_scene_sha256,
            basis,
        },
        ImportLimits::default(),
        &mut work,
    )?;
    let rig = SceneRig::from_document(&rig_document, &twin, &mut work)?;
    let query = checked(input::parse(json(&f.document).as_bytes(), h(&rig_bytes)))?;
    let domains = [0, 1].map(|index| {
        let view = &query.views[index];
        checked(view.image.prepare(
            rig.camera(view.camera).ok_or("camera")?.camera.intrinsics,
            &mut work,
        ))
        .map(|image| image.domain)
    });
    let [left, right] = domains;
    let captures = [f.capsules[1].capture, f.capsules[3].capture];
    let original = clock_fixtures::query(&rig, [left?, right?], &captures, 0)?;
    let path = f.directory().join("original-clock-query.json");
    let mut document = f.document.clone();
    let bytes = clock_fixtures::attach(
        &mut document,
        &rig,
        &f.capsules,
        &original,
        path.to_str().ok_or("UTF-8 fixture path")?,
    )?;
    fs::write(&path, &bytes)?;
    f.set_query(&document)?;
    f.document = document;
    Ok((f, path, bytes))
}

#[test]
fn exact_original_clock_query_reaches_retained_motion_report_without_losing_sources() -> Test {
    let (f, _, bytes) = clock_fixture("temporal-clock-complete")?;
    let mut stdout = Vec::new();
    let success = checked(execute(&f.options, &mut stdout))?;
    assert!(
        !success,
        "unresolved same-camera-only components remain visible"
    );
    assert_eq!(
        fs::read(f.options.report_out.as_ref().ok_or("output")?)?,
        stdout
    );
    let output = parse_report(std::str::from_utf8(&stdout)?)?;
    assert_eq!(
        field(&output, &["schema"])?.text(),
        Some("fss.scene_feature_motion_match_retained.v2")
    );
    let analysis = field(&output, &["report", "analysis"])?;
    let clock = field(analysis, &["clock_validation"])?;
    assert_eq!(
        field(clock, &["original_query_json"])?.text(),
        Some(std::str::from_utf8(&bytes)?)
    );
    assert_eq!(
        field(clock, &["query_digest"])?.text(),
        Some(h(&bytes).to_text().as_str())
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
    let mapped = field(clock, &["mapped_exposures"])?
        .array()
        .ok_or("mapped exposures")?;
    assert_eq!(mapped.len(), 4);
    for (index, row) in mapped.iter().enumerate() {
        let capsule = &f.capsules[index];
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
    for flag in [
        "clock_synchronization_established",
        "clock_query_source_custody_verified",
        "source_clock_basis_upgraded",
    ] {
        assert_eq!(field(clock, &[flag])?.boolean(), Some(false));
    }
    let geometry = geometry(&output)?;
    assert_eq!(
        field(geometry, &["counts", "exposures"])?.integer(),
        Some(4)
    );
    let mut solved = 0;
    for component in field(geometry, &["components"])?
        .array()
        .ok_or("components")?
    {
        let outcome = field(component, &["outcome"])?;
        if field(outcome, &["state"])?.text() == Some("estimated") {
            solved += 1;
            for velocity in field(outcome, &["velocity_per_second"])?
                .array()
                .ok_or("velocity")?
            {
                assert!(number(velocity)?.abs() < 0.0001);
            }
        }
    }
    assert!(solved >= 8);
    assert_eq!(
        field(&output, &["report", "cost", "source_bytes", "allowance"])?.text(),
        Some((SOURCE_BYTES - 1_048_576).to_string().as_str())
    );
    Ok(())
}

#[test]
fn changed_clock_sidecar_and_narrowed_full_interval_refuse_before_source_publication() -> Test {
    let (mut f, path, bytes) = clock_fixture("temporal-clock-refusals")?;
    // A later file change cannot be accepted merely because the v2 query pin is unchanged.
    fs::write(&path, b"{}")?;
    refused(&f)?;
    assert_eq!(
        f.head()?,
        f.head,
        "clock pin mismatch must precede JPEG derivatives"
    );
    fs::write(&path, &bytes)?;
    // Repinning a different original query does not authorize a point in place of the
    // exact complete retained target interval.
    let mut original = parse(std::str::from_utf8(&bytes)?)?;
    put(
        &mut original,
        &["projections", "0", "target_interval_ns"],
        parse("[1050,1050]")?,
    )?;
    let narrowed = json(&original);
    fs::write(&path, &narrowed)?;
    let digest = h(&narrowed).to_text();
    let mut document = f.document.clone();
    put(
        &mut document,
        &["clock_validation", "query_digest"],
        Value::Text(digest.clone()),
    )?;
    put(
        &mut document,
        &["clock_evidence"],
        Value::Text(digest.clone()),
    )?;
    for index in 0..4 {
        put(
            &mut document,
            &["views", &index.to_string(), "alignment", "basis"],
            Value::Text(digest.clone()),
        )?;
    }
    f.set_query(&document)?;
    refused(&f)?;
    assert_eq!(
        f.head()?,
        f.head,
        "full interval mismatch must precede JPEG derivatives"
    );
    Ok(())
}
