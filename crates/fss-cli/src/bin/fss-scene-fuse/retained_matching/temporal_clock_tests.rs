#![forbid(unsafe_code)]
//! Exact original clock replay reaches actual native retained-view binding and motion matching.
//! The source snapshots are synthetic native values; these tests do not claim retained custody.
use super::*;
use crate::retained_matching::images::PreparedImage;
use crate::retained_matching::temporal_clock::{self, fixtures};
use std::sync::atomic::{AtomicBool, Ordering};

fn fixture() -> Test<(Fixture, Vec<u8>, Value)> {
    let mut f = Fixture::new(6, 2, 2)?;
    for index in [1, 3, 5] {
        let capture = f.capsules[index].capture;
        f.set_capture(
            index,
            [
                capture.earliest.0 + 50_000_000,
                capture.latest.0 + 50_000_000,
            ],
        )?;
    }
    let captures = [1, 3, 5].map(|index| f.capsules[index].capture);
    let clock = fixtures::query(
        &f.rig,
        [h("image-camera-1"), h("image-camera-2")],
        &captures,
        50_000_000,
    )?;
    let bytes = fixtures::attach(
        &mut f.document,
        &f.rig,
        &f.capsules,
        &clock,
        "original-clock-query.json",
    )?;
    Ok((f, bytes, clock))
}
fn images(query: &Query, rig: &SceneRig, work: &mut WorkBudget<'_>) -> Test<Vec<PreparedImage>> {
    query
        .views
        .iter()
        .map(|view| {
            checked(view.image.prepare(
                rig.camera(view.camera).ok_or("camera")?.camera.intrinsics,
                work,
            ))
        })
        .collect()
}
fn replay(
    query: &Query,
    bytes: &[u8],
    rig: &SceneRig,
    work: &mut WorkBudget<'_>,
) -> Test<temporal_clock::Ready> {
    let images = images(query, rig, work)?;
    checked(query.clock_validation.as_ref().ok_or("clock spec")?.replay(
        bytes,
        &query.views,
        rig,
        &images,
        work,
    ))
}
fn report<'a>(value: &'a Value, path: &[&str]) -> Test<&'a Value> {
    let Some((key, rest)) = path.split_first() else {
        return Ok(value);
    };
    let value = value
        .object()
        .and_then(|v| v.get(*key))
        .ok_or("report field")?;
    report(value, rest)
}

#[test]
fn original_query_replay_feeds_all_clock_hypotheses_into_actual_motion_matching() -> Test {
    let (f, bytes, _) = fixture()?;
    let query = f.query()?;
    assert_eq!(query.version, 2);
    let mut work = WorkBudget::new(100_000_000);
    work.charge(41)?;
    let clock = replay(&query, &bytes, &f.rig, &mut work)?;
    let before_bind = work.used();
    let captures = query
        .views
        .iter()
        .zip(&f.capsules)
        .map(|(view, capsule)| checked(clock.capture(view, capsule)))
        .collect::<Test<Vec<_>>>()?;
    checked(validate_capture_policy(&query, &captures, &f.rig))?;
    let views = checked(bind_with_clock(&query, &f.resolved(), &f.rig, Some(&clock)))?;
    assert_eq!(
        work.used(),
        before_bind,
        "the adapter does not create/refill a geometry budget"
    );
    for (index, view) in views.iter().enumerate() {
        assert_eq!(view.capture, captures[index]);
        if index % 2 == 0 {
            assert_eq!(
                view.capture,
                [
                    (index / 2 + 1) as u64 * 1_000_000_000 - 5,
                    (index / 2 + 1) as u64 * 1_000_000_000 + 5
                ]
            );
        } else {
            assert!(
                view.capture[1] - view.capture[0] > 1_000_000,
                "unsupported rates must widen the retained time hull"
            );
        }
        assert_eq!(view.clock_evidence, h(&bytes).bytes());
        assert_eq!(view.frame.identity(), f.frames[index].identity());
    }
    let motion = associate_temporal_features(&f.twin, &views, query.matching, &mut work)?;
    assert_eq!(motion.views().len(), 6);
    assert_eq!(motion.pairs().len(), 15);
    let component = &motion.components()[0];
    let TemporalComponentOutcome::Fused(fused) = component.outcome() else {
        return Err(format!(
            "known common-time motion refused: {:?}",
            component.outcome()
        )
        .into());
    };
    assert_eq!(fused.inputs().len(), 6);
    for (actual, expected) in fused
        .estimate()
        .velocity_per_second
        .iter()
        .zip([0.25, 0.1, 0.1])
    {
        assert!((actual - expected).abs() < 0.0001, "{actual} vs {expected}");
    }
    let text = checked(clock.render(&query.views, &f.resolved(), &mut work))?;
    let output = json_input::parse(&text)?;
    assert_eq!(
        report(&output, &["native_replay", "report", "hypothesis_count"])?.integer(),
        Some(3)
    );
    assert_eq!(
        report(
            &output,
            &[
                "native_replay",
                "report",
                "supported_in_every_session_count"
            ]
        )?
        .integer(),
        Some(1)
    );
    let projections = report(&output, &["native_replay", "report", "projections"])?
        .array()
        .ok_or("projections")?;
    for projection in projections {
        assert_eq!(
            report(projection, &["mappings"])?
                .array()
                .ok_or("mappings")?
                .len(),
            3
        );
        assert_eq!(
            report(projection, &["observation_window"])?.text(),
            Some("outside_declared_sessions")
        );
    }
    assert_eq!(
        report(&output, &["original_query_json"])?.text(),
        Some(std::str::from_utf8(&bytes)?)
    );
    for field in [
        "clock_synchronization_established",
        "clock_query_source_custody_verified",
        "source_clock_basis_upgraded",
    ] {
        assert_eq!(report(&output, &[field])?.boolean(), Some(false));
    }
    Ok(())
}

#[test]
fn unsupported_candidates_cannot_be_filtered_to_sneak_through_the_uncertainty_gate() -> Test {
    let (mut f, bytes, mut original) = fixture()?;
    *at(&mut f.document, &["max_capture_uncertainty_ns"])? = Value::Number("1000".into());
    let query = f.query()?;
    let clock = replay(&query, &bytes, &f.rig, &mut WorkBudget::new(100_000_000))?;
    let captures = query
        .views
        .iter()
        .zip(&f.capsules)
        .map(|(view, capsule)| checked(clock.capture(view, capsule)))
        .collect::<Test<Vec<_>>>()?;
    assert!(validate_capture_policy(&query, &captures, &f.rig).is_err());
    assert!(bind_with_clock(&query, &f.resolved(), &f.rig, Some(&clock)).is_err());
    // Separate explicit one-candidate input is the control, not a mutation of the native replay.
    let Value::Array(hypotheses) = at(&mut original, &["hypotheses"])? else {
        return Err("hypotheses".into());
    };
    hypotheses.retain(|row| {
        row.object()
            .and_then(|f| f.get("skew_ppb"))
            .and_then(Value::integer)
            == Some(0)
    });
    let one = fixtures::attach(
        &mut f.document,
        &f.rig,
        &f.capsules,
        &original,
        "one-explicit-candidate.json",
    )?;
    *at(&mut f.document, &["max_capture_uncertainty_ns"])? = Value::Number("1000".into());
    let query = f.query()?;
    let clock = replay(&query, &one, &f.rig, &mut WorkBudget::new(100_000_000))?;
    let views = checked(bind_with_clock(&query, &f.resolved(), &f.rig, Some(&clock)))?;
    assert_eq!(views[1].capture[1] - views[1].capture[0], 10);
    Ok(())
}

#[test]
fn replay_refuses_different_world_clock_camera_models_and_generation_declarations() -> Test {
    let (f, _, original) = fixture()?;
    for (path, changed) in [
        (vec!["world_basis"], Value::Text(h("wrong world").to_text())),
        (vec!["target_camera", "clock"], Value::Number("99".into())),
        (
            vec!["reference_camera", "intrinsics", "fx"],
            Value::Number("161".into()),
        ),
        (
            vec!["target_camera", "center", "0"],
            Value::Number("1".into()),
        ),
        (
            vec!["target_camera", "image_domain"],
            Value::Text(h("wrong image").to_text()),
        ),
        (
            vec!["target_camera", "calibration_digest"],
            Value::Text(h("wrong calibration").to_text()),
        ),
    ] {
        let mut clock = original.clone();
        *at(&mut clock, &path)? = changed;
        let mut document = f.document.clone();
        let bytes = fixtures::attach(&mut document, &f.rig, &f.capsules, &clock, "changed.json")?;
        let query = checked(parse(shared::json(&document).as_bytes(), f.rig_digest))?;
        assert!(
            replay(&query, &bytes, &f.rig, &mut WorkBudget::new(100_000_000)).is_err(),
            "accepted {path:?}"
        );
    }
    for field in [
        "calibration_generation",
        "image_generation",
        "clock_generation",
    ] {
        let mut document = f.document.clone();
        *at(&mut document, &["clock_validation", "bindings", "1", field])? =
            Value::Number("99".into());
        let query = checked(parse(shared::json(&document).as_bytes(), f.rig_digest))?;
        let bytes = shared::json(&original);
        assert!(
            replay(
                &query,
                bytes.as_bytes(),
                &f.rig,
                &mut WorkBudget::new(100_000_000)
            )
            .is_err(),
            "accepted {field}"
        );
    }
    Ok(())
}

#[test]
fn exact_original_capsule_interval_cannot_be_replaced_by_a_point_or_subinterval() -> Test {
    let (f, _, original) = fixture()?;
    for shrink in [0_i128, 3] {
        let mut clock = original.clone();
        let capture = f.capsules[1].capture;
        let middle = (capture.earliest.0 + capture.latest.0) / 2;
        *at(&mut clock, &["projections", "0", "target_interval_ns"])? =
            json_input::parse(&format!("[{},{}]", middle - shrink, middle + shrink))?;
        let mut document = f.document.clone();
        let bytes = fixtures::attach(&mut document, &f.rig, &f.capsules, &clock, "narrowed.json")?;
        let query = checked(parse(shared::json(&document).as_bytes(), f.rig_digest))?;
        let ready = replay(&query, &bytes, &f.rig, &mut WorkBudget::new(100_000_000))?;
        assert!(ready.capture(&query.views[1], &f.capsules[1]).is_err());
        assert!(bind_with_clock(&query, &f.resolved(), &f.rig, Some(&ready)).is_err());
    }
    Ok(())
}

#[test]
fn source_sensor_stream_basis_and_source_bytes_are_rechecked_after_native_replay() -> Test {
    let (f, bytes, _) = fixture()?;
    let query = f.query()?;
    let ready = replay(&query, &bytes, &f.rig, &mut WorkBudget::new(100_000_000))?;
    for mutation in 0..5 {
        let mut source = f.capsules[1].clone();
        match mutation {
            0 => source.sensor_id = SensorId::parse("sensor:wrong")?,
            1 => source.stream_id = StreamId::parse("stream:reset:g2")?,
            2 => source.clock_basis = ClockBasis::DeviceMonotonic,
            3 => source.source_digest = h("different encoded source"),
            _ => {
                source.capture =
                    CaptureInterval::new(source.capture.earliest, source.capture.earliest)?
            }
        }
        assert!(
            ready.capture(&query.views[1], &source).is_err(),
            "accepted mutation {mutation}"
        );
    }
    Ok(())
}

#[test]
fn ready_replay_is_frozen_to_whole_mapping_spec_rig_and_evidence_inventory() -> Test {
    let (f, bytes, _) = fixture()?;
    let query = f.query()?;
    let ready = replay(&query, &bytes, &f.rig, &mut WorkBudget::new(100_000_000))?;
    assert!(
        bind(&query, &f.resolved(), &f.rig).is_err(),
        "v2 cannot fall back to additive binding"
    );
    let mut changed = f.query()?;
    changed.clock_validation.as_mut().ok_or("spec")?.projections[0].projection = 99;
    assert!(bind_with_clock(&changed, &f.resolved(), &f.rig, Some(&ready)).is_err());
    let mut changed = f.query()?;
    changed.matching.clock_evidence = h("unrelated clock evidence").bytes();
    assert!(bind_with_clock(&changed, &f.resolved(), &f.rig, Some(&ready)).is_err());
    let mut changed = f.query()?;
    changed.views.truncate(4);
    assert!(bind_with_clock(&changed, &f.resolved()[..4], &f.rig, Some(&ready)).is_err());
    let rig_document = json_input::parse(&rig_document(&package()))?;
    let rig = SceneRig::from_document(&rig_document, &f.twin, &mut WorkBudget::new(1_000_000))?;
    assert!(bind_with_clock(&query, &f.resolved(), &rig, Some(&ready)).is_err());
    Ok(())
}

#[test]
fn shared_work_and_live_cancellation_never_yield_a_ready_or_partial_clock_mapping() -> Test {
    let (f, bytes, _) = fixture()?;
    let query = f.query()?;
    let mut complete = WorkBudget::new(100_000_000);
    replay(&query, &bytes, &f.rig, &mut complete)?;
    let mut short = WorkBudget::new(complete.used() - 1);
    assert!(replay(&query, &bytes, &f.rig, &mut short).is_err());
    let cancelled = AtomicBool::new(true);
    let probe = || cancelled.load(Ordering::SeqCst);
    let mut work = WorkBudget::with_cancellation_probe(100_000_000, &probe);
    assert!(replay(&query, &bytes, &f.rig, &mut work).is_err());
    cancelled.store(false, Ordering::SeqCst);
    let ready = replay(&query, &bytes, &f.rig, &mut work)?;
    cancelled.store(true, Ordering::SeqCst);
    assert!(
        ready
            .render(&query.views, &f.resolved(), &mut work)
            .is_err()
    );
    Ok(())
}
