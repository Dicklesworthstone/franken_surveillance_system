#![forbid(unsafe_code)]
//! Executes the actual package data types, pure projection and scoring engine.
//! Synthetic rows exercise their contracts only; no mock retained owner or custody success
//! is defined here, and these cases establish no real detection quality.

#[path = "../../fss-reference/src/ingest/package_event/types.rs"]
pub mod actual_package_types;
#[path = "../../fss-reference/src/evaluation.rs"]
pub mod evaluation;
mod ingest {
    pub mod package_event {
        pub use crate::actual_package_types as types;
    }
}
#[path = "../../fss-reference/src/ingest/package_evaluation/contract.rs"]
pub mod contract;

use std::cell::Cell;

use actual_package_types::{
    PackageDetectionRecord, PackageObservation, PackageTrack, PackageTrackingBoundary,
    PackageTrackingConfig, RecordDetection, RecordFrame,
};
use contract::{
    MAX_PACKAGE_EVALUATION_MATCHING_CELLS, PackageEvaluationError, PackageEvaluationFrameBinding,
    PackageEvaluationProjection, PackageEvaluationRequest, PackageEvaluationSourceBinding,
    PackageEvaluationTrackDisposition, project_package_candidates,
    validate_package_evaluation_inputs,
};
use evaluation::{
    ClosedIntervalNs, EvaluationPolicy, FalseAlertBudget, LabelSet, LabeledClip,
    NotObservableInterval, NotObservableReason, TruthEvent, evaluate_cancellable,
};
use fss_core::{CaptureInterval, ClockBasis, ContentDigest, LedgerAnchor, TimestampNs};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[derive(Clone)]
struct Fixture {
    request: PackageEvaluationRequest,
    source: PackageEvaluationSourceBinding,
    record: PackageDetectionRecord,
    tracks: Vec<PackageTrack>,
    labels: LabelSet,
    policy: EvaluationPolicy,
}

fn digest(value: &str) -> ContentDigest {
    ContentDigest::sha256(value.as_bytes())
}

fn fixture() -> Fixture {
    let request = PackageEvaluationRequest {
        report_digest: digest("native-report"),
        label: "person".into(),
        tracking: PackageTrackingConfig {
            confirmation_hits: 3,
            maximum_missed_frames: 2,
            minimum_iou_ppm: 100_000,
        },
        clip_id: "clip:held-out".into(),
        clip_origin_ns: 100,
        stream_id: "stream:camera:g1".into(),
        clock_basis: ClockBasis::Estimated,
    };
    let scores = [0.99_f32, 0.9, 0.25000003, 0.99999, 0.999999];
    let frames: Vec<_> = scores
        .iter()
        .enumerate()
        .map(|(index, score)| {
            let capture = CaptureInterval {
                earliest: TimestampNs(100 + index as i128 * 10),
                latest: TimestampNs(100 + index as i128 * 10),
            };
            RecordFrame {
                segment: index as u64,
                capsule_digest: digest(&format!("capsule:{index}")),
                sensor_id: "sensor:camera".into(),
                capture,
                dimensions: [64, 48],
                color: "jpeg_rgb".into(),
                inference_identity: digest(&format!("inference:{index}")),
                output_digest: digest(&format!("output:{index}")),
                detection_report_digest: digest(&format!("head-report:{index}")),
                detections: vec![RecordDetection {
                    row: 7,
                    class_index: 0,
                    score_bits: score.to_bits(),
                    bounds: [0, 0, 20 * 256, 20 * 256],
                    clipped: false,
                }],
            }
        })
        .collect();
    let observations = frames
        .iter()
        .map(|frame| PackageObservation {
            segment: frame.segment,
            capsule_digest: frame.capsule_digest,
            track_box: [10, 10, 20, 20],
            detection: Some((
                7,
                frame.detections[0].score_bits,
                frame.detections[0].bounds,
                900_000,
            )),
        })
        .collect();
    let source_frames = frames
        .iter()
        .map(|frame| PackageEvaluationFrameBinding {
            segment: frame.segment,
            capsule_digest: frame.capsule_digest,
            source_digest: digest(&format!("source:{}", frame.segment)),
            sensor_id: frame.sensor_id.clone(),
            stream_id: request.stream_id.clone(),
            sequence: frame.segment + 10,
            clock_basis: ClockBasis::Estimated,
            capture: frame.capture,
            gap_before: false,
        })
        .collect();
    Fixture {
        source: PackageEvaluationSourceBinding {
            site_lineage: "site:local".into(),
            principal: "agent:evaluator".into(),
            analysis_digest: digest("analysis"),
            record_digest: digest("record"),
            retained_root: digest("retained-root"),
            retained_anchor: LedgerAnchor::genesis("site:local"),
            authority_anchor: LedgerAnchor::genesis("site:local"),
            import_manifest_digest: digest("import-manifest"),
            privacy_binding: digest("privacy:none"),
            privacy_policy: None,
            capture_time_label: "operator_assumption".into(),
            non_container_omissions: false,
            first_source_gap: None,
            frames: source_frames,
            boundaries: vec![],
        },
        record: PackageDetectionRecord {
            report_digest: request.report_digest,
            package_digest: digest("package"),
            manifest_digest: digest("manifest"),
            model_id: "MOD-EVAL-001".into(),
            generation: "model:g7".into(),
            model_digest: digest("model"),
            graph_digest: digest("graph"),
            contract_digest: digest("head-contract"),
            import_identity: digest("import"),
            import_root: digest("import-root"),
            media_format: "mjpeg".into(),
            first_segment: 0,
            segment_count: frames.len() as u64,
            minimum_score_ppm: 200_000,
            labels: vec!["person".into(), "cat".into()],
            frames,
        },
        tracks: vec![PackageTrack {
            identity: digest("track:1"),
            track_id: 1,
            confirmed: true,
            observations,
        }],
        labels: LabelSet {
            clips: vec![LabeledClip {
                clip_id: request.clip_id.clone(),
                duration_ns: 41,
                not_observable: vec![],
            }],
            events: vec![TruthEvent {
                event_id: "truth:person".into(),
                clip_id: request.clip_id.clone(),
                class: request.label.clone(),
                zone: None,
                interval: ClosedIntervalNs::new(0, 40),
            }],
        },
        policy: EvaluationPolicy {
            early_tolerance_ns: 0,
            late_tolerance_ns: 0,
            false_alert_budget: FalseAlertBudget {
                max_false_alerts: 1,
                per_observed_ns: 1_000,
            },
        },
        request,
    }
}

fn project(input: &Fixture) -> Result<PackageEvaluationProjection, PackageEvaluationError> {
    project_package_candidates(
        &input.request,
        &input.source,
        &input.record,
        &input.tracks,
        &input.labels,
        &input.policy,
        &|| false,
    )
}

fn set_score(input: &mut Fixture, frame: usize, value: f32) {
    input.record.frames[frame].detections[0].score_bits = value.to_bits();
    if let Some(assignment) = &mut input.tracks[0].observations[frame].detection {
        assignment.1 = value.to_bits();
    }
}

#[test]
fn first_confirmed_actual_assignment_sets_time_and_score_without_hindsight() -> Test {
    let input = fixture();
    let projected = project(&input)?;
    assert_eq!(projected.candidates.candidates.len(), 1);
    let candidate = &projected.candidates.candidates[0];
    assert_eq!(candidate.detect_ns, 20);
    assert_eq!(candidate.score_ppm, 250_000);
    assert_eq!(candidate.class, "person");
    assert_eq!(candidate.zone, None);
    let evidence = projected.provenance.tracks[0]
        .first_confirmation
        .as_ref()
        .ok_or("missing confirmation")?;
    assert_eq!(evidence.observation_index, 2);
    assert_eq!(evidence.segment, 2);
    assert_eq!(evidence.detection_row, 7);
    assert_eq!(evidence.score_bits, 0.25000003_f32.to_bits());
    assert_eq!(evidence.capture_ns, 120);
    assert_eq!(
        evidence.inference_identity,
        input.record.frames[2].inference_identity
    );
    assert_eq!(evidence.output_digest, input.record.frames[2].output_digest);
    assert_eq!(projected.provenance.minimum_score_ppm, 200_000);
    assert_eq!(projected.digest, ContentDigest::sha256(projected.encoded()));
    let evaluated = evaluate_cancellable(
        &projected.identity,
        &input.policy,
        &input.labels,
        &projected.candidates,
        MAX_PACKAGE_EVALUATION_MATCHING_CELLS,
        &|| false,
    )?;
    assert_eq!(evaluated.counts.true_positives, 1);
    assert_eq!(evaluated.counts.false_positives, 0);
    assert_eq!(evaluated.time_to_detect.ok_or("missing TTD")?.min_ns, 20);
    assert_eq!(evaluated.durations.observed_ns, 41);
    assert!(evaluated.verify_digest());
    Ok(())
}

#[test]
fn later_scores_and_truth_labels_never_rewrite_first_confirmation() -> Test {
    let input = fixture();
    let original = project(&input)?;
    let mut changed = input.clone();
    set_score(&mut changed, 0, 1.0);
    set_score(&mut changed, 3, 0.21);
    set_score(&mut changed, 4, 0.22);
    changed.labels.events[0].interval = ClosedIntervalNs::new(25, 40);
    let rerun = project(&changed)?;
    assert_eq!(original.candidates, rerun.candidates);
    assert_eq!(
        original.provenance.tracks[0].first_confirmation,
        rerun.provenance.tracks[0].first_confirmation
    );
    Ok(())
}

#[test]
fn confirmed_before_or_after_subwindow_is_excluded_without_later_replacement() -> Test {
    for (origin, duration, expected) in [
        (130, 11, PackageEvaluationTrackDisposition::BeforeClip),
        (100, 20, PackageEvaluationTrackDisposition::AfterClip),
    ] {
        let mut input = fixture();
        input.request.clip_origin_ns = origin;
        input.labels.clips[0].duration_ns = duration;
        input.labels.events.clear();
        let projected = project(&input)?;
        assert!(projected.candidates.candidates.is_empty());
        assert_eq!(projected.provenance.tracks.len(), 1);
        assert_eq!(projected.provenance.tracks[0].disposition, expected);
        assert_eq!(
            projected.provenance.tracks[0]
                .first_confirmation
                .as_ref()
                .ok_or("missing excluded confirmation")?
                .capture_ns,
            120
        );
    }
    let mut inclusive = fixture();
    inclusive.request.clip_origin_ns = 120;
    inclusive.labels.clips[0].duration_ns = 1;
    inclusive.labels.events.clear();
    assert_eq!(project(&inclusive)?.candidates.candidates[0].detect_ns, 0);
    Ok(())
}

#[test]
fn tentative_and_negative_clips_stay_in_complete_accounting() -> Test {
    let mut tentative = fixture();
    tentative.tracks[0].observations.truncate(2);
    tentative.tracks[0].confirmed = false;
    for frame in &mut tentative.record.frames[2..] {
        frame.detections.clear();
    }
    let projected = project(&tentative)?;
    assert!(projected.candidates.candidates.is_empty());
    assert_eq!(
        projected.provenance.tracks[0].disposition,
        PackageEvaluationTrackDisposition::Unconfirmed
    );
    assert!(projected.provenance.tracks[0].first_confirmation.is_none());
    let evaluated = evaluate_cancellable(
        &projected.identity,
        &tentative.policy,
        &tentative.labels,
        &projected.candidates,
        MAX_PACKAGE_EVALUATION_MATCHING_CELLS,
        &|| false,
    )?;
    assert_eq!(evaluated.counts.false_negatives, 1);

    let mut empty = fixture();
    empty.tracks.clear();
    empty.labels.events.clear();
    for frame in &mut empty.record.frames {
        frame.detections.clear();
    }
    let projected = project(&empty)?;
    let evaluated = evaluate_cancellable(
        &projected.identity,
        &empty.policy,
        &empty.labels,
        &projected.candidates,
        MAX_PACKAGE_EVALUATION_MATCHING_CELLS,
        &|| false,
    )?;
    assert_eq!(evaluated.counts.candidates, 0);
    assert_eq!(evaluated.durations.observed_ns, 41);
    Ok(())
}

#[test]
fn float_scores_are_floored_and_original_bits_survive() -> Test {
    for (score, expected) in [
        (0.0_f32, 0),
        (-0.0, 0),
        (0.9, 899_999),
        (1.0, 1_000_000),
        (f32::from_bits(1), 0),
    ] {
        let mut input = fixture();
        input.record.minimum_score_ppm = 0;
        set_score(&mut input, 2, score);
        let result = project(&input)?;
        assert_eq!(result.candidates.candidates[0].score_ppm, expected);
        assert_eq!(
            result.provenance.tracks[0]
                .first_confirmation
                .as_ref()
                .ok_or("missing confirmation")?
                .score_bits,
            score.to_bits()
        );
    }
    for score in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -0.01, 1.01] {
        let mut input = fixture();
        set_score(&mut input, 2, score);
        assert!(project(&input).is_err());
    }
    Ok(())
}

#[test]
fn source_time_uncertainty_unknown_labels_gaps_and_order_are_refused() {
    let mut cases = Vec::new();
    let mut input = fixture();
    input.source.capture_time_label = "unknown".into();
    cases.push(input);
    let mut input = fixture();
    input.source.non_container_omissions = true;
    cases.push(input);
    let mut input = fixture();
    input.source.first_source_gap = Some(0);
    cases.push(input);
    let mut input = fixture();
    input.source.frames[0].gap_before = true;
    cases.push(input);
    let mut input = fixture();
    input.source.frames[2].sequence += 1;
    cases.push(input);
    let mut input = fixture();
    input.source.frames[2].clock_basis = ClockBasis::HostMonotonic;
    cases.push(input);
    let mut input = fixture();
    input.source.frames[2].stream_id = "stream:other".into();
    cases.push(input);
    let mut input = fixture();
    input.record.frames[2].capture.latest.0 += 1;
    input.source.frames[2].capture.latest.0 += 1;
    cases.push(input);
    let mut input = fixture();
    input.record.frames.swap(1, 2);
    cases.push(input);
    let mut input = fixture();
    input.record.frames[1].capture = input.record.frames[0].capture;
    input.source.frames[1].capture = input.source.frames[0].capture;
    cases.push(input);
    for input in cases {
        assert!(project(&input).is_err());
    }
}

#[test]
fn declared_window_never_infers_padding_cadence_or_end_of_file_tail() -> Test {
    for (origin, duration) in [(99, 41), (100, 42), (141, 1)] {
        let mut input = fixture();
        input.request.clip_origin_ns = origin;
        input.labels.clips[0].duration_ns = duration;
        input.labels.events.clear();
        assert!(project(&input).is_err());
    }
    let mut exact = fixture();
    exact.labels.clips[0].duration_ns = 40;
    exact.labels.events.clear();
    assert_eq!(project(&exact)?.provenance.analysed_sample_hull, [100, 140]);
    let mut overflow = fixture();
    overflow.request.clip_origin_ns = i128::MAX;
    assert!(matches!(
        project(&overflow),
        Err(PackageEvaluationError::TimeOverflow)
    ));
    let mut one = fixture();
    one.record.frames.truncate(1);
    one.source.frames.truncate(1);
    one.record.segment_count = 1;
    assert!(matches!(project(&one), Err(PackageEvaluationError::Limit)));
    Ok(())
}

#[test]
fn source_epoch_restarts_never_join_tracks_and_false_boundary_flags_refuse() -> Test {
    let mut input = fixture();
    input.request.tracking.confirmation_hits = 2;
    input.record.frames[3].dimensions = [80, 48];
    input.record.frames[4].dimensions = [80, 48];
    input.source.boundaries = vec![PackageTrackingBoundary {
        before_segment: 3,
        source_gap: false,
        sequence_gap: false,
        dimensions_changed: true,
    }];
    assert!(project(&input).is_err()); // A pre-gap track may not borrow the new epoch's hits.
    let later = input.tracks[0].observations.split_off(3);
    input.tracks.push(PackageTrack {
        identity: digest("track:2"),
        track_id: 2,
        confirmed: true,
        observations: later,
    });
    let projected = project(&input)?;
    assert_eq!(projected.candidates.candidates.len(), 2);
    assert_eq!(
        projected.provenance.tracks[0]
            .first_confirmation
            .as_ref()
            .ok_or("first")?
            .capture_ns,
        110
    );
    assert_eq!(
        projected.provenance.tracks[1]
            .first_confirmation
            .as_ref()
            .ok_or("second")?
            .capture_ns,
        140
    );
    input.source.boundaries.clear();
    assert!(project(&input).is_err()); // Missing boundary cannot hide changed dimensions.
    let mut false_boundary = fixture();
    false_boundary.source.boundaries = vec![PackageTrackingBoundary {
        before_segment: 3,
        source_gap: false,
        sequence_gap: false,
        dimensions_changed: true,
    }];
    assert!(project(&false_boundary).is_err());
    Ok(())
}

#[test]
fn ever_confirmed_flags_missing_rows_and_reassigned_scores_do_not_authorize_samples() {
    let mut cases = Vec::new();
    let mut input = fixture();
    input.tracks[0].confirmed = false;
    cases.push(input);
    let mut input = fixture();
    input.tracks[0].observations.truncate(1);
    cases.push(input);
    let mut input = fixture();
    input.tracks[0].observations[2].detection = None;
    cases.push(input);
    let mut input = fixture();
    input.tracks[0].observations[2].capsule_digest = digest("wrong");
    cases.push(input);
    let mut input = fixture();
    input.record.frames[2].detections[0].class_index = 1;
    cases.push(input);
    let mut input = fixture();
    input.record.frames[2].detections[0].score_bits = 1.0_f32.to_bits();
    cases.push(input);
    let mut input = fixture();
    input.tracks[0].observations.swap(0, 1);
    cases.push(input);
    for input in cases {
        assert!(project(&input).is_err());
    }
}

#[test]
fn native_tentative_and_confirmed_retirement_rules_are_preserved() -> Test {
    let mut tentative = fixture();
    tentative.tracks[0].observations.remove(1);
    assert!(project(&tentative).is_err()); // Tentative first miss retires that identity.
    let mut retained = fixture();
    retained.request.tracking.confirmation_hits = 1;
    retained.tracks[0].observations.remove(1);
    project(&retained)?; // A confirmed track can recover after one miss.
    retained.tracks[0].observations = vec![
        retained.tracks[0].observations[0].clone(),
        retained.tracks[0].observations[3].clone(),
    ];
    assert!(project(&retained).is_err()); // Three misses exceed maximum two.
    Ok(())
}

#[test]
fn duplicate_tracks_and_double_assigned_rows_refuse_instead_of_inflating_recall() {
    let mut duplicate = fixture();
    duplicate.tracks.push(duplicate.tracks[0].clone());
    assert!(project(&duplicate).is_err());
    let mut duplicate = fixture();
    let mut track = duplicate.tracks[0].clone();
    track.track_id = 2;
    track.identity = digest("track:2");
    duplicate.tracks.push(track);
    assert!(project(&duplicate).is_err());
}

#[test]
fn one_native_class_no_zones_and_declared_label_gaps_are_explicit() -> Test {
    let mut wrong = fixture();
    wrong.labels.events[0].class = "intrusion".into();
    assert!(
        validate_package_evaluation_inputs(&wrong.request, &wrong.labels, &wrong.policy).is_err()
    );
    let mut zoned = fixture();
    zoned.labels.events[0].zone = Some("front-door".into());
    assert!(project(&zoned).is_err());
    let mut input = fixture();
    input.labels.clips[0]
        .not_observable
        .push(NotObservableInterval {
            interval: ClosedIntervalNs::new(19, 21),
            reason: NotObservableReason::Occluded,
        });
    let projected = project(&input)?;
    assert_eq!(projected.candidates.candidates.len(), 1); // Projection never silently removes it.
    let evaluated = evaluate_cancellable(
        &projected.identity,
        &input.policy,
        &input.labels,
        &projected.candidates,
        MAX_PACKAGE_EVALUATION_MATCHING_CELLS,
        &|| false,
    )?;
    assert_eq!(evaluated.counts.candidates_inside_not_observable, 1);
    assert_eq!(evaluated.durations.not_observable_ns, 3);
    assert_eq!(evaluated.durations.observed_ns, 38);
    Ok(())
}

#[test]
fn exact_model_threshold_authority_privacy_and_principal_pins_affect_identity() -> Test {
    let input = fixture();
    let original = project(&input)?;
    let mut changes = Vec::new();
    let mut changed = input.clone();
    changed.record.model_digest = digest("other-model");
    changes.push(changed);
    let mut changed = input.clone();
    changed.record.generation = "model:g8".into();
    changes.push(changed);
    let mut changed = input.clone();
    changed.record.contract_digest = digest("other-head");
    changes.push(changed);
    for changed in changes {
        let projected = project(&changed)?;
        assert_ne!(
            projected.identity.model_generation,
            original.identity.model_generation
        );
        assert_ne!(projected.digest, original.digest);
    }
    let mut changed = input.clone();
    changed.record.minimum_score_ppm += 1;
    assert_ne!(
        project(&changed)?.identity.pipeline_generation,
        original.identity.pipeline_generation
    );
    let mut changed = input.clone();
    changed.policy.late_tolerance_ns = 5;
    assert_ne!(
        project(&changed)?.identity.policy_generation,
        original.identity.policy_generation
    );
    let mut changes = Vec::new();
    let mut changed = input.clone();
    changed.source.privacy_binding = digest("privacy:changed");
    changes.push(changed);
    let mut changed = input.clone();
    changed.source.principal = "agent:other-reader".into();
    changes.push(changed);
    let mut changed = input;
    changed.source.authority_anchor.commit_sequence = 1;
    changes.push(changed);
    for changed in changes {
        assert_ne!(project(&changed)?.digest, original.digest);
    }
    Ok(())
}

#[test]
fn inconsistent_site_epoch_privacy_source_and_text_pins_refuse() {
    let mut cases = Vec::new();
    let mut input = fixture();
    input.source.site_lineage = "site:other".into();
    cases.push(input);
    let mut input = fixture();
    input.source.authority_anchor.ledger_epoch = 1;
    cases.push(input);
    let mut input = fixture();
    input.source.retained_anchor.commit_sequence = 1;
    cases.push(input);
    let mut input = fixture();
    input.source.principal.clear();
    cases.push(input);
    let mut input = fixture();
    input.source.frames[1].sensor_id = "sensor:other".into();
    cases.push(input);
    let mut input = fixture();
    input.request.report_digest = digest("other-report");
    cases.push(input);
    let mut input = fixture();
    input.request.label = "person with spaces".into();
    cases.push(input);
    for input in cases {
        assert!(project(&input).is_err());
    }
}

#[test]
fn canonical_projection_normalizes_unordered_binding_inputs_not_display_history() -> Test {
    let original = fixture();
    let expected = project(&original)?;
    let mut changed = original.clone();
    changed.source.frames.reverse();
    assert_eq!(expected, project(&changed)?);
    let mut changed = original;
    changed.record.frames.reverse();
    assert!(project(&changed).is_err());
    Ok(())
}

#[test]
fn hard_limits_and_cancellation_refuse_before_partial_projection() {
    let mut input = fixture();
    input.tracks.resize(129, input.tracks[0].clone());
    assert!(matches!(
        project(&input),
        Err(PackageEvaluationError::Limit)
    ));
    let mut input = fixture();
    input
        .labels
        .events
        .resize(129, input.labels.events[0].clone());
    assert!(matches!(
        project(&input),
        Err(PackageEvaluationError::Limit)
    ));
    let mut input = fixture();
    input.labels.clips[0].not_observable = vec![
        NotObservableInterval {
            interval: ClosedIntervalNs::new(0, 0),
            reason: NotObservableReason::Other
        };
        129
    ];
    assert!(matches!(
        project(&input),
        Err(PackageEvaluationError::Limit)
    ));
    let input = fixture();
    assert!(matches!(
        project_package_candidates(
            &input.request,
            &input.source,
            &input.record,
            &input.tracks,
            &input.labels,
            &input.policy,
            &|| true
        ),
        Err(PackageEvaluationError::Cancelled)
    ));
    let calls = Cell::new(0);
    let cancelled = || {
        let next = calls.get() + 1;
        calls.set(next);
        next >= 17
    };
    assert!(matches!(
        project_package_candidates(
            &input.request,
            &input.source,
            &input.record,
            &input.tracks,
            &input.labels,
            &input.policy,
            &cancelled
        ),
        Err(PackageEvaluationError::Cancelled)
    ));
    assert_eq!(calls.get(), 17);
}
