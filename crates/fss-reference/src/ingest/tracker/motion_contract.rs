#![forbid(unsafe_code)]
//! Executable motion-model and public coasting regressions.
use super::*;

fn config() -> TrackerConfig {
    TrackerConfig {
        min_hits: 2,
        max_misses: 5,
        iou_threshold: 0.1,
        process_noise: 1.0,
        measurement_noise: 1.0,
    }
}
fn detection(x: f64, y: f64) -> Detection {
    Detection {
        box_x: x,
        box_y: y,
        box_w: 20.0,
        box_h: 20.0,
    }
}

#[test]
fn prediction_transports_velocity_covariance_without_coupling_axes() {
    let mut state = KalmanState::new(3.0, 5.0);
    state.x[2] = 4.0;
    state.x[3] = -2.0;
    state.predict(2.0, 3.0);
    assert_eq!(state.x, [11.0, 1.0, 4.0, -2.0]);
    assert_eq!(
        state.p,
        [
            [416.0, 0.0, 200.0, 0.0],
            [0.0, 416.0, 0.0, 200.0],
            [200.0, 0.0, 106.0, 0.0],
            [0.0, 200.0, 0.0, 106.0]
        ]
    );
}

#[test]
fn measurement_learns_velocity_and_preserves_covariance() {
    let mut state = KalmanState::new(0.0, 0.0);
    state.predict(1.0, 1.0);
    state.update(10.0, 0.0, 1.0);
    assert!((state.x[0] - 1110.0 / 112.0).abs() < 1e-12);
    assert!((state.x[2] - 1000.0 / 112.0).abs() < 1e-12);
    assert_eq!(state.x[1], 0.0);
    assert_eq!(state.x[3], 0.0);
    assert!((state.p[0][0] - 111.0 / 112.0).abs() < 1e-12);
    assert!((state.p[0][2] - 100.0 / 112.0).abs() < 1e-12);
    assert!((state.p[2][2] - (101.0 - 10000.0 / 112.0)).abs() < 1e-12);
    for (i, row) in state.p.iter().enumerate() {
        for (j, value) in row.iter().enumerate() {
            assert_eq!(*value, state.p[j][i]);
        }
    }
}

#[test]
fn long_run_covariance_remains_positive_and_velocity_converges() {
    let mut state = KalmanState::new(0.0, 0.0);
    for frame in 1..=2000 {
        state.predict(1.0, 0.01);
        state.update(f64::from(frame) * 3.0, -f64::from(frame) * 2.0, 0.5);
        for axis in 0..2 {
            let position = state.p[axis][axis];
            let velocity = state.p[axis + 2][axis + 2];
            let cross = state.p[axis][axis + 2];
            assert!(position.is_finite() && velocity.is_finite());
            assert!(position > 0.0 && velocity > 0.0);
            assert!(position * velocity - cross * cross > 0.0);
            assert_eq!(cross, state.p[axis + 2][axis]);
        }
        assert_eq!(state.p[0][1], 0.0);
        assert_eq!(state.p[2][3], 0.0);
    }
    assert!((state.x[2] - 3.0).abs() < 1e-9);
    assert!((state.x[3] + 2.0).abs() < 1e-9);
}

#[test]
fn coasting_advances_public_position_and_reacquires_the_same_track() -> Result<(), TrackerError> {
    let mut tracker = MultiObjectTracker::new(config())?;
    for frame in 0..10 {
        tracker.step(&[detection(f64::from(frame) * 8.0, 20.0)]);
    }
    assert_eq!(tracker.tracks.len(), 1);
    let before = tracker.tracks[0].clone();
    assert!((before.vx - 8.0).abs() < 0.1);
    for gap in 1..=3 {
        let output = tracker.step(&[]);
        assert_eq!(output.tracks.len(), 1);
        let lost = &output.tracks[0];
        assert_eq!(lost.id, before.id);
        assert_eq!(lost.status, TrackStatus::Lost);
        assert_eq!(lost.misses, gap);
        assert!((lost.cx - before.cx - f64::from(gap) * before.vx).abs() < 1e-10);
        assert!((lost.cy - before.cy).abs() < 1e-10);
    }
    let output = tracker.step(&[detection(13.0 * 8.0, 20.0)]);
    assert_eq!(output.tracks.len(), 1);
    assert_eq!(output.new_tracks, 0);
    assert_eq!(output.tracks[0].id, before.id);
    assert_eq!(output.tracks[0].status, TrackStatus::Confirmed);
    assert_eq!(output.tracks[0].misses, 0);
    Ok(())
}

#[test]
fn one_required_hit_confirms_on_creation() -> Result<(), TrackerError> {
    let mut cfg = config();
    cfg.min_hits = 1;
    let mut tracker = MultiObjectTracker::new(cfg)?;
    let output = tracker.step(&[detection(0.0, 0.0)]);
    assert_eq!(output.tracks.len(), 1);
    assert_eq!(output.tracks[0].status, TrackStatus::Confirmed);
    assert_eq!(output.tracks[0].hits, 1);
    Ok(())
}

#[test]
fn nonfinite_parameters_are_rejected_before_state_creation() {
    for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        let mut cfg = config();
        cfg.iou_threshold = value;
        assert!(MultiObjectTracker::new(cfg).is_err());
        let mut cfg = config();
        cfg.process_noise = value;
        assert!(MultiObjectTracker::new(cfg).is_err());
        let mut cfg = config();
        cfg.measurement_noise = value;
        assert!(MultiObjectTracker::new(cfg).is_err());
    }
}
