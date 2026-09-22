#![forbid(unsafe_code)]
//! Existing association cases retained through the global compatibility API.

use super::*;

type Test = Result<(), CrossCameraError>;

fn config() -> CrossCameraConfig {
    CrossCameraConfig {
        max_time_delta_ns: 50_000_000,
        max_position_distance: 2.0,
        min_confidence: 0.1,
    }
}
fn obs(cam: &str, tid: u64, ts: i64, x: f64, y: f64) -> CameraObservation {
    CameraObservation {
        camera_id: cam.to_owned(), track_id: tid, timestamp_ns: ts, ground_x: x, ground_y: y,
    }
}

#[test]
fn same_object_in_two_cameras_associates() -> Test {
    let left = [obs("cam_a", 1, 1_000_000_000, 1.0, 2.0)];
    let right = [obs("cam_b", 3, 1_010_000_000, 1.3, 2.1)];
    let pairs = associate(&config(), &left, &right)?;
    assert_eq!(pairs.len(), 1);
    assert!(pairs[0].confidence > 0.5);
    Ok(())
}

#[test]
fn different_objects_do_not_associate() -> Test {
    let left = [obs("cam_a", 1, 1_000_000_000, 1.0, 2.0)];
    let right = [obs("cam_b", 3, 1_000_000_000, 15.0, 20.0)];
    assert!(associate(&config(), &left, &right)?.is_empty());
    Ok(())
}

#[test]
fn time_gap_beyond_max_delta_is_refused() -> Test {
    let left = [obs("cam_a", 1, 1_000_000_000, 1.0, 2.0)];
    let right = [obs("cam_b", 3, 2_000_000_000, 1.0, 2.0)];
    assert!(associate(&config(), &left, &right)?.is_empty());
    Ok(())
}

#[test]
fn greedy_best_first_prefers_closest_pair() -> Test {
    // Retain the historical test name: this unambiguous fixture is also globally optimal.
    let left = [obs("cam_a", 1, 1_000_000_000, 1.0, 2.0), obs("cam_a", 2, 1_000_000_000, 5.0, 6.0)];
    let right = [obs("cam_b", 10, 1_010_000_000, 1.1, 2.1), obs("cam_b", 20, 1_010_000_000, 5.1, 6.1)];
    let pairs = associate(&config(), &left, &right)?;
    assert_eq!(pairs.len(), 2);
    assert_eq!((pairs[0].first.track_id, pairs[0].second.track_id), (1, 10));
    assert_eq!((pairs[1].first.track_id, pairs[1].second.track_id), (2, 20));
    assert!(pairs.iter().all(|pair| pair.confidence > 0.5));
    Ok(())
}

#[test]
fn same_camera_observations_are_skipped() -> Test {
    let left = [obs("cam_a", 1, 1_000_000_000, 1.0, 2.0)];
    assert!(associate(&config(), &left, &left)?.is_empty());
    Ok(())
}

#[test]
fn invalid_config_is_refused() {
    assert!(CrossCameraConfig { max_time_delta_ns: 0, ..config() }.validate().is_err());
    assert!(CrossCameraConfig { min_confidence: 1.5, ..config() }.validate().is_err());
}

#[test]
fn non_finite_config_values_are_refused_not_silently_enabled() {
    assert!(CrossCameraConfig { max_position_distance: f64::NAN, ..config() }.validate().is_err());
    assert!(CrossCameraConfig { max_position_distance: f64::INFINITY, ..config() }.validate().is_err());
    assert!(CrossCameraConfig { min_confidence: f64::NAN, ..config() }.validate().is_err());
}

#[test]
fn deterministic_across_runs() -> Test {
    let left = [obs("cam_a", 1, 1_000_000_000, 1.0, 2.0)];
    let right = [obs("cam_b", 3, 1_010_000_000, 1.1, 2.1)];
    assert_eq!(associate(&config(), &left, &right)?, associate(&config(), &left, &right)?);
    Ok(())
}
