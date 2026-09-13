#![forbid(unsafe_code)]
//! Conditional motion contracts; fixtures are not property measurements.

use fss_geometry::{ForecastBasis, GeometryBasis, GeometryError, MAX_FORECAST_NS,
    MotionForecast, RouteCandidate, RouteEnd, RoutePriors, RouteSurface, WorkBudget,
    forecast_routes};
use std::sync::atomic::AtomicBool;

const SECOND: u64 = 1_000_000_000;
fn basis() -> Result<ForecastBasis, GeometryError> {
    ForecastBasis::new(GeometryBasis::new(1, 2)?, 3, 4, 5, 6)
}
fn route(points: &[[f64; 3]]) -> RouteCandidate<'_> {
    RouteCandidate { id: 1, points, speed: 2.0, initial_pause_ns: SECOND,
        end: RouteEnd::Stop, surface: RouteSurface::PedestrianPath,
        base_mass: 1, protected: false }
}
fn run(routes: &[RouteCandidate<'_>], classes: [u32; 4]) -> Result<MotionForecast, GeometryError> {
    forecast_routes(basis()?, 100 * SECOND, 5 * SECOND, RoutePriors::new(classes, 4)?,
        routes, &mut WorkBudget::new(1_000_000))
}

#[test]
fn turns_initial_pause_and_terminal_stop() -> Result<(), GeometryError> {
    let points = [[0.0, 0.0, 10.0], [2.0, 0.0, 10.0], [2.0, 2.0, 10.0]];
    let forecast = run(&[route(&points)], [1, 0, 0, 0])?;
    let path = &forecast.hypotheses()[0];
    let mut budget = WorkBudget::new(1000);
    for (time, expected) in [(0, points[0]), (SECOND, points[0]),
        (SECOND + SECOND / 2, [1.0, 0.0, 10.0]),
        (2 * SECOND + SECOND / 2, [2.0, 1.0, 10.0]), (5 * SECOND, points[2])] {
        assert_eq!(path.position_at(time, &mut budget)?, Some(expected));
    }
    assert_eq!(path.position_at(5 * SECOND + 1, &mut budget)?, None);
    assert_eq!(forecast.reference_ns(), 100 * SECOND);
    assert_eq!(forecast.basis(), basis()?);
    Ok(())
}

#[test]
fn unknown_tail_does_not_become_a_frozen_target() -> Result<(), GeometryError> {
    let points = [[0.0, 0.0, 10.0], [2.0, 0.0, 10.0]];
    let forecast = run(&[RouteCandidate { end: RouteEnd::Unknown, ..route(&points) }], [1, 0, 0, 0])?;
    let path = &forecast.hypotheses()[0];
    assert_eq!(path.modeled_until_ns(), 2 * SECOND);
    assert_eq!(path.position_at(2 * SECOND, &mut WorkBudget::new(20))?, Some(points[1]));
    assert_eq!(path.position_at(2 * SECOND + 1, &mut WorkBudget::new(20))?, None);
    Ok(())
}

#[test]
fn bears_and_unknown_classes_do_not_inherit_person_path_bias() -> Result<(), GeometryError> {
    let points = [[0.0, 0.0, 10.0]];
    let routes = [route(&points), RouteCandidate { id: 2, surface: RouteSurface::OffPath,
        protected: true, ..route(&points) }];
    for (classes, masses) in [([1, 0, 0, 0], [4, 1]), ([0, 1, 0, 0], [1, 1]),
        ([0, 0, 1, 0], [1, 1]), ([0, 0, 0, 1], [1, 1]), ([1, 1, 0, 0], [5, 2])] {
        let forecast = run(&routes, classes)?;
        assert_eq!(forecast.hypotheses().iter().map(|path| path.mass()).collect::<Vec<_>>(), masses);
        assert_eq!(forecast.total_mass(), masses.iter().sum::<u64>());
        assert!(forecast.hypotheses()[1].protected());
        assert_eq!(forecast.priors().class_masses(), classes);
    }
    Ok(())
}

#[test]
fn route_permutation_preserves_the_complete_forecast() -> Result<(), GeometryError> {
    let points = [[0.0, 0.0, 10.0], [10.0, 0.0, 10.0]];
    let a = route(&points);
    let b = RouteCandidate { id: 2, speed: 1.0, protected: true, ..a };
    assert_eq!(run(&[a, b], [1, 1, 0, 1])?, run(&[b, a], [1, 1, 0, 1])?);
    Ok(())
}

#[test]
fn horizon_clips_inside_a_segment_without_integer_overflow() -> Result<(), GeometryError> {
    let points = [[0.0, 0.0, 10.0], [20.0, 0.0, 10.0]];
    let forecast = run(&[RouteCandidate { initial_pause_ns: 0, ..route(&points) }], [1, 0, 0, 0])?;
    assert_eq!(forecast.hypotheses()[0].position_at(5 * SECOND, &mut WorkBudget::new(20))?,
        Some([10.0, 0.0, 10.0]));
    let slow = run(&[RouteCandidate { speed: 1e-9, ..route(&points) }], [1, 0, 0, 0])?;
    assert_eq!(slow.hypotheses()[0].modeled_until_ns(), 5 * SECOND);
    Ok(())
}

#[test]
fn one_point_stationary_and_unknown_are_different() -> Result<(), GeometryError> {
    let points = [[1.0, 2.0, 3.0]];
    let stop = run(&[route(&points)], [0, 0, 0, 1])?;
    let unknown = run(&[RouteCandidate { end: RouteEnd::Unknown, ..route(&points) }], [0, 0, 0, 1])?;
    assert_eq!(stop.hypotheses()[0].modeled_until_ns(), 5 * SECOND);
    assert_eq!(unknown.hypotheses()[0].modeled_until_ns(), SECOND);
    Ok(())
}

#[test]
fn malformed_unused_suffix_and_duplicate_route_ids_fail() -> Result<(), GeometryError> {
    let bad = [[0.0, 0.0, 10.0], [1000.0, 0.0, 10.0], [f64::NAN, 0.0, 0.0]];
    assert_eq!(run(&[route(&bad)], [1, 0, 0, 0]), Err(GeometryError::NonFinite));
    let points = [[0.0, 0.0, 10.0]];
    let a = route(&points);
    assert_eq!(run(&[a, a], [1, 0, 0, 0]), Err(GeometryError::InvalidIndex));
    let coincident = [[0.0; 3]; 2];
    assert_eq!(run(&[route(&coincident)], [1, 0, 0, 0]), Err(GeometryError::Degenerate));
    Ok(())
}

#[test]
fn bounds_do_not_silently_drop_routes_or_wrap_time() -> Result<(), GeometryError> {
    let points = [[0.0, 0.0, 10.0]];
    assert_eq!(run(&vec![route(&points); 65], [1, 0, 0, 0]), Err(GeometryError::LimitExceeded));
    let priors = RoutePriors::new([1, 0, 0, 0], 1)?;
    for (reference, horizon) in [(0, 0), (0, MAX_FORECAST_NS + 1), (u64::MAX, 1)] {
        assert_eq!(forecast_routes(basis()?, reference, horizon, priors, &[route(&points)],
            &mut WorkBudget::new(1000)), Err(GeometryError::OutOfRange));
    }
    assert!(RoutePriors::new([0; 4], 1).is_err());
    assert!(RoutePriors::new([1, 0, 0, 0], 0).is_err());
    assert!(ForecastBasis::new(GeometryBasis::new(1, 1)?, 0, 1, 1, 1).is_err());
    Ok(())
}

#[test]
fn cancellation_and_exhaustion_publish_no_partial_forecast() -> Result<(), GeometryError> {
    let points = [[0.0, 0.0, 10.0], [2.0, 0.0, 10.0]];
    let priors = RoutePriors::new([1, 0, 0, 0], 4)?;
    let cancelled = AtomicBool::new(true);
    assert_eq!(forecast_routes(basis()?, 0, 5 * SECOND, priors, &[route(&points)],
        &mut WorkBudget::cancellable(1000, &cancelled)), Err(GeometryError::Cancelled));
    assert_eq!(forecast_routes(basis()?, 0, 5 * SECOND, priors, &[route(&points)],
        &mut WorkBudget::new(0)), Err(GeometryError::BudgetExhausted));
    let forecast = run(&[route(&points)], [1, 0, 0, 0])?;
    assert_eq!(forecast.hypotheses()[0].position_at(SECOND, &mut WorkBudget::new(1)),
        Err(GeometryError::BudgetExhausted));
    Ok(())
}
