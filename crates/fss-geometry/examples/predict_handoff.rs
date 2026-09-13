#![forbid(unsafe_code)]
//! Synthetic Z-up property replay using the real motion and occlusion kernels.
//! This is an arithmetic/integration rehearsal, not real-camera qualification.

use fss_geometry::{
    BodySamples, CameraAvailability, CaptureSchedule, ForecastBasis, GeometryBasis,
    GeometryError, HandoffCamera, HandoffOptions, IndexedTriangle, MeshLimits,
    NanosecondInterval, NextCameraOutcome, PinholeIntrinsics, RigidPose,
    RouteBody, RouteCandidate, RouteEnd, RoutePriors, RouteSurface, TriangleMesh,
    WorkBudget, forecast_routes, predict_camera_handoffs,
};
use std::io::{self, Write};

const SECOND: u64 = 1_000_000_000;

fn body(generation: u64, radius: f64, height: f64,
    budget: &mut WorkBudget<'_>) -> Result<BodySamples, GeometryError> {
    let mut offsets = [[0.0; 3]; 8];
    let mut index = 0;
    for x in [-radius, radius] {
        for y in [-radius, radius] {
            for z in [0.0, height] {
                offsets[index] = [x, y, z];
                index += 1;
            }
        }
    }
    BodySamples::new(generation, &offsets, budget)
}

fn camera(id: u64, center: [f64; 3], basis: ForecastBasis)
    -> Result<HandoffCamera<'static>, GeometryError> {
    Ok(HandoffCamera {
        id, geometry: basis.geometry(), clock: basis.clock(),
        observation_generation: 8, image_mode: 9,
        pose: RigidPose::from_center(
            [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]], center)?,
        intrinsics: PinholeIntrinsics::new(100, 100, 100.0, 100.0, 50.0, 50.0)?,
        availability: CameraAvailability::Ready, already_observing: false,
        valid: NanosecondInterval::new(0, 10 * SECOND)?,
        schedule: CaptureSchedule::new(SECOND, 0)?,
        latency: NanosecondInterval::new(SECOND / 5, 2 * SECOND / 5)?,
        privacy_masks: &[], visible_per_mille: 1000, minimum_extent_px: [1.0, 1.0],
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = io::BufWriter::new(io::stdout().lock());
    let mut budget = WorkBudget::new(1_000_000);
    let geometry = GeometryBasis::new(1, 2)?;
    let basis = ForecastBasis::new(geometry, 3, 4, 5, 6)?;
    let mesh = TriangleMesh::from_indexed(geometry,
        &[[-20.0, -20.0, 0.0], [20.0, -20.0, 0.0],
          [20.0, 20.0, 0.0], [-20.0, 20.0, 0.0]],
        &[IndexedTriangle { vertices: [0, 1, 2], feature: 10, support: true, opaque: true },
          IndexedTriangle { vertices: [0, 2, 3], feature: 10, support: true, opaque: true }],
        MeshLimits::default(), &mut budget)?;
    let stone_path = [[-8.0, -8.0, 0.0], [8.0, -8.0, 0.0]];
    let grass_path = [[-8.0, -8.0, 0.0], [-8.0, 8.0, 0.0]];
    let stone = RouteCandidate { id: 1, points: &stone_path, speed: 1.0,
        initial_pause_ns: 0, end: RouteEnd::Stop, surface: RouteSurface::PedestrianPath,
        base_mass: 1, protected: false };
    let grass = RouteCandidate { id: 2, points: &grass_path, surface: RouteSurface::OffPath,
        protected: true, ..stone };
    let cameras = [camera(11, [0.0, -8.0, 10.0], basis)?,
        camera(22, [-8.0, 0.0, 10.0], basis)?];
    let human_body = body(71, 0.2, 1.5, &mut budget)?;
    let bear_body = body(72, 0.3, 0.8, &mut budget)?;
    for (class, masses, body) in [
        ("person", [1, 0, 0, 0], &human_body), ("bear", [0, 1, 0, 0], &bear_body),
    ] {
        let motion = forecast_routes(basis, 0, 10 * SECOND, RoutePriors::new(masses, 4)?,
            &[stone, grass], &mut budget)?;
        let forecast = predict_camera_handoffs(basis, &motion, &mesh, &cameras,
            &[RouteBody { route: 1, body }, RouteBody { route: 2, body }],
            HandoffOptions { max_samples_per_camera: 1000, endpoint_margin: 1e-6 },
            &mut budget)?;
        for route in &forecast.routes {
            let NextCameraOutcome::Predicted { nominal_capture_ns, cameras } = &route.next else {
                return Err(io::Error::other("fixture did not produce a complete modeled handoff").into());
            };
            let hit = route.observations.first()
                .ok_or_else(|| io::Error::other("missing first modeled observation"))?;
            if cameras.as_slice() != [hit.camera] || *nominal_capture_ns != hit.nominal_capture_ns {
                return Err(io::Error::other("inconsistent modeled first-camera outcome").into());
            }
            let min = hit.region.min();
            let max = hit.region.max();
            writeln!(output, concat!(
                "{{\"schema\":\"fss.handoff.replay/1\",\"synthetic\":true,",
                "\"event\":\"modeled_sample_eligibility\",\"class\":\"{}\",",
                "\"route\":{},\"camera\":{},\"mass\":{},\"total_mass\":{},\"protected\":{},",
                "\"capture_ns\":{},\"availability_ns\":[{},{}],",
                "\"region\":[{:.12},{:.12},{:.12},{:.12}],",
                "\"body_generation\":{},\"clock\":{},\"track_revision\":{},",
                "\"image_mode\":{},\"observation_generation\":{},\"work_units\":{}}}"
            ), class, route.route, hit.camera, route.mass, forecast.total_mass, route.protected,
                hit.nominal_capture_ns, hit.availability_ns.earliest(), hit.availability_ns.latest(),
                min[0], min[1], max[0], max[1], route.body_generation, forecast.basis.clock(),
                forecast.basis.track_revision(), hit.image_mode, hit.observation_generation,
                budget.used())?;
        }
    }
    output.flush()?;
    Ok(())
}
