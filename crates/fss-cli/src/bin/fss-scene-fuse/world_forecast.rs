#![forbid(unsafe_code)]
//! `fss-scene-fuse world-forecast` — end-to-end 3D ground-contact tracking, class-conditioned
//! route priors, and next-camera occlusion-emergence handoff forecasting (`BTI-005`, `BTI-006`,
//! `BTI-007`).
//!
//! Composes `fss-twin`'s `SupportNetwork`, `ContactTrack` (`project_contact` +
//! `fit_world_motion`), `build_route_frontier`, and `fss-geometry`'s `forecast_routes` +
//! `predict_camera_handoffs` over a pinned `.fsstwin` package and camera rig. Preserves every
//! protected off-path/animal/unknown-dynamics hypothesis, explicit stop branch, and
//! no-modeled-observation / indeterminate mass without ever renormalizing uncertainty away or
//! granting effect authority.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

use fss_cli::agent_json::{array, object, string};
use fss_cli::json_input::Value;
use fss_cli::scene_rig::SceneRig;
use fss_core::ContentDigest;
use fss_geometry::{
    BodySamples, CameraAvailability, CameraHandoffForecast, CaptureSchedule, ForecastBasis,
    HandoffCamera, HandoffOptions, NanosecondInterval, NextCameraOutcome, RouteBody,
    RouteCandidate, RouteEnd, RoutePriors, RouteSurface, WorkBudget, forecast_routes,
    predict_camera_handoffs,
};
use fss_reference::ReplayCx;
use fss_twin::frontier_handoff::HeadingMassPolicy;
use fss_twin::route_frontier::{
    FrontierRouteKind, RouteFrontier, RouteFrontierOptions, build_route_frontier,
};
use fss_twin::stream::{ContactTrack, TrackDisposition, TrackOptions, TrackReceipt, TrackScope};
use fss_twin::{
    ContactObservation, ImportExpectation, ImportLimits, MAX_NAVIGATION_TRIANGLES, MovementClass,
    NavigationProfile, ProjectionOptions, PropertyTwin, RouteOutcome, SupportNetwork, import_twin,
};

use super::{
    DEFAULT_WORK, MAX_JSON_BYTES, MAX_REPORT_BYTES, MAX_TWIN_BYTES, MAX_WORK, Result, authority,
    checkpoint, document, fail, input, input_error, read_input, write_report,
};

/// Schema and digest domain for `fss-scene-fuse world-forecast`
/// (`SCHEMA-DOMAIN-SCENE-WORLD-FORECAST-REPORT-001`).
pub(crate) const REPORT_SCHEMA: &str = "fss.scene_world_forecast_report.v1";
const QUERY_SCHEMA: &str = "fss.scene_world_forecast_query.v1";
const MAX_OBSERVATIONS: usize = 32;

const HELP: &str = "fss-scene-fuse world-forecast --twin PROPERTY.fsstwin --rig CAMERAS.json --observations QUERY.json\n\
    [--report-out REPORT.json] [--work-units N]\n\n\
Project ordered ground-contact observations onto the imported 3D property twin, infer 3D world\n\
velocity hypotheses, enumerate the complete class-conditioned route frontier across all semantic\n\
destinations (retaining protected off-path and stop alternatives without top-k pruning), and\n\
forecast next-camera / occlusion-emergence handoffs against the real 3D mesh.\n\n\
The query schema is fss.scene_world_forecast_query.v1. Supply rig_sha256, clock, track, epoch,\n\
horizon_ns, movement_class (person|bear|other_animal|unknown), optional person_path_multiplier\n\
(forced to 1 for non-person classes), retain_without_preference (default true), sample_period_ns,\n\
and 1..=32 ordered ground-contact observations. Heuristic route masses are not calibrated\n\
probabilities; no-observation and indeterminate masses are never renormalized away.\n\
Exit 0 on completed forecast; 2 on invalid input, I/O, or authority failure.\n";

#[derive(Clone, Debug)]
struct Options {
    twin: PathBuf,
    rig: PathBuf,
    observations: PathBuf,
    report_out: Option<PathBuf>,
    work: u64,
}

#[derive(Clone, Debug)]
struct QueryObservation {
    observation: ContactObservation,
    association: Option<[u8; 32]>,
}

#[derive(Clone, Debug)]
struct WorldForecastQuery {
    rig_sha256: [u8; 32],
    clock: u64,
    track: u64,
    epoch: u64,
    horizon_ns: u64,
    movement_class: MovementClass,
    person_path_multiplier: u32,
    retain_without_preference: bool,
    minimum_up_cosine: f64,
    minimum_portal_width: f64,
    sample_period_ns: u64,
    observations: Vec<QueryObservation>,
}

fn parse_options(args: &[OsString]) -> Result<Option<Options>> {
    if matches!(args, [flag] if matches!(flag.to_str(), Some("--help" | "-h"))) {
        return Ok(None);
    }
    let mut fields = BTreeMap::new();
    let mut it = args.iter();
    while let Some(key) = it.next() {
        let key = key
            .to_str()
            .ok_or_else(|| input_error("option must be UTF-8"))?
            .to_owned();
        if ![
            "--twin",
            "--rig",
            "--observations",
            "--report-out",
            "--work-units",
        ]
        .contains(&key.as_str())
        {
            return Err(input_error(
                "unknown world-forecast option; use world-forecast --help",
            ));
        }
        let value = it
            .next()
            .ok_or_else(|| input_error("option requires a value"))?;
        if fields.insert(key, value.clone()).is_some() {
            return Err(input_error("duplicate option"));
        }
    }
    let required = |key: &str| -> Result<PathBuf> {
        fields
            .get(key)
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .ok_or_else(|| input_error(format!("missing {key}")))
    };
    let work = fields
        .get("--work-units")
        .map(|v| {
            v.to_str()
                .and_then(|s| s.parse::<u64>().ok())
                .filter(|v| (1..=MAX_WORK).contains(v))
                .ok_or_else(|| input_error("work-units must be 1..=1000000000"))
        })
        .transpose()?
        .unwrap_or(DEFAULT_WORK);
    Ok(Some(Options {
        twin: required("--twin")?,
        rig: required("--rig")?,
        observations: required("--observations")?,
        report_out: fields.get("--report-out").map(PathBuf::from),
        work,
    }))
}

fn req_obj<'a>(value: &'a Value, what: &str) -> Result<&'a BTreeMap<String, Value>> {
    value
        .object()
        .ok_or_else(|| input_error(format!("{what} must be a JSON object")))
}

fn req_u64(obj: &BTreeMap<String, Value>, key: &str) -> Result<u64> {
    let raw = obj
        .get(key)
        .and_then(Value::integer)
        .ok_or_else(|| input_error(format!("missing or non-integer {key}")))?;
    u64::try_from(raw).map_err(|_| input_error(format!("{key} must be nonnegative u64")))
}

fn opt_u64(obj: &BTreeMap<String, Value>, key: &str, default: u64) -> Result<u64> {
    match obj.get(key) {
        None => Ok(default),
        Some(v) => {
            let raw = v
                .integer()
                .ok_or_else(|| input_error(format!("{key} must be integer")))?;
            u64::try_from(raw).map_err(|_| input_error(format!("{key} must be nonnegative u64")))
        }
    }
}

fn opt_f64(obj: &BTreeMap<String, Value>, key: &str, default: f64) -> Result<f64> {
    match obj.get(key) {
        None => Ok(default),
        Some(Value::Number(s)) => s
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite())
            .ok_or_else(|| input_error(format!("{key} must be finite number"))),
        Some(_) => Err(input_error(format!("{key} must be numeric"))),
    }
}

fn req_vec2(obj: &BTreeMap<String, Value>, key: &str) -> Result<[f64; 2]> {
    let arr = obj
        .get(key)
        .and_then(Value::array)
        .filter(|a| a.len() == 2)
        .ok_or_else(|| input_error(format!("{key} must be a 2-element numeric array")))?;
    let mut out = [0.0_f64; 2];
    for (idx, item) in arr.iter().enumerate() {
        let Value::Number(s) = item else {
            return Err(input_error(format!("{key}[{idx}] must be numeric")));
        };
        let v = s
            .parse::<f64>()
            .ok()
            .filter(|x| x.is_finite())
            .ok_or_else(|| input_error(format!("{key}[{idx}] must be finite")))?;
        out[idx] = v;
    }
    Ok(out)
}

fn req_sha256(obj: &BTreeMap<String, Value>, key: &str) -> Result<[u8; 32]> {
    let text = obj
        .get(key)
        .and_then(Value::text)
        .ok_or_else(|| input_error(format!("missing {key}")))?;
    let digest = ContentDigest::parse(text)
        .map_err(|_| input_error(format!("{key} must be sha256:<64 hex>")))?;
    let bytes = digest.bytes();
    if bytes == [0_u8; 32] {
        return Err(input_error(format!("{key} must be nonzero sha256")));
    }
    Ok(bytes)
}

fn parse_query(doc: &Value, expected_rig: ContentDigest) -> Result<WorldForecastQuery> {
    let top = req_obj(doc, "query")?;
    if top.get("schema").and_then(Value::text) != Some(QUERY_SCHEMA) {
        return Err(input_error(format!("query schema must be {QUERY_SCHEMA}")));
    }
    let rig_sha256 = req_sha256(top, "rig_sha256")?;
    if rig_sha256 != expected_rig.bytes() {
        return Err(fail(
            "ERR-SCENE-FUSION-RIG-001",
            "query rig_sha256 does not match the supplied camera rig bytes",
        ));
    }
    let clock = req_u64(top, "clock")?;
    let track = req_u64(top, "track")?;
    let epoch = req_u64(top, "epoch")?;
    let horizon_ns = req_u64(top, "horizon_ns")?;
    if [clock, track, epoch, horizon_ns].contains(&0) || horizon_ns > 3_600_000_000_000 {
        return Err(input_error(
            "clock, track, epoch, and horizon_ns must be positive (horizon <= 1h)",
        ));
    }
    let movement_class = match top.get("movement_class").and_then(Value::text) {
        Some("person") => MovementClass::Person,
        Some("bear") => MovementClass::Bear,
        Some("other_animal") => MovementClass::OtherAnimal,
        Some("unknown") | None => MovementClass::Unknown,
        Some(other) => {
            return Err(input_error(format!(
                "unsupported movement_class `{other}`; expected person, bear, other_animal, or unknown"
            )));
        }
    };
    let requested_mult = u32::try_from(opt_u64(
        top,
        "person_path_multiplier",
        if movement_class == MovementClass::Person {
            2
        } else {
            1
        },
    )?)
    .map_err(|_| input_error("person_path_multiplier out of u32 range"))?;
    // Non-person classes NEVER inherit pedestrian path preference.
    let person_path_multiplier = if movement_class == MovementClass::Person {
        requested_mult
    } else {
        1
    };
    let retain_without_preference = top
        .get("retain_without_preference")
        .and_then(Value::boolean)
        .unwrap_or(true);
    let minimum_up_cosine = opt_f64(top, "minimum_up_cosine", 0.7)?;
    let minimum_portal_width = opt_f64(top, "minimum_portal_width", 0.1)?;
    let sample_period_ns = opt_u64(top, "sample_period_ns", 200_000_000)?;
    if sample_period_ns == 0 {
        return Err(input_error("sample_period_ns must be >= 1"));
    }

    let raw_obs = top
        .get("observations")
        .and_then(Value::array)
        .ok_or_else(|| input_error("missing observations array"))?;
    if raw_obs.is_empty() || raw_obs.len() > MAX_OBSERVATIONS {
        return Err(input_error(format!(
            "observations must contain 1..={MAX_OBSERVATIONS} entries"
        )));
    }
    let mut observations = Vec::with_capacity(raw_obs.len());
    for (idx, item) in raw_obs.iter().enumerate() {
        let row = req_obj(item, &format!("observations[{idx}]"))?;
        let evidence = req_sha256(row, "evidence_digest")?;
        let camera = req_u64(row, "camera")?;
        let exposure = req_u64(row, "exposure")?;
        let image_domain = req_u64(row, "image_domain")?;
        let capture_min = req_u64(row, "capture_min_ns")?;
        let capture_max = req_u64(row, "capture_max_ns")?;
        if capture_min > capture_max {
            return Err(input_error(format!(
                "observations[{idx}] capture_min_ns > capture_max_ns"
            )));
        }
        let pixel_min = req_vec2(row, "pixel_min")?;
        let pixel_max = req_vec2(row, "pixel_max")?;
        let visible_contact = row
            .get("visible_contact")
            .and_then(Value::boolean)
            .ok_or_else(|| input_error(format!("observations[{idx}] missing visible_contact")))?;
        let association = match row.get("association_digest") {
            None | Some(Value::Null) => None,
            Some(_) => Some(req_sha256(row, "association_digest")?),
        };
        observations.push(QueryObservation {
            observation: ContactObservation {
                evidence,
                track,
                camera,
                exposure,
                image_domain,
                clock,
                capture: [capture_min, capture_max],
                pixel_min,
                pixel_max,
                visible_contact,
            },
            association,
        });
    }

    Ok(WorldForecastQuery {
        rig_sha256,
        clock,
        track,
        epoch,
        horizon_ns,
        movement_class,
        person_path_multiplier,
        retain_without_preference,
        minimum_up_cosine,
        minimum_portal_width,
        sample_period_ns,
        observations,
    })
}

fn disposition_str(d: TrackDisposition) -> &'static str {
    match d {
        TrackDisposition::Seeded => "seeded",
        TrackDisposition::MotionUpdated => "motion_updated",
        TrackDisposition::ContactUnavailable => "contact_unavailable",
        TrackDisposition::SupportUnavailable => "support_unavailable",
        TrackDisposition::TimeAmbiguous => "time_ambiguous",
        TrackDisposition::Gap => "gap",
        TrackDisposition::AssociationRequired => "association_required",
    }
}

fn class_str(c: MovementClass) -> &'static str {
    match c {
        MovementClass::Person => "person",
        MovementClass::Bear => "bear",
        MovementClass::OtherAnimal => "other_animal",
        MovementClass::Unknown => "unknown",
    }
}

fn fmt_f64(v: f64) -> String {
    if v.is_finite() {
        format!("{v:.6}")
    } else {
        "null".to_owned()
    }
}

fn fmt_vec3(v: [f64; 3]) -> String {
    array(&[fmt_f64(v[0]), fmt_f64(v[1]), fmt_f64(v[2])])
}

fn default_body_samples(class: MovementClass, work: &mut WorkBudget<'_>) -> Result<BodySamples> {
    let offsets: &[[f64; 3]] = match class {
        MovementClass::Person => &[
            [0.0, 0.0, 0.25],
            [0.0, 0.0, 0.90],
            [0.0, 0.0, 1.55],
            [0.2, 0.0, 1.10],
            [-0.2, 0.0, 1.10],
        ],
        MovementClass::Bear | MovementClass::OtherAnimal => &[
            [0.0, 0.0, 0.20],
            [0.0, 0.0, 0.70],
            [0.35, 0.0, 0.55],
            [-0.35, 0.0, 0.55],
        ],
        MovementClass::Unknown => &[[0.0, 0.0, 0.25], [0.0, 0.0, 0.85], [0.0, 0.0, 1.45]],
    };
    BodySamples::new(1, offsets, work)
        .map_err(|e| fail("ERR-SCENE-FUSION-GEOMETRY-001", e.to_string()))
}

struct ForecastArtifacts {
    json: String,
}

fn compute_world_forecast(
    twin: &PropertyTwin,
    rig: &SceneRig,
    query: &WorldForecastQuery,
    query_digest: ContentDigest,
    work: &mut WorkBudget<'_>,
    cx: &ReplayCx,
) -> Result<ForecastArtifacts> {
    checkpoint(cx, "world_forecast:support_network")?;
    let network = SupportNetwork::compile(twin, MAX_NAVIGATION_TRIANGLES, work)
        .map_err(|e| fail("ERR-SCENE-FUSION-TWIN-001", format!("support network: {e}")))?;

    let tracking_cameras: Vec<_> = rig.cameras().iter().map(|entry| entry.camera).collect();
    let scope = TrackScope {
        track: query.track,
        clock: query.clock,
        epoch: query.epoch,
    };
    let track_options = TrackOptions {
        projection: ProjectionOptions::default(),
        max_gap_ns: query.horizon_ns.clamp(30_000_000_000, 3_600_000_000_000),
        max_modes: 64,
        receipt_capacity: 256,
    };
    let mut track = ContactTrack::new(twin, scope, &tracking_cameras, track_options, work)
        .map_err(|e| fail("ERR-SCENE-FUSION-TRACK-001", format!("track init: {e}")))?;

    let mut receipts: Vec<TrackReceipt> = Vec::with_capacity(query.observations.len());
    for entry in &query.observations {
        checkpoint(cx, "world_forecast:ingest")?;
        let update = track
            .ingest(twin, entry.observation, entry.association, work)
            .map_err(|e| fail("ERR-SCENE-FUSION-TRACK-001", format!("track ingest: {e}")))?;
        receipts.push(update.receipt);
    }

    let snapshot = track
        .snapshot(track.revision())
        .map_err(|e| fail("ERR-SCENE-FUSION-TRACK-001", format!("track snapshot: {e}")))?;

    checkpoint(cx, "world_forecast:route_frontier")?;
    let profile = NavigationProfile::new(
        query.movement_class,
        query.minimum_up_cosine,
        query.minimum_portal_width,
        query.person_path_multiplier,
    )
    .map_err(|e| {
        fail(
            "ERR-SCENE-FUSION-INPUT-001",
            format!("navigation profile: {e}"),
        )
    })?;
    let frontier = build_route_frontier(
        twin,
        &network,
        snapshot,
        RouteFrontierOptions {
            profile,
            maximum_features: 4096,
            maximum_routes: 16_384,
            maximum_points: 256,
            retain_without_preference: query.retain_without_preference,
        },
        work,
    )
    .map_err(|e| fail("ERR-SCENE-FUSION-ROUTE-001", format!("route frontier: {e}")))?;

    checkpoint(cx, "world_forecast:handoff")?;
    let handoff = compute_handoff_forecast(twin, rig, query, snapshot, &frontier, work)?;

    let json = render_report(
        twin,
        rig,
        query,
        query_digest,
        &network,
        &receipts,
        snapshot,
        &frontier,
        handoff.as_ref(),
    );
    Ok(ForecastArtifacts { json })
}

fn compute_handoff_forecast(
    twin: &PropertyTwin,
    rig: &SceneRig,
    query: &WorldForecastQuery,
    snapshot: fss_twin::stream::TrackSnapshot<'_>,
    frontier: &RouteFrontier,
    work: &mut WorkBudget<'_>,
) -> Result<Option<CameraHandoffForecast>> {
    let Some(motion) = snapshot.motion() else {
        return Ok(None);
    };
    let masses = HeadingMassPolicy::default();
    type RouteStorageRow = (u64, Vec<[f64; 3]>, f64, RouteSurface, u32, bool, RouteEnd);
    let mut route_storage: Vec<RouteStorageRow> = Vec::new();
    for route in &frontier.routes {
        let RouteOutcome::Found(path) = &route.search.outcome else {
            continue;
        };
        for compat in &route.motion {
            let Some(speed) = compat
                .speed
                .filter(|s| s.is_finite() && (1e-9..=1e12).contains(s))
            else {
                continue;
            };
            if route_storage.len() == 64 {
                break;
            }
            let id = route_storage.len() as u64 + 1;
            let surface = if path.all_pedestrian() {
                RouteSurface::PedestrianPath
            } else {
                RouteSurface::OffPath
            };
            let base = match compat.initial_direction_cosine {
                None => masses.unknown,
                Some(c) => {
                    let t = ((c.clamp(-1.0, 1.0) + 1.0) * 0.5).clamp(0.0, 1.0);
                    (f64::from(masses.opposite) + f64::from(masses.aligned - masses.opposite) * t)
                        .round() as u32
                }
            };
            // Always protect off-path, neutral-preference, and non-person hypotheses!
            let protected = surface == RouteSurface::OffPath
                || route.kind == FrontierRouteKind::WithoutPathPreference
                || query.movement_class != MovementClass::Person;
            route_storage.push((
                id,
                path.points().to_vec(),
                speed,
                surface,
                base.max(1),
                protected,
                RouteEnd::Stop,
            ));
        }
    }
    for mode in motion.modes() {
        let Some(pos) = mode.nominal_position else {
            continue;
        };
        if route_storage.len() == 64 {
            break;
        }
        let id = route_storage.len() as u64 + 1;
        route_storage.push((
            id,
            vec![pos],
            1.0,
            RouteSurface::Other,
            masses.stopped,
            true,
            RouteEnd::Stop,
        ));
    }
    if route_storage.is_empty() {
        return Ok(None);
    }

    let body = default_body_samples(query.movement_class, work)?;
    let mut candidates = Vec::with_capacity(route_storage.len());
    let mut bodies = Vec::with_capacity(route_storage.len());
    for (id, points, speed, surface, base_mass, protected, end) in &route_storage {
        candidates.push(RouteCandidate {
            id: *id,
            points,
            speed: *speed,
            initial_pause_ns: 0,
            end: *end,
            surface: *surface,
            base_mass: *base_mass,
            protected: *protected,
        });
        bodies.push(RouteBody {
            route: *id,
            body: &body,
        });
    }

    let obs = snapshot.projection().observation();
    let reference = obs.capture[0] + (obs.capture[1] - obs.capture[0]) / 2;
    let receipt = snapshot.receipt();
    let basis = ForecastBasis::new(
        twin.basis(),
        receipt.scope.clock,
        receipt.scope.track,
        receipt.revision,
        1,
    )
    .map_err(|e| fail("ERR-SCENE-FUSION-GEOMETRY-001", e.to_string()))?;

    let mut class_weights = [0_u32; 4];
    class_weights[match query.movement_class {
        MovementClass::Person => 0,
        MovementClass::Bear => 1,
        MovementClass::OtherAnimal => 2,
        MovementClass::Unknown => 3,
    }] = 1;
    let priors = RoutePriors::new(class_weights, 1)
        .map_err(|e| fail("ERR-SCENE-FUSION-GEOMETRY-001", e.to_string()))?;
    let motion_forecast = forecast_routes(
        basis,
        reference,
        query.horizon_ns,
        priors,
        &candidates,
        work,
    )
    .map_err(|e| fail("ERR-SCENE-FUSION-GEOMETRY-001", e.to_string()))?;

    let schedule = CaptureSchedule::new(query.sample_period_ns, 0)
        .map_err(|e| fail("ERR-SCENE-FUSION-GEOMETRY-001", e.to_string()))?;
    let latency = NanosecondInterval::new(0, 0)
        .map_err(|e| fail("ERR-SCENE-FUSION-GEOMETRY-001", e.to_string()))?;
    let last_camera = obs.camera;

    let mut views = Vec::with_capacity(rig.cameras().len());
    for cam in rig.cameras() {
        let c = cam.camera;
        let valid = NanosecondInterval::new(c.validity[0], c.validity[1])
            .map_err(|e| fail("ERR-SCENE-FUSION-GEOMETRY-001", e.to_string()))?;
        views.push(HandoffCamera {
            id: c.camera,
            geometry: c.geometry,
            clock: c.clock,
            observation_generation: c.calibration,
            image_mode: c.image_domain,
            pose: c.pose,
            intrinsics: c.intrinsics,
            availability: CameraAvailability::Ready,
            already_observing: c.camera == last_camera,
            valid,
            schedule,
            latency,
            privacy_masks: &[],
            visible_per_mille: 500,
            minimum_extent_px: [2.0, 2.0],
        });
    }

    let handoff = predict_camera_handoffs(
        basis,
        &motion_forecast,
        twin.mesh(),
        &views,
        &bodies,
        HandoffOptions {
            max_samples_per_camera: 2048,
            endpoint_margin: 1e-3,
        },
        work,
    )
    .map_err(|e| fail("ERR-SCENE-FUSION-GEOMETRY-001", e.to_string()))?;
    Ok(Some(handoff))
}

#[allow(clippy::too_many_arguments)]
fn render_report(
    twin: &PropertyTwin,
    rig: &SceneRig,
    query: &WorldForecastQuery,
    query_digest: ContentDigest,
    network: &SupportNetwork,
    receipts: &[TrackReceipt],
    snapshot: fss_twin::stream::TrackSnapshot<'_>,
    frontier: &RouteFrontier,
    handoff: Option<&CameraHandoffForecast>,
) -> String {
    let twin_digest = ContentDigest::new(fss_core::DigestAlgorithm::Sha256, twin.digest());
    let rig_digest = ContentDigest::new(fss_core::DigestAlgorithm::Sha256, query.rig_sha256);

    let receipt_rows: Vec<String> = receipts
        .iter()
        .map(|r| {
            let ev = ContentDigest::new(fss_core::DigestAlgorithm::Sha256, r.evidence);
            object(&[
                ("revision", r.revision.to_string()),
                ("evidence_digest", string(&ev.to_text())),
                ("disposition", string(disposition_str(r.disposition))),
                ("supports", r.supports.to_string()),
                ("motion_modes", r.motion_modes.to_string()),
            ])
        })
        .collect();

    let motion_rows: Vec<String> = snapshot
        .motion()
        .map(|m| {
            m.modes()
                .iter()
                .map(|mode| {
                    object(&[
                        ("previous_triangle", mode.previous_triangle.to_string()),
                        ("current_triangle", mode.current_triangle.to_string()),
                        (
                            "nominal_position",
                            mode.nominal_position
                                .map_or_else(|| "null".to_owned(), fmt_vec3),
                        ),
                        (
                            "nominal_velocity",
                            mode.nominal_velocity
                                .map_or_else(|| "null".to_owned(), fmt_vec3),
                        ),
                        (
                            "nominal_occlusion_conflict",
                            mode.nominal_occlusion_conflict.to_string(),
                        ),
                    ])
                })
                .collect()
        })
        .unwrap_or_default();

    let route_rows: Vec<String> = frontier
        .routes
        .iter()
        .map(|route| {
            let feature_id = twin
                .features()
                .get(route.destination_feature as usize)
                .map_or("unknown", |f| f.id.as_str());
            let (found, distance, all_pedestrian, point_count) = match &route.search.outcome {
                RouteOutcome::Found(path) => (
                    true,
                    Some(path.distance()),
                    Some(path.all_pedestrian()),
                    path.points().len(),
                ),
                _ => (false, None, None, 0),
            };
            let kind = match route.kind {
                FrontierRouteKind::Preferred => "preferred",
                FrontierRouteKind::WithoutPathPreference => "without_path_preference",
            };
            object(&[
                ("route", route.route.to_string()),
                ("destination_feature", string(feature_id)),
                ("kind", string(kind)),
                ("found", found.to_string()),
                (
                    "distance",
                    distance.map_or_else(|| "null".to_owned(), fmt_f64),
                ),
                (
                    "all_pedestrian",
                    all_pedestrian.map_or_else(|| "null".to_owned(), |v| v.to_string()),
                ),
                ("point_count", point_count.to_string()),
                ("compatible_motion_modes", route.motion.len().to_string()),
            ])
        })
        .collect();

    let handoff_json = match handoff {
        None => "null".to_owned(),
        Some(forecast) => {
            let mut no_obs_mass = 0_u64;
            let mut indet_mass = 0_u64;
            let mut camera_support: BTreeMap<u64, (u64, u64, usize, u64)> = BTreeMap::new();
            let mut hroutes = Vec::with_capacity(forecast.routes.len());
            for rh in &forecast.routes {
                let next_json = match &rh.next {
                    NextCameraOutcome::Predicted {
                        nominal_capture_ns,
                        cameras,
                    } => {
                        for &cam_id in cameras {
                            let entry = camera_support.entry(cam_id).or_insert((0, 0, 0, u64::MAX));
                            entry.0 = entry.0.saturating_add(rh.mass);
                            if rh.protected {
                                entry.1 = entry.1.saturating_add(rh.mass);
                            }
                            entry.2 += 1;
                            entry.3 = entry.3.min(*nominal_capture_ns);
                        }
                        let cams: Vec<String> = cameras.iter().map(ToString::to_string).collect();
                        object(&[
                            ("outcome", string("predicted")),
                            ("nominal_capture_ns", nominal_capture_ns.to_string()),
                            ("cameras", array(&cams)),
                        ])
                    }
                    NextCameraOutcome::NoModeledObservation => {
                        no_obs_mass = no_obs_mass.saturating_add(rh.mass);
                        object(&[("outcome", string("no_modeled_observation"))])
                    }
                    NextCameraOutcome::Indeterminate => {
                        indet_mass = indet_mass.saturating_add(rh.mass);
                        object(&[("outcome", string("indeterminate"))])
                    }
                };
                let obs_json: Vec<String> = rh
                    .observations
                    .iter()
                    .map(|o| {
                        object(&[
                            ("camera", o.camera.to_string()),
                            ("nominal_capture_ns", o.nominal_capture_ns.to_string()),
                            ("visible_samples", o.visible_samples.to_string()),
                            ("body_samples", o.body_samples.to_string()),
                        ])
                    })
                    .collect();
                hroutes.push(object(&[
                    ("route", rh.route.to_string()),
                    ("mass", rh.mass.to_string()),
                    ("protected", rh.protected.to_string()),
                    ("unmodeled_tail", rh.unmodeled_tail.to_string()),
                    ("next", next_json),
                    ("observations", array(&obs_json)),
                ]));
            }
            let mut summary_rows: Vec<(u64, u64, u64, usize, u64)> = camera_support
                .into_iter()
                .map(|(cam, (mass, prot, count, earliest))| (cam, mass, prot, count, earliest))
                .collect();
            summary_rows.sort_by(|a, b| {
                b.1.cmp(&a.1)
                    .then_with(|| a.4.cmp(&b.4))
                    .then_with(|| a.0.cmp(&b.0))
            });
            let next_cameras: Vec<String> = summary_rows
                .iter()
                .map(|(cam, mass, prot, count, earliest)| {
                    object(&[
                        ("camera", cam.to_string()),
                        ("heuristic_support_mass", mass.to_string()),
                        ("protected_support_mass", prot.to_string()),
                        ("supporting_routes", count.to_string()),
                        ("earliest_capture_ns", earliest.to_string()),
                    ])
                })
                .collect();
            object(&[
                ("reference_ns", forecast.reference_ns.to_string()),
                ("horizon_ns", forecast.horizon_ns.to_string()),
                ("total_mass", forecast.total_mass.to_string()),
                ("no_modeled_observation_mass", no_obs_mass.to_string()),
                ("indeterminate_mass", indet_mass.to_string()),
                ("next_cameras", array(&next_cameras)),
                ("routes", array(&hroutes)),
            ])
        }
    };

    let body = object(&[
        ("schema", string(REPORT_SCHEMA)),
        (
            "basis",
            object(&[
                ("twin_digest", string(&twin_digest.to_text())),
                ("rig_digest", string(&rig_digest.to_text())),
                ("query_digest", string(&query_digest.to_text())),
                ("camera_count", rig.cameras().len().to_string()),
                ("clock", query.clock.to_string()),
                ("track", query.track.to_string()),
                ("epoch", query.epoch.to_string()),
                ("movement_class", string(class_str(query.movement_class))),
                (
                    "person_path_multiplier",
                    query.person_path_multiplier.to_string(),
                ),
                (
                    "retain_without_preference",
                    query.retain_without_preference.to_string(),
                ),
                ("horizon_ns", query.horizon_ns.to_string()),
                ("support_triangles", network.support_count().to_string()),
                ("support_portals", network.portal_count().to_string()),
            ]),
        ),
        ("track_receipts", array(&receipt_rows)),
        ("motion_modes", array(&motion_rows)),
        (
            "route_frontier",
            object(&[
                (
                    "destination_features",
                    frontier.destination_features.to_string(),
                ),
                (
                    "unresolved_sources",
                    frontier.unresolved_sources.len().to_string(),
                ),
                ("routes", array(&route_rows)),
            ]),
        ),
        ("handoff_forecast", handoff_json),
    ]);
    let report_digest =
        ContentDigest::sha256(&[REPORT_SCHEMA.as_bytes(), b"\0", body.as_bytes()].concat());
    object(&[
        ("schema", string(REPORT_SCHEMA)),
        ("report_digest", string(&report_digest.to_text())),
        ("report", body),
    ])
}

pub(crate) fn run(args: &[OsString], out: &mut impl Write) -> Result<bool> {
    let Some(options) = parse_options(args)? else {
        write!(out, "{HELP}")
            .map_err(|_| fail("ERR-SCENE-FUSION-OUTPUT-001", "stdout write failed"))?;
        return Ok(true);
    };
    let cx = authority()?;
    let result = (|| {
        if let Some(path) = &options.report_out {
            checkpoint(&cx, "world_forecast:output_preflight")?;
            match fs::symlink_metadata(path) {
                Ok(_) => {
                    return Err(fail(
                        "ERR-SCENE-FUSION-OUTPUT-001",
                        "report output already exists",
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(_) => {
                    return Err(fail(
                        "ERR-SCENE-FUSION-OUTPUT-001",
                        "report output cannot be inspected",
                    ));
                }
            }
        }
        let rig_bytes = read_input(&options.rig, MAX_JSON_BYTES, &cx)?;
        let rig_document = document(&rig_bytes)?;
        let query_bytes = read_input(&options.observations, MAX_JSON_BYTES, &cx)?;
        let query_document = document(&query_bytes)?;
        let (package_sha256, source_scene_sha256, basis) = input::twin_expectation(&rig_document)?;
        let twin_bytes = read_input(&options.twin, MAX_TWIN_BYTES, &cx)?;
        let mut work = WorkBudget::new(options.work);
        checkpoint(&cx, "world_forecast:import")?;
        let twin = import_twin(
            &twin_bytes,
            ImportExpectation {
                package_sha256,
                source_scene_sha256,
                basis,
            },
            ImportLimits::default(),
            &mut work,
        )
        .map_err(|e| fail("ERR-SCENE-FUSION-TWIN-001", e.to_string()))?;
        let rig = SceneRig::from_document(&rig_document, &twin, &mut work)
            .map_err(|e| fail("ERR-SCENE-FUSION-RIG-001", e.to_string()))?;
        let rig_digest = ContentDigest::sha256(&rig_bytes);
        let query = parse_query(&query_document, rig_digest)?;
        let artifacts = compute_world_forecast(
            &twin,
            &rig,
            &query,
            ContentDigest::sha256(&query_bytes),
            &mut work,
            &cx,
        )?;
        if artifacts.json.len() > MAX_REPORT_BYTES {
            return Err(fail(
                "ERR-SCENE-FUSION-LIMIT-001",
                "world forecast report exceeds byte limit",
            ));
        }
        if let Some(path) = &options.report_out {
            write_report(path, artifacts.json.as_bytes(), &cx)?;
        }
        if options.report_out.is_none() {
            checkpoint(&cx, "world_forecast:stdout")?;
        }
        writeln!(out, "{}", artifacts.json)
            .map_err(|_| fail("ERR-SCENE-FUSION-OUTPUT-001", "stdout write failed"))?;
        Ok(true)
    })();
    cx.drain_and_finalize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use fss_cli::json_input::parse;

    fn build_two_surface_walkable_twin() -> Vec<u8> {
        fn text(out: &mut Vec<u8>, value: &str) {
            out.extend_from_slice(&(value.len() as u16).to_le_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        let mut body = ContentDigest::sha256(b"world-forecast-test-scene")
            .bytes()
            .to_vec();
        text(&mut body, "world_forecast_scope");
        text(&mut body, "epoch_1");
        body.push(0); // ScaleEvidence::Relative
        for n in [0.0_f64, -1.0, -1.0] {
            body.extend_from_slice(&n.to_le_bytes());
        }
        // 2 features, 2 objects, 8 vertices, 6 triangles (manifold ground strip x in [0, 9], y in [0, 3])
        for n in [2_u32, 2, 8, 6] {
            body.extend_from_slice(&n.to_le_bytes());
        }
        // Features & objects must be strictly sorted by id per fss-twin wire contract.
        // Feature 0: lawn_exit (Grass = 2)
        text(&mut body, "lawn_exit");
        body.push(2);
        // Feature 1: walkway (PedestrianPath = 1)
        text(&mut body, "walkway");
        body.push(1);
        // Object 0 -> feature 0 (lawn_exit), support=1, opaque=0
        text(&mut body, "lawn_mesh");
        body.extend_from_slice(&0_u32.to_le_bytes());
        body.extend_from_slice(&[1, 0]);
        // Object 1 -> feature 1 (walkway), support=1, opaque=0
        text(&mut body, "walkway_mesh");
        body.extend_from_slice(&1_u32.to_le_bytes());
        body.extend_from_slice(&[1, 0]);

        let verts: [[f64; 3]; 8] = [
            [0.0, 0.0, 0.0], // 0
            [3.0, 0.0, 0.0], // 1
            [6.0, 0.0, 0.0], // 2
            [9.0, 0.0, 0.0], // 3
            [0.0, 3.0, 0.0], // 4
            [3.0, 3.0, 0.0], // 5
            [6.0, 3.0, 0.0], // 6
            [9.0, 3.0, 0.0], // 7
        ];
        for p in verts {
            for coord in p {
                body.extend_from_slice(&coord.to_le_bytes());
            }
        }
        // 3 quads split cleanly with CCW upward normals (+Z), sharing manifold interior edges.
        let tris: [[u32; 4]; 6] = [
            [0, 1, 5, 1], // walkway
            [0, 5, 4, 1], // walkway
            [1, 2, 6, 1], // walkway
            [1, 6, 5, 1], // walkway
            [2, 3, 7, 0], // lawn_exit
            [2, 7, 6, 0], // lawn_exit
        ];
        for tri in tris {
            for idx in tri {
                body.extend_from_slice(&idx.to_le_bytes());
            }
        }
        let mut bytes = b"FSSTWIN1".to_vec();
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend(body);
        bytes.extend_from_slice(&ContentDigest::sha256(&bytes).bytes());
        bytes
    }

    fn build_two_camera_rig(twin_bytes: &[u8]) -> String {
        // Overhead cameras at z = 6 looking straight down (-Z):
        // R = diag(1, -1, -1) -> p_cam = (x - cx, -(y - cy), -(z - 6)) so z=0 sits at z_cam = +6.
        let cam1 = object(&[
            ("camera", "1".into()),
            ("calibration", "1".into()),
            ("image_domain", "1".into()),
            ("clock", "11".into()),
            ("privacy_domain", "9".into()),
            ("validity_ns", format!("[0,{}]", u64::MAX)),
            ("source_object_id", string("cam_entry")),
            ("image_model", string("undistorted_pinhole")),
            ("status", string("authored_nominal")),
            ("error", "null".into()),
            (
                "world_to_camera",
                object(&[
                    ("rotation", "[[1,0,0],[0,-1,0],[0,0,-1]]".into()),
                    ("translation", "[-1.5,1.5,6.0]".into()),
                ]),
            ),
            (
                "intrinsics",
                r#"{"width":640,"height":480,"fx":600,"fy":600,"cx":320,"cy":240}"#.into(),
            ),
        ]);
        let cam2 = object(&[
            ("camera", "2".into()),
            ("calibration", "1".into()),
            ("image_domain", "1".into()),
            ("clock", "11".into()),
            ("privacy_domain", "9".into()),
            ("validity_ns", format!("[0,{}]", u64::MAX)),
            ("source_object_id", string("cam_exit")),
            ("image_model", string("undistorted_pinhole")),
            ("status", string("authored_nominal")),
            ("error", "null".into()),
            (
                "world_to_camera",
                object(&[
                    ("rotation", "[[1,0,0],[0,-1,0],[0,0,-1]]".into()),
                    ("translation", "[-7.5,1.5,6.0]".into()),
                ]),
            ),
            (
                "intrinsics",
                r#"{"width":640,"height":480,"fx":600,"fy":600,"cx":320,"cy":240}"#.into(),
            ),
        ]);
        object(&[
            ("schema", string("fss.scene_camera_rig.v1")),
            (
                "source_scene_digest",
                string(&ContentDigest::sha256(b"world-forecast-test-scene").to_text()),
            ),
            (
                "twin_digest",
                string(&ContentDigest::sha256(twin_bytes).to_text()),
            ),
            ("geometry_basis", "{\"property\":7,\"revision\":2}".into()),
            ("coordinate_frame", string("RH_Z_UP")),
            ("evaluation_scope", string("world_forecast_scope")),
            ("cameras", array(&[cam1, cam2])),
        ])
    }

    fn run_query(
        twin_bytes: &[u8],
        rig_json: &str,
        movement_class: &str,
        visible_contact: bool,
    ) -> std::result::Result<Value, Box<dyn std::error::Error>> {
        let rig_digest = ContentDigest::sha256(rig_json.as_bytes());
        // Cam 1 center at (1.5, 1.5, 6.0):
        // Point (1.0, 1.5, 0.0) -> cam = (-0.5, 0, 6.0) -> u = 320 + 600*(-0.5/6) = 270, v = 240.
        // Point (2.5, 1.5, 0.0) -> cam = (+1.0, 0, 6.0) -> u = 320 + 600*(+1.0/6) = 420, v = 240.
        let obs1 = object(&[
            (
                "evidence_digest",
                string(&ContentDigest::sha256(b"obs-1").to_text()),
            ),
            ("camera", "1".into()),
            ("exposure", "1".into()),
            ("image_domain", "1".into()),
            ("capture_min_ns", "1000000000".into()),
            ("capture_max_ns", "1000000000".into()),
            ("pixel_min", "[270.0,240.0]".into()),
            ("pixel_max", "[270.0,240.0]".into()),
            ("visible_contact", visible_contact.to_string()),
        ]);
        let obs2 = object(&[
            (
                "evidence_digest",
                string(&ContentDigest::sha256(b"obs-2").to_text()),
            ),
            ("camera", "1".into()),
            ("exposure", "2".into()),
            ("image_domain", "1".into()),
            ("capture_min_ns", "2000000000".into()),
            ("capture_max_ns", "2000000000".into()),
            ("pixel_min", "[420.0,240.0]".into()),
            ("pixel_max", "[420.0,240.0]".into()),
            ("visible_contact", visible_contact.to_string()),
        ]);
        let query_json = object(&[
            ("schema", string(QUERY_SCHEMA)),
            ("rig_sha256", string(&rig_digest.to_text())),
            ("clock", "11".into()),
            ("track", "77".into()),
            ("epoch", "1".into()),
            ("horizon_ns", "10000000000".into()),
            ("movement_class", string(movement_class)),
            ("person_path_multiplier", "3".into()),
            ("retain_without_preference", "true".into()),
            ("sample_period_ns", "250000000".into()),
            ("observations", array(&[obs1, obs2])),
        ]);

        let dir = std::env::temp_dir().join(format!(
            "fss-world-forecast-test-{}-{movement_class}-{visible_contact}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        let twin_path = dir.join("site.fsstwin");
        let rig_path = dir.join("rig.json");
        let query_path = dir.join("query.json");
        fs::write(&twin_path, twin_bytes)?;
        fs::write(&rig_path, rig_json)?;
        fs::write(&query_path, &query_json)?;

        let args = vec![
            OsString::from("--twin"),
            twin_path.into_os_string(),
            OsString::from("--rig"),
            rig_path.into_os_string(),
            OsString::from("--observations"),
            query_path.into_os_string(),
        ];
        let mut out = Vec::new();
        let ok = run(&args, &mut out).map_err(|e| format!("{}: {}", e.code, e.detail))?;
        let _ = fs::remove_dir_all(&dir);
        assert!(ok);
        let parsed = parse(std::str::from_utf8(&out)?)?;
        Ok(parsed)
    }

    #[test]
    fn person_world_forecast_predicts_camera_two_handoff_and_retains_protected_alternatives()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let twin = build_two_surface_walkable_twin();
        let rig = build_two_camera_rig(&twin);
        let doc = run_query(&twin, &rig, "person", true)?;
        let report = doc
            .object()
            .and_then(|o| o.get("report"))
            .and_then(Value::object)
            .ok_or("missing report")?;
        let receipts = report
            .get("track_receipts")
            .and_then(Value::array)
            .ok_or("missing track_receipts")?;
        assert_eq!(receipts.len(), 2);
        assert_eq!(
            receipts[0]
                .object()
                .and_then(|o| o.get("disposition"))
                .and_then(Value::text),
            Some("seeded")
        );
        assert_eq!(
            receipts[1]
                .object()
                .and_then(|o| o.get("disposition"))
                .and_then(Value::text),
            Some("motion_updated")
        );
        let frontier_routes = report
            .get("route_frontier")
            .and_then(Value::object)
            .and_then(|o| o.get("routes"))
            .and_then(Value::array)
            .ok_or("missing route_frontier.routes")?;
        assert!(
            frontier_routes.iter().any(|r| {
                r.object().and_then(|o| o.get("kind")).and_then(Value::text)
                    == Some("without_path_preference")
            }),
            "protected neutral/off-path route must be retained alongside preferred route"
        );
        let handoff = report
            .get("handoff_forecast")
            .and_then(Value::object)
            .ok_or("missing handoff_forecast")?;
        let next_cams = handoff
            .get("next_cameras")
            .and_then(Value::array)
            .ok_or("missing next_cameras")?;
        assert!(
            next_cams.iter().any(|c| {
                c.object()
                    .and_then(|o| o.get("camera"))
                    .and_then(Value::integer)
                    == Some(2)
            }),
            "expected camera 2 to appear in next_cameras handoff forecast: {next_cams:?}"
        );
        Ok(())
    }

    #[test]
    fn bear_class_disables_pedestrian_path_bias_and_hidden_contact_refuses_depth_invention()
    -> std::result::Result<(), Box<dyn std::error::Error>> {
        let twin = build_two_surface_walkable_twin();
        let rig = build_two_camera_rig(&twin);

        let bear_doc = run_query(&twin, &rig, "bear", true)?;
        let basis = bear_doc
            .object()
            .and_then(|o| o.get("report"))
            .and_then(Value::object)
            .and_then(|o| o.get("basis"))
            .and_then(Value::object)
            .ok_or("missing basis")?;
        assert_eq!(
            basis.get("person_path_multiplier").and_then(Value::integer),
            Some(1),
            "non-person classes must never inherit pedestrian path multiplier"
        );

        let hidden_doc = run_query(&twin, &rig, "unknown", false)?;
        let report = hidden_doc
            .object()
            .and_then(|o| o.get("report"))
            .and_then(Value::object)
            .ok_or("missing report")?;
        let receipts = report
            .get("track_receipts")
            .and_then(Value::array)
            .ok_or("missing track_receipts")?;
        assert_eq!(
            receipts[1]
                .object()
                .and_then(|o| o.get("disposition"))
                .and_then(Value::text),
            Some("contact_unavailable")
        );
        assert_eq!(report.get("handoff_forecast"), Some(&Value::Null));
        Ok(())
    }
}
