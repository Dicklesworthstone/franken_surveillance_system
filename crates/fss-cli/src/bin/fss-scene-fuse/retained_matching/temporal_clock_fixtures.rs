#![forbid(unsafe_code)]
//! Original synthetic clock observations for native adapter and retained-command tests.
use fss_cli::json_input::{Value, parse};
use fss_cli::json_output::{array, object, string};
use fss_cli::scene_rig::SceneRig;
use fss_core::{CaptureInterval, ContentDigest, SensorCapsule};

use super::shared;

type Test<T> = std::result::Result<T, Box<dyn std::error::Error>>;
fn h(value: impl AsRef<[u8]>) -> ContentDigest {
    ContentDigest::sha256(value.as_ref())
}
fn pin(value: ContentDigest) -> String {
    string(&value.to_text())
}
fn numbers<const N: usize>(values: [f64; N]) -> String {
    array(&values.map(|n| n.to_string()))
}
fn at<'a>(value: &'a mut Value, keys: &[&str]) -> Test<&'a mut Value> {
    let Some((key, rest)) = keys.split_first() else {
        return Ok(value);
    };
    match value {
        Value::Object(fields) => at(fields.get_mut(*key).ok_or("missing fixture field")?, rest),
        Value::Array(rows) => at(
            rows.get_mut(key.parse::<usize>()?)
                .ok_or("missing fixture row")?,
            rest,
        ),
        _ => Err("fixture object or array".into()),
    }
}

pub(in crate::retained_matching) fn calibration(camera: u64) -> ContentDigest {
    h(format!("temporal-clock-calibration-{camera}"))
}

/// Two explicitly separate passages: a stationary search and a moving validation session.
/// Projection requests use the complete independently supplied retained capture intervals.
pub(in crate::retained_matching) fn query(
    rig: &SceneRig,
    domains: [ContentDigest; 2],
    captures: &[CaptureInterval],
    offset: i128,
) -> Test<Value> {
    let mut cameras = Vec::new();
    for id in 1..=2 {
        let camera = rig.camera(id).ok_or("fixture camera")?.camera;
        let k = camera.intrinsics;
        let dimensions = k.dimensions();
        let focal = k.focal_lengths();
        let principal = k.principal_point();
        cameras.push(object(&[
            ("id", id.to_string()),
            ("clock", if id == 1 { "11".into() } else { "22".into() }),
            ("calibration_digest", pin(calibration(id))),
            ("image_domain", pin(domains[id as usize - 1])),
            (
                "intrinsics",
                object(&[
                    ("width", dimensions[0].to_string()),
                    ("height", dimensions[1].to_string()),
                    ("fx", focal[0].to_string()),
                    ("fy", focal[1].to_string()),
                    ("cx", principal[0].to_string()),
                    ("cy", principal[1].to_string()),
                ]),
            ),
            ("rotation", array(&camera.pose.rotation().map(numbers))),
            ("center", numbers(camera.pose.center())),
        ]));
    }
    let passage = |session: u64, start: i128, moving: bool| -> Test<(String, String)> {
        let mut training = Vec::new();
        let mut validation = Vec::new();
        for (holdout, times) in [(false, vec![0, 2, 4]), (true, vec![1, 3])] {
            for tick in times {
                for camera_id in 1..=2 {
                    let t = if moving { tick as f64 } else { 0.0 };
                    let camera = rig.camera(camera_id).ok_or("fixture camera")?.camera;
                    let point = [0.2 + 0.25 * t, 0.1 + 0.1 * t, 8.0 + 0.1 * t];
                    let pixel = camera.pose.project(camera.intrinsics, point)?;
                    let local =
                        (start + tick) * 1_000_000_000 + if camera_id == 2 { offset } else { 0 };
                    let label = format!(
                        "clock-session-{session}-camera-{camera_id}-tick-{tick}-holdout-{holdout}"
                    );
                    let mut row = vec![
                        ("camera", camera_id.to_string()),
                        (
                            "clock",
                            if camera_id == 1 {
                                "11".into()
                            } else {
                                "22".into()
                            },
                        ),
                        ("pixel", numbers(pixel)),
                        ("sigma_pixels", "0.5".into()),
                        ("exposure", string(&label)),
                        ("source_digest", pin(h(format!("source:{label}")))),
                        ("evidence_digest", pin(h(format!("evidence:{label}")))),
                    ];
                    row.push(if holdout {
                        (
                            "capture_interval_ns",
                            array(&[local, local].map(|v| string(&v.to_string()))),
                        )
                    } else {
                        ("capture_ns", string(&local.to_string()))
                    });
                    if holdout {
                        validation.push(object(&row));
                    } else {
                        training.push(object(&row));
                    }
                }
            }
        }
        Ok((array(&training), array(&validation)))
    };
    let search = passage(0, -20, false)?;
    let session = passage(17, -10, true)?;
    let projections = captures
        .iter()
        .enumerate()
        .map(|(index, capture)| {
            object(&[
                ("id", (index + 1).to_string()),
                (
                    "target_interval_ns",
                    array(&[capture.earliest.0, capture.latest.0].map(|v| string(&v.to_string()))),
                ),
            ])
        })
        .collect::<Vec<_>>();
    parse(&object(&[
        ("schema", string("fss.clock_validation_query.v1")), ("world_basis", pin(rig.twin_digest())),
        ("association_evidence", pin(h("original synthetic search association"))),
        ("reference_camera", cameras[0].clone()), ("target_camera", cameras[1].clone()),
        ("target_anchor_ns", "0".into()),
        ("hypotheses", array(&[-500_000, 0, 500_000].map(|skew| object(&[("offset_ns", string(&offset.to_string())), ("skew_ppb", skew.to_string())])))),
        ("fit_options", "{\"max_reprojection_pixels\":0.00001,\"max_distance\":1000,\"max_speed\":20,\"max_condition_number\":10000000000,\"max_iterations\":16}".into()),
        ("training", search.0), ("validation", search.1),
        ("sessions", array(&[object(&[("id", "17".into()), ("association_evidence", pin(h("original synthetic moving association"))),
            ("training", session.0), ("validation", session.1)])])),
        ("projections", array(&projections)),
    ])).map_err(Into::into)
}

/// Opt into v2 without changing a retained fact. The caller creates the original query first.
pub(in crate::retained_matching) fn attach(
    document: &mut Value,
    rig: &SceneRig,
    capsules: &[SensorCapsule],
    clock_query: &Value,
    path: &str,
) -> Test<Vec<u8>> {
    let clock_bytes = shared::json(clock_query).into_bytes();
    let digest = h(&clock_bytes);
    let mut bindings = Vec::new();
    for camera in 1..=2 {
        let capsule = &capsules[camera as usize - 1];
        let rig_camera = rig.camera(camera).ok_or("fixture camera")?.camera;
        bindings.push(object(&[
            ("camera", camera.to_string()),
            ("sensor_id", string(capsule.sensor_id.as_str())),
            ("stream_id", string(capsule.stream_id.as_str())),
            ("clock_basis", string(capsule.clock_basis.as_str())),
            (
                "clock_generation",
                if camera == 1 {
                    "11".into()
                } else {
                    "22".into()
                },
            ),
            ("calibration_generation", rig_camera.calibration.to_string()),
            ("image_generation", rig_camera.image_domain.to_string()),
            ("calibration_digest", pin(calibration(camera))),
        ]));
    }
    let mut projections = Vec::new();
    let views = at(document, &["views"])?;
    let Value::Array(views) = views else {
        return Err("fixture views".into());
    };
    let mut target = 0;
    for view in views {
        *at(view, &["alignment", "offset_ns"])? = parse("[0,0]")?;
        *at(view, &["alignment", "basis"])? = Value::Text(digest.to_text());
        if at(view, &["camera"])?.integer() == Some(2) {
            target += 1;
            let capsule = at(view, &["source", "capsule_digest"])?
                .text()
                .ok_or("capsule pin")?
                .to_owned();
            projections.push(object(&[
                ("capsule_digest", string(&capsule)),
                ("projection_id", target.to_string()),
            ]));
        }
    }
    let Value::Object(fields) = document else {
        return Err("fixture query".into());
    };
    fields.insert(
        "schema".into(),
        Value::Text("fss.scene_feature_motion_match_retained_query.v2".into()),
    );
    fields.insert("clock_evidence".into(), Value::Text(digest.to_text()));
    fields.insert(
        "max_capture_uncertainty_ns".into(),
        Value::Number("10000000".into()),
    );
    fields.insert(
        "clock_validation".into(),
        parse(&object(&[
            ("query_path", string(path)),
            ("query_digest", pin(digest)),
            ("bindings", array(&bindings)),
            ("projections", array(&projections)),
        ]))?,
    );
    Ok(clock_bytes)
}
