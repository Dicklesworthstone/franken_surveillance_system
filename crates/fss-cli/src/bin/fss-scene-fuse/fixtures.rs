#![forbid(unsafe_code)]
//! Explicit synthetic known-rig inputs shared by native CLI tests; not field evidence.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use fss_cli::{
    agent_json::{array, object, string},
    json_input::{Value, parse},
};
use fss_core::ContentDigest;

pub(crate) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

static NEXT: AtomicU64 = AtomicU64::new(0);
pub(crate) const REFERENCE_NS: u64 = 1_500_000_000;
pub(crate) const POSITION: [f64; 3] = [0.3, 0.2, 6.0];
pub(crate) const VELOCITY: [f64; 3] = [1.0, -0.25, 0.5];
pub(crate) const CENTERS: [[f64; 3]; 3] = [[-2.0, 0.0, 0.0], [2.0, 0.0, 0.0], [0.0, 2.0, 0.0]];

pub(crate) fn digest(text: &str) -> String {
    ContentDigest::sha256(text.as_bytes()).to_text()
}
fn vector<const N: usize>(v: [f64; N]) -> String {
    array(&v.map(|v| v.to_string()))
}
pub(crate) fn json(value: &Value) -> String {
    match value {
        Value::Null => "null".into(),
        Value::Bool(v) => v.to_string(),
        Value::Number(v) => v.clone(),
        Value::Text(v) => string(v),
        Value::Array(v) => array(&v.iter().map(json).collect::<Vec<_>>()),
        Value::Object(v) => object(
            &v.iter()
                .map(|(k, v)| (k.as_str(), json(v)))
                .collect::<Vec<_>>(),
        ),
    }
}
pub(crate) fn replace(value: &mut Value, path: &[&str], new: Value) -> TestResult {
    if path.is_empty() {
        *value = new;
        return Ok(());
    }
    match value {
        Value::Object(values) => replace(
            values.get_mut(path[0]).ok_or("fixture object field")?,
            &path[1..],
            new,
        ),
        Value::Array(values) => replace(
            values
                .get_mut(path[0].parse::<usize>()?)
                .ok_or("fixture index")?,
            &path[1..],
            new,
        ),
        _ => Err("fixture path is not a container".into()),
    }
}
pub(crate) fn field<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a Value> {
    if path.is_empty() {
        return Ok(value);
    }
    match value {
        Value::Object(values) => field(
            values.get(path[0]).ok_or("fixture object field")?,
            &path[1..],
        ),
        Value::Array(values) => field(
            values
                .get(path[0].parse::<usize>()?)
                .ok_or("fixture index")?,
            &path[1..],
        ),
        _ => Err("fixture path is not a container".into()),
    }
}

pub(crate) fn package(opaque: bool) -> Vec<u8> {
    fn text(out: &mut Vec<u8>, value: &str) {
        out.extend_from_slice(&(value.len() as u16).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    let mut body = ContentDigest::sha256(b"synthetic authored CLI scene")
        .bytes()
        .to_vec();
    text(&mut body, "synthetic_cli_scene");
    text(&mut body, "fixture_epoch");
    body.push(0);
    for n in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&n.to_le_bytes());
    }
    for n in [1_u32, 1, 3, 1] {
        body.extend_from_slice(&n.to_le_bytes());
    }
    text(&mut body, "wall");
    body.push(5);
    text(&mut body, "wall");
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[0, u8::from(opaque)]);
    for point in [
        [-10.0_f64, -10.0, 4.0],
        [10.0, -10.0, 4.0],
        [0.0, 10.0, 4.0],
    ] {
        for n in point {
            body.extend_from_slice(&n.to_le_bytes());
        }
    }
    for n in [0_u32, 1, 2, 0] {
        body.extend_from_slice(&n.to_le_bytes());
    }
    let mut bytes = b"FSSTWIN1".to_vec();
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend(body);
    bytes.extend_from_slice(&ContentDigest::sha256(&bytes).bytes());
    bytes
}

pub(crate) fn rig(bytes: &[u8]) -> String {
    let cameras: Vec<_> = CENTERS
        .iter()
        .enumerate()
        .map(|(index, center)| {
            object(&[
                ("camera", (index + 1).to_string()),
                ("calibration", "1".into()),
                ("image_domain", "1".into()),
                ("clock", "11".into()),
                ("privacy_domain", "9".into()),
                ("validity_ns", format!("[0,{}]", u64::MAX)),
                ("source_object_id", string(&format!("camera_{}", index + 1))),
                ("image_model", string("undistorted_pinhole")),
                ("status", string("authored_nominal")),
                ("error", "null".into()),
                (
                    "world_to_camera",
                    object(&[
                        ("rotation", "[[1,0,0],[0,1,0],[0,0,1]]".into()),
                        ("translation", vector(center.map(|v| -v))),
                    ]),
                ),
                (
                    "intrinsics",
                    r#"{"width":640,"height":480,"fx":400,"fy":400,"cx":320,"cy":240}"#.into(),
                ),
            ])
        })
        .collect();
    object(&[
        ("schema", string("fss.scene_camera_rig.v1")),
        (
            "source_scene_digest",
            string(&digest("synthetic authored CLI scene")),
        ),
        (
            "twin_digest",
            string(&ContentDigest::sha256(bytes).to_text()),
        ),
        ("geometry_basis", "{\"property\":7,\"revision\":2}".into()),
        ("coordinate_frame", string("RH_Z_UP")),
        ("evaluation_scope", string("synthetic_cli_scene")),
        ("cameras", array(&cameras)),
    ])
}

pub(crate) fn source(camera: usize, when: u64, ordinal: u64, moving: bool) -> String {
    let dt = (i128::from(when) - i128::from(REFERENCE_NS)) as f64 * 1e-9;
    let point: [f64; 3] =
        std::array::from_fn(|i| POSITION[i] + if moving { VELOCITY[i] * dt } else { 0.0 });
    let p: [f64; 3] = std::array::from_fn(|i| point[i] - CENTERS[camera - 1][i]);
    let pixel = [320.0 + 400.0 * p[0] / p[2], 240.0 + 400.0 * p[1] / p[2]];
    object(&[
        (
            "source_digest",
            string(&digest(&format!("source_camera_{camera}"))),
        ),
        (
            "evidence_digest",
            string(&digest(&format!("observation_{camera}_{when}_{ordinal}"))),
        ),
        ("camera", camera.to_string()),
        ("track", "42".into()),
        ("exposure", ordinal.to_string()),
        ("image_domain", "1".into()),
        ("capture_ns", format!("[\"{when}\",\"{when}\"]")),
        ("pixel_min", vector(pixel)),
        ("pixel_max", vector(pixel)),
        ("visible_contact", "true".into()),
        ("sigma_pixels", "0.5".into()),
    ])
}
pub(crate) fn hypothesis(id: &str, mode: &str) -> String {
    let moving = mode != "static";
    let sources: Vec<_> = if mode == "infer_linear" {
        (0..6)
            .map(|i| {
                source(
                    i % 3 + 1,
                    1_000_000_000 + i as u64 * 200_000_000,
                    i as u64 + 1,
                    true,
                )
            })
            .collect()
    } else {
        (1..=3)
            .map(|i| {
                source(
                    i,
                    if moving {
                        1_000_000_000 + i as u64 * 200_000_000
                    } else {
                        REFERENCE_NS
                    },
                    i as u64,
                    moving,
                )
            })
            .collect()
    };
    let motion = match mode {
        "infer_linear" => "{\"kind\":\"infer_linear\",\"max_capture_uncertainty_ns\":0}".into(),
        "linear" => object(&[
            ("kind", string("linear")),
            ("velocity_per_second", vector(VELOCITY)),
            ("evidence", string(&digest("external_motion"))),
        ]),
        _ => "{\"kind\":\"static\"}".into(),
    };
    object(&[
        ("id", string(id)),
        (
            "association_evidence",
            string(&digest(&format!("association_{id}"))),
        ),
        ("motion", motion),
        ("max_capture_span_ns", "1000000000".into()),
        ("observations", array(&sources)),
    ])
}
pub(crate) fn query(rig: &str, hypotheses: &[String]) -> TestResult<Value> {
    Ok(parse(&object(&[
        ("schema", string("fss.scene_fusion_query.v1")),
        (
            "camera_rig_digest",
            string(&ContentDigest::sha256(rig.as_bytes()).to_text()),
        ),
        ("privacy_domain", "9".into()),
        ("clock", "11".into()),
        ("clock_evidence", string(&digest("common_capture_clock"))),
        ("reference_time_ns", REFERENCE_NS.to_string()),
        ("hypotheses", array(hypotheses)),
    ]))?)
}

pub(crate) struct Fixture {
    pub directory: PathBuf,
    pub twin: PathBuf,
    pub rig: PathBuf,
    pub query: PathBuf,
    pub report: PathBuf,
}
impl Fixture {
    pub fn new(opaque: bool, modes: &[&str]) -> TestResult<Self> {
        let directory = std::env::temp_dir().join(format!(
            "fss-scene-fusion-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory)?;
        let result = Self {
            twin: directory.join("scene.fsstwin"),
            rig: directory.join("cameras.json"),
            query: directory.join("observations.json"),
            report: directory.join("report.json"),
            directory,
        };
        let bytes = package(opaque);
        let rig = rig(&bytes);
        let hypotheses: Vec<_> = modes
            .iter()
            .enumerate()
            .map(|(index, mode)| hypothesis(&format!("feature_{index}"), mode))
            .collect();
        let query = query(&rig, &hypotheses)?;
        std::fs::write(&result.twin, bytes)?;
        std::fs::write(&result.rig, rig)?;
        std::fs::write(&result.query, json(&query))?;
        Ok(result)
    }
    pub fn read_query(&self) -> TestResult<Value> {
        Ok(parse(&std::fs::read_to_string(&self.query)?)?)
    }
    pub fn write_query(&self, query: &Value) -> TestResult {
        Ok(std::fs::write(&self.query, json(query))?)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
