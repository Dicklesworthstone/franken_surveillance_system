#![forbid(unsafe_code)]
//! Original synthetic, memory-only JPEG/rig/query inputs; no physical accuracy claim.

use fss_cli::json_input::{Value, parse};
use fss_cli::json_output::{array, object, string};
use fss_cli::scene_rig::SceneRig;
use fss_core::ContentDigest;
use fss_geometry::{GeometryBasis, WorkBudget};
use fss_twin::{ImportExpectation, ImportLimits, PropertyTwin, import_twin};

use super::input::{self, Query};

pub(super) type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
pub(crate) const LEFT: &[u8] = include_bytes!("../../../../tests/fixtures/scene_match_left.jpg");
pub(crate) const RIGHT: &[u8] = include_bytes!("../../../../tests/fixtures/scene_match_right.jpg");
pub(crate) const WIDTH: u32 = 192;
pub(crate) const HEIGHT: u32 = 128;
pub(super) const WORK: u64 = 100_000_000;
pub(super) const REPORT_BYTES: usize = 8_388_608;

pub(super) fn ok<T>(result: super::super::Result<T>) -> TestResult<T> {
    result.map_err(|error| format!("native feature CLI: {error:?}").into())
}
pub(super) fn digest(value: &[u8]) -> String {
    ContentDigest::sha256(value).to_text()
}
pub(super) fn json(value: &Value) -> String {
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
pub(super) fn replace(value: &mut Value, path: &[&str], new: Value) -> TestResult {
    if path.is_empty() {
        *value = new;
        return Ok(());
    }
    match value {
        Value::Object(values) => replace(
            values.get_mut(path[0]).ok_or("missing fixture field")?,
            &path[1..],
            new,
        ),
        Value::Array(values) => replace(
            values
                .get_mut(path[0].parse::<usize>()?)
                .ok_or("missing fixture index")?,
            &path[1..],
            new,
        ),
        _ => Err("fixture path is not a container".into()),
    }
}
pub(super) fn field<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a Value> {
    if path.is_empty() {
        return Ok(value);
    }
    match value {
        Value::Object(values) => field(
            values.get(path[0]).ok_or("missing fixture field")?,
            &path[1..],
        ),
        Value::Array(values) => field(
            values
                .get(path[0].parse::<usize>()?)
                .ok_or("missing fixture index")?,
            &path[1..],
        ),
        _ => Err("fixture path is not a container".into()),
    }
}

/// Neutral authored triangle behind the synthetic textured plane, with relative scale.
pub(crate) fn package() -> Vec<u8> {
    fn text(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend_from_slice(&(value.len() as u16).to_le_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    let mut body = ContentDigest::sha256(b"synthetic native JPEG matching scene")
        .bytes()
        .to_vec();
    text(&mut body, "synthetic_native_match");
    text(&mut body, "synthetic_fixture_epoch");
    body.push(0);
    for value in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    for value in [1_u32, 1, 3, 1] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    text(&mut body, "background");
    body.push(5);
    text(&mut body, "background");
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[0, 1]);
    for point in [
        [-10.0_f64, -10.0, 20.0],
        [10.0, -10.0, 20.0],
        [0.0, 10.0, 20.0],
    ] {
        for value in point {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    for value in [0_u32, 1, 2, 0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    let mut bytes = b"FSSTWIN1".to_vec();
    bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
    bytes.extend(body);
    bytes.extend_from_slice(&ContentDigest::sha256(&bytes).bytes());
    bytes
}

pub(crate) fn rig_document(package: &[u8]) -> String {
    let cameras: Vec<_> = (1..=2)
        .map(|camera| {
            object(&[
                ("camera", camera.to_string()),
                ("calibration", "1".into()),
                ("image_domain", camera.to_string()),
                ("clock", "11".into()),
                ("privacy_domain", "9".into()),
                ("validity_ns", "[0,2000]".into()),
                (
                    "source_object_id",
                    string(&format!("synthetic_camera_{camera}")),
                ),
                ("image_model", string("undistorted_pinhole")),
                ("status", string("authored_nominal")),
                ("error", "null".into()),
                (
                    "world_to_camera",
                    object(&[
                        ("rotation", "[[1,0,0],[0,1,0],[0,0,1]]".into()),
                        ("translation", format!("[{},0,0]", 1 - camera)),
                    ]),
                ),
                (
                    "intrinsics",
                    object(&[
                        ("width", WIDTH.to_string()),
                        ("height", HEIGHT.to_string()),
                        ("fx", "160".into()),
                        ("fy", "160".into()),
                        ("cx", "96".into()),
                        ("cy", "64".into()),
                    ]),
                ),
            ])
        })
        .collect();
    object(&[
        ("schema", string("fss.scene_camera_rig.v1")),
        (
            "source_scene_digest",
            string(&digest(b"synthetic native JPEG matching scene")),
        ),
        ("twin_digest", string(&digest(package))),
        ("geometry_basis", "{\"property\":7,\"revision\":2}".into()),
        ("coordinate_frame", string("RH_Z_UP")),
        ("evaluation_scope", string("synthetic_native_match")),
        ("cameras", array(&cameras)),
    ])
}

pub(super) fn query_document(rig: &str, masks: [Option<&[u8]>; 2]) -> String {
    let views: Vec<_> = [LEFT, RIGHT]
        .into_iter()
        .enumerate()
        .map(|(index, bytes)| {
            let mask = match masks[index] {
                None => object(&[("kind", string("all_allowed"))]),
                Some(mask) => {
                    object(&[("kind", string("file")), ("digest", string(&digest(mask)))])
                }
            };
            object(&[
                ("camera", (index + 1).to_string()),
                ("source_digest", string(&digest(bytes))),
                (
                    "image_domain_digest",
                    string(&digest(
                        format!("synthetic undistorted grayscale image domain {}", index + 1)
                            .as_bytes(),
                    )),
                ),
                (
                    "mapping_basis",
                    string(&digest(
                        format!("declared synthetic image to rig camera {}", index + 1).as_bytes(),
                    )),
                ),
                ("capture_ns", "[1000,1100]".into()),
                ("sigma_pixels", "0.5".into()),
                ("component_interpretation", string("grayscale")),
                ("mask", mask),
            ])
        })
        .collect();
    object(&[
        ("schema", string("fss.scene_feature_match_query.v1")), ("camera_rig_digest", string(&digest(rig.as_bytes()))),
        ("privacy_domain", "9".into()), ("clock", "11".into()),
        ("clock_evidence", string(&digest(b"synthetic shared shutter clock"))),
        ("association_basis", string(&digest(b"declared stationary synthetic textured plane during full capture hull"))),
        ("reference_time_ns", "1050".into()), ("max_capture_span_ns", "100".into()),
        ("motion", string("static_during_capture_hull")), ("left", views[0].clone()), ("right", views[1].clone()),
        ("extraction", "{\"threshold\":20,\"maximum_features\":32,\"separation\":6}".into()),
        ("matching", "{\"maximum_hamming_distance\":0,\"ratio_percent\":80,\"maximum_epipolar_distance_pixels\":0.000001}".into()),
        ("triangulation", "{\"min_views\":2,\"max_outliers\":0,\"max_reprojection_pixels\":0.01}".into()),
    ])
}

pub(super) struct Fixture {
    pub package: Vec<u8>,
    pub rig_document: String,
    pub query_document: String,
    pub twin: PropertyTwin,
    pub rig: SceneRig,
}
impl Fixture {
    pub fn new() -> TestResult<Self> {
        let package = package();
        let twin = import_twin(
            &package,
            ImportExpectation {
                package_sha256: ContentDigest::sha256(&package).bytes(),
                source_scene_sha256: ContentDigest::sha256(b"synthetic native JPEG matching scene")
                    .bytes(),
                basis: GeometryBasis::new(7, 2)?,
            },
            ImportLimits::default(),
            &mut WorkBudget::new(WORK),
        )?;
        let rig_document = rig_document(&package);
        let rig =
            SceneRig::from_document(&parse(&rig_document)?, &twin, &mut WorkBudget::new(WORK))?;
        let query_document = query_document(&rig_document, [None, None]);
        Ok(Self {
            package,
            rig_document,
            query_document,
            twin,
            rig,
        })
    }
    pub fn parse_query(&self, document: &str) -> TestResult<Query> {
        ok(input::parse(
            document.as_bytes(),
            ContentDigest::sha256(self.rig_document.as_bytes()),
        ))
    }
}
