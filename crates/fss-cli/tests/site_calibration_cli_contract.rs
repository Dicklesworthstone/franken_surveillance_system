#![forbid(unsafe_code)]
//! Contract tests, through the real binaries, for the owner site-calibration path
//! (fss-x8j0v follow-up): `fss-event calibrate` -> `fss-event corroborate --calibration`.
//!
//! A deterministic synthetic site is built in-test: the walled `FSSTWIN1` twin of the
//! ground-coverage tests (world frame; also the corroboration scene mesh), a surveyed `FSATLAS1`
//! atlas of ten landmarks built and encoded through fss-twin, and three cameras (east and west
//! with fixed intrinsics exactly as the corroboration fixtures' `--pose` values, north with a
//! focal scan) whose observation files carry projected landmark pixels (with 0.002 px bounded
//! deterministic noise), atlas descriptors and eight shared tie points. The command takes these
//! correspondences, NOT images.
//!
//! Proven: the calibration's poses are within stated tolerances of ground truth; the bytes and
//! stdout are identical across runs; corroboration with the calibration yields ground-zone
//! visibility blocks identical to those from the true `--pose` values, with the calibration digest
//! in `pose_provenance`; tampering, a wrong pin, a distorted camera, a doubly posed camera and a
//! foreign twin are typed refusals; too few control points, a disconnected camera and a failed
//! localization are typed refusals that write nothing.
//!
//! Non-claim: a synthetic site does not establish calibration accuracy on real site footage.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;
use fss_geometry::{GeometryBasis, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_reference::ingest::site_calibration::SiteCalibration;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_twin::atlas_archive::{ReferenceProvenance, encode_atlas};
use fss_twin::localization::{
    AtlasBinding, AtlasLandmark, AtlasReference, BinaryDescriptor, FeatureFrame, ImageFeature,
    ImageIdentity, LocalizationAtlas,
};
use fss_twin::{ImportExpectation, ImportLimits, import_twin};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const SITE: &str = "site:site-calibration-cli";
/// East sees the ground from 10 units above (48, 24): `x = u`, `y = 48 - v`.
const EAST_GROUND: &str = "east:1,0,0,0,-1,48,0,0,1";
/// West is rotated half a turn about the vertical: `x = 96 - u`, `y = v`.
const WEST_GROUND: &str = "west:-1,0,96,0,1,0,0,0,1";
/// The calibrated poses those homographies describe (W,H,fx,fy,cx,cy,R row-major,t = -R*centre).
const EAST_POSE: &str = "east:96,48,10,10,48,24,1,0,0,0,-1,0,0,0,-1,-48,24,10";
const WEST_POSE: &str = "west:96,48,10,10,48,24,-1,0,0,0,1,0,0,0,-1,48,-24,10";
/// Descriptor generation of the synthetic atlas and every observation file.
const DESCRIPTOR_DOMAIN: [u8; 32] = [0x44; 32];
const LANDMARKS: u64 = 10;
const TIES: u64 = 8;
const TIE_BASE: u64 = 1001;
/// Bounded deterministic pixel noise added to every synthetic observation.
const NOISE_PX: f64 = 0.002;

// Minimal JSON reader: every assertion below goes through a full parse, so the output is also
// proven to be one well-formed JSON document.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
enum Json {
    Null,
    Bool(bool),
    Number(String),
    Text(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    fn parse(text: &str) -> TestResult<Self> {
        let bytes = text.as_bytes();
        let mut position = 0;
        let value = parse_value(bytes, &mut position)?;
        skip_whitespace(bytes, &mut position);
        if position != bytes.len() {
            return Err(format!("trailing bytes at {position}").into());
        }
        Ok(value)
    }

    fn get(&self, key: &str) -> TestResult<&Self> {
        match self {
            Self::Object(fields) => fields
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value)
                .ok_or_else(|| format!("missing key {key}").into()),
            _ => Err(format!("not an object when reading {key}").into()),
        }
    }

    fn path(&self, keys: &[&str]) -> TestResult<&Self> {
        let mut current = self;
        for key in keys {
            current = current.get(key)?;
        }
        Ok(current)
    }

    fn text(&self) -> TestResult<&str> {
        match self {
            Self::Text(value) => Ok(value),
            other => Err(format!("not a string: {other:?}").into()),
        }
    }

    fn items(&self) -> TestResult<&[Self]> {
        match self {
            Self::Array(items) => Ok(items),
            other => Err(format!("not an array: {other:?}").into()),
        }
    }

    fn texts(&self) -> TestResult<Vec<&str>> {
        self.items()?.iter().map(Self::text).collect()
    }

    fn number(&self) -> TestResult<u64> {
        match self {
            Self::Number(value) => Ok(value.parse()?),
            other => Err(format!("not a number: {other:?}").into()),
        }
    }
}

fn skip_whitespace(bytes: &[u8], position: &mut usize) {
    while bytes
        .get(*position)
        .is_some_and(|byte| byte.is_ascii_whitespace())
    {
        *position += 1;
    }
}

fn expect(bytes: &[u8], position: &mut usize, literal: &str) -> TestResult {
    if bytes[*position..].starts_with(literal.as_bytes()) {
        *position += literal.len();
        Ok(())
    } else {
        Err(format!("expected {literal} at {position}").into())
    }
}

fn parse_string(bytes: &[u8], position: &mut usize) -> TestResult<String> {
    expect(bytes, position, "\"")?;
    let mut out = String::new();
    loop {
        let byte = *bytes.get(*position).ok_or("unterminated string")?;
        *position += 1;
        match byte {
            b'"' => return Ok(out),
            b'\\' => {
                let escaped = *bytes.get(*position).ok_or("dangling escape")?;
                *position += 1;
                match escaped {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'b' => out.push('\u{8}'),
                    b'f' => out.push('\u{c}'),
                    b'u' => {
                        let hex = std::str::from_utf8(
                            bytes.get(*position..*position + 4).ok_or("short escape")?,
                        )?;
                        *position += 4;
                        out.push(
                            char::from_u32(u32::from_str_radix(hex, 16)?).ok_or("bad escape")?,
                        );
                    }
                    _ => return Err("unknown escape".into()),
                }
            }
            byte if byte < 0x20 => return Err("raw control character in string".into()),
            _ => {
                let start = *position - 1;
                let mut end = *position;
                while end < bytes.len() && bytes[end] != b'"' && bytes[end] != b'\\' {
                    end += 1;
                }
                out.push_str(std::str::from_utf8(&bytes[start..end])?);
                *position = end;
            }
        }
    }
}

fn parse_value(bytes: &[u8], position: &mut usize) -> TestResult<Json> {
    skip_whitespace(bytes, position);
    match bytes.get(*position).copied().ok_or("unexpected end")? {
        b'n' => expect(bytes, position, "null").map(|()| Json::Null),
        b't' => expect(bytes, position, "true").map(|()| Json::Bool(true)),
        b'f' => expect(bytes, position, "false").map(|()| Json::Bool(false)),
        b'"' => parse_string(bytes, position).map(Json::Text),
        b'[' => {
            *position += 1;
            let mut items = Vec::new();
            skip_whitespace(bytes, position);
            if bytes.get(*position) == Some(&b']') {
                *position += 1;
                return Ok(Json::Array(items));
            }
            loop {
                items.push(parse_value(bytes, position)?);
                skip_whitespace(bytes, position);
                match bytes.get(*position) {
                    Some(b',') => *position += 1,
                    Some(b']') => {
                        *position += 1;
                        return Ok(Json::Array(items));
                    }
                    _ => return Err("bad array".into()),
                }
            }
        }
        b'{' => {
            *position += 1;
            let mut fields: Vec<(String, Json)> = Vec::new();
            skip_whitespace(bytes, position);
            if bytes.get(*position) == Some(&b'}') {
                *position += 1;
                return Ok(Json::Object(fields));
            }
            loop {
                skip_whitespace(bytes, position);
                let key = parse_string(bytes, position)?;
                if fields.iter().any(|(seen, _)| *seen == key) {
                    return Err(format!("duplicate key {key}").into());
                }
                skip_whitespace(bytes, position);
                expect(bytes, position, ":")?;
                fields.push((key, parse_value(bytes, position)?));
                skip_whitespace(bytes, position);
                match bytes.get(*position) {
                    Some(b',') => *position += 1,
                    Some(b'}') => {
                        *position += 1;
                        return Ok(Json::Object(fields));
                    }
                    _ => return Err("bad object".into()),
                }
            }
        }
        _ => {
            let start = *position;
            while bytes
                .get(*position)
                .is_some_and(|byte| byte.is_ascii_digit() || b"-+.eE".contains(byte))
            {
                *position += 1;
            }
            if start == *position {
                return Err(format!("unexpected byte at {start}").into());
            }
            Ok(Json::Number(
                std::str::from_utf8(&bytes[start..*position])?.to_owned(),
            ))
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------------------------

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-site-calibration-cli-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }

    fn root(&self) -> PathBuf {
        self.0.join("deployment")
    }
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Fourteen quiet 96x48 grayscale MJPEG frames (no entry interrupts coverage).
fn quiet_scene() -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for _ in 0..14 {
        stream.extend(encode_jpeg(96, 48, &vec![40_u8; 96 * 48], &config)?);
    }
    Ok(stream)
}

fn text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

/// An fss-twin `FSSTWIN1` package (source scene digest `01..01`): an opaque ground plane at
/// z = 0 and, optionally, an opaque wall in the plane x = 52 (z 0..20) that stands between both
/// cameras (10 units above (48, 24)) and every ground point with x > 52.
fn twin_package(wall: bool) -> Vec<u8> {
    let mut body = vec![1_u8; 32];
    text(&mut body, "test/Z-up");
    text(&mut body, "synthetic");
    body.push(0);
    for value in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    let mut vertices: Vec<[f64; 3]> = vec![
        [-100.0, -100.0, 0.0],
        [200.0, -100.0, 0.0],
        [200.0, 200.0, 0.0],
        [-100.0, 200.0, 0.0],
    ];
    let mut triangles: Vec<[u32; 4]> = vec![[0, 1, 2, 0], [0, 2, 3, 0]];
    let objects: u32 = if wall { 2 } else { 1 };
    if wall {
        vertices.extend([
            [52.0, -10.0, 0.0],
            [52.0, 60.0, 0.0],
            [52.0, 60.0, 20.0],
            [52.0, -10.0, 20.0],
        ]);
        triangles.extend([[4, 5, 6, 1], [4, 6, 7, 1]]);
    }
    for count in [
        objects,
        objects,
        vertices.len() as u32,
        triangles.len() as u32,
    ] {
        body.extend_from_slice(&count.to_le_bytes());
    }
    text(&mut body, "ground");
    body.push(1);
    if wall {
        text(&mut body, "wall");
        body.push(5);
    }
    text(&mut body, "ground");
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[1, 1]);
    if wall {
        text(&mut body, "wall");
        body.extend_from_slice(&1_u32.to_le_bytes());
        body.extend_from_slice(&[0, 1]);
    }
    for vertex in &vertices {
        for value in vertex {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    for triangle in &triangles {
        for value in triangle {
            body.extend_from_slice(&value.to_le_bytes());
        }
    }
    let mut package = b"FSSTWIN1".to_vec();
    package.extend_from_slice(&(body.len() as u64).to_le_bytes());
    package.extend_from_slice(&body);
    let trailer = ContentDigest::sha256(&package).bytes();
    package.extend_from_slice(&trailer);
    package
}

fn source_scene() -> String {
    format!("sha256:{}", "01".repeat(32))
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn refusal(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("refusal_id=").map(str::to_owned))
        .unwrap_or_default()
}

/// Imports `bytes` for `sensor` with an operator capture hint (10 fps from 1 s, 1 ms
/// uncertainty). Returns the import identity.
fn import(
    directory: &OwnedDirectory,
    name: &str,
    bytes: &[u8],
    format: &str,
    sensor: &str,
) -> TestResult<String> {
    let input = directory.0.join(format!("{name}.media"));
    fs::write(&input, bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(directory.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{name}")])
        .args([
            "--media-format",
            format,
            "--receive-time-ns",
            "10000000000000",
            "--capture-start-ns",
            "1000000000",
            "--capture-uncertainty-ns",
            "1000000",
            "--assumed-fps",
            "10",
        ])
        .output()?;
    success(&output);
    fs::remove_file(input)?;
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("import identity missing")?)
}

fn event(root: &Path, command: &str, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .arg(command)
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args(args)
        .output()?)
}

fn recordings(directory: &OwnedDirectory) -> TestResult<[String; 2]> {
    Ok([
        format!(
            "east:{}",
            import(directory, "east", &quiet_scene()?, "mjpeg", "sensor:east")?
        ),
        format!(
            "west:{}",
            import(directory, "west", &quiet_scene()?, "mjpeg", "sensor:west")?
        ),
    ])
}

fn corroborate(root: &Path, cameras: &[String; 2], extra: &[&str]) -> TestResult<Output> {
    let mut args = vec![
        "--camera",
        &cameras[0],
        "--camera",
        &cameras[1],
        "--ground",
        EAST_GROUND,
        "--ground",
        WEST_GROUND,
        "--zone",
        "near:8,4,36,40",
        "--zone",
        "door:56,0,40,48",
        "--zone",
        "far:200,0,40,48",
        "--interpretation",
        "gray",
        "--time-gate-ns",
        "250000000",
        "--distance-gate",
        "16",
    ];
    args.extend_from_slice(extra);
    event(root, "corroborate", &args)
}

fn report(output: &Output) -> TestResult<Json> {
    success(output);
    Json::parse(String::from_utf8(output.stdout.clone())?.trim_end())
}

// ---------------------------------------------------------------------------------------------
// The synthetic site.
// ---------------------------------------------------------------------------------------------

/// SplitMix64: a fixed, platform-independent sequence.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn uniform(&mut self, low: f64, high: f64) -> f64 {
        low + (high - low) * ((self.next() >> 11) as f64 / (1_u64 << 53) as f64)
    }
}

fn descriptor(id: u64) -> BinaryDescriptor {
    let mut rng = Rng(0xD35C_0000 + id);
    BinaryDescriptor([rng.next(), rng.next(), rng.next(), rng.next()])
}

fn descriptor_hex(descriptor: BinaryDescriptor) -> String {
    descriptor
        .0
        .iter()
        .map(|word| format!("{word:016x}"))
        .collect()
}

type M3 = [[f64; 3]; 3];

fn look_at(center: [f64; 3], target: [f64; 3]) -> TestResult<RigidPose> {
    let unit = |a: [f64; 3]| {
        let n = (a[0] * a[0] + a[1] * a[1] + a[2] * a[2]).sqrt();
        [a[0] / n, a[1] / n, a[2] / n]
    };
    let cross = |a: [f64; 3], b: [f64; 3]| {
        [
            a[1] * b[2] - a[2] * b[1],
            a[2] * b[0] - a[0] * b[2],
            a[0] * b[1] - a[1] * b[0],
        ]
    };
    let z = unit([
        target[0] - center[0],
        target[1] - center[1],
        target[2] - center[2],
    ]);
    let x = unit(cross(z, [0.0, 0.0, 1.0]));
    let y = cross(z, x);
    Ok(RigidPose::from_center([x, y, z], center)?)
}

struct Truth {
    name: &'static str,
    handle: u64,
    intrinsics: PinholeIntrinsics,
    pose: RigidPose,
    /// The observation file's intrinsics line (fixed, or a focal scan bracketing the truth).
    intrinsics_line: &'static str,
}

fn truths() -> TestResult<Vec<Truth>> {
    Ok(vec![
        Truth {
            name: "east",
            handle: 21,
            intrinsics: PinholeIntrinsics::new(96, 48, 10.0, 10.0, 48.0, 24.0)?,
            pose: RigidPose::new(
                [[1.0, 0.0, 0.0], [0.0, -1.0, 0.0], [0.0, 0.0, -1.0]],
                [-48.0, 24.0, 10.0],
            )?,
            intrinsics_line: "intrinsics fixed 10 10 48 24",
        },
        Truth {
            name: "west",
            handle: 22,
            intrinsics: PinholeIntrinsics::new(96, 48, 10.0, 10.0, 48.0, 24.0)?,
            pose: RigidPose::new(
                [[-1.0, 0.0, 0.0], [0.0, 1.0, 0.0], [0.0, 0.0, -1.0]],
                [48.0, -24.0, 10.0],
            )?,
            intrinsics_line: "intrinsics fixed 10 10 48 24",
        },
        Truth {
            name: "north",
            handle: 23,
            intrinsics: PinholeIntrinsics::new(96, 48, 80.0, 80.0, 48.0, 24.0)?,
            pose: look_at([36.0, -20.0, 22.0], [36.0, 24.0, 0.0])?,
            intrinsics_line: "intrinsics focal 60 110 17 1 48 24",
        },
    ])
}

/// Landmarks (1..=10) then ties, all west of the wall at x = 52.
fn worlds() -> (Vec<[f64; 3]>, Vec<[f64; 3]>) {
    let mut rng = Rng(0x5173_CA11);
    let mut point = || {
        [
            rng.uniform(22.0, 50.0),
            rng.uniform(12.0, 36.0),
            rng.uniform(0.0, 3.0),
        ]
    };
    let landmarks = (0..LANDMARKS).map(|_| point()).collect();
    let ties = (0..TIES).map(|_| point()).collect();
    (landmarks, ties)
}

fn digest_text(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}

/// Paths and pins of one synthetic site on disk.
struct Site {
    twin: PathBuf,
    twin_digest: String,
    atlas: PathBuf,
    atlas_digest: String,
    provenance: String,
    observations: Vec<(&'static str, PathBuf)>,
}

enum Variant {
    Complete,
    /// North observes no tie point.
    NorthWithoutTies,
    /// West observes only five landmarks.
    WestFiveFeatures,
}

fn observation_file(
    truth: &Truth,
    landmarks: &[[f64; 3]],
    ties: &[[f64; 3]],
    rng: &mut Rng,
) -> TestResult<String> {
    let mut observe = |world: [f64; 3]| -> TestResult<[f64; 2]> {
        let clean = truth.pose.project(truth.intrinsics, world)?;
        let pixel = [
            clean[0] + rng.uniform(-NOISE_PX, NOISE_PX),
            clean[1] + rng.uniform(-NOISE_PX, NOISE_PX),
        ];
        if !truth.intrinsics.contains(pixel) {
            return Err(format!("{} does not see {world:?}", truth.name).into());
        }
        Ok(pixel)
    };
    let mut lines = vec![
        "fss.site_camera_observations.v1".to_owned(),
        format!("# synthetic camera {}", truth.name),
        format!("camera {} 1 1", truth.handle),
        "image 96 48".to_owned(),
        format!(
            "exposure {}",
            digest_text(&format!("exposure {}", truth.name))
        ),
        format!("pixels {}", digest_text(&format!("pixels {}", truth.name))),
        format!("image-domain {}", digest_text("image domain 96x48")),
        format!("descriptor-domain sha256:{}", "44".repeat(32)),
        truth.intrinsics_line.to_owned(),
    ];
    for (index, world) in landmarks.iter().enumerate() {
        let id = index as u64 + 1;
        let [u, v] = observe(*world)?;
        lines.push(format!(
            "feature {} {u} {v} {}",
            100 + id,
            descriptor_hex(descriptor(id))
        ));
    }
    for (index, world) in ties.iter().enumerate() {
        let [u, v] = observe(*world)?;
        lines.push(format!("tie {} {u} {v}", TIE_BASE + index as u64));
    }
    Ok(lines.join("\n") + "\n")
}

fn build_site(directory: &OwnedDirectory, variant: Variant) -> TestResult<Site> {
    let package = twin_package(true);
    let twin_path = directory.0.join("site.fsstwin");
    fs::write(&twin_path, &package)?;
    let mut budget = WorkBudget::new(100_000_000);
    let twin = import_twin(
        &package,
        ImportExpectation {
            package_sha256: ContentDigest::sha256(&package).bytes(),
            source_scene_sha256: [1; 32],
            basis: GeometryBasis::new(1, 1)?,
        },
        ImportLimits::default(),
        &mut budget,
    )?;
    let (landmark_worlds, tie_worlds) = worlds();
    // Only landmarks 1 and 2 declare a survey error; the others are unknown.
    let landmarks = landmark_worlds
        .iter()
        .enumerate()
        .map(|(index, world)| {
            let id = index as u64 + 1;
            AtlasLandmark {
                id,
                physical_group: id,
                feature: 0,
                world: *world,
                evidence: [7; 32],
                error: (id <= 2).then_some([0.001; 3]),
            }
        })
        .collect();
    let reference = FeatureFrame::new(
        ImageIdentity {
            exposure: [0xA1; 32],
            pixels: [0xA2; 32],
            image_domain: [0xA3; 32],
            dimensions: [640, 480],
        },
        DESCRIPTOR_DOMAIN,
        (1..=LANDMARKS)
            .map(|id| ImageFeature {
                id,
                pixel: [20.0 + 50.0 * id as f64, 100.0 + 30.0 * (id % 4) as f64],
                descriptor: descriptor(id),
            })
            .collect(),
        &mut budget,
    )?;
    let atlas = LocalizationAtlas::new(
        &twin,
        landmarks,
        vec![AtlasReference {
            id: 1,
            frame: reference,
        }],
        (1..=LANDMARKS)
            .map(|id| AtlasBinding {
                landmark: id,
                reference: 1,
                image_feature: id,
            })
            .collect(),
        &mut budget,
    )?;
    let atlas_bytes = encode_atlas(
        &atlas,
        [0xB1; 32],
        &[ReferenceProvenance {
            reference: 1,
            source_record: [0xB2; 32],
            allowed_mask: [0xB3; 32],
        }],
        &mut budget,
    )?;
    let atlas_path = directory.0.join("site.fsatlas");
    fs::write(&atlas_path, &atlas_bytes)?;
    let mut rng = Rng(0x0B5E_12FE);
    let mut observations = Vec::new();
    for truth in truths()? {
        let (landmarks, ties): (&[[f64; 3]], &[[f64; 3]]) = match (&variant, truth.name) {
            (Variant::NorthWithoutTies, "north") => (&landmark_worlds, &[]),
            (Variant::WestFiveFeatures, "west") => (&landmark_worlds[..5], &tie_worlds),
            _ => (&landmark_worlds, &tie_worlds),
        };
        let text = observation_file(&truth, landmarks, ties, &mut rng)?;
        let path = directory.0.join(format!("{}.obs", truth.name));
        fs::write(&path, text)?;
        observations.push((truth.name, path));
    }
    Ok(Site {
        twin: twin_path,
        twin_digest: ContentDigest::sha256(&package).to_text(),
        atlas: atlas_path,
        atlas_digest: ContentDigest::sha256(&atlas_bytes).to_text(),
        provenance: format!("sha256:{}", "b1".repeat(32)),
        observations,
    })
}

fn calibrate(site: &Site, out: &Path, extra: &[&str]) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    command
        .arg("calibrate")
        .arg("--twin")
        .arg(&site.twin)
        .args(["--twin-digest", &site.twin_digest])
        .args(["--twin-source-digest", &source_scene()])
        .arg("--atlas")
        .arg(&site.atlas)
        .args(["--atlas-digest", &site.atlas_digest])
        .args(["--atlas-provenance", &site.provenance]);
    for (name, path) in &site.observations {
        command
            .arg("--camera")
            .arg(format!("{name}:{}", path.to_str().ok_or("UTF-8 path")?));
    }
    Ok(command.arg("--out").arg(out).args(extra).output()?)
}

fn floats(value: &Json) -> TestResult<Vec<f64>> {
    value
        .items()?
        .iter()
        .map(|item| match item {
            Json::Number(text) => Ok(text.parse::<f64>()?),
            other => Err(format!("not a number: {other:?}").into()),
        })
        .collect()
}

fn rotation_error(a: M3, b: M3) -> f64 {
    let r: M3 =
        std::array::from_fn(|i| std::array::from_fn(|j| (0..3).map(|k| a[i][k] * b[j][k]).sum()));
    let sine =
        ((r[2][1] - r[1][2]).powi(2) + (r[0][2] - r[2][0]).powi(2) + (r[1][0] - r[0][1]).powi(2))
            .sqrt()
            / 2.0;
    let cosine = (r[0][0] + r[1][1] + r[2][2] - 1.0) / 2.0;
    sine.atan2(cosine)
}

/// `(zone id, visibility block)` of every coverage record, in report order.
fn visibilities(report: &Json) -> TestResult<Vec<(String, Json)>> {
    let mut found = Vec::new();
    for record in report.path(&["coverage", "records"])?.items()? {
        for zone in record.get("zones")?.items()? {
            found.push((
                zone.get("zone_id")?.text()?.to_owned(),
                zone.get("visibility")?.clone(),
            ));
        }
    }
    Ok(found)
}

fn provenance_sources(report: &Json) -> TestResult<Vec<(String, String)>> {
    report
        .get("pose_provenance")?
        .items()?
        .iter()
        .map(|entry| {
            Ok((
                entry.get("camera")?.text()?.to_owned(),
                entry.get("source")?.text()?.to_owned(),
            ))
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Contracts.
// ---------------------------------------------------------------------------------------------

/// Stated tolerances against ground truth under 0.002 px bounded observation noise:
/// `(rotation rad, centre units, relative focal)`. Fixed-intrinsics cameras (east, west: 10 units
/// above the ground, focal held) must recover rotation to 1e-4 rad and centre to 1e-3 units. The
/// focal-scan camera (north: ~49 units away, fx = 80 refined jointly) carries the focal/depth
/// coupling of its narrow view, so its centre tolerance is 0.03 units (6e-4 of its range) and its
/// focal tolerance 1e-3 relative. Measured on this fixture: east 3.9e-5 rad / 2.3e-4 units, west
/// 2.4e-5 rad / 4.1e-4 units, north 7.0e-5 rad / 1.2e-2 units / 2.7e-4 focal.
const FIXED_TOLERANCE: (f64, f64, f64) = (1e-4, 1e-3, 0.0);
const FOCAL_SCAN_TOLERANCE: (f64, f64, f64) = (2e-4, 3e-2, 1e-3);

#[test]
fn calibration_recovers_the_synthetic_site_and_corroborates_exactly_like_the_true_poses()
-> TestResult {
    let directory = OwnedDirectory::new("recover")?;
    let site = build_site(&directory, Variant::Complete)?;
    let first_out = directory.0.join("first.fsscal");
    let second_out = directory.0.join("second.fsscal");
    let first = calibrate(&site, &first_out, &[])?;
    success(&first);
    let second = calibrate(&site, &second_out, &[])?;
    success(&second);
    // Bit-identical across runs: file bytes and stdout.
    let bytes = fs::read(&first_out)?;
    assert_eq!(bytes, fs::read(&second_out)?);
    assert_eq!(first.stdout, second.stdout);
    let summary = Json::parse(String::from_utf8(first.stdout.clone())?.trim_end())?;
    let digest = summary.get("calibration_digest")?.text()?.to_owned();
    let (decoded, identity) =
        SiteCalibration::decode(&bytes, Some(ContentDigest::parse(&digest)?))?;
    assert_eq!(identity.to_text(), digest);
    assert_eq!(decoded.twin_package.to_text(), site.twin_digest);
    assert_eq!(decoded.atlas_package.to_text(), site.atlas_digest);
    assert_eq!(summary.get("format")?.text()?, "fss.site_calibration.v1");
    assert_eq!(
        summary.get("status")?.text()?,
        "candidate_calibration_not_activated"
    );
    assert_eq!(
        summary.get("control_points")?.items()?.len(),
        LANDMARKS as usize
    );
    assert_eq!(summary.get("tie_points")?.items()?.len(), TIES as usize);
    let solve = summary.get("joint_solve")?;
    let initial = floats(&Json::Array(vec![solve.get("initial_rms_px")?.clone()]))?[0];
    let final_rms = floats(&Json::Array(vec![solve.get("final_rms_px")?.clone()]))?[0];
    assert!(final_rms <= initial + 1e-12, "{final_rms} > {initial}");
    assert!(final_rms < 0.01, "joint RMS {final_rms} px");

    let truths = truths()?;
    let cameras = summary.get("cameras")?.items()?;
    assert_eq!(cameras.len(), 3);
    for (camera, truth) in cameras.iter().zip(&truths) {
        assert_eq!(camera.get("camera")?.text()?, truth.name);
        assert_eq!(camera.get("camera_handle")?.number()?, truth.handle);
        let invalidators = camera.get("invalidated_by")?;
        assert_eq!(invalidators.get("intrinsics_generation")?.number()?, 1);
        assert_eq!(invalidators.get("extrinsics_generation")?.number()?, 1);
        assert_eq!(camera.get("pinhole")?, &Json::Bool(true));
        let rows = camera.get("rotation_world_to_camera")?.items()?;
        let mut rotation = [[0.0; 3]; 3];
        for (r, row) in rows.iter().enumerate() {
            let values = floats(row)?;
            rotation[r].copy_from_slice(&values);
        }
        let center = floats(camera.get("center_world")?)?;
        let intrinsics = floats(camera.get("intrinsics_fx_fy_cx_cy")?)?;
        let truth_center = truth.pose.center();
        let angle = rotation_error(rotation, truth.pose.rotation());
        let offset = (0..3)
            .map(|k| (center[k] - truth_center[k]).powi(2))
            .sum::<f64>()
            .sqrt();
        let [fx, _] = truth.intrinsics.focal_lengths();
        let focal = (intrinsics[0] - fx).abs() / fx;
        eprintln!(
            "{}: rotation error {angle:.3e} rad, center error {offset:.3e} units, focal error {focal:.3e}",
            truth.name
        );
        let (rotation_tolerance, center_tolerance, focal_tolerance) = if truth.name == "north" {
            FOCAL_SCAN_TOLERANCE
        } else {
            FIXED_TOLERANCE
        };
        assert!(
            angle < rotation_tolerance,
            "{} rotation {angle}",
            truth.name
        );
        assert!(offset < center_tolerance, "{} center {offset}", truth.name);
        // Fixed intrinsics are held exactly (tolerance 0 means bit-equal focal length).
        assert!(focal <= focal_tolerance, "{} focal {focal}", truth.name);
        let covariance = camera.get("covariance")?;
        let parameters = covariance.get("parameters")?.texts()?;
        assert!(parameters.contains(&"rotation_x") && parameters.contains(&"translation_z"));
        assert_eq!(
            parameters.contains(&"focal"),
            truth.name == "north",
            "only the focal-scan camera refines its focal length"
        );
        let matrix = floats(covariance.get("matrix_row_major")?)?;
        assert_eq!(matrix.len(), parameters.len() * parameters.len());
        assert_eq!(
            camera.get("seed_mode")?.text()?,
            if truth.name == "north" {
                "focal_scan"
            } else {
                "fixed_intrinsics"
            }
        );
    }

    // Corroboration: the calibration versus the true --pose values, both with the scene mesh
    // that is the calibration's world frame.
    let root = directory.root();
    let recorded = recordings(&directory)?;
    let mesh = site.twin.to_str().ok_or("UTF-8 path")?.to_owned();
    let calibration_path = first_out.to_str().ok_or("UTF-8 path")?.to_owned();
    let source = source_scene();
    let mesh_args = [
        "--scene-mesh",
        mesh.as_str(),
        "--scene-mesh-digest",
        site.twin_digest.as_str(),
        "--scene-source-digest",
        source.as_str(),
    ];
    let mut posed_args = vec!["--pose", EAST_POSE, "--pose", WEST_POSE];
    posed_args.extend_from_slice(&mesh_args);
    let mut calibrated_args = vec![
        "--calibration",
        calibration_path.as_str(),
        "--calibration-digest",
        digest.as_str(),
    ];
    calibrated_args.extend_from_slice(&mesh_args);
    let posed = report(&corroborate(&root, &recorded, &posed_args)?)?;
    let calibrated_output = corroborate(&root, &recorded, &calibrated_args)?;
    let calibrated = report(&calibrated_output)?;
    let expected = visibilities(&posed)?;
    let actual = visibilities(&calibrated)?;
    assert_eq!(expected.len(), 6, "three zones for each of two cameras");
    assert_eq!(actual, expected, "identical ground-zone visibility");
    // The comparison is not vacuous: the zones differ in state and cause.
    for (zone, visibility) in &actual {
        assert_eq!(visibility.get("camera_model")?.text()?, "calibrated_pose");
        let (state, cause) = match zone.as_str() {
            "near" => ("observable", Json::Null),
            "door" => ("not_observable", Json::Text("occluded".to_owned())),
            _ => ("not_observable", Json::Text("outside_frustum".to_owned())),
        };
        assert_eq!(visibility.get("state")?.text()?, state, "{zone}");
        assert_eq!(visibility.get("cause")?, &cause, "{zone}");
    }
    assert_eq!(
        provenance_sources(&posed)?,
        vec![
            ("east".to_owned(), "owner_pose_argument".to_owned()),
            ("west".to_owned(), "owner_pose_argument".to_owned()),
        ]
    );
    assert_eq!(
        provenance_sources(&calibrated)?,
        vec![
            ("east".to_owned(), "site_calibration".to_owned()),
            ("west".to_owned(), "site_calibration".to_owned()),
        ]
    );
    for entry in calibrated.get("pose_provenance")?.items()? {
        assert_eq!(entry.get("calibration_digest")?.text()?, digest);
    }
    // Deterministic, and the calibration travels with the exact coverage approval rerun.
    let again = report(&corroborate(&root, &recorded, &calibrated_args)?)?;
    assert_eq!(again, calibrated);
    let approval = calibrated
        .path(&["coverage", "approval_digest"])?
        .text()?
        .to_owned();
    let mut retain_args = calibrated_args.clone();
    retain_args.extend_from_slice(&["--retain-coverage", approval.as_str()]);
    let retained = report(&corroborate(&root, &recorded, &retain_args)?)?;
    assert_eq!(
        retained.path(&["coverage", "coverage_status"])?.text()?,
        "retained"
    );
    Ok(())
}

#[test]
fn calibration_refusals_are_typed_and_write_nothing() -> TestResult {
    let directory = OwnedDirectory::new("refusals")?;
    let site = build_site(&directory, Variant::Complete)?;
    let out = directory.0.join("refused.fsscal");

    // Only two landmarks declare a survey error within 0.01: two control points.
    let few = calibrate(&site, &out, &["--control-max-error", "0.01"])?;
    assert!(!few.status.success());
    assert_eq!(refusal(&few), "ERR-SITE-CALIBRATION-CONTROL-POINTS-001");
    assert!(String::from_utf8_lossy(&few.stderr).contains("2 atlas control point(s)"));
    assert!(few.stdout.is_empty());
    assert!(!out.exists(), "a refused calibration writes nothing");

    let wrong_atlas = Site {
        atlas_digest: digest_text("another atlas"),
        twin: site.twin.clone(),
        twin_digest: site.twin_digest.clone(),
        atlas: site.atlas.clone(),
        provenance: site.provenance.clone(),
        observations: site.observations.clone(),
    };
    let refused = calibrate(&wrong_atlas, &out, &[])?;
    assert_eq!(refusal(&refused), "ERR-SITE-CALIBRATION-BASIS-001");
    assert!(!out.exists());

    let disconnected_dir = OwnedDirectory::new("disconnected")?;
    let disconnected = build_site(&disconnected_dir, Variant::NorthWithoutTies)?;
    let output = calibrate(&disconnected, &out, &[])?;
    assert_eq!(refusal(&output), "ERR-SITE-CALIBRATION-DISCONNECTED-001");
    assert!(String::from_utf8_lossy(&output.stderr).contains("camera north"));
    assert!(!out.exists());

    let unlocalized_dir = OwnedDirectory::new("unlocalized")?;
    let unlocalized = build_site(&unlocalized_dir, Variant::WestFiveFeatures)?;
    let output = calibrate(&unlocalized, &out, &[])?;
    assert_eq!(
        refusal(&output),
        "ERR-SITE-CALIBRATION-LOCALIZATION-FAILED-001"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("camera west"));
    assert!(!out.exists());

    // An existing output is never overwritten.
    fs::write(&out, b"owner file")?;
    let output = calibrate(&site, &out, &[])?;
    assert!(!output.status.success());
    assert_eq!(fs::read(&out)?, b"owner file");
    Ok(())
}

#[test]
fn corroboration_refuses_tampered_foreign_distorted_and_doubly_posed_calibrations() -> TestResult {
    let directory = OwnedDirectory::new("consumer")?;
    let site = build_site(&directory, Variant::Complete)?;
    let calibration = directory.0.join("site.fsscal");
    let made = calibrate(&site, &calibration, &[])?;
    success(&made);
    let bytes = fs::read(&calibration)?;
    let digest = Json::parse(String::from_utf8(made.stdout.clone())?.trim_end())?
        .get("calibration_digest")?
        .text()?
        .to_owned();
    let root = directory.root();
    let recorded = recordings(&directory)?;
    let source = source_scene();
    let run = |path: &Path, pinned: &str, extra: &[&str]| -> TestResult<Output> {
        let mut args = vec![
            "--calibration",
            path.to_str().ok_or("UTF-8 path")?,
            "--calibration-digest",
            pinned,
        ];
        args.extend_from_slice(extra);
        corroborate(&root, &recorded, &args)
    };
    let refused = |output: &Output, id: &str| {
        assert!(!output.status.success(), "{id}");
        assert!(output.stdout.is_empty(), "{id}");
        assert_eq!(refusal(output), id);
    };

    // Any changed byte is refused under the pinned digest.
    for index in [20, bytes.len() / 2, bytes.len() - 1] {
        let mut tampered = bytes.clone();
        tampered[index] ^= 0x01;
        let path = directory.0.join(format!("tampered-{index}.fsscal"));
        fs::write(&path, &tampered)?;
        refused(
            &run(&path, &digest, &[])?,
            "ERR-SITE-CALIBRATION-DIGEST-001",
        );
    }
    // The genuine file under another pin.
    refused(
        &run(&calibration, &digest_text("another calibration"), &[])?,
        "ERR-SITE-CALIBRATION-DIGEST-001",
    );
    // A camera posed by both sources.
    refused(
        &run(&calibration, &digest, &["--pose", EAST_POSE])?,
        "ERR-CORROBORATE-POSE-SOURCE-CONFLICT-001",
    );
    // A scene mesh other than the calibration's world frame.
    let open = twin_package(false);
    let open_path = directory.0.join("open.fsstwin");
    fs::write(&open_path, &open)?;
    let open_digest = ContentDigest::sha256(&open).to_text();
    refused(
        &run(
            &calibration,
            &digest,
            &[
                "--scene-mesh",
                open_path.to_str().ok_or("UTF-8 path")?,
                "--scene-mesh-digest",
                &open_digest,
                "--scene-source-digest",
                &source,
            ],
        )?,
        "ERR-SITE-CALIBRATION-FRAME-MISMATCH-001",
    );
    // A validly encoded calibration whose east camera carries radial distortion.
    let (mut record, _) = SiteCalibration::decode(&bytes, None)?;
    for camera in &mut record.cameras {
        if camera.name == "east" {
            camera.distortion = [-0.02, 0.0];
        }
    }
    let distorted_path = directory.0.join("distorted.fsscal");
    fs::write(&distorted_path, record.encode()?)?;
    refused(
        &run(&distorted_path, &record.digest()?.to_text(), &[])?,
        "ERR-SITE-CALIBRATION-DISTORTED-001",
    );
    // The pin is not optional.
    let unpinned = corroborate(
        &root,
        &recorded,
        &["--calibration", calibration.to_str().ok_or("UTF-8 path")?],
    )?;
    assert!(!unpinned.status.success());
    assert!(String::from_utf8_lossy(&unpinned.stderr).contains("go together"));
    // Nothing above published or retained anything: the genuine calibration still proposes.
    let fine = report(&run(&calibration, &digest, &[])?)?;
    assert_eq!(
        fine.path(&["coverage", "coverage_status"])?.text()?,
        "proposed"
    );
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Retained pose provenance and owner-asserted camera generations (fss-x8j0v follow-up).
// ---------------------------------------------------------------------------------------------

/// A calibration of the complete site with two imported recordings.
struct Calibrated {
    directory: OwnedDirectory,
    site: Site,
    path: String,
    digest: String,
    recorded: [String; 2],
}

fn calibrated(name: &str) -> TestResult<Calibrated> {
    let directory = OwnedDirectory::new(name)?;
    let site = build_site(&directory, Variant::Complete)?;
    let out = directory.0.join("site.fsscal");
    let made = calibrate(&site, &out, &[])?;
    success(&made);
    let digest = Json::parse(String::from_utf8(made.stdout.clone())?.trim_end())?
        .get("calibration_digest")?
        .text()?
        .to_owned();
    let recorded = recordings(&directory)?;
    Ok(Calibrated {
        path: out.to_str().ok_or("UTF-8 path")?.to_owned(),
        directory,
        site,
        digest,
        recorded,
    })
}

impl Calibrated {
    /// Corroborates with the pinned calibration and its twin as the scene mesh.
    fn run(&self, extra: &[&str]) -> TestResult<Output> {
        let mesh = self.site.twin.to_str().ok_or("UTF-8 path")?;
        let source = source_scene();
        let mut args = vec![
            "--calibration",
            self.path.as_str(),
            "--calibration-digest",
            self.digest.as_str(),
            "--scene-mesh",
            mesh,
            "--scene-mesh-digest",
            self.site.twin_digest.as_str(),
            "--scene-source-digest",
            source.as_str(),
        ];
        args.extend_from_slice(extra);
        corroborate(&self.directory.root(), &self.recorded, &args)
    }

    /// A cold, read-only reopen of the deployment from disk.
    fn snapshot(&self) -> TestResult<fss_reference::agent_orient::DeploymentSnapshot> {
        Ok(fss_reference::agent_orient::read_deployment(
            &self.directory.root(),
            &fss_reference::agent_orient::OrientLimits::default(),
        )?)
    }
}

/// `pose_provenance` of every coverage record in the report, in plan order.
fn record_provenance(report: &Json) -> TestResult<Vec<Json>> {
    report
        .path(&["coverage", "records"])?
        .items()?
        .iter()
        .map(|record| Ok(record.get("pose_provenance")?.clone()))
        .collect()
}

#[test]
fn calibrated_coverage_retains_the_calibration_digest_and_generations_and_reopens_cold()
-> TestResult {
    use fss_reference::ingest::recorded_coverage::{GenerationCurrency, PoseProvenance};

    let fixture = calibrated("provenance")?;
    let pinned = ContentDigest::parse(&fixture.digest)?;
    // East's generation is asserted current by the owner; west's is not asserted.
    let asserted = ["--camera-generation", "east:1:1"];
    let proposal = report(&fixture.run(&asserted)?)?;
    // Deterministic: the same inputs give the same report.
    assert_eq!(report(&fixture.run(&asserted)?)?, proposal);
    let bound = record_provenance(&proposal)?;
    assert_eq!(bound.len(), 2);
    for (entry, (handle, currency)) in bound.iter().zip([
        (21_u64, "owner_asserted_not_observed"),
        (22, "unasserted_unknown"),
    ]) {
        assert_eq!(entry.get("source")?.text()?, "site_calibration");
        assert_eq!(entry.get("calibration_digest")?.text()?, fixture.digest);
        assert_eq!(entry.get("camera_handle")?.number()?, handle);
        assert_eq!(entry.get("intrinsics_generation")?.number()?, 1);
        assert_eq!(entry.get("extrinsics_generation")?.number()?, 1);
        assert_eq!(entry.get("generation_currency")?.text()?, currency);
        assert_eq!(
            entry.get("claim")?.text()?,
            "candidate_calibration_not_a_certificate"
        );
    }
    let stdout_currency: Vec<String> = proposal
        .get("pose_provenance")?
        .items()?
        .iter()
        .map(|entry| Ok(entry.get("generation_currency")?.text()?.to_owned()))
        .collect::<TestResult<_>>()?;
    assert_eq!(
        stdout_currency,
        ["owner_asserted_not_observed", "unasserted_unknown"]
    );
    // The assertion is part of the analysis: without it the proposal differs.
    let unasserted = report(&fixture.run(&[])?)?;
    assert_ne!(
        unasserted.path(&["coverage", "approval_digest"])?,
        proposal.path(&["coverage", "approval_digest"])?
    );

    // Retain exactly the proposal, then reopen the deployment cold from disk.
    let before = fixture.snapshot()?;
    assert!(before.coverage.is_empty());
    let approval = proposal
        .path(&["coverage", "approval_digest"])?
        .text()?
        .to_owned();
    let mut retain = asserted.to_vec();
    retain.extend_from_slice(&["--retain-coverage", approval.as_str()]);
    let retained = report(&fixture.run(&retain)?)?;
    assert_eq!(
        retained.path(&["coverage", "coverage_status"])?.text()?,
        "retained"
    );
    let snapshot = fixture.snapshot()?;
    assert_eq!(snapshot.batch_count, before.batch_count + 1);
    assert_eq!(snapshot.coverage.len(), 2);
    let expected = [
        (21, GenerationCurrency::OwnerAsserted),
        (22, GenerationCurrency::Unasserted),
    ];
    let proposed_digests: Vec<String> = proposal
        .path(&["coverage", "records"])?
        .items()?
        .iter()
        .map(|record| Ok(record.get("record_digest")?.text()?.to_owned()))
        .collect::<TestResult<_>>()?;
    // Retained records are listed in ledger order, not plan order: match by payload digest.
    for ((handle, currency), digest) in expected.into_iter().zip(&proposed_digests) {
        // Exactly the proposed bytes, decoded and validated from the spool.
        let retained = snapshot
            .coverage
            .iter()
            .find(|retained| retained.payload_digest.to_text() == *digest)
            .ok_or("a proposed record was not retained")?;
        assert_eq!(
            retained.record.pose_provenance,
            Some(PoseProvenance::SiteCalibration {
                calibration_digest: pinned,
                camera_handle: handle,
                intrinsics_generation: 1,
                extrinsics_generation: 1,
                currency,
            })
        );
    }

    // Orient reads the same records and names the pose source in the posed zone cells.
    let orient = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["orient", "--json", "--root"])
        .arg(fixture.directory.root())
        .args(["--view", "brief"])
        .output()?;
    success(&orient);
    let text = String::from_utf8(orient.stdout)?;
    assert!(
        text.contains(&format!(
            "Pose source: site calibration {} camera 21 intrinsics generation 1 extrinsics \
             generation 1, generation currency owner_asserted_not_observed",
            fixture.digest
        )),
        "{text}"
    );
    assert!(
        text.contains(
            "camera 22 intrinsics generation 1 extrinsics generation 1, generation \
                       currency unasserted_unknown"
        ),
        "{text}"
    );
    Ok(())
}

#[test]
fn owner_pose_arguments_bind_explicit_owner_provenance() -> TestResult {
    use fss_reference::ingest::recorded_coverage::PoseProvenance;

    let fixture = calibrated("owner-pose")?;
    let mesh = fixture.site.twin.to_str().ok_or("UTF-8 path")?;
    let source = source_scene();
    let args = [
        "--pose",
        EAST_POSE,
        "--pose",
        WEST_POSE,
        "--scene-mesh",
        mesh,
        "--scene-mesh-digest",
        fixture.site.twin_digest.as_str(),
        "--scene-source-digest",
        source.as_str(),
    ];
    let root = fixture.directory.root();
    let posed = report(&corroborate(&root, &fixture.recorded, &args)?)?;
    for entry in record_provenance(&posed)? {
        assert_eq!(entry.get("source")?.text()?, "owner_pose_argument");
        assert_eq!(
            entry.get("claim")?.text()?,
            "owner_asserted_pose_not_a_certificate"
        );
        assert!(entry.get("calibration_digest").is_err());
    }
    // The same pose values from the calibration are another provenance: other records.
    let calibrated = report(&fixture.run(&[])?)?;
    assert_ne!(
        posed.path(&["coverage", "approval_digest"])?,
        calibrated.path(&["coverage", "approval_digest"])?
    );
    let approval = posed
        .path(&["coverage", "approval_digest"])?
        .text()?
        .to_owned();
    let mut retain = args.to_vec();
    retain.extend_from_slice(&["--retain-coverage", approval.as_str()]);
    let retained = report(&corroborate(&root, &fixture.recorded, &retain)?)?;
    assert_eq!(
        retained.path(&["coverage", "coverage_status"])?.text()?,
        "retained"
    );
    let snapshot = fixture.snapshot()?;
    assert_eq!(snapshot.coverage.len(), 2);
    for record in &snapshot.coverage {
        assert_eq!(
            record.record.pose_provenance,
            Some(PoseProvenance::OwnerPoseArgument)
        );
    }
    // Cameras without a pose bind nothing: their records carry no pose_provenance.
    let homography_only = report(&corroborate(&root, &fixture.recorded, &[])?)?;
    for record in homography_only.path(&["coverage", "records"])?.items()? {
        assert!(record.get("pose_provenance").is_err());
    }
    Ok(())
}

#[test]
fn a_stale_camera_generation_is_refused_before_anything_is_appended() -> TestResult {
    let fixture = calibrated("stale-generation")?;
    // A proposal and its exact approval, so a refusal cannot hide behind a missing approval.
    let proposal = report(&fixture.run(&["--camera-generation", "east:1:1"])?)?;
    let approval = proposal
        .path(&["coverage", "approval_digest"])?
        .text()?
        .to_owned();
    let before = fixture.snapshot()?;
    for (stale, message) in [
        ("east:1:2", "extrinsics 2"),
        ("east:2:1", "intrinsics 2"),
        ("west:7:9", "camera west"),
    ] {
        let output = fixture.run(&[
            "--camera-generation",
            stale,
            "--retain-coverage",
            approval.as_str(),
        ])?;
        assert!(!output.status.success(), "{stale}");
        assert!(output.stdout.is_empty(), "{stale}");
        assert_eq!(
            refusal(&output),
            "ERR-SITE-CALIBRATION-GENERATION-STALE-001",
            "{stale}"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{stale}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let after = fixture.snapshot()?;
        assert_eq!(after.batch_count, before.batch_count, "{stale}");
        assert_eq!(after.ledger_root, before.ledger_root, "{stale}");
        assert!(after.coverage.is_empty(), "{stale}");
    }
    // Usage refusals: no calibration, a name that is no camera, zero or malformed generations,
    // and a duplicate assertion.
    let root = fixture.directory.root();
    let without = corroborate(
        &root,
        &fixture.recorded,
        &["--camera-generation", "east:1:1"],
    )?;
    assert!(!without.status.success());
    assert!(String::from_utf8_lossy(&without.stderr).contains("requires --calibration"));
    for bad in [
        vec!["--camera-generation", "north:1:1"],
        vec!["--camera-generation", "east:0:1"],
        vec!["--camera-generation", "east:1"],
        vec![
            "--camera-generation",
            "east:1:1",
            "--camera-generation",
            "east:1:1",
        ],
    ] {
        let output = fixture.run(&bad)?;
        assert!(!output.status.success(), "{bad:?}");
        assert!(output.stdout.is_empty(), "{bad:?}");
    }
    let after = fixture.snapshot()?;
    assert_eq!(after.batch_count, before.batch_count);
    assert_eq!(after.ledger_root, before.ledger_root);
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Retained calibration authority: `fss-event calibration adopt` and adoption currency.
// ---------------------------------------------------------------------------------------------

const EAST_BIND: &str = "east:sensor:east";
const WEST_BIND: &str = "west:sensor:west";

/// `fss-event calibration <operation> --root ROOT --site SITE ARGS...`.
fn calibration(root: &Path, operation: &str, args: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["calibration", operation, "--root"])
        .arg(root)
        .args(["--site", SITE])
        .args(args)
        .output()?)
}

impl Calibrated {
    /// `calibration adopt` of `path`/`digest` with the given bindings and extra arguments.
    fn adopt(&self, path: &str, digest: &str, extra: &[&str]) -> TestResult<Output> {
        let mut args = vec!["--calibration", path, "--calibration-digest", digest];
        args.extend_from_slice(extra);
        calibration(&self.directory.root(), "adopt", &args)
    }

    /// Previews then approves the adoption; returns the retained report.
    fn adopt_approved(&self, path: &str, digest: &str, binds: &[&str]) -> TestResult<Json> {
        let preview = report(&self.adopt(path, digest, binds)?)?;
        assert_eq!(preview.get("status")?.text()?, "proposed");
        let approval = preview.get("approval_digest")?.text()?.to_owned();
        let mut approved = binds.to_vec();
        approved.extend_from_slice(&["--approve", approval.as_str()]);
        let retained = report(&self.adopt(path, digest, &approved)?)?;
        assert_eq!(retained.get("status")?.text()?, "retained");
        Ok(retained)
    }

    /// Corroborates with another pinned calibration of the same twin.
    fn run_with(&self, path: &str, digest: &str, extra: &[&str]) -> TestResult<Output> {
        let mesh = self.site.twin.to_str().ok_or("UTF-8 path")?;
        let source = source_scene();
        let mut args = vec![
            "--calibration",
            path,
            "--calibration-digest",
            digest,
            "--scene-mesh",
            mesh,
            "--scene-mesh-digest",
            self.site.twin_digest.as_str(),
            "--scene-source-digest",
            source.as_str(),
        ];
        args.extend_from_slice(extra);
        corroborate(&self.directory.root(), &self.recorded, &args)
    }

    /// A second calibration of the same site in which east's extrinsics generation is 2.
    fn recalibrate_east_extrinsics(&self) -> TestResult<(String, String)> {
        let (_, east) = self
            .site
            .observations
            .iter()
            .find(|(name, _)| *name == "east")
            .ok_or("east observations")?;
        let text = fs::read_to_string(east)?;
        assert!(text.contains("camera 21 1 1\n"));
        fs::write(east, text.replace("camera 21 1 1\n", "camera 21 1 2\n"))?;
        let out = self.directory.0.join("site-v2.fsscal");
        let made = calibrate(&self.site, &out, &[])?;
        success(&made);
        let digest = Json::parse(String::from_utf8(made.stdout)?.trim_end())?
            .get("calibration_digest")?
            .text()?
            .to_owned();
        Ok((out.to_str().ok_or("UTF-8 path")?.to_owned(), digest))
    }
}

/// `(camera_handle, receipt_digest)` of every camera of an adoption report.
fn adopted_receipts(adoption: &Json) -> TestResult<Vec<(u64, String)>> {
    adoption
        .get("cameras")?
        .items()?
        .iter()
        .map(|camera| {
            let receipt = camera.get("receipt")?;
            Ok((
                receipt.get("camera_handle")?.number()?,
                receipt.get("receipt_digest")?.text()?.to_owned(),
            ))
        })
        .collect()
}

#[test]
fn an_adopted_calibration_is_recorded_adopted_current_and_reopens_cold() -> TestResult {
    use fss_reference::ingest::recorded_coverage::{GenerationCurrency, PoseProvenance};

    let fixture = calibrated("adopt-current")?;
    let root = fixture.directory.root();
    let binds = ["--bind", EAST_BIND, "--bind", WEST_BIND];
    let before = fixture.snapshot()?;
    // The preview writes nothing and is deterministic.
    let preview = report(&fixture.adopt(&fixture.path, &fixture.digest, &binds)?)?;
    assert_eq!(
        report(&fixture.adopt(&fixture.path, &fixture.digest, &binds)?)?,
        preview
    );
    assert_eq!(fixture.snapshot()?.batch_count, before.batch_count);
    assert_eq!(fixture.snapshot()?.ledger_root, before.ledger_root);
    assert!(
        preview
            .get("approve_command")?
            .text()?
            .ends_with(preview.get("approval_digest")?.text()?)
    );
    assert_eq!(
        preview.get("claim")?.text()?,
        "owner_adoption_not_a_physical_observation"
    );
    for (camera, (handle, sensor)) in preview
        .get("cameras")?
        .items()?
        .iter()
        .zip([(21_u64, "sensor:east"), (22, "sensor:west")])
    {
        let receipt = camera.get("receipt")?;
        assert_eq!(receipt.get("camera_handle")?.number()?, handle);
        assert_eq!(receipt.get("sensor_id")?.text()?, sensor);
        assert_eq!(receipt.get("adoption")?.number()?, 1);
        assert_eq!(receipt.get("calibration_digest")?.text()?, fixture.digest);
        assert_eq!(
            receipt.get("twin_package")?.text()?,
            fixture.site.twin_digest
        );
        assert_eq!(receipt.get("intrinsics_generation")?.number()?, 1);
        assert_eq!(receipt.get("extrinsics_generation")?.number()?, 1);
        assert_eq!(receipt.get("supersedes")?, &Json::Null);
    }

    let adoption = fixture.adopt_approved(&fixture.path, &fixture.digest, &binds)?;
    let receipts = adopted_receipts(&adoption)?;
    let adopted = fixture.snapshot()?;
    assert_eq!(adopted.batch_count, before.batch_count + 1);
    assert_eq!(
        adopted.family_counts.get("twin_localization_receipt"),
        Some(&2)
    );
    // An exact rerun of the approval writes nothing.
    let approval = preview.get("approval_digest")?.text()?.to_owned();
    let mut again = binds.to_vec();
    again.extend_from_slice(&["--approve", approval.as_str()]);
    let rerun = report(&fixture.adopt(&fixture.path, &fixture.digest, &again)?)?;
    assert_eq!(rerun.get("status")?.text()?, "already_current");
    assert_eq!(fixture.snapshot()?.ledger_root, adopted.ledger_root);

    // Corroborate: both calibrated cameras are adopted_current, bound to their receipts. An owner
    // assertion of the same generation does not change it: the retained adoption decides.
    let proposal = report(&fixture.run(&[])?)?;
    assert_eq!(report(&fixture.run(&[])?)?, proposal);
    assert_eq!(
        report(&fixture.run(&["--camera-generation", "east:1:1"])?)?
            .path(&["coverage", "approval_digest"])?,
        proposal.path(&["coverage", "approval_digest"])?
    );
    for (entry, (handle, receipt)) in record_provenance(&proposal)?.iter().zip(&receipts) {
        assert_eq!(entry.get("camera_handle")?.number()?, *handle);
        assert_eq!(entry.get("generation_currency")?.text()?, "adopted_current");
        assert_eq!(entry.get("adoption_receipt")?.text()?, receipt);
        assert_eq!(
            entry.get("currency_claim")?.text()?,
            "retained_owner_adoption_not_a_physical_observation"
        );
    }
    for (entry, (_, receipt)) in proposal
        .get("pose_provenance")?
        .items()?
        .iter()
        .zip(&receipts)
    {
        assert_eq!(entry.get("generation_currency")?.text()?, "adopted_current");
        assert_eq!(entry.get("adoption_receipt")?.text()?, receipt);
    }

    // Retain the coverage and reopen the deployment cold.
    let approval = proposal
        .path(&["coverage", "approval_digest"])?
        .text()?
        .to_owned();
    let retained = report(&fixture.run(&["--retain-coverage", approval.as_str()])?)?;
    assert_eq!(
        retained.path(&["coverage", "coverage_status"])?.text()?,
        "retained"
    );
    let snapshot = fixture.snapshot()?;
    assert_eq!(snapshot.coverage.len(), 2);
    let pinned = ContentDigest::parse(&fixture.digest)?;
    for (handle, receipt) in &receipts {
        let receipt = ContentDigest::parse(receipt)?;
        let expected = PoseProvenance::SiteCalibration {
            calibration_digest: pinned,
            camera_handle: *handle,
            intrinsics_generation: 1,
            extrinsics_generation: 1,
            currency: GenerationCurrency::AdoptedCurrent { receipt },
        };
        assert!(
            snapshot
                .coverage
                .iter()
                .any(|record| record.record.pose_provenance == Some(expected)),
            "camera {handle}"
        );
    }

    // Orient names the adoption in the posed zone cells; `calibration show` lists both cameras.
    let orient = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["orient", "--json", "--root"])
        .arg(&root)
        .args(["--view", "brief"])
        .output()?;
    success(&orient);
    let text = String::from_utf8(orient.stdout)?;
    assert!(
        text.contains(&format!(
            "Pose source: site calibration {} camera 21 intrinsics generation 1 extrinsics \
             generation 1, generation currency adopted_current (retained owner adoption, not \
             observed)",
            fixture.digest
        )),
        "{text}"
    );
    let show = report(&calibration(&root, "show", &[])?)?;
    assert_eq!(
        show.get("format")?.text()?,
        "fss.calibration_adoption_state.v1"
    );
    let shown: Vec<String> = show
        .get("cameras")?
        .items()?
        .iter()
        .map(|camera| {
            Ok(camera
                .path(&["current", "receipt_digest"])?
                .text()?
                .to_owned())
        })
        .collect::<TestResult<_>>()?;
    assert_eq!(
        shown,
        receipts.iter().map(|(_, r)| r.clone()).collect::<Vec<_>>()
    );
    Ok(())
}

#[test]
fn a_superseded_calibration_is_refused_as_stale_before_anything_is_appended() -> TestResult {
    let fixture = calibrated("adopt-stale")?;
    let binds = ["--bind", EAST_BIND, "--bind", WEST_BIND];
    let v1 = fixture.adopt_approved(&fixture.path, &fixture.digest, &binds)?;
    let v1_receipts = adopted_receipts(&v1)?;
    // A valid v1 coverage approval, so the refusal cannot hide behind a missing approval.
    let proposal = report(&fixture.run(&[])?)?;
    let approval = proposal
        .path(&["coverage", "approval_digest"])?
        .text()?
        .to_owned();

    // v2: the same site with east's extrinsics generation 2; adopt it for both cameras.
    let (v2_path, v2_digest) = fixture.recalibrate_east_extrinsics()?;
    assert_ne!(v2_digest, fixture.digest);
    let v2 = fixture.adopt_approved(&v2_path, &v2_digest, &binds)?;
    for (camera, (_, prior)) in v2.get("cameras")?.items()?.iter().zip(&v1_receipts) {
        assert_eq!(camera.path(&["receipt", "adoption"])?.number()?, 2);
        assert_eq!(camera.path(&["receipt", "supersedes"])?.text()?, prior);
        assert_eq!(camera.get("supersedes_current")?.text()?, prior);
    }
    assert_eq!(
        v2.get("cameras")?.items()?[0]
            .path(&["receipt", "extrinsics_generation"])?
            .number()?,
        2
    );

    // Corroborating with v1 is refused as stale, with or without an owner assertion and even
    // with a valid --retain-coverage approval; nothing is appended.
    let before = fixture.snapshot()?;
    for extra in [
        vec!["--retain-coverage", approval.as_str()],
        vec![
            "--camera-generation",
            "east:1:1",
            "--retain-coverage",
            approval.as_str(),
        ],
    ] {
        let output = fixture.run(&extra)?;
        assert!(!output.status.success(), "{extra:?}");
        assert!(output.stdout.is_empty(), "{extra:?}");
        assert_eq!(
            refusal(&output),
            "ERR-CALIBRATION-ADOPTION-STALE-001",
            "{extra:?}"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("camera east"));
        let after = fixture.snapshot()?;
        assert_eq!(after.batch_count, before.batch_count);
        assert_eq!(after.ledger_root, before.ledger_root);
        assert!(after.coverage.is_empty());
    }
    // v2 is current for both cameras.
    let current = report(&fixture.run_with(&v2_path, &v2_digest, &[])?)?;
    for entry in record_provenance(&current)? {
        assert_eq!(entry.get("generation_currency")?.text()?, "adopted_current");
        assert_eq!(entry.get("calibration_digest")?.text()?, v2_digest);
    }
    // Monotone: v1 cannot be adopted again; history keeps both receipts, linked.
    let regression = fixture.adopt(&fixture.path, &fixture.digest, &binds)?;
    assert_eq!(
        refusal(&regression),
        "ERR-CALIBRATION-ADOPTION-REGRESSION-001"
    );
    let show = report(&calibration(&fixture.directory.root(), "show", &[])?)?;
    let east = &show.get("cameras")?.items()?[0];
    let history = east.get("history")?.items()?;
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].get("receipt_digest")?.text()?, v1_receipts[0].1);
    assert_eq!(history[1].get("supersedes")?.text()?, v1_receipts[0].1);
    assert_eq!(fixture.snapshot()?.ledger_root, before.ledger_root);
    Ok(())
}

#[test]
fn stale_tampered_and_invalid_adoption_approvals_are_refused_and_write_nothing() -> TestResult {
    let fixture = calibrated("adopt-approval")?;
    let east = ["--bind", EAST_BIND];
    let first = report(&fixture.adopt(&fixture.path, &fixture.digest, &east)?)?;
    let stale = first.get("approval_digest")?.text()?.to_owned();
    fixture.adopt_approved(&fixture.path, &fixture.digest, &east)?;
    let (v2_path, v2_digest) = fixture.recalibrate_east_extrinsics()?;
    let second = report(&fixture.adopt(&v2_path, &v2_digest, &east)?)?;
    let fresh = second.get("approval_digest")?.text()?.to_owned();
    assert_ne!(fresh, stale);
    // Tampered: the fresh approval with its last hex digit changed.
    let last = fresh.chars().last().ok_or("empty digest")?;
    let tampered = format!(
        "{}{}",
        &fresh[..fresh.len() - 1],
        if last == '0' { '1' } else { '0' }
    );
    let before = fixture.snapshot()?;
    for approval in [stale.as_str(), tampered.as_str()] {
        let output = fixture.adopt(
            &v2_path,
            &v2_digest,
            &["--bind", EAST_BIND, "--approve", approval],
        )?;
        assert!(!output.status.success(), "{approval}");
        assert!(output.stdout.is_empty(), "{approval}");
        assert_eq!(
            refusal(&output),
            "ERR-CALIBRATION-ADOPTION-APPROVAL-STALE-001",
            "{approval}"
        );
    }
    // A wrong calibration pin, an unknown camera, a sensor without retained evidence, and a
    // rebinding of east to west's sensor are typed refusals.
    for (args, id) in [
        (vec!["--bind", EAST_BIND], "ERR-SITE-CALIBRATION-DIGEST-001"),
        (
            vec!["--bind", "south:sensor:east"],
            "ERR-CALIBRATION-ADOPTION-INPUT-001",
        ),
        (
            vec!["--bind", "north:sensor:ghost"],
            "ERR-CALIBRATION-ADOPTION-SENSOR-UNRETAINED-001",
        ),
        (
            vec!["--bind", "east:sensor:west"],
            "ERR-CALIBRATION-ADOPTION-SENSOR-CONFLICT-001",
        ),
    ] {
        let pin = if id == "ERR-SITE-CALIBRATION-DIGEST-001" {
            fixture.digest.as_str()
        } else {
            v2_digest.as_str()
        };
        let output = fixture.adopt(&v2_path, pin, &args)?;
        assert!(!output.status.success(), "{args:?}");
        assert_eq!(refusal(&output), id, "{args:?}");
    }
    // Usage refusals: no binding, a malformed binding, a non-SHA-256 approval.
    for args in [
        vec![],
        vec!["--bind", "east"],
        vec!["--bind", EAST_BIND, "--approve", "not-a-digest"],
    ] {
        let output = fixture.adopt(&v2_path, &v2_digest, &args)?;
        assert!(!output.status.success(), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?}");
    }
    let after = fixture.snapshot()?;
    assert_eq!(after.batch_count, before.batch_count);
    assert_eq!(after.ledger_root, before.ledger_root);
    // The fresh approval still retains exactly the previewed adoption.
    let retained = report(&fixture.adopt(
        &v2_path,
        &v2_digest,
        &["--bind", EAST_BIND, "--approve", fresh.as_str()],
    )?)?;
    assert_eq!(retained.get("status")?.text()?, "retained");
    assert_eq!(fixture.snapshot()?.batch_count, before.batch_count + 1);
    Ok(())
}

#[test]
fn an_adopted_camera_over_another_sensors_recording_is_refused() -> TestResult {
    let fixture = calibrated("adopt-sensor")?;
    // The owner binds each camera to the other camera's sensor.
    fixture.adopt_approved(
        &fixture.path,
        &fixture.digest,
        &["--bind", "east:sensor:west", "--bind", "west:sensor:east"],
    )?;
    let before = fixture.snapshot()?;
    let output = fixture.run(&[])?;
    assert!(!output.status.success());
    assert_eq!(
        refusal(&output),
        "ERR-CALIBRATION-ADOPTION-SENSOR-MISMATCH-001"
    );
    assert_eq!(fixture.snapshot()?.ledger_root, before.ledger_root);
    Ok(())
}

#[test]
fn a_camera_without_an_adoption_keeps_its_owner_asserted_or_unasserted_currency() -> TestResult {
    let fixture = calibrated("adopt-partial")?;
    // Only east is adopted; west keeps the existing behaviour.
    let adoption =
        fixture.adopt_approved(&fixture.path, &fixture.digest, &["--bind", EAST_BIND])?;
    let receipt = adopted_receipts(&adoption)?[0].1.clone();
    for (extra, west) in [
        (vec![], "unasserted_unknown"),
        (
            vec!["--camera-generation", "west:1:1"],
            "owner_asserted_not_observed",
        ),
    ] {
        let proposal = report(&fixture.run(&extra)?)?;
        let entries = record_provenance(&proposal)?;
        assert_eq!(
            entries[0].get("generation_currency")?.text()?,
            "adopted_current"
        );
        assert_eq!(entries[0].get("adoption_receipt")?.text()?, receipt);
        assert_eq!(entries[1].get("generation_currency")?.text()?, west);
        assert!(entries[1].get("adoption_receipt").is_err());
    }
    Ok(())
}
