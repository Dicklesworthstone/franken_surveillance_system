#![forbid(unsafe_code)]
//! Contract tests, through the real binary, for frame input to `fss-event calibrate`
//! (fss-x8j0v follow-up: pixels in).
//!
//! A synthetic but pixel-real site is built in-test. The scene is a textured ground plane
//! (z = 0) with a raised textured deck (z = 50, x 40..80, y 30..60) whose side walls are flat
//! grey; the twin (`FSSTWIN1`) carries both surfaces. Every view is a nadir pinhole camera 100
//! units above the ground with fx = fy = 100 px, so the ground is imaged at one texel per pixel
//! and the deck at one (half-unit) texel per pixel, and each pixel is rendered by casting its
//! ray: deck top, then wall, then ground. Camera centres are integer and yaws are quarter turns,
//! so the renderings of one surface point agree exactly between views wherever the descriptor
//! patch stays on one surface; near the deck edge parallax changes the patches, as it would on
//! a real site.
//!
//! The atlas is built exactly the way the fss-twin `native_localization_contract` builds one
//! from pixels (reference rendering -> `extract_gray` -> one landmark per reference feature at
//! its known world point -> `AtlasBinding`), here with a 320x240 reference rendering of the two
//! surfaces (wall features are skipped), and encoded through `encode_atlas`. Three cameras (east
//! and west with fixed intrinsics, north with a focal scan that has no sample at its true focal
//! length) are rendered at 160x120, encoded as grayscale baseline JPEG (quality 95) with the
//! first-party fixture encoder, and calibrated from the JPEG files alone: the command decodes them, extracts
//! native features, matches them against the atlas descriptors, derives frame-to-frame ties, and
//! refines jointly.
//!
//! Proven: poses are recovered within stated tolerances; the record is `FSSCAL02` binding each
//! JPEG, metadata and luma digest and the decoder/extraction/tie policy; bytes and stdout are
//! identical across runs; a corrupted JPEG and a frame whose size differs from its metadata are
//! typed `ERR-SITE-CALIBRATION-FRAME-DECODE-001` refusals and a frame of unmapped ground is a
//! typed `ERR-SITE-CALIBRATION-LOCALIZATION-FAILED-001` refusal, none of which writes anything.
//!
//! No-Claim: synthetic renderings (exact nadir views, integer shifts, quarter-turn yaws, a
//! noise texture) do not establish calibration accuracy on real site footage.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;
use fss_geometry::{GeometryBasis, PinholeIntrinsics, RigidPose, WorkBudget};
use fss_reference::ingest::site_calibration::{
    CalibrationInput, FramePolicy, SITE_CALIBRATION_MAGIC_V2, SiteCalibration,
};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};
use fss_twin::atlas_archive::{ReferenceProvenance, encode_atlas};
use fss_twin::localization::native::{ExtractionOptions, GrayImage, extract_gray};
use fss_twin::localization::{
    AtlasBinding, AtlasLandmark, AtlasReference, ImageIdentity, LocalizationAtlas,
};
use fss_twin::{ImportExpectation, ImportLimits, import_twin};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

/// Camera height above the ground; also the focal length in pixels (one ground unit per pixel).
const HEIGHT: i64 = 100;
/// Deck top height (imaged at two pixels per unit from every camera).
const DECK_Z: i64 = 50;
/// Deck footprint `[x0, y0, x1, y1)`.
const DECK: [i64; 4] = [40, 30, 80, 60];
/// Flat grey of the deck walls.
const WALL: u8 = 110;

// ---------------------------------------------------------------------------------------------
// Scene and rendering.
// ---------------------------------------------------------------------------------------------

fn splitmix(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Texel value of surface `seed` at texel `(i, j)`.
fn texel(seed: u64, i: i64, j: i64) -> u8 {
    let key = seed ^ (i as u64).wrapping_mul(0x9E37_79B1) ^ (j as u64).wrapping_mul(0x85EB_CA77);
    20 + (splitmix(key) % 180) as u8
}

/// What one pixel's ray hits first.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Hit {
    /// Deck top point (twin feature 0).
    Deck([f64; 3]),
    /// Ground point (twin feature 1).
    Ground([f64; 3]),
    /// A deck side wall.
    Wall,
}

/// A nadir view: centre `(x, y, HEIGHT)`, yaw in quarter turns, principal point at the centre.
#[derive(Clone, Copy, Debug)]
struct View {
    center: [i64; 2],
    quarter_turns: u8,
    size: [u32; 2],
}

impl View {
    fn axes(self) -> (i64, i64) {
        match self.quarter_turns % 4 {
            0 => (1, 0),
            1 => (0, 1),
            2 => (-1, 0),
            _ => (0, -1),
        }
    }

    fn rotation(self) -> [[f64; 3]; 3] {
        let (c, s) = self.axes();
        let (c, s) = (c as f64, s as f64);
        [[c, s, 0.0], [s, -c, 0.0], [0.0, 0.0, -1.0]]
    }

    fn truth(self) -> TestResult<(PinholeIntrinsics, RigidPose)> {
        let [w, h] = self.size;
        Ok((
            PinholeIntrinsics::new(
                w,
                h,
                HEIGHT as f64,
                HEIGHT as f64,
                f64::from(w / 2),
                f64::from(h / 2),
            )?,
            RigidPose::from_center(
                self.rotation(),
                [self.center[0] as f64, self.center[1] as f64, HEIGHT as f64],
            )?,
        ))
    }

    /// Casts pixel `(u, v)`. World direction `(px c + py s, px s - py c, -1)` with
    /// `px = (u + 0.5 - cx) / f`; everything below is exact integer arithmetic in quarter units.
    fn cast(self, u: u32, v: u32) -> (Hit, u8) {
        let (c, s) = self.axes();
        let a = 2 * (i64::from(u) - i64::from(self.size[0] / 2)) + 1;
        let b = 2 * (i64::from(v) - i64::from(self.size[1] / 2)) + 1;
        let (dx, dy) = (a * c + b * s, a * s - b * c);
        let [cx, cy] = self.center;
        // At z = 50 the horizontal offset is (dx, dy) / 4; at z = 0 it is (dx, dy) / 2.
        let (qx, qy) = (4 * cx + dx, 4 * cy + dy);
        let inside = |x: f64, y: f64| {
            x >= DECK[0] as f64 && x < DECK[2] as f64 && y >= DECK[1] as f64 && y < DECK[3] as f64
        };
        if inside(qx as f64 / 4.0, qy as f64 / 4.0) {
            let value = texel(0xDEC4, qx.div_euclid(2), qy.div_euclid(2));
            let world = [qx as f64 / 4.0, qy as f64 / 4.0, DECK_Z as f64];
            return (Hit::Deck(world), value);
        }
        let (gx, gy) = (2 * cx + dx, 2 * cy + dy);
        // The ray between z = 50 and z = 0 crosses the footprint: it meets a wall.
        let (x50, y50) = (qx as f64 / 4.0, qy as f64 / 4.0);
        let (x0, y0) = (gx as f64 / 2.0, gy as f64 / 2.0);
        let crosses = (0..=64).any(|k| {
            let t = f64::from(k) / 64.0;
            inside(x50 + t * (x0 - x50), y50 + t * (y0 - y50))
        });
        if crosses {
            return (Hit::Wall, WALL);
        }
        let value = texel(0x96A3, gx.div_euclid(2), gy.div_euclid(2));
        (Hit::Ground([x0, y0, 0.0]), value)
    }

    fn render(self) -> Vec<u8> {
        let [w, h] = self.size;
        (0..h)
            .flat_map(|v| (0..w).map(move |u| self.cast(u, v).1))
            .collect()
    }
}

const REFERENCE: View = View {
    center: [60, 45],
    quarter_turns: 0,
    size: [320, 240],
};

/// `(name, handle, view)` of the calibrated cameras.
const CAMERAS: [(&str, u64, View); 3] = [
    (
        "east",
        31,
        View {
            center: [50, 40],
            quarter_turns: 0,
            size: [160, 120],
        },
    ),
    (
        "west",
        32,
        View {
            center: [72, 48],
            quarter_turns: 1,
            size: [160, 120],
        },
    ),
    (
        "north",
        33,
        View {
            center: [60, 54],
            quarter_turns: 2,
            size: [160, 120],
        },
    ),
];

/// The camera whose metadata declares a focal scan (85..130 px, 9 logarithmic samples, none of
/// them the true 100 px) instead of fixed intrinsics: its seed focal is wrong and the joint
/// refinement must recover it.
const FOCAL_SCAN_CAMERA: &str = "north";

/// A view of ground the reference never saw.
const UNMAPPED: View = View {
    center: [900, 900],
    quarter_turns: 0,
    size: [160, 120],
};

// ---------------------------------------------------------------------------------------------
// Packages and files.
// ---------------------------------------------------------------------------------------------

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-site-calibration-frames-{name}-{}-{attempt}",
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
}

impl Drop for OwnedDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn text(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u16).to_le_bytes());
    out.extend_from_slice(value.as_bytes());
}

/// `FSSTWIN1` (source scene `01..01`): features `deck` (kind 4) and `ground` (kind 1); the
/// ground quad at z = 0 and the deck box (top and four walls).
fn twin_package() -> Vec<u8> {
    let mut body = vec![1_u8; 32];
    text(&mut body, "test/Z-up");
    text(&mut body, "synthetic");
    body.push(0);
    for value in [0.0_f64, -1.0, -1.0] {
        body.extend_from_slice(&value.to_le_bytes());
    }
    let [x0, y0, x1, y1] = DECK.map(|v| v as f64);
    let z = DECK_Z as f64;
    let vertices: Vec<[f64; 3]> = vec![
        [-200.0, -200.0, 0.0],
        [1200.0, -200.0, 0.0],
        [1200.0, 1200.0, 0.0],
        [-200.0, 1200.0, 0.0],
        [x0, y0, 0.0],
        [x1, y0, 0.0],
        [x1, y1, 0.0],
        [x0, y1, 0.0],
        [x0, y0, z],
        [x1, y0, z],
        [x1, y1, z],
        [x0, y1, z],
    ];
    // Object 0 is the deck, object 1 the ground (objects sort by name).
    let triangles: Vec<[u32; 4]> = vec![
        [0, 1, 2, 1],
        [0, 2, 3, 1],
        [8, 9, 10, 0],
        [8, 10, 11, 0],
        [4, 5, 9, 0],
        [4, 9, 8, 0],
        [5, 6, 10, 0],
        [5, 10, 9, 0],
        [6, 7, 11, 0],
        [6, 11, 10, 0],
        [7, 4, 8, 0],
        [7, 8, 11, 0],
    ];
    for count in [2, 2, vertices.len() as u32, triangles.len() as u32] {
        body.extend_from_slice(&count.to_le_bytes());
    }
    text(&mut body, "deck");
    body.push(4);
    text(&mut body, "ground");
    body.push(1);
    text(&mut body, "deck");
    body.extend_from_slice(&0_u32.to_le_bytes());
    body.extend_from_slice(&[1, 1]);
    text(&mut body, "ground");
    body.extend_from_slice(&1_u32.to_le_bytes());
    body.extend_from_slice(&[1, 1]);
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

fn digest_text(label: &str) -> String {
    ContentDigest::sha256(label.as_bytes()).to_text()
}

fn jpeg(view: View) -> TestResult<Vec<u8>> {
    let [w, h] = view.size;
    Ok(encode_jpeg(
        w,
        h,
        &view.render(),
        &JpegConfig {
            quality: 95,
            subsampling: Subsampling::Grayscale,
            restart_interval: 0,
            custom_markers: Vec::new(),
        },
    )?)
}

fn metadata(name: &str, handle: u64, view: View) -> String {
    let [w, h] = view.size;
    [
        "fss.site_camera_frame.v1".to_owned(),
        format!("# synthetic nadir camera {name}"),
        format!("camera {handle} 1 1"),
        format!("image {w} {h}"),
        format!("exposure {}", digest_text(&format!("exposure {name}"))),
        format!(
            "image-domain {}",
            digest_text(&format!("image domain {w}x{h}"))
        ),
        "interpretation gray".to_owned(),
        if name == FOCAL_SCAN_CAMERA {
            format!("intrinsics focal 85 130 9 1 {} {}", w / 2, h / 2)
        } else {
            format!("intrinsics fixed {HEIGHT} {HEIGHT} {} {}", w / 2, h / 2)
        },
    ]
    .join("\n")
        + "\n"
}

/// Paths and pins of the synthetic site on disk.
struct Site {
    twin: PathBuf,
    twin_digest: String,
    atlas: PathBuf,
    atlas_digest: String,
    provenance: String,
    landmarks: usize,
    /// `(name, jpeg, metadata)` per camera.
    frames: Vec<(String, PathBuf, PathBuf)>,
}

fn build_site(directory: &OwnedDirectory) -> TestResult<Site> {
    let package = twin_package();
    let twin_path = directory.0.join("site.fsstwin");
    fs::write(&twin_path, &package)?;
    let mut budget = WorkBudget::new(1_000_000_000);
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
    // The fss-twin native_localization_contract construction: extract the reference rendering
    // natively and bind every feature to its known world point.
    let pixels = REFERENCE.render();
    let allowed = vec![1_u8; pixels.len()];
    let reference_image = GrayImage::new(
        ImageIdentity {
            exposure: [0xA1; 32],
            pixels: ContentDigest::sha256(&pixels).bytes(),
            image_domain: [0xA3; 32],
            dimensions: REFERENCE.size,
        },
        &pixels,
        &allowed,
        &mut budget,
    )?;
    let reference =
        extract_gray(&reference_image, ExtractionOptions::default(), &mut budget)?.frame;
    let mut landmarks = Vec::new();
    let mut bindings = Vec::new();
    for feature in reference.features() {
        let (hit, _) = REFERENCE.cast(feature.pixel[0] as u32, feature.pixel[1] as u32);
        let (world, twin_feature) = match hit {
            Hit::Deck(world) => (world, 0),
            Hit::Ground(world) => (world, 1),
            Hit::Wall => continue,
        };
        let id = landmarks.len() as u64 + 1;
        landmarks.push(AtlasLandmark {
            id,
            physical_group: id,
            feature: twin_feature,
            world,
            evidence: [7; 32],
            error: None,
        });
        bindings.push(AtlasBinding {
            landmark: id,
            reference: 1,
            image_feature: feature.id,
        });
    }
    let landmark_count = landmarks.len();
    let atlas = LocalizationAtlas::new(
        &twin,
        landmarks,
        vec![AtlasReference {
            id: 1,
            frame: reference,
        }],
        bindings,
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
    let mut frames = Vec::new();
    for (name, handle, view) in CAMERAS {
        frames.push(write_frame(directory, name, handle, view)?);
    }
    Ok(Site {
        twin: twin_path,
        twin_digest: ContentDigest::sha256(&package).to_text(),
        atlas: atlas_path,
        atlas_digest: ContentDigest::sha256(&atlas_bytes).to_text(),
        provenance: format!("sha256:{}", "b1".repeat(32)),
        landmarks: landmark_count,
        frames,
    })
}

fn write_frame(
    directory: &OwnedDirectory,
    name: &str,
    handle: u64,
    view: View,
) -> TestResult<(String, PathBuf, PathBuf)> {
    let jpeg_path = directory.0.join(format!("{name}.jpg"));
    fs::write(&jpeg_path, jpeg(view)?)?;
    let metadata_path = directory.0.join(format!("{name}.frame"));
    fs::write(&metadata_path, metadata(name, handle, view))?;
    Ok((name.to_owned(), jpeg_path, metadata_path))
}

fn calibrate(site: &Site, out: &Path) -> TestResult<Output> {
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
    for (name, jpeg, metadata) in &site.frames {
        command
            .arg("--frame")
            .arg(format!("{name}:{}", jpeg.to_str().ok_or("UTF-8 path")?))
            .arg("--frame-metadata")
            .arg(format!("{name}:{}", metadata.to_str().ok_or("UTF-8 path")?));
    }
    Ok(command.arg("--out").arg(out).output()?)
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

type M3 = [[f64; 3]; 3];

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

// ---------------------------------------------------------------------------------------------
// Contracts.
// ---------------------------------------------------------------------------------------------

/// Stated tolerances against the rendering poses: rotation (rad), centre (units; cameras are
/// 100 units above the ground) and relative focal length. The fixture is quantization-free
/// (every texel centre is a pixel centre), and quality-95 JPEG noise moved no matched feature,
/// so the solution is exact up to floating-point noise and the tolerances say so. Measured:
/// east 9.3e-14 rad / 3.1e-12 units, west 1.0e-13 rad / 4.2e-12 units, north (focal scan; seed
/// 8.2e-5 rad / 0.27 units / 3.2e-3 focal) 1.4e-13 rad / 2.9e-11 units / 4.3e-13 focal; joint
/// RMS 0.0132 -> 0.0000 px over 56 control points and 42 derived ties.
const ROTATION_TOLERANCE: f64 = 1e-9;
const CENTER_TOLERANCE: f64 = 1e-8;
const FOCAL_TOLERANCE: f64 = 1e-9;

#[test]
fn jpeg_frames_calibrate_the_site_deterministically_within_tolerance() -> TestResult {
    let directory = OwnedDirectory::new("recover")?;
    let site = build_site(&directory)?;
    eprintln!(
        "atlas landmarks from the reference rendering: {}",
        site.landmarks
    );
    let first_out = directory.0.join("first.fsscal");
    let second_out = directory.0.join("second.fsscal");
    let first = calibrate(&site, &first_out)?;
    success(&first);
    let second = calibrate(&site, &second_out)?;
    success(&second);
    // Bit-identical across runs: file bytes and stdout.
    let bytes = fs::read(&first_out)?;
    assert_eq!(bytes, fs::read(&second_out)?);
    assert_eq!(first.stdout, second.stdout);
    assert!(bytes.starts_with(SITE_CALIBRATION_MAGIC_V2));
    let (record, identity) = SiteCalibration::decode(&bytes, None)?;
    let stdout = String::from_utf8(first.stdout.clone())?;
    assert!(stdout.contains("\"format\":\"fss.site_calibration.v2\""));
    assert!(stdout.contains(&format!(
        "\"calibration_digest\":\"{}\"",
        identity.to_text()
    )));
    assert!(stdout.contains("\"kind\":\"jpeg_frame\""));
    assert_eq!(record.frame_policy, Some(FramePolicy::current()));
    assert_eq!(record.twin_package.to_text(), site.twin_digest);
    assert_eq!(record.atlas_package.to_text(), site.atlas_digest);
    // Frame ties are derived handles above every atlas landmark handle.
    assert!(!record.tie_points.is_empty(), "no frame tie survived");
    assert!(
        record
            .tie_points
            .iter()
            .all(|tie| *tie > site.landmarks as u64)
    );
    assert!(record.control_points.len() >= 3);
    eprintln!(
        "control points {}, tie points {}, excluded {}, joint RMS {:.4} -> {:.4} px",
        record.control_points.len(),
        record.tie_points.len(),
        record.excluded_points.len(),
        record.initial_rms_px,
        record.final_rms_px
    );
    assert!(record.final_rms_px <= record.initial_rms_px + 1e-12);
    assert!(
        record.final_rms_px < 1e-6,
        "joint RMS {}",
        record.final_rms_px
    );

    assert_eq!(record.cameras.len(), CAMERAS.len());
    for (camera, (name, handle, view)) in record.cameras.iter().zip(CAMERAS) {
        assert_eq!(camera.name, name);
        assert_eq!(camera.identity.camera, handle);
        let (jpeg_path, metadata_path) = site
            .frames
            .iter()
            .find(|(frame, _, _)| frame == name)
            .map(|(_, jpeg, metadata)| (jpeg, metadata))
            .ok_or("frame fixture")?;
        let jpeg = fs::read(jpeg_path)?;
        // The per-camera input digest is the exact JPEG; the metadata and luma are bound too.
        assert_eq!(camera.observations, ContentDigest::sha256(&jpeg));
        let CalibrationInput::Frame(frame) = camera.input else {
            return Err(format!("{name} is not a frame camera").into());
        };
        assert_eq!(
            frame.metadata,
            ContentDigest::sha256(&fs::read(metadata_path)?)
        );
        assert_ne!(
            frame.luma,
            ContentDigest::sha256(&view.render()),
            "JPEG is lossy"
        );
        assert!(frame.extracted_features > 0 && frame.atlas_matches >= 8);
        assert!(frame.tie_observations > 0, "{name} has no frame tie");
        let (intrinsics, truth) = view.truth()?;
        let [fx, fy] = intrinsics.focal_lengths();
        let [cx, cy] = intrinsics.principal_point();
        let focal_error = (camera.intrinsics[0] - fx).abs() / fx;
        let seed_focal_error = (camera.seed_intrinsics[0] - fx).abs() / fx;
        if name == FOCAL_SCAN_CAMERA {
            // The scan has no sample at the truth: the seed focal is off and the joint solve
            // refines it (aspect and principal point held).
            assert!(
                seed_focal_error > 1e-3,
                "seed focal {:?}",
                camera.seed_intrinsics
            );
            let seed_center = RigidPose::new(camera.seed_rotation, camera.seed_translation)?;
            let [sx, sy, sz] = seed_center.center();
            let [tx, ty, tz] = truth.center();
            assert!(
                ((sx - tx).powi(2) + (sy - ty).powi(2) + (sz - tz).powi(2)).sqrt() > 0.1,
                "the focal-scan seed is not already exact"
            );
            assert!(focal_error < FOCAL_TOLERANCE, "{name} focal {focal_error}");
            assert_eq!(camera.intrinsics[1], camera.intrinsics[0]);
            assert_eq!([camera.intrinsics[2], camera.intrinsics[3]], [cx, cy]);
        } else {
            assert_eq!(
                camera.intrinsics,
                [fx, fy, cx, cy],
                "fixed intrinsics are held"
            );
        }
        let pose = camera.pinhole_pose()?.pose;
        let angle = rotation_error(pose.rotation(), truth.rotation());
        let (center, expected) = (pose.center(), truth.center());
        let offset = (0..3)
            .map(|k| (center[k] - expected[k]).powi(2))
            .sum::<f64>()
            .sqrt();
        let seed = RigidPose::new(camera.seed_rotation, camera.seed_translation)?;
        let seed_angle = rotation_error(seed.rotation(), truth.rotation());
        let seed_offset = (0..3)
            .map(|k| (seed.center()[k] - expected[k]).powi(2))
            .sum::<f64>()
            .sqrt();
        eprintln!(
            "{name}: features {} atlas matches {} inliers {} ties {}; seed {seed_angle:.3e} rad / \
             {seed_offset:.3e} units / focal {seed_focal_error:.3e}; refined {angle:.3e} rad / \
             {offset:.3e} units / focal {focal_error:.3e}; RMS {:.4} -> {:.4} px",
            frame.extracted_features,
            frame.atlas_matches,
            camera.seed_inliers,
            frame.tie_observations,
            camera.seed_rms_px,
            camera.refined_rms_px
        );
        assert!(angle < ROTATION_TOLERANCE, "{name} rotation {angle}");
        assert!(offset < CENTER_TOLERANCE, "{name} center {offset}");
    }
    Ok(())
}

#[test]
fn undecodable_resized_and_unmapped_frames_are_typed_refusals_that_write_nothing() -> TestResult {
    let directory = OwnedDirectory::new("refusals")?;
    let site = build_site(&directory)?;
    let out = directory.0.join("refused.fsscal");
    let refused = |output: &Output, id: &str, camera: &str| {
        assert!(!output.status.success(), "{id}");
        assert!(output.stdout.is_empty(), "{id}");
        assert_eq!(refusal(output), id);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(&format!("camera {camera}")), "{stderr}");
        assert!(stderr.contains("No calibration was written."), "{stderr}");
        assert!(!out.exists(), "a refused calibration writes nothing");
    };

    // A truncated (corrupted) JPEG.
    let truncated_dir = OwnedDirectory::new("truncated")?;
    let truncated = build_site(&truncated_dir)?;
    assert_eq!(truncated.frames[1].0, "west");
    let whole = fs::read(&truncated.frames[1].1)?;
    fs::write(&truncated.frames[1].1, &whole[..whole.len() / 2])?;
    refused(
        &calibrate(&truncated, &out)?,
        "ERR-SITE-CALIBRATION-FRAME-DECODE-001",
        "west",
    );
    // Garbage in place of a JPEG.
    fs::write(
        &truncated.frames[1].1,
        b"\xff\xd8 this is not a baseline JPEG",
    )?;
    refused(
        &calibrate(&truncated, &out)?,
        "ERR-SITE-CALIBRATION-FRAME-DECODE-001",
        "west",
    );

    // A frame whose decoded size (128x120) differs from its metadata (160x120).
    let small = directory.0.join("west-small.jpg");
    fs::write(
        &small,
        jpeg(View {
            size: [128, 120],
            ..CAMERAS[1].2
        })?,
    )?;
    let resized = Site {
        frames: vec![
            site.frames[0].clone(),
            ("west".to_owned(), small, site.frames[1].2.clone()),
        ],
        twin: site.twin.clone(),
        twin_digest: site.twin_digest.clone(),
        atlas: site.atlas.clone(),
        atlas_digest: site.atlas_digest.clone(),
        provenance: site.provenance.clone(),
        landmarks: site.landmarks,
    };
    refused(
        &calibrate(&resized, &out)?,
        "ERR-SITE-CALIBRATION-FRAME-DECODE-001",
        "west",
    );

    // A frame of ground the atlas never saw: too few matched features to localize.
    let unmapped = Site {
        frames: vec![
            site.frames[0].clone(),
            write_frame(&directory, "far", 39, UNMAPPED)?,
        ],
        twin: site.twin.clone(),
        twin_digest: site.twin_digest.clone(),
        atlas: site.atlas.clone(),
        atlas_digest: site.atlas_digest.clone(),
        provenance: site.provenance.clone(),
        landmarks: site.landmarks,
    };
    let output = calibrate(&unmapped, &out)?;
    refused(
        &output,
        "ERR-SITE-CALIBRATION-LOCALIZATION-FAILED-001",
        "far",
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("descriptor match"));

    // A frame without its metadata is a malformed request.
    let output = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .arg("calibrate")
        .args(["--frame", "east:east.jpg", "--camera", "west:west.obs"])
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires --frame-metadata east"));
    Ok(())
}
