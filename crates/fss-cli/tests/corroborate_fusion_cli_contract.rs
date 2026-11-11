#![forbid(unsafe_code)]
//! The legacy corroboration calibration path must refuse before any read, write, or advice.
//!
//! Valid Wilson bins do not establish applicability to a detector class or model, and geometric
//! association scores cannot supply class evidence. Exercise the real binaries with a native
//! event proposal, exact publication approval, owner score overrides, both recording scopes,
//! and protected output paths. Supported pinned class fusion has its own profile/CLI contracts.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
use fss_fusion::ScoreCalibration;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 14;
const SITE: &str = "site:corroborate-fusion-cli";
const RECEIVE_NS: &str = "10000000000000";
const IDENTITY: &str = "1,0,0,0,1,0,0,0,1";
const MIRROR: &str = "-1,0,96,0,1,0,0,0,1";
const DOOR: &str = "door:56,0,40,48";

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-corroborate-fusion-{name}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
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

#[derive(Clone, Copy)]
enum Motion {
    Right,
    Left,
}

fn scene(motion: Motion) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let mut pixels = vec![40_u8; (WIDTH * HEIGHT) as usize];
        let left = match motion {
            Motion::Right if index >= 3 => Some((index - 3) * 8),
            Motion::Left if index >= 3 => Some(80 - (index - 3) * 8),
            _ => None,
        };
        if let Some(left) = left {
            for y in 8..24 {
                for x in left..left + 16 {
                    pixels[y * WIDTH as usize + x] = 220;
                }
            }
        }
        stream.extend(encode_jpeg(WIDTH, HEIGHT, &pixels, &config)?);
    }
    Ok(stream)
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn import(directory: &OwnedDirectory, motion: Motion, sensor: &str) -> TestResult<String> {
    let input = directory.0.join(format!("{sensor}.mjpeg").replace(':', "-"));
    fs::write(&input, scene(motion)?)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(directory.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{sensor}")])
        .args(["--receive-time-ns", RECEIVE_NS, "--media-format", "mjpeg"])
        .args(["--capture-start-ns", "1000000000"])
        .args(["--capture-uncertainty-ns", "1000000"])
        .args(["--assumed-fps", "10"])
        .output()?;
    success(&output);
    fs::remove_file(input)?;
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .find_map(|l| l.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("import identity missing")?)
}

struct Pair {
    east: String,
    west: String,
}

fn setup_pair(name: &str) -> TestResult<(OwnedDirectory, Pair)> {
    let directory = OwnedDirectory::new(name)?;
    let pair = Pair {
        east: import(&directory, Motion::Right, "sensor:east")?,
        west: import(&directory, Motion::Left, "sensor:west")?,
    };
    Ok((directory, pair))
}

fn corroborate(root: &Path, pair: &Pair, extra: &[&str]) -> TestResult<Output> {
    let east = format!("east:{}", pair.east);
    let west = format!("west:{}", pair.west);
    let east_ground = format!("east:{IDENTITY}");
    let west_ground = format!("west:{MIRROR}");
    let mut args = vec![
        "--camera",
        &east,
        "--camera",
        &west,
        "--ground",
        &east_ground,
        "--ground",
        &west_ground,
        "--zone",
        DOOR,
        "--interpretation",
        "gray",
        "--time-gate-ns",
        "250000000",
        "--distance-gate",
        "16",
    ];
    args.extend_from_slice(extra);
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .arg("corroborate")
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args(&args)
        .output()?)
}

fn write_calibration_file(
    dir: &Path,
    filename: &str,
    camera_scores_json: Option<&str>,
) -> TestResult<PathBuf> {
    let calibration = ScoreCalibration::from_counts(
        "cal:corroboration-test:v1",
        &[0, 500_000],
        &[(2, 98), (98, 2)],
    )?;
    let extra = camera_scores_json.map_or_else(String::new, |scores| {
        format!(",\"camera_scores_ppm\":{scores}")
    });
    let json = format!(
        "{{\"schema\":\"fss.score_calibration.v1\",\"generation\":\"{}\",\"digest\":\"{}\",\"bins\":[{{\"lo_ppm\":0,\"true_positives\":2,\"false_positives\":98}},{{\"lo_ppm\":500000,\"true_positives\":98,\"false_positives\":2}}]{extra}}}",
        calibration.generation, calibration.digest
    );
    let path = dir.join(filename);
    fs::write(&path, json)?;
    Ok(path)
}

fn migration_refusal(output: &Output) {
    assert!(!output.status.success(), "legacy calibration was accepted");
    assert!(output.stdout.is_empty(), "refusal must not deliver a report");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unsupported for corroborate"), "{stderr}");
    assert!(stderr.contains("--fusion-profile PATH"), "{stderr}");
    assert!(stderr.contains("--fusion-digest sha256:HEX"), "{stderr}");
    assert!(stderr.contains("read-only calibrated class advice"), "{stderr}");
}

fn snapshot(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    fn collect(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                collect(root, &path, entries)?;
            } else {
                entries.insert(path.strip_prefix(root)?.to_owned(), fs::read(path)?);
            }
        }
        Ok(())
    }
    let mut entries = BTreeMap::new();
    collect(root, root, &mut entries)?;
    Ok(entries)
}

#[test]
fn legacy_calibration_cannot_turn_geometry_or_camera_overrides_into_class_advice() -> TestResult {
    let (directory, pair) = setup_pair("legacy-refusal")?;
    let baseline = corroborate(&directory.root(), &pair, &[])?;
    success(&baseline);
    let document = parse(std::str::from_utf8(&baseline.stdout)?)?;
    let report = document.object().ok_or("report object")?;
    assert!(!report.contains_key("fusion_assessment"));
    let candidates = report
        .get("candidates")
        .and_then(Value::array)
        .ok_or("native candidates")?;
    assert_eq!(
        candidates.len(),
        1,
        "fixture must exercise an actual event proposal"
    );
    let approval = candidates[0]
        .object()
        .and_then(|candidate| candidate.get("proposal_digest"))
        .and_then(Value::text)
        .ok_or("native approval digest")?;
    let before = snapshot(&directory.root())?;

    // Every artifact has valid Wilson counts and a matching digest. None binds a detector class
    // or its producer. Geometry used to yield AlertWarranted, and owner overrides could produce
    // either that label or NoActivity without any class inference or negative-evidence witness.
    for (filename, scores) in [
        ("geometry.json", None),
        ("high.json", Some("{\"east\":900000,\"west\":900000}")),
        ("low.json", Some("{\"east\":100000,\"west\":100000}")),
    ] {
        let calibration = write_calibration_file(&directory.0, filename, scores)?;
        let calibration = calibration.to_str().ok_or("UTF-8 fixture path")?;
        for publish in [false, true] {
            let mut extra = vec![
                "--score-calibration",
                calibration,
                "--fusion-policy",
                "1000,0,-1000",
            ];
            if publish {
                extra.extend(["--approve", approval]);
            }
            migration_refusal(&corroborate(&directory.root(), &pair, &extra)?);
            assert_eq!(
                snapshot(&directory.root())?,
                before,
                "refusal must precede publication"
            );
        }
    }
    let repeated = corroborate(&directory.root(), &pair, &[])?;
    success(&repeated);
    assert_eq!(
        repeated.stdout, baseline.stdout,
        "native advice remains byte-identical"
    );
    Ok(())
}

#[test]
fn legacy_options_refuse_before_source_or_output_io_including_whole_recordings() -> TestResult {
    let directory = OwnedDirectory::new("before-io")?;
    let pair = Pair {
        east: ContentDigest::sha256(b"unopened east recording").to_text(),
        west: ContentDigest::sha256(b"unopened west recording").to_text(),
    };
    let missing_calibration = directory.0.join("must-not-open.json");
    let report_path = directory.0.join("report.json");
    let sentinel = b"existing operator report\n";
    fs::write(&report_path, sentinel)?;
    let approval = ContentDigest::sha256(b"unopened approval").to_text();

    for streaming in [false, true] {
        for legacy in ["--score-calibration", "--fusion-policy"] {
            for authority in [
                None,
                Some("--approve"),
                Some("--retain-coverage"),
                Some("--retain-health"),
            ] {
                if authority == Some("--retain-health") && !streaming {
                    continue;
                }
                let mut extra = vec![
                    "--report-out",
                    report_path.to_str().ok_or("UTF-8 report path")?,
                ];
                if streaming {
                    extra.extend(["--stream-corroborate", "--sensor-health", "conservative-v1"]);
                }
                if let Some(authority) = authority {
                    extra.extend([authority, &approval]);
                }
                extra.extend([
                    legacy,
                    if legacy == "--score-calibration" {
                        missing_calibration.to_str().ok_or("UTF-8 calibration path")?
                    } else {
                        "1000,0,-1000"
                    },
                ]);
                migration_refusal(&corroborate(&directory.root(), &pair, &extra)?);
                assert!(
                    !directory.root().exists(),
                    "refusal must precede opening the deployment"
                );
                assert!(!missing_calibration.exists());
                assert_eq!(fs::read(&report_path)?, sentinel);
            }
        }
    }
    Ok(())
}
