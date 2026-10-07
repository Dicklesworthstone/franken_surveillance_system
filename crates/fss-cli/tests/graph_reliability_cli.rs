#![forbid(unsafe_code)]
//! Contract tests for `fss-event graph reliability` (`ALG-RELIABILITY-001`) over a deployment
//! built through the real binaries (`fss-file import`, `fss-event watch --retain-coverage`):
//! a door watched by two sensors on separate circuits is blind only when both fail; the same
//! door with both sensors on one circuit is blind when that circuit fails (a single-domain
//! minimal cut); a zone watched by one sensor names it; the command writes nothing, is
//! byte-deterministic, and refuses malformed declarations and unknown sensors.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 14;
const SITE: &str = "site:graph-reliability";

struct OwnedDirectory(PathBuf);

impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        let path =
            std::env::temp_dir().join(format!("fss-reliability-cli-{name}-{}", std::process::id()));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir(&path)?;
        Ok(Self(path))
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

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn import(directory: &OwnedDirectory, name: &str, sensor: &str, level: u8) -> TestResult<String> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let pixels = vec![level; (WIDTH * HEIGHT) as usize];
    let mut stream = Vec::new();
    for _ in 0..FRAMES {
        stream.extend(encode_jpeg(WIDTH, HEIGHT, &pixels, &config)?);
    }
    let input = directory.0.join(format!("{name}.mjpeg"));
    fs::write(&input, stream)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(directory.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{name}")])
        .args([
            "--media-format",
            "mjpeg",
            "--receive-time-ns",
            "10000000000000",
        ])
        .args([
            "--capture-start-ns",
            "1000000000",
            "--capture-uncertainty-ns",
            "1000000",
        ])
        .args(["--assumed-fps", "10"])
        .output()?;
    success(&output);
    Ok(String::from_utf8(output.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("import identity missing")?)
}

fn watch(root: &Path, import_id: &str, zones: &[&str], extra: &[&str]) -> TestResult<Value> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    command.arg("watch").arg("--root").arg(root).args([
        "--site",
        SITE,
        "--import-id",
        import_id,
        "--interpretation",
        "gray",
    ]);
    for zone in zones {
        command.args(["--zone", zone]);
    }
    let output = command.args(extra).output()?;
    success(&output);
    Ok(parse(String::from_utf8(output.stdout)?.trim_end())?)
}

fn get<'a>(value: &'a Value, path: &[&str]) -> TestResult<&'a Value> {
    let mut current = value;
    for key in path {
        current = current
            .object()
            .and_then(|object| object.get(*key))
            .ok_or_else(|| format!("missing {key}"))?;
    }
    Ok(current)
}

fn retain(root: &Path, import_id: &str, zones: &[&str]) -> TestResult {
    let preview = watch(root, import_id, zones, &[])?;
    let approval = get(&preview, &["coverage", "approval_digest"])?
        .text()
        .ok_or("approval")?
        .to_owned();
    watch(root, import_id, zones, &["--retain-coverage", &approval])?;
    Ok(())
}

fn reliability(root: &Path, extra: &[&str]) -> TestResult<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .arg("graph")
        .arg("reliability")
        .arg("--root")
        .arg(root)
        .args(["--site", SITE])
        .args(extra)
        .output()?)
}

fn zone<'a>(report: &'a Value, scope: &str) -> TestResult<&'a Value> {
    get(report, &["zones"])?
        .array()
        .ok_or("zones")?
        .iter()
        .find(|row| get(row, &["scope"]).ok().and_then(Value::text) == Some(scope))
        .ok_or_else(|| format!("zone {scope}").into())
}

fn cuts(row: &Value) -> TestResult<Vec<Vec<String>>> {
    Ok(get(row, &["minimal_cuts"])?
        .array()
        .ok_or("cuts")?
        .iter()
        .map(|cut| {
            get(cut, &["domains"])
                .ok()
                .and_then(Value::array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::text)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default()
        })
        .collect())
}

fn ppm(row: &Value) -> TestResult<(i128, i128)> {
    let pair = get(row, &["blind_probability_ppm"])?.array().ok_or("ppm")?;
    Ok((
        pair[0].integer().ok_or("lo")?,
        pair[1].integer().ok_or("hi")?,
    ))
}

#[test]
fn blindness_bounds_follow_shared_and_separate_circuits() -> TestResult {
    let directory = OwnedDirectory::new("mesh")?;
    let root = directory.root();
    let north = import(&directory, "north", "sensor:north", 40)?;
    let south = import(&directory, "south", "sensor:south", 60)?;
    retain(&root, &north, &["door:64,0,32,32", "gate:0,0,32,32"])?;
    retain(&root, &south, &["door:64,0,32,32"])?;

    // Separate circuits: the door needs both cameras (or both circuits) to fail.
    let separate = reliability(
        &root,
        &[
            "--camera-failure",
            "10000:20000",
            "--domain",
            "power:c1=1000:5000=sensor:north",
            "--domain",
            "power:c2=1000:5000=sensor:south",
        ],
    )?;
    success(&separate);
    let report = parse(String::from_utf8(separate.stdout.clone())?.trim_end())?;
    assert_eq!(
        get(&report, &["format"])?.text(),
        Some("fss.coverage_reliability.v1")
    );
    let door = zone(&report, "zone:door")?;
    assert!(
        cuts(door)?.iter().all(|cut| cut.len() == 2),
        "{:?}",
        cuts(door)?
    );
    let (door_lo, door_hi) = ppm(door)?;
    // (0.011..0.025)^2 per camera-or-circuit pair: well under 1000 ppm.
    assert!(door_lo >= 100 && door_hi <= 700, "{door_lo} {door_hi}");
    let gate = zone(&report, "zone:gate")?;
    assert_eq!(
        cuts(gate)?,
        vec![
            vec!["camera:sensor:north".to_owned()],
            vec!["power:c1".to_owned()]
        ]
    );

    // One shared circuit: the circuit alone blinds the door.
    let shared = reliability(
        &root,
        &[
            "--camera-failure",
            "10000:20000",
            "--domain",
            "power:c1=1000:5000=sensor:north,sensor:south",
        ],
    )?;
    success(&shared);
    let report = parse(String::from_utf8(shared.stdout)?.trim_end())?;
    let door = zone(&report, "zone:door")?;
    assert_eq!(cuts(door)?[0], vec!["power:c1".to_owned()]);
    let (shared_lo, _) = ppm(door)?;
    assert!(
        shared_lo >= 1000 && shared_lo > door_hi,
        "a shared circuit must dominate: {shared_lo}"
    );

    // Deterministic and read-only.
    let again = reliability(
        &root,
        &[
            "--camera-failure",
            "10000:20000",
            "--domain",
            "power:c1=1000:5000=sensor:north",
            "--domain",
            "power:c2=1000:5000=sensor:south",
        ],
    )?;
    assert_eq!(again.stdout, separate.stdout);

    // Refusals: unknown sensor, inverted interval, malformed declaration.
    let unknown = reliability(&root, &["--domain", "power:c9=1:2=sensor:attic"])?;
    assert!(!unknown.status.success());
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("ERR-GRAPH-INPUT-INVALID-001"));
    for bad in ["power:c1=9:1=sensor:north", "power:c1=sensor:north"] {
        let output = reliability(&root, &["--domain", bad])?;
        assert_eq!(output.status.code(), Some(2), "{bad}");
        assert!(output.stdout.is_empty());
    }
    Ok(())
}
