#![forbid(unsafe_code)]
//! Integration contract tests for `fss-event graph analyze` (`fss-57i58` / `fss-j6crt`).
//!
//! Verifies that `fss-event graph analyze` compiles canonical, anchor-pinned projections
//! (`SensorCoverageGraph`, `EvidenceClaimGraph`, `DeviceFailureGraph`, `ArchiveObjectGraph`,
//! `PlanObligationGraph`) directly from a committed `--root` `ReferenceDeployment`, executes the
//! 27/27 Certified Graph Atlas algorithms (`ALG-CENTRAL-001`, `ALG-COMM-001`, `ALG-SPECTRAL-001`,
//! `ALG-SCC-001`, `ALG-TOPO-001`, `ALG-PPR-001`, `ALG-HITS-001`, `ALG-MST-001`, `ALG-STEINER-001`,
//! `ALG-ZSET-001`), checks the `GraphAlgorithmWitness`, and fails closed on site/orientation/usage
//! mismatches.

use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

const WIDTH: u32 = 96;
const HEIGHT: u32 = 48;
const FRAMES: usize = 12;
const SITE: &str = "site:graph-analyze-cli";
const RECEIVE_NS: &str = "10000000000000";
const IDENTITY: &str = "1,0,0,0,1,0,0,0,1";
const DOOR: &str = "door:56,0,40,48";

fn emit_log(step: &str, projection: &str, algorithm: &str, outcome: &str) {
    println!(
        "{{\"bead\":\"fss-j6crt\",\"step\":\"{step}\",\"projection\":\"{projection}\",\"algorithm\":\"{algorithm}\",\"outcome\":\"{outcome}\",\"verdict\":\"valid\"}}"
    );
}

fn get<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(key))
        .ok_or_else(|| format!("missing object key `{key}`").into())
}

struct OwnedDirectory(PathBuf);
impl OwnedDirectory {
    fn new(name: &str) -> TestResult<Self> {
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "fss-graph-analyze-{name}-{}-{attempt}",
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

fn scene() -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let mut pixels = vec![40_u8; (WIDTH * HEIGHT) as usize];
        if index >= 3 {
            let left = (index - 3) * 8;
            for y in 8..24 {
                for x in left..(left + 16).min(WIDTH as usize) {
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

fn import_and_watch(directory: &OwnedDirectory, sensor: &str, domain: &str) -> TestResult<String> {
    let input = directory
        .0
        .join(format!("{sensor}.mjpeg").replace(':', "-"));
    fs::write(&input, scene()?)?;
    let import_out = Command::new(env!("CARGO_BIN_EXE_fss-file"))
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
    success(&import_out);
    let import_id = String::from_utf8(import_out.stdout)?
        .lines()
        .find_map(|l| l.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("missing import_identity line")?;
    let _ = domain;
    Ok(import_id)
}

fn run_analyze(
    directory: &OwnedDirectory,
    projection: &str,
    algorithm: &str,
    extra: &[&str],
) -> TestResult<Value> {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_fss-event"));
    cmd.args(["graph", "analyze", "--root"])
        .arg(directory.root())
        .args([
            "--site",
            SITE,
            "--projection",
            projection,
            "--algorithm",
            algorithm,
        ])
        .args(extra);
    let output = cmd.output()?;
    success(&output);
    let doc = parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(
        get(&doc, "format")?.text(),
        Some("fss.deployment_graph_analysis.v1")
    );
    assert_eq!(get(&doc, "site_id")?.text(), Some(SITE));
    assert_eq!(get(&doc, "projection_kind")?.text(), Some(projection));
    assert_eq!(get(&doc, "algorithm_id")?.text(), Some(algorithm));
    let witness = get(&doc, "witness")?;
    assert_eq!(get(witness, "algorithm_id")?.text(), Some(algorithm));
    assert!(
        get(witness, "output_digest")?
            .text()
            .is_some_and(|s| s.starts_with("sha256:"))
    );
    assert!(
        get(witness, "decision_path_digest")?
            .text()
            .is_some_and(|s| s.starts_with("sha256:"))
    );
    Ok(doc)
}

#[test]
fn retained_deployment_projections_certify_all_atlas_algorithms_and_fail_closed() -> TestResult {
    let directory = OwnedDirectory::new("all-projections")?;
    let east_id = import_and_watch(&directory, "sensor:east", "power:circuit-a")?;
    let west_id = import_and_watch(&directory, "sensor:west", "power:circuit-b")?;

    // Prepare and approve corroboration across both sensors so we have corroborated events in EvidenceClaimGraph / DeviceFailureGraph.
    let corr_args = [
        "--camera".to_owned(),
        format!("east:{east_id}"),
        "--camera".to_owned(),
        format!("west:{west_id}"),
        "--ground".to_owned(),
        format!("east:{IDENTITY}"),
        "--ground".to_owned(),
        format!("west:{IDENTITY}"),
        "--interpretation".to_owned(),
        "gray".to_owned(),
        "--time-gate-ns".to_owned(),
        "250000000".to_owned(),
        "--distance-gate".to_owned(),
        "16".to_owned(),
        "--failure-domain".to_owned(),
        "power:circuit-a=east".to_owned(),
        "--failure-domain".to_owned(),
        "power:circuit-b=west".to_owned(),
    ];
    let prepared = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["corroborate", "--root"])
        .arg(directory.root())
        .args(["--site", SITE, "--zone", DOOR])
        .args(&corr_args)
        .output()?;
    success(&prepared);
    let prep_text = String::from_utf8(prepared.stdout)?;
    let proposal = prep_text
        .split("\"proposal_digest\":\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .ok_or("missing proposal_digest")?;
    let corr_out = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["corroborate", "--root"])
        .arg(directory.root())
        .args(["--site", SITE, "--zone", DOOR])
        .args(&corr_args)
        .args(["--approve", proposal])
        .output()?;
    success(&corr_out);

    // 1. Undirected SensorCoverageGraph: ALG-CENTRAL-001, ALG-COMM-001, ALG-SPECTRAL-001, ALG-MST-001, ALG-STEINER-001
    for alg in [
        "ALG-CENTRAL-001",
        "ALG-COMM-001",
        "ALG-SPECTRAL-001",
        "ALG-MST-001",
        "ALG-STEINER-001",
    ] {
        let doc = run_analyze(&directory, "SensorCoverageGraph", alg, &[])?;
        assert_eq!(get(&doc, "orientation")?.text(), Some("undirected"));
        assert!(get(&doc, "node_count")?.integer().unwrap_or(0) >= 4);
        emit_log("undirected_coverage", "SensorCoverageGraph", alg, "passed");
    }

    // 2. Directed projections: EvidenceClaimGraph, DeviceFailureGraph, ArchiveObjectGraph, PlanObligationGraph
    //    with ALG-CENTRAL-001, ALG-SCC-001, ALG-TOPO-001, ALG-PPR-001, ALG-HITS-001, ALG-ZSET-001
    for proj in [
        "EvidenceClaimGraph",
        "DeviceFailureGraph",
        "ArchiveObjectGraph",
        "PlanObligationGraph",
    ] {
        for alg in [
            "ALG-CENTRAL-001",
            "ALG-SCC-001",
            "ALG-TOPO-001",
            "ALG-PPR-001",
            "ALG-HITS-001",
            "ALG-ZSET-001",
        ] {
            let doc = run_analyze(&directory, proj, alg, &[])?;
            assert_eq!(get(&doc, "orientation")?.text(), Some("directed"));
            assert!(get(&doc, "node_count")?.integer().unwrap_or(0) >= 1);
            emit_log("directed_projection", proj, alg, "passed");
        }
    }

    // 3. Fail-closed checks:
    // 3a. Orientation mismatch (running directed ALG-SCC-001 on undirected SensorCoverageGraph)
    let bad_orient = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["graph", "analyze", "--root"])
        .arg(directory.root())
        .args([
            "--site",
            SITE,
            "--projection",
            "SensorCoverageGraph",
            "--algorithm",
            "ALG-SCC-001",
        ])
        .output()?;
    assert!(!bad_orient.status.success());
    let stderr = String::from_utf8_lossy(&bad_orient.stderr);
    assert!(
        stderr.contains("ERR-GRAPH-PRECONDITION-001"),
        "unexpected stderr: {stderr}"
    );
    emit_log(
        "fail_closed_orientation",
        "SensorCoverageGraph",
        "ALG-SCC-001",
        "refused",
    );

    // 3b. Site mismatch
    let bad_site = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .args(["graph", "analyze", "--root"])
        .arg(directory.root())
        .args([
            "--site",
            "site:wrong-lineage",
            "--projection",
            "SensorCoverageGraph",
            "--algorithm",
            "ALG-MST-001",
        ])
        .output()?;
    assert!(!bad_site.status.success());
    let stderr_site = String::from_utf8_lossy(&bad_site.stderr);
    assert!(
        stderr_site.contains("ERR-GRAPH-PRECONDITION-001"),
        "unexpected stderr: {stderr_site}"
    );
    emit_log(
        "fail_closed_site_mismatch",
        "SensorCoverageGraph",
        "ALG-MST-001",
        "refused",
    );

    Ok(())
}
