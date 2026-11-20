#![forbid(unsafe_code)]
//! Integration contract tests for `fss-event graph analyze` (`fss-57i58` / `fss-j6crt`).
//!
//! Exercises the registered deployment projections on a cold recording fixture and checks
//! the coverage and active-support topology against the retained records.

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

fn scene(moving: bool) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for index in 0..FRAMES {
        let mut pixels = vec![40_u8; (WIDTH * HEIGHT) as usize];
        if moving && index >= 3 {
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

fn import(
    directory: &OwnedDirectory,
    sensor: &str,
    timed: bool,
    moving: bool,
) -> TestResult<String> {
    let input = directory
        .0
        .join(format!("{sensor}.mjpeg").replace(':', "-"));
    fs::write(&input, scene(moving)?)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss-file"));
    command
        .arg("import")
        .arg("--root")
        .arg(directory.root())
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args(["--sensor", sensor, "--stream", &format!("stream:{sensor}")])
        .args(["--receive-time-ns", RECEIVE_NS, "--media-format", "mjpeg"]);
    if timed {
        command
            .args(["--capture-start-ns", "1000000000"])
            .args(["--capture-uncertainty-ns", "1000000"])
            .args(["--assumed-fps", "10"]);
    }
    let import_out = command.output()?;
    success(&import_out);
    let import_id = String::from_utf8(import_out.stdout)?
        .lines()
        .find_map(|l| l.strip_prefix("import_identity=").map(str::to_owned))
        .ok_or("missing import_identity line")?;
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
fn registered_deployment_pairs_preserve_current_evidence_and_refuse_invalid_requests() -> TestResult
{
    let directory = OwnedDirectory::new("all-projections")?;
    let east_id = import(&directory, "sensor:east", true, true)?;
    let west_id = import(&directory, "sensor:west", true, true)?;

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

    let snapshot =
        fss_reference::agent_orient::read_deployment(&directory.root(), &Default::default())?;
    assert!(!snapshot.events.is_empty());
    let heads: Vec<_> = snapshot
        .events
        .iter()
        .map(|record| record.event.clone())
        .collect();
    let evidence =
        fss_graph_algorithms::evidence::EvidenceClaimProjection::build(&heads, Default::default())?;
    let expected_evidence = evidence.graph().digest().to_text();
    let scc = run_analyze(&directory, "EvidenceClaimGraph", "ALG-SCC-001", &[])?;
    assert_eq!(
        get(&scc, "projection_digest")?.text(),
        Some(expected_evidence.as_str())
    );
    assert!(evidence.graph().arc_count() > 0);

    let support_node = evidence
        .graph()
        .ids()
        .iter()
        .find(|id| id.starts_with("support:"))
        .ok_or("missing current support incidence")?;
    run_analyze(
        &directory,
        "EvidenceClaimGraph",
        "ALG-PPR-001",
        &["--seed", support_node],
    )?;

    for (projection, algorithms) in [
        (
            "SensorCoverageGraph",
            &[
                "ALG-CENTRAL-001",
                "ALG-MST-001",
                "ALG-STEINER-001",
                "ALG-ZSET-001",
            ][..],
        ),
        (
            "EvidenceClaimGraph",
            &["ALG-PPR-001", "ALG-HITS-001", "ALG-ZSET-001"],
        ),
        (
            "DeviceFailureGraph",
            &["ALG-CENTRAL-001", "ALG-SPECTRAL-001", "ALG-ZSET-001"],
        ),
        ("ArchiveObjectGraph", &["ALG-ZSET-001"]),
        (
            "PlanObligationGraph",
            &["ALG-SCC-001", "ALG-TOPO-001", "ALG-ZSET-001"],
        ),
    ] {
        for alg in algorithms {
            let doc = run_analyze(&directory, projection, alg, &[])?;
            if projection == "SensorCoverageGraph" {
                // Imports and corroborated events alone cannot establish coverage.
                assert_eq!(get(&doc, "node_count")?.integer(), Some(1));
                assert_eq!(get(&doc, "edge_count")?.integer(), Some(0));
            }
        }
    }

    for (projection, algorithm) in [
        ("SensorCoverageGraph", "ALG-SCC-001"),
        ("SensorCoverageGraph", "ALG-COMM-001"),
        ("ArchiveObjectGraph", "ALG-PPR-001"),
        ("EvidenceClaimGraph", "ALG-TOPO-001"),
        ("ArchiveObjectGraph", "ALG-MST-001"), // registered, but the archive view is directed
    ] {
        let refused = Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["graph", "analyze", "--root"])
            .arg(directory.root())
            .args([
                "--site",
                SITE,
                "--projection",
                projection,
                "--algorithm",
                algorithm,
            ])
            .output()?;
        assert!(!refused.status.success());
        assert!(refused.stdout.is_empty());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("ERR-GRAPH-PRECONDITION-001"));
    }

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

#[test]
fn cold_graph_uses_only_positive_retained_zone_witnesses() -> TestResult {
    use fss_graph_algorithms::weighted::WeightedGraphBuilder;

    let directory = OwnedDirectory::new("witnesses")?;
    let plane = format!("plane/{SITE}");
    let mut expected = WeightedGraphBuilder::undirected("retained-witnesses:v1");
    expected.add_node(&plane);
    for (sensor, timed) in [("sensor:unknown", false), ("sensor:known", true)] {
        let id = import(&directory, sensor, timed, false)?;
        let watch = |extra: &[&str]| {
            Command::new(env!("CARGO_BIN_EXE_fss-event"))
                .args(["watch", "--root"])
                .arg(directory.root())
                .args([
                    "--site",
                    SITE,
                    "--import-id",
                    &id,
                    "--interpretation",
                    "gray",
                    "--zone",
                    DOOR,
                ])
                .args(extra)
                .output()
        };
        let preview = watch(&[])?;
        success(&preview);
        let preview = parse(std::str::from_utf8(&preview.stdout)?)?;
        let coverage = get(&preview, "coverage")?;
        let count = get(coverage, "witness_count")?
            .integer()
            .ok_or("missing witness count")?;
        assert_eq!(count > 0, timed);
        let before = run_analyze(&directory, "SensorCoverageGraph", "ALG-MST-001", &[])?;
        assert_eq!(
            get(&before, "projection_digest")?.text(),
            Some(expected.clone().build()?.digest().to_text().as_str())
        );

        let approval = get(coverage, "approval_digest")?
            .text()
            .ok_or("missing approval")?;
        success(&watch(&["--retain-coverage", approval])?);
        let node = format!("sensor/{sensor}");
        expected.add_node(&node).add_arc(&plane, &node, 1);
        if timed {
            expected.add_arc(&node, "zone/zone:door", u64::try_from(count)?);
        } else {
            expected.add_node("zone/zone:door");
        }
        let after = run_analyze(&directory, "SensorCoverageGraph", "ALG-MST-001", &[])?;
        assert_eq!(
            get(&after, "projection_digest")?.text(),
            Some(expected.clone().build()?.digest().to_text().as_str())
        );
        assert_ne!(
            get(&before, "authority_anchor")?,
            get(&after, "authority_anchor")?
        );
        assert_eq!(
            get(&after, "edge_count")?.integer(),
            Some(if timed { 3 } else { 1 })
        );
        let device = run_analyze(&directory, "DeviceFailureGraph", "ALG-ZSET-001", &[])?;
        assert_eq!(get(&device, "edge_count")?, get(&after, "edge_count")?);
    }
    Ok(())
}

#[test]
fn all_seven_newly_wired_algorithms_and_incremental_zset_work_end_to_end() -> TestResult {
    let directory = OwnedDirectory::new("wired-seven-and-incremental-zset")?;
    let east_id = import(&directory, "sensor:east", true, true)?;
    let west_id = import(&directory, "sensor:west", true, true)?;

    // Retain positive coverage on both sensors so SensorCoverageGraph has plane -> sensor -> zone edges.
    for import_id in [&east_id, &west_id] {
        let preview = Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["watch", "--root"])
            .arg(directory.root())
            .args([
                "--site",
                SITE,
                "--import-id",
                import_id,
                "--interpretation",
                "gray",
                "--zone",
                DOOR,
            ])
            .output()?;
        success(&preview);
        let doc = parse(std::str::from_utf8(&preview.stdout)?)?;
        let approval = get(get(&doc, "coverage")?, "approval_digest")?
            .text()
            .ok_or("missing coverage approval")?;
        let retain = Command::new(env!("CARGO_BIN_EXE_fss-event"))
            .args(["watch", "--root"])
            .arg(directory.root())
            .args([
                "--site",
                SITE,
                "--import-id",
                import_id,
                "--interpretation",
                "gray",
                "--zone",
                DOOR,
                "--retain-coverage",
                approval,
            ])
            .output()?;
        success(&retain);
    }

    // Also corroborate an event so EvidenceClaimGraph, DeviceFailureGraph, ArchiveObjectGraph have rich edges.
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

    // 1. ALG-DYNCONN-001 on SensorCoverageGraph (with live edge deletion batch)
    let dynconn = run_analyze(
        &directory,
        "SensorCoverageGraph",
        "ALG-DYNCONN-001",
        &["--update", "-sensor/sensor:east,zone/zone:door"],
    )?;
    assert!(
        get(get(&dynconn, "result")?, "component_counts")?
            .array()
            .is_some()
    );

    // 2. ALG-GH-001 (Gomory-Hu min-cut tree) on SensorCoverageGraph
    let gh = run_analyze(&directory, "SensorCoverageGraph", "ALG-GH-001", &[])?;
    assert!(get(get(&gh, "result")?, "tree")?.array().is_some());

    // 3. ALG-SP-001 (Shortest path) on ArchiveObjectGraph
    let sp = run_analyze(
        &directory,
        "ArchiveObjectGraph",
        "ALG-SP-001",
        &["--source", "root:deployment"],
    )?;
    assert!(get(get(&sp, "result")?, "reachable")?.array().is_some());

    // 4. ALG-MSD-001 (Multi-source distance) on SensorCoverageGraph
    let msd = run_analyze(
        &directory,
        "SensorCoverageGraph",
        "ALG-MSD-001",
        &[
            "--source",
            "sensor/sensor:east",
            "--source",
            "sensor/sensor:west",
        ],
    )?;
    assert!(get(get(&msd, "result")?, "reachable")?.array().is_some());

    // 5. ALG-KSP-001 (k shortest diverse paths) on ArchiveObjectGraph
    let ksp_doc = run_analyze(
        &directory,
        "ArchiveObjectGraph",
        "ALG-KSP-001",
        &["--source", "root:deployment", "--k", "2"],
    )?;
    assert!(get(get(&ksp_doc, "result")?, "paths")?.array().is_some());

    // 6. ALG-SUBMOD-001 (Budgeted weighted coverage) on SensorCoverageGraph
    let submod = run_analyze(
        &directory,
        "SensorCoverageGraph",
        "ALG-SUBMOD-001",
        &["--budget", "1"],
    )?;
    assert_eq!(
        get(get(&submod, "result")?, "cost_units")?.integer(),
        Some(1)
    );

    // 7. ALG-FACTOR-001 (Factorized free join) on EvidenceClaimGraph
    let factor = run_analyze(&directory, "EvidenceClaimGraph", "ALG-FACTOR-001", &[])?;
    assert!(
        get(get(&factor, "result")?, "complete_bindings")?
            .integer()
            .is_some()
    );

    // 8. True incremental ALG-ZSET-001 across committed ledger revisions
    let zset_inc = run_analyze(&directory, "ArchiveObjectGraph", "ALG-ZSET-001", &[])?;
    let zres = get(&zset_inc, "result")?;
    assert_eq!(get(zres, "incremental")?.boolean(), Some(true));
    let base_seq = get(zres, "base_commit_sequence")?
        .integer()
        .ok_or("missing base_commit_sequence")?;
    let head_seq = get(zres, "head_commit_sequence")?
        .integer()
        .ok_or("missing head_commit_sequence")?;
    assert!(base_seq > 0 && base_seq < head_seq);

    // Explicit --from-commit 0 runs full cold-start baseline for comparison.
    let zset_cold = run_analyze(
        &directory,
        "ArchiveObjectGraph",
        "ALG-ZSET-001",
        &["--from-commit", "0"],
    )?;
    assert_eq!(
        get(get(&zset_cold, "result")?, "incremental")?.boolean(),
        Some(false)
    );
    Ok(())
}
