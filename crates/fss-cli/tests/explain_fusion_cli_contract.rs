#![forbid(unsafe_code)]
//! Retained event explanations require explicit score assumptions and preserve common causes.
//! Model-free source relations cannot manufacture scores, physical independence or coverage.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::{ContentDigest, EvidenceEdgeRelation};
use fss_reference::agent_orient::{OrientLimits, read_deployment};
use fss_fusion::ScoreCalibration;
use fss_reference::media_fixture::jpeg::{JpegConfig, Subsampling, encode_jpeg};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:explain-fusion-cli";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for attempt in 0..64 {
            let path = std::env::temp_dir().join(format!(
                "fss-explain-fusion-{label}-{}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err("test directory allocation exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn get<'a>(value: &'a Value, key: &str) -> TestResult<&'a Value> {
    value
        .object()
        .and_then(|object| object.get(key))
        .ok_or_else(|| format!("missing object key {key}").into())
}
fn text(value: &Value) -> TestResult<&str> {
    value.text().ok_or_else(|| "expected text".into())
}
fn array(value: &Value) -> TestResult<&[Value]> {
    value.array().ok_or_else(|| "expected array".into())
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn report_field(output: &Output, key: &str) -> TestResult<String> {
    let output = std::str::from_utf8(&output.stdout)?;
    let pattern = format!("\"{key}\":");
    let rest = output
        .split_once(pattern.as_str())
        .ok_or_else(|| format!("missing {key}"))?
        .1;
    Ok(match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or_default().to_owned(),
        None => rest
            .split([',', '}', ']'])
            .next()
            .unwrap_or_default()
            .to_owned(),
    })
}

fn write_score_calibration(
    dir: &Path,
    name: &str,
    domain_scores: Option<&[(String, u32)]>,
) -> TestResult<PathBuf> {
    let edges = [0_u32, 300_000, 700_000];
    let counts = [(5_u64, 95_u64), (50_u64, 50_u64), (95_u64, 5_u64)];
    let cal = ScoreCalibration::from_counts("cal:explain:v1", &edges, &counts)?;
    let extra = match domain_scores {
        None => String::new(),
        Some(entries) => {
            let mut map = String::new();
            for (idx, (cam, score)) in entries.iter().enumerate() {
                if idx > 0 {
                    map.push(',');
                }
                map.push_str(&format!("\"{}\":{score}", fss_cli::escape_json_str(cam)));
            }
            format!(",\"domain_scores_ppm\":{{{map}}}")
        }
    };
    let json = format!(
        "{{\"schema\":\"fss.score_calibration.v1\",\"generation\":\"{}\",\"digest\":\"{}\",\"bins\":[{{\"lo_ppm\":0,\"true_positives\":5,\"false_positives\":95}},{{\"lo_ppm\":300000,\"true_positives\":50,\"false_positives\":50}},{{\"lo_ppm\":700000,\"true_positives\":95,\"false_positives\":5}}]{extra}}}\n",
        cal.generation, cal.digest
    );
    let path = dir.join(name);
    fs::write(&path, json)?;
    Ok(path)
}

fn recording(
    start_frame: usize,
    initial_left: usize,
    step: isize,
    top: usize,
) -> TestResult<Vec<u8>> {
    let config = JpegConfig {
        quality: 90,
        subsampling: Subsampling::Grayscale,
        restart_interval: 0,
        custom_markers: Vec::new(),
    };
    let mut stream = Vec::new();
    for frame in 0..14_usize {
        let mut pixels = vec![40_u8; 96 * 48];
        if frame >= start_frame {
            let offset = (frame - start_frame) as isize * step;
            let left = (initial_left as isize + offset) as usize;
            if left + 16 <= 96 {
                for y in top..top + 16 {
                    for x in left..left + 16 {
                        pixels[y * 96 + x] = 220;
                    }
                }
            }
        }
        stream.extend(encode_jpeg(96, 48, &pixels, &config)?);
    }
    Ok(stream)
}

fn import(
    root: &Path,
    temp: &Path,
    name: &str,
    sensor: &str,
    receive_time_ns: i128,
    bytes: &[u8],
) -> TestResult<String> {
    let input = temp.join(format!("{name}.mjpeg"));
    fs::write(&input, bytes)?;
    let output = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .args(["import", "--root"])
        .arg(root)
        .args(["--site", SITE, "--input"])
        .arg(&input)
        .args([
            "--sensor",
            sensor,
            "--stream",
            &format!("stream:{name}"),
            "--receive-time-ns",
            &receive_time_ns.to_string(),
            "--capture-start-ns",
            "1000000000",
            "--capture-uncertainty-ns",
            "1000000",
            "--assumed-fps",
            "10",
            "--media-format",
            "mjpeg",
        ])
        .output()?;
    success(&output);
    let stdout = String::from_utf8(output.stdout)?;
    stdout
        .lines()
        .find_map(|line| line.strip_prefix("import_identity="))
        .map(str::to_owned)
        .ok_or_else(|| format!("missing import_identity in {stdout}").into())
}

fn published_corroborated(
    label: &str,
    shared_domain: bool,
) -> TestResult<(Directory, PathBuf, String)> {
    let directory = Directory::new(label)?;
    let root = directory.0.join("deployment");
    let first = import(
        &root,
        &directory.0,
        "north",
        "sensor:north",
        10_000_000_000_000,
        &recording(3, 0, 8, 8)?,
    )?;
    let second = import(
        &root,
        &directory.0,
        "east",
        "sensor:east",
        10_000_000_000_000,
        &recording(3, 80, -8, 8)?,
    )?;
    let run_corroborate = |extra: &[&str]| -> TestResult<Output> {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fss-event"));
        cmd.args(["corroborate", "--root"])
            .arg(&root)
            .args([
                "--site",
                SITE,
                "--camera",
                &format!("north:{first}"),
                "--camera",
                &format!("east:{second}"),
                "--ground",
                "north:1,0,0,0,1,0,0,0,1",
                "--ground",
                "east:-1,0,96,0,1,0,0,0,1",
                "--interpretation",
                "gray",
                "--zone",
                "door:56,0,40,48",
                "--time-gate-ns",
                "250000000",
                "--distance-gate",
                "16",
            ]);
        if shared_domain {
            cmd.args(["--failure-domain", "clock:shared-ntp=north,east"]);
        }
        cmd.args(extra);
        Ok(cmd.output()?)
    };
    let preview = run_corroborate(&[])?;
    success(&preview);
    let proposal = report_field(&preview, "proposal_digest")?;
    let committed = run_corroborate(&["--approve", &proposal])?;
    success(&committed);
    assert_eq!(report_field(&committed, "status")?, "published");
    Ok((directory, root, report_field(&committed, "event_id")?))
}

fn tree(root: &Path) -> TestResult<BTreeMap<PathBuf, ContentDigest>> {
    fn walk(root: &Path, path: &Path, output: &mut BTreeMap<PathBuf, ContentDigest>) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                walk(root, &entry.path(), output)?;
            } else {
                assert!(entry.file_type()?.is_file());
                output.insert(
                    entry.path().strip_prefix(root)?.to_path_buf(),
                    ContentDigest::sha256(&fs::read(entry.path())?),
                );
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result)?;
    Ok(result)
}

fn score_assumptions(
    root: &Path,
    event_id: &str,
    score: u32,
) -> TestResult<Vec<(String, u32)>> {
    let snapshot = read_deployment(root, &OrientLimits::default())?;
    let retained = snapshot
        .events
        .iter()
        .find(|retained| retained.event.event_id.as_str() == event_id)
        .ok_or("fixture event was not retained")?;
    let mut domains = BTreeMap::new();
    for edge in &retained.event.evidence {
        if matches!(
            edge.relation,
            EvidenceEdgeRelation::Supports | EvidenceEdgeRelation::Contradicts
        ) {
            assert!(!edge.failure_domain.is_empty());
            domains.insert(edge.failure_domain.clone(), score);
        }
    }
    if domains.is_empty() {
        return Err("fixture has no scored evidence domains".into());
    }
    Ok(domains.into_iter().collect())
}

fn explain(root: &Path, event_id: &str, calibration: Option<&Path>) -> TestResult<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fss"));
    command
        .args(["explain", "--json", "--root"])
        .arg(root)
        .args(["--event-id", event_id, "--view", "forensic"]);
    if let Some(path) = calibration {
        command.arg("--score-calibration").arg(path);
    }
    Ok(command.output()?)
}

fn propositions(value: &Value) -> TestResult<&[Value]> {
    array(get(get(get(value, "payload")?, "epistemic")?, "propositions")?)
}

fn posterior(rows: &[Value]) -> TestResult<&Value> {
    rows.iter()
        .find(|row| {
            row.object()
                .and_then(|object| object.get("id"))
                .and_then(Value::text)
                .is_some_and(|id| {
                    id.starts_with("claim:event-fusion:") && id.ends_with(":posterior-llr")
                })
        })
        .ok_or_else(|| "missing posterior proposition".into())
}


fn caller_assumptions(rows: &[Value]) -> TestResult<&Value> {
    rows.iter()
        .find(|row| {
            row.object()
                .and_then(|object| object.get("id"))
                .and_then(Value::text)
                .is_some_and(|id| {
                    id.starts_with("claim:event-fusion:") && id.ends_with(":caller-assumptions")
                })
        })
        .ok_or_else(|| "missing caller assumptions proposition".into())
}

fn assert_unknown_coverage(rows: &[Value]) -> TestResult {
    let claim = caller_assumptions(rows)?;
    let statement = text(get(claim, "statement")?)?;
    assert!(statement.contains("coverage=gap"), "{statement}");
    assert!(statement.contains("caller-declared scores"), "{statement}");
    assert!(
        statement.contains("no current physical coverage witness was supplied"),
        "{statement}"
    );
    assert_eq!(text(get(claim, "state")?)?, "estimated");
    assert_eq!(text(get(claim, "provenance")?)?, "derived");
    Ok(())
}

fn refusal(output: &Output, error: &str) -> TestResult {
    assert!(
        !output.status.success(),
        "unexpected success: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let document = parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(get(&document, "outcome")?)?, "refused");
    assert_eq!(text(get(&document, "errorId")?)?, error);
    assert!(matches!(get(&document, "payload")?, Value::Null));
    Ok(())
}

#[test]
fn explicit_scores_preserve_shared_calibration_and_unknown_coverage() -> TestResult {
    let (directory, root, event_id) = published_corroborated("explicit", false)?;
    let assumptions = score_assumptions(&root, &event_id, 900_000)?;
    assert!(assumptions.len() >= 2, "fixture must declare distinct domains");
    let calibration =
        write_score_calibration(&directory.0, "explicit.json", Some(&assumptions))?;
    let before = tree(&root)?;

    let baseline = explain(&root, &event_id, None)?;
    success(&baseline);
    assert_eq!(baseline.stdout, explain(&root, &event_id, None)?.stdout);

    let output = explain(&root, &event_id, Some(&calibration))?;
    success(&output);
    let document = parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(get(&document, "operationId")?)?, "AOP-011");
    assert_eq!(text(get(&document, "outcome")?)?, "ok");
    let rows = propositions(&document)?;
    let claim = posterior(rows)?;
    let statement = text(get(claim, "statement")?)?;
    assert!(statement.contains("supporting_clusters=1"), "{statement}");
    assert!(!statement.contains("AlertWarranted"), "{statement}");
    assert_unknown_coverage(rows)?;
    let clusters: Vec<_> = rows
        .iter()
        .filter(|row| {
            row.object()
                .and_then(|object| object.get("id"))
                .and_then(Value::text)
                .is_some_and(|id| id.contains(":cluster:"))
        })
        .collect();
    assert_eq!(clusters.len(), 1, "one calibration is one shared failure domain");
    assert!(
        text(get(clusters[0], "statement")?)?.contains("calibration:"),
        "shared calibration provenance must survive projection"
    );
    assert_eq!(before, tree(&root)?, "explanation must not mutate retained state");
    Ok(())
}

#[test]
fn missing_unused_numeric_and_conflicting_score_mappings_refuse_without_writes() -> TestResult {
    let (directory, root, event_id) = published_corroborated("mapping-refusals", false)?;
    let assumptions = score_assumptions(&root, &event_id, 900_000)?;
    let before = tree(&root)?;
    let missing = write_score_calibration(&directory.0, "missing.json", None)?;
    refusal(
        &explain(&root, &event_id, Some(&missing))?,
        "ERR-FUSION-INPUT-INVALID-001",
    )?;

    let incomplete = write_score_calibration(
        &directory.0,
        "incomplete.json",
        Some(&assumptions[1..]),
    )?;
    refusal(
        &explain(&root, &event_id, Some(&incomplete))?,
        "ERR-FUSION-INPUT-INVALID-001",
    )?;

    let mut unused = assumptions.clone();
    unused.push(("not-a-retained-domain".to_owned(), 900_000));
    let unused = write_score_calibration(&directory.0, "unused.json", Some(&unused))?;
    refusal(
        &explain(&root, &event_id, Some(&unused))?,
        "ERR-FUSION-INPUT-INVALID-001",
    )?;

    let positional: Vec<_> = assumptions
        .iter()
        .enumerate()
        .map(|(index, (_, score))| (index.to_string(), *score))
        .collect();
    let positional =
        write_score_calibration(&directory.0, "positional.json", Some(&positional))?;
    refusal(
        &explain(&root, &event_id, Some(&positional))?,
        "ERR-FUSION-INPUT-INVALID-001",
    )?;

    let valid = write_score_calibration(&directory.0, "valid.json", Some(&assumptions))?;
    let original = fs::read_to_string(valid)?;
    for (name, score) in [("conflicting-alias", 100_000), ("duplicate-alias", 900_000)] {
        let path = directory.0.join(format!("{name}.json"));
        let head = original.trim_end().strip_suffix('}').ok_or("calibration shape")?;
        fs::write(
            &path,
            format!(
                "{head},\"camera_scores_ppm\":{{\"{}\":{score}}}}}\n",
                fss_cli::escape_json_str(&assumptions[0].0)
            ),
        )?;
        refusal(
            &explain(&root, &event_id, Some(&path))?,
            "ERR-FUSION-INPUT-INVALID-001",
        )?;
    }
    assert_eq!(before, tree(&root)?, "refused explanations must not mutate retained state");
    Ok(())
}

#[test]
fn low_caller_scores_never_assert_physical_absence_or_create_independence() -> TestResult {
    let (directory, root, event_id) = published_corroborated("low-scores", true)?;
    let assumptions = score_assumptions(&root, &event_id, 100_000)?;
    let calibration =
        write_score_calibration(&directory.0, "low.json", Some(&assumptions))?;
    let before = tree(&root)?;
    let output = explain(&root, &event_id, Some(&calibration))?;
    success(&output);
    let document = parse(std::str::from_utf8(&output.stdout)?)?;
    let rows = propositions(&document)?;
    let claim = posterior(rows)?;
    let statement = text(get(claim, "statement")?)?;
    assert!(!statement.contains("NoActivity"), "{statement}");
    assert_unknown_coverage(rows)?;
    assert_ne!(text(get(claim, "state")?)?, "known");
    assert_eq!(before, tree(&root)?);
    Ok(())
}

#[test]
fn calibration_count_tampering_and_insufficient_complete_output_budget_refuse() -> TestResult {
    let (directory, root, event_id) = published_corroborated("bounds", false)?;
    let assumptions = score_assumptions(&root, &event_id, 900_000)?;
    let valid =
        write_score_calibration(&directory.0, "valid.json", Some(&assumptions))?;
    let raw = fs::read_to_string(&valid)?;
    let tampered = directory.0.join("tampered.json");
    fs::write(&tampered, raw.replace("\"true_positives\":95", "\"true_positives\":94"))?;
    let before = tree(&root)?;
    refusal(
        &explain(&root, &event_id, Some(&tampered))?,
        "ERR-FUSION-INPUT-INVALID-001",
    )?;

    let baseline = explain(&root, &event_id, None)?;
    success(&baseline);
    let document = parse(std::str::from_utf8(&baseline.stdout)?)?;
    let tokens = get(get(get(&document, "budgets")?, "consumed")?, "tokens")?
        .integer()
        .ok_or("missing consumed tokens")?;
    let tight = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"])
        .arg(&root)
        .args([
            "--event-id", &event_id, "--view", "forensic",
            "--budget-tokens", &(tokens + 10).to_string(), "--score-calibration",
        ])
        .arg(&valid)
        .output()?;
    refusal(&tight, "ERR-AGENT-CONTEXT-INCOMPLETE-001")?;
    assert_eq!(before, tree(&root)?);
    Ok(())
}

#[test]
fn raw_assumptions_bind_receipts_while_map_order_is_semantically_irrelevant() -> TestResult {
    let (directory, root, event_id) = published_corroborated("assumption-identity", false)?;
    let assumptions = score_assumptions(&root, &event_id, 900_000)?;
    let before = tree(&root)?;
    let path = write_score_calibration(&directory.0, "identity.json", Some(&assumptions))?;
    let first = explain(&root, &event_id, Some(&path))?;
    success(&first);

    let mut reversed = assumptions.clone();
    reversed.reverse();
    write_score_calibration(&directory.0, "identity.json", Some(&reversed))?;
    let reordered = explain(&root, &event_id, Some(&path))?;
    success(&reordered);
    assert_eq!(first.stdout, reordered.stdout, "map order cannot change a semantic receipt");

    // The two scores occupy the same calibrated bin, so this specifically checks that the
    // original assumptions remain bound even when the numerical fusion inputs do not change.
    let calibration = ScoreCalibration::from_counts(
        "cal:explain:v1",
        &[0, 300_000, 700_000],
        &[(5, 95), (50, 50), (95, 5)],
    )?;
    assert_eq!(calibration.calibrate(900_000), calibration.calibrate(850_000));
    let mut changed = assumptions;
    changed[0].1 = 850_000;
    write_score_calibration(&directory.0, "identity.json", Some(&changed))?;
    let changed_output = explain(&root, &event_id, Some(&path))?;
    success(&changed_output);
    let first_document = parse(std::str::from_utf8(&first.stdout)?)?;
    let changed_document = parse(std::str::from_utf8(&changed_output.stdout)?)?;
    assert_ne!(
        text(get(&first_document, "decisionFingerprint")?)?,
        text(get(&changed_document, "decisionFingerprint")?)?,
        "different original score assumptions require different receipts"
    );
    assert_eq!(before, tree(&root)?);
    Ok(())
}
