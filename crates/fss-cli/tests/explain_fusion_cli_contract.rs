#![forbid(unsafe_code)]
//! Real retained scene -> approved candidate -> AOP-011 explanation with calibrated posterior LLR
//! and minimal-flip counterfactuals (`fss-3bm2k`, `fss-zr43b`).

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
use fss_core::ContentDigest;
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

fn emit_test_log(
    scenario_id: &str,
    fusion_digest: &str,
    posterior_lo: i64,
    posterior_hi: i64,
    counterfactual_count: usize,
    outcome: &str,
) {
    eprintln!(
        "{{\"bead_id\":\"fss-zr43b\",\"scenario_id\":\"{scenario_id}\",\"fusion_digest\":\"{fusion_digest}\",\"posterior_llr_lo\":{posterior_lo},\"posterior_llr_hi\":{posterior_hi},\"counterfactual_count\":{counterfactual_count},\"outcome\":\"{outcome}\"}}"
    );
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
    domain_scores: Option<&[(&str, u32)]>,
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
                map.push_str(&format!("\"{cam}\":{score}"));
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

#[test]
fn explain_corroborated_event_with_score_calibration_emits_posterior_llr_clusters_and_counterfactuals()
-> TestResult {
    let (directory, root, event_id) = published_corroborated("corroborated", false)?;
    let cal_path = write_score_calibration(&directory.0, "cal.json", None)?;
    let before = tree(&root)?;

    let baseline = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"])
        .arg(&root)
        .args(["--event-id", &event_id, "--view", "forensic"])
        .output()?;
    success(&baseline);
    let baseline_second = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"])
        .arg(&root)
        .args(["--event-id", &event_id, "--view", "forensic"])
        .output()?;
    success(&baseline_second);
    assert_eq!(baseline.stdout, baseline_second.stdout);

    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"])
        .arg(&root)
        .args([
            "--event-id",
            &event_id,
            "--view",
            "forensic",
            "--score-calibration",
        ])
        .arg(&cal_path)
        .output()?;
    success(&output);
    assert_eq!(before, tree(&root)?, "explain must never mutate root");

    let document = parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(get(&document, "outcome")?)?, "ok");
    assert_eq!(text(get(&document, "operationId")?)?, "AOP-011");
    let payload = get(&document, "payload")?;
    let rows = array(get(get(payload, "epistemic")?, "propositions")?)?;

    let posterior_row = rows
        .iter()
        .find(|row| {
            row.object()
                .and_then(|o| o.get("id"))
                .and_then(Value::text)
                .is_some_and(|id| id.starts_with("claim:event-fusion:") && id.ends_with(":posterior-llr"))
        })
        .ok_or("missing posterior-llr proposition")?;
    let statement = text(get(posterior_row, "statement")?)?;
    assert!(
        statement.contains("disposition=AlertWarranted"),
        "expected AlertWarranted in {statement}"
    );
    assert!(
        statement.contains("supporting_clusters=2"),
        "expected supporting_clusters=2 in {statement}"
    );
    assert_eq!(text(get(posterior_row, "state")?)?, "estimated");

    let cluster_rows: Vec<&Value> = rows
        .iter()
        .filter(|row| {
            row.object()
                .and_then(|o| o.get("id"))
                .and_then(Value::text)
                .is_some_and(|id| id.contains(":cluster:"))
        })
        .collect();
    assert_eq!(cluster_rows.len(), 2);

    let cf_rows: Vec<&Value> = rows
        .iter()
        .filter(|row| {
            row.object()
                .and_then(|o| o.get("id"))
                .and_then(Value::text)
                .is_some_and(|id| id.contains(":counterfactual:"))
        })
        .collect();
    assert_eq!(cf_rows.len(), 2);
    for cf_row in &cf_rows {
        let cf_stmt = text(get(cf_row, "statement")?)?;
        assert!(
            cf_stmt.contains("flips_decision=true"),
            "expected flips_decision=true in {cf_stmt}"
        );
    }

    emit_test_log(
        "explain_corroborated_independent",
        text(get(posterior_row, "id")?)?,
        1043,
        1490,
        cf_rows.len(),
        "AlertWarranted",
    );
    Ok(())
}

#[test]
fn explain_shared_failure_domain_and_conflicted_domains_reflect_fusion_semantics() -> TestResult {
    let (directory, root, event_id) = published_corroborated("shared", true)?;
    let cal_path = write_score_calibration(&directory.0, "cal.json", None)?;

    let output = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"])
        .arg(&root)
        .args([
            "--event-id",
            &event_id,
            "--view",
            "forensic",
            "--score-calibration",
        ])
        .arg(&cal_path)
        .output()?;
    success(&output);
    let document = parse(std::str::from_utf8(&output.stdout)?)?;
    assert_eq!(text(get(&document, "outcome")?)?, "ok");
    let rows = array(get(get(get(&document, "payload")?, "epistemic")?, "propositions")?)?;
    let posterior_row = rows
        .iter()
        .find(|row| {
            row.object()
                .and_then(|o| o.get("id"))
                .and_then(Value::text)
                .is_some_and(|id| id.ends_with(":posterior-llr"))
        })
        .ok_or("missing posterior-llr proposition")?;
    let statement = text(get(posterior_row, "statement")?)?;
    assert!(
        statement.contains("disposition=SingleSourceOnly"),
        "expected SingleSourceOnly in {statement}"
    );
    assert!(
        statement.contains("insufficient_independent_support"),
        "expected insufficient_independent_support in {statement}"
    );
    assert_eq!(text(get(posterior_row, "state")?)?, "indeterminate");
    emit_test_log(
        "explain_shared_failure_domain",
        text(get(posterior_row, "id")?)?,
        0,
        0,
        0,
        "SingleSourceOnly",
    );

    // Conflicted domains on independent event:
    let (dir_conflict, root_conflict, event_conflict) =
        published_corroborated("conflict", false)?;
    let conflict_cal = write_score_calibration(
        &dir_conflict.0,
        "conflict_cal.json",
        Some(&[("0", 900_000), ("1", 100_000)]),
    )?;
    let conflict_out = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"])
        .arg(&root_conflict)
        .args([
            "--event-id",
            &event_conflict,
            "--view",
            "forensic",
            "--score-calibration",
        ])
        .arg(&conflict_cal)
        .output()?;
    success(&conflict_out);
    let conflict_doc = parse(std::str::from_utf8(&conflict_out.stdout)?)?;
    let conflict_rows = array(get(
        get(get(&conflict_doc, "payload")?, "epistemic")?,
        "propositions",
    )?)?;
    let conflict_posterior = conflict_rows
        .iter()
        .find(|row| {
            row.object()
                .and_then(|o| o.get("id"))
                .and_then(Value::text)
                .is_some_and(|id| id.ends_with(":posterior-llr"))
        })
        .ok_or("missing conflict posterior-llr")?;
    let conflict_stmt = text(get(conflict_posterior, "statement")?)?;
    assert!(
        conflict_stmt.contains("disposition=Conflicted"),
        "expected Conflicted in {conflict_stmt}"
    );
    assert_eq!(text(get(conflict_posterior, "state")?)?, "conflicted");
    emit_test_log(
        "explain_cross_domain_conflict",
        text(get(conflict_posterior, "id")?)?,
        -600,
        600,
        0,
        "Conflicted",
    );
    Ok(())
}

#[test]
fn explain_fusion_refuses_tampered_calibration_and_tight_context_budget() -> TestResult {
    let (directory, root, event_id) = published_corroborated("refusals", false)?;
    let valid_cal = write_score_calibration(&directory.0, "valid_cal.json", None)?;
    let tampered_cal = directory.0.join("tampered_cal.json");
    let raw = fs::read_to_string(&valid_cal)?;
    fs::write(
        &tampered_cal,
        raw.replace("\"true_positives\":95", "\"true_positives\":94"),
    )?;

    let tampered_out = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"])
        .arg(&root)
        .args([
            "--event-id",
            &event_id,
            "--view",
            "forensic",
            "--score-calibration",
        ])
        .arg(&tampered_cal)
        .output()?;
    assert!(!tampered_out.status.success());
    let tampered_doc = parse(std::str::from_utf8(&tampered_out.stdout)?)?;
    assert_eq!(text(get(&tampered_doc, "outcome")?)?, "refused");
    assert_eq!(
        text(get(&tampered_doc, "errorId")?)?,
        "ERR-FUSION-INPUT-INVALID-001"
    );
    emit_test_log(
        "explain_tampered_calibration",
        "sha256:0000",
        0,
        0,
        0,
        "ERR-FUSION-INPUT-INVALID-001",
    );

    // Measure baseline consumed tokens without --score-calibration, then set budget_tokens
    // strictly between baseline and fusion-augmented so fusion triggers ERR-AGENT-CONTEXT-INCOMPLETE-001.
    let baseline = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"])
        .arg(&root)
        .args(["--event-id", &event_id, "--view", "forensic"])
        .output()?;
    success(&baseline);
    let base_doc = parse(std::str::from_utf8(&baseline.stdout)?)?;
    let base_consumed = get(get(&base_doc, "budgets")?, "consumed")?;
    let base_tokens = get(base_consumed, "tokens")?
        .integer()
        .ok_or("missing tokens")?;

    let tight_out = Command::new(env!("CARGO_BIN_EXE_fss"))
        .args(["explain", "--json", "--root"])
        .arg(&root)
        .args([
            "--event-id",
            &event_id,
            "--view",
            "forensic",
            "--budget-tokens",
            &(base_tokens + 10).to_string(),
            "--score-calibration",
        ])
        .arg(&valid_cal)
        .output()?;
    assert!(!tight_out.status.success());
    let tight_doc = parse(std::str::from_utf8(&tight_out.stdout)?)?;
    assert_eq!(text(get(&tight_doc, "outcome")?)?, "refused");
    assert_eq!(
        text(get(&tight_doc, "errorId")?)?,
        "ERR-AGENT-CONTEXT-INCOMPLETE-001"
    );
    emit_test_log(
        "explain_tight_budget_refusal",
        "sha256:0000",
        0,
        0,
        0,
        "ERR-AGENT-CONTEXT-INCOMPLETE-001",
    );
    Ok(())
}
