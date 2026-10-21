#![forbid(unsafe_code)]
//! Integration tests for `fss-event corroborate --score-calibration` (`fss-808pm` / `fss-13suu`).
//!
//! Verifies:
//! 1. Independent multi-camera corroboration (`AlertWarranted` + 2-domain counterfactual minimal-flip set);
//! 2. Common-cause failure-domain collapse (`SingleSourceOnly` under Fréchet-Hoeffding hull, NEG-003);
//! 3. Cross-camera conflict detection (`Conflicted` disposition with opposing cluster directions);
//! 4. Byte-for-byte backward compatibility when `--score-calibration` is omitted, plus failure-first
//!    refusals (corrupted calibration digest, invalid fusion policy, work-budget exhaustion).

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_cli::json_input::{Value, parse};
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

fn emit_log(step: &str, case: &str, outcome: &str) {
    println!(
        "{{\"bead\":\"fss-13suu\",\"step\":\"{step}\",\"case\":\"{case}\",\"outcome\":\"{outcome}\",\"verdict\":\"valid\"}}"
    );
}

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
    let input = directory
        .0
        .join(format!("{sensor}.mjpeg").replace(':', "-"));
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
    tamper_digest: bool,
) -> TestResult<(PathBuf, ScoreCalibration)> {
    let edges = [0_u32, 500_000];
    // Bin 0 (0..499_999): 2 TP, 98 FP -> strongly negative LLR
    // Bin 1 (500_000..1_000_000): 98 TP, 2 FP -> strongly positive LLR
    let counts = [(2_u64, 98_u64), (98_u64, 2_u64)];
    let cal = ScoreCalibration::from_counts("cal:corroboration-test:v1", &edges, &counts)?;
    let digest = if tamper_digest {
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned()
    } else {
        cal.digest.to_text()
    };
    let extra = camera_scores_json.map_or_else(String::new, |s| format!(",\"camera_scores_ppm\":{s}"));
    let json = format!(
        "{{\"schema\":\"fss.score_calibration.v1\",\"generation\":\"{}\",\"digest\":\"{}\",\"bins\":[{{\"lo_ppm\":0,\"true_positives\":2,\"false_positives\":98}},{{\"lo_ppm\":500000,\"true_positives\":98,\"false_positives\":2}}]{extra}}}",
        cal.generation, digest
    );
    let path = dir.join(filename);
    fs::write(&path, json)?;
    Ok((path, cal))
}

#[test]
fn independent_multi_camera_corroboration_produces_alert_warranted_and_counterfactuals() -> TestResult {
    let (directory, pair) = setup_pair("independent")?;
    let (cal_path, cal) = write_calibration_file(&directory.0, "cal.json", None, false)?;
    let cal_str = cal_path.to_str().ok_or("utf8 path")?;

    let output = corroborate(
        &directory.root(),
        &pair,
        &["--score-calibration", cal_str, "--fusion-policy", "1000,0,-1000"],
    )?;
    success(&output);
    let doc = parse(std::str::from_utf8(&output.stdout)?)?;
    let root_obj = doc.object().ok_or("root object")?;
    let fusion = root_obj
        .get("fusion_assessment")
        .ok_or("missing fusion_assessment")?
        .object()
        .ok_or("fusion_assessment object")?;
    assert_eq!(
        fusion.get("format").and_then(Value::text),
        Some("fss.corroboration_fusion_assessment.v1")
    );
    assert_eq!(
        fusion.get("score_calibration_digest").and_then(Value::text),
        Some(cal.digest.to_text().as_str())
    );
    let candidates = fusion
        .get("candidates")
        .and_then(Value::array)
        .ok_or("candidates array")?;
    assert_eq!(candidates.len(), 1);
    let cand = candidates[0].object().ok_or("candidate object")?;
    assert_eq!(cand.get("decision").and_then(Value::text), Some("alert"));
    assert_eq!(
        cand.get("disposition").and_then(Value::text),
        Some("AlertWarranted")
    );
    assert_eq!(cand.get("supporting_clusters").and_then(Value::integer), Some(2));
    assert_eq!(
        cand.get("contradicting_clusters").and_then(Value::integer),
        Some(0)
    );
    let posterior = cand
        .get("posterior_llr_mban")
        .and_then(Value::array)
        .ok_or("posterior_llr_mban")?;
    let lo = posterior[0].integer().ok_or("lo")?;
    let hi = posterior[1].integer().ok_or("hi")?;
    assert!(lo >= 1000 && hi >= lo, "expected lo >= 1000, got [{lo}, {hi}]");

    let counterfactuals = cand
        .get("counterfactuals")
        .and_then(Value::array)
        .ok_or("counterfactuals array")?;
    assert_eq!(counterfactuals.len(), 2);
    for cf in counterfactuals {
        let cf_obj = cf.object().ok_or("cf object")?;
        assert_eq!(cf_obj.get("flips_decision").and_then(Value::boolean), Some(true));
        assert_ne!(cf_obj.get("decision").and_then(Value::text), Some("alert"));
    }
    emit_log("corroborate_fusion", "independent_multi_camera_alert_warranted", "ok");
    Ok(())
}

#[test]
fn common_cause_failure_domain_collapse_prevents_self_corroboration() -> TestResult {
    let (directory, pair) = setup_pair("common-cause")?;
    let (cal_path, _) = write_calibration_file(&directory.0, "cal.json", None, false)?;
    let cal_str = cal_path.to_str().ok_or("utf8 path")?;

    let output = corroborate(
        &directory.root(),
        &pair,
        &[
            "--failure-domain",
            "clock:shared-ntp=east,west",
            "--score-calibration",
            cal_str,
            "--fusion-policy",
            "1000,0,-1000",
        ],
    )?;
    success(&output);
    let doc = parse(std::str::from_utf8(&output.stdout)?)?;
    let fusion = doc
        .object()
        .and_then(|o| o.get("fusion_assessment"))
        .and_then(Value::object)
        .ok_or("fusion_assessment")?;
    let candidates = fusion
        .get("candidates")
        .and_then(Value::array)
        .ok_or("candidates")?;
    assert_eq!(candidates.len(), 1);
    let cand = candidates[0].object().ok_or("candidate")?;
    // Both cameras collapse into 1 cluster via Frechet-Hoeffding hull and cannot meet 2-domain support.
    assert_eq!(cand.get("supporting_clusters").and_then(Value::integer), Some(1));
    assert_eq!(
        cand.get("disposition").and_then(Value::text),
        Some("SingleSourceOnly")
    );
    let clusters = cand.get("clusters").and_then(Value::array).ok_or("clusters")?;
    assert_eq!(clusters.len(), 1);
    let reasons = cand.get("reasons").and_then(Value::array).ok_or("reasons")?;
    assert!(
        reasons
            .iter()
            .any(|r| r.text() == Some("insufficient_independent_support"))
    );
    emit_log("corroborate_fusion", "common_cause_failure_domain_collapse", "ok");
    Ok(())
}

#[test]
fn cross_camera_conflict_detection_surfaces_conflicted_disposition() -> TestResult {
    let (directory, pair) = setup_pair("conflict")?;
    // east has high score (900_000 -> bin 1 positive LLR), west has low score (100_000 -> bin 0 negative LLR)
    let (cal_path, _) = write_calibration_file(
        &directory.0,
        "cal-conflict.json",
        Some("{\"east\":900000,\"west\":100000}"),
        false,
    )?;
    let cal_str = cal_path.to_str().ok_or("utf8 path")?;

    let output = corroborate(
        &directory.root(),
        &pair,
        &["--score-calibration", cal_str, "--fusion-policy", "1000,0,-1000"],
    )?;
    success(&output);
    let doc = parse(std::str::from_utf8(&output.stdout)?)?;
    let fusion = doc
        .object()
        .and_then(|o| o.get("fusion_assessment"))
        .and_then(Value::object)
        .ok_or("fusion_assessment")?;
    let candidates = fusion
        .get("candidates")
        .and_then(Value::array)
        .ok_or("candidates")?;
    let cand = candidates[0].object().ok_or("candidate")?;
    assert_eq!(
        cand.get("disposition").and_then(Value::text),
        Some("Conflicted")
    );
    assert_eq!(
        cand.get("knowledge_state").and_then(Value::text),
        Some("conflicted")
    );
    assert_eq!(cand.get("supporting_clusters").and_then(Value::integer), Some(1));
    assert_eq!(
        cand.get("contradicting_clusters").and_then(Value::integer),
        Some(1)
    );
    let reasons = cand.get("reasons").and_then(Value::array).ok_or("reasons")?;
    assert!(reasons.iter().any(|r| r.text() == Some("conflicting_evidence")));
    emit_log("corroborate_fusion", "cross_camera_conflict_detection", "ok");
    Ok(())
}

#[test]
fn backward_compatibility_and_failure_first_refusals() -> TestResult {
    let (directory, pair) = setup_pair("compat-and-failures")?;
    let baseline = corroborate(&directory.root(), &pair, &[])?;
    success(&baseline);
    let baseline_text = String::from_utf8(baseline.stdout.clone())?;
    assert!(!baseline_text.contains("fusion_assessment"));

    let (cal_path, _) = write_calibration_file(&directory.0, "cal.json", None, false)?;
    let cal_str = cal_path.to_str().ok_or("utf8 path")?;
    let with_fusion = corroborate(&directory.root(), &pair, &["--score-calibration", cal_str])?;
    success(&with_fusion);
    let with_fusion_text = String::from_utf8(with_fusion.stdout)?;
    let prefix = with_fusion_text
        .split(",\"fusion_assessment\":")
        .next()
        .ok_or("missing fusion_assessment suffix")?;
    assert_eq!(
        format!("{prefix}}}\n"),
        baseline_text,
        "report prefix before fusion_assessment must be 100% byte-identical to baseline"
    );
    emit_log("corroborate_fusion", "backward_compatibility_byte_identical", "ok");

    // Failure-first 1: tampered score calibration digest must fail closed with ERR-CORROBORATE-PLAN-INVALID-001
    let (tampered_path, _) = write_calibration_file(&directory.0, "tampered.json", None, true)?;
    let tampered_str = tampered_path.to_str().ok_or("utf8 path")?;
    let tampered_out = corroborate(
        &directory.root(),
        &pair,
        &["--score-calibration", tampered_str],
    )?;
    assert!(!tampered_out.status.success());
    let stderr = String::from_utf8_lossy(&tampered_out.stderr);
    assert!(
        stderr.contains("refusal_id=ERR-CORROBORATE-PLAN-INVALID-001"),
        "unexpected stderr: {stderr}"
    );
    emit_log("corroborate_fusion", "tampered_calibration_digest_refusal", "error");

    // Failure-first 2: --fusion-policy without --score-calibration or inverted thresholds refuses
    let orphan_policy = corroborate(
        &directory.root(),
        &pair,
        &["--fusion-policy", "1000,0,-1000"],
    )?;
    assert!(!orphan_policy.status.success());
    let inverted_policy = corroborate(
        &directory.root(),
        &pair,
        &[
            "--score-calibration",
            cal_str,
            "--fusion-policy",
            "100,500,-1000",
        ],
    )?;
    assert!(!inverted_policy.status.success());
    emit_log("corroborate_fusion", "invalid_fusion_policy_refusal", "error");

    // Failure-first 3: work budget exhaustion fails closed
    let budget_exhausted = corroborate(
        &directory.root(),
        &pair,
        &["--score-calibration", cal_str, "--work-units", "1"],
    )?;
    assert!(!budget_exhausted.status.success());
    emit_log("corroborate_fusion", "work_budget_exhausted_refusal", "budget_exhausted");
    Ok(())
}
