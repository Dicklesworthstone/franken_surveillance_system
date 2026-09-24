#![forbid(unsafe_code)]
//! Cross-process recording execution, verified restart reuse, and event-report interoperability.

use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fss_core::ContentDigest;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;
const JPEG: &[u8] = include_bytes!("fixtures/retained_file_8x8.jpg");
const MODEL: &[u8] = include_bytes!("fixtures/detector_rows_8x8.fssmodel");
const MODEL_DIGEST: &str =
    "sha256:2b1c64990f1c1820b3bdb77ea32cc25b2fff484db11fe7d68b0e1f04bd2c45c8";

struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for n in 0..100 {
            let path = std::env::temp_dir().join(format!(
                "fss-analyze-cli-{label}-{}-{n}",
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
}
impl Drop for Directory {
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
fn field(output: &Output, key: &str) -> TestResult<String> {
    std::str::from_utf8(&output.stdout)?
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{key}=")))
        .map(str::to_owned)
        .ok_or_else(|| std::io::Error::other(format!("missing field {key}")).into())
}
struct Fixture {
    dir: Directory,
    root: PathBuf,
    source: PathBuf,
    model: PathBuf,
    import: String,
}
fn fixture(label: &str) -> TestResult<Fixture> {
    let dir = Directory::new(label)?;
    let root = dir.0.join("deployment");
    let source = dir.0.join("source.mjpeg");
    let model = dir.0.join("model.fssmodel");
    assert_eq!(ContentDigest::sha256(MODEL).to_text(), MODEL_DIGEST);
    fs::write(&source, [JPEG, JPEG, JPEG].concat())?;
    fs::write(&model, MODEL)?;
    let result = Command::new(env!("CARGO_BIN_EXE_fss-file"))
        .arg("import")
        .arg("--root")
        .arg(&root)
        .args([
            "--site",
            "site:analyze-cli",
            "--sensor",
            "sensor:analyze-cli",
            "--stream",
            "stream:analyze-cli",
            "--receive-time-ns",
            "1000000000",
        ])
        .arg("--input")
        .arg(&source)
        .output()?;
    success(&result);
    let import = field(&result, "import_identity")?;
    Ok(Fixture {
        dir,
        root,
        source,
        model,
        import,
    })
}
fn command(f: &Fixture, report: &Path, frames: usize, from_file: bool) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_fss-infer"));
    c.arg("analyze")
        .arg("--root")
        .arg(&f.root)
        .args([
            "--site",
            "site:analyze-cli",
            "--import-id",
            &f.import,
            "--first-segment",
            "0",
            "--frames",
            &frames.to_string(),
            "--interpretation",
            "gray",
            "--model-digest",
            MODEL_DIGEST,
            "--output-port",
            "detections",
            "--labels",
            "vehicle,animal",
            "--box-format",
            "xyxy",
            "--coordinates",
            "normalized",
        ])
        .arg("--report-out")
        .arg(report);
    if from_file {
        c.arg("--model").arg(&f.model);
    }
    c
}
// Exact snapshots of the tiny test deployment, used only to assert refusal makes no changes.
fn snapshot(root: &Path) -> TestResult<BTreeMap<PathBuf, Vec<u8>>> {
    fn walk(path: &Path, root: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> TestResult {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                walk(&entry.path(), root, files)?;
            } else {
                files.insert(
                    entry.path().strip_prefix(root)?.to_path_buf(),
                    fs::read(entry.path())?,
                );
            }
        }
        Ok(())
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files)?;
    Ok(files)
}

#[test]
fn one_command_report_replays_without_external_inputs_and_prepares_an_event() -> TestResult {
    let f = fixture("replay")?;
    let report = f.dir.0.join("report.bin");
    let runs = f.dir.0.join("runs.txt");
    let first = command(&f, &report, 3, true)
        .arg("--runs-out")
        .arg(&runs)
        .output()?;
    success(&first);
    assert_eq!(field(&first, "complete")?, "true");
    assert_eq!(field(&first, "completed_inferences")?, "3");
    assert_eq!(field(&first, "new_decodes")?, "3");
    assert_eq!(field(&first, "new_inferences")?, "3");
    let bytes = fs::read(&report)?;
    assert_eq!(
        ContentDigest::sha256(&bytes).to_text(),
        field(&first, "report_digest")?
    );
    let run_list = fs::read_to_string(&runs)?;
    assert_eq!(run_list.lines().count(), 3);
    for segment in 0..3 {
        assert!(run_list.contains(&format!(
            "{segment} {}\n",
            field(&first, &format!("run.{segment}"))?
        )));
    }
    fs::remove_file(&f.source)?;
    fs::remove_file(&f.model)?;
    let before = snapshot(&f.root)?;
    let repeated_path = f.dir.0.join("repeated.bin");
    let repeated = command(&f, &repeated_path, 3, false)
        .args(["--decode-work-units", "0", "--max-macs", "0"])
        .output()?;
    success(&repeated);
    assert_eq!(fs::read(&repeated_path)?, bytes);
    assert_eq!(
        field(&repeated, "authority_sequence")?,
        field(&first, "authority_sequence")?
    );
    assert_eq!(field(&repeated, "new_inferences")?, "0");
    assert_eq!(field(&repeated, "reused_decodes")?, "3");
    assert_eq!(field(&repeated, "reused_inferences")?, "3");
    assert_eq!(field(&repeated, "decode_work_units")?, "0");
    assert_eq!(field(&repeated, "model_work_charged")?, "0");
    assert_eq!(snapshot(&f.root)?, before);
    let event_path = f.dir.0.join("candidate.json");
    let prepared = Command::new(env!("CARGO_BIN_EXE_fss-event"))
        .arg("prepare")
        .arg("--root")
        .arg(&f.root)
        .args(["--site", "site:analyze-cli"])
        .arg("--report")
        .arg(&repeated_path)
        .args([
            "--report-digest",
            &field(&repeated, "report_digest")?,
            "--track",
            &field(&repeated, "track")?,
        ])
        .arg("--event-out")
        .arg(&event_path)
        .output()?;
    success(&prepared);
    let json = fs::read_to_string(event_path)?;
    assert!(json.contains("\"state\":\"indeterminate\""));
    assert!(json.contains("\"kind\":\"unclassified\""));
    assert!(json.contains("\"abstained\":true"));
    assert_eq!(
        snapshot(&f.root)?,
        before,
        "event preparation cannot publish authority"
    );
    Ok(())
}

#[test]
fn exhausted_model_budget_reports_pending_frame_then_reuses_its_decode() -> TestResult {
    let f = fixture("model-budget")?;
    let refused_path = f.dir.0.join("refused.bin");
    let refused = command(&f, &refused_path, 3, true)
        .args(["--max-macs", "0"])
        .output()?;
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(field(&refused, "complete")?, "false");
    assert_eq!(field(&refused, "stage")?, "inference");
    assert_eq!(field(&refused, "next_segment")?, "0");
    assert_eq!(field(&refused, "completed_inferences")?, "0");
    assert_eq!(field(&refused, "new_decodes")?, "1");
    assert!(!refused_path.exists());
    let completed = command(&f, &f.dir.0.join("completed.bin"), 3, true).output()?;
    success(&completed);
    assert_eq!(field(&completed, "reused_decodes")?, "1");
    assert_eq!(field(&completed, "new_decodes")?, "2");
    assert_eq!(field(&completed, "new_inferences")?, "3");
    Ok(())
}

#[test]
fn postprocessing_failure_retains_all_numeric_work_without_exporting_partial_report() -> TestResult
{
    let f = fixture("analysis-budget")?;
    let refused_path = f.dir.0.join("refused.bin");
    let refused = command(&f, &refused_path, 3, true)
        .args(["--detection-work-units", "0"])
        .output()?;
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(field(&refused, "complete")?, "false");
    assert_eq!(field(&refused, "stage")?, "analysis");
    assert_eq!(field(&refused, "completed_inferences")?, "3");
    assert_eq!(field(&refused, "next_segment")?, "none");
    assert!(!refused_path.exists());
    fs::remove_file(&f.source)?;
    fs::remove_file(&f.model)?;
    let before = snapshot(&f.root)?;
    let completed = command(&f, &f.dir.0.join("complete.bin"), 3, false)
        .args(["--decode-work-units", "0", "--max-macs", "0"])
        .output()?;
    success(&completed);
    assert_eq!(field(&completed, "new_inferences")?, "0");
    for segment in 0..3 {
        assert_eq!(
            field(&completed, &format!("run.{segment}"))?,
            field(&refused, &format!("run.{segment}"))?
        );
    }
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn export_refusals_precede_numeric_execution_and_do_not_modify_deployment() -> TestResult {
    let f = fixture("exports")?;
    let before = snapshot(&f.root)?;
    let existing = f.dir.0.join("existing.bin");
    fs::write(&existing, b"operator-owned report")?;
    let refused = command(&f, &existing, 3, true).output()?;
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(fs::read(&existing)?, b"operator-owned report");
    let inside = f.root.join("inside.bin");
    assert!(!command(&f, &inside, 3, true).output()?.status.success());
    assert!(!inside.exists());
    let alias = f.dir.0.join("same.bin");
    assert!(
        !command(&f, &alias, 3, true)
            .arg("--runs-out")
            .arg(&alias)
            .output()?
            .status
            .success()
    );
    assert!(!alias.exists());
    #[cfg(unix)]
    {
        let link = f.dir.0.join("link.bin");
        std::os::unix::fs::symlink(&existing, &link)?;
        assert!(!command(&f, &link, 3, true).output()?.status.success());
        assert_eq!(fs::read(&existing)?, b"operator-owned report");
    }
    assert_eq!(snapshot(&f.root)?, before);
    Ok(())
}

#[test]
fn invalid_ranges_models_and_absent_deployments_fail_without_creating_results() -> TestResult {
    let f = fixture("refusals")?;
    let before = snapshot(&f.root)?;
    let report = f.dir.0.join("report.bin");
    assert_eq!(
        command(&f, &report, 0, true).output()?.status.code(),
        Some(2)
    );
    assert_eq!(
        command(&f, &report, 257, true).output()?.status.code(),
        Some(2)
    );
    assert_eq!(
        command(&f, &report, 4, true).output()?.status.code(),
        Some(1)
    );
    assert!(
        !command(&f, &report, 3, false).output()?.status.success(),
        "unretained model is not inferred"
    );
    fs::write(&f.model, b"not the pinned model")?;
    assert!(!command(&f, &report, 3, true).output()?.status.success());
    assert!(!report.exists());
    assert_eq!(snapshot(&f.root)?, before);
    let mut absent = fixture("absent")?;
    absent.root = absent.dir.0.join("missing-deployment");
    assert_eq!(
        command(&absent, &absent.dir.0.join("report.bin"), 3, true)
            .output()?
            .status
            .code(),
        Some(1)
    );
    assert!(!absent.root.exists());
    Ok(())
}

#[test]
fn cached_prefix_does_not_consume_the_new_suffix_model_budget() -> TestResult {
    let f = fixture("suffix")?;
    let first = command(&f, &f.dir.0.join("first.bin"), 1, true).output()?;
    success(&first);
    let cost: u64 = field(&first, "model_work_charged")?.parse()?;
    assert!(cost > 0);
    let completed = command(&f, &f.dir.0.join("all.bin"), 3, false)
        .args(["--max-macs", &(2 * cost).to_string()])
        .output()?;
    success(&completed);
    assert_eq!(field(&completed, "reused_inferences")?, "1");
    assert_eq!(field(&completed, "new_inferences")?, "2");
    assert_eq!(
        field(&completed, "model_work_charged")?,
        (2 * cost).to_string()
    );
    assert_eq!(field(&completed, "model_work_remaining")?, "0");
    assert_eq!(field(&completed, "run.0")?, field(&first, "run.0")?);
    Ok(())
}

#[test]
fn empty_thresholded_analysis_does_not_invent_tracks_or_absence() -> TestResult {
    let f = fixture("empty")?;
    let report = f.dir.0.join("report.bin");
    let completed = command(&f, &report, 3, true)
        .args(["--minimum-score-ppm", "1000000"])
        .output()?;
    success(&completed);
    assert_eq!(field(&completed, "complete")?, "true");
    assert_eq!(field(&completed, "candidate_tracks")?, "0");
    assert_eq!(field(&completed, "absence_certifiable")?, "false");
    assert_eq!(field(&completed, "effects_authorized")?, "false");
    assert!(field(&completed, "track").is_err());
    assert_eq!(
        ContentDigest::sha256(&fs::read(report)?).to_text(),
        field(&completed, "report_digest")?
    );
    Ok(())
}
