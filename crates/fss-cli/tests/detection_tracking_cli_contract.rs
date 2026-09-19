#![forbid(unsafe_code)]
//! Cross-process operator tests for real stored model runs, detector proposals and tracking.

use std::error::Error;
use std::fs;
use std::path::{Path,PathBuf};
use std::process::{Command,Output};
use fss_core::ContentDigest;

type TestResult<T=()> = Result<T,Box<dyn Error>>;
const JPEG: &[u8]=include_bytes!("fixtures/retained_file_8x8.jpg");
const MODEL: &[u8]=include_bytes!("fixtures/detector_rows_8x8.fssmodel");
struct Directory(PathBuf);
impl Directory {
    fn new(label: &str) -> TestResult<Self> {
        for n in 0..100 {
            let p=std::env::temp_dir().join(format!("fss-track-cli-{label}-{}-{n}",std::process::id()));
            match fs::create_dir(&p) {
                Ok(())=>return Ok(Self(p)),Err(e) if e.kind()==std::io::ErrorKind::AlreadyExists=>{},Err(e)=>return Err(e.into()),
            }
        }
        Err(std::io::Error::other("test directory capacity").into())
    }
}
impl Drop for Directory {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn success(output: &Output) {
    assert!(output.status.success(),"stdout={} stderr={}",String::from_utf8_lossy(&output.stdout),String::from_utf8_lossy(&output.stderr));
}
fn field(output: &Output,key: &str)->TestResult<String> {
    let text=std::str::from_utf8(&output.stdout)?;
    text.lines().find_map(|line|line.strip_prefix(&format!("{key}="))).map(str::to_owned)
        .ok_or_else(||std::io::Error::other(format!("missing {key}")).into())
}
struct Fixture {dir:Directory,root:PathBuf,import:String,runs:Vec<String>}
fn fixture(label: &str)->TestResult<Fixture> {
    let dir=Directory::new(label)?;let root=dir.0.join("deployment");let source=dir.0.join("source.mjpeg");let model=dir.0.join("model.fssmodel");
    fs::write(&source,[JPEG,JPEG,JPEG].concat())?;fs::write(&model,MODEL)?;
    assert_eq!(ContentDigest::sha256(MODEL).to_text(),"sha256:2b1c64990f1c1820b3bdb77ea32cc25b2fff484db11fe7d68b0e1f04bd2c45c8");
    let imported=Command::new(env!("CARGO_BIN_EXE_fss-file")).arg("import").arg("--root").arg(&root)
        .args(["--site","site:track-cli","--sensor","sensor:track-cli","--stream","stream:track-cli","--receive-time-ns","1000000000"])
        .arg("--input").arg(&source).output()?;
    success(&imported);let import=field(&imported,"import_identity")?;
    let mut runs=Vec::new();
    for segment in 0..3 {
        let result=Command::new(env!("CARGO_BIN_EXE_fss-infer")).arg("run").arg("--root").arg(&root)
            .args(["--site","site:track-cli","--import-id",&import,"--interpretation","gray","--segment",&segment.to_string()])
            .arg("--model").arg(&model).args(["--model-digest",&ContentDigest::sha256(MODEL).to_text()]).output()?;
        success(&result);runs.push(field(&result,"run_identity")?);
    }
    fs::remove_file(&source)?;fs::remove_file(&model)?;
    Ok(Fixture{dir,root,import,runs})
}
fn command(root:&Path,import:&str,action:&str)->Command {
    let mut c=Command::new(env!("CARGO_BIN_EXE_fss-infer"));
    c.arg(action).arg("--root").arg(root).args(["--site","site:track-cli","--import-id",import,"--interpretation","gray",
        "--model-digest","sha256:2b1c64990f1c1820b3bdb77ea32cc25b2fff484db11fe7d68b0e1f04bd2c45c8",
        "--output-port","detections","--labels","vehicle,animal","--box-format","xyxy","--coordinates","normalized"]);c
}
fn list(f:&Fixture,ids:&[&str])->TestResult<PathBuf> {
    let path=f.dir.0.join("runs.txt");
    let bytes=ids.iter().enumerate().map(|(i,id)|format!("{i} {id}\n")).collect::<String>();
    fs::write(&path,bytes)?;Ok(path)
}
#[test]
fn detect_and_track_replay_after_source_removal_is_byte_identical()->TestResult {
    let f=fixture("replay")?;
    let detected=command(&f.root,&f.import,"detect").args(["--segment","0","--run-id",&f.runs[0]]).output()?;
    success(&detected);let text=std::str::from_utf8(&detected.stdout)?;
    assert!(text.contains("\"rows\":3"));assert!(text.contains("\"suppressed\":1"));
    assert!(text.contains("\"complete\":true"));assert!(text.contains("\"absence_certifiable\":false"));
    let path=list(&f,&f.runs.iter().map(String::as_str).collect::<Vec<_>>())?;
    let first=command(&f.root,&f.import,"track").arg("--runs").arg(&path).output()?;
    let second=command(&f.root,&f.import,"track").arg("--runs").arg(&path).output()?;
    success(&first);success(&second);assert_eq!(first.stdout,second.stdout);
    let text=std::str::from_utf8(&first.stdout)?;
    assert!(text.contains("\"completed_entries\":3"));assert!(text.contains("\"observations\":3"));
    assert!(text.contains("\"confirmed\":true"));assert!(text.contains("\"association_is_hypothesis\":true"));
    assert!(text.contains("\"effects_authorized\":false"));Ok(())
}
#[test]
fn unavailable_run_and_budget_failure_report_exact_partial_progress()->TestResult {
    let f=fixture("partial")?;
    let path=list(&f,&[&f.runs[0],&f.runs[0]])?;
    let failed=command(&f.root,&f.import,"track").arg("--runs").arg(&path).output()?;
    assert_eq!(failed.status.code(),Some(1));
    let text=std::str::from_utf8(&failed.stdout)?;
    assert!(text.contains("\"complete\":false"));assert!(text.contains("\"completed_entries\":1"));assert!(text.contains("\"next_segment\":1"));
    let path=list(&f,&[&f.runs[0],&f.runs[1]])?;
    let failed=command(&f.root,&f.import,"track").arg("--runs").arg(&path)
        .args(["--association-work-units","0"]).output()?;
    assert_eq!(failed.status.code(),Some(1));let text=std::str::from_utf8(&failed.stdout)?;
    assert!(text.contains("\"complete\":false"));assert!(text.contains("\"completed_entries\":1"));
    assert!(text.contains("local association work budget exhausted"));Ok(())
}
#[test]
fn report_exports_never_replace_files_or_write_into_deployment()->TestResult {
    let f=fixture("export")?;let path=list(&f,&[&f.runs[0],&f.runs[1]])?;
    let report=f.dir.0.join("report.json");fs::write(&report,b"existing operator report")?;
    let result=command(&f.root,&f.import,"track").arg("--runs").arg(&path).arg("--report-out").arg(&report).output()?;
    assert!(!result.status.success());assert_eq!(fs::read(&report)?,b"existing operator report");
    let inside=f.root.join("report.json");
    let result=command(&f.root,&f.import,"track").arg("--runs").arg(&path).arg("--report-out").arg(&inside).output()?;
    assert!(!result.status.success());assert!(!inside.exists());
    let fresh=f.dir.0.join("fresh.json");
    let result=command(&f.root,&f.import,"track").arg("--runs").arg(&path).arg("--report-out").arg(&fresh).output()?;
    success(&result);assert_eq!(fs::read(fresh)?,result.stdout);Ok(())
}
#[test]
fn argument_refusals_and_missing_deployment_do_not_initialize_storage()->TestResult {
    let dir=Directory::new("args")?;let root=dir.0.join("absent");let id=ContentDigest::sha256(b"absent").to_text();
    let result=command(&root,&id,"detect").args(["--segment","0","--run-id",&id,"--maximum-rows","0"]).output()?;
    assert_eq!(result.status.code(),Some(2));assert!(!root.exists());
    let result=command(&root,&id,"detect").args(["--segment","0","--run-id",&id]).output()?;
    assert_eq!(result.status.code(),Some(1));assert!(!root.exists());
    Ok(())
}
