#![forbid(unsafe_code)]
//! Real local ReplayCx, byte reads, report creation and complete failure behavior.

use super::fixtures::{Fixture, LEFT, RIGHT, TestResult, field, ok};
use super::*;
use fss_cli::json_input::parse;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Files {
    root: PathBuf,
    options: Options,
}
impl Files {
    fn new() -> TestResult<Self> {
        let fixture = Fixture::new()?;
        let root = std::env::temp_dir().join(format!(
            "fss-scene-match-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root)?;
        let paths = [
            "property.fsstwin",
            "rig.json",
            "query.json",
            "left.jpg",
            "right.jpg",
        ]
        .map(|name| root.join(name));
        for (path, bytes) in paths.iter().zip([
            fixture.package.as_slice(),
            fixture.rig_document.as_bytes(),
            fixture.query_document.as_bytes(),
            LEFT,
            RIGHT,
        ]) {
            fs::write(path, bytes)?;
        }
        Ok(Self {
            root: root.clone(),
            options: Options {
                twin: paths[0].clone(),
                rig: paths[1].clone(),
                query: paths[2].clone(),
                images: [paths[3].clone(), paths[4].clone()],
                masks: [None, None],
                report_out: Some(root.join("report.json")),
                work: DEFAULT_MATCH_WORK,
                timeout: Duration::from_secs(30),
                report_bytes: MAX_REPORT_BYTES,
            },
        })
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn owner_reads_actual_jpegs_and_writes_identical_private_complete_report() -> TestResult {
    let files = Files::new()?;
    let mut stdout = Vec::new();
    assert!(ok(execute(&files.options, &mut stdout))?);
    let path = files.options.report_out.as_ref().ok_or("report path")?;
    assert_eq!(fs::read(path)?, stdout);
    let report = parse(std::str::from_utf8(&stdout)?)?;
    assert_eq!(
        field(&report, &["report", "outcome"])?.text(),
        Some("reconstructed")
    );
    assert_eq!(
        field(&report, &["report", "physical_identity_established"])?.boolean(),
        Some(false)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
    }
    let mut second_stdout = Vec::new();
    assert!(execute(&files.options, &mut second_stdout).is_err());
    assert!(second_stdout.is_empty());
    assert_eq!(fs::read(path)?, stdout);
    Ok(())
}

#[test]
fn changed_source_missing_mask_and_output_limit_release_no_partial_result() -> TestResult {
    for case in 0..3 {
        let mut files = Files::new()?;
        match case {
            0 => fs::write(&files.options.images[1], LEFT)?,
            1 => files.options.masks[0] = Some(files.root.join("undeclared.mask")),
            _ => files.options.report_bytes = 1024,
        }
        let mut stdout = Vec::new();
        assert!(execute(&files.options, &mut stdout).is_err());
        assert!(stdout.is_empty());
        assert!(
            !files
                .options
                .report_out
                .as_ref()
                .ok_or("report path")?
                .exists()
        );
    }
    Ok(())
}

#[test]
fn owner_cancellation_deadline_and_work_exhaustion_refuse_before_output() -> TestResult {
    let mut files = Files::new()?;
    let cx = ok(authority())?;
    cx.request_cancellation();
    assert!(analyze(&files.options, &cx).is_err());
    cx.drain_and_finalize();
    for deadline in [true, false] {
        files.options.timeout = if deadline {
            Duration::ZERO
        } else {
            Duration::from_secs(30)
        };
        files.options.work = if deadline { DEFAULT_MATCH_WORK } else { 1 };
        let mut stdout = Vec::new();
        assert!(execute(&files.options, &mut stdout).is_err());
        assert!(stdout.is_empty());
        assert!(
            !files
                .options
                .report_out
                .as_ref()
                .ok_or("report path")?
                .exists()
        );
    }
    Ok(())
}
