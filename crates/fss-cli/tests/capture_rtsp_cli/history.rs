#![forbid(unsafe_code)]
//! Native capture and cold exact history selection across separate processes.

use super::*;
use std::collections::BTreeMap;
use std::path::Path;

#[path = "campaign_watch.rs"]
mod watch;

#[path = "campaign_sentinel.rs"]
mod sentinel;

#[path = "history/continuation.rs"]
mod continuation;

fn set(input: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = input.iter().position(|part| part == key) {
        input[index + 1] = value.into();
    } else {
        input.extend([key.into(), value.into()]);
    }
}

fn history_args(directory: &Directory, peer: SocketAddr) -> Vec<OsString> {
    let mut input = campaign_args(directory, peer);
    set(&mut input, "--max-attempts", "2");
    set(
        &mut input,
        "--history-root",
        directory.0.join("history").to_str().unwrap(),
    );
    input
}

fn receipts(output: &Output) -> Test<Vec<Value>> {
    let (rows, _) = campaign_rows(output)?;
    rows.iter()
        .filter(|row| text(row, "kind").ok() == Some("history_durable"))
        .map(|row| Ok(value(value(row, "detail")?, "pin")?.clone()))
        .collect()
}

fn inspect_args(directory: &Directory, pin: &Value) -> Test<Vec<OsString>> {
    let mut input = vec!["campaign-inspect".into()];
    input.extend([
        "--history-root".into(),
        directory.0.join("history").into_os_string(),
    ]);
    for (option, field) in [
        ("--approval", "approval"),
        ("--plan-digest", "plan"),
        ("--root-digest", "root"),
    ] {
        input.extend([option.into(), text(pin, field)?.into()]);
    }
    input.extend([
        "--records".into(),
        integer(pin, "records")?.to_string().into(),
    ]);
    Ok(input)
}

#[derive(Debug, Eq, PartialEq)]
struct TreeEntry {
    directory: bool,
    length: u64,
    readonly: bool,
    modified: std::time::SystemTime,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    changed: (i64, i64),
    contents: Option<Vec<u8>>,
}

fn tree(root: &Path) -> Test<BTreeMap<PathBuf, TreeEntry>> {
    fn walk(root: &Path, path: &Path, result: &mut BTreeMap<PathBuf, TreeEntry>) -> Test {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        let metadata = fs::symlink_metadata(path)?;
        assert!(
            metadata.is_dir() || metadata.is_file(),
            "unexpected fixture entry"
        );
        // Ordinary reads may update access time; all recorded mutation metadata must agree.
        result.insert(
            path.strip_prefix(root)?.to_owned(),
            TreeEntry {
                directory: metadata.is_dir(),
                length: metadata.len(),
                readonly: metadata.permissions().readonly(),
                modified: metadata.modified()?,
                #[cfg(unix)]
                inode: metadata.ino(),
                #[cfg(unix)]
                mode: metadata.mode(),
                #[cfg(unix)]
                changed: (metadata.ctime(), metadata.ctime_nsec()),
                contents: if metadata.is_file() {
                    Some(fs::read(path)?)
                } else {
                    None
                },
            },
        );
        if metadata.is_dir() {
            for entry in fs::read_dir(path)? {
                walk(root, &entry?.path(), result)?;
            }
        }
        Ok(())
    }
    let mut result = BTreeMap::new();
    walk(root, root, &mut result)?;
    Ok(result)
}

#[test]
fn history_cold_exact_prefixes_preserve_independent_native_evidence_without_media_reads() -> Test {
    let directory = Directory::new("history-cold")?;
    let camera = listener()?;
    let input = history_args(&directory, camera.local_addr()?);
    let (approved, preview) = campaign_approval(&input)?;
    assert!(!directory.0.join("history").exists());
    no_connection(&camera)?;
    let (output, transcripts) =
        capture_sessions(&camera, &approved, &[Behavior::Target, Behavior::Target])?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(transcripts.len(), 2);
    let pins = receipts(&output)?;
    assert_eq!(pins.len(), 5);
    assert_eq!(integer(&pins[0], "records")?, 1);
    assert_eq!(integer(&pins[4], "records")?, 5);
    assert_eq!(
        text(&pins[4], "plan")?,
        text(value(&preview, "campaign_history")?, "plan_digest")?
    );
    let (_, native_rows) = campaign_rows(&output)?;
    // Inspection must survive unavailable original archives and pin journals.
    for ordinal in 1..=2 {
        fs::rename(
            epoch_path(&directory, "capture", ordinal),
            directory.0.join(format!("offline-capture-{ordinal}")),
        )?;
        fs::rename(
            epoch_path(&directory, "pins", ordinal),
            directory.0.join(format!("offline-pins-{ordinal}")),
        )?;
    }
    let before = tree(&directory.0.join("history"))?;
    let terminal = parse(&good(run(
        "capture",
        &inspect_args(&directory, &pins[4])?,
    )?)?)?;
    assert_eq!(text(&terminal, "campaign_completion")?, "observed_complete");
    assert_eq!(integer(&terminal, "observed_started_attempts")?, 2);
    assert_eq!(integer(&terminal, "observed_finished_attempts")?, 2);
    assert!(!boolean(&terminal, "durability_resynced")?);
    assert!(!boolean(&terminal, "camera_opened")?);
    assert!(!boolean(&terminal, "capture_resume_authorized")?);
    assert_eq!(text(&terminal, "current_media_custody")?, "unchecked");
    let attempts = value(&terminal, "attempts")?.array().ok_or("attempts")?;
    for (index, attempt) in attempts.iter().enumerate() {
        let finish = value(attempt, "finish")?;
        let native = value(finish, "native")?;
        assert!(boolean(finish, "settled_success")?);
        assert_eq!(integer(native, "durable_pictures")?, 2);
        let catalogs = value(native, "catalogs")?.array().ok_or("catalogs")?;
        let published = native_rows[index]
            .iter()
            .find(|row| text(row, "kind").ok() == Some("catalog_published"))
            .ok_or("native catalog")?;
        let published = value(published, "detail")?;
        assert_eq!(text(&catalogs[0], "root")?, text(published, "root")?);
        assert_eq!(text(&catalogs[0], "slot")?, text(published, "slot")?);
    }
    let started = parse(&good(run(
        "capture",
        &inspect_args(&directory, &pins[0])?,
    )?)?)?;
    assert_eq!(text(&started, "campaign_completion")?, "unknown");
    assert_eq!(integer(&started, "observed_started_attempts")?, 1);
    assert_eq!(integer(&started, "observed_finished_attempts")?, 0);
    let started_attempts = value(&started, "attempts")?
        .array()
        .ok_or("started attempts")?;
    assert_eq!(
        text(&started_attempts[0], "state")?,
        "started_completion_unknown"
    );
    assert_eq!(value(&started_attempts[0], "finish")?, &Value::Null);
    assert_eq!(text(&started, "later_records")?, "not_asserted");
    assert_eq!(tree(&directory.0.join("history"))?, before);
    no_connection(&camera)?;
    Ok(())
}

#[test]
fn history_cold_limits_wrong_scope_and_corrupt_selected_root_fail_without_fallback() -> Test {
    let directory = Directory::new("history-refusal")?;
    let camera = listener()?;
    let input = history_args(&directory, camera.local_addr()?);
    let (approved, _) = campaign_approval(&input)?;
    let (output, _) = capture_sessions(&camera, &approved, &[Behavior::Target, Behavior::Target])?;
    assert!(output.status.success());
    let pins = receipts(&output)?;
    let pin = pins.last().ok_or("terminal pin")?;
    let input = inspect_args(&directory, pin)?;
    let before = tree(&directory.0.join("history"))?;
    for (key, value) in [
        ("--history-work", "1".to_owned()),
        ("--history-metadata-bytes", "1".to_owned()),
        ("--history-storage-bytes", "1".to_owned()),
        ("--history-max-records", "1".to_owned()),
        ("--max-report-bytes", "1".to_owned()),
        ("--principal", "principal:other".to_owned()),
        ("--approval", digest("wrong independent approval")),
        ("--plan-digest", digest("wrong independent plan")),
        ("--root-digest", digest("wrong selected root")),
        ("--records", "4".to_owned()),
    ] {
        let mut refused = input.clone();
        set(&mut refused, key, &value);
        let output = run("capture", &refused)?;
        assert!(!output.status.success(), "{key}");
        assert!(output.stdout.is_empty(), "{key}: partial inspection report");
    }
    assert_eq!(tree(&directory.0.join("history"))?, before);
    let object = directory
        .0
        .join("history/spool/objects")
        .join(text(pin, "root")?.strip_prefix("sha256:").ok_or("digest")?);
    let mut bytes = fs::read(&object)?;
    *bytes.first_mut().ok_or("empty root object")? ^= 1;
    fs::write(&object, bytes)?;
    let output = run("capture", &input)?;
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "corrupt selected root fell back or emitted partial observations"
    );
    no_connection(&camera)?;
    Ok(())
}

#[test]
fn history_missing_root_and_exhausted_retention_grant_never_open_camera() -> Test {
    let directory = Directory::new("history-before-camera")?;
    let camera = listener()?;
    let pin = parse(&format!(
        "{{\"approval\":\"{}\",\"plan\":\"{}\",\"root\":\"{}\",\"records\":1}}",
        digest("approval"),
        digest("plan"),
        digest("root")
    ))?;
    let inspection = inspect_args(&directory, &pin)?;
    assert!(!run("capture", &inspection)?.status.success());
    assert!(
        !directory.0.join("history").exists(),
        "cold inspection created a missing root"
    );
    let mut input = history_args(&directory, camera.local_addr()?);
    set(&mut input, "--history-work", "1");
    let (approved, _) = campaign_approval(&input)?;
    let output = run("capture", &approved)?;
    assert!(!output.status.success());
    assert!(!epoch_path(&directory, "capture", 1).exists());
    assert!(!epoch_path(&directory, "pins", 1).exists());
    no_connection(&camera)?;
    Ok(())
}

#[test]
fn history_preserves_eof_failure_before_a_successful_independent_session() -> Test {
    let directory = Directory::new("history-partial")?;
    let camera = listener()?;
    let (approved, _) = campaign_approval(&history_args(&directory, camera.local_addr()?))?;
    let (output, _) = capture_sessions(
        &camera,
        &approved,
        &[Behavior::EofAfterOne, Behavior::Target],
    )?;
    assert!(!output.status.success());
    let pins = receipts(&output)?;
    let report = parse(&good(run(
        "capture",
        &inspect_args(&directory, pins.last().ok_or("terminal")?)?,
    )?)?)?;
    assert_eq!(text(&report, "campaign_completion")?, "observed_failed");
    let attempts = value(&report, "attempts")?.array().ok_or("attempts")?;
    let first = value(&attempts[0], "finish")?;
    let native = value(first, "native")?;
    assert_eq!(text(native, "error_id")?, "ERR-CAPTURE-RTSP-SHORTFALL-001");
    assert_eq!(integer(native, "durable_pictures")?, 1);
    assert_eq!(value(first, "controller_error")?, &Value::Null);
    assert!(boolean(first, "next_attempt_planned")?);
    assert!(boolean(value(&attempts[1], "finish")?, "settled_success")?);
    no_connection(&camera)?;
    Ok(())
}

#[test]
fn history_retains_known_empty_source_pin_on_authentication_refusal() -> Test {
    let directory = Directory::new("history-empty-source")?;
    let camera = listener()?;
    let mut input = history_args(&directory, camera.local_addr()?);
    set(
        &mut input,
        "--source-root",
        directory.0.join("source").to_str().ok_or("source path")?,
    );
    set(
        &mut input,
        "--source-retention-evidence",
        &digest("explicit raw source retention"),
    );
    let (approved, _) = campaign_approval(&input)?;
    let (output, _) = capture_sessions(&camera, &approved, &[Behavior::AuthenticationRequired])?;
    assert!(!output.status.success());
    let pins = receipts(&output)?;
    assert_eq!(pins.len(), 3);
    let report = parse(&good(run(
        "capture",
        &inspect_args(&directory, pins.last().ok_or("terminal")?)?,
    )?)?)?;
    let attempt = value(&report, "attempts")?
        .array()
        .ok_or("attempts")?
        .first()
        .ok_or("attempt")?;
    let native = value(value(attempt, "finish")?, "native")?;
    assert_eq!(integer(native, "durable_pictures")?, 0);
    assert_eq!(
        text(native, "error_id")?,
        "ERR-CAPTURE-RTSP-AUTH-UNSUPPORTED-001"
    );
    let source = value(native, "source_pin")?;
    let binding = value(attempt, "source")?;
    assert_eq!(
        text(binding, "path")?,
        epoch_path(&directory, "source", 1)
            .to_str()
            .ok_or("source path")?
    );
    assert_eq!(text(binding, "scope")?, text(source, "scope")?);
    assert_eq!(integer(source, "datagrams")?, 0);
    assert_eq!(integer(source, "bytes")?, 0);
    assert_eq!(text(source, "head")?, text(source, "scope")?);
    assert!(!epoch_path(&directory, "capture", 2).exists());
    no_connection(&camera)?;
    Ok(())
}
