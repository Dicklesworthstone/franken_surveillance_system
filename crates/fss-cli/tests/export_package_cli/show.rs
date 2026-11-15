#![forbid(unsafe_code)]
//! Immutable export inspection through the real native operator command.

use super::*;
use fss_cli::json_input::{Value, parse};
use std::collections::BTreeMap;

fn args(fixture: &Fixture) -> Vec<OsString> {
    vec![
        "show".into(),
        "--root".into(),
        fixture.root.as_os_str().to_owned(),
        "--site".into(),
        SITE.into(),
        "--principal".into(),
        ACTOR.into(),
        "--export-root".into(),
        fixture.export_root.to_text().into(),
    ]
}

fn execute(args: &[OsString]) -> Test<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_fss-export"))
        .args(args)
        .output()?)
}

fn report(args: &[OsString]) -> Test<Value> {
    let output = execute(args)?;
    success(&output);
    assert!(output.stderr.is_empty());
    assert!(output.stdout.len() <= 1024 * 1024);
    Ok(parse(std::str::from_utf8(&output.stdout)?)?)
}

fn item<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    Ok(value
        .object()
        .and_then(|object| object.get(key))
        .ok_or("report field")?)
}

fn set(args: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = args.iter().position(|arg| arg == key) {
        args[index + 1] = value.into();
    } else {
        args.extend([key.into(), value.into()]);
    }
}

fn filesystem(root: &Path) -> Test<BTreeMap<PathBuf, Option<Vec<u8>>>> {
    let mut pending = vec![root.to_path_buf()];
    let mut result = BTreeMap::new();
    while let Some(path) = pending.pop() {
        let metadata = fs::symlink_metadata(&path)?;
        let relative = path.strip_prefix(root)?.to_path_buf();
        if metadata.file_type().is_dir() {
            result.insert(relative, None);
            for entry in fs::read_dir(path)? {
                pending.push(entry?.path());
            }
        } else if metadata.file_type().is_file() {
            result.insert(relative, Some(fs::read(path)?));
        } else {
            return Err("unexpected fixture file type".into());
        }
    }
    Ok(result)
}

#[test]
fn export_show_works_with_active_writer_and_unavailable_raw_media_without_writes() -> Test {
    let _serial = SERIAL.lock().map_err(|_| "serial fixture lock")?;
    let fixture = Fixture::new("immutable-show")?;
    let args = args(&fixture);
    let expected = report(&args)?;
    assert_eq!(
        item(&expected, "deployment_mutated")?.boolean(),
        Some(false)
    );
    assert_eq!(item(&expected, "raw_media_read")?.boolean(), Some(false));
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:export-show-writer".into(),
        operation_id: OperationId::parse("operation:export-show-writer")?,
        principal: ACTOR.into(),
        capabilities: vec!["ADP-REPLAY-001".into()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::builder().bytes(64 * 1024 * 1024).build()?,
        privacy_scope: "privacy:redacted-export-test".into(),
        retention_scope: "retention:test".into(),
        anchor_universe: ContentDigest::sha256(SITE.as_bytes()),
        generation: 1,
    })?;
    let cx = ReplayCx::from_context_authority(&authority, fixture.root.clone())?;
    let writer = ReferenceDeployment::open(&fixture.root, SITE, &cx)?;
    for payload in [
        b"private source sentinel".as_slice(),
        b"private model sentinel",
    ] {
        fs::write(
            writer
                .publisher()
                .spool()
                .object_path(ContentDigest::sha256(payload)),
            b"unavailable source payload",
        )?;
    }
    let before = filesystem(&fixture.root)?;
    assert_eq!(report(&args)?, expected);
    assert_eq!(filesystem(&fixture.root)?, before);
    drop(writer);
    cx.drain_and_finalize();
    let before = filesystem(&fixture.root)?;
    assert_eq!(report(&args)?, expected);
    assert_eq!(filesystem(&fixture.root)?, before);
    Ok(())
}

#[test]
fn export_show_aggregate_allowances_include_final_revalidation() -> Test {
    let _serial = SERIAL.lock().map_err(|_| "serial fixture lock")?;
    let fixture = Fixture::new("show-allowance")?;
    let args = args(&fixture);
    let before = filesystem(&fixture.root)?;
    let expected = report(&args)?;
    let bytes = item(&expected, "payload_read_bytes")?
        .integer()
        .ok_or("payload bytes")?;
    let reads = item(&expected, "payload_read_attempts")?
        .integer()
        .ok_or("payload reads")?;
    assert!(bytes > 1 && reads > 1);
    let mut exact = args;
    set(&mut exact, "--max-read-bytes", &bytes.to_string());
    set(&mut exact, "--max-read-objects", &reads.to_string());
    assert_eq!(report(&exact)?, expected);
    for (key, allowance) in [
        ("--max-read-bytes", bytes - 1),
        ("--max-read-objects", reads - 1),
    ] {
        let mut exhausted = exact.clone();
        set(&mut exhausted, key, &allowance.to_string());
        refused(&execute(&exhausted)?, "ERR-EXPORT-CUSTODY-001");
    }
    assert_eq!(filesystem(&fixture.root)?, before);
    Ok(())
}

#[test]
fn export_show_refuses_both_torn_journals_and_missing_roots_without_recovery() -> Test {
    let _serial = SERIAL.lock().map_err(|_| "serial fixture lock")?;
    let fixture = Fixture::new("show-incomplete")?;
    let args = args(&fixture);
    for relative in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let path = fixture.root.join(relative);
        let original = fs::read(&path)?;
        let mut torn = original.clone();
        torn.extend_from_slice(&[0x46, 0x53, 0x53]);
        fs::write(&path, torn)?;
        let before = filesystem(&fixture.root)?;
        refused(&execute(&args)?, "ERR-EXPORT-CUSTODY-001");
        assert_eq!(filesystem(&fixture.root)?, before, "repaired {relative}");
        fs::write(path, original)?;
    }
    let before = filesystem(&fixture.root)?;
    let mut foreign = args.clone();
    set(&mut foreign, "--site", "site:foreign");
    refused(&execute(&foreign)?, "ERR-AUTH-DENIED-001");
    assert_eq!(filesystem(&fixture.root)?, before);
    let missing = fixture.directory.0.join("missing deployment");
    let mut absent = args;
    set(
        &mut absent,
        "--root",
        missing.to_str().ok_or("UTF-8 fixture path")?,
    );
    let output = execute(&absent)?;
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(!missing.exists());
    Ok(())
}
