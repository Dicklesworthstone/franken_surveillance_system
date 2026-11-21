#![forbid(unsafe_code)]
//! Exact portable-copy approval without taking ownership of a running deployment.

use super::*;
use fss_cli::json_input::{Value, parse};
use std::collections::BTreeMap;

fn item<'a>(value: &'a Value, key: &str) -> Test<&'a Value> {
    Ok(value
        .object()
        .and_then(|fields| fields.get(key))
        .ok_or("report field")?)
}

fn report(args: &[OsString]) -> Test<Value> {
    let output = execute(args)?;
    success(&output);
    assert!(output.stderr.is_empty());
    Ok(parse(std::str::from_utf8(&output.stdout)?)?)
}

fn option(args: &mut Vec<OsString>, key: &str, value: &str) {
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
fn package_preview_works_during_capture_without_raw_media_models_or_writes() -> Test {
    let _serial = SERIAL.lock().map_err(|_| "serial fixture lock")?;
    let fixture = Fixture::new("capture-preview")?;
    let expected = report(&fixture.pack())?;
    assert_eq!(
        item(&expected, "deployment_open_may_reconcile")?.boolean(),
        Some(false)
    );
    let approval = field(&execute(&fixture.pack())?, "approval_digest")?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:package-preview-writer".into(),
        operation_id: OperationId::parse("operation:package-preview-writer")?,
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
    let before = filesystem(&fixture.directory.0)?;
    assert_eq!(report(&fixture.pack())?, expected);
    // File creation keeps its existing exclusive-owner requirement even when preview can run.
    refused(
        &execute(&approved(fixture.pack(), &approval))?,
        "ERR-EXPORT-STORAGE-001",
    );
    assert_eq!(filesystem(&fixture.directory.0)?, before);
    for payload in [
        b"private source sentinel".as_slice(),
        b"private model sentinel",
    ] {
        fs::write(
            writer
                .publisher()
                .spool()
                .object_path(ContentDigest::sha256(payload)),
            b"unavailable original payload",
        )?;
    }
    let before = filesystem(&fixture.directory.0)?;
    assert_eq!(report(&fixture.pack())?, expected);
    assert!(!fixture.output.exists());
    assert_eq!(filesystem(&fixture.directory.0)?, before);
    drop(writer);
    cx.drain_and_finalize();
    // The immutable profile also avoids reopening unrelated corrupt original payloads cold.
    assert_eq!(report(&fixture.pack())?, expected);
    assert_eq!(filesystem(&fixture.directory.0)?, before);
    Ok(())
}

#[test]
fn package_preview_budget_includes_metadata_custody_and_final_revalidation() -> Test {
    let _serial = SERIAL.lock().map_err(|_| "serial fixture lock")?;
    let fixture = Fixture::new("preview-budget")?;
    let before = filesystem(&fixture.directory.0)?;
    let expected = report(&fixture.pack())?;
    let bytes = item(&expected, "payload_read_bytes")?
        .integer()
        .ok_or("payload bytes")?;
    let reads = item(&expected, "payload_read_attempts")?
        .integer()
        .ok_or("payload reads")?;
    assert!(bytes > 1 && reads > 1);
    let mut exact = fixture.pack();
    option(&mut exact, "--max-read-bytes", &bytes.to_string());
    option(&mut exact, "--max-read-objects", &reads.to_string());
    assert_eq!(report(&exact)?, expected);
    for (key, allowance) in [
        ("--max-read-bytes", bytes - 1),
        ("--max-read-objects", reads - 1),
    ] {
        let mut exhausted = exact.clone();
        option(&mut exhausted, key, &allowance.to_string());
        refused(&execute(&exhausted)?, "ERR-EXPORT-CUSTODY-001");
    }
    assert_eq!(filesystem(&fixture.directory.0)?, before);
    Ok(())
}

#[test]
fn package_preview_refuses_incomplete_journals_without_repair_or_recreation() -> Test {
    let _serial = SERIAL.lock().map_err(|_| "serial fixture lock")?;
    let fixture = Fixture::new("preview-incomplete")?;
    for relative in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let path = fixture.root.join(relative);
        let original = fs::read(&path)?;
        let mut torn = original.clone();
        torn.extend_from_slice(b"FSS");
        fs::write(&path, torn)?;
        let before = filesystem(&fixture.directory.0)?;
        refused(&execute(&fixture.pack())?, "ERR-EXPORT-CUSTODY-001");
        assert_eq!(
            filesystem(&fixture.directory.0)?,
            before,
            "repaired {relative}"
        );
        fs::remove_file(&path)?;
        let before = filesystem(&fixture.directory.0)?;
        refused(&execute(&fixture.pack())?, "ERR-EXPORT-CUSTODY-001");
        assert_eq!(
            filesystem(&fixture.directory.0)?,
            before,
            "recreated {relative}"
        );
        fs::write(path, original)?;
    }
    let before = filesystem(&fixture.directory.0)?;
    let mut foreign = fixture.pack();
    option(&mut foreign, "--site", "site:foreign");
    refused(&execute(&foreign)?, "ERR-AUTH-DENIED-001");
    let mut missing = fixture.pack();
    let absent = fixture.directory.0.join("missing");
    set(&mut missing, "--root", absent.as_os_str().to_owned())?;
    refused(&execute(&missing)?, "ERR-EXPORT-STORAGE-001");
    assert!(!absent.exists());
    assert_eq!(filesystem(&fixture.directory.0)?, before);
    Ok(())
}

#[test]
fn preview_bounds_are_explicit_positive_and_cannot_change_approved_copy_semantics() -> Test {
    let _serial = SERIAL.lock().map_err(|_| "serial fixture lock")?;
    let fixture = Fixture::new("preview-options")?;
    let before = filesystem(&fixture.directory.0)?;
    let approval = field(&execute(&fixture.pack())?, "approval_digest")?;
    for (key, maximum) in [
        ("--max-read-bytes", 1024_u64 * 1024 * 1024),
        ("--max-read-objects", 1_000_000),
        ("--timeout-ms", 600_000),
    ] {
        for value in ["0".to_owned(), "-1".to_owned(), (maximum + 1).to_string()] {
            let mut args = fixture.pack();
            option(&mut args, key, &value);
            let output = execute(&args)?;
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty());
        }
        let mut args = approved(fixture.pack(), &approval);
        option(&mut args, key, "1");
        let output = execute(&args)?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        let mut args = fixture.verify(&fixture.output);
        option(&mut args, key, "1");
        let output = execute(&args)?;
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    assert_eq!(filesystem(&fixture.directory.0)?, before);
    Ok(())
}
