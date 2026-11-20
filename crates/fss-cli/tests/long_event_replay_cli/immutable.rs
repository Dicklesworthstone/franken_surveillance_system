#![forbid(unsafe_code)]
//! Operator inspection shares immutable custody with a live deployment writer.

use super::*;

fn tree(root: &Path) -> Test<Vec<(PathBuf, ContentDigest)>> {
    fn visit(base: &Path, at: &Path, rows: &mut Vec<(PathBuf, ContentDigest)>) -> Test {
        for entry in fs::read_dir(at)? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                visit(base, &path, rows)?;
            } else {
                assert!(entry.file_type()?.is_file(), "unexpected fixture file type");
                rows.push((
                    path.strip_prefix(base)?.to_path_buf(),
                    ContentDigest::sha256(&fs::read(path)?),
                ));
            }
        }
        Ok(())
    }
    let mut rows = Vec::new();
    visit(root, root, &mut rows)?;
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(rows)
}

#[test]
fn whole_recording_inspection_replay_and_exports_coexist_with_a_live_writer() -> Test {
    for cameras in [1, 2] {
        let f = Fixture::new(&format!("immutable-writer-{cameras}"), cameras)?;
        let event = f.publish(cameras == 2)?;
        let cx = context(&f.root)?;
        let writer = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
        let before = tree(&f.root)?;
        let report_path = f.directory.0.join("live-inspection.json");
        let event_path = f.directory.0.join("live-event.json");
        let mut args = f.read(&event);
        args.extend([
            "--report-out".into(),
            report_path.as_os_str().to_owned(),
            "--event-out".into(),
            event_path.as_os_str().to_owned(),
        ]);
        let inspected = good(run(&args)?)?;
        assert_eq!(field(&inspected, "status")?, "inspected_not_replayed");
        assert_eq!(member(&inspected, "native_replayed")?, &Value::Bool(false));
        assert_eq!(parse(&fs::read_to_string(report_path)?)?, inspected);
        assert_eq!(
            parse(&fs::read_to_string(event_path)?)?,
            *member(&inspected, "event")?
        );
        assert_eq!(
            tree(&f.root)?,
            before,
            "inspection changed deployment bytes"
        );
        let report_path = f.directory.0.join("live-verification.json");
        let event_path = f.directory.0.join("live-verified-event.json");
        let mut args = verification_args(&inspected)?;
        args.extend([
            "--report-out".into(),
            report_path.as_os_str().to_owned(),
            "--event-out".into(),
            event_path.as_os_str().to_owned(),
        ]);
        let verified = good(run(&args)?)?;
        assert_eq!(field(&verified, "status")?, "native_replay_matched");
        assert_eq!(member(&verified, "native_replayed")?, &Value::Bool(true));
        assert_eq!(
            member(&verified, "frames_replayed")?.integer(),
            Some((cameras * FRAMES) as i128)
        );
        assert_eq!(member(&verified, "event")?, member(&inspected, "event")?);
        assert_eq!(parse(&fs::read_to_string(report_path)?)?, verified);
        assert_eq!(
            parse(&fs::read_to_string(event_path)?)?,
            *member(&verified, "event")?
        );
        assert_eq!(tree(&f.root)?, before, "replay changed deployment bytes");
        drop(writer);
        cx.drain_and_finalize();
    }
    Ok(())
}

#[test]
fn incomplete_journals_are_refused_without_recovery_or_exports() -> Test {
    let f = Fixture::new("immutable-journal-tail", 1)?;
    let event = f.publish(false)?;
    let inspection = good(run(&f.read(&event))?)?;
    let verify = verification_args(&inspection)?;
    for relative in ["ledger/journal.fssj", "effects/journal.fssj"] {
        let path = f.root.join(relative);
        let original = fs::read(&path)?;
        let mut damaged = original.clone();
        damaged.extend_from_slice(b"incomplete-journal-frame");
        fs::write(&path, damaged)?;
        let before = tree(&f.root)?;
        let event_path = f.directory.0.join("refused-event.json");
        let report_path = f.directory.0.join("refused-inspection.json");
        for mut args in [f.read(&event), verify.clone()] {
            args.extend([
                "--event-out".into(),
                event_path.as_os_str().to_owned(),
                "--report-out".into(),
                report_path.as_os_str().to_owned(),
            ]);
            refuses(run(&args)?, "ERR-CLI");
            assert!(!event_path.exists());
            assert!(!report_path.exists());
            assert_eq!(
                tree(&f.root)?,
                before,
                "read or replay repaired an incomplete journal"
            );
        }
        fs::write(path, original)?;
    }
    Ok(())
}

#[test]
fn read_allowance_or_metadata_damage_never_emits_or_exports_a_success() -> Test {
    let f = Fixture::new("immutable-read-refusals", 1)?;
    let event = f.publish(false)?;
    let inspected = good(run(&f.read(&event))?)?;
    let before = tree(&f.root)?;
    let event_path = f.directory.0.join("refused-event.json");
    let report_path = f.directory.0.join("refused-inspection.json");
    let mut args = f.read(&event);
    args.extend([
        "--event-out".into(),
        event_path.as_os_str().to_owned(),
        "--report-out".into(),
        report_path.as_os_str().to_owned(),
    ]);
    for key in ["--max-read-bytes", "--max-read-objects"] {
        let mut bounded = args.clone();
        bounded.extend([key.into(), "1".into()]);
        refuses(run(&bounded)?, "ERR-CLI");
        assert!(!event_path.exists());
        assert!(!report_path.exists());
        assert_eq!(tree(&f.root)?, before);
        let mut verify = verification_args(&inspected)?;
        set(&mut verify, key, "1")?;
        verify.extend([
            "--event-out".into(),
            event_path.as_os_str().to_owned(),
            "--report-out".into(),
            report_path.as_os_str().to_owned(),
        ]);
        refuses(run(&verify)?, "ERR-CLI");
        assert!(!event_path.exists());
        assert!(!report_path.exists());
        assert_eq!(tree(&f.root)?, before);
    }
    let cx = context(&f.root)?;
    let writer = ReferenceDeployment::reopen(&f.root, SITE, &cx)?;
    let root = ContentDigest::parse(&field(&inspected, "event_root")?)?;
    let path = writer.publisher().spool().object_path(root);
    drop(writer);
    cx.drain_and_finalize();
    let mut damaged = fs::read(&path)?;
    *damaged.last_mut().ok_or("empty retained event manifest")? ^= 0x80;
    fs::write(&path, damaged)?;
    let before = tree(&f.root)?;
    refuses(run(&args)?, "ERR-CLI");
    assert!(!event_path.exists());
    assert!(!report_path.exists());
    assert_eq!(tree(&f.root)?, before, "read repaired retained metadata");
    Ok(())
}
