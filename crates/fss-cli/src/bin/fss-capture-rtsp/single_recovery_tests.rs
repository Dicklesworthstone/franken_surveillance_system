#![forbid(unsafe_code)]
//! Recovery requests preserve the original capture scope and never delegate to intake.

use super::*;

type Test<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn args() -> Vec<OsString> {
    let mut input: Vec<OsString> = [
        ("--root", "/owner/archive"),
        ("--pins", "/owner/pins"),
        ("--peer", "127.0.0.1:8554"),
        ("--authority", "camera.test:8554"),
        ("--presentation", "/camera/main"),
        ("--control-root", "/camera"),
        ("--sensor-id", "sensor:camera"),
        ("--stream-id", "stream:main"),
        ("--generation", "1"),
        ("--ingress", "1"),
        ("--ssrc", "7"),
        ("--frame-duration-ticks", "18000"),
        ("--stop-after-pictures", "2"),
        ("--owner-authorized", "yes"),
        ("--plaintext", "yes"),
        ("--retain-originals", "yes"),
    ]
    .into_iter()
    .flat_map(|(key, value)| [OsString::from(key), OsString::from(value)])
    .collect();
    for key in [
        "--anchor",
        "--receive-clock",
        "--timing-evidence",
        "--journal-id",
    ] {
        input.extend([
            key.into(),
            ContentDigest::sha256(key.as_bytes()).to_text().into(),
        ]);
    }
    input
}

fn set(input: &mut Vec<OsString>, key: &str, value: &str) {
    if let Some(index) = input.iter().position(|arg| arg == key) {
        input[index + 1] = value.into();
    } else {
        input.extend([key.into(), value.into()]);
    }
}

#[test]
fn work_recovery_preserves_original_scope_including_optional_supervision() -> Test {
    for codec in ["avc", "hevc"] {
        for supervision in [None, Some("1"), Some("600000")] {
            let mut input = args();
            set(&mut input, "--codec", codec);
            if let Some(timeout) = supervision {
                set(&mut input, "--progress-timeout-ms", timeout);
            }
            let original = SinglePlan::parse(&input)?;
            set(&mut input, "--recover", "yes");
            let recovering = SinglePlan::parse(&input)?;
            assert_eq!(recovering.capture_digest()?, original.digest()?);
            assert_eq!(recovering.capture.digest()?, original.capture.digest()?);
            assert_eq!(recovering.attempts().len(), 1);
            assert!(std::ptr::eq(&recovering.attempts()[0], &recovering.capture));
            assert_eq!(recovering.capture.root, original.capture.root);
            assert_eq!(recovering.capture.pins, original.capture.pins);
            assert_eq!(
                recovering.capture.recording_config().scope.generation,
                original.capture.recording_config().scope.generation
            );
            assert_eq!(
                recovering.capture.recording_config().scope.receive_clock,
                original.capture.recording_config().scope.receive_clock
            );
            assert_eq!(
                recovering.capture.pin_scope().journal_id,
                original.capture.pin_scope().journal_id
            );
            assert_eq!(
                recovering.maximum_storage_bytes(),
                original.capture.publication_limits().spool.max_total_bytes
            );
            assert_eq!(recovering.recovery_timeout_ns, Some(30_000_000_000));
            assert!(!recovering.index_catalogs());
        }
    }
    Ok(())
}

#[test]
fn even_the_correct_capture_approval_cannot_admit_recovery_as_network_work() -> Test {
    let mut input = args();
    set(&mut input, "--progress-timeout-ms", "5000");
    let capture_approval = SinglePlan::parse(&input)?.digest()?;
    set(&mut input, "--approve", &capture_approval.to_text());
    set(&mut input, "--recover", "yes");
    let mut recovering = SinglePlan::parse(&input)?;
    let child_before = recovering.capture.approve;
    assert!(recovering.approved());
    assert_eq!(recovering.recovery_approval(), Some(capture_approval));
    assert_eq!(recovering.admit(), Err("ERR-CAPTURE-RTSP-STATE-001"));
    assert_eq!(recovering.capture.approve, child_before);
    Ok(())
}

#[test]
fn recovery_timeout_is_separate_from_the_capture_basis_and_never_widens_native_limits() -> Test {
    let mut input = args();
    let original = SinglePlan::parse(&input)?;
    set(&mut input, "--recover", "yes");
    for (milliseconds, nanoseconds) in [("1", 1_000_000), ("3600000", 3_600_000_000_000)] {
        set(&mut input, "--recovery-timeout-ms", milliseconds);
        let recovering = SinglePlan::parse(&input)?;
        assert_eq!(recovering.recovery_timeout_ns, Some(nanoseconds));
        assert_eq!(recovering.capture_digest()?, original.digest()?);
        assert_eq!(recovering.capture.timeout_ns, original.capture.timeout_ns);
        assert_eq!(
            recovering.capture.drain_timeout_ns,
            original.capture.drain_timeout_ns
        );
        assert_eq!(recovering.capture.max_steps, original.capture.max_steps);
    }
    Ok(())
}

#[test]
fn recovery_parser_refuses_ambiguous_malformed_or_unpaired_options() {
    let mut input = args();
    set(&mut input, "--recovery-timeout-ms", "30000");
    assert!(SinglePlan::parse(&input).is_err());
    set(&mut input, "--recover", "yes");
    for value in [
        "",
        "0",
        "3600001",
        "-1",
        "+1",
        "1.0",
        "1e3",
        "18446744073709551616",
    ] {
        set(&mut input, "--recovery-timeout-ms", value);
        assert!(SinglePlan::parse(&input).is_err(), "{value}");
    }
    set(&mut input, "--recovery-timeout-ms", "30000");
    for value in ["no", "true", "YES", "repair"] {
        set(&mut input, "--recover", value);
        assert!(SinglePlan::parse(&input).is_err(), "{value}");
    }
    set(&mut input, "--recover", "yes");
    for (key, value) in [
        ("--recover", "yes"),
        ("--recovery-timeout-ms", "30000"),
        ("--max-attempts", "1"),
        ("--unknown", "yes"),
    ] {
        let mut invalid = input.clone();
        invalid.extend([key.into(), value.into()]);
        assert!(SinglePlan::parse(&invalid).is_err(), "{key}");
    }
    input.push("--recover".into());
    assert!(SinglePlan::parse(&input).is_err());
}

#[test]
fn recovery_does_not_increment_a_maximal_generation_or_rehash_receive_clocks() -> Test {
    let mut input = args();
    set(&mut input, "--generation", &u64::MAX.to_string());
    set(&mut input, "--ingress", &u128::MAX.to_string());
    let native = Options::parse(&input)?;
    set(&mut input, "--recover", "yes");
    let forward = SinglePlan::parse(&input)?;
    let reversed: Vec<_> = input
        .chunks_exact(2)
        .rev()
        .flat_map(|pair| pair.iter().cloned())
        .collect();
    let backward = SinglePlan::parse(&reversed)?;
    assert_eq!(forward.capture_digest()?, native.digest()?);
    assert_eq!(backward.capture_digest()?, forward.capture_digest()?);
    assert_eq!(forward.capture.recording_config().scope.generation, u64::MAX);
    assert_eq!(forward.capture.root, native.root);
    assert_eq!(forward.capture.pins, native.pins);
    Ok(())
}

#[test]
fn omitting_recovery_preserves_native_preview_and_capture_delegation() -> Test {
    for codec in ["avc", "hevc"] {
        let mut input = args();
        set(&mut input, "--codec", codec);
        let native = Options::parse(&input)?;
        let mut current = SinglePlan::parse(&input)?;
        assert_eq!(current.preview()?, native.preview()?);
        assert_eq!(current.recovery_timeout_ns, None);
        current.approval = Some(current.digest()?);
        assert_eq!(current.admit()?, None);
        assert_eq!(current.capture.approve, current.approval);
    }
    Ok(())
}

#[test]
fn catalog_recovery_is_explicit_and_does_not_change_the_original_capture_identity() -> Test {
    for supervision in [None, Some("5000")] {
        let mut input = args();
        if let Some(timeout) = supervision {
            set(&mut input, "--progress-timeout-ms", timeout);
        }
        let original = SinglePlan::parse(&input)?;
        set(&mut input, "--recover", "index");
        let mut indexing = SinglePlan::parse(&input)?;
        assert!(indexing.index_catalogs());
        assert_eq!(indexing.capture_digest()?, original.digest()?);
        assert_eq!(indexing.attempts().len(), 1);
        assert_eq!(indexing.capture.root, original.capture.root);
        assert_eq!(indexing.capture.pins, original.capture.pins);
        indexing.approval = Some(original.digest()?);
        assert_eq!(indexing.admit(), Err("ERR-CAPTURE-RTSP-STATE-001"));
        input.extend(["--recover".into(), "yes".into()]);
        assert!(SinglePlan::parse(&input).is_err());
    }
    Ok(())
}

#[cfg(unix)]
#[path = "../../../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod source;

#[cfg(unix)]
mod native {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    use fss_cli::json_input::parse;
    use fss_publication::{LocalRootPublisher, NeverCancel};
    use fss_reference::rtsp::archive_pins::HevcArchivePinJournal;
    use fss_reference::rtsp::recording::hevc::{
        PreparedHevcRecording, local::load_hevc_recording, prepare_hevc_recording,
    };
    use fss_reference::rtsp::recording_archive::checkpoint::write_ahead::{
        CheckpointedArchiveProgress, CheckpointedHevcArchiveWriter,
    };
    use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;

    struct Directory(PathBuf);
    impl Directory {
        fn new(label: &str) -> Test<Self> {
            use std::os::unix::fs::DirBuilderExt;
            for index in 0..100 {
                let path = std::env::temp_dir().join(format!(
                    "fss-single-recovery-{label}-{}-{index}",
                    std::process::id()
                ));
                match fs::DirBuilder::new().mode(0o700).create(&path) {
                    Ok(()) => return Ok(Self(fs::canonicalize(path)?)),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
            }
            Err("test directory reservation exhausted".into())
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn input(directory: &Directory, codec: &str, mode: &str) -> Test<Vec<OsString>> {
        let mut input = args();
        for (key, leaf) in [("--root", "archive"), ("--pins", "pins")] {
            let path = directory.0.join(leaf);
            set(&mut input, key, path.to_str().ok_or("UTF-8 test path")?);
        }
        set(&mut input, "--codec", codec);
        set(&mut input, "--recover", mode);
        Ok(input)
    }

    fn digest_field(report: &str, key: &str) -> Test<ContentDigest> {
        let value = parse(report)?;
        let fields = value.object().ok_or("report object missing")?;
        let text = fields
            .get(key)
            .and_then(|value| value.text())
            .ok_or("digest field missing")?;
        Ok(ContentDigest::parse(text)?)
    }

    fn approve(plan: &mut SinglePlan) -> Test<ContentDigest> {
        let approval = digest_field(&plan.preview()?, "approval")?;
        assert_ne!(approval, plan.capture_digest()?);
        plan.approval = Some(approval);
        Ok(approval)
    }

    fn recording(options: &Options) -> Test<PreparedHevcRecording> {
        let packets = source::packets()?;
        Ok(prepare_hevc_recording(
            options.recording_config().scope,
            &source::configuration()?,
            90_000,
            &source::timings(2),
            &source::borrowed(&packets[..6]),
        )?)
    }

    /// Drop the live writer before recovery: only retained originals and pins survive.
    fn fixture(options: &Options, durable_work: bool) -> Test<ContentDigest> {
        let namespace = HevcArchiveNamespace::new(options.catalog_scope().clone())?;
        assert_eq!(namespace.digest(), options.pin_scope().archive_namespace);
        let mut publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
        let mut pins = HevcArchivePinJournal::create(
            &options.pins,
            options.pin_scope(),
            options.pin_limits(),
            &NeverCancel,
        )?;
        let mut writer = CheckpointedHevcArchiveWriter::open(
            &mut publisher,
            namespace,
            options.work_limits().archive,
            options.work_limits(),
            256,
            0,
            1000,
            &NeverCancel,
        )?;
        let window = recording(options)?;
        let expected = window.manifest().root();
        let bytes = window.byte_len();
        writer.offer(window, bytes, 0)?;
        let CheckpointedArchiveProgress::PinRequired(pin) = writer.step(0, &NeverCancel)? else {
            return Err("missing checkpoint candidate".into());
        };
        pins.persist_candidate(&pin, &NeverCancel)?;
        if durable_work {
            writer.acknowledge_checkpoint(&pin, 0, &NeverCancel)?;
            assert!(matches!(
                writer.step(0, &NeverCancel)?,
                CheckpointedArchiveProgress::WorkDurable { .. }
            ));
        }
        let _retirement = writer.retire();
        Ok(expected)
    }

    fn names(path: &Path) -> Test<Vec<OsString>> {
        let mut names = fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.file_name()))
            .collect::<std::io::Result<Vec<_>>>()?;
        names.sort();
        Ok(names)
    }

    fn journal(options: &Options) -> Test<Vec<u8>> {
        Ok(fs::read(options.pins.join("pins.journal"))?)
    }

    fn window_present(options: &Options) -> Test<bool> {
        let publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
        let namespace = HevcArchiveNamespace::new(options.catalog_scope().clone())?;
        Ok(publisher.root(&namespace.window_slot(0)?).is_some())
    }

    fn cold_window(options: &Options, expected: ContentDigest) -> Test {
        let publisher = LocalRootPublisher::open(&options.root, options.publication_limits())?;
        let namespace = HevcArchiveNamespace::new(options.catalog_scope().clone())?;
        let loaded = load_hevc_recording(
            &publisher,
            &namespace.window_slot(0)?,
            expected,
            &options.recording_config().scope,
            &NeverCancel,
        )?;
        let original = recording(options)?;
        assert_eq!(loaded.manifest().root(), expected);
        assert_eq!(loaded.objects().source, original.objects().source);
        assert_eq!(loaded.objects().media, original.objects().media);
        assert_eq!(loaded.samples(), original.samples());
        assert_eq!(loaded.source_only_nals(), 1);
        assert_eq!(loaded.summary().samples, 2);
        assert!(publisher.root(&namespace.window_slot(1)?).is_none());
        Ok(())
    }

    #[test]
    fn unobserved_store_previews_stay_offline_and_do_not_create_an_attempt_epoch() -> Test {
        let directory = Directory::new("preview")?;
        for codec in ["avc", "hevc"] {
            for mode in ["yes", "index"] {
                let mut input = input(&directory, codec, mode)?;
                let missing = directory.0.join("missing-credential");
                set(
                    &mut input,
                    "--credential-file",
                    missing.to_str().ok_or("UTF-8 path")?,
                );
                set(&mut input, "--auth-realm", "camera-owner");
                set(&mut input, "--progress-timeout-ms", "5000");
                let plan = SinglePlan::parse(&input)?;
                let report = plan.preview()?;
                assert_eq!(digest_field(&report, "capture_plan")?, plan.capture_digest()?);
                assert!(report.contains("\"network_requested\":false"));
                assert!(report.contains("\"capture_complete\":false"));
                assert!(report.contains("both_stores_unobserved"));
                assert!(!report.contains("attempt-0001"));
                assert_eq!(plan.capture.root, directory.0.join("archive"));
                assert_eq!(plan.capture.pins, directory.0.join("pins"));
                assert!(names(&directory.0)?.is_empty());
            }
        }
        Ok(())
    }

    #[test]
    fn capture_approval_and_changed_deadline_refuse_before_restoring_originals() -> Test {
        let directory = Directory::new("approval")?;
        let mut plan = SinglePlan::parse(&input(&directory, "hevc", "yes")?)?;
        fixture(&plan.capture, true)?;
        let pins = journal(&plan.capture)?;
        let roots = names(&plan.capture.root.join("roots"))?;
        plan.approval = Some(plan.capture_digest()?);
        assert_eq!(plan.execute(), Err("ERR-CAPTURE-RTSP-APPROVAL-001"));
        approve(&mut plan)?;
        plan.recovery_timeout_ns = Some(29_000_000_000);
        assert_eq!(plan.execute(), Err("ERR-CAPTURE-RTSP-APPROVAL-001"));
        assert_eq!(journal(&plan.capture)?, pins);
        assert_eq!(names(&plan.capture.root.join("roots"))?, roots);
        assert!(!window_present(&plan.capture)?);
        Ok(())
    }

    #[test]
    fn cold_work_restoration_is_exact_and_stale_reply_retries_require_current_pins() -> Test {
        let directory = Directory::new("restore")?;
        let mut input = input(&directory, "hevc", "yes")?;
        // Authentication configuration is retained in the original plan, but recovery has
        // neither a reason nor authority to read the absent credential or contact the peer.
        let missing = directory.0.join("absent-credential");
        set(
            &mut input,
            "--credential-file",
            missing.to_str().ok_or("UTF-8 path")?,
        );
        set(&mut input, "--auth-realm", "camera-owner");
        set(&mut input, "--progress-timeout-ms", "5000");
        let before = SinglePlan::parse(&input)?;
        let expected = fixture(&before.capture, true)?;
        drop(before);
        let mut cold = SinglePlan::parse(&input)?;
        let old_approval = approve(&mut cold)?;
        cold.execute()?;
        cold_window(&cold.capture, expected)?;
        let pins = journal(&cold.capture)?;
        let roots = names(&cold.capture.root.join("roots"))?;
        assert_eq!(cold.execute(), Err("ERR-CAPTURE-RTSP-APPROVAL-001"));
        let new_approval = approve(&mut cold)?;
        assert_ne!(old_approval, new_approval);
        cold.execute()?;
        cold_window(&cold.capture, expected)?;
        assert_eq!(journal(&cold.capture)?, pins);
        assert_eq!(names(&cold.capture.root.join("roots"))?, roots);
        assert!(!missing.exists());
        assert_eq!(names(&directory.0)?.len(), 2);
        Ok(())
    }

    #[test]
    fn a_candidate_without_protected_originals_cannot_be_replaced_by_recapture() -> Test {
        let directory = Directory::new("unpublished")?;
        let mut plan = SinglePlan::parse(&input(&directory, "hevc", "yes")?)?;
        fixture(&plan.capture, false)?;
        let pins = journal(&plan.capture)?;
        let roots = names(&plan.capture.root.join("roots"))?;
        approve(&mut plan)?;
        assert_eq!(plan.execute(), Err("ERR-CAPTURE-RTSP-STORAGE-001"));
        assert_eq!(journal(&plan.capture)?, pins);
        assert_eq!(names(&plan.capture.root.join("roots"))?, roots);
        assert!(!window_present(&plan.capture)?);
        assert_eq!(names(&directory.0)?.len(), 2);
        Ok(())
    }

    #[test]
    fn index_requires_settled_work_and_separate_approval_then_retries_without_new_pages() -> Test {
        let directory = Directory::new("index")?;
        let work_input = input(&directory, "hevc", "yes")?;
        let mut work = SinglePlan::parse(&work_input)?;
        let expected = fixture(&work.capture, true)?;
        let index_input = input(&directory, "hevc", "index")?;
        let mut indexing = SinglePlan::parse(&index_input)?;
        let before = journal(&work.capture)?;
        assert!(indexing.preview().is_err());
        assert_eq!(journal(&work.capture)?, before);
        approve(&mut work)?;
        work.execute()?;
        let recovery_approval = approve(&mut work)?;
        indexing.approval = Some(recovery_approval);
        let pins_before_index = journal(&work.capture)?;
        let roots_before_index = names(&work.capture.root.join("roots"))?;
        assert_eq!(indexing.execute(), Err("ERR-CAPTURE-RTSP-APPROVAL-001"));
        assert_eq!(journal(&work.capture)?, pins_before_index);
        assert_eq!(names(&work.capture.root.join("roots"))?, roots_before_index);
        let preview = indexing.preview()?;
        assert!(preview.contains("\"new_pages\":1"));
        assert!(preview.contains("\"durable_windows\":1"));
        assert!(preview.contains("\"indexed_windows\":0"));
        approve(&mut indexing)?;
        indexing.execute()?;
        cold_window(&indexing.capture, expected)?;
        let pins = journal(&indexing.capture)?;
        let roots = names(&indexing.capture.root.join("roots"))?;
        let no_op = indexing.preview()?;
        assert!(no_op.contains("\"new_pages\":0"));
        assert!(no_op.contains("\"indexed_windows\":1"));
        approve(&mut indexing)?;
        indexing.execute()?;
        assert_eq!(journal(&indexing.capture)?, pins);
        assert_eq!(names(&indexing.capture.root.join("roots"))?, roots);
        cold_window(&indexing.capture, expected)?;
        Ok(())
    }

    #[test]
    fn partial_layout_and_symlinked_journal_refuse_without_creating_replacements() -> Test {
        use std::os::unix::fs::symlink;
        let partial = Directory::new("partial")?;
        let plan = SinglePlan::parse(&input(&partial, "hevc", "yes")?)?;
        fs::create_dir(&plan.capture.root)?;
        assert!(plan.preview().is_err());
        assert!(!plan.capture.pins.exists());
        let directory = Directory::new("replaced")?;
        let mut plan = SinglePlan::parse(&input(&directory, "hevc", "yes")?)?;
        fixture(&plan.capture, true)?;
        approve(&mut plan)?;
        let retained = directory.0.join("retained-pins");
        let old = journal(&plan.capture)?;
        fs::rename(&plan.capture.pins, &retained)?;
        symlink(&retained, &plan.capture.pins)?;
        assert_eq!(plan.execute(), Err("ERR-CAPTURE-RTSP-ROOT-001"));
        assert_eq!(fs::read(retained.join("pins.journal"))?, old);
        assert!(!window_present(&plan.capture)?);
        Ok(())
    }

    #[test]
    fn recovery_mode_and_timeout_reject_non_utf8_before_any_io() {
        use std::os::unix::ffi::OsStringExt;
        for key in ["--recover", "--recovery-timeout-ms"] {
            let mut input = args();
            input.extend([key.into(), OsString::from_vec(vec![0xff])]);
            assert!(SinglePlan::parse(&input).is_err());
        }
    }
}
