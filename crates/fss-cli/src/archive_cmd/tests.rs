#![forbid(unsafe_code)]
use super::*;
use fss_publication::{NeverCancel, SlotName};
use fss_reference::rtsp::recording::hevc::{PreparedHevcRecording, prepare_hevc_recording};
use fss_reference::rtsp::recording::local::{RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_archive::hevc::HevcArchiveNamespace;
use fss_reference::rtsp::recording_catalog::hevc::local::HevcCatalogPublication;
use fss_reference::rtsp::recording_catalog::hevc::{HevcCatalogWindow, prepare_hevc_catalog};
use fss_reference::rtsp::recording_catalog::local::CatalogProgress;
#[path = "../../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod source;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;
pub(super) struct FixedClock {
    now: u64,
    end: u64,
}
impl PublishCancellation for FixedClock {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.now >= self.end
    }
}
impl OperationClock for FixedClock {
    fn now_ns(&self) -> Result<u64> {
        Ok(self.now)
    }
    fn deadline_ns(&self) -> u64 {
        self.end
    }
}
fn basis() -> std::result::Result<CatalogScope, Box<dyn std::error::Error>> {
    Ok(CatalogScope {
        recording: source::scope()?,
        decode_clock: ContentDigest::sha256(b"operator-dts"),
        time_scale: 90_000,
    })
}
pub(super) fn argv(action: &str, extra: &[&str]) -> Vec<OsString> {
    let digest = ContentDigest::sha256(b"explicit parser fixture").to_text();
    [
        action,
        "--root",
        "/unused/private-archive",
        "--codec",
        "hevc",
        "--sensor",
        "sensor-fixture",
        "--stream",
        "stream-fixture",
        "--generation",
        "1",
        "--anchor",
        &digest,
        "--receive-clock",
        &digest,
        "--decode-clock",
        &digest,
        "--time-scale",
        "90000",
    ]
    .into_iter()
    .chain(extra.iter().copied())
    .map(OsString::from)
    .collect()
}
fn options() -> std::result::Result<ArchiveOptions, Box<dyn std::error::Error>> {
    let mut o = parse_archive_args(&argv("inspect", &[]))?.ok_or("options")?;
    o.scope = basis()?;
    Ok(o)
}
pub(super) fn path(name: &str) -> std::result::Result<PathBuf, Box<dyn std::error::Error>> {
    let p = std::env::temp_dir().join(format!(
        "fss-archive-operator-{}-{name}",
        std::process::id()
    ));
    match fs::remove_dir_all(&p) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(p)
}
pub(super) fn window(
    base: u64,
) -> std::result::Result<PreparedHevcRecording, Box<dyn std::error::Error>> {
    let mut timings = source::timings(4);
    for t in &mut timings {
        t.decode_time += base;
    }
    Ok(prepare_hevc_recording(
        basis()?.recording,
        &source::configuration()?,
        90_000,
        &timings,
        &source::borrowed(&source::packets()?),
    )?)
}
fn publish(p: &mut LocalRootPublisher, slot: &SlotName, w: &PreparedHevcRecording) -> TestResult {
    let mut request =
        RecordingPublication::new(w.publication_plan(), p, slot.clone(), w.byte_len(), 100)?;
    for i in 0..4 {
        assert!(matches!(
            request.step(i, &NeverCancel)?,
            RecordingProgress::ChildStaged { .. }
        ));
    }
    assert!(matches!(
        request.step(4, &NeverCancel)?,
        RecordingProgress::Published(_)
    ));
    Ok(())
}
pub(super) fn setup(
    name: &str,
) -> std::result::Result<(ArchiveOptions, LocalRootPublisher), Box<dyn std::error::Error>> {
    let mut o = options()?;
    o.root = path(name)?;
    let mut p = LocalRootPublisher::open(&o.root, o.storage_limits)?;
    let ns = HevcArchiveNamespace::new(o.scope.clone())?;
    for ordinal in 0..3 {
        let w = window(ordinal as u64 * 100_000)?;
        let slot = ns.window_slot(ordinal)?;
        publish(&mut p, &slot, &w)?;
        // Third durable window deliberately has no catalog: it must remain unindexed.
        if ordinal < 2 {
            let catalog = prepare_hevc_catalog(
                o.scope.clone(),
                &[HevcCatalogWindow {
                    slot: &slot,
                    recording: &w,
                }],
            )?;
            let mut job = HevcCatalogPublication::new(
                &catalog,
                &mut p,
                ns.page_slot(ordinal)?,
                catalog.byte_len(),
                100,
            )?;
            assert!(matches!(
                job.step(0, &NeverCancel)?,
                CatalogProgress::WindowVerified { .. }
            ));
            assert!(matches!(
                job.step(1, &NeverCancel)?,
                CatalogProgress::IndexStaged { .. }
            ));
            assert!(matches!(
                job.step(2, &NeverCancel)?,
                CatalogProgress::Published(_)
            ));
        }
    }
    let snapshot =
        CodecArchiveSnapshot::<HevcArchiveCodec>::load(&p, ns, o.archive_limits, &NeverCancel)?;
    o.expected = Some(snapshot.digest()?);
    Ok((o, p))
}
pub(super) fn clock() -> FixedClock {
    FixedClock { now: 1, end: 100 }
}

#[test]
fn arguments_pin_codec_scope_clock_and_ranges_without_effects() -> TestResult {
    assert!(parse_archive_args(&argv("inspect", &[]))?.is_some());
    let digest = ContentDigest::sha256(b"snapshot").to_text();
    assert!(
        parse_archive_args(&argv(
            "query",
            &["--expected-snapshot", &digest, "--start", "0", "--end", "1"]
        ))?
        .is_some()
    );
    for extra in [
        vec!["--codec", "avc"],
        vec!["--unknown", "1"],
        vec!["--timeout-ms", "0"],
        vec!["--max-windows", "4097"],
        vec!["--max-objects", "131073"],
        vec!["--max-pages", "+1"],
        vec!["--start", "1"],
        vec!["--time-scale"],
        vec!["--max-total-bytes", "18446744073709551616"],
    ] {
        assert!(parse_archive_args(&argv("inspect", &extra)).is_err());
    }
    for extra in [
        vec!["--start", "0", "--end", "1"],
        vec!["--expected-snapshot", &digest, "--start", "1", "--end", "1"],
    ] {
        assert!(parse_archive_args(&argv("verify", &extra)).is_err());
    }
    for (at, replacement) in [
        (4, "auto"),
        (10, "0"),
        (18, "0"),
        (12, "md5:00000000000000000000000000000000"),
    ] {
        let mut args = argv("inspect", &[]);
        args[at] = replacement.into();
        assert!(parse_archive_args(&args).is_err());
    }
    Ok(())
}
#[test]
fn help_and_diagnostics_do_not_echo_private_paths_or_values() -> TestResult {
    assert!(parse_archive_args(&["help".into()])?.is_none());
    assert!(parse_archive_args(&["help".into(), "extra".into()]).is_err());
    let mut args = argv("inspect", &[]);
    args.extend(["--private-token".into(), "SECRET".into()]);
    let e = parse_archive_args(&args).err().ok_or("unexpected parse")?;
    assert!(!format!("{e:?}").contains("SECRET"));
    assert!(!format!("{:?}", options()?).contains("private-archive"));
    Ok(())
}
#[cfg(unix)]
#[test]
fn root_path_accepts_native_bytes_while_identity_fields_require_utf8() -> TestResult {
    use std::os::unix::ffi::OsStringExt;
    let mut args = argv("inspect", &[]);
    args[2] = OsString::from_vec(b"/private/\xff".to_vec());
    assert!(parse_archive_args(&args)?.is_some());
    args[6] = OsString::from_vec(b"sensor-\xff".to_vec());
    assert!(parse_archive_args(&args).is_err());
    Ok(())
}
#[test]
fn nonexistent_or_incomplete_root_is_not_created_or_migrated() -> TestResult {
    let root = path("nonexistent")?;
    assert!(matches!(
        existing_archive(&root),
        Err(ArchiveCommandError::NotArchive)
    ));
    assert!(!root.exists());
    fs::create_dir(&root)?;
    assert!(matches!(
        existing_archive(&root),
        Err(ArchiveCommandError::NotArchive)
    ));
    assert_eq!(fs::read_dir(&root)?.count(), 0);
    Ok(())
}
#[test]
fn inspect_reports_durable_unindexed_tail_and_exact_scope() -> TestResult {
    let (o, p) = setup("inspect")?;
    let report = execute_for::<HevcArchiveCodec>(&o, &p, &clock())?;
    assert!(report.contains("\"durable_windows\":3,\"indexed_windows\":2,\"pages\":2"));
    assert_eq!(report.matches("\"indexed\":false").count(), 1);
    assert!(report.contains(&quoted(&o.expected.ok_or("pin")?.to_text())));
    assert!(report.contains("\"coverage_claim\":\"not_claimed\""));
    assert!(!report.contains("private-archive"));
    Ok(())
}
#[test]
fn query_and_verify_preserve_gaps_and_price_whole_recordings() -> TestResult {
    let (mut o, p) = setup("query")?;
    o.action = Action::Query;
    o.query = Some(70_000..210_000);
    let query = execute_for::<HevcArchiveCodec>(&o, &p, &clock())?;
    assert!(query.contains("\"unindexed\":[[72000,100000],[172000,210000]]"));
    assert!(query.contains("\"range_read_completed\":false"));
    assert_eq!(query.matches("\"indexed\":true").count(), 2);
    o.action = Action::Verify;
    let read = execute_for::<HevcArchiveCodec>(&o, &p, &clock())?;
    assert!(
        read.contains(
            "\"requested_interval\":[70000,72000],\"returned_decode_interval\":[0,72000]"
        )
    );
    assert!(read.contains("\"range_read_completed\":true,\"verified_windows\":2"));
    assert!(read.contains("objects_source_init_media_index"));
    o.query = Some(1..2);
    o.query_limits.max_output_bytes = 1;
    assert!(execute_for::<HevcArchiveCodec>(&o, &p, &clock()).is_err());
    Ok(())
}
#[test]
fn exact_snapshot_pin_refuses_changed_inventory_or_wrong_codec() -> TestResult {
    let (mut o, p) = setup("pin")?;
    o.action = Action::Verify;
    o.query = Some(0..1);
    o.expected = Some(ContentDigest::sha256(b"not this inventory"));
    assert!(matches!(
        execute_for::<HevcArchiveCodec>(&o, &p, &clock()),
        Err(ArchiveCommandError::SnapshotMismatch)
    ));
    assert!(matches!(
        execute_for::<AvcArchiveCodec>(&o, &p, &clock()),
        Err(ArchiveCommandError::SnapshotMismatch)
    ));
    Ok(())
}
#[test]
fn read_outside_indexed_pages_is_explicitly_empty_not_coverage() -> TestResult {
    let (mut o, p) = setup("empty")?;
    o.action = Action::Verify;
    o.query = Some(200_000..210_000);
    let report = execute_for::<HevcArchiveCodec>(&o, &p, &clock())?;
    assert!(report.contains("\"unindexed\":[[200000,210000]]"));
    assert!(
        report.contains("\"verified\":[],\"range_read_completed\":true,\"verified_windows\":0")
    );
    Ok(())
}
#[test]
fn expired_operation_and_inventory_quota_cannot_emit_a_report() -> TestResult {
    let (mut o, p) = setup("limits")?;
    assert!(matches!(
        execute_for::<HevcArchiveCodec>(&o, &p, &FixedClock { now: 100, end: 100 }),
        Err(ArchiveCommandError::Deadline)
    ));
    o.archive_limits.max_windows = 2;
    assert!(execute_for::<HevcArchiveCodec>(&o, &p, &clock()).is_err());
    Ok(())
}
#[test]
fn corrupt_original_storage_refuses_even_a_metadata_query() -> TestResult {
    let (mut o, p) = setup("corrupt")?;
    o.action = Action::Query;
    o.query = Some(0..1);
    let w = window(0)?;
    let digest = w.publication_plan().children()[0].1.to_text();
    let name = digest.strip_prefix("sha256:").ok_or("sha256")?;
    fs::write(
        o.root.join("spool/objects").join(name),
        b"corrupt source object",
    )?;
    assert!(execute_for::<HevcArchiveCodec>(&o, &p, &clock()).is_err());
    Ok(())
}
#[test]
fn executable_service_reopens_existing_archive_without_creating_output() -> TestResult {
    let (mut o, p) = setup("reopen")?;
    drop(p);
    assert_eq!(existing_archive(&o.root)?, fs::canonicalize(&o.root)?);
    o.action = Action::Verify;
    o.query = Some(0..172_000);
    let report = execute_archive(&o)?;
    assert!(report.contains("\"verified_windows\":2"));
    assert!(report.ends_with("\"complete\":true}\n"));
    Ok(())
}
#[test]
fn report_budget_refuses_before_appending_partial_item() -> TestResult {
    let mut out = "a".repeat(MAX_REPORT_BYTES);
    assert!(matches!(
        append(&mut out, "b"),
        Err(ArchiveCommandError::ReportLimit)
    ));
    assert_eq!(out.len(), MAX_REPORT_BYTES);
    Ok(())
}
