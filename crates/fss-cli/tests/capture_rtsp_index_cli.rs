#![forbid(unsafe_code)]
//! Fresh-process indexing -> complete catalog import -> native cold HEVC decode.
//! All media is a pinned synthetic fixture; the reserved loopback peer is never contacted.
#[path = "../../fss-reference/tests/hevc_recording_support/mod.rs"]
mod source;

use fss_cli::json_input::{Value, parse};
use fss_core::{ContentDigest, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_publication::{LocalPublicationLimits, LocalRootPublisher, NeverCancel};
use fss_reference::rtsp::archive_pins::{ArchivePinLimits, ArchivePinScope, HevcArchivePinJournal};
use fss_reference::rtsp::recording::RecordingScope;
use fss_reference::rtsp::recording::hevc::prepare_hevc_recording;
use fss_reference::rtsp::recording_archive::checkpoint::ArchiveWorkLimits;
use fss_reference::rtsp::recording_archive::checkpoint::write_ahead::{
    CheckpointedArchiveProgress, CheckpointedHevcArchiveWriter,
};
use fss_reference::rtsp::recording_archive::{
    ArchiveCodec, ArchiveLimits, CodecArchiveNamespace, CodecArchiveSnapshot, HevcArchiveCodec,
};
use fss_reference::rtsp::recording_catalog::CatalogScope;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, Read};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

type Test<T = ()> = Result<T, Box<dyn std::error::Error>>;
const SITE: &str = "site:index-cli";
const LIMIT: u64 = 2 * 1024 * 1024;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Test<Self> {
        for index in 0..100 {
            let path =
                std::env::temp_dir().join(format!("fss-index-cli-{}-{index}", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(fs::canonicalize(path)?)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err("fixture directory allowance exhausted".into())
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn run(directory: &Directory, name: &str, args: &[OsString]) -> Test<Output> {
    let binary = match name {
        "capture" => env!("CARGO_BIN_EXE_fss-capture-rtsp"),
        "import" => env!("CARGO_BIN_EXE_fss-import-rtsp"),
        "file" => env!("CARGO_BIN_EXE_fss-file"),
        _ => return Err("unknown fixture binary".into()),
    };
    let out = directory.0.join("stdout");
    let err = directory.0.join("stderr");
    let mut child = Process(
        Command::new(binary)
            .args(args)
            .stdin(Stdio::null())
            .stdout(File::create(&out)?)
            .stderr(File::create(&err)?)
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if Instant::now() >= deadline
            || fs::metadata(&out)?.len() > LIMIT
            || fs::metadata(&err)?.len() > LIMIT
        {
            return Err("native process exceeded fixture bounds".into());
        }
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let read = |path| -> Test<Vec<u8>> {
        let mut data = Vec::new();
        File::open(path)?.take(LIMIT + 1).read_to_end(&mut data)?;
        if data.len() as u64 > LIMIT {
            return Err("fixture output bound".into());
        }
        Ok(data)
    };
    Ok(Output {
        status,
        stdout: read(out)?,
        stderr: read(err)?,
    })
}
fn good(output: Output) -> Test<String> {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}
fn field<'a>(v: &'a Value, name: &str) -> Test<&'a Value> {
    v.object()
        .and_then(|v| v.get(name))
        .ok_or_else(|| format!("missing {name}").into())
}
fn text<'a>(v: &'a Value, name: &str) -> Test<&'a str> {
    field(v, name)?
        .text()
        .ok_or_else(|| format!("nontext {name}").into())
}
fn number(v: &Value, name: &str) -> Test<u64> {
    Ok(u64::try_from(field(v, name)?.integer().ok_or("integer")?)?)
}
fn digest(v: &Value, name: &str) -> Test<ContentDigest> {
    Ok(ContentDigest::parse(text(v, name)?)?)
}
fn base(directory: &Directory, peer: &str) -> Vec<OsString> {
    let mut values = vec![OsString::from("reconnect")];
    for (key, value) in [
        ("--root", directory.0.join("capture").display().to_string()),
        ("--pins", directory.0.join("pins").display().to_string()),
        ("--peer", peer.into()),
        ("--authority", peer.into()),
        ("--presentation", "/camera/main".into()),
        ("--control-root", "/camera".into()),
        ("--sensor-id", "sensor:index".into()),
        ("--stream-id", "stream:index".into()),
        ("--generation", "1".into()),
        ("--ingress", "1".into()),
        ("--ssrc", "7".into()),
        ("--codec", "hevc".into()),
        ("--payload-type", "98".into()),
        ("--frame-duration-ticks", "18000".into()),
        ("--stop-after-pictures", "2".into()),
        ("--owner-authorized", "yes".into()),
        ("--plaintext", "yes".into()),
        ("--retain-originals", "yes".into()),
        ("--max-attempts", "1".into()),
    ] {
        values.extend([key.into(), value.into()]);
    }
    for key in [
        "--anchor",
        "--receive-clock",
        "--timing-evidence",
        "--journal-id",
    ] {
        values.extend([
            key.into(),
            ContentDigest::sha256(key.as_bytes()).to_text().into(),
        ]);
    }
    values
}
fn unindexed(child: &Value) -> Test<(PathBuf, ContentDigest, LocalPublicationLimits)> {
    let bounds = field(child, "bounds")?;
    let n = |key| -> Test<usize> { Ok(usize::try_from(number(bounds, key)?)?) };
    let archive = PathBuf::from(text(child, "root")?);
    let storage = LocalPublicationLimits::new(
        n("publication_roots")?,
        n("publication_children")?,
        n("publication_tombstones")?,
        n("publication_scan_entries")?,
        SpoolLimits::new(
            n("spool_objects")?,
            number(bounds, "spool_total_bytes")?,
            n("spool_object_bytes")?,
            n("spool_scan_entries")?,
        ),
    );
    let limits = ArchiveLimits {
        max_windows: n("archive_windows")?,
        max_pages: n("archive_pages")?,
        max_scan_roots: n("archive_scan_roots")?,
        windows_per_page: n("windows_per_page")?,
    };
    let work = ArchiveWorkLimits {
        archive: limits,
        max_pending_bytes: n("work_pending_bytes")?,
        max_graph_objects: n("work_graph_objects")?,
        max_new_bytes: n("work_new_bytes")?,
    };
    let scope = RecordingScope {
        sensor: SensorId::parse(text(child, "sensor")?)?,
        stream: StreamId::parse(text(child, "stream")?)?,
        generation: number(bounds, "generation")?,
        anchor: digest(child, "anchor")?,
        receive_clock: digest(child, "receive_clock")?,
    };
    let catalog = CatalogScope {
        recording: scope.clone(),
        decode_clock: digest(child, "decode_clock")?,
        time_scale: u32::try_from(number(bounds, "time_scale")?)?,
    };
    let namespace = CodecArchiveNamespace::<HevcArchiveCodec>::new(catalog.clone())?;
    assert_eq!(namespace.digest(), digest(child, "archive_namespace")?);
    let mut publisher = LocalRootPublisher::open(&archive, storage)?;
    let mut pins = HevcArchivePinJournal::create(
        text(child, "pins")?,
        ArchivePinScope {
            journal_id: digest(child, "journal_id")?,
            archive_namespace: namespace.digest(),
        },
        ArchivePinLimits {
            max_records: n("pin_records")?,
            max_bytes: n("pin_bytes")?,
        },
        &NeverCancel,
    )?;
    let packets = source::packets()?;
    let recording = prepare_hevc_recording(
        scope,
        &source::configuration()?,
        catalog.time_scale,
        &source::timings(2),
        &source::borrowed(&packets[..6]),
    )?;
    let root = recording.manifest().root();
    let bytes = recording.byte_len();
    let mut writer = CheckpointedHevcArchiveWriter::open(
        &mut publisher,
        namespace,
        limits,
        work,
        256,
        0,
        1000,
        &NeverCancel,
    )?;
    writer.offer(recording, bytes, 0)?;
    let CheckpointedArchiveProgress::PinRequired(pin) = writer.step(0, &NeverCancel)? else {
        return Err("missing checkpoint".into());
    };
    pins.persist_candidate(&pin, &NeverCancel)?;
    writer.acknowledge_checkpoint(&pin, 0, &NeverCancel)?;
    assert!(matches!(
        writer.step(0, &NeverCancel)?,
        CheckpointedArchiveProgress::WorkDurable { .. }
    ));
    let _retained = writer.retire();
    let restored = pins.restore_work(&mut publisher, work, 0, 1000, &NeverCancel)?;
    assert_eq!(restored.durable_windows, 1);
    assert_eq!(restored.indexed_windows, 0);
    let snapshot = CodecArchiveSnapshot::<HevcArchiveCodec>::load(
        &publisher,
        CodecArchiveNamespace::new(catalog)?,
        limits,
        &NeverCancel,
    )?;
    assert_eq!(snapshot.windows()[0].root(), root);
    assert!(snapshot.pages().is_empty());
    Ok((archive, root, storage))
}

#[test]
fn newly_indexed_catalog_imports_and_cold_decodes_without_capture_or_source_archive() -> Test {
    let directory = Directory::new()?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let base = base(&directory, &listener.local_addr()?.to_string());
    let capture_plan = parse(&good(run(&directory, "capture", &base)?)?)?;
    let child = field(&capture_plan, "attempts")?
        .array()
        .and_then(|v| v.first())
        .ok_or("attempt")?;
    let (archive, original, storage) = unindexed(child)?;
    let mut args = base.clone();
    args.extend(["--recover".into(), "index".into()]);
    let preview = parse(&good(run(&directory, "capture", &args)?)?)?;
    assert_eq!(text(&preview, "schema")?, "fss.rtsp_reconnect_index_cli.v1");
    let quote = field(&preview, "attempts")?
        .array()
        .and_then(|v| v.first())
        .ok_or("quote")?;
    assert_eq!(number(field(quote, "index")?, "new_pages")?, 1);
    let mut wrong = args.clone();
    wrong.extend(["--approve".into(), text(&capture_plan, "approval")?.into()]);
    assert!(!run(&directory, "capture", &wrong)?.status.success());
    args.extend(["--approve".into(), text(&preview, "approval")?.into()]);
    let output = good(run(&directory, "capture", &args)?)?;
    let rows = output.lines().map(parse).collect::<Result<Vec<_>, _>>()?;
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(number(row, "sequence")?, i as u64);
    }
    let result = rows
        .iter()
        .find(|v| text(v, "kind").ok() == Some("attempt_index"))
        .ok_or("indexed attempt")?;
    let result = field(result, "detail")?;
    let page = field(result, "catalogs")?
        .array()
        .and_then(|v| v.first())
        .ok_or("catalog")?;
    assert_eq!(number(result, "indexed_windows")?, 1);
    assert_eq!(
        text(page, "root")?,
        text(field(quote, "index")?, "next_catalog_root")?
    );
    let destination = directory.0.join("deployment");
    let mut import: Vec<OsString> = [
        "--archive",
        archive.to_str().ok_or("archive")?,
        "--root",
        destination.to_str().ok_or("destination")?,
        "--site",
        SITE,
        "--catalog-slot",
        text(page, "slot")?,
        "--catalog-root",
        text(page, "root")?,
        "--codec",
        "hevc",
        "--sensor-id",
        text(result, "sensor")?,
        "--stream-id",
        text(result, "stream")?,
        "--anchor",
        text(result, "anchor")?,
        "--receive-clock",
        text(result, "receive_clock")?,
        "--decode-clock",
        text(result, "decode_clock")?,
        "--receive-time-ns",
        "5000000000",
        "--owner-authorized",
        "yes",
        "--read-originals",
        "yes",
        "--retain-originals",
        "yes",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    import.extend([
        "--generation".into(),
        number(result, "generation")?.to_string().into(),
        "--time-scale".into(),
        number(result, "time_scale")?.to_string().into(),
    ]);
    let approval = parse(&good(run(&directory, "import", &import)?)?)?;
    assert!(!destination.exists());
    import.extend([
        "--approve".into(),
        text(&approval, "approval_digest")?.into(),
    ]);
    let imported = parse(&good(run(&directory, "import", &import)?)?)?;
    assert_eq!(number(&imported, "frames")?, 2);
    assert_eq!(number(&imported, "windows")?, 1);
    let ledger = fs::read(destination.join("ledger/journal.fssj"))?;
    let effects = fs::read(destination.join("effects/journal.fssj"))?;
    let publisher = LocalRootPublisher::open(&archive, storage)?;
    let scope = CatalogScope {
        recording: RecordingScope {
            sensor: SensorId::parse(text(result, "sensor")?)?,
            stream: StreamId::parse(text(result, "stream")?)?,
            generation: number(result, "generation")?,
            anchor: digest(result, "anchor")?,
            receive_clock: digest(result, "receive_clock")?,
        },
        decode_clock: digest(result, "decode_clock")?,
        time_scale: u32::try_from(number(result, "time_scale")?)?,
    };
    let catalog = HevcArchiveCodec::load_catalog(
        &publisher,
        &fss_publication::SlotName::parse(text(page, "slot")?)?,
        digest(page, "root")?,
        &scope,
        &NeverCancel,
    )?;
    assert_eq!(HevcArchiveCodec::entries(&catalog)[0].root(), original);
    drop(publisher);
    fs::rename(&archive, directory.0.join("offline archive"))?;
    let common: Vec<OsString> = [
        "--root",
        destination.to_str().ok_or("destination")?,
        "--site",
        SITE,
        "--import-id",
        text(&imported, "import_identity")?,
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    let mut verify = vec![OsString::from("verify")];
    verify.extend(common.clone());
    let verified = good(run(&directory, "file", &verify)?)?;
    assert!(verified.contains("media_format=mp4hevc"), "{verified}");
    let mut decode = vec![OsString::from("decode")];
    decode.extend(common);
    decode.extend(
        [
            "--segment",
            "0",
            "--segment-count",
            "2",
            "--interpretation",
            "ycbcr",
            "--work-units",
            "1000000000",
        ]
        .into_iter()
        .map(OsString::from),
    );
    let decoded = good(run(&directory, "file", &decode)?)?;
    assert!(decoded.contains("decode_complete=true"), "{decoded}");
    assert_eq!(
        decoded
            .lines()
            .filter(|line| line.starts_with("frame_luma_sha256="))
            .count(),
        2,
        "{decoded}"
    );
    assert_eq!(fs::read(destination.join("ledger/journal.fssj"))?, ledger);
    assert_eq!(fs::read(destination.join("effects/journal.fssj"))?, effects);
    assert!(!archive.exists());
    assert!(matches!(listener.accept(), Err(e) if e.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}
