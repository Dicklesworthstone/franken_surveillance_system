#![forbid(unsafe_code)]
//! REVIEW-ONLY probe (r23b), not for merge: races a path swap between the adapter's lstat and
//! its open. A swapper thread atomically renames a regular file and a symlink over the source
//! path while the main thread imports it in a loop.
//!
//! Probe 1 (symlink to a JPEG): the regular file is not media (UnknownFormat); the symlink
//! target is a JPEG. With an Annex-B hint, a followed symlink surfaces as
//! FormatConflict { detected: JpegStream } (or Ok): that is a bypass.
//! Probe 2 (symlink to a FIFO): counts opens that blocked on the FIFO. A watchdog opens the
//! FIFO for writing with O_NONBLOCK, which succeeds only while a reader is blocked in open,
//! and so releases it.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;

use fss_core::{
    BudgetVector, ContentDigest, ContextAuthority, OperationId, RootAuthoritySpec, SensorId,
    StreamId, TimestampNs,
};
use fss_reference::ingest::{
    DetectedFileFormat, FileFormatHint, FileIngestAdapter, FileIngestError, FileIngestRequest,
};
use fss_reference::{
    ADP_FILE_ROW_ID, ADP_REPLAY_ROW_ID, ReferenceDeployment, ReplayCx, ReplayIoAuthority,
    VirtualClock,
};

/// Linux O_NONBLOCK (x86_64 and aarch64).
const O_NONBLOCK: i32 = 0o4000;
const ITERATIONS: usize = 20_000;

fn scratch(label: &str) -> Result<PathBuf, Box<dyn Error>> {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("r23b-toctou-{label}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn cx(label: &str) -> Result<ReplayCx, Box<dyn Error>> {
    let spec = RootAuthoritySpec {
        trace_id: format!("trace:r23b-{label}"),
        operation_id: OperationId::parse(format!("operation:r23b-{label}"))?,
        principal: format!("operator:r23b-{label}"),
        capabilities: vec![ADP_FILE_ROW_ID.to_string(), ADP_REPLAY_ROW_ID.to_string()],
        deadline: None,
        priority: 10,
        budgets: BudgetVector::default(),
        privacy_scope: "privacy:internal".to_string(),
        retention_scope: "retention:ephemeral".to_string(),
        anchor_universe: ContentDigest::sha256(b"r23b"),
        generation: 1,
    };
    let auth = ContextAuthority::new_root(spec)?;
    let io = ReplayIoAuthority::from_context_authority(&auth, scratch(&format!("cx-{label}"))?)?;
    Ok(ReplayCx::new(io))
}

/// Swaps `path` between a hard link of `regular` and a symlink to `target` until `stop`.
fn spawn_swapper(
    dir: PathBuf,
    regular: PathBuf,
    target: PathBuf,
    path: PathBuf,
    stop: Arc<AtomicBool>,
    swaps: Arc<AtomicU64>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let reg_tmp = dir.join("reg.tmp");
        let lnk_tmp = dir.join("lnk.tmp");
        while !stop.load(Ordering::Relaxed) {
            let _ = fs::remove_file(&lnk_tmp);
            if symlink(&target, &lnk_tmp).is_ok() && fs::rename(&lnk_tmp, &path).is_ok() {
                swaps.fetch_add(1, Ordering::Relaxed);
            }
            let _ = fs::remove_file(&reg_tmp);
            if fs::hard_link(&regular, &reg_tmp).is_ok() && fs::rename(&reg_tmp, &path).is_ok() {
                swaps.fetch_add(1, Ordering::Relaxed);
            }
        }
    })
}

#[derive(Default, Debug)]
struct Tally {
    unknown_format: u64,
    symlink_refused: u64,
    changed_during_open: u64,
    not_regular: u64,
    empty: u64,
    io_error: u64,
    bypass: u64,
    other: u64,
}

fn classify(t: &mut Tally, r: Result<fss_reference::ingest::FileIngestReceipt, FileIngestError>) {
    match r {
        Err(FileIngestError::UnknownFormat { .. }) => t.unknown_format += 1,
        Err(FileIngestError::SymlinkNotAllowed { .. }) => t.symlink_refused += 1,
        Err(FileIngestError::SourceChangedDuringOpen { .. }) => t.changed_during_open += 1,
        Err(FileIngestError::NotRegularFile { .. }) => t.not_regular += 1,
        Err(FileIngestError::EmptyFile { .. }) => t.empty += 1,
        Err(FileIngestError::Io(_)) => t.io_error += 1,
        Err(FileIngestError::FormatConflict {
            detected: DetectedFileFormat::JpegStream,
            ..
        })
        | Ok(_) => t.bypass += 1,
        Err(_) => t.other += 1,
    }
}

fn run_race(label: &str, target: &Path, watchdog_fifo: Option<PathBuf>) -> Result<Tally, Box<dyn Error>> {
    let dir = scratch(label)?;
    let regular = dir.join("regular.bin");
    fs::write(&regular, b"NOT-MEDIA regular source bytes for the toctou probe")?;
    let path = dir.join("source");
    fs::copy(&regular, &path)?;

    let cx = cx(label)?;
    let mut deployment =
        ReferenceDeployment::open(&scratch(&format!("dep-{label}"))?, "site:deploy:r23b", &cx)?;
    let clock = VirtualClock::new(0x23b, TimestampNs(5_000_000_000_000));

    let stop = Arc::new(AtomicBool::new(false));
    let swaps = Arc::new(AtomicU64::new(0));
    let released = Arc::new(AtomicU64::new(0));
    let swapper = spawn_swapper(
        dir.clone(),
        regular.clone(),
        target.to_path_buf(),
        path.clone(),
        Arc::clone(&stop),
        Arc::clone(&swaps),
    );
    let watchdog = watchdog_fifo.map(|fifo| {
        let stop = Arc::clone(&stop);
        let released = Arc::clone(&released);
        thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if OpenOptions::new()
                    .write(true)
                    .custom_flags(O_NONBLOCK)
                    .open(&fifo)
                    .is_ok()
                {
                    released.fetch_add(1, Ordering::Relaxed);
                }
                thread::yield_now();
            }
        })
    });

    let mut tally = Tally::default();
    for _ in 0..ITERATIONS {
        let request = FileIngestRequest::new(
            path.clone(),
            SensorId::parse("sensor:r23b")?,
            StreamId::parse("stream:r23b")?,
        )
        .with_format_hint(FileFormatHint::AnnexB);
        classify(&mut tally, FileIngestAdapter::ingest(request, &clock, &cx, &mut deployment));
    }
    stop.store(true, Ordering::Relaxed);
    let _ = swapper.join();
    if let Some(w) = watchdog {
        let _ = w.join();
    }
    println!(
        "CAPLOG {{\"probe\":\"{label}\",\"iterations\":{ITERATIONS},\"swaps\":{},\"blocked_opens_released\":{},\"tally\":\"{tally:?}\"}}",
        swaps.load(Ordering::Relaxed),
        released.load(Ordering::Relaxed)
    );
    Ok(tally)
}

#[test]
fn probe_toctou_symlink_to_jpeg_is_never_followed() -> Result<(), Box<dyn Error>> {
    let dir = scratch("jpeg-target")?;
    let target = dir.join("target.mjpeg");
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/media/mjpeg/mjpeg_clean_3frames.mjpeg");
    fs::copy(&fixture, &target)?;
    let tally = run_race("jpeg", &target, None)?;
    assert_eq!(tally.bypass, 0, "a swapped-in symlink was followed: {tally:?}");
    assert_eq!(tally.other, 0, "unexpected outcome: {tally:?}");
    Ok(())
}

#[test]
fn probe_toctou_symlink_to_fifo_blocking_open() -> Result<(), Box<dyn Error>> {
    let dir = scratch("fifo-target")?;
    let fifo = dir.join("target.fifo");
    let status = std::process::Command::new("mkfifo").arg(&fifo).status()?;
    if !status.success() {
        return Err("mkfifo failed on this host".into());
    }
    let tally = run_race("fifo", &fifo, Some(fifo.clone()))?;
    assert_eq!(tally.bypass, 0, "{tally:?}");
    Ok(())
}
