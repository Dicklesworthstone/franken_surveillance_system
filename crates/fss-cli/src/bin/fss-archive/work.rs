#![forbid(unsafe_code)]
//! Storage-only operator inspection/restoration of exact durable AVC work.
//! This deliberately does not create additional catalog pages: the original work pin
//! remains usable after any command cut or lost stdout acknowledgement. Full indexing
//! is a separate, explicitly planned archive operation, never implied by this command.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use fss_cli::archive_cmd::ArchiveCommandError;
use fss_cli::{ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_UNKNOWN_OPTION};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_object::{SpoolLimits, MAX_MANIFEST_CHILDREN};
use fss_publication::{LocalPublicationLimits, LocalPublicationReceipt, LocalPublicationState,
    LocalRootPublisher, PublishCancellation, PublishCutPoint, PublishOutcome, SlotName};
use fss_reference::rtsp::archive_recovery::archive_retirement_digest;
use fss_reference::rtsp::recording::MAX_RECORDING_BYTES;
use fss_reference::rtsp::recording::local::{RecordingIoError, RecordingProgress, RecordingPublication};
use fss_reference::rtsp::recording_archive::{ArchiveError, ArchiveLimits, ArchiveNamespace, ArchiveSnapshot};
use fss_reference::rtsp::recording_archive::checkpoint::{ArchiveWorkLimits, MAX_ARCHIVE_WORK_BYTES, load_archive_work};

type Result<T> = std::result::Result<T, ArchiveCommandError>;
pub(super) const HELP: &str = "fss-archive <inspect-work|restore-work> [options]\n\
  Required: --root EXISTING_DIR --work-slot SLOT --work-root sha256:HEX\n\
            --expected-namespace sha256:HEX\n\
  restore-work additionally requires: --commit yes\n\
  Bounds: --timeout-ms N --max-windows N --max-pages N --max-scan-roots N\n\
          --max-page-windows N --max-pending-bytes N --max-graph-objects N\n\
          --max-new-bytes N --max-objects N --max-total-bytes N\n\
  AVC work only; exact independent pins required. No camera, codec fallback,\n\
  guessed scope, deletion, root repair or overwrite. Open takes existing locks\n\
  and normal recovery/verification I/O; it is not a forensic read-only open.\n\
  restore-work publishes only the original prepared catalog and pending window.\n\
  Remaining indexing is reported, not silently fabricated or marked complete.\n";

pub(super) fn handles(args: &[OsString]) -> bool {
    args.first().and_then(|a| a.to_str()).is_some_and(|a| matches!(a, "inspect-work" | "restore-work"))
}
struct Options {
    root: PathBuf, slot: SlotName, root_digest: ContentDigest, namespace: ContentDigest,
    restore: bool, timeout: Duration, limits: ArchiveWorkLimits, storage: LocalPublicationLimits,
}
fn error(code: &'static str, message: &'static str) -> ArchiveCommandError {
    ArchiveCommandError::Argument { code, message }
}
fn malformed(message: &'static str) -> ArchiveCommandError { error(ERR_CLI_MALFORMED_VALUE, message) }
fn parse(args: &[OsString]) -> Result<Options> {
    if args.len() > 65 || args.iter().any(|a| a.as_encoded_bytes().len() > 4096) {
        return Err(malformed("argument count or length bound exceeded"));
    }
    if !handles(args) { return Err(malformed("expected inspect-work or restore-work")); }
    let restore = args[0].as_os_str() == OsStr::new("restore-work");
    let allowed = ["--root", "--work-slot", "--work-root", "--expected-namespace", "--timeout-ms",
        "--max-windows", "--max-pages", "--max-scan-roots", "--max-page-windows", "--max-pending-bytes",
        "--max-graph-objects", "--max-new-bytes", "--max-objects", "--max-total-bytes"];
    let mut values: BTreeMap<&str, &OsStr> = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or_else(|| error(ERR_CLI_INVALID_UNICODE, "option name must be UTF-8"))?;
        if !allowed.contains(&key) && !(restore && key == "--commit") {
            return Err(error(ERR_CLI_UNKNOWN_OPTION, "unknown or inapplicable option"));
        }
        if values.contains_key(key) { return Err(error(ERR_CLI_DUPLICATE_OPTION, "duplicate option")); }
        let value = pair.get(1).filter(|v| !v.is_empty() && !v.to_str().is_some_and(|s| s.starts_with("--")))
            .ok_or_else(|| error(ERR_CLI_MISSING_VALUE, "missing option value"))?;
        values.insert(key, value.as_os_str());
    }
    let required = |key: &str| values.get(key).copied().ok_or_else(|| error(ERR_CLI_MISSING_VALUE, "required option missing"));
    let text = |key: &str| required(key)?.to_str().ok_or_else(|| error(ERR_CLI_INVALID_UNICODE, "identity must be UTF-8"));
    let number = |key: &str, default: u64, minimum: u64, maximum: u64| -> Result<u64> {
        let n = if values.contains_key(key) {
            let raw = text(key)?;
            if !raw.bytes().all(|b| b.is_ascii_digit()) { return Err(malformed("expected unsigned decimal integer")); }
            raw.parse::<u64>().map_err(|_| malformed("integer overflow"))?
        } else { default };
        if !(minimum..=maximum).contains(&n) { return Err(malformed("numeric value outside supported bounds")); }
        Ok(n)
    };
    let digest = |key: &str| -> Result<ContentDigest> {
        let value = ContentDigest::parse(text(key)?).map_err(|_| malformed("invalid digest"))?;
        if value.algorithm() != DigestAlgorithm::Sha256 { return Err(malformed("SHA-256 required")); }
        Ok(value)
    };
    if restore && text("--commit")? != "yes" { return Err(malformed("restoration requires explicit commit acknowledgement")); }
    let scan = number("--max-scan-roots", 16_384, 1, 65_536)? as usize;
    let graph = number("--max-graph-objects", MAX_MANIFEST_CHILDREN as u64, 1, MAX_MANIFEST_CHILDREN as u64)? as usize;
    let objects = number("--max-objects", 65_536, 1, 131_072)? as usize;
    let limits = ArchiveWorkLimits {
        archive: ArchiveLimits {
            max_windows: number("--max-windows", 4096, 1, 4096)? as usize,
            max_pages: number("--max-pages", 1024, 1, 4096)? as usize,
            max_scan_roots: scan, windows_per_page: number("--max-page-windows", 64, 1, 64)? as usize,
        },
        max_pending_bytes: number("--max-pending-bytes", MAX_RECORDING_BYTES as u64, 0, MAX_RECORDING_BYTES as u64)? as usize,
        max_graph_objects: graph,
        max_new_bytes: number("--max-new-bytes", MAX_ARCHIVE_WORK_BYTES as u64, 0, MAX_ARCHIVE_WORK_BYTES as u64)? as usize,
    };
    let storage = LocalPublicationLimits::new(scan, graph, scan, scan,
        SpoolLimits::new(objects, number("--max-total-bytes", 1024 * 1024 * 1024, 1, 1024 * 1024 * 1024 * 1024)?,
            MAX_RECORDING_BYTES, objects));
    storage.validate().map_err(ArchiveCommandError::Storage)?;
    Ok(Options {
        root: PathBuf::from(required("--root")?),
        slot: SlotName::parse(text("--work-slot")?).map_err(|_| malformed("invalid work slot"))?,
        root_digest: digest("--work-root")?, namespace: digest("--expected-namespace")?, restore,
        timeout: Duration::from_millis(number("--timeout-ms", 30_000, 1, 3_600_000)?), limits, storage,
    })
}

struct Clock { start: Instant, duration: Duration }
impl Clock {
    fn now(&self) -> Result<u64> {
        let nanos = self.start.elapsed().as_nanos();
        if nanos >= self.duration.as_nanos() { return Err(ArchiveCommandError::Deadline); }
        u64::try_from(nanos).map_err(|_| ArchiveCommandError::Deadline)
    }
    fn deadline(&self) -> Result<u64> {
        u64::try_from(self.duration.as_nanos()).map_err(|_| ArchiveCommandError::Deadline)
    }
}
impl PublishCancellation for Clock {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool { self.start.elapsed() >= self.duration }
}
fn existing(path: &Path) -> Result<PathBuf> {
    if !fs::symlink_metadata(path).map_err(|_| ArchiveCommandError::NotArchive)?.is_dir() {
        return Err(ArchiveCommandError::NotArchive);
    }
    let root = fs::canonicalize(path).map_err(|e| ArchiveCommandError::Io { operation: "canonicalize archive", kind: e.kind() })?;
    for name in ["roots", "tombstones", "spool", "spool/objects", "spool/staging", "spool/verified"] {
        if !fs::symlink_metadata(root.join(name)).map_err(|_| ArchiveCommandError::NotArchive)?.is_dir() {
            return Err(ArchiveCommandError::NotArchive);
        }
    }
    for name in ["LOCK", "spool/LOCK"] {
        if !fs::symlink_metadata(root.join(name)).map_err(|_| ArchiveCommandError::NotArchive)?.is_file() {
            return Err(ArchiveCommandError::NotArchive);
        }
    }
    Ok(root)
}
fn outcome(receipt: LocalPublicationReceipt) -> Result<&'static str> {
    if receipt.claims.local != LocalPublicationState::Durable {
        return Err(ArchiveError::Storage(RecordingIoError::NotDurable).into());
    }
    Ok(if receipt.outcome == PublishOutcome::AlreadyPublished { "already_durable" } else { "published" })
}
fn run(options: Options) -> Result<String> {
    let clock = Clock { start: Instant::now(), duration: options.timeout };
    let root = existing(&options.root)?;
    clock.now()?;
    let mut publisher = LocalRootPublisher::open(root, options.storage).map_err(ArchiveCommandError::Storage)?;
    clock.now()?; // Owner open is bounded but not preemptible by this command.
    let work = load_archive_work(&publisher, &options.slot, options.root_digest, options.limits, &clock)?;
    if work.snapshot.namespace().digest() != options.namespace { return Err(ArchiveCommandError::SnapshotMismatch); }
    let retirement = archive_retirement_digest(&work)?;
    let mut report = String::new();
    // Fixed fields and at most two root results fit this reservation. Do not allocate a
    // potentially large world/source dump after committing a storage operation.
    report.try_reserve_exact(4096).map_err(|_| ArchiveCommandError::ReportLimit)?;
    let (mut window_result, mut page_result) = ("not_requested", "not_requested");
    if options.restore {
        page_result = "not_pending";
        // Preserve the original page-before-next-window constraint. Never construct another
        // page as an undocumented side effect: its root is not in this checkpoint's scope.
        if let Some(page) = &work.prepared_page {
            clock.now()?;
            let slot = work.snapshot.namespace().page_slot(work.snapshot.indexed_windows())?;
            let digest = publisher.stage_object(page.index_bytes())
                .map_err(|e| ArchiveError::Storage(RecordingIoError::from(e)))?;
            if Some(digest) != page.manifest().metadata_digest() { return Err(ArchiveError::Metadata.into()); }
            page_result = outcome(publisher.publish_cancellable(&slot, page.manifest(), &clock)
                .map_err(|e| ArchiveError::Storage(RecordingIoError::from(e)))?)?;
        }
        window_result = "not_pending";
        if let Some(window) = &work.pending {
            let slot = work.snapshot.namespace().window_slot(work.snapshot.windows().len())?;
            let mut job = RecordingPublication::new(window, &mut publisher, slot,
                options.limits.max_pending_bytes, clock.deadline()?).map_err(ArchiveError::Storage)?;
            let mut receipt = None;
            for _ in 0..5 {
                if let RecordingProgress::Published(value) = job.step(clock.now()?, &clock).map_err(ArchiveError::Storage)? {
                    receipt = Some(value); break;
                }
            }
            window_result = outcome(receipt.ok_or(ArchiveError::Metadata)?)?;
        }
    }
    clock.now()?;
    let namespace = ArchiveNamespace::new(work.snapshot.namespace().scope().clone())?;
    let current = ArchiveSnapshot::load(&publisher, namespace, work.snapshot.limits(), &clock)?;
    let snapshot = current.digest()?;
    clock.now()?;
    write!(&mut report,
        "{{\"schema\":\"fss.local_archive_work_operator_report.v1\",\"command\":\"{}\",\"codec\":\"avc\",\"work_root\":\"{}\",\"retirement_root\":\"{}\",\"namespace\":\"{}\",\"snapshot\":\"{}\",\"prior_acknowledged_windows\":{},\"durable_windows\":{},\"indexed_windows\":{},\"pages\":{},\"window_result\":\"{}\",\"catalog_result\":\"{}\",\"indexing_remaining\":{},\"publication_requested\":{},\"storage_only\":true,\"source_bytes_emitted\":false,\"capture_complete\":false,\"operation_complete\":true}}\n",
        if options.restore { "restore-work" } else { "inspect-work" }, options.root_digest, retirement,
        options.namespace, snapshot, work.snapshot.windows().len(), current.windows().len(),
        current.indexed_windows(), current.pages().len(), window_result, page_result,
        !current.unindexed_windows().is_empty(), options.restore).map_err(|_| ArchiveCommandError::ReportLimit)?;
    if report.len() > 4096 { return Err(ArchiveCommandError::ReportLimit); }
    Ok(report)
}

pub(super) fn execute(args: &[OsString]) -> Result<String> {
    if args.len() == 2 && args[1].as_os_str() == OsStr::new("--help") { return Ok(HELP.to_owned()); }
    run(parse(args)?)
}
