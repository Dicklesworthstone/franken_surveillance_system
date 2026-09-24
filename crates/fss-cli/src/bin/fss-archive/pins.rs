#![forbid(unsafe_code)]
//! Operator recovery from actual saved references, not another agent protocol or authority.
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt::{self, Write as _};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use fss_cli::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_RUNTIME_FAILURE, ERR_CLI_UNKNOWN_OPTION, ExitIdentity,
};
use fss_core::{ContentDigest, DigestAlgorithm};
use fss_object::{MAX_MANIFEST_CHILDREN, SpoolLimits};
use fss_publication::{
    LocalPublicationLimits, LocalPublicationReceipt, LocalRootPublisher, PublishCancellation,
    PublishCutPoint, PublishOutcome,
};
use fss_reference::rtsp::archive_pins::{
    ArchivePinAnchor, ArchivePinError, ArchivePinJournal, ArchivePinLimits, ArchivePinScope,
    StoredArchivePin,
};
use fss_reference::rtsp::recording::MAX_RECORDING_BYTES;
use fss_reference::rtsp::recording_archive::ArchiveLimits;
use fss_reference::rtsp::recording_archive::checkpoint::{
    ArchiveWorkLimits, MAX_ARCHIVE_WORK_BYTES,
};

const MAX_REPORT_BYTES: usize = 8192;
pub(super) const HELP: &str = "fss-archive <inspect-pins|restore-pins> [options]\n\
  Required: --pin-root EXISTING_DIR --journal-id sha256:HEX\n\
            --expected-namespace sha256:HEX\n\
  restore-pins additionally requires: --root EXISTING_ARCHIVE --commit yes\n\
  Independent prefix: --minimum-sequence N --minimum-root sha256:HEX (together)\n\
  Bounds: --timeout-ms N --max-pin-records N --max-pin-bytes N\n\
  Restore bounds: --max-windows N --max-pages N --max-scan-roots N\n\
    --max-page-windows N --max-pending-bytes N --max-graph-objects N\n\
    --max-new-bytes N --max-objects N --max-total-bytes N\n\
  inspect-pins verifies metadata only; work/source custody is NOT checked.\n\
  restore-pins verifies the current candidate (otherwise last confirmed),\n\
  confirms it, then restores only its original catalog and pending recording.\n\
  No fallback on a bad candidate, guessed work roots, camera, deletion, tail\n\
  repair, new directories, or implicit indexing. Both owners take native locks.\n\
  A partial success may survive an error or lost stdout; inspect and retry the\n\
  same journal. Without a minimum prefix, trust rests in the protected directory.\n";

pub(super) fn handles(args: &[OsString]) -> bool {
    args.first()
        .and_then(|a| a.to_str())
        .is_some_and(|a| matches!(a, "inspect-pins" | "restore-pins"))
}
// Retain typed failures internally, but never print paths, arbitrary arguments or source bytes.
enum Error {
    Argument(&'static str, &'static str),
    Pins(ArchivePinError),
    Storage(fss_publication::LocalPublicationError),
    Layout,
    Deadline,
    Report,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argument(_, message) => f.write_str(message),
            Self::Pins(error) => fmt::Display::fmt(error, f),
            Self::Storage(error) => write!(f, "archive owner refused: {}", error.code()),
            Self::Layout => f.write_str("existing disjoint real storage directories required"),
            Self::Deadline => f.write_str("pin recovery deadline elapsed"),
            Self::Report => f.write_str("pin recovery report bound exceeded"),
        }
    }
}
impl From<ArchivePinError> for Error {
    fn from(e: ArchivePinError) -> Self {
        Self::Pins(e)
    }
}
type Result<T> = std::result::Result<T, Error>;
fn malformed(message: &'static str) -> Error {
    Error::Argument(ERR_CLI_MALFORMED_VALUE, message)
}
struct Options {
    pin_root: PathBuf,
    root: Option<PathBuf>,
    scope: ArchivePinScope,
    minimum: Option<ArchivePinAnchor>,
    pins: ArchivePinLimits,
    work: ArchiveWorkLimits,
    storage: LocalPublicationLimits,
    timeout: Duration,
}
fn parse(args: &[OsString]) -> Result<Options> {
    if !handles(args) || args.len() > 65 || args.iter().any(|a| a.as_encoded_bytes().len() > 4096) {
        return Err(malformed("command, argument count or length refused"));
    }
    let restore = args[0].as_os_str() == OsStr::new("restore-pins");
    let common = [
        "--pin-root",
        "--journal-id",
        "--expected-namespace",
        "--minimum-sequence",
        "--minimum-root",
        "--timeout-ms",
        "--max-pin-records",
        "--max-pin-bytes",
    ];
    let mutation = [
        "--root",
        "--commit",
        "--max-windows",
        "--max-pages",
        "--max-scan-roots",
        "--max-page-windows",
        "--max-pending-bytes",
        "--max-graph-objects",
        "--max-new-bytes",
        "--max-objects",
        "--max-total-bytes",
    ];
    let mut values: BTreeMap<&str, &OsStr> = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0].to_str().ok_or(Error::Argument(
            ERR_CLI_INVALID_UNICODE,
            "option name must be UTF-8",
        ))?;
        if !common.contains(&key) && !(restore && mutation.contains(&key)) {
            return Err(Error::Argument(
                ERR_CLI_UNKNOWN_OPTION,
                "unknown or inapplicable option",
            ));
        }
        if values.contains_key(key) {
            return Err(Error::Argument(
                ERR_CLI_DUPLICATE_OPTION,
                "duplicate option",
            ));
        }
        let value = pair
            .get(1)
            .filter(|v| !v.is_empty() && !v.to_str().is_some_and(|s| s.starts_with("--")))
            .ok_or(Error::Argument(
                ERR_CLI_MISSING_VALUE,
                "missing option value",
            ))?;
        values.insert(key, value.as_os_str());
    }
    let required = |key: &str| {
        values.get(key).copied().ok_or(Error::Argument(
            ERR_CLI_MISSING_VALUE,
            "required option missing",
        ))
    };
    let text = |key: &str| {
        required(key)?.to_str().ok_or(Error::Argument(
            ERR_CLI_INVALID_UNICODE,
            "identity must be UTF-8",
        ))
    };
    let number = |key: &str, default: u64, minimum: u64, maximum: u64| -> Result<u64> {
        let value = if values.contains_key(key) {
            let raw = text(key)?;
            if !raw.bytes().all(|b| b.is_ascii_digit()) {
                return Err(malformed("unsigned decimal integer required"));
            }
            raw.parse::<u64>()
                .map_err(|_| malformed("integer overflow"))?
        } else {
            default
        };
        if !(minimum..=maximum).contains(&value) {
            return Err(malformed("numeric bound refused"));
        }
        Ok(value)
    };
    let digest = |key: &str| -> Result<ContentDigest> {
        let value = ContentDigest::parse(text(key)?).map_err(|_| malformed("invalid digest"))?;
        if value.algorithm() != DigestAlgorithm::Sha256 || value.bytes() == [0; 32] {
            return Err(malformed("nonzero SHA-256 required"));
        }
        Ok(value)
    };
    if restore && text("--commit")? != "yes" {
        return Err(malformed("restoration requires --commit yes"));
    }
    if values.contains_key("--minimum-sequence") != values.contains_key("--minimum-root") {
        return Err(malformed(
            "minimum sequence and root must be supplied together",
        ));
    }
    let minimum = if values.contains_key("--minimum-root") {
        Some(ArchivePinAnchor {
            sequence: number("--minimum-sequence", 0, 1, 16_384)?,
            root: digest("--minimum-root")?,
        })
    } else {
        None
    };
    let scan = number("--max-scan-roots", 16_384, 1, 65_536)? as usize;
    let graph = number(
        "--max-graph-objects",
        MAX_MANIFEST_CHILDREN as u64,
        1,
        MAX_MANIFEST_CHILDREN as u64,
    )? as usize;
    let objects = number("--max-objects", 65_536, 1, 131_072)? as usize;
    let storage = LocalPublicationLimits::new(
        scan,
        graph,
        scan,
        scan,
        SpoolLimits::new(
            objects,
            number(
                "--max-total-bytes",
                1024 * 1024 * 1024,
                1,
                1024 * 1024 * 1024 * 1024,
            )?,
            MAX_RECORDING_BYTES,
            objects,
        ),
    );
    storage.validate().map_err(Error::Storage)?;
    Ok(Options {
        pin_root: PathBuf::from(required("--pin-root")?),
        root: if restore {
            Some(PathBuf::from(required("--root")?))
        } else {
            None
        },
        scope: ArchivePinScope {
            journal_id: digest("--journal-id")?,
            archive_namespace: digest("--expected-namespace")?,
        },
        minimum,
        pins: ArchivePinLimits {
            max_records: number("--max-pin-records", 8193, 1, 16_384)? as usize,
            max_bytes: number("--max-pin-bytes", 8 * 1024 * 1024, 128, 16 * 1024 * 1024)? as usize,
        },
        work: ArchiveWorkLimits {
            archive: ArchiveLimits {
                max_windows: number("--max-windows", 4096, 1, 4096)? as usize,
                max_pages: number("--max-pages", 1024, 1, 4096)? as usize,
                max_scan_roots: scan,
                windows_per_page: number("--max-page-windows", 64, 1, 64)? as usize,
            },
            max_pending_bytes: number(
                "--max-pending-bytes",
                MAX_RECORDING_BYTES as u64,
                0,
                MAX_RECORDING_BYTES as u64,
            )? as usize,
            max_graph_objects: graph,
            max_new_bytes: number(
                "--max-new-bytes",
                MAX_ARCHIVE_WORK_BYTES as u64,
                0,
                MAX_ARCHIVE_WORK_BYTES as u64,
            )? as usize,
        },
        storage,
        timeout: Duration::from_millis(number("--timeout-ms", 30_000, 1, 3_600_000)?),
    })
}
struct Clock {
    start: Instant,
    duration: Duration,
}
impl Clock {
    fn now(&self) -> Result<u64> {
        let n = self.start.elapsed().as_nanos();
        if n >= self.duration.as_nanos() {
            return Err(Error::Deadline);
        }
        u64::try_from(n).map_err(|_| Error::Deadline)
    }
    fn deadline(&self) -> u64 {
        self.duration.as_nanos() as u64
    }
}
impl PublishCancellation for Clock {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.start.elapsed() >= self.duration
    }
}
fn directory(path: &Path) -> Result<PathBuf> {
    if !fs::symlink_metadata(path)
        .map_err(|_| Error::Layout)?
        .is_dir()
    {
        return Err(Error::Layout);
    }
    fs::canonicalize(path).map_err(|_| Error::Layout)
}
fn archive(path: &Path) -> Result<PathBuf> {
    let root = directory(path)?;
    for name in [
        "roots",
        "tombstones",
        "spool",
        "spool/objects",
        "spool/staging",
        "spool/verified",
    ] {
        if !fs::symlink_metadata(root.join(name))
            .map_err(|_| Error::Layout)?
            .is_dir()
        {
            return Err(Error::Layout);
        }
    }
    for name in ["LOCK", "spool/LOCK"] {
        if !fs::symlink_metadata(root.join(name))
            .map_err(|_| Error::Layout)?
            .is_file()
        {
            return Err(Error::Layout);
        }
    }
    Ok(root)
}
fn pin_json(pin: Option<&StoredArchivePin>) -> String {
    // All dynamic fields are validated slot grammar, digests or integers, not arbitrary text.
    pin.map_or_else(|| "null".to_owned(), |p| format!(
        "{{\"slot\":\"{}\",\"root\":\"{}\",\"retirement\":\"{}\",\"new_payload_bytes\":{}}}",
        p.slot(), p.root(), p.retirement_digest(), p.new_payload_bytes()))
}
fn receipt_json(receipt: Option<&LocalPublicationReceipt>) -> String {
    receipt.map_or_else(
        || "null".to_owned(),
        |r| {
            format!(
                "{{\"root\":\"{}\",\"outcome\":\"{}\"}}",
                r.root,
                if r.outcome == PublishOutcome::AlreadyPublished {
                    "already_durable"
                } else {
                    "published"
                }
            )
        },
    )
}
fn run(options: Options) -> Result<String> {
    let clock = Clock {
        start: Instant::now(),
        duration: options.timeout,
    };
    let pin_root = directory(&options.pin_root)?;
    let media = options.root.as_ref().map(|p| archive(p)).transpose()?;
    if media
        .as_ref()
        .is_some_and(|p| p.starts_with(&pin_root) || pin_root.starts_with(p))
    {
        return Err(Error::Layout);
    }
    clock.now()?;
    let mut pins = ArchivePinJournal::open_complete(
        &pin_root,
        options.scope,
        options.minimum,
        options.pins,
        &clock,
    )?;
    let mut report = String::new();
    report
        .try_reserve_exact(MAX_REPORT_BYTES)
        .map_err(|_| Error::Report)?;
    let restored = if let Some(media) = media {
        clock.now()?;
        let mut publisher =
            LocalRootPublisher::open(media, options.storage).map_err(Error::Storage)?;
        clock.now()?; // Existing owner open is bounded, not a preemptible syscall.
        Some(pins.restore_work(
            &mut publisher,
            options.work,
            clock.now()?,
            clock.deadline(),
            &clock,
        )?)
    } else {
        None
    };
    pins.verify(&clock)?;
    clock.now()?;
    let anchor = pins.anchor();
    write!(&mut report, "{{\"schema\":\"fss.local_archive_pin_operator_report.v1\",\"command\":\"{}\",\"journal_id\":\"{}\",\"namespace\":\"{}\",\"journal_sequence\":{},\"journal_root\":\"{}\",\"minimum_prefix_supplied\":{},\"candidate\":{},\"last_confirmed\":{}",
        if restored.is_some() { "restore-pins" } else { "inspect-pins" }, options.scope.journal_id,
        options.scope.archive_namespace, anchor.sequence, anchor.root, options.minimum.is_some(),
        pin_json(pins.state().candidate()), pin_json(pins.state().last_confirmed())).map_err(|_| Error::Report)?;
    if let Some(result) = restored {
        write!(&mut report, ",\"work_root\":\"{}\",\"snapshot\":\"{}\",\"confirmation_recorded\":{},\"window\":{},\"catalog\":{},\"durable_windows\":{},\"indexed_windows\":{},\"pages\":{},\"indexing_remaining\":{},\"work_custody\":\"verified\",\"publication_requested\":true",
            result.pin.root(), result.snapshot_digest, result.confirmation.is_some(), receipt_json(result.window.as_ref()),
            receipt_json(result.catalog.as_ref()), result.durable_windows, result.indexed_windows, result.pages,
            result.indexed_windows != result.durable_windows).map_err(|_| Error::Report)?;
    } else {
        report.push_str(",\"work_custody\":\"not_checked\",\"publication_requested\":false");
    }
    report.push_str(",\"storage_only\":true,\"source_bytes_emitted\":false,\"capture_complete\":false,\"operation_complete\":true}\n");
    if report.len() > MAX_REPORT_BYTES {
        return Err(Error::Report);
    }
    clock.now()?;
    Ok(report)
}
pub(super) fn dispatch(args: &[OsString]) -> ExitCode {
    let result = if args.len() == 2 && args[1].as_os_str() == OsStr::new("--help") {
        Ok(HELP.to_owned())
    } else {
        parse(args).and_then(run)
    };
    match result {
        Ok(report) => match super::emit(&mut io::stdout().lock(), report.as_bytes()) {
            Ok(()) => ExitCode::from(ExitIdentity::SUCCESS.code),
            Err(_) => ExitCode::from(ExitIdentity::RUNTIME_FAILURE.code),
        },
        Err(error) => {
            let (code, exit) = match &error {
                Error::Argument(code, _) => (*code, ExitIdentity::MALFORMED_VALUE.code),
                _ => (ERR_CLI_RUNTIME_FAILURE, ExitIdentity::RUNTIME_FAILURE.code),
            };
            eprintln!("{code}: {error}");
            eprintln!(
                "No complete report was emitted. Keep the journal and archive: confirmation or original roots may have committed. Inspect/reconcile and retry the same work; no automatic cleanup, tail repair or camera operation occurred."
            );
            ExitCode::from(exit)
        }
    }
}
