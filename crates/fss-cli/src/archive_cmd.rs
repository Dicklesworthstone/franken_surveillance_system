#![forbid(unsafe_code)]
//! Operator access to existing local recording archives. Not an agent protocol,
//! export capability, capture-time conversion, or coverage/absence certificate.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::{
    ERR_CLI_DUPLICATE_OPTION, ERR_CLI_INVALID_UNICODE, ERR_CLI_MALFORMED_VALUE,
    ERR_CLI_MISSING_VALUE, ERR_CLI_UNKNOWN_COMMAND, ERR_CLI_UNKNOWN_OPTION, escape_json_str,
};
use fss_core::{ContentDigest, DigestAlgorithm, SensorId, StreamId};
use fss_object::SpoolLimits;
use fss_publication::{
    LocalPublicationError, LocalPublicationLimits, LocalRootPublisher, PublishCancellation,
    PublishCutPoint,
};
use fss_reference::rtsp::recording::{MAX_RECORDING_BYTES, PreparedRecording, RecordingScope};
use fss_reference::rtsp::recording_archive::{
    ArchiveCodec, ArchiveError, ArchiveLimits, ArchiveQueryLimits, ArchiveReadProgress,
    AvcArchiveCodec, CodecArchiveNamespace, CodecArchiveRead, CodecArchiveSnapshot,
    HevcArchiveCodec,
};
use fss_reference::rtsp::recording_catalog::{CatalogEntry, CatalogScope};

mod export;

const MAX_REPORT_BYTES: usize = 4 * 1024 * 1024;
/// Explicitly versioned operator output; this is not an fss/1 agent response.
pub const ARCHIVE_REPORT_SCHEMA: &str = "fss.local_archive_operator_report.v1";
/// Help for the standalone archive utility. Paths accept native OS strings.
pub const HELP: &str = "fss-archive <inspect|query|verify|export> [options]\n\
  Required: --root DIR --codec avc|hevc --sensor ID --stream ID --generation N\n\
            --anchor sha256:HEX --receive-clock sha256:HEX\n\
            --decode-clock sha256:HEX --time-scale N\n\
  query/verify/export: --expected-snapshot sha256:HEX --start N --end N\n\
               [--max-output-windows N] [--max-output-bytes N]\n\
  export: --output-dir NEW_DIR --allow-whole-windows yes [--max-export-bytes N]\n\
          --privacy-root EXISTING_DEPLOYMENT --site SITE (the deployment retaining the\n\
          sensor's privacy-mask authority). Original packets cannot be masked: export of a\n\
          sensor with a current retained privacy mask, or naming no deployment, is refused\n\
          before any output (ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001); no override exists.\n\
  Bounds: [--timeout-ms N] [--max-windows N] [--max-pages N]\n\
          [--max-scan-roots N] [--max-objects N] [--max-total-bytes N]\n\
  inspect recovers and source-verifies an existing archive; it does not create one.\n\
  query selects metadata from that exact snapshot; verify additionally reads every\n\
  selected whole window. All times are explicit decode ticks, not capture times.\n\
  Export includes original packets and boundary lookahead beyond requested samples.\n\
  Unindexed ranges are not coverage or absence evidence. Output is bounded JSON.\n\
  Open takes the existing exclusive storage locks and performs normal recovery,\n\
  verification holds and directory sync; it is NOT a forensic read-only open.\n\
  No network access, guessed scope, automatic repair, retention change or deletion.\n";

/// Error retains lower-level typed failures without echoing paths or source bytes.
pub enum ArchiveCommandError {
    /// Strict, side-effect-free argument refusal with an existing CLI error identity.
    Argument {
        /// Existing stable CLI error identity.
        code: &'static str,
        /// Payload-free explanation that never echoes an argument value.
        message: &'static str,
    },
    /// Existing source replay, catalog, clock, cancellation or recovery failure.
    Archive(ArchiveError),
    /// Existing root owner could not open or recover.
    Storage(LocalPublicationError),
    /// A bounded host operation failed; its private path is never printed.
    Io {
        /// Static host operation label, not a path.
        operation: &'static str,
        /// OS error category, without private source text.
        kind: std::io::ErrorKind,
    },
    /// Root/layout must already exist as real directories and regular lock files.
    NotArchive,
    /// Current recovered inventory differs from the caller's pinned snapshot.
    SnapshotMismatch,
    /// The explicit operation timeout elapsed.
    Deadline,
    /// The fixed output allocation/size bound was exceeded.
    ReportLimit,
    /// Export requires a new directory outside the source archive.
    OutputScope,
    /// Existing output is never overwritten, merged or implicitly resumed.
    OutputExists,
    /// Independent export-byte reservation is insufficient.
    ExportBudget,
    /// An export directory may contain partial output; no cleanup/rollback is claimed.
    ExportIncomplete(Box<ArchiveCommandError>),
    /// Raw original packets of a sensor with a current retained privacy mask (or of a sensor
    /// whose mask authority was not named) are never exported; nothing was written.
    Privacy {
        /// Registered stable identity (registries/ERRORS.md).
        code: &'static str,
        /// Payload-free explanation.
        message: &'static str,
    },
}
impl ArchiveCommandError {
    /// Stable identity printed before the refusal.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Argument { code, .. } | Self::Privacy { code, .. } => code,
            _ => crate::ERR_CLI_RUNTIME_FAILURE,
        }
    }
}
impl fmt::Debug for ArchiveCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Argument { code, message } => f.debug_tuple(code).field(message).finish(),
            Self::Archive(e) => f.debug_tuple("Archive").field(e).finish(),
            Self::Storage(e) => f.debug_tuple("Storage").field(&e.code()).finish(),
            Self::Io { operation, kind } => f.debug_tuple(operation).field(kind).finish(),
            Self::NotArchive => f.write_str("NotArchive"),
            Self::SnapshotMismatch => f.write_str("SnapshotMismatch"),
            Self::Deadline => f.write_str("Deadline"),
            Self::ReportLimit => f.write_str("ReportLimit"),
            Self::OutputScope => f.write_str("OutputScope"),
            Self::OutputExists => f.write_str("OutputExists"),
            Self::ExportBudget => f.write_str("ExportBudget"),
            Self::ExportIncomplete(e) => f.debug_tuple("ExportIncomplete").field(e).finish(),
            Self::Privacy { code, message } => f.debug_tuple(code).field(message).finish(),
        }
    }
}
impl fmt::Display for ArchiveCommandError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "archive operator refusal: {self:?}")
    }
}
impl std::error::Error for ArchiveCommandError {}
impl From<ArchiveError> for ArchiveCommandError {
    fn from(value: ArchiveError) -> Self {
        Self::Archive(value)
    }
}
type Result<T> = std::result::Result<T, ArchiveCommandError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Codec {
    Avc,
    Hevc,
}
impl Codec {
    fn name(self) -> &'static str {
        match self {
            Self::Avc => "avc",
            Self::Hevc => "hevc",
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Action {
    Inspect,
    Query,
    Verify,
    Export,
}
impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::Inspect => "inspect",
            Self::Query => "query",
            Self::Verify => "verify",
            Self::Export => "export",
        }
    }
}

/// Immutable validated command. Codec and scope are chosen by arguments, not stored metadata.
/// No I/O occurs during construction. Debug intentionally excludes paths and scope identities.
pub struct ArchiveOptions {
    root: PathBuf,
    codec: Codec,
    action: Action,
    scope: CatalogScope,
    expected: Option<ContentDigest>,
    query: Option<Range<u64>>,
    query_limits: ArchiveQueryLimits,
    archive_limits: ArchiveLimits,
    storage_limits: LocalPublicationLimits,
    timeout: Duration,
    output: Option<PathBuf>,
    export_budget: u64,
    /// Export only: the deployment retaining the sensor's privacy-mask authority and its site.
    privacy: Option<(PathBuf, String)>,
}
impl fmt::Debug for ArchiveOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArchiveOptions")
            .field("codec", &self.codec)
            .field("action", &self.action)
            .field("archive_limits", &self.archive_limits)
            .finish_non_exhaustive()
    }
}
fn argument(code: &'static str, message: &'static str) -> ArchiveCommandError {
    ArchiveCommandError::Argument { code, message }
}
fn malformed(message: &'static str) -> ArchiveCommandError {
    argument(ERR_CLI_MALFORMED_VALUE, message)
}

/// Total OS-native parsing. Reject duplicate, unknown and inapplicable options before opening storage.
pub fn parse_archive_args(args: &[OsString]) -> Result<Option<ArchiveOptions>> {
    if args.is_empty() {
        return Ok(None);
    }
    if args.len() > 65 || args.iter().any(|a| a.as_encoded_bytes().len() > 4096) {
        return Err(malformed("argument count/length bound exceeded"));
    }
    let command = args[0]
        .to_str()
        .ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "command must be UTF-8"))?;
    if matches!(command, "help" | "--help" | "-h") {
        if args.len() != 1 {
            return Err(malformed("help accepts no extra arguments"));
        }
        return Ok(None);
    }
    let action = match command {
        "inspect" => Action::Inspect,
        "query" => Action::Query,
        "verify" => Action::Verify,
        "export" => Action::Export,
        _ => {
            return Err(argument(
                ERR_CLI_UNKNOWN_COMMAND,
                "expected inspect, query, verify or export",
            ));
        }
    };
    let common = [
        "--root",
        "--codec",
        "--sensor",
        "--stream",
        "--generation",
        "--anchor",
        "--receive-clock",
        "--decode-clock",
        "--time-scale",
        "--timeout-ms",
        "--max-windows",
        "--max-pages",
        "--max-scan-roots",
        "--max-objects",
        "--max-total-bytes",
    ];
    let ranged = [
        "--expected-snapshot",
        "--start",
        "--end",
        "--max-output-windows",
        "--max-output-bytes",
    ];
    let mut values: BTreeMap<&str, &OsStr> = BTreeMap::new();
    for pair in args[1..].chunks(2) {
        let key = pair[0]
            .to_str()
            .ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "option name must be UTF-8"))?;
        if !common.contains(&key)
            && !(action != Action::Inspect && ranged.contains(&key))
            && !(action == Action::Export
                && [
                    "--output-dir",
                    "--allow-whole-windows",
                    "--max-export-bytes",
                    "--privacy-root",
                    "--site",
                ]
                .contains(&key))
        {
            return Err(argument(
                ERR_CLI_UNKNOWN_OPTION,
                "unknown or inapplicable option",
            ));
        }
        if values.contains_key(key) {
            return Err(argument(ERR_CLI_DUPLICATE_OPTION, "duplicate option"));
        }
        let value = pair
            .get(1)
            .filter(|v| !v.is_empty() && !v.to_str().is_some_and(|s| s.starts_with("--")))
            .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "missing option value"))?;
        values.insert(key, value.as_os_str());
    }
    let required = |key: &str| {
        values
            .get(key)
            .copied()
            .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "required option missing"))
    };
    let text = |key: &str| {
        required(key)?
            .to_str()
            .ok_or_else(|| argument(ERR_CLI_INVALID_UNICODE, "identity/value must be UTF-8"))
    };
    let number = |key: &str, default: Option<u64>, min: u64, max: u64| -> Result<u64> {
        let value = if values.contains_key(key) {
            let raw = text(key)?;
            if !raw.bytes().all(|b| b.is_ascii_digit()) {
                return Err(malformed("expected unsigned decimal integer"));
            }
            raw.parse::<u64>()
                .map_err(|_| malformed("integer overflow"))?
        } else {
            default
                .ok_or_else(|| argument(ERR_CLI_MISSING_VALUE, "required numeric option missing"))?
        };
        if !(min..=max).contains(&value) {
            return Err(malformed("numeric value outside supported bounds"));
        }
        Ok(value)
    };
    let digest = |key: &str| -> Result<ContentDigest> {
        let digest = ContentDigest::parse(text(key)?).map_err(|_| malformed("invalid digest"))?;
        if digest.algorithm() != DigestAlgorithm::Sha256 {
            return Err(malformed("SHA-256 digest required"));
        }
        Ok(digest)
    };
    let codec = match text("--codec")? {
        "avc" => Codec::Avc,
        "hevc" => Codec::Hevc,
        _ => return Err(malformed("codec must be avc or hevc; no autodetection")),
    };
    let scope = CatalogScope {
        recording: RecordingScope {
            sensor: SensorId::parse(text("--sensor")?)
                .map_err(|_| malformed("invalid sensor ID"))?,
            stream: StreamId::parse(text("--stream")?)
                .map_err(|_| malformed("invalid stream ID"))?,
            generation: number("--generation", None, 1, u64::MAX)?,
            anchor: digest("--anchor")?,
            receive_clock: digest("--receive-clock")?,
        },
        decode_clock: digest("--decode-clock")?,
        time_scale: number("--time-scale", None, 1, u64::from(u32::MAX))? as u32,
    };
    let scan = number("--max-scan-roots", Some(16_384), 1, 65_536)? as usize;
    let objects = number("--max-objects", Some(65_536), 1, 131_072)? as usize;
    let storage_limits = LocalPublicationLimits::new(
        scan,
        512,
        scan,
        scan,
        SpoolLimits::new(
            objects,
            number(
                "--max-total-bytes",
                Some(1024 * 1024 * 1024),
                1,
                1024 * 1024 * 1024 * 1024,
            )?,
            MAX_RECORDING_BYTES,
            objects,
        ),
    );
    storage_limits
        .validate()
        .map_err(ArchiveCommandError::Storage)?;
    let archive_limits = ArchiveLimits {
        max_windows: number("--max-windows", Some(4096), 1, 4096)? as usize,
        max_pages: number("--max-pages", Some(1024), 1, 4096)? as usize,
        max_scan_roots: scan,
        windows_per_page: 64,
    };
    archive_limits.validate()?;
    let (expected, query) = if action == Action::Inspect {
        (None, None)
    } else {
        let start = number("--start", None, 0, u64::MAX)?;
        let end = number("--end", None, 1, u64::MAX)?;
        if start >= end {
            return Err(malformed(
                "query must be a nonempty half-open decode interval",
            ));
        }
        (Some(digest("--expected-snapshot")?), Some(start..end))
    };
    let output = if action == Action::Export {
        if text("--allow-whole-windows")? != "yes" {
            return Err(malformed(
                "export requires explicit whole-window disclosure acknowledgement",
            ));
        }
        Some(PathBuf::from(required("--output-dir")?))
    } else {
        None
    };
    let privacy = match (
        values.contains_key("--privacy-root"),
        values.contains_key("--site"),
    ) {
        (false, false) => None,
        (true, true) => {
            let site = text("--site")?.to_owned();
            fss_reference::reference_deployment::validate_site_lineage(&site)
                .map_err(|_| malformed("invalid site lineage"))?;
            Some((PathBuf::from(required("--privacy-root")?), site))
        }
        _ => {
            return Err(argument(
                ERR_CLI_MISSING_VALUE,
                "--privacy-root and --site are given together",
            ));
        }
    };
    Ok(Some(ArchiveOptions {
        privacy,
        root: PathBuf::from(required("--root")?),
        codec,
        action,
        scope,
        expected,
        query,
        archive_limits,
        storage_limits,
        output,
        export_budget: number(
            "--max-export-bytes",
            Some(512 * 1024 * 1024),
            1,
            export::MAX_EXPORT_BYTES,
        )?,
        query_limits: ArchiveQueryLimits {
            max_windows: number("--max-output-windows", Some(64), 1, 4096)? as usize,
            max_output_bytes: number(
                "--max-output-bytes",
                Some(256 * 1024 * 1024),
                1,
                4096 * MAX_RECORDING_BYTES as u64,
            )?,
        },
        timeout: Duration::from_millis(number("--timeout-ms", Some(30_000), 1, 3_600_000)?),
    }))
}

// The clock is an explicit, request-owned dependency. Tests need neither sleeps nor global time.
trait OperationClock: PublishCancellation {
    fn now_ns(&self) -> Result<u64>;
    fn deadline_ns(&self) -> u64;
    fn check(&self) -> Result<()> {
        if self.now_ns()? >= self.deadline_ns()
            || self.cancel_requested(PublishCutPoint::AfterChildrenVerified)
        {
            return Err(ArchiveCommandError::Deadline);
        }
        Ok(())
    }
}
struct Deadline {
    start: Instant,
    nanos: u64,
}
impl Deadline {
    fn new(timeout: Duration) -> Result<Self> {
        let nanos = u64::try_from(timeout.as_nanos()).map_err(|_| ArchiveCommandError::Deadline)?;
        Ok(Self {
            start: Instant::now(),
            nanos,
        })
    }
}
impl PublishCancellation for Deadline {
    fn cancel_requested(&self, _: PublishCutPoint) -> bool {
        self.start.elapsed().as_nanos() >= u128::from(self.nanos)
    }
}
impl OperationClock for Deadline {
    fn now_ns(&self) -> Result<u64> {
        u64::try_from(self.start.elapsed().as_nanos()).map_err(|_| ArchiveCommandError::Deadline)
    }
    fn deadline_ns(&self) -> u64 {
        self.nanos
    }
}

/// Recover and inspect/query/reverify an existing archive under explicit local owner bounds.
/// Returns a single report only after the entire command succeeds. Open performs the
/// existing owner's recovery I/O; this is not a read-only forensic interface or an agent grant.
pub fn execute_archive(options: &ArchiveOptions) -> Result<String> {
    let clock = Deadline::new(options.timeout)?;
    if options.action == Action::Export {
        // Before the archive is opened or any output directory exists.
        refuse_masked_export(options)?;
    }
    let root = existing_archive(&options.root)?;
    clock.check()?;
    let publisher = LocalRootPublisher::open(&root, options.storage_limits)
        .map_err(ArchiveCommandError::Storage)?;
    // Existing owner open has count/byte bounds but no cancellation argument.
    // Recheck immediately after it; do not claim a preemptible filesystem syscall.
    clock.check()?;
    match options.codec {
        Codec::Avc => execute_for::<AvcArchiveCodec>(options, &publisher, &clock),
        Codec::Hevc => execute_for::<HevcArchiveCodec>(options, &publisher, &clock),
    }
}
const ERR_PRIVACY_UNMASKED_ACCESS_REFUSED: &str = "ERR-PRIVACY-UNMASKED-ACCESS-REFUSED-001";
const ERR_PRIVACY_MASK: &str = "ERR-PRIVACY-MASK-001";

/// Raw export emits original packets, which cannot be masked without re-encoding: the sensor's
/// current retained privacy mask (read from the named deployment) must be absent. An export
/// naming no deployment cannot prove that and is refused the same way. There is no override.
fn refuse_masked_export(options: &ArchiveOptions) -> Result<()> {
    use fss_core::region::{ContextAuthority, RootAuthoritySpec};
    use fss_core::{BudgetVector, OperationId};
    use fss_reference::ingest::privacy_mask::{PrivacyMaskError, refuse_unmasked_source};
    use fss_reference::{ReferenceDeployment, ReplayCx};

    let Some((root, site)) = &options.privacy else {
        return Err(ArchiveCommandError::Privacy {
            code: ERR_PRIVACY_UNMASKED_ACCESS_REFUSED,
            message: "export of original packets must name the deployment retaining the sensor's privacy-mask authority (--privacy-root, --site); nothing was written",
        });
    };
    let unavailable = ArchiveCommandError::Privacy {
        code: ERR_PRIVACY_MASK,
        message: "the privacy deployment could not be opened to resolve the sensor's mask; nothing was written",
    };
    let directory = fs::symlink_metadata(root).is_ok_and(|m| m.is_dir());
    let layout = fs::symlink_metadata(root.join("LAYOUT")).is_ok_and(|m| m.is_file());
    if !directory || !layout {
        return Err(unavailable);
    }
    let failed = |_| ArchiveCommandError::Privacy {
        code: ERR_PRIVACY_MASK,
        message: "the privacy deployment could not be opened to resolve the sensor's mask; nothing was written",
    };
    let budgets = BudgetVector::builder()
        .bytes(64 * 1024 * 1024)
        .build()
        .map_err(|e| failed(e.to_string()))?;
    let authority = ContextAuthority::new_root(RootAuthoritySpec {
        trace_id: "trace:archive-export".into(),
        operation_id: OperationId::parse("operation:archive-export")
            .map_err(|e| failed(e.to_string()))?,
        principal: "principal:local-operator".into(),
        capabilities: vec!["ADP-REPLAY-001".to_owned()],
        deadline: None,
        priority: 10,
        budgets,
        privacy_scope: "privacy:local-authorized-files".into(),
        retention_scope: "retention:existing-deployment-policy".into(),
        anchor_universe: ContentDigest::sha256(site.as_bytes()),
        generation: 1,
    })
    .map_err(|e| failed(e.to_string()))?;
    authority.validate().map_err(|e| failed(e.to_string()))?;
    let cx = ReplayCx::from_context_authority(&authority, root.clone())
        .map_err(|e| failed(e.to_string()))?;
    let result = ReferenceDeployment::reopen(root, site, &cx)
        .map_err(|e| failed(e.to_string()))
        .and_then(|deployment| {
            refuse_unmasked_source(&deployment, &options.scope.recording.sensor).map_err(|e| {
                match e {
                    PrivacyMaskError::UnmaskedAccessRefused => ArchiveCommandError::Privacy {
                        code: ERR_PRIVACY_UNMASKED_ACCESS_REFUSED,
                        message: "the sensor has a current retained privacy mask; its original packets have no unmasked export path; nothing was written",
                    },
                    _ => failed(e.to_string()),
                }
            })
        });
    cx.drain_and_finalize();
    result
}

fn existing_archive(path: &Path) -> Result<PathBuf> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ArchiveCommandError::NotArchive)?;
    if !metadata.is_dir() {
        return Err(ArchiveCommandError::NotArchive);
    }
    let root = fs::canonicalize(path).map_err(|e| io_error("canonicalize archive", e))?;
    // Refuse missing/legacy layouts rather than silently creating directories or migrating holds.
    for name in [
        "roots",
        "tombstones",
        "spool",
        "spool/objects",
        "spool/staging",
        "spool/verified",
    ] {
        if !fs::symlink_metadata(root.join(name))
            .map_err(|_| ArchiveCommandError::NotArchive)?
            .is_dir()
        {
            return Err(ArchiveCommandError::NotArchive);
        }
    }
    for name in ["LOCK", "spool/LOCK"] {
        if !fs::symlink_metadata(root.join(name))
            .map_err(|_| ArchiveCommandError::NotArchive)?
            .is_file()
        {
            return Err(ArchiveCommandError::NotArchive);
        }
    }
    Ok(root)
}
fn io_error(operation: &'static str, error: std::io::Error) -> ArchiveCommandError {
    ArchiveCommandError::Io {
        operation,
        kind: error.kind(),
    }
}
fn append(out: &mut String, value: &str) -> Result<()> {
    if value.len() > MAX_REPORT_BYTES.saturating_sub(out.len()) {
        return Err(ArchiveCommandError::ReportLimit);
    }
    out.try_reserve(value.len())
        .map_err(|_| ArchiveCommandError::ReportLimit)?;
    out.push_str(value);
    Ok(())
}
fn quoted(value: &str) -> String {
    format!("\"{}\"", escape_json_str(value))
}
fn interval(value: &Range<u64>) -> String {
    format!("[{},{}]", value.start, value.end)
}
fn ranges(values: &[Range<u64>]) -> String {
    format!(
        "[{}]",
        values.iter().map(interval).collect::<Vec<_>>().join(",")
    )
}
fn entry_json(ordinal: usize, e: &CatalogEntry, indexed: bool) -> String {
    format!(
        "{{\"ordinal\":{ordinal},\"root\":{},\"slot\":{},\"decode_interval\":{},\"samples\":{},\"whole_window_bytes\":{},\"indexed\":{indexed}}}",
        quoted(&e.root().to_text()),
        quoted(e.slot().as_str()),
        interval(&e.decode_interval()),
        e.samples(),
        e.byte_len()
    )
}
fn plan_json(ordinal: usize, overlap: &Range<u64>, plan: &PreparedRecording) -> String {
    let objects = plan
        .children()
        .iter()
        .map(|(_, d, b)| {
            format!(
                "{{\"sha256\":{},\"bytes\":{}}}",
                quoted(&d.to_text()),
                b.len()
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{{\"ordinal\":{ordinal},\"root\":{},\"requested_interval\":{},\"returned_decode_interval\":{},\"whole_window_bytes\":{},\"objects_source_init_media_index\":[{objects}]}}",
        quoted(&plan.manifest().root().to_text()),
        interval(overlap),
        interval(&plan.summary().decode_interval),
        plan.byte_len()
    )
}
fn execute_for<C: ArchiveCodec>(
    options: &ArchiveOptions,
    publisher: &LocalRootPublisher,
    clock: &impl OperationClock,
) -> Result<String> {
    clock.check()?;
    let namespace = CodecArchiveNamespace::<C>::new(options.scope.clone())?;
    let snapshot =
        CodecArchiveSnapshot::<C>::load(publisher, namespace, options.archive_limits, clock)?;
    clock.check()?;
    let identity = snapshot.digest()?;
    if options
        .expected
        .is_some_and(|expected| expected != identity)
    {
        return Err(ArchiveCommandError::SnapshotMismatch);
    }
    let mut out = String::new();
    append(
        &mut out,
        &format!(
            "{{\"schema\":\"{ARCHIVE_REPORT_SCHEMA}\",\"command\":\"{}\",\"codec\":\"{}\",\"snapshot\":{},\"namespace\":{},\"sensor\":{},\"stream\":{},\"generation\":{},\"anchor\":{},\"receive_clock\":{},\"decode_clock\":{},\"time_scale\":{},\"durable_windows\":{},\"indexed_windows\":{},\"pages\":{},\"source_replay_on_recovery\":true,\"coverage_claim\":\"not_claimed\",\"time_basis\":\"owner_declared_decode_ticks\",",
            options.action.name(),
            options.codec.name(),
            quoted(&identity.to_text()),
            quoted(&snapshot.namespace().digest().to_text()),
            quoted(options.scope.recording.sensor.as_str()),
            quoted(options.scope.recording.stream.as_str()),
            options.scope.recording.generation,
            quoted(&options.scope.recording.anchor.to_text()),
            quoted(&options.scope.recording.receive_clock.to_text()),
            quoted(&options.scope.decode_clock.to_text()),
            options.scope.time_scale,
            snapshot.windows().len(),
            snapshot.indexed_windows(),
            snapshot.pages().len()
        ),
    )?;
    if options.action == Action::Inspect {
        append(&mut out, "\"windows\":[")?;
        for (ordinal, entry) in snapshot.windows().iter().enumerate() {
            if ordinal != 0 {
                append(&mut out, ",")?;
            }
            append(
                &mut out,
                &entry_json(ordinal, entry, ordinal < snapshot.indexed_windows()),
            )?;
        }
        append(&mut out, "],\"complete\":true}\n")?;
    } else {
        let query = options
            .query
            .clone()
            .ok_or_else(|| malformed("query missing"))?;
        let selection = snapshot.select(query.clone(), options.query_limits)?;
        append(
            &mut out,
            &format!(
                "\"query\":{},\"whole_window_selection_bytes\":{},\"unindexed\":{},",
                interval(&query),
                selection.output_bytes(),
                ranges(selection.unindexed())
            ),
        )?;
        if options.action == Action::Query {
            append(&mut out, "\"selected\":[")?;
            for (n, &ordinal) in selection.ordinals().iter().enumerate() {
                if n != 0 {
                    append(&mut out, ",")?;
                }
                append(
                    &mut out,
                    &entry_json(ordinal, &snapshot.windows()[ordinal], true),
                )?;
            }
            append(
                &mut out,
                "],\"range_read_completed\":false,\"complete\":true}\n",
            )?;
        } else {
            let mut destination = if options.action == Action::Export {
                Some(export::Destination::begin(
                    options,
                    identity,
                    selection.output_bytes(),
                    clock,
                )?)
            } else {
                None
            };
            let result = (|| -> Result<String> {
                let mut reader = CodecArchiveRead::<C>::new(
                    publisher,
                    &snapshot,
                    query,
                    options.query_limits,
                    clock.deadline_ns(),
                )?;
                append(&mut out, "\"verified\":[")?;
                let mut count = 0;
                // Bounded by selected windows + one aggregate completion. Never loop on Exhausted.
                for _ in 0..=selection.ordinals().len() {
                    clock.check()?;
                    match reader.step(clock.now_ns()?, clock)? {
                        ArchiveReadProgress::Window {
                            ordinal,
                            requested_interval,
                            recording,
                        } => {
                            if count != 0 {
                                append(&mut out, ",")?;
                            }
                            let plan = C::plan(&recording);
                            let mut row = plan_json(ordinal, &requested_interval, plan);
                            if let Some(destination) = &mut destination {
                                let files = destination.window(ordinal, plan, clock)?;
                                let _ = row.pop();
                                row.push_str(&format!(",\"exported_files\":[{files}]}}"));
                            }
                            append(&mut out, &row)?;
                            count += 1;
                        }
                        ArchiveReadProgress::Complete(receipt) => {
                            if receipt.windows != count {
                                return Err(ArchiveError::Metadata.into());
                            }
                            append(
                                &mut out,
                                &format!(
                                    "],\"range_read_completed\":true,\"verified_windows\":{},\"verified_payload_bytes\":{}",
                                    receipt.windows, receipt.output_bytes
                                ),
                            )?;
                            if let Some(destination) = &destination {
                                append(
                                    &mut out,
                                    &format!(
                                        ",\"export_payload_bytes_excluding_completion\":{},\"whole_windows_authorized\":true,\"source_may_include_boundary_lookahead\":true,\"completion_file\":\"COMPLETE.json\"",
                                        destination.payload_bytes()
                                    ),
                                )?;
                            }
                            append(&mut out, ",\"complete\":true}\n")?;
                            clock.check()?;
                            if let Some(destination) = &mut destination {
                                destination.complete(&out, clock)?;
                            }
                            return Ok(out);
                        }
                        ArchiveReadProgress::Exhausted => return Err(ArchiveError::Metadata.into()),
                    }
                }
                Err(ArchiveError::Metadata.into())
            })();
            return result.map_err(|e| {
                if destination.is_some() {
                    ArchiveCommandError::ExportIncomplete(Box::new(e))
                } else {
                    e
                }
            });
        }
    }
    clock.check()?;
    Ok(out)
}

#[cfg(test)]
#[path = "archive_cmd/tests.rs"]
mod tests;
